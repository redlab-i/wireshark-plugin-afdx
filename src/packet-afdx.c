/* packet-afdx.c
 *
 * AFDX protocol dissector for wireshark -- main source file
 *
 * https://github.com/redlab-i/wireshark-plugin-afdx
 *
 * Copyright 2015-2017 REDLAB-I, LLC <http://redlab-i.ru>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 */

#include <stdio.h>

#include <config.h>

#include <epan/packet.h>
#include <epan/proto.h>
#include <epan/proto_data.h>
#include <epan/prefs.h>
#include <epan/uat.h>
#include <epan/tvbuff.h>
#include <epan/tvbuff-int.h>
#include <epan/expert.h>
#include <epan/epan.h>
#include <epan/epan-int.h>
#include <epan/wmem/wmem.h>
#include <epan/to_str.h>
#include <epan/crc32-tvb.h>
#include <wsutil/nstime.h>
#include <wsutil/filesystem.h>
#include <wiretap/wtap.h>
#include <glib.h>
#include <libintl.h>

#define GETTEXT_PACKAGE "afdx"
#include <glib/gi18n-lib.h>

#undef _
#define _(text) dgettext(GETTEXT_PACKAGE, text)

#include "interval_map.h"
#include "afdx_utilities.h"

#define MAC_LENGTH 6
#define ETHERNET_HEADER_LENGTH 14
#define ETHERTYPE_IPv4 0x0800
#define IP_PROTOCOL_UDP 0x11
#define AFDX_MAX_VL_ID 0xFFFF

#define AFDX_PROTO_DATA_DELTA 0
#define AFDX_PROTO_DATA_PREVIOUS_SN 1

#ifndef _U_
    #define _U_ __attribute__((unused))
#endif

static int proto_afdx = -1;

static int hf_afdx_vl_id = -1;
static int hf_afdx_time_delta = -1;
static int hf_afdx_hw_interface = -1;
static int hf_afdx_mac_src = -1;
static int hf_afdx_mac_dst = -1;
static int hf_afdx_mac_sender_network_id = -1;
static int hf_afdx_mac_sender_device_id = -1;
static int hf_afdx_mac_sender_device_direction = -1;
static int hf_afdx_mac_sender_device_location = -1;
static int hf_afdx_mac_sender_interface = -1;

static int hf_afdx_ip_src = -1;
static int hf_afdx_ip_dst = -1;

// unicast sender IP address fields
static int hf_afdx_ip_sender_network_id = -1;
static int hf_afdx_ip_sender_device_id = -1;
static int hf_afdx_ip_sender_device_direction = -1;
static int hf_afdx_ip_sender_device_location = -1;
static int hf_afdx_ip_sender_partition_id = -1;

// unicast dst IP address fields
static int hf_afdx_ip_dst_network_id = -1;
static int hf_afdx_ip_dst_device_id = -1;
static int hf_afdx_ip_dst_device_direction = -1;
static int hf_afdx_ip_dst_device_location = -1;
static int hf_afdx_ip_dst_partition_id = -1;

// multicast dst IP address field
static int hf_afdx_ip_dst_vl_id = -1;

static int hf_afdx_frame_counter = -1;

static int hf_afdx_data = -1;

static int hf_afdx_frame_time = -1;
static int hf_afdx_frame_time_delta = -1;
static int hf_afdx_frame_time_delta_displayed = -1;
static int hf_afdx_frame_time_epoch = -1;
static int hf_afdx_frame_time_relative = -1;

static int hf_afdx_equipment = -1;
static int hf_afdx_application = -1;

static int hf_afdx_fcs = -1;

static int hf_eth_type = -1;

static gint ett_afdx = -1;
static gint ett_mac_dst = -1;
static gint ett_mac_src = -1;
static gint ett_mac_src_device_id = -1;
static gint ett_ip_src = -1;
static gint ett_ip_src_device_id = -1;
static gint ett_ip_dst = -1;
static gint ett_ip_dst_device_id = -1;

static expert_field ei_afdx_unknown_vl = EI_INIT;
static expert_field ei_afdx_incorrect_vl = EI_INIT;
static expert_field ei_afdx_vl_range_not_specified = EI_INIT;
static expert_field ei_afdx_bad_mtu = EI_INIT;
static expert_field ei_afdx_network_id_mismatch = EI_INIT;
static expert_field ei_afdx_device_id_mismatch = EI_INIT;
static expert_field ei_afdx_vl_bag_violation = EI_INIT;
static expert_field ei_afdx_src_ip_not_unicast = EI_INIT;
static expert_field ei_afdx_dst_ip_incorrect = EI_INIT;
static expert_field ei_afdx_dst_ip_vl_id_mismatch = EI_INIT;
static expert_field ei_afdx_frame_number_gap = EI_INIT;
static expert_field ei_afdx_fcs_incorrect = EI_INIT;

static dissector_handle_t ethertype_handle;
static dissector_handle_t eth_handle;
static module_t* afdx_prefs_module;

static gboolean afdx_enabled = FALSE;
static gboolean afdx_assume_fcs = TRUE;
static gboolean afdx_check_fcs = TRUE;

static const gchar* afdx_vl_table_file;

// A hashtable containing (interface name -> set of possible VL ID's)
static GHashTable* iface_vl_table = NULL;

// UAT for Interface -> vl_ids

typedef struct _iface_table_row_t {
    gchar* iface_name;
    gchar* filename;
} iface_table_row_t;

static iface_table_row_t * iface_table_rows = NULL;
static guint num_iface_table_rows = 0;

UAT_CSTRING_CB_DEF(iface_table_rows, iface_name, iface_table_row_t)
UAT_FILENAME_CB_DEF(iface_table_rows, filename, iface_table_row_t)

gboolean vl_list_file_chk_cb(void* r _U_, const char* p, guint len _U_, const void* u1 _U_, const void* u2 _U_, char ** err) {
    const gchar* filename = p;
    const char *cerr = *err;
    range_t* range = load_range_from_file(filename, &cerr, AFDX_MAX_VL_ID);
    g_free(range);
    if(!range) return FALSE;
    else return TRUE;
}

int iface_table_update_cb(void *r, char **err) {
    iface_table_row_t* row = (iface_table_row_t*) r;
    const gchar* filename = row->filename;
    const char *cerr = *err;
    range_t* range = load_range_from_file(filename, &cerr, AFDX_MAX_VL_ID);
    g_free(range);
    return range != 0;
}
void* iface_table_copy_cb(void* to, const void* from, size_t siz ) {
    iface_table_row_t * destination = (iface_table_row_t *) to;
    iface_table_row_t * source = (iface_table_row_t *) from;
    destination->iface_name = g_strdup(source->iface_name);
    destination->filename = g_strdup(source->filename);
    return destination;
}

void iface_table_free_cb(void*r) {
    iface_table_row_t * row = (iface_table_row_t *) r;
    g_free(row->iface_name);
    g_free(row->filename);
}

void iface_table_initialize_cb() {
    if(iface_vl_table) {
        g_hash_table_destroy(iface_vl_table);
    }
    
    iface_vl_table = g_hash_table_new_full(g_str_hash,
                                            g_str_equal,
                                            g_free,
                                            g_free);
    
    guint i = 0;
    for(i = 0; i < num_iface_table_rows; ++i) {
        iface_table_row_t* row = iface_table_rows + i;
        const gchar* filename = row->filename;
        range_t* range = load_range_from_file(filename, NULL, AFDX_MAX_VL_ID);
        if(!range) {
            continue;
        }
        
        gchar* iface_name = g_ascii_strdown(row->iface_name, -1);
        
        range_t* old_range = (range_t*) g_hash_table_lookup(iface_vl_table, iface_name);
        if(old_range) {
            range_t* merged_range = merge_ranges(range, old_range);
            if(merged_range) {
                g_hash_table_replace(iface_vl_table, g_strdup(iface_name), merged_range);
            } else {
                g_print("iface_table_initialize_cb(): Failed to merge ranges");
            }
            g_free(range);
        } else {
            g_hash_table_insert(iface_vl_table, g_strdup(iface_name), range);
        }
        g_free(iface_name);
    }
}

// 'known' VLs (with specified MTUs, BAGs and Jitters) from CSV file in settings
static GHashTable* vl_table = NULL;

static const gchar* afdx_mac_equipment_file = NULL;

static wmem_tree_t* vl_first_pass_map = NULL;

// This structure is used during first pass. It stores last packet time & sequence number for each VL.
typedef struct _vl_first_pass {
    nstime_t previous_time;
    guint8 previous_sn;
} vl_first_pass;

// One row in VL parameters table
typedef struct _vl_table_row_t {
    guint vl_id;
    guint mtu;
    guint bag;
    guint jitter;
} vl_table_row_t;

gboolean vl_table_read_cb(const gchar** fields, void* user_data) {
    if(!fields || !fields[0] || !fields[1] || !fields[2] || !fields[3]) {
        g_print("Error parsing CSV file %s: not all required fields present\n", afdx_vl_table_file);
        return FALSE;
    }
    
    gchar* endptr;
    
    guint64 vl_id = g_ascii_strtoull(fields[0], &endptr, 16);
    if(endptr == fields[0] || vl_id > AFDX_MAX_VL_ID) {
        g_print("Error parsing CSV file %s: '%s' is not a valid VL ID\n", afdx_vl_table_file, fields[0]);
        return FALSE;
    }
    
    guint64 mtu = g_ascii_strtoull(fields[1], &endptr, 10);
    if(endptr == fields[1]) {
        g_print("Error parsing CSV file %s: '%s' is not a valid MTU\n", afdx_vl_table_file, fields[1]);
        return FALSE;
    }
    
    guint64 bag = g_ascii_strtoull(fields[2], &endptr, 10);
    if(endptr == fields[2]) {
        g_print("Error parsing CSV file %s: '%s' is not a valid BAG\n", afdx_vl_table_file, fields[2]);
        return FALSE;
    }
    
    guint64 jitter = g_ascii_strtoull(fields[3], &endptr, 10);
    if(endptr == fields[3]) {
        g_print("Error parsing CSV file %s: '%s' is not a valid Jitter\n", afdx_vl_table_file, fields[3]);
        return FALSE;
    }
    
//     g_print("Read VL spec from CSV: vl_id: %#x"
//     ", MTU: %" 
//     G_GUINT64_FORMAT 
//     ", BAG: %"
//     G_GUINT64_FORMAT
//     ", Jitter: %"
//     G_GUINT64_FORMAT
//     "\n", (guint)vl_id, mtu, bag, jitter);
    
    if(!vl_table) {
        vl_table = g_hash_table_new_full(g_int64_hash, g_int64_equal, g_free, g_free);
    }

    gpointer v = g_hash_table_lookup(vl_table, &vl_id);
    if(v) {
        g_print("Warning: duplicate VL spec for VL ID %#llx, using the first spec", (unsigned long long)vl_id);
        return TRUE;
    }
    
    vl_table_row_t* row;
    
    row = g_new0(vl_table_row_t, 1);
    row->vl_id = vl_id;
    row->mtu = mtu;
    row->bag = bag;
    row->jitter = jitter;
    
    guint64* key_p = g_new0(guint64, 1);
    *key_p = vl_id;
    
    g_hash_table_insert(vl_table, key_p, row);
    
    return TRUE;
}

// This mapping contains MAC addres intervals and corresponding equipment/application names
interval_map_t* equipment_mac_map = NULL;
wmem_allocator_t* settings_allocator = NULL;

typedef struct {
    gchar* equipment;
    gchar* application;
} equipment_desc_t;

// CSV format: min MAC, max MAC, equipment name, application name
gboolean equipment_mac_read_cb(const gchar** fields, void* user_data) {
    if(!settings_allocator) {
        g_print("Internal error: equipment_mac_read_cb(): settings allocator not initialized");
        return FALSE;
    }
    
    if(!equipment_mac_map) {
        g_print("Internal error: equipment_mac_read_cb(): equipment_mac_map not initialized");
        return FALSE;
    }
    
    if(!fields || !fields[0] || !fields[1] || !fields[2] || !fields[3]) {
        g_print("Error parsing CSV file %s: not all required fields present\n", afdx_mac_equipment_file);
        return FALSE;
    }
    
    gint64 min_mac = parse_mac(fields[0]);
    if(min_mac < 0) {
        g_print("Error parsing CSV file %s: invalid MAC address: '%s'\n", afdx_mac_equipment_file, fields[0]);
        return FALSE;
    }
    
    gint64 max_mac = parse_mac(fields[1]);
    if(max_mac < 0) {
        g_print("Error parsing CSV file %s: invalid MAC address: '%s'\n", afdx_mac_equipment_file, fields[1]);
        return FALSE;
    }
    
    if(min_mac > max_mac) {
        gint64 temp = max_mac;
        max_mac = min_mac;
        min_mac = temp;
    }

    equipment_desc_t* value = wmem_new0(settings_allocator, equipment_desc_t);
    value->equipment = wmem_strdup(settings_allocator, fields[2]);
    g_strstrip(value->equipment);
    value->application = wmem_strdup(settings_allocator, fields[3]);
    g_strstrip(value->application);
    
    if(!interval_map_insert(equipment_mac_map, min_mac, max_mac, value)) {
        g_print("Error parsing CSV file %s: MAC interval [%s, %s] (%s, %s) overlaps with other MAC intervals, ignoring it\n",
                afdx_mac_equipment_file, fields[0], fields[1], fields[2], fields[3]);
        return TRUE;
    }
    
    return TRUE;
}

void 
afdx_prefs_changed() {
    if(!settings_allocator) {
        settings_allocator = wmem_allocator_new(WMEM_ALLOCATOR_BLOCK);
    } else {
        wmem_free_all(settings_allocator);
        wmem_gc(settings_allocator);
    }
    
    if(vl_table) {
        g_hash_table_remove_all(vl_table);
    }
    if(afdx_vl_table_file && afdx_vl_table_file[0]) {   
        gboolean ok = process_csv_file(afdx_vl_table_file, &vl_table_read_cb, NULL);
        if(!ok) {
            g_print("Warning: VL table file '%s' content is invalid\n", afdx_vl_table_file);
        }
    }
    
    if(!equipment_mac_map) {
        equipment_mac_map = interval_map_new_autoreset(wmem_epan_scope(), settings_allocator);
    }
    
    if(afdx_mac_equipment_file && afdx_mac_equipment_file[0]) {
        gboolean ok = process_csv_file(afdx_mac_equipment_file, &equipment_mac_read_cb, NULL);
        if(!ok) {
            g_print("Warning: MAC equipment file '%s' content is invalid\n", afdx_mac_equipment_file);
        }
    }
}

/// Returns the AFDX sequence number, which is stored in the last byte of payload
guint8 afdx_get_sn(tvbuff_t* tvb, guint32* offset) {
    guint length = tvb->length;
    guint offset_from_back = 1;
    if(afdx_assume_fcs) {
       // Here we take into account 4-byte FCS and 1-byte sequence number
       offset_from_back = 5;
    }
    if(offset) *offset = length - offset_from_back;
    return tvb_get_guint8(tvb, length - offset_from_back);
}

/// Returns the FCS
guint32 afdx_get_fcs(tvbuff_t* tvb, guint32* offset) {
    guint length = tvb->length;
    if(!afdx_assume_fcs) return 0;
    if(offset) *offset = length - 4;
    return tvb_get_ntohl(tvb, length - 4);
}

#define MAKE_KEY(array_key, has_interface_id, interface_id, vl_id) wmem_tree_key_t array_key[4]; \
array_key[0].length = 1; \
array_key[0].key = &has_interface_id; \
array_key[1].length = 1; \
array_key[1].key = &interface_id; \
array_key[2].length = 1; \
array_key[2].key = &vl_id; \
array_key[3].length = 0; \
array_key[3].key = NULL;

static void
dissect_afdx_first_pass(packet_info* pinfo, tvbuff_t* tvb, gint vl_id) {
    if(!vl_first_pass_map) {
        vl_first_pass_map = wmem_tree_new_autoreset(wmem_epan_scope(), wmem_file_scope());
    }

    guint has_interface_id = 0;
    guint interface_id = 0;
    if(pinfo->rec->presence_flags & WTAP_HAS_INTERFACE_ID) {
        has_interface_id = 1;
        interface_id = pinfo->rec->rec_header.packet_header.interface_id;
    }
    
    MAKE_KEY(array_key, has_interface_id, interface_id, vl_id);

    vl_first_pass* first_pass = (vl_first_pass* )wmem_tree_lookup32_array(vl_first_pass_map, (wmem_tree_key_t *) array_key);
    
    guint8 sn = afdx_get_sn(tvb, NULL);
    
    if(!first_pass) {
        first_pass = wmem_new(wmem_file_scope(), vl_first_pass);
        first_pass->previous_time = pinfo->fd->abs_ts;
        first_pass->previous_sn = sn;
        wmem_tree_insert32_array(vl_first_pass_map, (wmem_tree_key_t *) &array_key, first_pass);
        return;
    }
    
    nstime_t *prev_time = &first_pass->previous_time;
    nstime_t* delta = wmem_new(wmem_file_scope(), nstime_t);
    
    nstime_delta(delta, &pinfo->fd->abs_ts, prev_time);
    
    p_add_proto_data(wmem_file_scope(), pinfo, proto_afdx, AFDX_PROTO_DATA_DELTA, delta);
    
    guint16* previous_sn = wmem_new(wmem_file_scope(), guint16);
    *previous_sn = first_pass->previous_sn;
        
    p_add_proto_data(wmem_file_scope(), pinfo, proto_afdx, AFDX_PROTO_DATA_PREVIOUS_SN, previous_sn);
    
    first_pass->previous_time = pinfo->fd->abs_ts;
    first_pass->previous_sn = sn;
}

// copypaste from epan.c
const char *
epan_get_interface_name(const epan_t *session, guint32 interface_id)
{
    if (session->get_interface_name)
        return session->get_interface_name(session->data, interface_id);

    return NULL;
}

unsigned get_total_milliseconds(const nstime_t* time) {
    return time->secs * 100 + time->nsecs / 1000000;
}

unsigned get_nanoseconds(const nstime_t* time) {
    return time->nsecs % 1000000;
}

const char* get_network_name(guint8 interface_id) {
    const gchar * network_name = _("Invalid");
    if(interface_id == 1) network_name = "A";
    else if (interface_id == 2) network_name = "B";   
}

static proto_tree *
dissect_afdx(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, vl_table_row_t* row, guint32 vl_id)
{   
    gboolean is_vl_known = TRUE;
    if(!row) {
        is_vl_known = FALSE;
    }
        
    // delta from previous frame of the same VL
    nstime_t* delta = p_get_proto_data(wmem_file_scope(), pinfo, proto_afdx, AFDX_PROTO_DATA_DELTA);
    guint8* previous_sn = p_get_proto_data(wmem_file_scope(), pinfo, proto_afdx, AFDX_PROTO_DATA_PREVIOUS_SN);
    gboolean first_frame_of_vl = FALSE;
    if(!delta || !previous_sn) {
        first_frame_of_vl = TRUE;
    }
    
    if(tree) {
        proto_item *ti = NULL;
        proto_item *proto_ti = NULL;
        
        proto_tree *proto_subtree = NULL;
        proto_tree *subtree_mac_dst = NULL;
        proto_tree *subtree_mac_src = NULL;
        proto_tree *subtree_mac_src_device_id = NULL;
        proto_tree *subtree_ip_src = NULL;
        proto_tree *subtree_ip_src_device_id = NULL;
        proto_tree *subtree_ip_dst = NULL;
        proto_tree *subtree_ip_dst_device_id = NULL;
        
        tvbuff_t *ds_tvb = tvb->ds_tvb;
        
        tvb = tvb->ds_tvb;
        ti = proto_tree_add_item(tree, proto_afdx, tvb, 0, -1, ENC_NA);
        proto_ti = ti;
        
        proto_item_append_text(proto_ti, ", VL ID: 0x%04x", vl_id);
        
        proto_subtree = proto_item_add_subtree(ti, ett_afdx);

        if(row && ds_tvb->length > row->mtu) {
            expert_add_info_format(pinfo, proto_ti, &ei_afdx_bad_mtu, 
                _("Frame size larger than MTU: frame size = %d bytes > %d bytes = MTU"), ds_tvb->length, row->mtu);
        }
        
        if (pinfo->rec->presence_flags & WTAP_HAS_INTERFACE_ID) {
            const char *interface_name = epan_get_interface_name(pinfo->epan, pinfo->rec->rec_header.packet_header.interface_id);

            if (interface_name) {
                ti = proto_tree_add_string_format_value(proto_subtree, hf_afdx_hw_interface, tvb, 0, 0, interface_name, "%s", interface_name);
                proto_item_append_text(proto_ti, _(", Iface: %s"), interface_name);
                
                char* interface_name_lower = g_ascii_strdown(interface_name, -1);
                range_t* vl_id_range = (range_t*)g_hash_table_lookup(iface_vl_table, interface_name_lower);
                g_free(interface_name_lower);
                
                if(vl_id_range) {
                    if(!value_is_in_range(vl_id_range, vl_id)) {
                        expert_add_info(pinfo, ti, &ei_afdx_incorrect_vl);
                    }
                } else {
                    expert_add_info(pinfo, ti, &ei_afdx_vl_range_not_specified);
                }
            } else {
//                 ti = proto_tree_add_uint(proto_subtree, hf_afdx_hw_interface, tvb, 0, 0, pinfo->phdr->interface_id);
            }
            
        }
        
        if(delta) {
            ti = proto_tree_add_time_format_value(proto_subtree, hf_afdx_time_delta, ds_tvb, 0, 0, delta,
                _("%d.%06d ms"), get_total_milliseconds(delta), get_nanoseconds(delta)
            );
            PROTO_ITEM_SET_GENERATED(ti);
            
            if(row) {
                //TODO we should ensure that this is always positive ?
                guint min_usecs_between = row->bag - row->jitter;
                guint delta_usecs = delta->secs * 1000000ul + delta->nsecs / 1000;
                
                nstime_t min_time_between;
                min_time_between.secs = min_usecs_between / 1000000ul;
                min_time_between.nsecs = (min_usecs_between % 1000000ul) * 1000;
                
                if(nstime_cmp(delta, &min_time_between) < 0) {
                    expert_add_info_format(pinfo, ti, &ei_afdx_vl_bag_violation, _("VL BAG violation: delta = %d.%06d ms < %d.%06d ms = BAG - Jitter"), 
                                           get_total_milliseconds(delta), get_nanoseconds(delta), 
                                           get_total_milliseconds(&min_time_between), get_nanoseconds(&min_time_between));
                }
            }
        }
        
        const guint8* dst_mac = tvb_get_ptr(tvb, 0, MAC_LENGTH);
        const guint8* src_mac = tvb_get_ptr(tvb, MAC_LENGTH, MAC_LENGTH);
        
        guint8 sender_network_id_from_mac = tvb_get_guint8(tvb, MAC_LENGTH + 3);
        guint8 sender_device_id_from_mac = tvb_get_guint8(tvb, MAC_LENGTH + 4);
        
        ti = proto_tree_add_ether_format_value(proto_subtree, hf_afdx_mac_dst, tvb, 0, MAC_LENGTH, dst_mac, "%s", tvb_ether_to_str(tvb, 0));
        
        subtree_mac_dst = proto_item_add_subtree(ti, ett_mac_dst);
        
        ti = proto_tree_add_item(subtree_mac_dst, hf_afdx_vl_id, tvb, 4, 2, ENC_BIG_ENDIAN);
        if(!is_vl_known) {
            expert_add_info(pinfo, ti, &ei_afdx_unknown_vl);
        }
        
        gint64 dst_mac_int64 = 0;
        int i;
        for(i = 0; i < 6; ++i) {
            dst_mac_int64 <<= 8;
            dst_mac_int64 |= dst_mac[i];
        }
        
        equipment_desc_t* equipment_desc = interval_map_lookup(equipment_mac_map, dst_mac_int64);
        if(equipment_desc) {
            ti = proto_tree_add_string_format_value(subtree_mac_dst, hf_afdx_equipment, tvb, 0, 0, equipment_desc->equipment,
                "%s", equipment_desc->equipment);
            PROTO_ITEM_SET_GENERATED(ti);
            ti = proto_tree_add_string_format_value(subtree_mac_dst, hf_afdx_application, tvb, 0, 0, equipment_desc->application,
                "%s", equipment_desc->application);
            PROTO_ITEM_SET_GENERATED(ti);
        }
        
        ti = proto_tree_add_ether_format_value(proto_subtree, hf_afdx_mac_src, tvb, MAC_LENGTH, MAC_LENGTH, src_mac, "%s", tvb_ether_to_str(tvb, MAC_LENGTH));
        
        subtree_mac_src = proto_item_add_subtree(ti, ett_mac_src);
        
        ti = proto_tree_add_item(subtree_mac_src, hf_afdx_mac_sender_network_id, tvb, MAC_LENGTH + 3, 1, ENC_BIG_ENDIAN);
        ti = proto_tree_add_item(subtree_mac_src, hf_afdx_mac_sender_device_id, tvb, MAC_LENGTH + 4, 1, ENC_BIG_ENDIAN);
        
        subtree_mac_src_device_id = proto_item_add_subtree(ti, ett_mac_src_device_id);
        
        ti = proto_tree_add_item(subtree_mac_src_device_id, hf_afdx_mac_sender_device_direction, tvb, MAC_LENGTH + 4, 1, ENC_BIG_ENDIAN);
        ti = proto_tree_add_item(subtree_mac_src_device_id, hf_afdx_mac_sender_device_location, tvb, MAC_LENGTH + 4, 1, ENC_BIG_ENDIAN);
        
        guint8 interface_id = tvb_get_guint8(tvb, MAC_LENGTH + 5) >> 5;
        const char* network_name = get_network_name(interface_id);
        ti = proto_tree_add_uint_bits_format_value(subtree_mac_src, hf_afdx_mac_sender_interface, tvb, (MAC_LENGTH + 5)*8, 3,
                                              interface_id, "%u (%s)", interface_id, network_name);
        
        if(tvb_offset_exists(tvb, ETHERNET_HEADER_LENGTH + 20)) {
            tvb = tvb_new_subset_remaining(tvb, ETHERNET_HEADER_LENGTH + 12);
            
            guint32 src_ip = tvb_get_ipv4(tvb, 0);
            proto_item * ip_src_ti = proto_tree_add_ipv4_format_value(proto_subtree, hf_afdx_ip_src, tvb, 0, 4, src_ip, 
                "%s", tvb_ip_to_str(tvb, 0)
            );
                
            guint8 sender_network_id_from_ip = tvb_get_guint8(tvb, 1);
            guint8 sender_device_id_from_ip = tvb_get_guint8(tvb, 2);
            
            subtree_ip_src = proto_item_add_subtree(ip_src_ti, ett_ip_src);
                            
            ti = proto_tree_add_item(subtree_ip_src, hf_afdx_ip_sender_network_id, tvb, 1, 1, ENC_BIG_ENDIAN);
            if(sender_network_id_from_ip != sender_network_id_from_mac) {
                expert_add_info(pinfo, ti, &ei_afdx_network_id_mismatch);
            }
            ti = proto_tree_add_item(subtree_ip_src, hf_afdx_ip_sender_device_id, tvb, 2, 1, ENC_BIG_ENDIAN);
            if(sender_device_id_from_ip != sender_device_id_from_mac) {
                expert_add_info(pinfo, ti, &ei_afdx_device_id_mismatch);
            }
            subtree_ip_src_device_id = proto_item_add_subtree(ti, ett_ip_src_device_id);
            ti = proto_tree_add_item(subtree_ip_src_device_id, hf_afdx_ip_sender_device_direction, tvb, 2, 1, ENC_BIG_ENDIAN);
            ti = proto_tree_add_item(subtree_ip_src_device_id, hf_afdx_ip_sender_device_location, tvb, 2, 1, ENC_BIG_ENDIAN);        
            ti = proto_tree_add_item(subtree_ip_src, hf_afdx_ip_sender_partition_id, tvb, 3, 1, ENC_BIG_ENDIAN);
                
            guint8 first_octet = tvb_get_guint8(tvb, 0);
            if(((guint32)first_octet & 0x80u) != 0) {
                expert_add_info(pinfo, ip_src_ti, &ei_afdx_src_ip_not_unicast);
            }
            
            guint32 dst_ip = tvb_get_ipv4(tvb, 4);
            proto_item* ip_dst_ti = proto_tree_add_ipv4_format_value(proto_subtree, hf_afdx_ip_dst, tvb, 4, 4, dst_ip, 
                "%s", tvb_ip_to_str(tvb, 4)
            );
            
            tvb = tvb_new_subset_remaining(tvb, 4);
            
            first_octet = tvb_get_guint8(tvb, 0);
            
            subtree_ip_dst = proto_item_add_subtree(ip_dst_ti, ett_ip_dst);
                
            if (((guint32)first_octet & 0xF0u) == 0xE) {
                ti = proto_tree_add_item(subtree_ip_dst, hf_afdx_ip_dst_vl_id, tvb, 2, 2, ENC_BIG_ENDIAN);
                guint16 dst_ip_vl_id = tvb_get_ntohs(tvb, 2);
                if(dst_ip_vl_id != vl_id) {
                    expert_add_info(pinfo, ti, &ei_afdx_dst_ip_vl_id_mismatch);
                }
            } else {
                
                ti = proto_tree_add_item(subtree_ip_dst, hf_afdx_ip_dst_network_id, tvb, 1, 1, ENC_BIG_ENDIAN);
                ti = proto_tree_add_item(subtree_ip_dst, hf_afdx_ip_dst_device_id, tvb, 2, 1, ENC_BIG_ENDIAN);
                
                subtree_ip_dst_device_id = proto_item_add_subtree(ti, ett_ip_dst_device_id);
                
                ti = proto_tree_add_item(subtree_ip_dst_device_id, hf_afdx_ip_dst_device_direction, tvb, 2, 1, ENC_BIG_ENDIAN);
                ti = proto_tree_add_item(subtree_ip_dst_device_id, hf_afdx_ip_dst_device_location, tvb, 2, 1, ENC_BIG_ENDIAN);        
                
                ti = proto_tree_add_item(subtree_ip_dst, hf_afdx_ip_dst_partition_id, tvb, 3, 1, ENC_BIG_ENDIAN);
           
                if(((guint32)first_octet & 0x80u) != 0)
                    expert_add_info(pinfo, ip_dst_ti, &ei_afdx_dst_ip_incorrect);
            }
        }
        
        guint sn_offset = 0;
        
        guint8 sn = afdx_get_sn(ds_tvb, &sn_offset);
        
        ti = proto_tree_add_item(proto_subtree, hf_afdx_frame_counter, ds_tvb, sn_offset, 1, ENC_BIG_ENDIAN);
        
        if(previous_sn && ((guint16)256 + (guint16)sn - (guint16)*previous_sn) % 256 != 1) {
            expert_add_info_format(pinfo, ti, &ei_afdx_frame_number_gap, 
                                   _("Frame number gap: previous: %d, current: %d"),
                                   (guint)*previous_sn,
                                   (guint)sn
                                  );
        }
        
        if(afdx_assume_fcs) {
            guint fcs_offset = 0;

            guint32 received_fcs = afdx_get_fcs(ds_tvb, &fcs_offset);
        
            gchar* fcs_comment = _("validation disabled");
        
            gboolean bad_fcs = FALSE;
            guint32 true_fcs = 0;
        
            if(afdx_check_fcs) {
                true_fcs = crc32_802_tvb(ds_tvb, ds_tvb->length - 4);
                if(true_fcs == received_fcs) {
                    fcs_comment = _("correct");
                } else {
                    fcs_comment = _("incorrect, should be:");
                    bad_fcs = TRUE;
                }
            }

            if(!bad_fcs) {
                ti = proto_tree_add_uint_format_value(proto_subtree, hf_afdx_fcs, ds_tvb,
                                                    fcs_offset, 4, received_fcs,
                                                    "0x%08x [%s]", received_fcs, fcs_comment);
            } else {
                ti = proto_tree_add_uint_format_value(proto_subtree, hf_afdx_fcs, ds_tvb,
                                                    fcs_offset, 4, received_fcs,
                                                    "0x%08x [%s 0x%08x]", received_fcs, fcs_comment, true_fcs);                
            }

            if(bad_fcs) {
                expert_add_info(pinfo, ti, &ei_afdx_fcs_incorrect);
            }
        }
        
        return proto_subtree;
    }
    
    return NULL;
}

static int
dissect_afdx_heur(tvbuff_t *tvb, packet_info *pinfo, proto_tree *tree, void *data _U_)
{
    if(!afdx_enabled) {
        return 0;
    }
    
    ethertype_data_t ethertype_data;
    
    guint16 etype = tvb_get_ntohs(tvb, MAC_LENGTH * 2);
    
    guint16 ip_protocol = 0;
    if(tvb_offset_exists(tvb, ETHERNET_HEADER_LENGTH + 12)) {
        ip_protocol = tvb_get_ntohs(tvb, ETHERNET_HEADER_LENGTH + 8) & 0xFF;
    }
    
    gboolean can_be_afdx = etype == ETHERTYPE_IPv4 && ip_protocol == IP_PROTOCOL_UDP;
    vl_table_row_t* row = NULL;
    guint64 vl_id = 0;
    
    if(!can_be_afdx) {
        return 0;
    }
    
    if (can_be_afdx) {
        col_set_str(pinfo->cinfo, COL_PROTOCOL, "AFDX ");
        col_set_fence(pinfo->cinfo, COL_PROTOCOL);
        
        const guint8 *mac_dst_data = (const guint8*) pinfo->dl_dst.data;
        vl_id = mac_dst_data[4];
        vl_id <<= 8;
        vl_id |= mac_dst_data[5];
        
        gboolean is_vl_known = TRUE;
        
        if (vl_table) {
            row = g_hash_table_lookup(vl_table, &vl_id);
        }
        
        if(!pinfo->fd->flags.visited) {
            dissect_afdx_first_pass(pinfo, tvb, vl_id);
        }
        
        proto_tree* fh_tree = dissect_afdx(tvb, pinfo, tree, row, vl_id);
        
        
    }
    
    ethertype_data.etype = tvb_get_ntohs(tvb, MAC_LENGTH * 2);
    ethertype_data.offset_after_ethertype = ETHERNET_HEADER_LENGTH;
    ethertype_data.fh_tree = NULL;
    ethertype_data.etype_id = hf_eth_type;
    ethertype_data.trailer_id = 0;
    ethertype_data.fcs_len = 0;

    call_dissector_with_data(ethertype_handle, tvb, pinfo, tree, &ethertype_data);
    
    if(can_be_afdx) {
        /* Clear out stuff in the info column */
        col_clear(pinfo->cinfo, COL_INFO);
        
        col_append_fstr(pinfo->cinfo, COL_INFO, "VL ID: %#06llx", (unsigned long long)vl_id);
        
        if(pinfo->rec->presence_flags & WTAP_HAS_INTERFACE_ID) {
            const char *interface_name = epan_get_interface_name(pinfo->epan,
			    pinfo->rec->rec_header.packet_header.interface_id);
            if (interface_name) {
                col_append_fstr(pinfo->cinfo, COL_INFO, _(", Iface: %s"), interface_name);
            }
        }
        
        if(!row) {
            col_append_str(pinfo->cinfo, COL_INFO, _(" (Unknown VL ID)"));
        } else {
            col_append_fstr(pinfo->cinfo, COL_INFO, _(" (MTU: %d bytes; BAG: %d us; Jitter: %d us)"),
                            row->mtu, row->bag, row->jitter);
        }
    }
    
    return tvb_captured_length(tvb);
}

// translate the specified string member for all structs in struct array
#define TRANSLATE_ARRAY(array, member) \
do {   \
    unsigned i; \
    for(i = 0; i < array_length(array); ++i) \
    {   \
        if(array[i].member) array[i].member = _(array[i].member); \
    }   \
} while(0)

void
proto_register_afdx(void)
{
    if(iface_vl_table) {
        g_hash_table_destroy(iface_vl_table);
    }
    
    iface_vl_table = g_hash_table_new_full(g_str_hash,
                                            g_str_equal,
                                            g_free,
                                            g_free);
    bindtextdomain(GETTEXT_PACKAGE, LOCALE_PATH);
    
    static uat_field_t iface_table_fields[] = {
        UAT_FLD_CSTRING(iface_table_rows, iface_name, N_("Interface name"), N_("Interface name")),
        UAT_FLD_FILENAME_OTHER(iface_table_rows, filename, N_("VL ID list filename"), vl_list_file_chk_cb,
                               N_("A file with the list of valid VL ID ranges for this interface")),
        UAT_END_FIELDS
    };
    
    TRANSLATE_ARRAY(iface_table_fields, title);
    TRANSLATE_ARRAY(iface_table_fields, desc);
    
    uat_t* uat;
#ifdef UAT_AFFECTS_DISSECTION
    uat = uat_new(_("Valid VL table"),
                  sizeof(iface_table_row_t),
                  "valid_vl_table",
                  TRUE,
                  &iface_table_rows,
                  &num_iface_table_rows,
                  UAT_AFFECTS_DISSECTION,
                  _("A table with names of files with valid VL ID ranges for each interface"),
                  iface_table_copy_cb,
                  iface_table_update_cb,
                  iface_table_free_cb,
                  iface_table_initialize_cb,
		  NULL,
                  iface_table_fields
    );
#else
    uat = uat_new(_("Valid VL table"),
                  sizeof(iface_table_row_t),
                  "valid_vl_table",
                  TRUE,
                  &iface_table_rows,
                  &num_iface_table_rows,
                  UAT_CAT_GENERAL,
                  _("A table with names of files with valid VL ID ranges for each interface"),
                  iface_table_copy_cb,
                  iface_table_update_cb,
                  iface_table_free_cb,
                  iface_table_initialize_cb,
		  NULL,
                  iface_table_fields
    );    
#endif
    
    // TODO add blurbs
    static hf_register_info hf[] = {
        { &hf_afdx_vl_id,
          { N_("VL ID"),     "afdx.vl_id",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        N_("Virtual Link Identifier"), HFILL }},
        
        { &hf_afdx_time_delta,
          { N_("Time delta for previous packet of same VL"),     "afdx.vl_time_delta",
        FT_RELATIVE_TIME, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
        
        { &hf_afdx_mac_src,
          { N_("Source MAC"),     "afdx.mac_src",
        FT_ETHER, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
        { &hf_afdx_mac_dst,
          { N_("Destination MAC"),     "afdx.mac_dst",
        FT_ETHER, BASE_NONE, NULL, 0x0,
        NULL, HFILL }},
        { &hf_afdx_ip_dst,
          { N_("Destination IP"), "afdx.ip_dst", FT_IPv4, BASE_NONE,
        NULL, 0x0, NULL, HFILL }},
        { &hf_afdx_ip_src,
          { N_("Source IP"), "afdx.ip_src", FT_IPv4, BASE_NONE,
        NULL, 0x0, NULL, HFILL }},

        
        { &hf_afdx_mac_sender_network_id,
          { N_("Sender network ID"),     "afdx.mac_src.network_id",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},
        { &hf_afdx_mac_sender_device_id,
          { N_("Sender device ID"),     "afdx.mac_src.device_id",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},
        { &hf_afdx_mac_sender_device_direction,
          { N_("Sender device direction"),     "afdx.mac_src.device_direction",
        FT_UINT8, BASE_DEC, NULL, 0xe0,
        NULL, HFILL }},
        { &hf_afdx_mac_sender_device_location,
          { N_("Sender device location"),     "afdx.mac_src.device_location",
        FT_UINT8, BASE_DEC, NULL, 0x1f,
        NULL, HFILL }},
        { &hf_afdx_mac_sender_interface,
          { N_("Interface ID"),     "afdx.mac_src.interface_id",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        N_("AFDX interface identifier (1 - network A, 2 - network B)"), HFILL }},
        
        { &hf_afdx_ip_sender_network_id,
          { N_("Sender network ID"),     "afdx.ip_src.network_id",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},
        { &hf_afdx_ip_sender_device_id,
          { N_("Sender device ID"),     "afdx.ip_src.device_id",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},
        { &hf_afdx_ip_sender_device_direction,
          { N_("Sender device direction"),     "afdx.ip_src.device_direction",
        FT_UINT8, BASE_DEC, NULL, 0xe0,
        NULL, HFILL }},
        { &hf_afdx_ip_sender_device_location,
          { N_("Sender device location"),     "afdx.ip_src.device_location",
        FT_UINT8, BASE_DEC, NULL, 0x1f,
        NULL, HFILL }},
        { &hf_afdx_ip_sender_partition_id,
          { N_("Sender partition ID"),     "afdx.ip_src.partition_id",
        FT_UINT8, BASE_DEC, NULL, 0xe0,
        NULL, HFILL }},
        
        { &hf_afdx_ip_dst_network_id,
          { N_("Destinaion network ID"),     "afdx.ip_dst.network_id",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},
        { &hf_afdx_ip_dst_device_id,
          { N_("Destinaion device ID"),     "afdx.ip_dst.device_id",
        FT_UINT8, BASE_HEX, NULL, 0x0,
        NULL, HFILL }},
        { &hf_afdx_ip_dst_device_direction,
          { N_("Destinaion device direction"),     "afdx.ip_dst.device_direction",
        FT_UINT8, BASE_DEC, NULL, 0xe0,
        NULL, HFILL }},
        { &hf_afdx_ip_dst_device_location,
          { N_("Destinaion device location"),     "afdx.ip_dst.device_location",
        FT_UINT8, BASE_DEC, NULL, 0x1f,
        NULL, HFILL }},
        { &hf_afdx_ip_dst_partition_id,
          { N_("Partition ID"),     "afdx.ip_dst.partition_id",
        FT_UINT8, BASE_DEC, NULL, 0xe0,
        NULL, HFILL }},
        
        { &hf_afdx_ip_dst_vl_id,
          { N_("VL ID"),     "afdx.ip_dst.vl_id",
        FT_UINT16, BASE_HEX, NULL, 0x0,
        N_("Virtual Link Identifier"), HFILL }},
        
        { &hf_afdx_hw_interface,
          { N_("Hardware interface"), "afdx.hw_interface",
        FT_STRING, BASE_NONE, NULL, 0x0,
        N_("The hardware interface where the packet was actually captured"), HFILL }},
        
        { &hf_afdx_frame_counter,
            { N_("Frame counter"),     "afdx.frame_counter",
        FT_UINT8, BASE_DEC, NULL, 0x0,
        NULL, HFILL }},
        
	{ &hf_afdx_fcs,
        { N_("Frame check sequence"), "eth.fcs", FT_UINT32, BASE_HEX, NULL, 0x0,
            N_("Ethernet checksum"), HFILL }},
	
        { &hf_afdx_equipment,
            { N_("Equipment"),     "afdx.mac_dst.equipment",
        FT_STRING, BASE_NONE, NULL, 0x0,
        N_("Equipment name based on MAC destination"), HFILL }},
        { &hf_afdx_application,
            { N_("Application"),     "afdx.mac_dst.application",
        FT_STRING, BASE_NONE, NULL, 0x0,
        N_("Application name based on MAC destination"), HFILL }},

    };
    
    TRANSLATE_ARRAY(hf, hfinfo.name);
    TRANSLATE_ARRAY(hf, hfinfo.blurb);
    
    static gint* ett[] = {
        &ett_afdx,
        &ett_mac_dst,
        &ett_mac_src,
        &ett_mac_src_device_id,
        &ett_ip_src,
        &ett_ip_src_device_id,
        &ett_ip_dst,
        &ett_ip_dst_device_id
    };
    
    static ei_register_info ei[] = {
        { &ei_afdx_unknown_vl, { "afdx.vl_id.unknown", PI_PROTOCOL, PI_WARN, N_("Unknown Virtual Link ID"), EXPFILL }},
        { &ei_afdx_incorrect_vl, { "afdx.vl_id.incorrect", PI_PROTOCOL, PI_ERROR, N_("Incorrect Virtual Link ID for this interface"), EXPFILL }},
        { &ei_afdx_vl_range_not_specified, { "afdx.hw_interface.vl_range_not_specified", PI_PROTOCOL, PI_COMMENT, N_("Valid VL range not specified for this interface"), EXPFILL }},
        { &ei_afdx_bad_mtu, { "afdx.vl_mtu_violation", PI_SEQUENCE, PI_ERROR, N_("Frame size exceeds MTU"), EXPFILL }},
        { &ei_afdx_network_id_mismatch, { "afdx.sender_network_id_mismatch", PI_PROTOCOL, PI_WARN, N_("Sender Network ID in IP doesn't match Sender Network ID in MAC"), EXPFILL }},
        { &ei_afdx_device_id_mismatch, { "afdx.sender_device_id_mismatch", PI_PROTOCOL, PI_WARN, N_("Sender Device ID in IP doesn't match Sender Device ID in MAC"), EXPFILL }},
        { &ei_afdx_vl_bag_violation, { "afdx.vl_bag_violation", PI_PROTOCOL, PI_ERROR, N_("VL BAG violation"), EXPFILL }},
        { &ei_afdx_src_ip_not_unicast, { "afdx.ip_src.not_unicast", PI_PROTOCOL, PI_ERROR, N_("Source IP is not Class A"), EXPFILL }},
        { &ei_afdx_dst_ip_incorrect, { "afdx.ip_dst.incorrect", PI_PROTOCOL, PI_ERROR, N_("Destination IP is neither Class A nor Class D"), EXPFILL }},
        { &ei_afdx_dst_ip_vl_id_mismatch, { "afdx.ip_dst.vl_id_mismatch", PI_PROTOCOL, PI_WARN, N_("VL ID in dst IP does not match VL ID in dst MAC"), EXPFILL }},
        { &ei_afdx_frame_number_gap, { "afdx.frame_number_error", PI_SEQUENCE, PI_ERROR, N_("Frame number error"), EXPFILL }},
        { &ei_afdx_fcs_incorrect, { "afdx.fcs_bad", PI_PROTOCOL, PI_ERROR, N_("Incorrect FCS"), EXPFILL }},
    };
    
    TRANSLATE_ARRAY(ei, eiinfo.summary);
    
    proto_afdx = proto_register_protocol (
        _("Avionics Full-Duplex Switched Ethernet"), /* name       */
        "AFDX",      /* short name */
        "afdx"       /* abbrev     */
        );
    
    
    proto_register_field_array(proto_afdx, hf, array_length(hf));
    proto_register_subtree_array(ett, array_length(ett));
    
    expert_module_t* expert_afdx = expert_register_protocol(proto_afdx);
    expert_register_field_array(expert_afdx, ei, array_length(ei));
    
    afdx_prefs_module = prefs_register_protocol(proto_afdx, &afdx_prefs_changed);
    prefs_register_bool_preference(afdx_prefs_module, "enabled",
                 _("Enable AFDX dissection"),
                 _("If enabled, all UDP frames are interpreted as AFDX (rather than plain Ethernet)"),
                 &afdx_enabled);
    prefs_register_bool_preference(afdx_prefs_module, "assume_fcs",
                 _("Assume AFDX packets have FCS"),
                 _("If enabled, assume that all AFDX packets have Frame Check Sequence"),
                 &afdx_assume_fcs);
    prefs_register_bool_preference(afdx_prefs_module, "check_fcs",
                 _("Check FCS for AFDX packets"),
                 _("If enabled, check FCS for AFDX packets"),
                 &afdx_check_fcs);
    prefs_register_filename_preference(afdx_prefs_module, "file",
                 _("Parameters of Virtual Links"),
                 _("A CSV file containing VL ID, MTU, BAG and Jitter for each virtual link"),
                 &afdx_vl_table_file, 1);
    prefs_register_filename_preference(afdx_prefs_module, "dst_mac_equipment",
                _("Destination MAC equipment table"),
                _("A CSV file containing min dst MAC, max dst MAC, Equipment name and Application name for each equipment and application"),
                &afdx_mac_equipment_file, 1);
    prefs_register_uat_preference(afdx_prefs_module, "valid_vl_files",
                 _("Valid VLs"),
                 _("A table with names of files with valid VL ID ranges for each interface"),
                 uat);
}

void
proto_reg_handoff_afdx(void)
{       
    hf_eth_type = proto_registrar_get_id_byname("eth.type");

    ethertype_handle = find_dissector("ethertype");
    
    heur_dissector_add("eth", dissect_afdx_heur, "AFDX", "afdx", proto_afdx, 1);
}
