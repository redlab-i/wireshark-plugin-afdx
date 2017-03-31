/* afdx_utilities.c
 *
 * Utilities for AFDX wireshark plugin -- source file
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

#include "afdx_utilities.h"

#include <csv.h>

#include <string.h>

gint64 parse_mac(const gchar* mac_str) {
    gint64 result = 0;
    
    gchar** bytes = g_strsplit_set(mac_str, " :", 0);
    
    if(!bytes) {
        return -1;
    }
    
    int i = 0;
    gchar** p = bytes;
    while(*p) {
        gchar* current_byte_str = *p;
        ++p;
        
        if(!current_byte_str) {
            return -1;
        }
        
        while(g_ascii_isspace(*current_byte_str)) ++current_byte_str;
        
        if(!current_byte_str[0]) {
            continue;
        }
        
        gchar* endptr = NULL;
        // TODO maybe use 0 instead of 16 for base to allow strage MAC addresses
        guint64 current_byte = g_ascii_strtoull(current_byte_str, &endptr, 16);
        if(endptr == current_byte_str || current_byte > 0xFF) {
            return -1;
        }
        
        result <<= 8;
        result |= current_byte;
        ++i;
    }
    
    if(i != 6) {
        // MAC address must have 6 bytes
        return -1;
    }
    
    g_strfreev(bytes);
    
    return result;
}

struct parsing_helper {
    // Array where we collect fields of one record
    GArray* string_array;
    
    csv_read_row_cb cb;
    void* external_user_data;
    
    gboolean error;
};

typedef struct parsing_helper parsing_helper;

void csv_field_cb(void* field_data, size_t byte_count, void* user_data) {
   parsing_helper* helper = (parsing_helper*) user_data;
   if(!helper->string_array) {
       helper->string_array = g_array_new(TRUE, TRUE, sizeof(gchar*));
   }
   
   gchar* field = (gchar*) field_data;
   // TODO maybe strip spaces here
   
   gchar* field_dup = g_strndup(field, byte_count);
   g_array_append_val(helper->string_array, field_dup);
}

void csv_record_cb(int end_char, void* user_data) {
    parsing_helper* helper = (parsing_helper*) user_data;
    if(!helper->string_array) {
       return;
    }
    
    gchar** fields = (gchar**)helper->string_array->data;
    
    helper->error = helper->error 
        || !helper->cb((const gchar**)fields, helper->external_user_data);
    
    g_array_free(helper->string_array, FALSE);
    helper->string_array = NULL;
    
    g_strfreev(fields);
}

gboolean 
process_csv_file(const char* filename, csv_read_row_cb callback, void* user_data)
{
    gchar* csv_file_contents = NULL;
    GError* error;
    gboolean ok = g_file_get_contents(filename, &csv_file_contents, NULL, &error);
    if(!ok) {
        return FALSE;
    }
    
    struct csv_parser p;
    struct parsing_helper helper;
    helper.string_array = NULL;
    helper.cb = callback;
    helper.external_user_data = user_data;
    helper.error = FALSE;
    
    csv_init(&p, CSV_APPEND_NULL);
    size_t len = strlen(csv_file_contents);
    size_t processed = csv_parse(&p, csv_file_contents, len, &csv_field_cb, &csv_record_cb, &helper);
    csv_fini(&p, &csv_field_cb, &csv_record_cb, &helper);
    
    return (processed == len) && !helper.error;
}

range_t* merge_ranges(range_t* first, range_t* second) {
    // range_convert_range() makes ep-allocated string, so
    // it seems we need not worry about freeing it
    char* first_str = range_convert_range(NULL, first);
    if(!first_str) {
        first_str = "";
    }
    char* second_str = range_convert_range(NULL, second);
    if(!second_str) {
        second_str = "";
    }
    
    range_t* result = NULL;
    
    if(!*first_str && !*second_str) {
        return range_empty();
    } else if(*first_str && !*second_str) {
        convert_ret_t r = range_convert_str(&result, first_str, G_MAXUINT32);
        if(r == CVT_NO_ERROR) {
            return result;
        } else {
            g_free(result);
            return NULL;
        }
    } else if (!*first_str && *second_str) {
        convert_ret_t r = range_convert_str(&result, second_str, G_MAXUINT32);
        if(r == CVT_NO_ERROR) {
            return result;
        } else {
            g_free(result);
            return NULL;
        }
    }
    
    gchar* joined_str = g_strjoin(",", first_str, second_str, NULL);
    convert_ret_t r = range_convert_str(&result, joined_str, G_MAXUINT32);
    g_free(joined_str);
    if(r == CVT_NO_ERROR) {
        return result;
    } else {
        g_free(result);
        return NULL;
    }
}

gchar* convert_range_str_to_dec(gchar* range_str) {
    if(!range_str) {
        return NULL;
    }
    
    GString* result = g_string_new("");
    GString* temp = g_string_new("");
    
    while(TRUE) {
        if(g_ascii_isdigit(*range_str)
            || (*range_str >= 'a' && *range_str <= 'f') 
            || (*range_str >= 'A' && *range_str <= 'F')
            || (*range_str == 'x')
            || (*range_str == 'X')
        ) {
            g_string_append_c(temp, *range_str);
        } else {
            if(temp->str[0]) {
                gchar* endptr = NULL;
                guint64 value = g_ascii_strtoull(temp->str, &endptr, 0);
                if(endptr == temp->str) {
                    // we failed to parse the number, just append str from temp
                    g_string_append(result, temp->str);
                } else {
                    gchar* decimal_str = g_strdup_printf("%" G_GUINT64_FORMAT, value);
                    g_string_append(result, decimal_str);
                    g_free(decimal_str);
                }
                
                g_string_assign(temp, "");
            }
            
            g_string_append_c(result, *range_str);
        }
        
        if(!(*range_str)) {
            break;
        }
        
        ++range_str;
    }
    
    g_string_free(temp, TRUE);
    gchar* result_str = result->str;
    g_string_free(result, FALSE);
    return result_str;
}

gchar* process_file_contents(gchar* contents) {
    // remove whitespace and comments (from # to EOL), join lines containing content with ','
    gchar** lines = g_strsplit_set(contents, "\r\n", -1);
    GString* result = g_string_new("");
    gboolean prepend_comma = FALSE;
    gboolean content_after_comma = FALSE;
    
    gchar** original_lines = lines;
    while(*lines) {
        gchar* current_line = *lines;
        
        while(*current_line) {
            if(*current_line == '#') {
                break;
            }
            
            if(!g_ascii_isspace(*current_line)) {
                if(prepend_comma) {
                    g_string_append_c(result, ',');
                    prepend_comma = FALSE;
                }
                g_string_append_c(result, *current_line);
                content_after_comma = TRUE;
            }
            
            ++current_line;
        }
        
        if(content_after_comma) {
            prepend_comma = TRUE;
            content_after_comma = FALSE;
        }
        
        ++lines;
    }
    
    g_strfreev(original_lines);
    
    gchar* result_str = result->str;
    g_string_free(result, FALSE);
    return result_str;
}

range_t* load_range_from_file(const gchar* filename, const char** err, guint32 max_value) {
    char *contents = NULL;
    char* local_err = NULL;
    if(!err) err = (const char**) &local_err;
    
    gboolean ok = g_file_get_contents(filename, &contents, NULL, NULL);
    if(!ok) {
        *err = g_strdup_printf("Error opening file '%s' for reading", filename);
        g_print("%s\n", *err);
        return NULL;
    }
        
    gchar* processed_contents = process_file_contents(contents);
    g_free(contents);
    
    gchar* converted_contents = convert_range_str_to_dec(processed_contents);
    g_free(processed_contents);
    
    range_t* result = NULL;
    convert_ret_t r = range_convert_str(&result, converted_contents, max_value);
    g_free(converted_contents);
    
    if(r == CVT_SYNTAX_ERROR) {
        *err = g_strdup_printf("Error reading file '%s': syntax error", filename);
        g_print("%s\n", *err);
        g_free(result);
        g_free(local_err);
        return NULL;
    } else if (r == CVT_NUMBER_TOO_BIG) {
        *err = g_strdup_printf("Error reading file '%s': one of specified values is out of bounds", filename);
        g_print("%s\n", *err);
        g_free(result);
        g_free(local_err);
        return NULL;
    } else {
        return result;
    }
}
