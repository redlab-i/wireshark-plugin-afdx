/* afdx_utilities.h
 *
 * Utilities for AFDX wireshark plugin -- header file
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

#ifndef __AFDX_UTILITIES_H_
#define __AFDX_UTILITIES_H_

#include <glib.h>

#include <epan/range.h>

/// Returns MAC address or -1 on failure
gint64 parse_mac(const gchar* mac_str);

/// Callback for reading a row of CSV file
typedef gboolean (*csv_read_row_cb)(const gchar** fields, void* user_data);

/// Read CSV file row-by-row
gboolean process_csv_file(const char* filename, csv_read_row_cb callback, void* user_data);

/// Load a comma or newline-separated list of ranges from a file. Ranges can be specified in dec or hex
range_t* load_range_from_file(const gchar* filename, const char** err, guint32 max_value);

/// Merge two ranges
range_t* merge_ranges(range_t* first, range_t* second);

/// Convert a string containing a list of comma-separated hex ranges 
/// to a string containing a list of comma-separated decimal ranges.
/// We need to understand ranges of hex values (i.e. 0x00-0xff).
/// Unfortunately, range_convert_str() from wireshark only understands decimal ranges,
/// so we need to convert every number in range_str to decimal
/// before calling range_convert_str()
gchar* convert_range_str_to_dec(gchar* range_str);

#endif
