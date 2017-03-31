/* interval_map.h
 *
 * Interval map AFDX wireshark plugin -- header file
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

#ifndef __INTERVAL_MAP_H__
#define __INTERVAL_MAP_H__

/// \file interval_map.h Defines a wmem-style data structure containing non-overlapping closed intervals
/// that maps a closed interval to a value.

#include <epan/wmem/wmem_tree.h>

typedef struct {
    wmem_tree_t* tree;
    wmem_allocator_t *slave;
} interval_map_t;

/// Creates and interval map with two allocation scopes (a la wmem_tree_new_autoreset)
interval_map_t* interval_map_new_autoreset(wmem_allocator_t *master, wmem_allocator_t *slave);

/// Tries to insert an interval into interval map.
/// If the interval being inserted overlaps with an existing interval in the map,
/// does not change the map and returns false.
/// This function is log time on the number of intervals in the map
gboolean interval_map_insert(interval_map_t* map, gint64 left, gint64 right, void* value);

/// Looks up a value in the map that corresponds to an interval containing key
void* interval_map_lookup(interval_map_t* map, gint64 key);

#endif
