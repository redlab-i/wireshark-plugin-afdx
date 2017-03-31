/* interval_map.c
 *
 * Interval map AFDX wireshark plugin -- source file
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

#include "interval_map.h"

typedef struct {
    gint64 left;
    gint64 right;
    void* value;
} interval_map_value_int;

interval_map_t* interval_map_new_autoreset(wmem_allocator_t *master, wmem_allocator_t *slave) {
    interval_map_t* result = wmem_new0(master, interval_map_t);
    result->tree = wmem_tree_new_autoreset(master, slave);
    result->slave = slave;
    return result;
}

gboolean interval_contains(interval_map_value_int* interval, gint64 value) {
    return interval->left <= value && value <= interval->right;
}

gboolean interval_map_check(void* value, void* user_data) {
    interval_map_value_int* current_interval = (interval_map_value_int*) value;
    
    interval_map_value_int* new_interval = (interval_map_value_int*) user_data;
    
    return interval_contains(current_interval, new_interval->left)
        || interval_contains(current_interval, new_interval->right)
        || interval_contains(new_interval, current_interval->left)
        || interval_contains(new_interval, current_interval->right);
}

#define MAKE_KEY(array_key, key1, key2) wmem_tree_key_t array_key[3]; \
guint32 key1_var = (guint32)key1; \
guint32 key2_var = (guint32)key2; \
array_key[0].length = 1; \
array_key[0].key = &key1_var; \
array_key[1].length = 1; \
array_key[1].key = &key2_var; \
array_key[2].length = 0; \
array_key[2].key = NULL;

#define MAKE_KEY_FROM_INT64(array_key, v) MAKE_KEY(array_key, (v >> 32), (v & 0xFFFFFFFF));

gboolean interval_map_insert(interval_map_t* map, gint64 left, gint64 right, void* value) {
    interval_map_value_int* value_int = wmem_new0(map->slave, interval_map_value_int);
    value_int->left = left;
    value_int->right = right;
    value_int->value = value;
    
    {// we need a new scope because MAKE_KEY_FROM_INT64 declares variables
        MAKE_KEY_FROM_INT64(array_key, right);
        interval_map_value_int* candidate = (interval_map_value_int*) 
            wmem_tree_lookup32_array_le(map->tree, array_key);
        
        if(candidate && (interval_contains(candidate, left)
            || interval_contains(candidate, right)
            || interval_contains(value_int, candidate->left)
            || interval_contains(value_int, candidate->right))
        ) {
            // The interval being inserted intersects with an existing interval,
            // don't insert it
            wmem_free(map->slave, value_int);
            return FALSE;
        }
    }
    
    {
        MAKE_KEY_FROM_INT64(array_key, left);
        
        wmem_tree_insert32_array(map->tree, array_key, value_int);
    }
    
    return TRUE;
}

void* interval_map_lookup(interval_map_t* map, gint64 key) {
    MAKE_KEY_FROM_INT64(array_key, key);
    
    interval_map_value_int* value_int = (interval_map_value_int*) 
        wmem_tree_lookup32_array_le(map->tree, array_key);
    if(!value_int || !interval_contains(value_int, key)) {
        return NULL;
    }
    
    return value_int->value;
}
