/*
 * This file is part of cSploit.
 *
 * cSploit is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * cSploit is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with cSploit.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.csploit.android.helpers;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.util.Map;

/**
 * Helper class for safe Map operations.
 * Provides utilities for safely accessing nested maps and handling null values.
 *
 * This addresses the common pattern of unsafe nested .get() calls like:
 * map.get(key1).get(key2) - which throws NPE if key1 returns null
 */
public final class MapHelper {

    private static final String TAG = "MapHelper";

    /**
     * Safely get a value from a map.
     *
     * @param map The map to get from
     * @param key The key to look up
     * @param <K> Key type
     * @param <V> Value type
     * @return The value, or null if map is null or key not found
     */
    @Nullable
    public static <K, V> V get(@Nullable Map<K, V> map, @Nullable K key) {
        if (map == null || key == null) {
            return null;
        }
        return map.get(key);
    }

    /**
     * Safely get a value from a map with a default fallback.
     *
     * @param map The map to get from
     * @param key The key to look up
     * @param defaultValue The default value if not found
     * @param <K> Key type
     * @param <V> Value type
     * @return The value, or defaultValue if map is null or key not found
     */
    @NonNull
    public static <K, V> V getOrDefault(@Nullable Map<K, V> map, @Nullable K key, @NonNull V defaultValue) {
        V value = get(map, key);
        return value != null ? value : defaultValue;
    }

    /**
     * Safely get a String value from a map.
     *
     * @param map The map to get from
     * @param key The key to look up
     * @return The String value, or null if not found or not a String
     */
    @Nullable
    public static String getString(@Nullable Map<?, ?> map, @Nullable Object key) {
        if (map == null || key == null) {
            return null;
        }
        Object value = map.get(key);
        return value instanceof String ? (String) value : null;
    }

    /**
     * Safely get a String value from a map with default.
     *
     * @param map The map to get from
     * @param key The key to look up
     * @param defaultValue The default value if not found
     * @return The String value, or defaultValue if not found
     */
    @NonNull
    public static String getStringOrDefault(@Nullable Map<?, ?> map, @Nullable Object key, @NonNull String defaultValue) {
        String value = getString(map, key);
        return value != null ? value : defaultValue;
    }

    /**
     * Safely get an Integer value from a map.
     *
     * @param map The map to get from
     * @param key The key to look up
     * @return The Integer value, or null if not found or not an Integer
     */
    @Nullable
    public static Integer getInt(@Nullable Map<?, ?> map, @Nullable Object key) {
        if (map == null || key == null) {
            return null;
        }
        Object value = map.get(key);
        if (value instanceof Integer) {
            return (Integer) value;
        } else if (value instanceof Number) {
            return ((Number) value).intValue();
        } else if (value instanceof String) {
            try {
                return Integer.parseInt((String) value);
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return null;
    }

    /**
     * Safely get an int value from a map with default.
     *
     * @param map The map to get from
     * @param key The key to look up
     * @param defaultValue The default value if not found
     * @return The int value, or defaultValue if not found
     */
    public static int getIntOrDefault(@Nullable Map<?, ?> map, @Nullable Object key, int defaultValue) {
        Integer value = getInt(map, key);
        return value != null ? value : defaultValue;
    }

    /**
     * Safely get a Long value from a map.
     *
     * @param map The map to get from
     * @param key The key to look up
     * @return The Long value, or null if not found or not a Long
     */
    @Nullable
    public static Long getLong(@Nullable Map<?, ?> map, @Nullable Object key) {
        if (map == null || key == null) {
            return null;
        }
        Object value = map.get(key);
        if (value instanceof Long) {
            return (Long) value;
        } else if (value instanceof Number) {
            return ((Number) value).longValue();
        } else if (value instanceof String) {
            try {
                return Long.parseLong((String) value);
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return null;
    }

    /**
     * Safely get a Boolean value from a map.
     *
     * @param map The map to get from
     * @param key The key to look up
     * @return The Boolean value, or null if not found or not a Boolean
     */
    @Nullable
    public static Boolean getBoolean(@Nullable Map<?, ?> map, @Nullable Object key) {
        if (map == null || key == null) {
            return null;
        }
        Object value = map.get(key);
        if (value instanceof Boolean) {
            return (Boolean) value;
        } else if (value instanceof String) {
            String strVal = ((String) value).toLowerCase();
            if ("true".equals(strVal) || "1".equals(strVal) || "yes".equals(strVal)) {
                return true;
            } else if ("false".equals(strVal) || "0".equals(strVal) || "no".equals(strVal)) {
                return false;
            }
        } else if (value instanceof Number) {
            return ((Number) value).intValue() != 0;
        }
        return null;
    }

    /**
     * Safely get a boolean value from a map with default.
     *
     * @param map The map to get from
     * @param key The key to look up
     * @param defaultValue The default value if not found
     * @return The boolean value, or defaultValue if not found
     */
    public static boolean getBooleanOrDefault(@Nullable Map<?, ?> map, @Nullable Object key, boolean defaultValue) {
        Boolean value = getBoolean(map, key);
        return value != null ? value : defaultValue;
    }

    /**
     * Safely get a nested Map value.
     *
     * @param map The map to get from
     * @param key The key to look up
     * @return The nested Map, or null if not found or not a Map
     */
    @SuppressWarnings("unchecked")
    @Nullable
    public static <K, V> Map<K, V> getMap(@Nullable Map<?, ?> map, @Nullable Object key) {
        if (map == null || key == null) {
            return null;
        }
        Object value = map.get(key);
        return value instanceof Map ? (Map<K, V>) value : null;
    }

    /**
     * Safely traverse nested maps using multiple keys.
     * This replaces unsafe chains like: map.get(k1).get(k2).get(k3)
     *
     * @param map The root map
     * @param keys The keys to traverse
     * @return The final value, or null if any step is null
     */
    @SuppressWarnings("unchecked")
    @Nullable
    public static Object getPath(@Nullable Map<?, ?> map, @NonNull Object... keys) {
        if (map == null || keys.length == 0) {
            return null;
        }

        Object current = map;
        for (Object key : keys) {
            if (!(current instanceof Map)) {
                return null;
            }
            current = ((Map<?, ?>) current).get(key);
            if (current == null) {
                return null;
            }
        }
        return current;
    }

    /**
     * Safely get a String from nested maps.
     *
     * @param map The root map
     * @param keys The keys to traverse
     * @return The String value, or null if path is invalid
     */
    @Nullable
    public static String getPathString(@Nullable Map<?, ?> map, @NonNull Object... keys) {
        Object value = getPath(map, keys);
        return value instanceof String ? (String) value : null;
    }

    /**
     * Safely get an Integer from nested maps.
     *
     * @param map The root map
     * @param keys The keys to traverse
     * @return The Integer value, or null if path is invalid
     */
    @Nullable
    public static Integer getPathInt(@Nullable Map<?, ?> map, @NonNull Object... keys) {
        Object value = getPath(map, keys);
        if (value instanceof Integer) {
            return (Integer) value;
        } else if (value instanceof Number) {
            return ((Number) value).intValue();
        }
        return null;
    }

    /**
     * Check if a map contains a key (null-safe).
     *
     * @param map The map to check
     * @param key The key to look for
     * @return true if map is not null and contains the key
     */
    public static boolean containsKey(@Nullable Map<?, ?> map, @Nullable Object key) {
        return map != null && key != null && map.containsKey(key);
    }

    /**
     * Check if a map contains a non-null value for a key.
     *
     * @param map The map to check
     * @param key The key to look for
     * @return true if map contains a non-null value for the key
     */
    public static boolean hasValue(@Nullable Map<?, ?> map, @Nullable Object key) {
        return get(map, key) != null;
    }

    /**
     * Get the size of a map (null-safe).
     *
     * @param map The map
     * @return The size, or 0 if null
     */
    public static int size(@Nullable Map<?, ?> map) {
        return map == null ? 0 : map.size();
    }

    /**
     * Check if a map is null or empty.
     *
     * @param map The map to check
     * @return true if null or empty
     */
    public static boolean isEmpty(@Nullable Map<?, ?> map) {
        return map == null || map.isEmpty();
    }

    /**
     * Check if a map is not null and not empty.
     *
     * @param map The map to check
     * @return true if not null and not empty
     */
    public static boolean isNotEmpty(@Nullable Map<?, ?> map) {
        return map != null && !map.isEmpty();
    }

    private MapHelper() {
        // Prevent instantiation
    }
}
