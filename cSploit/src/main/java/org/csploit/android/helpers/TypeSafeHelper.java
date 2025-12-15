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

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * TypeSafeHelper - Type-safe casting utilities to replace @SuppressWarnings("unchecked")
 *
 * Provides safe casting methods that avoid ClassCastException and eliminate the need
 * for unchecked cast warnings. These methods perform proper instanceof checks before
 * casting and return Optional or default values when casting fails.
 *
 * Usage:
 * {@code
 * // Instead of: Map<String, Object> map = (Map<String, Object>) obj;
 * Map<String, Object> map = TypeSafeHelper.asMap(obj, String.class, Object.class);
 *
 * // For optional values
 * Optional<List<String>> list = TypeSafeHelper.asListOptional(obj, String.class);
 *
 * // With default value
 * String value = TypeSafeHelper.asString(obj, "default");
 * }
 */
public final class TypeSafeHelper {

    private static final String TAG = "TypeSafeHelper";

    private TypeSafeHelper() {}

    // ==================== String Casting ====================

    /**
     * Safely cast an object to String.
     *
     * @param obj the object to cast
     * @return the String value, or null if not a String
     */
    @Nullable
    public static String asString(@Nullable Object obj) {
        if (obj instanceof String) {
            return (String) obj;
        }
        return obj != null ? obj.toString() : null;
    }

    /**
     * Safely cast an object to String with default value.
     *
     * @param obj the object to cast
     * @param defaultValue default value if casting fails
     * @return the String value, or defaultValue if not a String
     */
    @NonNull
    public static String asString(@Nullable Object obj, @NonNull String defaultValue) {
        if (obj instanceof String) {
            return (String) obj;
        }
        return obj != null ? obj.toString() : defaultValue;
    }

    /**
     * Safely cast an object to String, returning Optional.
     *
     * @param obj the object to cast
     * @return Optional containing String, or empty if not a String
     */
    @NonNull
    public static Optional<String> asStringOptional(@Nullable Object obj) {
        if (obj instanceof String) {
            return Optional.of((String) obj);
        }
        return Optional.empty();
    }

    // ==================== Integer Casting ====================

    /**
     * Safely cast an object to Integer.
     *
     * @param obj the object to cast
     * @return the Integer value, or null if not convertible
     */
    @Nullable
    public static Integer asInteger(@Nullable Object obj) {
        if (obj instanceof Integer) {
            return (Integer) obj;
        }
        if (obj instanceof Number) {
            return ((Number) obj).intValue();
        }
        if (obj instanceof String) {
            try {
                return Integer.parseInt((String) obj);
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return null;
    }

    /**
     * Safely cast an object to int with default value.
     *
     * @param obj the object to cast
     * @param defaultValue default value if casting fails
     * @return the int value, or defaultValue if not convertible
     */
    public static int asInt(@Nullable Object obj, int defaultValue) {
        Integer result = asInteger(obj);
        return result != null ? result : defaultValue;
    }

    // ==================== Long Casting ====================

    /**
     * Safely cast an object to Long.
     *
     * @param obj the object to cast
     * @return the Long value, or null if not convertible
     */
    @Nullable
    public static Long asLong(@Nullable Object obj) {
        if (obj instanceof Long) {
            return (Long) obj;
        }
        if (obj instanceof Number) {
            return ((Number) obj).longValue();
        }
        if (obj instanceof String) {
            try {
                return Long.parseLong((String) obj);
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return null;
    }

    /**
     * Safely cast an object to long with default value.
     *
     * @param obj the object to cast
     * @param defaultValue default value if casting fails
     * @return the long value, or defaultValue if not convertible
     */
    public static long asLong(@Nullable Object obj, long defaultValue) {
        Long result = asLong(obj);
        return result != null ? result : defaultValue;
    }

    // ==================== Double Casting ====================

    /**
     * Safely cast an object to Double.
     *
     * @param obj the object to cast
     * @return the Double value, or null if not convertible
     */
    @Nullable
    public static Double asDouble(@Nullable Object obj) {
        if (obj instanceof Double) {
            return (Double) obj;
        }
        if (obj instanceof Number) {
            return ((Number) obj).doubleValue();
        }
        if (obj instanceof String) {
            try {
                return Double.parseDouble((String) obj);
            } catch (NumberFormatException e) {
                return null;
            }
        }
        return null;
    }

    /**
     * Safely cast an object to double with default value.
     *
     * @param obj the object to cast
     * @param defaultValue default value if casting fails
     * @return the double value, or defaultValue if not convertible
     */
    public static double asDouble(@Nullable Object obj, double defaultValue) {
        Double result = asDouble(obj);
        return result != null ? result : defaultValue;
    }

    // ==================== Boolean Casting ====================

    /**
     * Safely cast an object to Boolean.
     *
     * @param obj the object to cast
     * @return the Boolean value, or null if not convertible
     */
    @Nullable
    public static Boolean asBoolean(@Nullable Object obj) {
        if (obj instanceof Boolean) {
            return (Boolean) obj;
        }
        if (obj instanceof String) {
            String str = (String) obj;
            if ("true".equalsIgnoreCase(str) || "1".equals(str)) {
                return Boolean.TRUE;
            }
            if ("false".equalsIgnoreCase(str) || "0".equals(str)) {
                return Boolean.FALSE;
            }
        }
        if (obj instanceof Number) {
            return ((Number) obj).intValue() != 0;
        }
        return null;
    }

    /**
     * Safely cast an object to boolean with default value.
     *
     * @param obj the object to cast
     * @param defaultValue default value if casting fails
     * @return the boolean value, or defaultValue if not convertible
     */
    public static boolean asBoolean(@Nullable Object obj, boolean defaultValue) {
        Boolean result = asBoolean(obj);
        return result != null ? result : defaultValue;
    }

    // ==================== List Casting ====================

    /**
     * Safely cast an object to a List.
     *
     * @param obj the object to cast
     * @param elementType the expected element type class
     * @param <T> the element type
     * @return the List, or empty list if not a List or wrong element type
     */
    @NonNull
    public static <T> List<T> asList(@Nullable Object obj, @NonNull Class<T> elementType) {
        if (!(obj instanceof List<?>)) {
            return Collections.emptyList();
        }
        List<?> list = (List<?>) obj;
        List<T> result = new ArrayList<>(list.size());
        for (Object item : list) {
            if (elementType.isInstance(item)) {
                result.add(elementType.cast(item));
            }
        }
        return result;
    }

    /**
     * Safely cast an object to a List, returning Optional.
     *
     * @param obj the object to cast
     * @param elementType the expected element type class
     * @param <T> the element type
     * @return Optional containing List, or empty if not a List
     */
    @NonNull
    public static <T> Optional<List<T>> asListOptional(@Nullable Object obj, @NonNull Class<T> elementType) {
        if (!(obj instanceof List<?>)) {
            return Optional.empty();
        }
        return Optional.of(asList(obj, elementType));
    }

    /**
     * Safely cast an object to a raw List.
     *
     * @param obj the object to cast
     * @return the List, or empty list if not a List
     */
    @NonNull
    public static List<?> asRawList(@Nullable Object obj) {
        if (obj instanceof List<?>) {
            return (List<?>) obj;
        }
        return Collections.emptyList();
    }

    // ==================== Map Casting ====================

    /**
     * Safely cast an object to a Map.
     *
     * @param obj the object to cast
     * @param keyType the expected key type class
     * @param valueType the expected value type class
     * @param <K> the key type
     * @param <V> the value type
     * @return the Map, or empty map if not a Map or wrong types
     */
    @NonNull
    public static <K, V> Map<K, V> asMap(@Nullable Object obj, @NonNull Class<K> keyType, @NonNull Class<V> valueType) {
        if (!(obj instanceof Map<?, ?>)) {
            return Collections.emptyMap();
        }
        Map<?, ?> map = (Map<?, ?>) obj;
        Map<K, V> result = new HashMap<>();
        for (Map.Entry<?, ?> entry : map.entrySet()) {
            if (keyType.isInstance(entry.getKey()) && valueType.isInstance(entry.getValue())) {
                result.put(keyType.cast(entry.getKey()), valueType.cast(entry.getValue()));
            }
        }
        return result;
    }

    /**
     * Safely cast an object to a Map, returning Optional.
     *
     * @param obj the object to cast
     * @param keyType the expected key type class
     * @param valueType the expected value type class
     * @param <K> the key type
     * @param <V> the value type
     * @return Optional containing Map, or empty if not a Map
     */
    @NonNull
    public static <K, V> Optional<Map<K, V>> asMapOptional(@Nullable Object obj, @NonNull Class<K> keyType, @NonNull Class<V> valueType) {
        if (!(obj instanceof Map<?, ?>)) {
            return Optional.empty();
        }
        return Optional.of(asMap(obj, keyType, valueType));
    }

    /**
     * Safely cast an object to a raw Map.
     *
     * @param obj the object to cast
     * @return the Map, or empty map if not a Map
     */
    @NonNull
    public static Map<?, ?> asRawMap(@Nullable Object obj) {
        if (obj instanceof Map<?, ?>) {
            return (Map<?, ?>) obj;
        }
        return Collections.emptyMap();
    }

    /**
     * Safely cast an object to a Map with Object values (common for RPC responses).
     *
     * @param obj the object to cast
     * @return the Map, or empty map if not a Map
     */
    @NonNull
    public static Map<String, Object> asStringObjectMap(@Nullable Object obj) {
        return asMap(obj, String.class, Object.class);
    }

    // ==================== Generic Casting ====================

    /**
     * Safely cast an object to a specific type.
     *
     * @param obj the object to cast
     * @param type the expected type class
     * @param <T> the expected type
     * @return the cast object, or null if not the expected type
     */
    @Nullable
    public static <T> T as(@Nullable Object obj, @NonNull Class<T> type) {
        if (type.isInstance(obj)) {
            return type.cast(obj);
        }
        return null;
    }

    /**
     * Safely cast an object to a specific type with default value.
     *
     * @param obj the object to cast
     * @param type the expected type class
     * @param defaultValue default value if casting fails
     * @param <T> the expected type
     * @return the cast object, or defaultValue if not the expected type
     */
    @NonNull
    public static <T> T as(@Nullable Object obj, @NonNull Class<T> type, @NonNull T defaultValue) {
        if (type.isInstance(obj)) {
            return type.cast(obj);
        }
        return defaultValue;
    }

    /**
     * Safely cast an object to a specific type, returning Optional.
     *
     * @param obj the object to cast
     * @param type the expected type class
     * @param <T> the expected type
     * @return Optional containing cast object, or empty if not the expected type
     */
    @NonNull
    public static <T> Optional<T> asOptional(@Nullable Object obj, @NonNull Class<T> type) {
        if (type.isInstance(obj)) {
            return Optional.of(type.cast(obj));
        }
        return Optional.empty();
    }

    // ==================== Byte Array Casting ====================

    /**
     * Safely cast an object to byte array.
     *
     * @param obj the object to cast
     * @return the byte array, or null if not a byte array
     */
    @Nullable
    public static byte[] asByteArray(@Nullable Object obj) {
        if (obj instanceof byte[]) {
            return (byte[]) obj;
        }
        return null;
    }

    /**
     * Safely cast an object to byte array with default value.
     *
     * @param obj the object to cast
     * @param defaultValue default value if casting fails
     * @return the byte array, or defaultValue if not a byte array
     */
    @NonNull
    public static byte[] asByteArray(@Nullable Object obj, @NonNull byte[] defaultValue) {
        if (obj instanceof byte[]) {
            return (byte[]) obj;
        }
        return defaultValue;
    }

    // ==================== Array Casting ====================

    /**
     * Safely cast an object to an array of specified type.
     *
     * @param obj the object to cast
     * @param elementType the array element type
     * @param <T> the element type
     * @return the array, or null if not an array of the expected type
     */
    @Nullable
    @SuppressWarnings("unchecked")
    public static <T> T[] asArray(@Nullable Object obj, @NonNull Class<T> elementType) {
        if (obj == null) {
            return null;
        }
        Class<?> objClass = obj.getClass();
        if (!objClass.isArray()) {
            return null;
        }
        Class<?> componentType = objClass.getComponentType();
        if (componentType != null && elementType.isAssignableFrom(componentType)) {
            return (T[]) obj;
        }
        return null;
    }

    // ==================== Validation Helpers ====================

    /**
     * Check if an object is a List.
     *
     * @param obj the object to check
     * @return true if the object is a List
     */
    public static boolean isList(@Nullable Object obj) {
        return obj instanceof List<?>;
    }

    /**
     * Check if an object is a Map.
     *
     * @param obj the object to check
     * @return true if the object is a Map
     */
    public static boolean isMap(@Nullable Object obj) {
        return obj instanceof Map<?, ?>;
    }

    /**
     * Check if an object is a number.
     *
     * @param obj the object to check
     * @return true if the object is a Number
     */
    public static boolean isNumber(@Nullable Object obj) {
        return obj instanceof Number;
    }

    /**
     * Check if an object is of a specific type.
     *
     * @param obj the object to check
     * @param type the expected type class
     * @return true if the object is of the expected type
     */
    public static boolean isType(@Nullable Object obj, @NonNull Class<?> type) {
        return type.isInstance(obj);
    }

    // ==================== Map Value Extraction ====================

    /**
     * Safely get a String value from a Map.
     *
     * @param map the map to get value from
     * @param key the key to look up
     * @return the String value, or null if not found or not a String
     */
    @Nullable
    public static String getMapString(@Nullable Map<?, ?> map, @NonNull Object key) {
        if (map == null) {
            return null;
        }
        return asString(map.get(key));
    }

    /**
     * Safely get a String value from a Map with default.
     *
     * @param map the map to get value from
     * @param key the key to look up
     * @param defaultValue default value if not found
     * @return the String value, or defaultValue if not found or not a String
     */
    @NonNull
    public static String getMapString(@Nullable Map<?, ?> map, @NonNull Object key, @NonNull String defaultValue) {
        if (map == null) {
            return defaultValue;
        }
        return asString(map.get(key), defaultValue);
    }

    /**
     * Safely get an int value from a Map.
     *
     * @param map the map to get value from
     * @param key the key to look up
     * @param defaultValue default value if not found
     * @return the int value, or defaultValue if not found or not a number
     */
    public static int getMapInt(@Nullable Map<?, ?> map, @NonNull Object key, int defaultValue) {
        if (map == null) {
            return defaultValue;
        }
        return asInt(map.get(key), defaultValue);
    }

    /**
     * Safely get a long value from a Map.
     *
     * @param map the map to get value from
     * @param key the key to look up
     * @param defaultValue default value if not found
     * @return the long value, or defaultValue if not found or not a number
     */
    public static long getMapLong(@Nullable Map<?, ?> map, @NonNull Object key, long defaultValue) {
        if (map == null) {
            return defaultValue;
        }
        return asLong(map.get(key), defaultValue);
    }

    /**
     * Safely get a boolean value from a Map.
     *
     * @param map the map to get value from
     * @param key the key to look up
     * @param defaultValue default value if not found
     * @return the boolean value, or defaultValue if not found or not a boolean
     */
    public static boolean getMapBoolean(@Nullable Map<?, ?> map, @NonNull Object key, boolean defaultValue) {
        if (map == null) {
            return defaultValue;
        }
        return asBoolean(map.get(key), defaultValue);
    }

    /**
     * Safely get a List value from a Map.
     *
     * @param map the map to get value from
     * @param key the key to look up
     * @param elementType the expected list element type
     * @param <T> the element type
     * @return the List, or empty list if not found or not a List
     */
    @NonNull
    public static <T> List<T> getMapList(@Nullable Map<?, ?> map, @NonNull Object key, @NonNull Class<T> elementType) {
        if (map == null) {
            return Collections.emptyList();
        }
        return asList(map.get(key), elementType);
    }

    /**
     * Safely get a nested Map value from a Map.
     *
     * @param map the map to get value from
     * @param key the key to look up
     * @return the nested Map, or empty map if not found or not a Map
     */
    @NonNull
    public static Map<String, Object> getNestedMap(@Nullable Map<?, ?> map, @NonNull Object key) {
        if (map == null) {
            return Collections.emptyMap();
        }
        return asStringObjectMap(map.get(key));
    }
}
