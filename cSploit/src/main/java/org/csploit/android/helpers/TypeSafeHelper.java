package org.csploit.android.helpers;

import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

/**
 * Utility class for safe type casting and conversion of arbitrary objects,
 * commonly used when parsing loosely-typed data structures (e.g. JSON/MsgPack maps).
 */
public class TypeSafeHelper {

    private TypeSafeHelper() {}

    // ==================== String ====================

    /** Convert any non-null object to String via toString(), or return null for null input. */
    public static String asString(Object obj) {
        if (obj == null) return null;
        return obj.toString();
    }

    /** Return obj.toString() if non-null, else defaultValue. */
    public static String asString(Object obj, String defaultValue) {
        if (obj == null) return defaultValue;
        return obj.toString();
    }

    /** Return Optional of obj if it is a String instance, else Optional.empty(). */
    public static Optional<String> asStringOptional(Object obj) {
        if (obj instanceof String) return Optional.of((String) obj);
        return Optional.empty();
    }

    // ==================== Integer ====================

    public static Integer asInteger(Object obj) {
        if (obj == null) return null;
        if (obj instanceof Integer) return (Integer) obj;
        if (obj instanceof Number) return ((Number) obj).intValue();
        if (obj instanceof String) {
            try { return Integer.parseInt((String) obj); } catch (NumberFormatException e) { return null; }
        }
        return null;
    }

    public static int asInt(Object obj, int defaultValue) {
        Integer result = asInteger(obj);
        return result != null ? result : defaultValue;
    }

    // ==================== Long ====================

    public static Long asLong(Object obj) {
        if (obj == null) return null;
        if (obj instanceof Long) return (Long) obj;
        if (obj instanceof Number) return ((Number) obj).longValue();
        if (obj instanceof String) {
            try { return Long.parseLong((String) obj); } catch (NumberFormatException e) { return null; }
        }
        return null;
    }

    public static long asLong(Object obj, long defaultValue) {
        Long result = asLong(obj);
        return result != null ? result : defaultValue;
    }

    // ==================== Double ====================

    public static Double asDouble(Object obj) {
        if (obj == null) return null;
        if (obj instanceof Double) return (Double) obj;
        if (obj instanceof Number) return ((Number) obj).doubleValue();
        if (obj instanceof String) {
            try { return Double.parseDouble((String) obj); } catch (NumberFormatException e) { return null; }
        }
        return null;
    }

    public static double asDouble(Object obj, double defaultValue) {
        Double result = asDouble(obj);
        return result != null ? result : defaultValue;
    }

    // ==================== Boolean ====================

    public static Boolean asBoolean(Object obj) {
        if (obj == null) return null;
        if (obj instanceof Boolean) return (Boolean) obj;
        if (obj instanceof Number) return ((Number) obj).intValue() != 0;
        if (obj instanceof String) {
            String s = (String) obj;
            if (s.equalsIgnoreCase("true") || s.equals("1")) return Boolean.TRUE;
            if (s.equalsIgnoreCase("false") || s.equals("0")) return Boolean.FALSE;
            return null;
        }
        return null;
    }

    public static boolean asBoolean(Object obj, boolean defaultValue) {
        Boolean result = asBoolean(obj);
        return result != null ? result : defaultValue;
    }

    // ==================== List ====================

    @SuppressWarnings("unchecked")
    public static <T> List<T> asList(Object obj, Class<T> elementType) {
        if (!(obj instanceof List)) return Collections.emptyList();
        List<?> raw = (List<?>) obj;
        List<T> result = new ArrayList<>();
        for (Object item : raw) {
            if (elementType.isInstance(item)) {
                result.add((T) item);
            }
        }
        return result;
    }

    public static List<?> asRawList(Object obj) {
        if (obj instanceof List) return (List<?>) obj;
        return Collections.emptyList();
    }

    // ==================== Map ====================

    @SuppressWarnings("unchecked")
    public static <K, V> Map<K, V> asMap(Object obj, Class<K> keyType, Class<V> valueType) {
        if (!(obj instanceof Map)) return Collections.emptyMap();
        Map<?, ?> raw = (Map<?, ?>) obj;
        Map<K, V> result = new HashMap<>();
        for (Map.Entry<?, ?> entry : raw.entrySet()) {
            if (keyType.isInstance(entry.getKey()) && valueType.isInstance(entry.getValue())) {
                result.put((K) entry.getKey(), (V) entry.getValue());
            }
        }
        return result;
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> asStringObjectMap(Object obj) {
        if (!(obj instanceof Map)) return Collections.emptyMap();
        Map<?, ?> raw = (Map<?, ?>) obj;
        Map<String, Object> result = new HashMap<>();
        for (Map.Entry<?, ?> entry : raw.entrySet()) {
            if (entry.getKey() instanceof String) {
                result.put((String) entry.getKey(), entry.getValue());
            }
        }
        return result;
    }

    // ==================== Generic cast ====================

    @SuppressWarnings("unchecked")
    public static <T> T as(Object obj, Class<T> type) {
        if (type.isInstance(obj)) return (T) obj;
        return null;
    }

    public static <T> T as(Object obj, Class<T> type, T defaultValue) {
        T result = as(obj, type);
        return result != null ? result : defaultValue;
    }

    public static <T> Optional<T> asOptional(Object obj, Class<T> type) {
        T result = as(obj, type);
        return Optional.ofNullable(result);
    }

    // ==================== Byte array ====================

    public static byte[] asByteArray(Object obj) {
        if (obj instanceof byte[]) return (byte[]) obj;
        return null;
    }

    public static byte[] asByteArray(Object obj, byte[] defaultValue) {
        if (obj instanceof byte[]) return (byte[]) obj;
        return defaultValue;
    }

    // ==================== Type checks ====================

    public static boolean isList(Object obj) {
        return obj instanceof List;
    }

    public static boolean isMap(Object obj) {
        return obj instanceof Map;
    }

    public static boolean isNumber(Object obj) {
        return obj instanceof Number;
    }

    public static boolean isType(Object obj, Class<?> type) {
        return type.isInstance(obj);
    }

    // ==================== Map value extraction ====================

    public static String getMapString(Map<String, Object> map, String key) {
        if (map == null) return null;
        return asString(map.get(key));
    }

    public static String getMapString(Map<String, Object> map, String key, String defaultValue) {
        if (map == null) return defaultValue;
        Object val = map.get(key);
        return val != null ? asString(val) : defaultValue;
    }

    public static int getMapInt(Map<String, Object> map, String key, int defaultValue) {
        if (map == null) return defaultValue;
        return asInt(map.get(key), defaultValue);
    }

    public static long getMapLong(Map<String, Object> map, String key, long defaultValue) {
        if (map == null) return defaultValue;
        return asLong(map.get(key), defaultValue);
    }

    public static boolean getMapBoolean(Map<String, Object> map, String key, boolean defaultValue) {
        if (map == null) return defaultValue;
        return asBoolean(map.get(key), defaultValue);
    }

    public static <T> List<T> getMapList(Map<String, Object> map, String key, Class<T> elementType) {
        if (map == null) return Collections.emptyList();
        return asList(map.get(key), elementType);
    }

    @SuppressWarnings("unchecked")
    public static Map<String, Object> getNestedMap(Map<String, Object> map, String key) {
        if (map == null) return Collections.emptyMap();
        Object val = map.get(key);
        return asStringObjectMap(val);
    }
}
