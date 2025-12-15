package org.csploit.android.helpers;

import org.junit.Test;
import static org.junit.Assert.*;

import java.util.*;

/**
 * Unit tests for TypeSafeHelper
 */
public class TypeSafeHelperTest {

    // String casting tests

    @Test
    public void testAsString_fromString() {
        assertEquals("hello", TypeSafeHelper.asString("hello"));
    }

    @Test
    public void testAsString_fromObject() {
        assertEquals("123", TypeSafeHelper.asString(Integer.valueOf(123)));
    }

    @Test
    public void testAsString_fromNull() {
        assertNull(TypeSafeHelper.asString(null));
    }

    @Test
    public void testAsString_withDefault() {
        assertEquals("hello", TypeSafeHelper.asString("hello", "default"));
        assertEquals("default", TypeSafeHelper.asString(null, "default"));
    }

    @Test
    public void testAsStringOptional() {
        assertTrue(TypeSafeHelper.asStringOptional("hello").isPresent());
        assertEquals("hello", TypeSafeHelper.asStringOptional("hello").get());
        assertFalse(TypeSafeHelper.asStringOptional(Integer.valueOf(123)).isPresent());
    }

    // Integer casting tests

    @Test
    public void testAsInteger_fromInteger() {
        assertEquals(Integer.valueOf(42), TypeSafeHelper.asInteger(Integer.valueOf(42)));
    }

    @Test
    public void testAsInteger_fromLong() {
        assertEquals(Integer.valueOf(42), TypeSafeHelper.asInteger(Long.valueOf(42)));
    }

    @Test
    public void testAsInteger_fromString() {
        assertEquals(Integer.valueOf(42), TypeSafeHelper.asInteger("42"));
    }

    @Test
    public void testAsInteger_fromInvalidString() {
        assertNull(TypeSafeHelper.asInteger("not a number"));
    }

    @Test
    public void testAsInt_withDefault() {
        assertEquals(42, TypeSafeHelper.asInt(Integer.valueOf(42), 0));
        assertEquals(0, TypeSafeHelper.asInt(null, 0));
        assertEquals(0, TypeSafeHelper.asInt("invalid", 0));
    }

    // Long casting tests

    @Test
    public void testAsLong_fromLong() {
        assertEquals(Long.valueOf(42L), TypeSafeHelper.asLong(Long.valueOf(42L)));
    }

    @Test
    public void testAsLong_fromInteger() {
        assertEquals(Long.valueOf(42L), TypeSafeHelper.asLong(Integer.valueOf(42)));
    }

    @Test
    public void testAsLong_fromString() {
        assertEquals(Long.valueOf(42L), TypeSafeHelper.asLong("42"));
    }

    @Test
    public void testAsLong_withDefault() {
        assertEquals(42L, TypeSafeHelper.asLong(Long.valueOf(42L), 0L));
        assertEquals(0L, TypeSafeHelper.asLong(null, 0L));
    }

    // Double casting tests

    @Test
    public void testAsDouble_fromDouble() {
        assertEquals(Double.valueOf(3.14), TypeSafeHelper.asDouble(Double.valueOf(3.14)));
    }

    @Test
    public void testAsDouble_fromInteger() {
        assertEquals(Double.valueOf(42.0), TypeSafeHelper.asDouble(Integer.valueOf(42)));
    }

    @Test
    public void testAsDouble_fromString() {
        assertEquals(Double.valueOf(3.14), TypeSafeHelper.asDouble("3.14"));
    }

    @Test
    public void testAsDouble_withDefault() {
        assertEquals(3.14, TypeSafeHelper.asDouble(Double.valueOf(3.14), 0.0), 0.001);
        assertEquals(0.0, TypeSafeHelper.asDouble(null, 0.0), 0.001);
    }

    // Boolean casting tests

    @Test
    public void testAsBoolean_fromBoolean() {
        assertEquals(Boolean.TRUE, TypeSafeHelper.asBoolean(Boolean.TRUE));
        assertEquals(Boolean.FALSE, TypeSafeHelper.asBoolean(Boolean.FALSE));
    }

    @Test
    public void testAsBoolean_fromString() {
        assertEquals(Boolean.TRUE, TypeSafeHelper.asBoolean("true"));
        assertEquals(Boolean.TRUE, TypeSafeHelper.asBoolean("TRUE"));
        assertEquals(Boolean.TRUE, TypeSafeHelper.asBoolean("1"));
        assertEquals(Boolean.FALSE, TypeSafeHelper.asBoolean("false"));
        assertEquals(Boolean.FALSE, TypeSafeHelper.asBoolean("0"));
    }

    @Test
    public void testAsBoolean_fromNumber() {
        assertEquals(Boolean.TRUE, TypeSafeHelper.asBoolean(Integer.valueOf(1)));
        assertEquals(Boolean.FALSE, TypeSafeHelper.asBoolean(Integer.valueOf(0)));
    }

    @Test
    public void testAsBoolean_withDefault() {
        assertTrue(TypeSafeHelper.asBoolean(Boolean.TRUE, false));
        assertFalse(TypeSafeHelper.asBoolean(null, false));
    }

    // List casting tests

    @Test
    public void testAsList_fromList() {
        List<String> input = Arrays.asList("a", "b", "c");
        List<String> result = TypeSafeHelper.asList(input, String.class);
        assertEquals(3, result.size());
        assertEquals("a", result.get(0));
    }

    @Test
    public void testAsList_fromMixedList() {
        List<Object> input = Arrays.asList("a", 1, "c");
        List<String> result = TypeSafeHelper.asList(input, String.class);
        assertEquals(2, result.size()); // Only strings
    }

    @Test
    public void testAsList_fromNonList() {
        List<String> result = TypeSafeHelper.asList("not a list", String.class);
        assertTrue(result.isEmpty());
    }

    @Test
    public void testAsRawList() {
        List<String> input = Arrays.asList("a", "b");
        List<?> result = TypeSafeHelper.asRawList(input);
        assertEquals(2, result.size());
    }

    // Map casting tests

    @Test
    public void testAsMap_fromMap() {
        Map<String, Integer> input = new HashMap<>();
        input.put("a", 1);
        input.put("b", 2);
        
        Map<String, Integer> result = TypeSafeHelper.asMap(input, String.class, Integer.class);
        assertEquals(2, result.size());
        assertEquals(Integer.valueOf(1), result.get("a"));
    }

    @Test
    public void testAsMap_fromMixedMap() {
        Map<Object, Object> input = new HashMap<>();
        input.put("a", 1);
        input.put(2, "b"); // Wrong key type
        
        Map<String, Integer> result = TypeSafeHelper.asMap(input, String.class, Integer.class);
        assertEquals(1, result.size());
    }

    @Test
    public void testAsMap_fromNonMap() {
        Map<String, Object> result = TypeSafeHelper.asMap("not a map", String.class, Object.class);
        assertTrue(result.isEmpty());
    }

    @Test
    public void testAsStringObjectMap() {
        Map<String, Object> input = new HashMap<>();
        input.put("key", "value");
        
        Map<String, Object> result = TypeSafeHelper.asStringObjectMap(input);
        assertEquals(1, result.size());
    }

    // Generic casting tests

    @Test
    public void testAs_correctType() {
        String result = TypeSafeHelper.as("hello", String.class);
        assertEquals("hello", result);
    }

    @Test
    public void testAs_wrongType() {
        String result = TypeSafeHelper.as(Integer.valueOf(42), String.class);
        assertNull(result);
    }

    @Test
    public void testAs_withDefault() {
        assertEquals("hello", TypeSafeHelper.as("hello", String.class, "default"));
        assertEquals("default", TypeSafeHelper.as(Integer.valueOf(42), String.class, "default"));
    }

    @Test
    public void testAsOptional() {
        assertTrue(TypeSafeHelper.asOptional("hello", String.class).isPresent());
        assertFalse(TypeSafeHelper.asOptional(Integer.valueOf(42), String.class).isPresent());
    }

    // Byte array casting tests

    @Test
    public void testAsByteArray() {
        byte[] input = {1, 2, 3};
        byte[] result = TypeSafeHelper.asByteArray(input);
        assertArrayEquals(input, result);
    }

    @Test
    public void testAsByteArray_fromNonArray() {
        assertNull(TypeSafeHelper.asByteArray("not an array"));
    }

    @Test
    public void testAsByteArray_withDefault() {
        byte[] input = {1, 2, 3};
        byte[] defaultVal = {0};
        
        assertArrayEquals(input, TypeSafeHelper.asByteArray(input, defaultVal));
        assertArrayEquals(defaultVal, TypeSafeHelper.asByteArray(null, defaultVal));
    }

    // Validation tests

    @Test
    public void testIsList() {
        assertTrue(TypeSafeHelper.isList(Arrays.asList("a", "b")));
        assertFalse(TypeSafeHelper.isList("not a list"));
        assertFalse(TypeSafeHelper.isList(null));
    }

    @Test
    public void testIsMap() {
        assertTrue(TypeSafeHelper.isMap(new HashMap<>()));
        assertFalse(TypeSafeHelper.isMap("not a map"));
        assertFalse(TypeSafeHelper.isMap(null));
    }

    @Test
    public void testIsNumber() {
        assertTrue(TypeSafeHelper.isNumber(Integer.valueOf(42)));
        assertTrue(TypeSafeHelper.isNumber(Double.valueOf(3.14)));
        assertFalse(TypeSafeHelper.isNumber("42"));
        assertFalse(TypeSafeHelper.isNumber(null));
    }

    @Test
    public void testIsType() {
        assertTrue(TypeSafeHelper.isType("hello", String.class));
        assertFalse(TypeSafeHelper.isType("hello", Integer.class));
        assertFalse(TypeSafeHelper.isType(null, String.class));
    }

    // Map value extraction tests

    @Test
    public void testGetMapString() {
        Map<String, Object> map = new HashMap<>();
        map.put("key", "value");
        
        assertEquals("value", TypeSafeHelper.getMapString(map, "key"));
        assertNull(TypeSafeHelper.getMapString(map, "missing"));
        assertNull(TypeSafeHelper.getMapString(null, "key"));
    }

    @Test
    public void testGetMapString_withDefault() {
        Map<String, Object> map = new HashMap<>();
        map.put("key", "value");
        
        assertEquals("value", TypeSafeHelper.getMapString(map, "key", "default"));
        assertEquals("default", TypeSafeHelper.getMapString(map, "missing", "default"));
    }

    @Test
    public void testGetMapInt() {
        Map<String, Object> map = new HashMap<>();
        map.put("num", Integer.valueOf(42));
        
        assertEquals(42, TypeSafeHelper.getMapInt(map, "num", 0));
        assertEquals(0, TypeSafeHelper.getMapInt(map, "missing", 0));
    }

    @Test
    public void testGetMapLong() {
        Map<String, Object> map = new HashMap<>();
        map.put("num", Long.valueOf(42L));
        
        assertEquals(42L, TypeSafeHelper.getMapLong(map, "num", 0L));
        assertEquals(0L, TypeSafeHelper.getMapLong(map, "missing", 0L));
    }

    @Test
    public void testGetMapBoolean() {
        Map<String, Object> map = new HashMap<>();
        map.put("flag", Boolean.TRUE);
        
        assertTrue(TypeSafeHelper.getMapBoolean(map, "flag", false));
        assertFalse(TypeSafeHelper.getMapBoolean(map, "missing", false));
    }

    @Test
    public void testGetMapList() {
        Map<String, Object> map = new HashMap<>();
        map.put("list", Arrays.asList("a", "b", "c"));
        
        List<String> result = TypeSafeHelper.getMapList(map, "list", String.class);
        assertEquals(3, result.size());
        
        List<String> empty = TypeSafeHelper.getMapList(map, "missing", String.class);
        assertTrue(empty.isEmpty());
    }

    @Test
    public void testGetNestedMap() {
        Map<String, Object> inner = new HashMap<>();
        inner.put("nested", "value");
        
        Map<String, Object> outer = new HashMap<>();
        outer.put("inner", inner);
        
        Map<String, Object> result = TypeSafeHelper.getNestedMap(outer, "inner");
        assertEquals(1, result.size());
        assertEquals("value", result.get("nested"));
    }
}
