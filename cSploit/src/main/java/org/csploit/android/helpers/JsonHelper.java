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
import org.csploit.android.helpers.LoggingHelper;
import androidx.annotation.Nullable;

import org.json.JSONArray;
import org.json.JSONException;
import org.json.JSONObject;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

/**
 * Helper class for JSON serialization and deserialization.
 * Provides safe JSON operations with proper error handling.
 */
public class JsonHelper {
    
    private static final String TAG = "JsonHelper";
    
    /**
     * Parse JSON string to JSONObject safely.
     * 
     * @param jsonString JSON string to parse
     * @return JSONObject or null if parsing fails
     */
    @Nullable
    public static JSONObject parseObject(@Nullable String jsonString) {
        if (jsonString == null || jsonString.trim().isEmpty()) {
            return null;
        }
        
        try {
            return new JSONObject(jsonString);
        } catch (JSONException e) {
            LoggingHelper.e(TAG, "Failed to parse JSON object", e);
            return null;
        }
    }
    
    /**
     * Parse JSON string to JSONArray safely.
     * 
     * @param jsonString JSON string to parse
     * @return JSONArray or null if parsing fails
     */
    @Nullable
    public static JSONArray parseArray(@Nullable String jsonString) {
        if (jsonString == null || jsonString.trim().isEmpty()) {
            return null;
        }
        
        try {
            return new JSONArray(jsonString);
        } catch (JSONException e) {
            LoggingHelper.e(TAG, "Failed to parse JSON array", e);
            return null;
        }
    }
    
    /**
     * Convert JSONObject to pretty-printed string.
     * 
     * @param jsonObject JSONObject to convert
     * @param indent Indent spaces (typically 2 or 4)
     * @return Pretty-printed JSON string or null if conversion fails
     */
    @Nullable
    public static String toPrettyString(@Nullable JSONObject jsonObject, int indent) {
        if (jsonObject == null) {
            return null;
        }
        
        try {
            return jsonObject.toString(indent);
        } catch (JSONException e) {
            LoggingHelper.e(TAG, "Failed to convert JSON to pretty string", e);
            return jsonObject.toString();
        }
    }
    
    /**
     * Convert JSONArray to pretty-printed string.
     * 
     * @param jsonArray JSONArray to convert
     * @param indent Indent spaces (typically 2 or 4)
     * @return Pretty-printed JSON string or null if conversion fails
     */
    @Nullable
    public static String toPrettyString(@Nullable JSONArray jsonArray, int indent) {
        if (jsonArray == null) {
            return null;
        }
        
        try {
            return jsonArray.toString(indent);
        } catch (JSONException e) {
            LoggingHelper.e(TAG, "Failed to convert JSON array to pretty string", e);
            return jsonArray.toString();
        }
    }
    
    /**
     * Safely get string from JSONObject.
     * 
     * @param json JSONObject
     * @param key Key to retrieve
     * @param defaultValue Default value if key doesn't exist
     * @return String value or default
     */
    @NonNull
    public static String getString(@NonNull JSONObject json, @NonNull String key, 
                                   @NonNull String defaultValue) {
        try {
            return json.has(key) ? json.getString(key) : defaultValue;
        } catch (JSONException e) {
            LoggingHelper.w(TAG, "Failed to get string for key: " + key, e);
            return defaultValue;
        }
    }
    
    /**
     * Safely get int from JSONObject.
     * 
     * @param json JSONObject
     * @param key Key to retrieve
     * @param defaultValue Default value if key doesn't exist
     * @return int value or default
     */
    public static int getInt(@NonNull JSONObject json, @NonNull String key, int defaultValue) {
        try {
            return json.has(key) ? json.getInt(key) : defaultValue;
        } catch (JSONException e) {
            LoggingHelper.w(TAG, "Failed to get int for key: " + key, e);
            return defaultValue;
        }
    }
    
    /**
     * Safely get long from JSONObject.
     * 
     * @param json JSONObject
     * @param key Key to retrieve
     * @param defaultValue Default value if key doesn't exist
     * @return long value or default
     */
    public static long getLong(@NonNull JSONObject json, @NonNull String key, long defaultValue) {
        try {
            return json.has(key) ? json.getLong(key) : defaultValue;
        } catch (JSONException e) {
            LoggingHelper.w(TAG, "Failed to get long for key: " + key, e);
            return defaultValue;
        }
    }
    
    /**
     * Safely get boolean from JSONObject.
     * 
     * @param json JSONObject
     * @param key Key to retrieve
     * @param defaultValue Default value if key doesn't exist
     * @return boolean value or default
     */
    public static boolean getBoolean(@NonNull JSONObject json, @NonNull String key, 
                                    boolean defaultValue) {
        try {
            return json.has(key) ? json.getBoolean(key) : defaultValue;
        } catch (JSONException e) {
            LoggingHelper.w(TAG, "Failed to get boolean for key: " + key, e);
            return defaultValue;
        }
    }
    
    /**
     * Convert Map to JSONObject.
     * 
     * @param map Map to convert
     * @return JSONObject or null if conversion fails
     */
    @Nullable
    public static JSONObject fromMap(@Nullable Map<String, Object> map) {
        if (map == null) {
            return null;
        }
        
        try {
            return new JSONObject(map);
        } catch (Exception e) {
            LoggingHelper.e(TAG, "Failed to convert map to JSON", e);
            return null;
        }
    }
    
    /**
     * Convert JSONObject to Map.
     * 
     * @param json JSONObject to convert
     * @return Map or empty map if conversion fails
     */
    @NonNull
    public static Map<String, Object> toMap(@Nullable JSONObject json) {
        Map<String, Object> map = new HashMap<>();
        
        if (json == null) {
            return map;
        }
        
        try {
            Iterator<String> keys = json.keys();
            while (keys.hasNext()) {
                String key = keys.next();
                Object value = json.get(key);
                
                if (value instanceof JSONObject) {
                    map.put(key, toMap((JSONObject) value));
                } else if (value instanceof JSONArray) {
                    map.put(key, toList((JSONArray) value));
                } else {
                    map.put(key, value);
                }
            }
        } catch (JSONException e) {
            LoggingHelper.e(TAG, "Failed to convert JSON to map", e);
        }
        
        return map;
    }
    
    /**
     * Convert JSONArray to List.
     * 
     * @param array JSONArray to convert
     * @return List or empty list if conversion fails
     */
    @NonNull
    public static List<Object> toList(@Nullable JSONArray array) {
        List<Object> list = new ArrayList<>();
        
        if (array == null) {
            return list;
        }
        
        try {
            for (int i = 0; i < array.length(); i++) {
                Object value = array.get(i);
                
                if (value instanceof JSONObject) {
                    list.add(toMap((JSONObject) value));
                } else if (value instanceof JSONArray) {
                    list.add(toList((JSONArray) value));
                } else {
                    list.add(value);
                }
            }
        } catch (JSONException e) {
            LoggingHelper.e(TAG, "Failed to convert JSON array to list", e);
        }
        
        return list;
    }
    
    /**
     * Write JSON to file.
     * 
     * @param json JSONObject to write
     * @param file Target file
     * @param prettyPrint Whether to format with indentation
     * @return true if successful
     */
    public static boolean writeToFile(@NonNull JSONObject json, @NonNull File file, 
                                     boolean prettyPrint) {
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(file))) {
            String jsonString = prettyPrint ? json.toString(2) : json.toString();
            writer.write(jsonString);
            return true;
        } catch (IOException | JSONException e) {
            LoggingHelper.e(TAG, "Failed to write JSON to file: " + file.getPath(), e);
            return false;
        }
    }
    
    /**
     * Read JSON from file.
     * 
     * @param file Source file
     * @return JSONObject or null if reading fails
     */
    @Nullable
    public static JSONObject readFromFile(@NonNull File file) {
        if (!file.exists() || !file.isFile()) {
            LoggingHelper.w(TAG, "File does not exist: " + file.getPath());
            return null;
        }
        
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line);
            }
            return new JSONObject(sb.toString());
        } catch (IOException | JSONException e) {
            LoggingHelper.e(TAG, "Failed to read JSON from file: " + file.getPath(), e);
            return null;
        }
    }
    
    /**
     * Merge two JSONObjects. Values from second object override first.
     * 
     * @param base Base JSONObject
     * @param override JSONObject to merge
     * @return Merged JSONObject
     */
    @NonNull
    public static JSONObject merge(@Nullable JSONObject base, @Nullable JSONObject override) {
        if (base == null && override == null) {
            return new JSONObject();
        }
        if (base == null) {
            return override;
        }
        if (override == null) {
            return base;
        }
        
        JSONObject result = new JSONObject();
        try {
            // Copy base
            Iterator<String> keys = base.keys();
            while (keys.hasNext()) {
                String key = keys.next();
                result.put(key, base.get(key));
            }
            
            // Override with second object
            keys = override.keys();
            while (keys.hasNext()) {
                String key = keys.next();
                result.put(key, override.get(key));
            }
        } catch (JSONException e) {
            LoggingHelper.e(TAG, "Failed to merge JSON objects", e);
        }
        
        return result;
    }
    
    /**
     * Get nested value from JSONObject using dot notation (e.g., "user.profile.name").
     *
     * @param json JSONObject to query
     * @param path Dot-separated path to the value
     * @return Value at path or null if not found
     */
    @Nullable
    public static Object getNestedValue(@Nullable JSONObject json, @NonNull String path) {
        if (json == null || path == null || path.isEmpty()) {
            return null;
        }

        String[] parts = path.split("\\.");
        Object current = json;

        for (String part : parts) {
            if (current instanceof JSONObject) {
                try {
                    current = ((JSONObject) current).get(part);
                } catch (JSONException e) {
                    return null;
                }
            } else if (current instanceof JSONArray) {
                try {
                    int index = Integer.parseInt(part);
                    current = ((JSONArray) current).get(index);
                } catch (NumberFormatException | JSONException e) {
                    return null;
                }
            } else {
                return null;
            }
        }

        return current == JSONObject.NULL ? null : current;
    }

    /**
     * Get nested string from JSONObject using dot notation.
     *
     * @param json JSONObject to query
     * @param path Dot-separated path to the value
     * @param defaultValue Default value if not found
     * @return String value at path or default
     */
    @NonNull
    public static String getNestedString(@Nullable JSONObject json, @NonNull String path,
                                         @NonNull String defaultValue) {
        Object value = getNestedValue(json, path);
        return value != null ? value.toString() : defaultValue;
    }

    /**
     * Safely get double from JSONObject.
     *
     * @param json JSONObject
     * @param key Key to retrieve
     * @param defaultValue Default value if key doesn't exist
     * @return double value or default
     */
    public static double getDouble(@NonNull JSONObject json, @NonNull String key, double defaultValue) {
        try {
            return json.has(key) ? json.getDouble(key) : defaultValue;
        } catch (JSONException e) {
            LoggingHelper.w(TAG, "Failed to get double for key: " + key, e);
            return defaultValue;
        }
    }

    /**
     * Safely get JSONObject from JSONObject.
     *
     * @param json Parent JSONObject
     * @param key Key to retrieve
     * @return Child JSONObject or null
     */
    @Nullable
    public static JSONObject getObject(@NonNull JSONObject json, @NonNull String key) {
        try {
            return json.has(key) ? json.getJSONObject(key) : null;
        } catch (JSONException e) {
            LoggingHelper.w(TAG, "Failed to get object for key: " + key, e);
            return null;
        }
    }

    /**
     * Safely get JSONArray from JSONObject.
     *
     * @param json Parent JSONObject
     * @param key Key to retrieve
     * @return JSONArray or null
     */
    @Nullable
    public static JSONArray getArray(@NonNull JSONObject json, @NonNull String key) {
        try {
            return json.has(key) ? json.getJSONArray(key) : null;
        } catch (JSONException e) {
            LoggingHelper.w(TAG, "Failed to get array for key: " + key, e);
            return null;
        }
    }

    /**
     * Convert JSONArray to List of Strings.
     *
     * @param array JSONArray to convert
     * @return List of strings
     */
    @NonNull
    public static List<String> toStringList(@Nullable JSONArray array) {
        List<String> list = new ArrayList<>();
        if (array == null) {
            return list;
        }
        for (int i = 0; i < array.length(); i++) {
            try {
                list.add(array.getString(i));
            } catch (JSONException e) {
                // Skip invalid entries
            }
        }
        return list;
    }

    /**
     * Convert JSONArray to List of Integers.
     *
     * @param array JSONArray to convert
     * @return List of integers
     */
    @NonNull
    public static List<Integer> toIntList(@Nullable JSONArray array) {
        List<Integer> list = new ArrayList<>();
        if (array == null) {
            return list;
        }
        for (int i = 0; i < array.length(); i++) {
            try {
                list.add(array.getInt(i));
            } catch (JSONException e) {
                // Skip invalid entries
            }
        }
        return list;
    }

    /**
     * Check if JSON object has non-null, non-empty value for key.
     *
     * @param json JSONObject to check
     * @param key Key to check
     * @return true if key exists and has a non-null, non-empty value
     */
    public static boolean hasValue(@Nullable JSONObject json, @NonNull String key) {
        if (json == null || !json.has(key)) {
            return false;
        }
        try {
            Object value = json.get(key);
            if (value == JSONObject.NULL) {
                return false;
            }
            if (value instanceof String) {
                return !((String) value).isEmpty();
            }
            return true;
        } catch (JSONException e) {
            return false;
        }
    }

    /**
     * Safely put value into JSONObject, handling null values.
     *
     * @param json JSONObject to modify
     * @param key Key to set
     * @param value Value to set (null will be converted to JSONObject.NULL)
     */
    public static void put(@NonNull JSONObject json, @NonNull String key, @Nullable Object value) {
        try {
            json.put(key, value != null ? value : JSONObject.NULL);
        } catch (JSONException e) {
            LoggingHelper.e(TAG, "Failed to put value into JSON for key: " + key, e);
        }
    }

    /**
     * Create a copy of a JSONObject.
     *
     * @param json JSONObject to copy
     * @return New JSONObject with same content or empty JSONObject if null
     */
    @NonNull
    public static JSONObject copy(@Nullable JSONObject json) {
        if (json == null) {
            return new JSONObject();
        }
        try {
            return new JSONObject(json.toString());
        } catch (JSONException e) {
            LoggingHelper.e(TAG, "Failed to copy JSON object", e);
            return new JSONObject();
        }
    }

    /**
     * Create a copy of a JSONArray.
     *
     * @param array JSONArray to copy
     * @return New JSONArray with same content or empty JSONArray if null
     */
    @NonNull
    public static JSONArray copy(@Nullable JSONArray array) {
        if (array == null) {
            return new JSONArray();
        }
        try {
            return new JSONArray(array.toString());
        } catch (JSONException e) {
            LoggingHelper.e(TAG, "Failed to copy JSON array", e);
            return new JSONArray();
        }
    }

    private JsonHelper() {
        // Prevent instantiation
    }
}
