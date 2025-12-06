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
import java.util.Arrays;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

/**
 * Helper class for common collection operations.
 * Provides utilities for safe collection manipulation.
 */
public class CollectionHelper {
    
    /**
     * Check if a collection is null or empty.
     * 
     * @param collection Collection to check
     * @return true if null or empty
     */
    public static boolean isEmpty(@Nullable Collection<?> collection) {
        return collection == null || collection.isEmpty();
    }
    
    /**
     * Check if a collection is not null and not empty.
     * 
     * @param collection Collection to check
     * @return true if not null and not empty
     */
    public static boolean isNotEmpty(@Nullable Collection<?> collection) {
        return collection != null && !collection.isEmpty();
    }
    
    /**
     * Check if a map is null or empty.
     * 
     * @param map Map to check
     * @return true if null or empty
     */
    public static boolean isEmpty(@Nullable Map<?, ?> map) {
        return map == null || map.isEmpty();
    }
    
    /**
     * Check if a map is not null and not empty.
     * 
     * @param map Map to check
     * @return true if not null and not empty
     */
    public static boolean isNotEmpty(@Nullable Map<?, ?> map) {
        return map != null && !map.isEmpty();
    }
    
    /**
     * Get size of collection safely.
     * 
     * @param collection Collection
     * @return Size, or 0 if null
     */
    public static int size(@Nullable Collection<?> collection) {
        return collection == null ? 0 : collection.size();
    }
    
    /**
     * Get size of map safely.
     * 
     * @param map Map
     * @return Size, or 0 if null
     */
    public static int size(@Nullable Map<?, ?> map) {
        return map == null ? 0 : map.size();
    }
    
    /**
     * Get first element from list safely.
     * 
     * @param list List
     * @param <T> Element type
     * @return First element, or null if empty/null
     */
    @Nullable
    public static <T> T first(@Nullable List<T> list) {
        if (isEmpty(list)) {
            return null;
        }
        return list.get(0);
    }
    
    /**
     * Get last element from list safely.
     * 
     * @param list List
     * @param <T> Element type
     * @return Last element, or null if empty/null
     */
    @Nullable
    public static <T> T last(@Nullable List<T> list) {
        if (isEmpty(list)) {
            return null;
        }
        return list.get(list.size() - 1);
    }
    
    /**
     * Get element at index safely.
     * 
     * @param list List
     * @param index Index
     * @param <T> Element type
     * @return Element at index, or null if out of bounds
     */
    @Nullable
    public static <T> T get(@Nullable List<T> list, int index) {
        if (isEmpty(list) || index < 0 || index >= list.size()) {
            return null;
        }
        return list.get(index);
    }
    
    /**
     * Get element at index with default value.
     * 
     * @param list List
     * @param index Index
     * @param defaultValue Default value if not found
     * @param <T> Element type
     * @return Element at index, or default value
     */
    @NonNull
    public static <T> T getOrDefault(@Nullable List<T> list, int index, @NonNull T defaultValue) {
        T value = get(list, index);
        return value != null ? value : defaultValue;
    }
    
    /**
     * Create an immutable list from elements.
     * 
     * @param elements Elements
     * @param <T> Element type
     * @return Immutable list
     */
    @SafeVarargs
    @NonNull
    public static <T> List<T> listOf(@NonNull T... elements) {
        return Collections.unmodifiableList(Arrays.asList(elements));
    }
    
    /**
     * Create a mutable list from elements.
     * 
     * @param elements Elements
     * @param <T> Element type
     * @return Mutable ArrayList
     */
    @SafeVarargs
    @NonNull
    public static <T> ArrayList<T> mutableListOf(@NonNull T... elements) {
        return new ArrayList<>(Arrays.asList(elements));
    }
    
    /**
     * Create an immutable set from elements.
     * 
     * @param elements Elements
     * @param <T> Element type
     * @return Immutable set
     */
    @SafeVarargs
    @NonNull
    public static <T> Set<T> setOf(@NonNull T... elements) {
        return Collections.unmodifiableSet(new HashSet<>(Arrays.asList(elements)));
    }
    
    /**
     * Create a mutable set from elements.
     * 
     * @param elements Elements
     * @param <T> Element type
     * @return Mutable HashSet
     */
    @SafeVarargs
    @NonNull
    public static <T> HashSet<T> mutableSetOf(@NonNull T... elements) {
        return new HashSet<>(Arrays.asList(elements));
    }
    
    /**
     * Create a map from key-value pairs.
     * 
     * @param entries Key-value pairs (must be even number of args)
     * @param <K> Key type
     * @param <V> Value type
     * @return Map
     */
    @SuppressWarnings("unchecked")
    @NonNull
    public static <K, V> Map<K, V> mapOf(@NonNull Object... entries) {
        if (entries.length % 2 != 0) {
            throw new IllegalArgumentException("Must provide even number of arguments");
        }
        
        Map<K, V> map = new HashMap<>();
        for (int i = 0; i < entries.length; i += 2) {
            map.put((K) entries[i], (V) entries[i + 1]);
        }
        return Collections.unmodifiableMap(map);
    }
    
    /**
     * Filter a list with a predicate.
     * 
     * @param list Source list
     * @param predicate Filter predicate
     * @param <T> Element type
     * @return Filtered list
     */
    @NonNull
    public static <T> List<T> filter(@Nullable List<T> list, @NonNull Predicate<T> predicate) {
        if (isEmpty(list)) {
            return new ArrayList<>();
        }
        
        List<T> result = new ArrayList<>();
        for (T item : list) {
            if (predicate.test(item)) {
                result.add(item);
            }
        }
        return result;
    }
    
    /**
     * Find first matching element.
     * 
     * @param list Source list
     * @param predicate Match predicate
     * @param <T> Element type
     * @return First matching element, or null
     */
    @Nullable
    public static <T> T find(@Nullable List<T> list, @NonNull Predicate<T> predicate) {
        if (isEmpty(list)) {
            return null;
        }
        
        for (T item : list) {
            if (predicate.test(item)) {
                return item;
            }
        }
        return null;
    }
    
    /**
     * Check if any element matches predicate.
     * 
     * @param list Source list
     * @param predicate Match predicate
     * @param <T> Element type
     * @return true if any match
     */
    public static <T> boolean any(@Nullable List<T> list, @NonNull Predicate<T> predicate) {
        return find(list, predicate) != null;
    }
    
    /**
     * Check if all elements match predicate.
     * 
     * @param list Source list
     * @param predicate Match predicate
     * @param <T> Element type
     * @return true if all match
     */
    public static <T> boolean all(@Nullable List<T> list, @NonNull Predicate<T> predicate) {
        if (isEmpty(list)) {
            return true;
        }
        
        for (T item : list) {
            if (!predicate.test(item)) {
                return false;
            }
        }
        return true;
    }
    
    /**
     * Count elements matching predicate.
     * 
     * @param list Source list
     * @param predicate Match predicate
     * @param <T> Element type
     * @return Count of matching elements
     */
    public static <T> int count(@Nullable List<T> list, @NonNull Predicate<T> predicate) {
        if (isEmpty(list)) {
            return 0;
        }
        
        int count = 0;
        for (T item : list) {
            if (predicate.test(item)) {
                count++;
            }
        }
        return count;
    }
    
    /**
     * Join list elements to string.
     * 
     * @param list Source list
     * @param separator Separator string
     * @param <T> Element type
     * @return Joined string
     */
    @NonNull
    public static <T> String join(@Nullable List<T> list, @NonNull String separator) {
        if (isEmpty(list)) {
            return "";
        }
        
        StringBuilder sb = new StringBuilder();
        boolean first = true;
        for (T item : list) {
            if (!first) {
                sb.append(separator);
            }
            sb.append(item);
            first = false;
        }
        return sb.toString();
    }
    
    /**
     * Reverse a list (returns new list).
     * 
     * @param list Source list
     * @param <T> Element type
     * @return Reversed list
     */
    @NonNull
    public static <T> List<T> reverse(@Nullable List<T> list) {
        if (isEmpty(list)) {
            return new ArrayList<>();
        }
        
        List<T> result = new ArrayList<>(list);
        Collections.reverse(result);
        return result;
    }
    
    /**
     * Get distinct elements from list.
     * 
     * @param list Source list
     * @param <T> Element type
     * @return List with distinct elements
     */
    @NonNull
    public static <T> List<T> distinct(@Nullable List<T> list) {
        if (isEmpty(list)) {
            return new ArrayList<>();
        }
        return new ArrayList<>(new HashSet<>(list));
    }
    
    /**
     * Take first n elements from list.
     * 
     * @param list Source list
     * @param n Number of elements
     * @param <T> Element type
     * @return List with first n elements
     */
    @NonNull
    public static <T> List<T> take(@Nullable List<T> list, int n) {
        if (isEmpty(list) || n <= 0) {
            return new ArrayList<>();
        }
        return new ArrayList<>(list.subList(0, Math.min(n, list.size())));
    }
    
    /**
     * Drop first n elements from list.
     * 
     * @param list Source list
     * @param n Number of elements to drop
     * @param <T> Element type
     * @return List without first n elements
     */
    @NonNull
    public static <T> List<T> drop(@Nullable List<T> list, int n) {
        if (isEmpty(list)) {
            return new ArrayList<>();
        }
        if (n >= list.size()) {
            return new ArrayList<>();
        }
        return new ArrayList<>(list.subList(n, list.size()));
    }
    
    /**
     * Simple predicate interface for Java 7 compatibility.
     * 
     * @param <T> Type to test
     */
    public interface Predicate<T> {
        boolean test(T t);
    }
    
    private CollectionHelper() {
        // Prevent instantiation
    }
}
