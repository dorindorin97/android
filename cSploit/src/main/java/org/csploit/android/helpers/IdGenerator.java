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
import org.csploit.android.helpers.LoggingHelper;

import java.util.concurrent.atomic.AtomicLong;
import org.csploit.android.helpers.LoggingHelper;
import java.util.concurrent.ConcurrentHashMap;
import org.csploit.android.helpers.LoggingHelper;
import java.util.Map;
import org.csploit.android.helpers.LoggingHelper;

/**
 * Helper class for generating and managing unique IDs.
 * Provides thread-safe ID generation for various use cases.
 */
public class IdGenerator {
    
    private static final String TAG = "IdGenerator";
    
    // Default sequence counter
    private static final AtomicLong defaultSequence = new AtomicLong(0);
    
    // Named sequences for different ID types
    private static final Map<String, AtomicLong> namedSequences = new ConcurrentHashMap<>();
    
    /**
     * Generate a unique ID using the default sequence.
     * 
     * @return Unique long ID
     */
    public static long generateId() {
        return defaultSequence.incrementAndGet();
    }
    
    /**
     * Generate a unique ID for a named sequence.
     * Creates the sequence if it doesn't exist.
     * 
     * @param sequenceName Name of the sequence
     * @return Unique long ID
     */
    public static long generateId(@NonNull String sequenceName) {
        AtomicLong sequence = namedSequences.computeIfAbsent(
                sequenceName, k -> new AtomicLong(0));
        return sequence.incrementAndGet();
    }
    
    /**
     * Generate a unique string ID using timestamp and sequence.
     * Format: timestamp_sequence
     * 
     * @return Unique string ID
     */
    @NonNull
    public static String generateStringId() {
        return System.currentTimeMillis() + "_" + defaultSequence.incrementAndGet();
    }
    
    /**
     * Generate a unique string ID with a prefix.
     * Format: prefix_timestamp_sequence
     * 
     * @param prefix Prefix string
     * @return Unique prefixed string ID
     */
    @NonNull
    public static String generateStringId(@NonNull String prefix) {
        return prefix + "_" + System.currentTimeMillis() + "_" + defaultSequence.incrementAndGet();
    }
    
    /**
     * Generate a UUID-like string (not cryptographically secure).
     * Format: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
     * 
     * @return UUID-like string
     */
    @NonNull
    public static String generateUUID() {
        return java.util.UUID.randomUUID().toString();
    }
    
    /**
     * Generate a short unique ID (8 characters, alphanumeric).
     * 
     * @return Short unique ID
     */
    @NonNull
    public static String generateShortId() {
        String uuid = generateUUID().replace("-", "");
        return uuid.substring(0, 8);
    }
    
    /**
     * Generate a session ID.
     * Format: session_timestamp_sequence
     * 
     * @return Session ID string
     */
    @NonNull
    public static String generateSessionId() {
        return generateStringId("session");
    }
    
    /**
     * Generate a target ID.
     * Format: target_timestamp_sequence
     * 
     * @return Target ID string
     */
    @NonNull
    public static String generateTargetId() {
        return generateStringId("target");
    }
    
    /**
     * Generate a scan ID.
     * Format: scan_timestamp_sequence
     * 
     * @return Scan ID string
     */
    @NonNull
    public static String generateScanId() {
        return generateStringId("scan");
    }
    
    /**
     * Get the current value of the default sequence (for debugging).
     * 
     * @return Current sequence value
     */
    public static long getCurrentSequenceValue() {
        return defaultSequence.get();
    }
    
    /**
     * Get the current value of a named sequence.
     * 
     * @param sequenceName Name of the sequence
     * @return Current sequence value, or -1 if sequence doesn't exist
     */
    public static long getCurrentSequenceValue(@NonNull String sequenceName) {
        AtomicLong sequence = namedSequences.get(sequenceName);
        return sequence != null ? sequence.get() : -1;
    }
    
    /**
     * Reset the default sequence to 0.
     * Use with caution - may cause ID collisions if IDs are persisted.
     */
    public static void resetDefaultSequence() {
        defaultSequence.set(0);
        LoggingHelper.w(TAG, "Default sequence reset to 0");
    }
    
    /**
     * Reset a named sequence to 0.
     * 
     * @param sequenceName Name of the sequence
     */
    public static void resetNamedSequence(@NonNull String sequenceName) {
        AtomicLong sequence = namedSequences.get(sequenceName);
        if (sequence != null) {
            sequence.set(0);
            LoggingHelper.w(TAG, "Named sequence '" + sequenceName + "' reset to 0");
        }
    }
    
    /**
     * Clear all named sequences.
     */
    public static void clearNamedSequences() {
        namedSequences.clear();
        LoggingHelper.w(TAG, "All named sequences cleared");
    }
    
    private IdGenerator() {
        // Prevent instantiation
    }
}
