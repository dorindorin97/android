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

import android.content.ContentValues;
import org.csploit.android.helpers.LoggingHelper;
import android.content.Context;
import org.csploit.android.helpers.LoggingHelper;
import android.database.Cursor;
import org.csploit.android.helpers.LoggingHelper;
import android.database.sqlite.SQLiteDatabase;
import org.csploit.android.helpers.LoggingHelper;
import android.database.sqlite.SQLiteOpenHelper;
import org.csploit.android.helpers.LoggingHelper;
import androidx.annotation.NonNull;
import org.csploit.android.helpers.LoggingHelper;
import androidx.annotation.Nullable;
import org.csploit.android.helpers.LoggingHelper;

/**
 * Database helper for persistent storage of scan results, targets, and history.
 * Uses SQLite for structured data storage with proper schema management.
 */
public class DatabaseHelper extends SQLiteOpenHelper {
    
    private static final String TAG = "DatabaseHelper";
    private static final String DATABASE_NAME = "csploit.db";
    private static final int DATABASE_VERSION = 2;
    
    // Table names
    public static final String TABLE_TARGETS = "targets";
    public static final String TABLE_SCAN_HISTORY = "scan_history";
    public static final String TABLE_EXPLOITS = "exploits";
    
    // Common columns
    public static final String COLUMN_ID = "_id";
    public static final String COLUMN_TIMESTAMP = "timestamp";
    
    // Targets table columns
    public static final String COLUMN_IP_ADDRESS = "ip_address";
    public static final String COLUMN_MAC_ADDRESS = "mac_address";
    public static final String COLUMN_HOSTNAME = "hostname";
    public static final String COLUMN_DEVICE_TYPE = "device_type";
    public static final String COLUMN_OS = "os";
    public static final String COLUMN_OPEN_PORTS = "open_ports";
    public static final String COLUMN_LAST_SEEN = "last_seen";
    
    // Scan history table columns
    public static final String COLUMN_SCAN_TYPE = "scan_type";
    public static final String COLUMN_TARGET_COUNT = "target_count";
    public static final String COLUMN_DURATION = "duration";
    public static final String COLUMN_STATUS = "status";
    
    // Exploits table columns
    public static final String COLUMN_EXPLOIT_NAME = "exploit_name";
    public static final String COLUMN_TARGET_ID = "target_id";
    public static final String COLUMN_SUCCESS = "success";
    public static final String COLUMN_DETAILS = "details";
    
    private static DatabaseHelper instance;
    
    /**
     * Get singleton instance of DatabaseHelper.
     * 
     * @param context Application context
     * @return DatabaseHelper instance
     */
    public static synchronized DatabaseHelper getInstance(@NonNull Context context) {
        if (instance == null) {
            instance = new DatabaseHelper(context.getApplicationContext());
        }
        return instance;
    }
    
    private DatabaseHelper(@NonNull Context context) {
        super(context, DATABASE_NAME, null, DATABASE_VERSION);
    }
    
    @Override
    public void onCreate(@NonNull SQLiteDatabase db) {
        createTables(db);
    }
    
    @Override
    public void onUpgrade(@NonNull SQLiteDatabase db, int oldVersion, int newVersion) {
        LoggingHelper.i(TAG, "Upgrading database from version " + oldVersion + " to " + newVersion);
        
        if (oldVersion < 2) {
            // Migration from version 1 to 2
            // Add new columns or tables here
        }
        
        // For major upgrades, consider backing up data first
    }
    
    /**
     * Create all database tables.
     * 
     * @param db SQLiteDatabase instance
     */
    private void createTables(@NonNull SQLiteDatabase db) {
        // Targets table
        String createTargetsTable = "CREATE TABLE IF NOT EXISTS " + TABLE_TARGETS + " (" +
                COLUMN_ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
                COLUMN_IP_ADDRESS + " TEXT NOT NULL UNIQUE, " +
                COLUMN_MAC_ADDRESS + " TEXT, " +
                COLUMN_HOSTNAME + " TEXT, " +
                COLUMN_DEVICE_TYPE + " TEXT, " +
                COLUMN_OS + " TEXT, " +
                COLUMN_OPEN_PORTS + " TEXT, " +
                COLUMN_LAST_SEEN + " INTEGER, " +
                COLUMN_TIMESTAMP + " INTEGER DEFAULT (strftime('%s', 'now')))";
        
        // Scan history table
        String createScanHistoryTable = "CREATE TABLE IF NOT EXISTS " + TABLE_SCAN_HISTORY + " (" +
                COLUMN_ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
                COLUMN_SCAN_TYPE + " TEXT NOT NULL, " +
                COLUMN_TARGET_COUNT + " INTEGER DEFAULT 0, " +
                COLUMN_DURATION + " INTEGER, " +
                COLUMN_STATUS + " TEXT, " +
                COLUMN_TIMESTAMP + " INTEGER DEFAULT (strftime('%s', 'now')))";
        
        // Exploits table
        String createExploitsTable = "CREATE TABLE IF NOT EXISTS " + TABLE_EXPLOITS + " (" +
                COLUMN_ID + " INTEGER PRIMARY KEY AUTOINCREMENT, " +
                COLUMN_EXPLOIT_NAME + " TEXT NOT NULL, " +
                COLUMN_TARGET_ID + " INTEGER, " +
                COLUMN_SUCCESS + " INTEGER DEFAULT 0, " +
                COLUMN_DETAILS + " TEXT, " +
                COLUMN_TIMESTAMP + " INTEGER DEFAULT (strftime('%s', 'now')), " +
                "FOREIGN KEY(" + COLUMN_TARGET_ID + ") REFERENCES " + 
                TABLE_TARGETS + "(" + COLUMN_ID + "))";
        
        db.execSQL(createTargetsTable);
        db.execSQL(createScanHistoryTable);
        db.execSQL(createExploitsTable);
        
        // Create indexes for better query performance
        db.execSQL("CREATE INDEX IF NOT EXISTS idx_ip_address ON " + 
                TABLE_TARGETS + "(" + COLUMN_IP_ADDRESS + ")");
        db.execSQL("CREATE INDEX IF NOT EXISTS idx_timestamp ON " + 
                TABLE_SCAN_HISTORY + "(" + COLUMN_TIMESTAMP + ")");
        
        LoggingHelper.d(TAG, "Database tables created successfully");
    }
    
    /**
     * Insert a target into the database.
     * 
     * @param ipAddress Target IP address
     * @param macAddress Target MAC address (can be null)
     * @param hostname Target hostname (can be null)
     * @return Row ID or -1 if failed
     */
    public long insertTarget(@NonNull String ipAddress, 
                            @Nullable String macAddress, 
                            @Nullable String hostname) {
        SQLiteDatabase db = getWritableDatabase();
        ContentValues values = new ContentValues();
        values.put(COLUMN_IP_ADDRESS, ipAddress);
        values.put(COLUMN_MAC_ADDRESS, macAddress);
        values.put(COLUMN_HOSTNAME, hostname);
        values.put(COLUMN_LAST_SEEN, System.currentTimeMillis() / 1000);
        
        try {
            return db.insertWithOnConflict(TABLE_TARGETS, null, values, 
                    SQLiteDatabase.CONFLICT_REPLACE);
        } catch (Exception e) {
            LoggingHelper.e(TAG, "Failed to insert target", e);
            return -1;
        }
    }
    
    /**
     * Get all targets from database.
     * 
     * @return Cursor with target data
     */
    @Nullable
    public Cursor getAllTargets() {
        SQLiteDatabase db = getReadableDatabase();
        try {
            return db.query(TABLE_TARGETS, null, null, null, null, null, 
                    COLUMN_LAST_SEEN + " DESC");
        } catch (Exception e) {
            LoggingHelper.e(TAG, "Failed to get targets", e);
            return null;
        }
    }
    
    /**
     * Insert scan history entry.
     * 
     * @param scanType Type of scan performed
     * @param targetCount Number of targets found
     * @param duration Scan duration in milliseconds
     * @param status Scan status
     * @return Row ID or -1 if failed
     */
    public long insertScanHistory(@NonNull String scanType, int targetCount, 
                                  long duration, @NonNull String status) {
        SQLiteDatabase db = getWritableDatabase();
        ContentValues values = new ContentValues();
        values.put(COLUMN_SCAN_TYPE, scanType);
        values.put(COLUMN_TARGET_COUNT, targetCount);
        values.put(COLUMN_DURATION, duration);
        values.put(COLUMN_STATUS, status);
        
        try {
            return db.insert(TABLE_SCAN_HISTORY, null, values);
        } catch (Exception e) {
            LoggingHelper.e(TAG, "Failed to insert scan history", e);
            return -1;
        }
    }
    
    /**
     * Clear all data from database.
     */
    public void clearAllData() {
        SQLiteDatabase db = getWritableDatabase();
        try {
            db.delete(TABLE_TARGETS, null, null);
            db.delete(TABLE_SCAN_HISTORY, null, null);
            db.delete(TABLE_EXPLOITS, null, null);
            LoggingHelper.i(TAG, "All database data cleared");
        } catch (Exception e) {
            LoggingHelper.e(TAG, "Failed to clear database", e);
        }
    }
    
    /**
     * Get database size in bytes.
     * 
     * @param context Application context
     * @return Database size in bytes
     */
    public static long getDatabaseSize(@NonNull Context context) {
        return context.getDatabasePath(DATABASE_NAME).length();
    }
    
    /**
     * Close database connection.
     */
    public static synchronized void closeDatabase() {
        if (instance != null) {
            instance.close();
            instance = null;
        }
    }
}
