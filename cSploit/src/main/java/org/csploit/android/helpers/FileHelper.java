package org.csploit.android.helpers;

import android.content.Context;
import android.os.Build;
import android.os.Environment;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.nio.charset.StandardCharsets;

/**
 * File operations utility helper for safe file access and scoped storage support.
 * 
 * Features:
 * - Safe file I/O operations
 * - Scoped storage support (Android 11+)
 * - File existence and access checks
 * - Safe read/write operations
 * - Permission checking
 * - Directory creation
 * - File deletion
 * 
 * Example:
 * <pre>
 * String content = FileHelper.readFile(context, "data.txt");
 * FileHelper.writeFile(context, "output.txt", "Some data");
 * if (FileHelper.fileExists(context, "myfile.txt")) {
 *     FileHelper.deleteFile(context, "myfile.txt");
 * }
 * </pre>
 */
public final class FileHelper {
    private static final String TAG = "FileHelper";
    
    /**
     * Check if file exists in app's private storage
     * 
     * @param context Android context
     * @param filename filename to check
     * @return true if file exists
     */
    public static boolean fileExists(@NonNull Context context, @NonNull String filename) {
        try {
            File file = new File(context.getFilesDir(), filename);
            return file.exists() && file.isFile();
        } catch (Exception e) {
            LoggingHelper.w(TAG, "Error checking file existence", e);
            return false;
        }
    }
    
    /**
     * Read file content as string
     * 
     * @param context Android context
     * @param filename filename to read
     * @return file content or empty string if file not found
     */
    public static String readFile(@NonNull Context context, @NonNull String filename) {
        BufferedReader reader = null;
        
        try {
            File file = new File(context.getFilesDir(), filename);
            
            if (!file.exists()) {
                LoggingHelper.d(TAG, "File not found: " + filename);
                return "";
            }
            
            reader = new BufferedReader(
                    new InputStreamReader(
                            new FileInputStream(file),
                            StandardCharsets.UTF_8
                    )
            );
            
            StringBuilder sb = new StringBuilder();
            String line;
            
            while ((line = reader.readLine()) != null) {
                sb.append(line).append("\n");
            }
            
            String result = sb.toString();
            // Remove trailing newline if present
            return result.endsWith("\n") ? result.substring(0, result.length() - 1) : result;
            
        } catch (IOException e) {
            LoggingHelper.w(TAG, "Error reading file: " + filename, e);
            return "";
        } finally {
            if (reader != null) {
                try {
                    reader.close();
                } catch (IOException e) {
                    LoggingHelper.w(TAG, "Error closing file reader", e);
                }
            }
        }
    }
    
    /**
     * Write content to file
     * 
     * @param context Android context
     * @param filename filename to write
     * @param content content to write
     * @return true if write was successful
     */
    public static boolean writeFile(@NonNull Context context, @NonNull String filename, @NonNull String content) {
        BufferedWriter writer = null;
        
        try {
            File file = new File(context.getFilesDir(), filename);
            
            // Ensure parent directory exists
            File parent = file.getParentFile();
            if (parent != null && !parent.exists()) {
                if (!parent.mkdirs()) {
                    LoggingHelper.w(TAG, "Failed to create directory: " + parent.getAbsolutePath());
                    return false;
                }
            }
            
            writer = new BufferedWriter(
                    new OutputStreamWriter(
                            new FileOutputStream(file),
                            StandardCharsets.UTF_8
                    )
            );
            
            writer.write(content);
            writer.flush();
            
            LoggingHelper.d(TAG, "File written successfully: " + filename);
            return true;
            
        } catch (IOException e) {
            LoggingHelper.w(TAG, "Error writing file: " + filename, e);
            return false;
        } finally {
            if (writer != null) {
                try {
                    writer.close();
                } catch (IOException e) {
                    LoggingHelper.w(TAG, "Error closing file writer", e);
                }
            }
        }
    }
    
    /**
     * Append content to file
     * 
     * @param context Android context
     * @param filename filename to append to
     * @param content content to append
     * @return true if append was successful
     */
    public static boolean appendFile(@NonNull Context context, @NonNull String filename, @NonNull String content) {
        BufferedWriter writer = null;
        
        try {
            File file = new File(context.getFilesDir(), filename);
            
            writer = new BufferedWriter(
                    new OutputStreamWriter(
                            new FileOutputStream(file, true),  // true = append mode
                            StandardCharsets.UTF_8
                    )
            );
            
            writer.write(content);
            writer.write("\n");
            writer.flush();
            
            LoggingHelper.d(TAG, "Content appended successfully: " + filename);
            return true;
            
        } catch (IOException e) {
            LoggingHelper.w(TAG, "Error appending to file: " + filename, e);
            return false;
        } finally {
            if (writer != null) {
                try {
                    writer.close();
                } catch (IOException e) {
                    LoggingHelper.w(TAG, "Error closing file writer", e);
                }
            }
        }
    }
    
    /**
     * Delete file
     * 
     * @param context Android context
     * @param filename filename to delete
     * @return true if deletion was successful
     */
    public static boolean deleteFile(@NonNull Context context, @NonNull String filename) {
        try {
            File file = new File(context.getFilesDir(), filename);
            
            if (!file.exists()) {
                LoggingHelper.d(TAG, "File not found for deletion: " + filename);
                return true;
            }
            
            if (file.delete()) {
                LoggingHelper.d(TAG, "File deleted successfully: " + filename);
                return true;
            } else {
                LoggingHelper.w(TAG, "Failed to delete file: " + filename);
                return false;
            }
            
        } catch (Exception e) {
            LoggingHelper.w(TAG, "Error deleting file: " + filename, e);
            return false;
        }
    }
    
    /**
     * Get file size
     * 
     * @param context Android context
     * @param filename filename to get size of
     * @return file size in bytes, or -1 if file not found
     */
    public static long getFileSize(@NonNull Context context, @NonNull String filename) {
        try {
            File file = new File(context.getFilesDir(), filename);
            
            if (!file.exists()) {
                return -1;
            }
            
            return file.length();
            
        } catch (Exception e) {
            LoggingHelper.w(TAG, "Error getting file size: " + filename, e);
            return -1;
        }
    }
    
    /**
     * Get file as byte array
     * 
     * @param context Android context
     * @param filename filename to read
     * @return byte array or null if file not found
     */
    @Nullable
    public static byte[] readFileBytes(@NonNull Context context, @NonNull String filename) {
        FileInputStream fis = null;
        
        try {
            File file = new File(context.getFilesDir(), filename);
            
            if (!file.exists()) {
                return null;
            }
            
            fis = new FileInputStream(file);
            byte[] data = new byte[(int) file.length()];
            fis.read(data);
            
            return data;
            
        } catch (IOException e) {
            LoggingHelper.w(TAG, "Error reading file bytes: " + filename, e);
            return null;
        } finally {
            if (fis != null) {
                try {
                    fis.close();
                } catch (IOException e) {
                    LoggingHelper.w(TAG, "Error closing file input stream", e);
                }
            }
        }
    }
    
    /**
     * Write byte array to file
     * 
     * @param context Android context
     * @param filename filename to write
     * @param data data to write
     * @return true if write was successful
     */
    public static boolean writeFileBytes(@NonNull Context context, @NonNull String filename, @NonNull byte[] data) {
        FileOutputStream fos = null;
        
        try {
            File file = new File(context.getFilesDir(), filename);
            
            fos = new FileOutputStream(file);
            fos.write(data);
            fos.flush();
            
            LoggingHelper.d(TAG, "Bytes written successfully: " + filename);
            return true;
            
        } catch (IOException e) {
            LoggingHelper.w(TAG, "Error writing file bytes: " + filename, e);
            return false;
        } finally {
            if (fos != null) {
                try {
                    fos.close();
                } catch (IOException e) {
                    LoggingHelper.w(TAG, "Error closing file output stream", e);
                }
            }
        }
    }
    
    /**
     * Get cache directory
     * 
     * @param context Android context
     * @return cache directory File object
     */
    @NonNull
    public static File getCacheDir(@NonNull Context context) {
        return context.getCacheDir();
    }
    
    /**
     * Get files directory
     * 
     * @param context Android context
     * @return files directory File object
     */
    @NonNull
    public static File getFilesDir(@NonNull Context context) {
        return context.getFilesDir();
    }
    
    /**
     * Get database directory
     * 
     * @param context Android context
     * @param name database name
     * @return database file File object
     */
    @NonNull
    public static File getDatabaseDir(@NonNull Context context, @NonNull String name) {
        return context.getDatabasePath(name);
    }
    
    /**
     * Clear cache directory
     * 
     * @param context Android context
     * @return true if cache was cleared successfully
     */
    public static boolean clearCache(@NonNull Context context) {
        try {
            File cacheDir = getCacheDir(context);
            
            if (!cacheDir.exists()) {
                return true;
            }
            
            return deleteDir(cacheDir);
        } catch (Exception e) {
            LoggingHelper.w(TAG, "Error clearing cache", e);
            return false;
        }
    }
    
    /**
     * Recursively delete directory
     * 
     * @param dir directory to delete
     * @return true if deletion was successful
     */
    public static boolean deleteDir(@NonNull File dir) {
        if (dir.isDirectory()) {
            File[] children = dir.listFiles();
            
            if (children != null) {
                for (File child : children) {
                    if (!deleteDir(child)) {
                        return false;
                    }
                }
            }
        }
        
        return dir.delete();
    }
    
    /**
     * Get external storage state
     * 
     * @return external storage state string
     */
    public static String getExternalStorageState() {
        return Environment.getExternalStorageState();
    }
    
    /**
     * Check if external storage is available
     * 
     * @return true if external storage is available
     */
    public static boolean isExternalStorageAvailable() {
        return Environment.MEDIA_MOUNTED.equals(getExternalStorageState());
    }
    
    /**
     * Get file extension
     * 
     * @param filename filename
     * @return file extension (without dot) or empty string
     */
    @NonNull
    public static String getFileExtension(@NonNull String filename) {
        int lastDot = filename.lastIndexOf('.');
        
        if (lastDot <= 0) {
            return "";
        }
        
        return filename.substring(lastDot + 1).toLowerCase();
    }
    
    /**
     * Get file name without extension
     * 
     * @param filename filename
     * @return filename without extension
     */
    @NonNull
    public static String getFileNameWithoutExtension(@NonNull String filename) {
        int lastDot = filename.lastIndexOf('.');
        
        if (lastDot <= 0) {
            return filename;
        }
        
        return filename.substring(0, lastDot);
    }
}
