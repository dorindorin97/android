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

import android.content.Context;
import org.csploit.android.helpers.LoggingHelper;
import android.content.res.AssetManager;
import org.csploit.android.helpers.LoggingHelper;
import android.os.Build;
import org.csploit.android.helpers.LoggingHelper;

import androidx.annotation.NonNull;
import org.csploit.android.helpers.LoggingHelper;
import androidx.annotation.Nullable;
import org.csploit.android.helpers.LoggingHelper;

import java.io.BufferedReader;
import org.csploit.android.helpers.LoggingHelper;
import java.io.File;
import org.csploit.android.helpers.LoggingHelper;
import java.io.FileInputStream;
import org.csploit.android.helpers.LoggingHelper;
import java.io.FileOutputStream;
import org.csploit.android.helpers.LoggingHelper;
import java.io.IOException;
import org.csploit.android.helpers.LoggingHelper;
import java.io.InputStream;
import org.csploit.android.helpers.LoggingHelper;
import java.io.InputStreamReader;
import org.csploit.android.helpers.LoggingHelper;
import java.io.OutputStream;
import org.csploit.android.helpers.LoggingHelper;
import java.nio.charset.StandardCharsets;
import org.csploit.android.helpers.LoggingHelper;
import java.security.MessageDigest;
import org.csploit.android.helpers.LoggingHelper;
import java.security.NoSuchAlgorithmException;
import org.csploit.android.helpers.LoggingHelper;
import java.util.zip.GZIPInputStream;
import org.csploit.android.helpers.LoggingHelper;
import java.util.zip.GZIPOutputStream;
import org.csploit.android.helpers.LoggingHelper;
import java.util.zip.ZipEntry;
import org.csploit.android.helpers.LoggingHelper;
import java.util.zip.ZipInputStream;
import org.csploit.android.helpers.LoggingHelper;

/**
 * AssetHelper - Utilities for working with app assets and files.
 * 
 * Provides methods for:
 * - Extracting assets to filesystem
 * - Copying files between locations
 * - Checksum validation
 * - Compression/decompression
 */
public final class AssetHelper {
    
    private static final String TAG = "AssetHelper";
    private static final int BUFFER_SIZE = 8192;
    
    private AssetHelper() {}
    
    /**
     * Copy an asset file to the filesystem.
     * 
     * @param context Application context
     * @param assetPath Path within assets folder
     * @param destFile Destination file
     * @return true if successful
     */
    public static boolean copyAssetToFile(@NonNull Context context, @NonNull String assetPath,
                                          @NonNull File destFile) {
        try {
            // Ensure parent directory exists
            File parent = destFile.getParentFile();
            if (parent != null && !parent.exists() && !parent.mkdirs()) {
                LoggingHelper.w(TAG, "Failed to create directory: " + parent);
                return false;
            }
            
            try (InputStream in = context.getAssets().open(assetPath);
                 FileOutputStream out = new FileOutputStream(destFile)) {
                copyStream(in, out);
            }
            return true;
        } catch (IOException e) {
            LoggingHelper.e(TAG, "Failed to copy asset: " + assetPath, e);
            return false;
        }
    }
    
    /**
     * Copy all files from an asset directory to filesystem.
     * 
     * @param context Application context
     * @param assetDir Directory within assets
     * @param destDir Destination directory
     * @return Number of files copied
     */
    public static int copyAssetDirectory(@NonNull Context context, @NonNull String assetDir,
                                         @NonNull File destDir) {
        int copied = 0;
        try {
            AssetManager assets = context.getAssets();
            String[] files = assets.list(assetDir);
            
            if (files == null || files.length == 0) {
                return 0;
            }
            
            if (!destDir.exists() && !destDir.mkdirs()) {
                LoggingHelper.w(TAG, "Failed to create directory: " + destDir);
                return 0;
            }
            
            for (String fileName : files) {
                String assetPath = assetDir.isEmpty() ? fileName : assetDir + "/" + fileName;
                File destFile = new File(destDir, fileName);
                
                // Check if it's a directory by trying to list it
                String[] subFiles = assets.list(assetPath);
                if (subFiles != null && subFiles.length > 0) {
                    // It's a directory
                    copied += copyAssetDirectory(context, assetPath, destFile);
                } else {
                    // It's a file
                    if (copyAssetToFile(context, assetPath, destFile)) {
                        copied++;
                    }
                }
            }
        } catch (IOException e) {
            LoggingHelper.e(TAG, "Failed to copy asset directory: " + assetDir, e);
        }
        return copied;
    }
    
    /**
     * Read an asset file as a string.
     * 
     * @param context Application context
     * @param assetPath Path within assets folder
     * @return File contents or null on error
     */
    @Nullable
    public static String readAssetAsString(@NonNull Context context, @NonNull String assetPath) {
        try (InputStream in = context.getAssets().open(assetPath);
             BufferedReader reader = new BufferedReader(new InputStreamReader(in, StandardCharsets.UTF_8))) {
            
            StringBuilder sb = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line).append('\n');
            }
            return sb.toString();
        } catch (IOException e) {
            LoggingHelper.e(TAG, "Failed to read asset: " + assetPath, e);
            return null;
        }
    }
    
    /**
     * Read an asset file as bytes.
     * 
     * @param context Application context
     * @param assetPath Path within assets folder
     * @return File bytes or null on error
     */
    @Nullable
    public static byte[] readAssetAsBytes(@NonNull Context context, @NonNull String assetPath) {
        try (InputStream in = context.getAssets().open(assetPath)) {
            byte[] buffer = new byte[in.available()];
            int read = in.read(buffer);
            if (read != buffer.length) {
                LoggingHelper.w(TAG, "Partial read of asset: " + assetPath);
            }
            return buffer;
        } catch (IOException e) {
            LoggingHelper.e(TAG, "Failed to read asset: " + assetPath, e);
            return null;
        }
    }
    
    /**
     * Check if an asset exists.
     * 
     * @param context Application context
     * @param assetPath Path within assets folder
     * @return true if asset exists
     */
    public static boolean assetExists(@NonNull Context context, @NonNull String assetPath) {
        try (InputStream in = context.getAssets().open(assetPath)) {
            return true;
        } catch (IOException e) {
            return false;
        }
    }
    
    /**
     * Copy a file from one location to another.
     * 
     * @param src Source file
     * @param dest Destination file
     * @return true if successful
     */
    public static boolean copyFile(@NonNull File src, @NonNull File dest) {
        try {
            File parent = dest.getParentFile();
            if (parent != null && !parent.exists() && !parent.mkdirs()) {
                return false;
            }
            
            try (FileInputStream in = new FileInputStream(src);
                 FileOutputStream out = new FileOutputStream(dest)) {
                copyStream(in, out);
            }
            return true;
        } catch (IOException e) {
            LoggingHelper.e(TAG, "Failed to copy file: " + src + " -> " + dest, e);
            return false;
        }
    }
    
    /**
     * Copy data between streams.
     * 
     * @param in Input stream
     * @param out Output stream
     * @throws IOException on I/O error
     */
    public static void copyStream(@NonNull InputStream in, @NonNull OutputStream out) throws IOException {
        byte[] buffer = new byte[BUFFER_SIZE];
        int read;
        while ((read = in.read(buffer)) != -1) {
            out.write(buffer, 0, read);
        }
        out.flush();
    }
    
    /**
     * Calculate MD5 hash of a file.
     * 
     * @param file File to hash
     * @return MD5 hash as hex string, or null on error
     */
    @Nullable
    public static String md5sum(@NonNull File file) {
        return hashFile(file, "MD5");
    }
    
    /**
     * Calculate SHA-256 hash of a file.
     * 
     * @param file File to hash
     * @return SHA-256 hash as hex string, or null on error
     */
    @Nullable
    public static String sha256sum(@NonNull File file) {
        return hashFile(file, "SHA-256");
    }
    
    /**
     * Calculate hash of a file.
     * 
     * @param file File to hash
     * @param algorithm Hash algorithm (MD5, SHA-1, SHA-256, etc.)
     * @return Hash as hex string, or null on error
     */
    @Nullable
    public static String hashFile(@NonNull File file, @NonNull String algorithm) {
        try {
            MessageDigest digest = MessageDigest.getInstance(algorithm);
            
            try (FileInputStream in = new FileInputStream(file)) {
                byte[] buffer = new byte[BUFFER_SIZE];
                int read;
                while ((read = in.read(buffer)) != -1) {
                    digest.update(buffer, 0, read);
                }
            }
            
            return bytesToHex(digest.digest());
        } catch (NoSuchAlgorithmException | IOException e) {
            LoggingHelper.e(TAG, "Failed to hash file: " + file, e);
            return null;
        }
    }
    
    /**
     * Calculate hash of bytes.
     * 
     * @param data Data to hash
     * @param algorithm Hash algorithm
     * @return Hash as hex string, or null on error
     */
    @Nullable
    public static String hashBytes(@NonNull byte[] data, @NonNull String algorithm) {
        try {
            MessageDigest digest = MessageDigest.getInstance(algorithm);
            return bytesToHex(digest.digest(data));
        } catch (NoSuchAlgorithmException e) {
            LoggingHelper.e(TAG, "Unknown algorithm: " + algorithm, e);
            return null;
        }
    }
    
    /**
     * Compress a file using GZIP.
     * 
     * @param src Source file
     * @param dest Destination file (.gz)
     * @return true if successful
     */
    public static boolean gzipCompress(@NonNull File src, @NonNull File dest) {
        try (FileInputStream in = new FileInputStream(src);
             GZIPOutputStream out = new GZIPOutputStream(new FileOutputStream(dest))) {
            copyStream(in, out);
            return true;
        } catch (IOException e) {
            LoggingHelper.e(TAG, "Failed to compress file: " + src, e);
            return false;
        }
    }
    
    /**
     * Decompress a GZIP file.
     * 
     * @param src Source file (.gz)
     * @param dest Destination file
     * @return true if successful
     */
    public static boolean gzipDecompress(@NonNull File src, @NonNull File dest) {
        try (GZIPInputStream in = new GZIPInputStream(new FileInputStream(src));
             FileOutputStream out = new FileOutputStream(dest)) {
            copyStream(in, out);
            return true;
        } catch (IOException e) {
            LoggingHelper.e(TAG, "Failed to decompress file: " + src, e);
            return false;
        }
    }
    
    /**
     * Extract a ZIP archive.
     * 
     * @param zipFile ZIP file
     * @param destDir Destination directory
     * @return Number of files extracted
     */
    public static int extractZip(@NonNull File zipFile, @NonNull File destDir) {
        int extracted = 0;
        
        try (ZipInputStream zis = new ZipInputStream(new FileInputStream(zipFile))) {
            ZipEntry entry;
            byte[] buffer = new byte[BUFFER_SIZE];
            
            while ((entry = zis.getNextEntry()) != null) {
                File destFile = new File(destDir, entry.getName());
                
                // Security check - prevent zip slip attack
                String destPath = destFile.getCanonicalPath();
                String destDirPath = destDir.getCanonicalPath();
                if (!destPath.startsWith(destDirPath + File.separator)) {
                    LoggingHelper.w(TAG, "Skipping entry outside dest dir: " + entry.getName());
                    continue;
                }
                
                if (entry.isDirectory()) {
                    if (!destFile.mkdirs() && !destFile.isDirectory()) {
                        LoggingHelper.w(TAG, "Failed to create directory: " + destFile);
                    }
                } else {
                    // Ensure parent directory exists
                    File parent = destFile.getParentFile();
                    if (parent != null && !parent.exists() && !parent.mkdirs()) {
                        LoggingHelper.w(TAG, "Failed to create directory: " + parent);
                        continue;
                    }
                    
                    try (FileOutputStream out = new FileOutputStream(destFile)) {
                        int read;
                        while ((read = zis.read(buffer)) != -1) {
                            out.write(buffer, 0, read);
                        }
                    }
                    extracted++;
                }
                zis.closeEntry();
            }
        } catch (IOException e) {
            LoggingHelper.e(TAG, "Failed to extract ZIP: " + zipFile, e);
        }
        
        return extracted;
    }
    
    /**
     * Delete a directory recursively.
     * 
     * @param dir Directory to delete
     * @return true if completely deleted
     */
    public static boolean deleteDirectory(@NonNull File dir) {
        if (!dir.exists()) {
            return true;
        }
        
        if (dir.isDirectory()) {
            File[] children = dir.listFiles();
            if (children != null) {
                for (File child : children) {
                    if (!deleteDirectory(child)) {
                        return false;
                    }
                }
            }
        }
        
        return dir.delete();
    }
    
    /**
     * Get the size of a directory (sum of all files).
     * 
     * @param dir Directory
     * @return Size in bytes
     */
    public static long getDirectorySize(@NonNull File dir) {
        if (!dir.exists()) {
            return 0;
        }
        
        if (dir.isFile()) {
            return dir.length();
        }
        
        long size = 0;
        File[] children = dir.listFiles();
        if (children != null) {
            for (File child : children) {
                size += getDirectorySize(child);
            }
        }
        return size;
    }
    
    /**
     * Format file size for display.
     * 
     * @param bytes Size in bytes
     * @return Formatted size string (e.g., "1.5 MB")
     */
    @NonNull
    public static String formatFileSize(long bytes) {
        if (bytes < 1024) {
            return bytes + " B";
        } else if (bytes < 1024 * 1024) {
            return String.format("%.1f KB", bytes / 1024.0);
        } else if (bytes < 1024 * 1024 * 1024) {
            return String.format("%.1f MB", bytes / (1024.0 * 1024));
        } else {
            return String.format("%.2f GB", bytes / (1024.0 * 1024 * 1024));
        }
    }
    
    /**
     * Make a file executable.
     * 
     * @param file File to make executable
     * @return true if successful
     */
    public static boolean setExecutable(@NonNull File file) {
        return file.setExecutable(true, false);
    }
    
    /**
     * Check if a file is executable.
     * 
     * @param file File to check
     * @return true if executable
     */
    public static boolean isExecutable(@NonNull File file) {
        return file.canExecute();
    }
    
    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }
}
