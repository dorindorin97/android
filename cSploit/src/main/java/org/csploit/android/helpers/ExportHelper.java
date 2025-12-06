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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with cSploit. If not, see <http://www.gnu.org/licenses/>.
 */

package org.csploit.android.helpers;

import android.content.ContentResolver;
import android.content.ContentValues;
import android.content.Context;
import android.database.Cursor;
import android.net.Uri;
import android.os.Build;
import android.os.Environment;
import android.provider.MediaStore;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.io.OutputStreamWriter;
import java.text.SimpleDateFormat;
import java.util.Date;
import java.util.Locale;
import java.util.zip.GZIPOutputStream;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

/**
 * ExportHelper - Data export utilities for scan results, logs, and reports.
 * 
 * Provides methods for:
 * - Exporting data to files (JSON, CSV, TXT)
 * - Creating compressed archives
 * - Using MediaStore for Android 10+ compatibility
 * - Generating timestamped filenames
 * - Sharing exported files
 * 
 * Usage:
 * {@code
 * // Export scan results
 * ExportHelper.ExportResult result = ExportHelper.exportToFile(
 *     context, "scan_results", ExportFormat.JSON, jsonData);
 * 
 * // Create CSV export
 * String csvData = ExportHelper.toCsv(headers, rows);
 * ExportHelper.exportToFile(context, "ports", ExportFormat.CSV, csvData);
 * }
 */
public final class ExportHelper {
    
    public static final String TAG = "ExportHelper";
    
    private static final SimpleDateFormat TIMESTAMP_FORMAT = 
            new SimpleDateFormat("yyyyMMdd_HHmmss", Locale.US);
    
    /**
     * Export format types.
     */
    public enum ExportFormat {
        JSON("json", "application/json"),
        CSV("csv", "text/csv"),
        TXT("txt", "text/plain"),
        XML("xml", "application/xml"),
        HTML("html", "text/html"),
        LOG("log", "text/plain");
        
        public final String extension;
        public final String mimeType;
        
        ExportFormat(String extension, String mimeType) {
            this.extension = extension;
            this.mimeType = mimeType;
        }
    }
    
    /**
     * Export result data.
     */
    public static class ExportResult {
        public final boolean success;
        public final String filePath;
        public final Uri uri;
        public final String error;
        
        private ExportResult(boolean success, String filePath, Uri uri, String error) {
            this.success = success;
            this.filePath = filePath;
            this.uri = uri;
            this.error = error;
        }
        
        public static ExportResult success(String filePath, Uri uri) {
            return new ExportResult(true, filePath, uri, null);
        }
        
        public static ExportResult failure(String error) {
            return new ExportResult(false, null, null, error);
        }
    }
    
    private ExportHelper() {}
    
    /**
     * Generate timestamped filename.
     * 
     * @param baseName base name for the file
     * @param format export format
     * @return filename with timestamp
     */
    @NonNull
    public static String generateFilename(@NonNull String baseName, @NonNull ExportFormat format) {
        String timestamp = TIMESTAMP_FORMAT.format(new Date());
        return String.format("%s_%s.%s", baseName, timestamp, format.extension);
    }
    
    /**
     * Export data to a file.
     * Uses MediaStore on Android 10+ for proper external storage access.
     * 
     * @param context Android context
     * @param baseName base filename (without extension)
     * @param format export format
     * @param content data to export
     * @return export result
     */
    @NonNull
    public static ExportResult exportToFile(@NonNull Context context, 
                                            @NonNull String baseName,
                                            @NonNull ExportFormat format,
                                            @NonNull String content) {
        String filename = generateFilename(baseName, format);
        
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
            return exportWithMediaStore(context, filename, format, content);
        } else {
            return exportLegacy(context, filename, format, content);
        }
    }
    
    /**
     * Export using MediaStore (Android 10+).
     */
    @NonNull
    private static ExportResult exportWithMediaStore(@NonNull Context context,
                                                     @NonNull String filename,
                                                     @NonNull ExportFormat format,
                                                     @NonNull String content) {
        ContentResolver resolver = context.getContentResolver();
        ContentValues values = new ContentValues();
        
        values.put(MediaStore.Downloads.DISPLAY_NAME, filename);
        values.put(MediaStore.Downloads.MIME_TYPE, format.mimeType);
        values.put(MediaStore.Downloads.IS_PENDING, 1);
        
        Uri collection = MediaStore.Downloads.getContentUri(MediaStore.VOLUME_EXTERNAL_PRIMARY);
        Uri itemUri = resolver.insert(collection, values);
        
        if (itemUri == null) {
            return ExportResult.failure("Failed to create file in MediaStore");
        }
        
        try (OutputStream os = resolver.openOutputStream(itemUri);
             BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(os))) {
            
            writer.write(content);
            writer.flush();
            
            // Mark as complete
            values.clear();
            values.put(MediaStore.Downloads.IS_PENDING, 0);
            resolver.update(itemUri, values, null, null);
            
            return ExportResult.success(filename, itemUri);
            
        } catch (IOException e) {
            LoggingHelper.e(TAG, "Export failed", e);
            resolver.delete(itemUri, null, null);
            return ExportResult.failure("Export failed: " + e.getMessage());
        }
    }
    
    /**
     * Export using legacy file system (pre-Android 10).
     */
    @NonNull
    private static ExportResult exportLegacy(@NonNull Context context,
                                             @NonNull String filename,
                                             @NonNull ExportFormat format,
                                             @NonNull String content) {
        File downloadsDir = Environment.getExternalStoragePublicDirectory(
                Environment.DIRECTORY_DOWNLOADS);
        
        if (!downloadsDir.exists() && !downloadsDir.mkdirs()) {
            return ExportResult.failure("Failed to create downloads directory");
        }
        
        File file = new File(downloadsDir, filename);
        
        try (FileOutputStream fos = new FileOutputStream(file);
             BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(fos))) {
            
            writer.write(content);
            writer.flush();
            
            Uri uri = Uri.fromFile(file);
            return ExportResult.success(file.getAbsolutePath(), uri);
            
        } catch (IOException e) {
            LoggingHelper.e(TAG, "Export failed", e);
            return ExportResult.failure("Export failed: " + e.getMessage());
        }
    }
    
    /**
     * Export to app's private directory (no permissions required).
     * 
     * @param context Android context
     * @param baseName base filename
     * @param format export format
     * @param content data to export
     * @return export result
     */
    @NonNull
    public static ExportResult exportToPrivate(@NonNull Context context,
                                               @NonNull String baseName,
                                               @NonNull ExportFormat format,
                                               @NonNull String content) {
        String filename = generateFilename(baseName, format);
        File exportsDir = new File(context.getExternalFilesDir(null), "exports");
        
        if (!exportsDir.exists() && !exportsDir.mkdirs()) {
            return ExportResult.failure("Failed to create exports directory");
        }
        
        File file = new File(exportsDir, filename);
        
        try (FileOutputStream fos = new FileOutputStream(file);
             BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(fos))) {
            
            writer.write(content);
            writer.flush();
            
            Uri uri = Uri.fromFile(file);
            return ExportResult.success(file.getAbsolutePath(), uri);
            
        } catch (IOException e) {
            LoggingHelper.e(TAG, "Export to private failed", e);
            return ExportResult.failure("Export failed: " + e.getMessage());
        }
    }
    
    /**
     * Convert data to CSV format.
     * 
     * @param headers column headers
     * @param rows data rows
     * @return CSV formatted string
     */
    @NonNull
    public static String toCsv(@NonNull String[] headers, @NonNull String[][] rows) {
        StringBuilder sb = new StringBuilder();
        
        // Headers
        for (int i = 0; i < headers.length; i++) {
            if (i > 0) sb.append(",");
            sb.append(escapeCsv(headers[i]));
        }
        sb.append("\n");
        
        // Data rows
        for (String[] row : rows) {
            for (int i = 0; i < row.length; i++) {
                if (i > 0) sb.append(",");
                sb.append(escapeCsv(row[i]));
            }
            sb.append("\n");
        }
        
        return sb.toString();
    }
    
    /**
     * Escape a value for CSV.
     */
    @NonNull
    private static String escapeCsv(@Nullable String value) {
        if (value == null) return "";
        
        if (value.contains(",") || value.contains("\"") || value.contains("\n")) {
            return "\"" + value.replace("\"", "\"\"") + "\"";
        }
        return value;
    }
    
    /**
     * Create a ZIP archive from multiple files.
     * 
     * @param context Android context
     * @param archiveName base name for the archive
     * @param files files to include
     * @return export result with archive path
     */
    @NonNull
    public static ExportResult createZipArchive(@NonNull Context context,
                                                @NonNull String archiveName,
                                                @NonNull File[] files) {
        String filename = generateFilename(archiveName, ExportFormat.TXT).replace(".txt", ".zip");
        File exportsDir = new File(context.getExternalFilesDir(null), "exports");
        
        if (!exportsDir.exists() && !exportsDir.mkdirs()) {
            return ExportResult.failure("Failed to create exports directory");
        }
        
        File zipFile = new File(exportsDir, filename);
        
        try (ZipOutputStream zos = new ZipOutputStream(new FileOutputStream(zipFile))) {
            byte[] buffer = new byte[4096];
            
            for (File file : files) {
                if (!file.exists() || !file.isFile()) continue;
                
                ZipEntry entry = new ZipEntry(file.getName());
                zos.putNextEntry(entry);
                
                try (FileInputStream fis = new FileInputStream(file)) {
                    int len;
                    while ((len = fis.read(buffer)) > 0) {
                        zos.write(buffer, 0, len);
                    }
                }
                
                zos.closeEntry();
            }
            
            Uri uri = Uri.fromFile(zipFile);
            return ExportResult.success(zipFile.getAbsolutePath(), uri);
            
        } catch (IOException e) {
            LoggingHelper.e(TAG, "ZIP creation failed", e);
            return ExportResult.failure("ZIP creation failed: " + e.getMessage());
        }
    }
    
    /**
     * Compress content using GZIP.
     * 
     * @param context Android context
     * @param baseName base filename
     * @param content content to compress
     * @return export result
     */
    @NonNull
    public static ExportResult compressGzip(@NonNull Context context,
                                            @NonNull String baseName,
                                            @NonNull String content) {
        String filename = generateFilename(baseName, ExportFormat.TXT) + ".gz";
        File exportsDir = new File(context.getExternalFilesDir(null), "exports");
        
        if (!exportsDir.exists() && !exportsDir.mkdirs()) {
            return ExportResult.failure("Failed to create exports directory");
        }
        
        File gzFile = new File(exportsDir, filename);
        
        try (GZIPOutputStream gzos = new GZIPOutputStream(new FileOutputStream(gzFile));
             OutputStreamWriter writer = new OutputStreamWriter(gzos)) {
            
            writer.write(content);
            writer.flush();
            
            Uri uri = Uri.fromFile(gzFile);
            return ExportResult.success(gzFile.getAbsolutePath(), uri);
            
        } catch (IOException e) {
            LoggingHelper.e(TAG, "GZIP compression failed", e);
            return ExportResult.failure("Compression failed: " + e.getMessage());
        }
    }
    
    /**
     * Read file content as string.
     * 
     * @param file file to read
     * @return file content or null on error
     */
    @Nullable
    public static String readFileAsString(@NonNull File file) {
        if (!file.exists() || !file.isFile()) {
            return null;
        }
        
        StringBuilder sb = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(new FileInputStream(file)))) {
            
            String line;
            while ((line = reader.readLine()) != null) {
                sb.append(line).append("\n");
            }
            
            return sb.toString();
            
        } catch (IOException e) {
            LoggingHelper.e(TAG, "Failed to read file", e);
            return null;
        }
    }
    
    /**
     * Get exports directory.
     * 
     * @param context Android context
     * @return exports directory
     */
    @NonNull
    public static File getExportsDirectory(@NonNull Context context) {
        File exportsDir = new File(context.getExternalFilesDir(null), "exports");
        if (!exportsDir.exists()) {
            exportsDir.mkdirs();
        }
        return exportsDir;
    }
    
    /**
     * List exported files.
     * 
     * @param context Android context
     * @return array of exported files
     */
    @NonNull
    public static File[] listExports(@NonNull Context context) {
        File exportsDir = getExportsDirectory(context);
        File[] files = exportsDir.listFiles();
        return files != null ? files : new File[0];
    }
    
    /**
     * Delete all exported files.
     * 
     * @param context Android context
     * @return number of files deleted
     */
    public static int clearExports(@NonNull Context context) {
        File[] files = listExports(context);
        int deleted = 0;
        
        for (File file : files) {
            if (file.delete()) {
                deleted++;
            }
        }
        
        LoggingHelper.i(TAG, "Cleared " + deleted + " export files");
        return deleted;
    }
}
