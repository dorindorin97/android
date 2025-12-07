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

import java.io.Closeable;
import org.csploit.android.helpers.LoggingHelper;
import java.io.IOException;
import org.csploit.android.helpers.LoggingHelper;
import java.io.InputStream;
import org.csploit.android.helpers.LoggingHelper;
import java.io.OutputStream;
import org.csploit.android.helpers.LoggingHelper;
import java.net.Socket;
import org.csploit.android.helpers.LoggingHelper;

/**
 * Helper class for closing resources safely without exceptions.
 * Provides centralized resource cleanup utilities.
 */
public class CloseableHelper {
    
    private static final String TAG = "CloseableHelper";
    
    /**
     * Close a Closeable resource silently (no exceptions).
     * 
     * @param closeable Resource to close (can be null)
     */
    public static void closeQuietly(@Nullable Closeable closeable) {
        if (closeable != null) {
            try {
                closeable.close();
            } catch (IOException e) {
                // Intentionally silent - this is a cleanup operation
                LoggingHelper.v(TAG, "Exception while closing resource: " + e.getMessage());
            }
        }
    }
    
    /**
     * Close multiple Closeable resources silently.
     * 
     * @param closeables Resources to close (can contain nulls)
     */
    public static void closeQuietly(@Nullable Closeable... closeables) {
        if (closeables == null) return;
        
        for (Closeable closeable : closeables) {
            closeQuietly(closeable);
        }
    }
    
    /**
     * Close a Socket silently.
     * 
     * @param socket Socket to close (can be null)
     */
    public static void closeQuietly(@Nullable Socket socket) {
        if (socket != null) {
            try {
                socket.close();
            } catch (IOException e) {
                LoggingHelper.v(TAG, "Exception while closing socket: " + e.getMessage());
            }
        }
    }
    
    /**
     * Close an InputStream silently.
     * 
     * @param inputStream Stream to close (can be null)
     */
    public static void closeQuietly(@Nullable InputStream inputStream) {
        if (inputStream != null) {
            try {
                inputStream.close();
            } catch (IOException e) {
                LoggingHelper.v(TAG, "Exception while closing input stream: " + e.getMessage());
            }
        }
    }
    
    /**
     * Close an OutputStream silently (flushes first).
     * 
     * @param outputStream Stream to close (can be null)
     */
    public static void closeQuietly(@Nullable OutputStream outputStream) {
        if (outputStream != null) {
            try {
                outputStream.flush();
            } catch (IOException e) {
                // Ignore flush exception
            }
            try {
                outputStream.close();
            } catch (IOException e) {
                LoggingHelper.v(TAG, "Exception while closing output stream: " + e.getMessage());
            }
        }
    }
    
    /**
     * Close an AutoCloseable resource silently.
     * 
     * @param autoCloseable Resource to close (can be null)
     */
    public static void closeQuietly(@Nullable AutoCloseable autoCloseable) {
        if (autoCloseable != null) {
            try {
                autoCloseable.close();
            } catch (Exception e) {
                LoggingHelper.v(TAG, "Exception while closing auto-closeable: " + e.getMessage());
            }
        }
    }
    
    /**
     * Close a resource with logging on failure.
     * 
     * @param closeable Resource to close
     * @param resourceName Name of resource for logging
     */
    public static void closeWithLogging(@Nullable Closeable closeable, 
                                        @NonNull String resourceName) {
        if (closeable != null) {
            try {
                closeable.close();
                LoggingHelper.v(TAG, "Closed resource: " + resourceName);
            } catch (IOException e) {
                LoggingHelper.w(TAG, "Failed to close " + resourceName + ": " + e.getMessage());
            }
        }
    }
    
    /**
     * Ensure a socket is fully closed (both input and output streams).
     * 
     * @param socket Socket to close completely
     */
    public static void closeSocketFully(@Nullable Socket socket) {
        if (socket == null) return;
        
        try {
            if (!socket.isInputShutdown()) {
                socket.shutdownInput();
            }
        } catch (IOException e) {
            // Ignore
        }
        
        try {
            if (!socket.isOutputShutdown()) {
                socket.shutdownOutput();
            }
        } catch (IOException e) {
            // Ignore
        }
        
        closeQuietly(socket);
    }
    
    private CloseableHelper() {
        // Prevent instantiation
    }
}
