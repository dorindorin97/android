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
package org.csploit.android.core;

import androidx.annotation.NonNull;

/**
 * Central repository for configuration constants used throughout the application.
 * This consolidates hardcoded values that were previously scattered across multiple files.
 *
 * Benefits:
 * - Single source of truth for configuration values
 * - Easier to modify default values
 * - Better documentation of what values are configurable
 * - Reduces magic numbers in code
 */
public final class ConfigurationConstants {

    // ==================== Network Ports ====================

    /** Default HTTP proxy port */
    public static final int DEFAULT_HTTP_PROXY_PORT = 8080;

    /** Default HTTP server port */
    public static final int DEFAULT_HTTP_SERVER_PORT = 8081;

    /** Default HTTPS redirector port */
    public static final int DEFAULT_HTTPS_REDIRECTOR_PORT = 8082;

    /** Default Metasploit RPC port */
    public static final int DEFAULT_MSF_RPC_PORT = 55553;

    /** Minimum valid port number */
    public static final int PORT_MIN = 1;

    /** Maximum valid port number */
    public static final int PORT_MAX = 65535;

    // ==================== Preference Keys ====================

    /** Storage path preference key */
    public static final String PREF_SAVE_PATH = "PREF_SAVE_PATH";

    /** Wake lock preference key */
    public static final String PREF_WAKE_LOCK = "PREF_WAKE_LOCK";

    /** Debug error logging preference key */
    public static final String PREF_DEBUG_ERROR_LOGGING = "PREF_DEBUG_ERROR_LOGGING";

    /** HTTP proxy port preference key */
    public static final String PREF_HTTP_PROXY_PORT = "PREF_HTTP_PROXY_PORT";

    /** HTTP server port preference key */
    public static final String PREF_HTTP_SERVER_PORT = "PREF_HTTP_SERVER_PORT";

    /** HTTPS redirector port preference key */
    public static final String PREF_HTTPS_REDIRECTOR_PORT = "PREF_HTTPS_REDIRECTOR_PORT";

    /** MSF RPC port preference key */
    public static final String PREF_MSF_RPC_PORT = "MSF_RPC_PORT";

    /** Ruby directory preference key */
    public static final String PREF_RUBY_DIR = "RUBY_DIR";

    /** MSF directory preference key */
    public static final String PREF_MSF_DIR = "MSF_DIR";

    /** Auto scan enabled preference key */
    public static final String PREF_AUTO_SCAN = "PREF_AUTO_SCAN";

    /** Theme preference key */
    public static final String PREF_THEME = "PREF_THEME";

    // ==================== File Names ====================

    /** Debug error log filename */
    public static final String ERROR_LOG_FILENAME = "csploit-debug-error.log";

    /** Session file extension */
    public static final String SESSION_FILE_EXTENSION = ".dss";

    /** Hijacker session file extension */
    public static final String HIJACKER_SESSION_FILE_EXTENSION = ".dhs";

    /** Session magic header */
    public static final String SESSION_MAGIC = "cSploitSession";

    /** Daemon socket filename */
    public static final String DAEMON_SOCKET_FILENAME = "cSploitd.sock";

    /** Daemon log filename */
    public static final String DAEMON_LOG_FILENAME = "cSploitd.log";

    /** Core version filename */
    public static final String VERSION_FILENAME = "VERSION";

    /** Start daemon script filename */
    public static final String START_DAEMON_SCRIPT = "start_daemon.sh";

    /** Daemon binary filename */
    public static final String DAEMON_BINARY = "cSploitd";

    /** Known issues filename */
    public static final String ISSUES_FILENAME = "issues";

    // ==================== Directory Names ====================

    /** Tools subdirectory */
    public static final String TOOLS_DIR = "tools";

    /** Ruby subdirectory */
    public static final String RUBY_DIR = "ruby";

    /** MSF subdirectory */
    public static final String MSF_DIR = "msf";

    /** NMap subdirectory under tools */
    public static final String NMAP_DIR = "nmap";

    /** NMap services filename */
    public static final String NMAP_SERVICES_FILE = "nmap-services";

    /** NMap MAC prefixes filename */
    public static final String NMAP_MAC_PREFIXES_FILE = "nmap-mac-prefixes";

    // ==================== System Paths ====================

    /** IPv4 forwarding control file */
    public static final String IPV4_FORWARD_FILEPATH = "/proc/sys/net/ipv4/ip_forward";

    // ==================== Timeouts (milliseconds) ====================

    /** Default network timeout */
    public static final int DEFAULT_NETWORK_TIMEOUT_MS = 5000;

    /** Default connection timeout */
    public static final int DEFAULT_CONNECTION_TIMEOUT_MS = 10000;

    /** Default socket timeout */
    public static final int DEFAULT_SOCKET_TIMEOUT_MS = 15000;

    /** Wake lock timeout (10 minutes) */
    public static final long WAKE_LOCK_TIMEOUT_MS = 10 * 60 * 1000L;

    /** Daemon connection retry delay */
    public static final int DAEMON_RETRY_DELAY_MS = 500;

    /** Maximum daemon connection retries */
    public static final int DAEMON_MAX_RETRIES = 10;

    // ==================== Buffer Sizes ====================

    /** Default buffer size for I/O operations */
    public static final int DEFAULT_BUFFER_SIZE = 8192;

    /** Large buffer size for bulk operations */
    public static final int LARGE_BUFFER_SIZE = 65536;

    // ==================== Scan Settings ====================

    /** Maximum lines to read during IRC scan */
    public static final int IRC_MAX_SCAN_LINES = 200;

    /** Default port scan timeout */
    public static final int DEFAULT_PORT_SCAN_TIMEOUT_MS = 200;

    /** Port availability check retries */
    public static final int PORT_CHECK_RETRIES = 3;

    // ==================== Authentication ====================

    /** Default daemon username */
    public static final String DAEMON_USERNAME = "android";

    /** Default daemon password (placeholder) */
    public static final String DAEMON_PASSWORD = "DEADBEEF";

    // ==================== MIME Types ====================

    /** JPEG MIME type */
    public static final String MIME_TYPE_JPEG = "image/jpeg";

    /** PNG MIME type */
    public static final String MIME_TYPE_PNG = "image/png";

    /** GIF MIME type */
    public static final String MIME_TYPE_GIF = "image/gif";

    /** TIFF MIME type */
    public static final String MIME_TYPE_TIFF = "image/tiff";

    // ==================== Utility Methods ====================

    /**
     * Get the MIME type for an image file based on its extension.
     *
     * @param fileName The filename to check
     * @return The MIME type string
     */
    @NonNull
    public static String getImageMimeType(@NonNull String fileName) {
        String name = fileName.toLowerCase();

        if (name.endsWith(".jpeg") || name.endsWith(".jpg")) {
            return MIME_TYPE_JPEG;
        } else if (name.endsWith(".png")) {
            return MIME_TYPE_PNG;
        } else if (name.endsWith(".gif")) {
            return MIME_TYPE_GIF;
        } else if (name.endsWith(".tiff")) {
            return MIME_TYPE_TIFF;
        }

        return MIME_TYPE_JPEG; // Default
    }

    /**
     * Check if a port number is valid.
     *
     * @param port The port number to check
     * @return true if the port is valid
     */
    public static boolean isValidPort(int port) {
        return port >= PORT_MIN && port <= PORT_MAX;
    }

    /**
     * Parse a port number from string with default fallback.
     *
     * @param portString The port string to parse
     * @param defaultPort The default port if parsing fails
     * @return The parsed port or default
     */
    public static int parsePort(String portString, int defaultPort) {
        if (portString == null || portString.isEmpty()) {
            return defaultPort;
        }

        try {
            int port = Integer.parseInt(portString);
            return isValidPort(port) ? port : defaultPort;
        } catch (NumberFormatException e) {
            return defaultPort;
        }
    }

    private ConfigurationConstants() {
        // Prevent instantiation
    }
}
