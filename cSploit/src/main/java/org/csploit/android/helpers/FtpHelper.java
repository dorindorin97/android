/*
 * This file is part of the cSploit.
 *
 * Copyleft of Simone Margaritelli aka evilsocket <evilsocket@gmail.com>
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

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Helper class for FTP protocol operations and analysis.
 * Provides utilities for FTP banner parsing, command execution,
 * and protocol fingerprinting.
 */
public final class FtpHelper {

    private static final String TAG = "FtpHelper";

    // Default FTP port
    public static final int DEFAULT_FTP_PORT = 21;
    public static final int DEFAULT_FTPS_PORT = 990;
    public static final int DEFAULT_TIMEOUT_MS = 10000;

    // FTP response codes
    public static final int CODE_SERVICE_READY = 220;
    public static final int CODE_NEED_PASSWORD = 331;
    public static final int CODE_LOGIN_SUCCESS = 230;
    public static final int CODE_LOGIN_FAILED = 530;
    public static final int CODE_COMMAND_OK = 200;
    public static final int CODE_SERVICE_CLOSING = 221;
    public static final int CODE_PASSIVE_MODE = 227;
    public static final int CODE_ENTERING_EPSV = 229;
    public static final int CODE_FILE_STATUS = 213;
    public static final int CODE_SYSTEM_TYPE = 215;
    public static final int CODE_DIRECTORY_STATUS = 212;
    public static final int CODE_FEATURE_LIST = 211;

    // Common FTP commands
    public static final String CMD_USER = "USER";
    public static final String CMD_PASS = "PASS";
    public static final String CMD_SYST = "SYST";
    public static final String CMD_FEAT = "FEAT";
    public static final String CMD_PWD = "PWD";
    public static final String CMD_LIST = "LIST";
    public static final String CMD_PASV = "PASV";
    public static final String CMD_PORT = "PORT";
    public static final String CMD_TYPE = "TYPE";
    public static final String CMD_QUIT = "QUIT";
    public static final String CMD_HELP = "HELP";
    public static final String CMD_STAT = "STAT";
    public static final String CMD_NOOP = "NOOP";

    // Patterns for parsing
    private static final Pattern RESPONSE_PATTERN = Pattern.compile("^(\\d{3})[-\\s](.*)$");
    private static final Pattern PASV_PATTERN = Pattern.compile(
            "\\((\\d+),(\\d+),(\\d+),(\\d+),(\\d+),(\\d+)\\)");
    private static final Pattern EPSV_PATTERN = Pattern.compile("\\|\\|\\|(\\d+)\\|");
    private static final Pattern BANNER_VERSION_PATTERN = Pattern.compile(
            "(?:FTP|vsftpd|ProFTPD|Pure-FTPd|FileZilla|wu-ftpd)[\\s-]*(\\d+\\.\\d+(?:\\.\\d+)?)", 
            Pattern.CASE_INSENSITIVE);

    // Known FTP server signatures
    private static final Map<String, String> SERVER_SIGNATURES = new LinkedHashMap<>();
    static {
        SERVER_SIGNATURES.put("vsftpd", "vsftpd");
        SERVER_SIGNATURES.put("proftpd", "ProFTPD");
        SERVER_SIGNATURES.put("pure-ftpd", "Pure-FTPd");
        SERVER_SIGNATURES.put("filezilla", "FileZilla Server");
        SERVER_SIGNATURES.put("wu-ftpd", "WU-FTPD");
        SERVER_SIGNATURES.put("microsoft ftp", "Microsoft FTP");
        SERVER_SIGNATURES.put("iis", "Microsoft IIS FTP");
        SERVER_SIGNATURES.put("serv-u", "Serv-U FTP");
        SERVER_SIGNATURES.put("gene6", "Gene6 FTP");
        SERVER_SIGNATURES.put("glftpd", "glFTPd");
        SERVER_SIGNATURES.put("ncftpd", "NcFTPd");
        SERVER_SIGNATURES.put("bftpd", "Bftpd");
    }

    private FtpHelper() {
        // Private constructor to prevent instantiation
    }

    /**
     * Represents an FTP server response.
     */
    public static class FtpResponse {
        private final int code;
        private final String message;
        private final List<String> lines;
        private final boolean multiline;

        public FtpResponse(int code, @NonNull String message) {
            this(code, message, Collections.singletonList(message), false);
        }

        public FtpResponse(int code, @NonNull String message, 
                          @NonNull List<String> lines, boolean multiline) {
            this.code = code;
            this.message = message;
            this.lines = new ArrayList<>(lines);
            this.multiline = multiline;
        }

        public int getCode() {
            return code;
        }

        @NonNull
        public String getMessage() {
            return message;
        }

        @NonNull
        public List<String> getLines() {
            return Collections.unmodifiableList(lines);
        }

        public boolean isMultiline() {
            return multiline;
        }

        public boolean isSuccess() {
            return code >= 200 && code < 400;
        }

        public boolean isError() {
            return code >= 400;
        }

        public boolean isPreliminary() {
            return code >= 100 && code < 200;
        }

        @Override
        public String toString() {
            return String.format(Locale.US, "%d %s", code, message);
        }
    }

    /**
     * Represents FTP server information.
     */
    public static class FtpServerInfo {
        private final String banner;
        private final String serverType;
        private final String version;
        private final String systemType;
        private final List<String> features;
        private final boolean anonymousAllowed;
        private final Map<String, String> additionalInfo;

        private FtpServerInfo(Builder builder) {
            this.banner = builder.banner;
            this.serverType = builder.serverType;
            this.version = builder.version;
            this.systemType = builder.systemType;
            this.features = new ArrayList<>(builder.features);
            this.anonymousAllowed = builder.anonymousAllowed;
            this.additionalInfo = new HashMap<>(builder.additionalInfo);
        }

        @Nullable
        public String getBanner() {
            return banner;
        }

        @Nullable
        public String getServerType() {
            return serverType;
        }

        @Nullable
        public String getVersion() {
            return version;
        }

        @Nullable
        public String getSystemType() {
            return systemType;
        }

        @NonNull
        public List<String> getFeatures() {
            return Collections.unmodifiableList(features);
        }

        public boolean isAnonymousAllowed() {
            return anonymousAllowed;
        }

        @NonNull
        public Map<String, String> getAdditionalInfo() {
            return Collections.unmodifiableMap(additionalInfo);
        }

        public boolean hasFeature(@NonNull String feature) {
            for (String f : features) {
                if (f.equalsIgnoreCase(feature)) {
                    return true;
                }
            }
            return false;
        }

        public static class Builder {
            private String banner;
            private String serverType;
            private String version;
            private String systemType;
            private List<String> features = new ArrayList<>();
            private boolean anonymousAllowed;
            private Map<String, String> additionalInfo = new HashMap<>();

            public Builder setBanner(String banner) {
                this.banner = banner;
                return this;
            }

            public Builder setServerType(String serverType) {
                this.serverType = serverType;
                return this;
            }

            public Builder setVersion(String version) {
                this.version = version;
                return this;
            }

            public Builder setSystemType(String systemType) {
                this.systemType = systemType;
                return this;
            }

            public Builder setFeatures(List<String> features) {
                this.features = new ArrayList<>(features);
                return this;
            }

            public Builder addFeature(String feature) {
                this.features.add(feature);
                return this;
            }

            public Builder setAnonymousAllowed(boolean anonymousAllowed) {
                this.anonymousAllowed = anonymousAllowed;
                return this;
            }

            public Builder addInfo(String key, String value) {
                this.additionalInfo.put(key, value);
                return this;
            }

            public FtpServerInfo build() {
                return new FtpServerInfo(this);
            }
        }
    }

    /**
     * Simple FTP client for basic operations.
     */
    public static class SimpleFtpClient implements AutoCloseable {
        private Socket socket;
        private BufferedReader reader;
        private PrintWriter writer;
        private final String host;
        private final int port;
        private final int timeout;

        public SimpleFtpClient(@NonNull String host) {
            this(host, DEFAULT_FTP_PORT, DEFAULT_TIMEOUT_MS);
        }

        public SimpleFtpClient(@NonNull String host, int port) {
            this(host, port, DEFAULT_TIMEOUT_MS);
        }

        public SimpleFtpClient(@NonNull String host, int port, int timeout) {
            this.host = host;
            this.port = port;
            this.timeout = timeout;
        }

        /**
         * Connects to the FTP server.
         */
        @NonNull
        public FtpResponse connect() throws IOException {
            socket = new Socket();
            socket.connect(new InetSocketAddress(host, port), timeout);
            socket.setSoTimeout(timeout);

            reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            writer = new PrintWriter(new OutputStreamWriter(socket.getOutputStream()), true);

            return readResponse();
        }

        /**
         * Sends a command and reads the response.
         */
        @NonNull
        public FtpResponse sendCommand(@NonNull String command) throws IOException {
            writer.println(command);
            return readResponse();
        }

        /**
         * Sends a command with an argument.
         */
        @NonNull
        public FtpResponse sendCommand(@NonNull String command, @NonNull String argument) 
                throws IOException {
            return sendCommand(command + " " + argument);
        }

        /**
         * Reads a response from the server.
         */
        @NonNull
        public FtpResponse readResponse() throws IOException {
            String line = reader.readLine();
            if (line == null) {
                throw new IOException("Connection closed by server");
            }

            Matcher matcher = RESPONSE_PATTERN.matcher(line);
            if (!matcher.matches()) {
                return new FtpResponse(-1, line);
            }

            int code = Integer.parseInt(matcher.group(1));
            String message = matcher.group(2);
            List<String> lines = new ArrayList<>();
            lines.add(message);

            // Check for multi-line response
            boolean multiline = line.charAt(3) == '-';
            if (multiline) {
                String endMarker = String.valueOf(code) + " ";
                while ((line = reader.readLine()) != null) {
                    if (line.startsWith(endMarker)) {
                        lines.add(line.substring(4));
                        break;
                    }
                    lines.add(line);
                }
            }

            return new FtpResponse(code, message, lines, multiline);
        }

        /**
         * Logs in with credentials.
         */
        @NonNull
        public FtpResponse login(@NonNull String username, @NonNull String password) 
                throws IOException {
            FtpResponse userResponse = sendCommand(CMD_USER, username);
            if (userResponse.getCode() == CODE_LOGIN_SUCCESS) {
                return userResponse;
            }
            if (userResponse.getCode() != CODE_NEED_PASSWORD) {
                return userResponse;
            }
            return sendCommand(CMD_PASS, password);
        }

        /**
         * Attempts anonymous login.
         */
        @NonNull
        public FtpResponse loginAnonymous() throws IOException {
            return login("anonymous", "anonymous@example.com");
        }

        /**
         * Gets system type.
         */
        @NonNull
        public FtpResponse getSystemType() throws IOException {
            return sendCommand(CMD_SYST);
        }

        /**
         * Gets supported features.
         */
        @NonNull
        public FtpResponse getFeatures() throws IOException {
            return sendCommand(CMD_FEAT);
        }

        /**
         * Disconnects from the server.
         */
        public void disconnect() {
            try {
                if (writer != null) {
                    sendCommand(CMD_QUIT);
                }
            } catch (IOException ignored) {
                // Ignore errors during disconnect
            }
            close();
        }

        @Override
        public void close() {
            try {
                if (reader != null) reader.close();
                if (writer != null) writer.close();
                if (socket != null && !socket.isClosed()) socket.close();
            } catch (IOException ignored) {
                // Ignore close errors
            }
        }
    }

    /**
     * Parses an FTP response string.
     */
    @Nullable
    public static FtpResponse parseResponse(@NonNull String response) {
        Matcher matcher = RESPONSE_PATTERN.matcher(response);
        if (matcher.matches()) {
            int code = Integer.parseInt(matcher.group(1));
            String message = matcher.group(2);
            return new FtpResponse(code, message);
        }
        return null;
    }

    /**
     * Identifies the FTP server type from a banner.
     */
    @Nullable
    public static String identifyServer(@NonNull String banner) {
        String lowerBanner = banner.toLowerCase(Locale.US);
        
        for (Map.Entry<String, String> entry : SERVER_SIGNATURES.entrySet()) {
            if (lowerBanner.contains(entry.getKey())) {
                return entry.getValue();
            }
        }
        
        return null;
    }

    /**
     * Extracts version information from a banner.
     */
    @Nullable
    public static String extractVersion(@NonNull String banner) {
        Matcher matcher = BANNER_VERSION_PATTERN.matcher(banner);
        if (matcher.find()) {
            return matcher.group(1);
        }
        return null;
    }

    /**
     * Parses PASV response to extract host and port.
     */
    @Nullable
    public static InetSocketAddress parsePasvResponse(@NonNull String response) {
        Matcher matcher = PASV_PATTERN.matcher(response);
        if (matcher.find()) {
            String host = String.format(Locale.US, "%s.%s.%s.%s",
                    matcher.group(1), matcher.group(2),
                    matcher.group(3), matcher.group(4));
            int port = Integer.parseInt(matcher.group(5)) * 256 + 
                       Integer.parseInt(matcher.group(6));
            return new InetSocketAddress(host, port);
        }
        return null;
    }

    /**
     * Parses EPSV response to extract port.
     */
    public static int parseEpsvResponse(@NonNull String response) {
        Matcher matcher = EPSV_PATTERN.matcher(response);
        if (matcher.find()) {
            return Integer.parseInt(matcher.group(1));
        }
        return -1;
    }

    /**
     * Parses feature list from FEAT response.
     */
    @NonNull
    public static List<String> parseFeatures(@NonNull FtpResponse response) {
        List<String> features = new ArrayList<>();
        
        if (response.getCode() == CODE_FEATURE_LIST && response.isMultiline()) {
            for (String line : response.getLines()) {
                line = line.trim();
                if (!line.isEmpty() && !line.startsWith("211") && !line.startsWith("Features")) {
                    features.add(line);
                }
            }
        }
        
        return features;
    }

    /**
     * Fingerprints an FTP server.
     */
    @NonNull
    public static FtpServerInfo fingerprintServer(@NonNull String host) throws IOException {
        return fingerprintServer(host, DEFAULT_FTP_PORT);
    }

    /**
     * Fingerprints an FTP server on a specific port.
     */
    @NonNull
    public static FtpServerInfo fingerprintServer(@NonNull String host, int port) 
            throws IOException {
        FtpServerInfo.Builder builder = new FtpServerInfo.Builder();
        
        try (SimpleFtpClient client = new SimpleFtpClient(host, port)) {
            // Connect and get banner
            FtpResponse banner = client.connect();
            builder.setBanner(banner.getMessage());
            
            // Identify server type
            String serverType = identifyServer(banner.getMessage());
            if (serverType != null) {
                builder.setServerType(serverType);
            }
            
            // Extract version
            String version = extractVersion(banner.getMessage());
            if (version != null) {
                builder.setVersion(version);
            }
            
            // Try anonymous login
            FtpResponse anonResponse = client.loginAnonymous();
            builder.setAnonymousAllowed(anonResponse.isSuccess());
            
            if (anonResponse.isSuccess()) {
                // Get system type
                FtpResponse systResponse = client.getSystemType();
                if (systResponse.isSuccess()) {
                    builder.setSystemType(systResponse.getMessage());
                }
                
                // Get features
                FtpResponse featResponse = client.getFeatures();
                if (featResponse.isSuccess()) {
                    builder.setFeatures(parseFeatures(featResponse));
                }
            }
            
            client.disconnect();
        }
        
        return builder.build();
    }

    /**
     * Tests if a host has an FTP server.
     */
    public static boolean isPortOpen(@NonNull String host, int port) {
        return isPortOpen(host, port, DEFAULT_TIMEOUT_MS);
    }

    /**
     * Tests if a host has an FTP server with custom timeout.
     */
    public static boolean isPortOpen(@NonNull String host, int port, int timeout) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), timeout);
            return true;
        } catch (IOException e) {
            return false;
        }
    }

    /**
     * Gets response code description.
     */
    @NonNull
    public static String getCodeDescription(int code) {
        switch (code) {
            case 110: return "Restart marker reply";
            case 120: return "Service ready in N minutes";
            case 125: return "Data connection already open";
            case 150: return "File status okay; about to open data connection";
            case 200: return "Command okay";
            case 202: return "Command not implemented";
            case 211: return "System status or help reply";
            case 212: return "Directory status";
            case 213: return "File status";
            case 214: return "Help message";
            case 215: return "System type";
            case 220: return "Service ready";
            case 221: return "Service closing control connection";
            case 225: return "Data connection open; no transfer in progress";
            case 226: return "Closing data connection; transfer complete";
            case 227: return "Entering Passive Mode";
            case 229: return "Entering Extended Passive Mode";
            case 230: return "User logged in";
            case 250: return "File action okay";
            case 257: return "Pathname created";
            case 331: return "Username okay, need password";
            case 332: return "Need account for login";
            case 350: return "File action pending further information";
            case 421: return "Service not available";
            case 425: return "Can't open data connection";
            case 426: return "Connection closed; transfer aborted";
            case 450: return "File action not taken";
            case 451: return "Local error in processing";
            case 452: return "Insufficient storage space";
            case 500: return "Syntax error; command unrecognized";
            case 501: return "Syntax error in parameters";
            case 502: return "Command not implemented";
            case 503: return "Bad sequence of commands";
            case 504: return "Command not implemented for that parameter";
            case 530: return "Not logged in";
            case 532: return "Need account for storing files";
            case 550: return "File unavailable";
            case 551: return "Page type unknown";
            case 552: return "Exceeded storage allocation";
            case 553: return "File name not allowed";
            default: return "Unknown response code";
        }
    }

    /**
     * Checks for common FTP vulnerabilities.
     */
    @NonNull
    public static List<String> checkVulnerabilities(@NonNull FtpServerInfo serverInfo) {
        List<String> vulnerabilities = new ArrayList<>();
        
        // Check anonymous access
        if (serverInfo.isAnonymousAllowed()) {
            vulnerabilities.add("Anonymous FTP access is enabled");
        }
        
        // Check for known vulnerable versions
        String version = serverInfo.getVersion();
        String serverType = serverInfo.getServerType();
        
        if (serverType != null && version != null) {
            // vsftpd vulnerabilities
            if ("vsftpd".equalsIgnoreCase(serverType)) {
                if (version.startsWith("2.3.4")) {
                    vulnerabilities.add("vsftpd 2.3.4 backdoor vulnerability (CVE-2011-2523)");
                }
            }
            
            // ProFTPD vulnerabilities
            if ("ProFTPD".equalsIgnoreCase(serverType)) {
                if (version.startsWith("1.3.3")) {
                    vulnerabilities.add("ProFTPD 1.3.3c may be vulnerable to backdoor (compromised source)");
                }
            }
            
            // WU-FTPD vulnerabilities
            if ("WU-FTPD".equalsIgnoreCase(serverType)) {
                vulnerabilities.add("WU-FTPD is legacy software with known vulnerabilities");
            }
        }
        
        // Check for cleartext protocol
        vulnerabilities.add("FTP transmits credentials in cleartext (use FTPS or SFTP instead)");
        
        // Check for missing security features
        if (!serverInfo.hasFeature("AUTH TLS") && !serverInfo.hasFeature("AUTH SSL")) {
            vulnerabilities.add("No TLS/SSL support detected (insecure)");
        }
        
        return vulnerabilities;
    }

    /**
     * Generates a summary report for FTP server.
     */
    @NonNull
    public static String generateReport(@NonNull FtpServerInfo serverInfo) {
        StringBuilder report = new StringBuilder();
        
        report.append("FTP Server Analysis Report\n");
        report.append("==========================\n\n");
        
        if (serverInfo.getBanner() != null) {
            report.append("Banner: ").append(serverInfo.getBanner()).append("\n");
        }
        
        if (serverInfo.getServerType() != null) {
            report.append("Server Type: ").append(serverInfo.getServerType()).append("\n");
        }
        
        if (serverInfo.getVersion() != null) {
            report.append("Version: ").append(serverInfo.getVersion()).append("\n");
        }
        
        if (serverInfo.getSystemType() != null) {
            report.append("System: ").append(serverInfo.getSystemType()).append("\n");
        }
        
        report.append("Anonymous Access: ")
              .append(serverInfo.isAnonymousAllowed() ? "ENABLED" : "Disabled")
              .append("\n");
        
        List<String> features = serverInfo.getFeatures();
        if (!features.isEmpty()) {
            report.append("\nSupported Features:\n");
            for (String feature : features) {
                report.append("  • ").append(feature).append("\n");
            }
        }
        
        List<String> vulnerabilities = checkVulnerabilities(serverInfo);
        if (!vulnerabilities.isEmpty()) {
            report.append("\nSecurity Concerns:\n");
            for (String vuln : vulnerabilities) {
                report.append("  ⚠ ").append(vuln).append("\n");
            }
        }
        
        return report.toString();
    }
}
