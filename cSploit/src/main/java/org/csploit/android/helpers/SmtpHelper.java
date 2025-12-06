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
 * Helper class for SMTP protocol operations and analysis.
 * Provides utilities for SMTP banner parsing, command execution,
 * server enumeration, and email validation.
 */
public final class SmtpHelper {

    private static final String TAG = "SmtpHelper";

    // Default SMTP ports
    public static final int PORT_SMTP = 25;
    public static final int PORT_SUBMISSION = 587;
    public static final int PORT_SMTPS = 465;
    public static final int DEFAULT_TIMEOUT_MS = 10000;

    // SMTP response codes
    public static final int CODE_SYSTEM_STATUS = 211;
    public static final int CODE_HELP_MESSAGE = 214;
    public static final int CODE_SERVICE_READY = 220;
    public static final int CODE_SERVICE_CLOSING = 221;
    public static final int CODE_AUTH_SUCCESS = 235;
    public static final int CODE_COMMAND_OK = 250;
    public static final int CODE_USER_NOT_LOCAL = 251;
    public static final int CODE_CANNOT_VERIFY = 252;
    public static final int CODE_AUTH_CONTINUE = 334;
    public static final int CODE_START_MAIL_INPUT = 354;
    public static final int CODE_SERVICE_UNAVAILABLE = 421;
    public static final int CODE_MAILBOX_BUSY = 450;
    public static final int CODE_LOCAL_ERROR = 451;
    public static final int CODE_INSUFFICIENT_STORAGE = 452;
    public static final int CODE_COMMAND_UNRECOGNIZED = 500;
    public static final int CODE_SYNTAX_ERROR = 501;
    public static final int CODE_COMMAND_NOT_IMPLEMENTED = 502;
    public static final int CODE_BAD_SEQUENCE = 503;
    public static final int CODE_PARAMETER_NOT_IMPLEMENTED = 504;
    public static final int CODE_AUTH_REQUIRED = 530;
    public static final int CODE_AUTH_FAILED = 535;
    public static final int CODE_MAILBOX_UNAVAILABLE = 550;
    public static final int CODE_USER_NOT_LOCAL_ERROR = 551;
    public static final int CODE_STORAGE_EXCEEDED = 552;
    public static final int CODE_MAILBOX_NAME_NOT_ALLOWED = 553;
    public static final int CODE_TRANSACTION_FAILED = 554;

    // SMTP commands
    public static final String CMD_EHLO = "EHLO";
    public static final String CMD_HELO = "HELO";
    public static final String CMD_MAIL = "MAIL FROM";
    public static final String CMD_RCPT = "RCPT TO";
    public static final String CMD_DATA = "DATA";
    public static final String CMD_RSET = "RSET";
    public static final String CMD_VRFY = "VRFY";
    public static final String CMD_EXPN = "EXPN";
    public static final String CMD_HELP = "HELP";
    public static final String CMD_NOOP = "NOOP";
    public static final String CMD_QUIT = "QUIT";
    public static final String CMD_STARTTLS = "STARTTLS";
    public static final String CMD_AUTH = "AUTH";

    // Patterns
    private static final Pattern RESPONSE_PATTERN = Pattern.compile("^(\\d{3})[-\\s](.*)$");
    private static final Pattern EHLO_EXTENSION_PATTERN = Pattern.compile("^250[-\\s](.+)$");
    private static final Pattern EMAIL_PATTERN = Pattern.compile(
            "^[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}$");
    private static final Pattern SIZE_PATTERN = Pattern.compile("SIZE\\s*(\\d+)", Pattern.CASE_INSENSITIVE);
    private static final Pattern BANNER_PATTERN = Pattern.compile(
            "(?:ESMTP|SMTP)[\\s-]*([\\w.-]+)?", Pattern.CASE_INSENSITIVE);

    // Known SMTP server signatures
    private static final Map<String, String> SERVER_SIGNATURES = new LinkedHashMap<>();
    static {
        SERVER_SIGNATURES.put("postfix", "Postfix");
        SERVER_SIGNATURES.put("sendmail", "Sendmail");
        SERVER_SIGNATURES.put("exim", "Exim");
        SERVER_SIGNATURES.put("microsoft", "Microsoft Exchange");
        SERVER_SIGNATURES.put("exchange", "Microsoft Exchange");
        SERVER_SIGNATURES.put("outlook", "Microsoft Outlook");
        SERVER_SIGNATURES.put("qmail", "Qmail");
        SERVER_SIGNATURES.put("gmail", "Google Gmail");
        SERVER_SIGNATURES.put("google", "Google");
        SERVER_SIGNATURES.put("zimbra", "Zimbra");
        SERVER_SIGNATURES.put("dovecot", "Dovecot");
        SERVER_SIGNATURES.put("mdaemon", "MDaemon");
        SERVER_SIGNATURES.put("mercury", "Mercury");
        SERVER_SIGNATURES.put("hmailserver", "hMailServer");
        SERVER_SIGNATURES.put("mailenable", "MailEnable");
    }

    private SmtpHelper() {
        // Private constructor to prevent instantiation
    }

    /**
     * Represents an SMTP server response.
     */
    public static class SmtpResponse {
        private final int code;
        private final String message;
        private final List<String> lines;

        public SmtpResponse(int code, @NonNull String message) {
            this(code, message, Collections.singletonList(message));
        }

        public SmtpResponse(int code, @NonNull String message, @NonNull List<String> lines) {
            this.code = code;
            this.message = message;
            this.lines = new ArrayList<>(lines);
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

        public boolean isSuccess() {
            return code >= 200 && code < 400;
        }

        public boolean isTransientError() {
            return code >= 400 && code < 500;
        }

        public boolean isPermanentError() {
            return code >= 500;
        }

        @Override
        public String toString() {
            return String.format(Locale.US, "%d %s", code, message);
        }
    }

    /**
     * Represents SMTP server information.
     */
    public static class SmtpServerInfo {
        private final String banner;
        private final String serverType;
        private final String hostname;
        private final List<String> extensions;
        private final long maxMessageSize;
        private final boolean supportsStartTls;
        private final boolean supportsAuth;
        private final List<String> authMethods;
        private final boolean vrfyEnabled;
        private final boolean expnEnabled;
        private final boolean openRelay;

        private SmtpServerInfo(Builder builder) {
            this.banner = builder.banner;
            this.serverType = builder.serverType;
            this.hostname = builder.hostname;
            this.extensions = new ArrayList<>(builder.extensions);
            this.maxMessageSize = builder.maxMessageSize;
            this.supportsStartTls = builder.supportsStartTls;
            this.supportsAuth = builder.supportsAuth;
            this.authMethods = new ArrayList<>(builder.authMethods);
            this.vrfyEnabled = builder.vrfyEnabled;
            this.expnEnabled = builder.expnEnabled;
            this.openRelay = builder.openRelay;
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
        public String getHostname() {
            return hostname;
        }

        @NonNull
        public List<String> getExtensions() {
            return Collections.unmodifiableList(extensions);
        }

        public long getMaxMessageSize() {
            return maxMessageSize;
        }

        public boolean supportsStartTls() {
            return supportsStartTls;
        }

        public boolean supportsAuth() {
            return supportsAuth;
        }

        @NonNull
        public List<String> getAuthMethods() {
            return Collections.unmodifiableList(authMethods);
        }

        public boolean isVrfyEnabled() {
            return vrfyEnabled;
        }

        public boolean isExpnEnabled() {
            return expnEnabled;
        }

        public boolean isOpenRelay() {
            return openRelay;
        }

        public boolean hasExtension(@NonNull String extension) {
            for (String ext : extensions) {
                if (ext.toUpperCase(Locale.US).startsWith(extension.toUpperCase(Locale.US))) {
                    return true;
                }
            }
            return false;
        }

        public static class Builder {
            private String banner;
            private String serverType;
            private String hostname;
            private List<String> extensions = new ArrayList<>();
            private long maxMessageSize = -1;
            private boolean supportsStartTls;
            private boolean supportsAuth;
            private List<String> authMethods = new ArrayList<>();
            private boolean vrfyEnabled;
            private boolean expnEnabled;
            private boolean openRelay;

            public Builder setBanner(String banner) {
                this.banner = banner;
                return this;
            }

            public Builder setServerType(String serverType) {
                this.serverType = serverType;
                return this;
            }

            public Builder setHostname(String hostname) {
                this.hostname = hostname;
                return this;
            }

            public Builder setExtensions(List<String> extensions) {
                this.extensions = new ArrayList<>(extensions);
                return this;
            }

            public Builder addExtension(String extension) {
                this.extensions.add(extension);
                return this;
            }

            public Builder setMaxMessageSize(long size) {
                this.maxMessageSize = size;
                return this;
            }

            public Builder setSupportsStartTls(boolean supports) {
                this.supportsStartTls = supports;
                return this;
            }

            public Builder setSupportsAuth(boolean supports) {
                this.supportsAuth = supports;
                return this;
            }

            public Builder setAuthMethods(List<String> methods) {
                this.authMethods = new ArrayList<>(methods);
                return this;
            }

            public Builder addAuthMethod(String method) {
                this.authMethods.add(method);
                return this;
            }

            public Builder setVrfyEnabled(boolean enabled) {
                this.vrfyEnabled = enabled;
                return this;
            }

            public Builder setExpnEnabled(boolean enabled) {
                this.expnEnabled = enabled;
                return this;
            }

            public Builder setOpenRelay(boolean openRelay) {
                this.openRelay = openRelay;
                return this;
            }

            public SmtpServerInfo build() {
                return new SmtpServerInfo(this);
            }
        }
    }

    /**
     * Simple SMTP client for basic operations.
     */
    public static class SimpleSmtpClient implements AutoCloseable {
        private Socket socket;
        private BufferedReader reader;
        private PrintWriter writer;
        private final String host;
        private final int port;
        private final int timeout;

        public SimpleSmtpClient(@NonNull String host) {
            this(host, PORT_SMTP, DEFAULT_TIMEOUT_MS);
        }

        public SimpleSmtpClient(@NonNull String host, int port) {
            this(host, port, DEFAULT_TIMEOUT_MS);
        }

        public SimpleSmtpClient(@NonNull String host, int port, int timeout) {
            this.host = host;
            this.port = port;
            this.timeout = timeout;
        }

        /**
         * Connects to the SMTP server.
         */
        @NonNull
        public SmtpResponse connect() throws IOException {
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
        public SmtpResponse sendCommand(@NonNull String command) throws IOException {
            writer.println(command);
            return readResponse();
        }

        /**
         * Sends a command with an argument.
         */
        @NonNull
        public SmtpResponse sendCommand(@NonNull String command, @NonNull String argument) 
                throws IOException {
            return sendCommand(command + " " + argument);
        }

        /**
         * Reads a response from the server.
         */
        @NonNull
        public SmtpResponse readResponse() throws IOException {
            List<String> lines = new ArrayList<>();
            String line;
            int code = -1;
            String message = "";

            while ((line = reader.readLine()) != null) {
                Matcher matcher = RESPONSE_PATTERN.matcher(line);
                if (matcher.matches()) {
                    code = Integer.parseInt(matcher.group(1));
                    message = matcher.group(2);
                    lines.add(message);
                    
                    // Check if this is the last line (space after code, not hyphen)
                    if (line.length() > 3 && line.charAt(3) == ' ') {
                        break;
                    }
                } else {
                    lines.add(line);
                    break;
                }
            }

            if (lines.isEmpty() && code == -1) {
                throw new IOException("Connection closed by server");
            }

            return new SmtpResponse(code, message, lines);
        }

        /**
         * Sends EHLO command.
         */
        @NonNull
        public SmtpResponse ehlo(@NonNull String hostname) throws IOException {
            return sendCommand(CMD_EHLO, hostname);
        }

        /**
         * Sends HELO command.
         */
        @NonNull
        public SmtpResponse helo(@NonNull String hostname) throws IOException {
            return sendCommand(CMD_HELO, hostname);
        }

        /**
         * Verifies an email address using VRFY command.
         */
        @NonNull
        public SmtpResponse vrfy(@NonNull String email) throws IOException {
            return sendCommand(CMD_VRFY, email);
        }

        /**
         * Expands a mailing list using EXPN command.
         */
        @NonNull
        public SmtpResponse expn(@NonNull String listName) throws IOException {
            return sendCommand(CMD_EXPN, listName);
        }

        /**
         * Sends QUIT command.
         */
        @NonNull
        public SmtpResponse quit() throws IOException {
            return sendCommand(CMD_QUIT);
        }

        /**
         * Disconnects from the server.
         */
        public void disconnect() {
            try {
                if (writer != null) {
                    quit();
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
     * Parses an SMTP response string.
     */
    @Nullable
    public static SmtpResponse parseResponse(@NonNull String response) {
        Matcher matcher = RESPONSE_PATTERN.matcher(response);
        if (matcher.matches()) {
            int code = Integer.parseInt(matcher.group(1));
            String message = matcher.group(2);
            return new SmtpResponse(code, message);
        }
        return null;
    }

    /**
     * Identifies the SMTP server type from a banner.
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
     * Parses EHLO extensions from response.
     */
    @NonNull
    public static List<String> parseExtensions(@NonNull SmtpResponse response) {
        List<String> extensions = new ArrayList<>();
        
        if (response.isSuccess()) {
            List<String> lines = response.getLines();
            // Skip first line (greeting)
            for (int i = 1; i < lines.size(); i++) {
                String line = lines.get(i).trim();
                if (!line.isEmpty()) {
                    extensions.add(line);
                }
            }
        }
        
        return extensions;
    }

    /**
     * Extracts maximum message size from extensions.
     */
    public static long parseMaxSize(@NonNull List<String> extensions) {
        for (String ext : extensions) {
            Matcher matcher = SIZE_PATTERN.matcher(ext);
            if (matcher.find()) {
                try {
                    return Long.parseLong(matcher.group(1));
                } catch (NumberFormatException ignored) {
                    // Continue searching
                }
            }
        }
        return -1;
    }

    /**
     * Extracts authentication methods from extensions.
     */
    @NonNull
    public static List<String> parseAuthMethods(@NonNull List<String> extensions) {
        List<String> methods = new ArrayList<>();
        
        for (String ext : extensions) {
            String upperExt = ext.toUpperCase(Locale.US);
            if (upperExt.startsWith("AUTH ")) {
                String[] parts = ext.substring(5).split("\\s+");
                Collections.addAll(methods, parts);
            }
        }
        
        return methods;
    }

    /**
     * Validates an email address format.
     */
    public static boolean isValidEmail(@NonNull String email) {
        return EMAIL_PATTERN.matcher(email).matches();
    }

    /**
     * Fingerprints an SMTP server.
     */
    @NonNull
    public static SmtpServerInfo fingerprintServer(@NonNull String host) throws IOException {
        return fingerprintServer(host, PORT_SMTP);
    }

    /**
     * Fingerprints an SMTP server on a specific port.
     */
    @NonNull
    public static SmtpServerInfo fingerprintServer(@NonNull String host, int port) 
            throws IOException {
        SmtpServerInfo.Builder builder = new SmtpServerInfo.Builder();
        
        try (SimpleSmtpClient client = new SimpleSmtpClient(host, port)) {
            // Connect and get banner
            SmtpResponse banner = client.connect();
            builder.setBanner(banner.getMessage());
            
            // Identify server type
            String serverType = identifyServer(banner.getMessage());
            if (serverType != null) {
                builder.setServerType(serverType);
            }
            
            // Send EHLO to get extensions
            SmtpResponse ehloResponse = client.ehlo("test.local");
            
            if (ehloResponse.isSuccess()) {
                List<String> extensions = parseExtensions(ehloResponse);
                builder.setExtensions(extensions);
                
                // Parse extensions
                builder.setMaxMessageSize(parseMaxSize(extensions));
                builder.setSupportsStartTls(hasExtension(extensions, "STARTTLS"));
                
                List<String> authMethods = parseAuthMethods(extensions);
                builder.setSupportsAuth(!authMethods.isEmpty());
                builder.setAuthMethods(authMethods);
                
                // Test VRFY
                SmtpResponse vrfyResponse = client.vrfy("test");
                builder.setVrfyEnabled(vrfyResponse.getCode() != CODE_COMMAND_NOT_IMPLEMENTED &&
                                       vrfyResponse.getCode() != CODE_COMMAND_UNRECOGNIZED);
                
                // Test EXPN
                SmtpResponse expnResponse = client.expn("test");
                builder.setExpnEnabled(expnResponse.getCode() != CODE_COMMAND_NOT_IMPLEMENTED &&
                                       expnResponse.getCode() != CODE_COMMAND_UNRECOGNIZED);
            } else {
                // Try HELO for older servers
                SmtpResponse heloResponse = client.helo("test.local");
                if (heloResponse.isSuccess()) {
                    builder.addExtension("HELO only (no ESMTP)");
                }
            }
            
            client.disconnect();
        }
        
        return builder.build();
    }

    /**
     * Checks if extensions list contains a specific extension.
     */
    private static boolean hasExtension(@NonNull List<String> extensions, @NonNull String name) {
        for (String ext : extensions) {
            if (ext.toUpperCase(Locale.US).startsWith(name.toUpperCase(Locale.US))) {
                return true;
            }
        }
        return false;
    }

    /**
     * Gets response code description.
     */
    @NonNull
    public static String getCodeDescription(int code) {
        switch (code) {
            case 211: return "System status or help reply";
            case 214: return "Help message";
            case 220: return "Service ready";
            case 221: return "Service closing transmission channel";
            case 235: return "Authentication successful";
            case 250: return "Requested action completed";
            case 251: return "User not local; will forward";
            case 252: return "Cannot VRFY user; will accept message";
            case 334: return "Server challenge (authentication)";
            case 354: return "Start mail input";
            case 421: return "Service not available, closing transmission channel";
            case 450: return "Mailbox unavailable (busy)";
            case 451: return "Local error in processing";
            case 452: return "Insufficient system storage";
            case 455: return "Server unable to accommodate parameters";
            case 500: return "Syntax error, command unrecognized";
            case 501: return "Syntax error in parameters or arguments";
            case 502: return "Command not implemented";
            case 503: return "Bad sequence of commands";
            case 504: return "Command parameter not implemented";
            case 530: return "Authentication required";
            case 534: return "Authentication mechanism is too weak";
            case 535: return "Authentication credentials invalid";
            case 538: return "Encryption required for requested authentication";
            case 550: return "Mailbox unavailable";
            case 551: return "User not local; please try different path";
            case 552: return "Exceeded storage allocation";
            case 553: return "Mailbox name not allowed";
            case 554: return "Transaction failed";
            default: return "Unknown response code";
        }
    }

    /**
     * Checks for common SMTP vulnerabilities.
     */
    @NonNull
    public static List<String> checkVulnerabilities(@NonNull SmtpServerInfo serverInfo) {
        List<String> vulnerabilities = new ArrayList<>();
        
        // Check for VRFY enabled
        if (serverInfo.isVrfyEnabled()) {
            vulnerabilities.add("VRFY command enabled - allows user enumeration");
        }
        
        // Check for EXPN enabled
        if (serverInfo.isExpnEnabled()) {
            vulnerabilities.add("EXPN command enabled - allows mailing list enumeration");
        }
        
        // Check for open relay
        if (serverInfo.isOpenRelay()) {
            vulnerabilities.add("CRITICAL: Server is an open relay");
        }
        
        // Check for missing TLS
        if (!serverInfo.supportsStartTls()) {
            vulnerabilities.add("No STARTTLS support - emails transmitted in cleartext");
        }
        
        // Check authentication methods
        List<String> authMethods = serverInfo.getAuthMethods();
        if (authMethods.contains("PLAIN") || authMethods.contains("LOGIN")) {
            if (!serverInfo.supportsStartTls()) {
                vulnerabilities.add("Weak authentication methods available without TLS");
            }
        }
        
        // Check for no authentication
        if (!serverInfo.supportsAuth()) {
            vulnerabilities.add("No authentication required - potential for abuse");
        }
        
        return vulnerabilities;
    }

    /**
     * Generates a summary report for SMTP server.
     */
    @NonNull
    public static String generateReport(@NonNull SmtpServerInfo serverInfo) {
        StringBuilder report = new StringBuilder();
        
        report.append("SMTP Server Analysis Report\n");
        report.append("===========================\n\n");
        
        if (serverInfo.getBanner() != null) {
            report.append("Banner: ").append(serverInfo.getBanner()).append("\n");
        }
        
        if (serverInfo.getServerType() != null) {
            report.append("Server Type: ").append(serverInfo.getServerType()).append("\n");
        }
        
        report.append("STARTTLS: ").append(serverInfo.supportsStartTls() ? "Supported" : "Not supported").append("\n");
        report.append("Authentication: ").append(serverInfo.supportsAuth() ? "Required" : "Not required").append("\n");
        
        if (serverInfo.supportsAuth()) {
            List<String> methods = serverInfo.getAuthMethods();
            if (!methods.isEmpty()) {
                report.append("Auth Methods: ").append(String.join(", ", methods)).append("\n");
            }
        }
        
        if (serverInfo.getMaxMessageSize() > 0) {
            report.append("Max Message Size: ").append(formatSize(serverInfo.getMaxMessageSize())).append("\n");
        }
        
        report.append("VRFY: ").append(serverInfo.isVrfyEnabled() ? "Enabled" : "Disabled").append("\n");
        report.append("EXPN: ").append(serverInfo.isExpnEnabled() ? "Enabled" : "Disabled").append("\n");
        
        List<String> extensions = serverInfo.getExtensions();
        if (!extensions.isEmpty()) {
            report.append("\nSupported Extensions:\n");
            for (String ext : extensions) {
                report.append("  • ").append(ext).append("\n");
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

    /**
     * Formats size in human-readable format.
     */
    @NonNull
    private static String formatSize(long bytes) {
        if (bytes < 1024) {
            return bytes + " B";
        }
        if (bytes < 1024 * 1024) {
            return String.format(Locale.US, "%.1f KB", bytes / 1024.0);
        }
        if (bytes < 1024 * 1024 * 1024) {
            return String.format(Locale.US, "%.1f MB", bytes / (1024.0 * 1024));
        }
        return String.format(Locale.US, "%.1f GB", bytes / (1024.0 * 1024 * 1024));
    }

    /**
     * Enumerate users using VRFY command.
     */
    @NonNull
    public static Map<String, Boolean> enumerateUsers(@NonNull String host, 
                                                       @NonNull List<String> usernames) 
            throws IOException {
        Map<String, Boolean> results = new HashMap<>();
        
        try (SimpleSmtpClient client = new SimpleSmtpClient(host)) {
            client.connect();
            client.ehlo("test.local");
            
            for (String username : usernames) {
                SmtpResponse response = client.vrfy(username);
                boolean exists = response.getCode() == CODE_COMMAND_OK ||
                                response.getCode() == CODE_USER_NOT_LOCAL;
                results.put(username, exists);
            }
            
            client.disconnect();
        }
        
        return results;
    }
}
