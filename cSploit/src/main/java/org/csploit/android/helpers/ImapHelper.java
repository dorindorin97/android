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

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Helper class for IMAP protocol operations and analysis.
 * Provides utilities for IMAP server analysis, capability enumeration,
 * and security assessment.
 */
public final class ImapHelper {

    private static final String TAG = "ImapHelper";

    // Default IMAP ports
    public static final int DEFAULT_IMAP_PORT = 143;
    public static final int DEFAULT_IMAPS_PORT = 993;
    public static final int DEFAULT_TIMEOUT_MS = 10000;

    // IMAP response codes
    public static final String RESPONSE_OK = "OK";
    public static final String RESPONSE_NO = "NO";
    public static final String RESPONSE_BAD = "BAD";
    public static final String RESPONSE_PREAUTH = "PREAUTH";
    public static final String RESPONSE_BYE = "BYE";

    // IMAP commands
    public static final String CMD_CAPABILITY = "CAPABILITY";
    public static final String CMD_NOOP = "NOOP";
    public static final String CMD_LOGOUT = "LOGOUT";
    public static final String CMD_STARTTLS = "STARTTLS";
    public static final String CMD_LOGIN = "LOGIN";
    public static final String CMD_AUTHENTICATE = "AUTHENTICATE";
    public static final String CMD_SELECT = "SELECT";
    public static final String CMD_EXAMINE = "EXAMINE";
    public static final String CMD_LIST = "LIST";
    public static final String CMD_STATUS = "STATUS";
    public static final String CMD_NAMESPACE = "NAMESPACE";
    public static final String CMD_ID = "ID";

    // IMAP capabilities
    public static final String CAP_IMAP4 = "IMAP4";
    public static final String CAP_IMAP4REV1 = "IMAP4rev1";
    public static final String CAP_IMAP4REV2 = "IMAP4rev2";
    public static final String CAP_STARTTLS = "STARTTLS";
    public static final String CAP_LOGINDISABLED = "LOGINDISABLED";
    public static final String CAP_AUTH_PLAIN = "AUTH=PLAIN";
    public static final String CAP_AUTH_LOGIN = "AUTH=LOGIN";
    public static final String CAP_AUTH_CRAM_MD5 = "AUTH=CRAM-MD5";
    public static final String CAP_AUTH_DIGEST_MD5 = "AUTH=DIGEST-MD5";
    public static final String CAP_AUTH_GSSAPI = "AUTH=GSSAPI";
    public static final String CAP_AUTH_NTLM = "AUTH=NTLM";
    public static final String CAP_AUTH_XOAUTH = "AUTH=XOAUTH";
    public static final String CAP_AUTH_XOAUTH2 = "AUTH=XOAUTH2";
    public static final String CAP_IDLE = "IDLE";
    public static final String CAP_NAMESPACE = "NAMESPACE";
    public static final String CAP_ID = "ID";
    public static final String CAP_CHILDREN = "CHILDREN";
    public static final String CAP_UIDPLUS = "UIDPLUS";
    public static final String CAP_LITERAL_PLUS = "LITERAL+";
    public static final String CAP_COMPRESS_DEFLATE = "COMPRESS=DEFLATE";
    public static final String CAP_QUOTA = "QUOTA";
    public static final String CAP_SORT = "SORT";
    public static final String CAP_THREAD = "THREAD";
    public static final String CAP_MOVE = "MOVE";
    public static final String CAP_CONDSTORE = "CONDSTORE";
    public static final String CAP_QRESYNC = "QRESYNC";

    // Common IMAP servers
    private static final Map<String, String> SERVER_SIGNATURES = new HashMap<>();
    
    static {
        SERVER_SIGNATURES.put("Dovecot", "Dovecot");
        SERVER_SIGNATURES.put("Courier-IMAP", "Courier");
        SERVER_SIGNATURES.put("Cyrus IMAP", "Cyrus");
        SERVER_SIGNATURES.put("Microsoft Exchange", "Exchange");
        SERVER_SIGNATURES.put("Zimbra", "Zimbra");
        SERVER_SIGNATURES.put("UW IMAP", "UW IMAP");
        SERVER_SIGNATURES.put("uw-imapd", "UW IMAP");
        SERVER_SIGNATURES.put("hMailServer", "hMailServer");
        SERVER_SIGNATURES.put("Gmail", "Gmail");
        SERVER_SIGNATURES.put("Gimap", "Gmail");
        SERVER_SIGNATURES.put("Mercury", "Mercury");
        SERVER_SIGNATURES.put("MDaemon", "MDaemon");
        SERVER_SIGNATURES.put("MailEnable", "MailEnable");
        SERVER_SIGNATURES.put("Postfix", "Postfix");
        SERVER_SIGNATURES.put("InterMail", "InterMail");
        SERVER_SIGNATURES.put("SmarterMail", "SmarterMail");
    }

    private static int tagCounter = 0;

    private ImapHelper() {
        // Private constructor to prevent instantiation
    }

    /**
     * Represents IMAP server information.
     */
    public static class ServerInfo {
        private final String banner;
        private final String serverType;
        private final String version;
        private final Set<String> capabilities;
        private final List<String> authMechanisms;
        private final boolean starttls;
        private final boolean loginDisabled;
        private final Map<String, String> additionalInfo;

        private ServerInfo(Builder builder) {
            this.banner = builder.banner;
            this.serverType = builder.serverType;
            this.version = builder.version;
            this.capabilities = new HashSet<>(builder.capabilities);
            this.authMechanisms = new ArrayList<>(builder.authMechanisms);
            this.starttls = builder.starttls;
            this.loginDisabled = builder.loginDisabled;
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

        @NonNull
        public Set<String> getCapabilities() {
            return Collections.unmodifiableSet(capabilities);
        }

        @NonNull
        public List<String> getAuthMechanisms() {
            return Collections.unmodifiableList(authMechanisms);
        }

        public boolean hasCapability(@NonNull String capability) {
            return capabilities.contains(capability.toUpperCase(Locale.US));
        }

        public boolean supportsStartTls() {
            return starttls;
        }

        public boolean isLoginDisabled() {
            return loginDisabled;
        }

        @NonNull
        public Map<String, String> getAdditionalInfo() {
            return Collections.unmodifiableMap(additionalInfo);
        }

        public static class Builder {
            private String banner;
            private String serverType;
            private String version;
            private Set<String> capabilities = new HashSet<>();
            private List<String> authMechanisms = new ArrayList<>();
            private boolean starttls;
            private boolean loginDisabled;
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

            public Builder addCapability(String capability) {
                this.capabilities.add(capability.toUpperCase(Locale.US));
                return this;
            }

            public Builder addCapabilities(Set<String> capabilities) {
                for (String cap : capabilities) {
                    this.capabilities.add(cap.toUpperCase(Locale.US));
                }
                return this;
            }

            public Builder addAuthMechanism(String mechanism) {
                this.authMechanisms.add(mechanism);
                return this;
            }

            public Builder setStarttls(boolean starttls) {
                this.starttls = starttls;
                return this;
            }

            public Builder setLoginDisabled(boolean loginDisabled) {
                this.loginDisabled = loginDisabled;
                return this;
            }

            public Builder addInfo(String key, String value) {
                this.additionalInfo.put(key, value);
                return this;
            }

            public ServerInfo build() {
                return new ServerInfo(this);
            }
        }
    }

    /**
     * Represents an IMAP response.
     */
    public static class ImapResponse {
        private final String tag;
        private final String status;
        private final String message;
        private final List<String> untaggedResponses;
        private final long responseTime;

        private ImapResponse(Builder builder) {
            this.tag = builder.tag;
            this.status = builder.status;
            this.message = builder.message;
            this.untaggedResponses = new ArrayList<>(builder.untaggedResponses);
            this.responseTime = builder.responseTime;
        }

        @Nullable
        public String getTag() {
            return tag;
        }

        @Nullable
        public String getStatus() {
            return status;
        }

        @Nullable
        public String getMessage() {
            return message;
        }

        @NonNull
        public List<String> getUntaggedResponses() {
            return Collections.unmodifiableList(untaggedResponses);
        }

        public long getResponseTime() {
            return responseTime;
        }

        public boolean isOk() {
            return RESPONSE_OK.equals(status);
        }

        public boolean isNo() {
            return RESPONSE_NO.equals(status);
        }

        public boolean isBad() {
            return RESPONSE_BAD.equals(status);
        }

        public static class Builder {
            private String tag;
            private String status;
            private String message;
            private List<String> untaggedResponses = new ArrayList<>();
            private long responseTime;

            public Builder setTag(String tag) {
                this.tag = tag;
                return this;
            }

            public Builder setStatus(String status) {
                this.status = status;
                return this;
            }

            public Builder setMessage(String message) {
                this.message = message;
                return this;
            }

            public Builder addUntaggedResponse(String response) {
                this.untaggedResponses.add(response);
                return this;
            }

            public Builder setResponseTime(long responseTime) {
                this.responseTime = responseTime;
                return this;
            }

            public ImapResponse build() {
                return new ImapResponse(this);
            }
        }
    }

    /**
     * Represents IMAP security assessment.
     */
    public static class SecurityAssessment {
        private final boolean secure;
        private final List<String> vulnerabilities;
        private final List<String> recommendations;
        private final String riskLevel;

        private SecurityAssessment(Builder builder) {
            this.secure = builder.secure;
            this.vulnerabilities = new ArrayList<>(builder.vulnerabilities);
            this.recommendations = new ArrayList<>(builder.recommendations);
            this.riskLevel = builder.riskLevel;
        }

        public boolean isSecure() {
            return secure;
        }

        @NonNull
        public List<String> getVulnerabilities() {
            return Collections.unmodifiableList(vulnerabilities);
        }

        @NonNull
        public List<String> getRecommendations() {
            return Collections.unmodifiableList(recommendations);
        }

        @NonNull
        public String getRiskLevel() {
            return riskLevel;
        }

        public static class Builder {
            private boolean secure = true;
            private List<String> vulnerabilities = new ArrayList<>();
            private List<String> recommendations = new ArrayList<>();
            private String riskLevel = "LOW";

            public Builder setSecure(boolean secure) {
                this.secure = secure;
                return this;
            }

            public Builder addVulnerability(String vulnerability) {
                this.vulnerabilities.add(vulnerability);
                this.secure = false;
                return this;
            }

            public Builder addRecommendation(String recommendation) {
                this.recommendations.add(recommendation);
                return this;
            }

            public Builder setRiskLevel(String riskLevel) {
                this.riskLevel = riskLevel;
                return this;
            }

            public SecurityAssessment build() {
                return new SecurityAssessment(this);
            }
        }
    }

    /**
     * Grabs the IMAP banner from a server.
     */
    @Nullable
    public static String grabBanner(@NonNull String host) {
        return grabBanner(host, DEFAULT_IMAP_PORT, DEFAULT_TIMEOUT_MS);
    }

    /**
     * Grabs the IMAP banner from a server.
     */
    @Nullable
    public static String grabBanner(@NonNull String host, int port, int timeout) {
        try (Socket socket = new Socket()) {
            socket.connect(new java.net.InetSocketAddress(host, port), timeout);
            socket.setSoTimeout(timeout);

            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));

            String response = reader.readLine();
            return response;
        } catch (IOException e) {
            return null;
        }
    }

    /**
     * Gets server capabilities.
     */
    @NonNull
    public static Set<String> getCapabilities(@NonNull String host) {
        return getCapabilities(host, DEFAULT_IMAP_PORT, DEFAULT_TIMEOUT_MS);
    }

    /**
     * Gets server capabilities.
     */
    @NonNull
    public static Set<String> getCapabilities(@NonNull String host, int port, int timeout) {
        Set<String> capabilities = new HashSet<>();

        try (Socket socket = new Socket()) {
            socket.connect(new java.net.InetSocketAddress(host, port), timeout);
            socket.setSoTimeout(timeout);

            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
            BufferedWriter writer = new BufferedWriter(
                    new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8));

            // Read banner
            String banner = reader.readLine();
            
            // Parse capabilities from banner if present
            if (banner != null && banner.contains("CAPABILITY")) {
                capabilities.addAll(parseCapabilities(banner));
            }

            // Send CAPABILITY command
            String tag = getNextTag();
            writer.write(tag + " " + CMD_CAPABILITY + "\r\n");
            writer.flush();

            // Read responses
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.startsWith("*") && line.contains("CAPABILITY")) {
                    capabilities.addAll(parseCapabilities(line));
                }
                if (line.startsWith(tag)) {
                    break;
                }
            }

            // Logout gracefully
            tag = getNextTag();
            writer.write(tag + " " + CMD_LOGOUT + "\r\n");
            writer.flush();

        } catch (IOException e) {
            // Connection failed
        }

        return capabilities;
    }

    /**
     * Gets detailed server information.
     */
    @NonNull
    public static ServerInfo getServerInfo(@NonNull String host) {
        return getServerInfo(host, DEFAULT_IMAP_PORT, DEFAULT_TIMEOUT_MS);
    }

    /**
     * Gets detailed server information.
     */
    @NonNull
    public static ServerInfo getServerInfo(@NonNull String host, int port, int timeout) {
        ServerInfo.Builder builder = new ServerInfo.Builder();

        try (Socket socket = new Socket()) {
            socket.connect(new java.net.InetSocketAddress(host, port), timeout);
            socket.setSoTimeout(timeout);

            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
            BufferedWriter writer = new BufferedWriter(
                    new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8));

            // Read banner
            String banner = reader.readLine();
            if (banner != null) {
                builder.setBanner(banner);
                
                // Detect server type
                String serverType = detectServerType(banner);
                if (serverType != null) {
                    builder.setServerType(serverType);
                }
                
                // Extract version if possible
                String version = extractVersion(banner);
                if (version != null) {
                    builder.setVersion(version);
                }
                
                // Parse capabilities from banner
                if (banner.contains("CAPABILITY")) {
                    Set<String> caps = parseCapabilities(banner);
                    builder.addCapabilities(caps);
                }
            }

            // Send CAPABILITY command
            String tag = getNextTag();
            writer.write(tag + " " + CMD_CAPABILITY + "\r\n");
            writer.flush();

            // Read capability response
            String line;
            while ((line = reader.readLine()) != null) {
                if (line.startsWith("*") && line.contains("CAPABILITY")) {
                    Set<String> caps = parseCapabilities(line);
                    builder.addCapabilities(caps);
                    
                    // Check for STARTTLS
                    if (caps.contains(CAP_STARTTLS)) {
                        builder.setStarttls(true);
                    }
                    
                    // Check for LOGINDISABLED
                    if (caps.contains(CAP_LOGINDISABLED)) {
                        builder.setLoginDisabled(true);
                    }
                    
                    // Extract auth mechanisms
                    for (String cap : caps) {
                        if (cap.startsWith("AUTH=")) {
                            builder.addAuthMechanism(cap.substring(5));
                        }
                    }
                }
                if (line.startsWith(tag)) {
                    break;
                }
            }

            // Try ID command if supported
            if (builder.capabilities.contains("ID")) {
                tag = getNextTag();
                writer.write(tag + " " + CMD_ID + " NIL\r\n");
                writer.flush();

                while ((line = reader.readLine()) != null) {
                    if (line.startsWith("* ID")) {
                        parseIdResponse(line, builder);
                    }
                    if (line.startsWith(tag)) {
                        break;
                    }
                }
            }

            // Logout
            tag = getNextTag();
            writer.write(tag + " " + CMD_LOGOUT + "\r\n");
            writer.flush();

        } catch (IOException e) {
            // Connection failed
        }

        return builder.build();
    }

    /**
     * Performs a security assessment on the IMAP server.
     */
    @NonNull
    public static SecurityAssessment assessSecurity(@NonNull String host) {
        return assessSecurity(host, DEFAULT_IMAP_PORT, DEFAULT_TIMEOUT_MS);
    }

    /**
     * Performs a security assessment on the IMAP server.
     */
    @NonNull
    public static SecurityAssessment assessSecurity(@NonNull String host, int port, int timeout) {
        SecurityAssessment.Builder builder = new SecurityAssessment.Builder();
        ServerInfo serverInfo = getServerInfo(host, port, timeout);

        int riskScore = 0;

        // Check STARTTLS support
        if (!serverInfo.supportsStartTls() && port == DEFAULT_IMAP_PORT) {
            builder.addVulnerability("STARTTLS not supported - credentials transmitted in plaintext");
            builder.addRecommendation("Enable STARTTLS or use IMAPS (port 993)");
            riskScore += 3;
        }

        // Check login disabled
        if (!serverInfo.isLoginDisabled() && !serverInfo.supportsStartTls() && port == DEFAULT_IMAP_PORT) {
            builder.addVulnerability("LOGIN not disabled on plaintext connection");
            builder.addRecommendation("Disable LOGIN before STARTTLS");
            riskScore += 2;
        }

        // Check for weak auth mechanisms
        List<String> authMechs = serverInfo.getAuthMechanisms();
        if (authMechs.contains("PLAIN") && !serverInfo.supportsStartTls()) {
            builder.addVulnerability("PLAIN authentication available without encryption");
            riskScore += 2;
        }

        if (authMechs.contains("LOGIN") && !serverInfo.supportsStartTls()) {
            builder.addVulnerability("LOGIN authentication available without encryption");
            riskScore += 2;
        }

        // Check for strong auth mechanisms
        boolean hasStrongAuth = authMechs.contains("CRAM-MD5") ||
                                authMechs.contains("DIGEST-MD5") ||
                                authMechs.contains("GSSAPI") ||
                                authMechs.contains("XOAUTH2");
        
        if (!hasStrongAuth && !serverInfo.supportsStartTls()) {
            builder.addVulnerability("No strong authentication mechanisms available");
            builder.addRecommendation("Enable CRAM-MD5, GSSAPI, or XOAUTH2");
            riskScore += 1;
        }

        // Check banner information leakage
        String banner = serverInfo.getBanner();
        if (banner != null) {
            if (serverInfo.getVersion() != null) {
                builder.addVulnerability("Server version disclosed in banner: " + serverInfo.getVersion());
                builder.addRecommendation("Consider hiding version information in banner");
                riskScore += 1;
            }
        }

        // Check for outdated protocol
        if (!serverInfo.hasCapability(CAP_IMAP4REV1) && !serverInfo.hasCapability(CAP_IMAP4REV2)) {
            builder.addVulnerability("Server may not support modern IMAP protocol");
            riskScore += 1;
        }

        // Determine risk level
        if (riskScore >= 5) {
            builder.setRiskLevel("HIGH");
        } else if (riskScore >= 3) {
            builder.setRiskLevel("MEDIUM");
        } else if (riskScore > 0) {
            builder.setRiskLevel("LOW");
        } else {
            builder.setRiskLevel("MINIMAL");
        }

        return builder.build();
    }

    /**
     * Sends an IMAP command and receives response.
     */
    @NonNull
    public static ImapResponse sendCommand(@NonNull Socket socket, @NonNull String command,
                                           int timeout) throws IOException {
        long startTime = System.currentTimeMillis();
        ImapResponse.Builder builder = new ImapResponse.Builder();

        BufferedReader reader = new BufferedReader(
                new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
        BufferedWriter writer = new BufferedWriter(
                new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8));

        String tag = getNextTag();
        builder.setTag(tag);

        writer.write(tag + " " + command + "\r\n");
        writer.flush();

        String line;
        while ((line = reader.readLine()) != null) {
            if (line.startsWith("*")) {
                builder.addUntaggedResponse(line);
            } else if (line.startsWith(tag)) {
                // Parse tagged response
                Pattern pattern = Pattern.compile("^\\S+\\s+(OK|NO|BAD)\\s*(.*)$");
                Matcher matcher = pattern.matcher(line);
                if (matcher.find()) {
                    builder.setStatus(matcher.group(1));
                    builder.setMessage(matcher.group(2));
                }
                break;
            }
        }

        builder.setResponseTime(System.currentTimeMillis() - startTime);
        return builder.build();
    }

    /**
     * Parses capabilities from a response line.
     */
    @NonNull
    private static Set<String> parseCapabilities(@NonNull String line) {
        Set<String> capabilities = new HashSet<>();
        
        // Find CAPABILITY section
        int capStart = line.indexOf("CAPABILITY");
        if (capStart >= 0) {
            String capSection = line.substring(capStart);
            // Find end of capabilities (] or end of line)
            int capEnd = capSection.indexOf(']');
            if (capEnd < 0) {
                capEnd = capSection.length();
            }
            String capsStr = capSection.substring(0, capEnd);
            
            String[] parts = capsStr.split("\\s+");
            for (String part : parts) {
                if (!part.isEmpty() && !part.equals("CAPABILITY")) {
                    capabilities.add(part.toUpperCase(Locale.US));
                }
            }
        }
        
        return capabilities;
    }

    /**
     * Detects server type from banner.
     */
    @Nullable
    private static String detectServerType(@NonNull String banner) {
        String upperBanner = banner.toUpperCase(Locale.US);
        
        for (Map.Entry<String, String> entry : SERVER_SIGNATURES.entrySet()) {
            if (upperBanner.contains(entry.getKey().toUpperCase(Locale.US))) {
                return entry.getValue();
            }
        }
        
        return null;
    }

    /**
     * Extracts version from banner.
     */
    @Nullable
    private static String extractVersion(@NonNull String banner) {
        // Common version patterns
        Pattern[] patterns = {
                Pattern.compile("v?([0-9]+\\.[0-9]+(?:\\.[0-9]+)*)"),
                Pattern.compile("version\\s*([0-9]+\\.[0-9]+(?:\\.[0-9]+)*)", Pattern.CASE_INSENSITIVE),
                Pattern.compile("release\\s*([0-9]+\\.[0-9]+(?:\\.[0-9]+)*)", Pattern.CASE_INSENSITIVE)
        };

        for (Pattern pattern : patterns) {
            Matcher matcher = pattern.matcher(banner);
            if (matcher.find()) {
                return matcher.group(1);
            }
        }

        return null;
    }

    /**
     * Parses ID response.
     */
    private static void parseIdResponse(@NonNull String line, @NonNull ServerInfo.Builder builder) {
        // Format: * ID ("name" "value" "name" "value" ...)
        Pattern kvPattern = Pattern.compile("\"([^\"]+)\"\\s+\"([^\"]+)\"");
        Matcher matcher = kvPattern.matcher(line);
        
        while (matcher.find()) {
            String key = matcher.group(1);
            String value = matcher.group(2);
            
            if ("name".equalsIgnoreCase(key)) {
                builder.setServerType(value);
            } else if ("version".equalsIgnoreCase(key)) {
                builder.setVersion(value);
            } else {
                builder.addInfo(key, value);
            }
        }
    }

    /**
     * Generates next IMAP tag.
     */
    @NonNull
    private static synchronized String getNextTag() {
        return String.format(Locale.US, "A%04d", ++tagCounter);
    }

    /**
     * Tests if IMAP server is reachable.
     */
    public static boolean isReachable(@NonNull String host) {
        return isReachable(host, DEFAULT_IMAP_PORT, DEFAULT_TIMEOUT_MS);
    }

    /**
     * Tests if IMAP server is reachable.
     */
    public static boolean isReachable(@NonNull String host, int port, int timeout) {
        try (Socket socket = new Socket()) {
            socket.connect(new java.net.InetSocketAddress(host, port), timeout);
            socket.setSoTimeout(timeout);
            
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
            
            String response = reader.readLine();
            return response != null && (response.contains("OK") || response.contains("IMAP"));
        } catch (IOException e) {
            return false;
        }
    }

    /**
     * Generates a report for IMAP server.
     */
    @NonNull
    public static String generateReport(@NonNull ServerInfo serverInfo) {
        StringBuilder report = new StringBuilder();
        
        report.append("IMAP Server Information\n");
        report.append("=======================\n\n");
        
        if (serverInfo.getBanner() != null) {
            report.append("Banner: ").append(serverInfo.getBanner()).append("\n");
        }
        
        if (serverInfo.getServerType() != null) {
            report.append("Server Type: ").append(serverInfo.getServerType()).append("\n");
        }
        
        if (serverInfo.getVersion() != null) {
            report.append("Version: ").append(serverInfo.getVersion()).append("\n");
        }
        
        report.append("STARTTLS: ").append(serverInfo.supportsStartTls() ? "Yes" : "No").append("\n");
        report.append("Login Disabled: ").append(serverInfo.isLoginDisabled() ? "Yes" : "No").append("\n");
        
        if (!serverInfo.getAuthMechanisms().isEmpty()) {
            report.append("\nAuthentication Mechanisms:\n");
            for (String mech : serverInfo.getAuthMechanisms()) {
                report.append("  - ").append(mech).append("\n");
            }
        }
        
        if (!serverInfo.getCapabilities().isEmpty()) {
            report.append("\nCapabilities:\n");
            List<String> sortedCaps = new ArrayList<>(serverInfo.getCapabilities());
            Collections.sort(sortedCaps);
            for (String cap : sortedCaps) {
                if (!cap.startsWith("AUTH=")) {
                    report.append("  - ").append(cap).append("\n");
                }
            }
        }
        
        return report.toString();
    }

    /**
     * Generates a security report.
     */
    @NonNull
    public static String generateSecurityReport(@NonNull SecurityAssessment assessment) {
        StringBuilder report = new StringBuilder();
        
        report.append("IMAP Security Assessment\n");
        report.append("========================\n\n");
        
        report.append("Risk Level: ").append(assessment.getRiskLevel()).append("\n");
        report.append("Secure: ").append(assessment.isSecure() ? "Yes" : "No").append("\n\n");
        
        if (!assessment.getVulnerabilities().isEmpty()) {
            report.append("Vulnerabilities:\n");
            for (String vuln : assessment.getVulnerabilities()) {
                report.append("  [!] ").append(vuln).append("\n");
            }
            report.append("\n");
        }
        
        if (!assessment.getRecommendations().isEmpty()) {
            report.append("Recommendations:\n");
            for (String rec : assessment.getRecommendations()) {
                report.append("  [*] ").append(rec).append("\n");
            }
        }
        
        return report.toString();
    }
}
