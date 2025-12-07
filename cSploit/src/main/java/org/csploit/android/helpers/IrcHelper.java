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
 * Helper class for IRC protocol operations and analysis.
 * Provides utilities for IRC server fingerprinting, enumeration,
 * and security assessment.
 */
public final class IrcHelper {

    private static final String TAG = "IrcHelper";

    // Default IRC ports
    public static final int DEFAULT_IRC_PORT = 6667;
    public static final int DEFAULT_IRCS_PORT = 6697;
    public static final int DEFAULT_TIMEOUT_MS = 15000;

    // IRC reply codes
    public static final int RPL_WELCOME = 1;
    public static final int RPL_YOURHOST = 2;
    public static final int RPL_CREATED = 3;
    public static final int RPL_MYINFO = 4;
    public static final int RPL_ISUPPORT = 5;
    public static final int RPL_LUSERCLIENT = 251;
    public static final int RPL_LUSEROP = 252;
    public static final int RPL_LUSERUNKNOWN = 253;
    public static final int RPL_LUSERCHANNELS = 254;
    public static final int RPL_LUSERME = 255;
    public static final int RPL_ADMINME = 256;
    public static final int RPL_ADMINLOC1 = 257;
    public static final int RPL_ADMINLOC2 = 258;
    public static final int RPL_ADMINEMAIL = 259;
    public static final int RPL_LOCALUSERS = 265;
    public static final int RPL_GLOBALUSERS = 266;
    public static final int RPL_MOTDSTART = 375;
    public static final int RPL_MOTD = 372;
    public static final int RPL_ENDOFMOTD = 376;
    public static final int RPL_LIST = 322;
    public static final int RPL_LISTEND = 323;
    public static final int ERR_NOSUCHNICK = 401;
    public static final int ERR_NOSUCHCHANNEL = 403;
    public static final int ERR_NICKNAMEINUSE = 433;
    public static final int ERR_NOPRIVILEGES = 481;

    // IRC commands
    public static final String CMD_NICK = "NICK";
    public static final String CMD_USER = "USER";
    public static final String CMD_PING = "PING";
    public static final String CMD_PONG = "PONG";
    public static final String CMD_QUIT = "QUIT";
    public static final String CMD_JOIN = "JOIN";
    public static final String CMD_PART = "PART";
    public static final String CMD_PRIVMSG = "PRIVMSG";
    public static final String CMD_NOTICE = "NOTICE";
    public static final String CMD_MOTD = "MOTD";
    public static final String CMD_LUSERS = "LUSERS";
    public static final String CMD_VERSION = "VERSION";
    public static final String CMD_ADMIN = "ADMIN";
    public static final String CMD_INFO = "INFO";
    public static final String CMD_LIST = "LIST";
    public static final String CMD_WHO = "WHO";
    public static final String CMD_WHOIS = "WHOIS";
    public static final String CMD_USERHOST = "USERHOST";
    public static final String CMD_CAP = "CAP";

    // Common ISUPPORT tokens
    public static final String ISUPPORT_NETWORK = "NETWORK";
    public static final String ISUPPORT_CHANTYPES = "CHANTYPES";
    public static final String ISUPPORT_CHANMODES = "CHANMODES";
    public static final String ISUPPORT_PREFIX = "PREFIX";
    public static final String ISUPPORT_MAXCHANNELS = "MAXCHANNELS";
    public static final String ISUPPORT_NICKLEN = "NICKLEN";
    public static final String ISUPPORT_TOPICLEN = "TOPICLEN";
    public static final String ISUPPORT_KICKLEN = "KICKLEN";
    public static final String ISUPPORT_SSL = "SSL";
    public static final String ISUPPORT_SAFELIST = "SAFELIST";
    public static final String ISUPPORT_CASEMAPPING = "CASEMAPPING";

    // IRC daemon signatures
    private static final Map<String, String> IRCD_SIGNATURES = new HashMap<>();

    static {
        IRCD_SIGNATURES.put("Unreal", "UnrealIRCd");
        IRCD_SIGNATURES.put("UnrealIRCd", "UnrealIRCd");
        IRCD_SIGNATURES.put("InspIRCd", "InspIRCd");
        IRCD_SIGNATURES.put("ircd-hybrid", "IRCd-Hybrid");
        IRCD_SIGNATURES.put("Hybrid", "IRCd-Hybrid");
        IRCD_SIGNATURES.put("ircd-seven", "ircd-seven");
        IRCD_SIGNATURES.put("charybdis", "Charybdis");
        IRCD_SIGNATURES.put("ratbox", "IRCd-Ratbox");
        IRCD_SIGNATURES.put("Bahamut", "Bahamut");
        IRCD_SIGNATURES.put("ircu", "IRCu");
        IRCD_SIGNATURES.put("snircd", "snircd");
        IRCD_SIGNATURES.put("ngIRCd", "ngIRCd");
        IRCD_SIGNATURES.put("irc2", "irc2");
        IRCD_SIGNATURES.put("plexus", "Plexus");
        IRCD_SIGNATURES.put("Nefarious", "Nefarious");
        IRCD_SIGNATURES.put("ergo", "Ergo");
        IRCD_SIGNATURES.put("solanum", "Solanum");
    }

    private IrcHelper() {
        // Private constructor to prevent instantiation
    }

    /**
     * Represents IRC server information.
     */
    public static class ServerInfo {
        private final String serverName;
        private final String version;
        private final String ircdType;
        private final String network;
        private final String welcomeMessage;
        private final String motd;
        private final Map<String, String> isupport;
        private final ServerStats stats;
        private final AdminInfo adminInfo;

        private ServerInfo(Builder builder) {
            this.serverName = builder.serverName;
            this.version = builder.version;
            this.ircdType = builder.ircdType;
            this.network = builder.network;
            this.welcomeMessage = builder.welcomeMessage;
            this.motd = builder.motd;
            this.isupport = new HashMap<>(builder.isupport);
            this.stats = builder.stats;
            this.adminInfo = builder.adminInfo;
        }

        @Nullable
        public String getServerName() {
            return serverName;
        }

        @Nullable
        public String getVersion() {
            return version;
        }

        @Nullable
        public String getIrcdType() {
            return ircdType;
        }

        @Nullable
        public String getNetwork() {
            return network;
        }

        @Nullable
        public String getWelcomeMessage() {
            return welcomeMessage;
        }

        @Nullable
        public String getMotd() {
            return motd;
        }

        @NonNull
        public Map<String, String> getIsupport() {
            return Collections.unmodifiableMap(isupport);
        }

        @Nullable
        public String getIsupportValue(String token) {
            return isupport.get(token.toUpperCase(Locale.US));
        }

        @Nullable
        public ServerStats getStats() {
            return stats;
        }

        @Nullable
        public AdminInfo getAdminInfo() {
            return adminInfo;
        }

        public static class Builder {
            private String serverName;
            private String version;
            private String ircdType;
            private String network;
            private String welcomeMessage;
            private String motd;
            private Map<String, String> isupport = new HashMap<>();
            private ServerStats stats;
            private AdminInfo adminInfo;

            public Builder setServerName(String serverName) {
                this.serverName = serverName;
                return this;
            }

            public Builder setVersion(String version) {
                this.version = version;
                return this;
            }

            public Builder setIrcdType(String ircdType) {
                this.ircdType = ircdType;
                return this;
            }

            public Builder setNetwork(String network) {
                this.network = network;
                return this;
            }

            public Builder setWelcomeMessage(String welcomeMessage) {
                this.welcomeMessage = welcomeMessage;
                return this;
            }

            public Builder setMotd(String motd) {
                this.motd = motd;
                return this;
            }

            public Builder addIsupport(String token, String value) {
                this.isupport.put(token.toUpperCase(Locale.US), value);
                return this;
            }

            public Builder setStats(ServerStats stats) {
                this.stats = stats;
                return this;
            }

            public Builder setAdminInfo(AdminInfo adminInfo) {
                this.adminInfo = adminInfo;
                return this;
            }

            public ServerInfo build() {
                return new ServerInfo(this);
            }
        }
    }

    /**
     * Represents IRC server statistics.
     */
    public static class ServerStats {
        private final int localUsers;
        private final int localUsersMax;
        private final int globalUsers;
        private final int globalUsersMax;
        private final int operators;
        private final int channels;
        private final int unknownConnections;

        private ServerStats(Builder builder) {
            this.localUsers = builder.localUsers;
            this.localUsersMax = builder.localUsersMax;
            this.globalUsers = builder.globalUsers;
            this.globalUsersMax = builder.globalUsersMax;
            this.operators = builder.operators;
            this.channels = builder.channels;
            this.unknownConnections = builder.unknownConnections;
        }

        public int getLocalUsers() {
            return localUsers;
        }

        public int getLocalUsersMax() {
            return localUsersMax;
        }

        public int getGlobalUsers() {
            return globalUsers;
        }

        public int getGlobalUsersMax() {
            return globalUsersMax;
        }

        public int getOperators() {
            return operators;
        }

        public int getChannels() {
            return channels;
        }

        public int getUnknownConnections() {
            return unknownConnections;
        }

        public static class Builder {
            private int localUsers;
            private int localUsersMax;
            private int globalUsers;
            private int globalUsersMax;
            private int operators;
            private int channels;
            private int unknownConnections;

            public Builder setLocalUsers(int localUsers) {
                this.localUsers = localUsers;
                return this;
            }

            public Builder setLocalUsersMax(int localUsersMax) {
                this.localUsersMax = localUsersMax;
                return this;
            }

            public Builder setGlobalUsers(int globalUsers) {
                this.globalUsers = globalUsers;
                return this;
            }

            public Builder setGlobalUsersMax(int globalUsersMax) {
                this.globalUsersMax = globalUsersMax;
                return this;
            }

            public Builder setOperators(int operators) {
                this.operators = operators;
                return this;
            }

            public Builder setChannels(int channels) {
                this.channels = channels;
                return this;
            }

            public Builder setUnknownConnections(int unknownConnections) {
                this.unknownConnections = unknownConnections;
                return this;
            }

            public ServerStats build() {
                return new ServerStats(this);
            }
        }
    }

    /**
     * Represents IRC admin information.
     */
    public static class AdminInfo {
        private final String location1;
        private final String location2;
        private final String email;

        public AdminInfo(@Nullable String location1, @Nullable String location2, @Nullable String email) {
            this.location1 = location1;
            this.location2 = location2;
            this.email = email;
        }

        @Nullable
        public String getLocation1() {
            return location1;
        }

        @Nullable
        public String getLocation2() {
            return location2;
        }

        @Nullable
        public String getEmail() {
            return email;
        }
    }

    /**
     * Represents an IRC message.
     */
    public static class IrcMessage {
        private final String prefix;
        private final String command;
        private final List<String> params;
        private final String trailing;

        private IrcMessage(Builder builder) {
            this.prefix = builder.prefix;
            this.command = builder.command;
            this.params = new ArrayList<>(builder.params);
            this.trailing = builder.trailing;
        }

        @Nullable
        public String getPrefix() {
            return prefix;
        }

        @NonNull
        public String getCommand() {
            return command;
        }

        @NonNull
        public List<String> getParams() {
            return Collections.unmodifiableList(params);
        }

        @Nullable
        public String getTrailing() {
            return trailing;
        }

        public int getNumericCommand() {
            try {
                return Integer.parseInt(command);
            } catch (NumberFormatException e) {
                return -1;
            }
        }

        public static class Builder {
            private String prefix;
            private String command;
            private List<String> params = new ArrayList<>();
            private String trailing;

            public Builder setPrefix(String prefix) {
                this.prefix = prefix;
                return this;
            }

            public Builder setCommand(String command) {
                this.command = command;
                return this;
            }

            public Builder addParam(String param) {
                this.params.add(param);
                return this;
            }

            public Builder setTrailing(String trailing) {
                this.trailing = trailing;
                return this;
            }

            public IrcMessage build() {
                return new IrcMessage(this);
            }
        }

        @NonNull
        public static IrcMessage parse(@NonNull String line) {
            Builder builder = new Builder();
            String remaining = line;

            // Check for prefix
            if (remaining.startsWith(":")) {
                int spaceIndex = remaining.indexOf(' ');
                if (spaceIndex > 0) {
                    builder.setPrefix(remaining.substring(1, spaceIndex));
                    remaining = remaining.substring(spaceIndex + 1);
                }
            }

            // Find trailing (starts with :)
            int trailingIndex = remaining.indexOf(" :");
            String paramsSection = remaining;
            if (trailingIndex >= 0) {
                builder.setTrailing(remaining.substring(trailingIndex + 2));
                paramsSection = remaining.substring(0, trailingIndex);
            }

            // Split command and params
            String[] parts = paramsSection.split("\\s+");
            if (parts.length > 0) {
                builder.setCommand(parts[0]);
                for (int i = 1; i < parts.length; i++) {
                    builder.addParam(parts[i]);
                }
            }

            return builder.build();
        }
    }

    /**
     * Represents IRC security assessment.
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
     * Gets server information.
     */
    @NonNull
    public static ServerInfo getServerInfo(@NonNull String host) {
        return getServerInfo(host, DEFAULT_IRC_PORT, DEFAULT_TIMEOUT_MS);
    }

    /**
     * Gets server information with custom settings.
     */
    @NonNull
    public static ServerInfo getServerInfo(@NonNull String host, int port, int timeout) {
        ServerInfo.Builder builder = new ServerInfo.Builder();
        ServerStats.Builder statsBuilder = new ServerStats.Builder();
        StringBuilder motdBuilder = new StringBuilder();
        String adminLoc1 = null, adminLoc2 = null, adminEmail = null;

        try (Socket socket = new Socket()) {
            socket.connect(new java.net.InetSocketAddress(host, port), timeout);
            socket.setSoTimeout(timeout);

            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
            BufferedWriter writer = new BufferedWriter(
                    new OutputStreamWriter(socket.getOutputStream(), StandardCharsets.UTF_8));

            // Register with server
            String nick = generateRandomNick();
            writer.write(CMD_NICK + " " + nick + "\r\n");
            writer.write(CMD_USER + " " + nick + " 0 * :cSploit Scanner\r\n");
            writer.flush();

            // Read responses
            String line;
            boolean connected = false;
            int linesRead = 0;
            int maxLines = 200;

            while ((line = reader.readLine()) != null && linesRead < maxLines) {
                linesRead++;

                // Handle PING
                if (line.startsWith("PING")) {
                    String pingArg = line.substring(5);
                    writer.write("PONG " + pingArg + "\r\n");
                    writer.flush();
                    continue;
                }

                IrcMessage msg = IrcMessage.parse(line);
                int numeric = msg.getNumericCommand();

                switch (numeric) {
                    case RPL_WELCOME:
                        connected = true;
                        builder.setWelcomeMessage(msg.getTrailing());
                        break;

                    case RPL_YOURHOST:
                        if (msg.getTrailing() != null) {
                            // Extract server name and version
                            Pattern hostPattern = Pattern.compile("Your host is ([^,]+), running version (.+)");
                            Matcher hostMatcher = hostPattern.matcher(msg.getTrailing());
                            if (hostMatcher.find()) {
                                builder.setServerName(hostMatcher.group(1));
                                builder.setVersion(hostMatcher.group(2));
                            }
                        }
                        break;

                    case RPL_MYINFO:
                        if (msg.getParams().size() >= 2) {
                            builder.setServerName(msg.getParams().get(1));
                        }
                        if (msg.getParams().size() >= 3) {
                            builder.setVersion(msg.getParams().get(2));
                            // Detect IRCD type
                            String ircd = detectIrcdType(msg.getParams().get(2));
                            if (ircd != null) {
                                builder.setIrcdType(ircd);
                            }
                        }
                        break;

                    case RPL_ISUPPORT:
                        // Parse ISUPPORT tokens
                        for (String param : msg.getParams()) {
                            if (param.contains("=")) {
                                String[] kv = param.split("=", 2);
                                builder.addIsupport(kv[0], kv.length > 1 ? kv[1] : "");
                                if (kv[0].equalsIgnoreCase(ISUPPORT_NETWORK)) {
                                    builder.setNetwork(kv[1]);
                                }
                            } else if (!param.equals(nick)) {
                                builder.addIsupport(param, "true");
                            }
                        }
                        break;

                    case RPL_LUSERCLIENT:
                    case RPL_LUSERME:
                        // Parse user counts
                        if (msg.getTrailing() != null) {
                            Pattern userPattern = Pattern.compile("(\\d+)\\s+(user|invisible|server|client)", Pattern.CASE_INSENSITIVE);
                            Matcher userMatcher = userPattern.matcher(msg.getTrailing());
                            while (userMatcher.find()) {
                                int count = Integer.parseInt(userMatcher.group(1));
                                String type = userMatcher.group(2).toLowerCase(Locale.US);
                                if (type.contains("user") || type.contains("client")) {
                                    statsBuilder.setLocalUsers(count);
                                }
                            }
                        }
                        break;

                    case RPL_LUSEROP:
                        if (!msg.getParams().isEmpty()) {
                            try {
                                statsBuilder.setOperators(Integer.parseInt(msg.getParams().get(msg.getParams().size() - 1)));
                            } catch (NumberFormatException ignored) {}
                        }
                        break;

                    case RPL_LUSERCHANNELS:
                        if (!msg.getParams().isEmpty()) {
                            try {
                                statsBuilder.setChannels(Integer.parseInt(msg.getParams().get(msg.getParams().size() - 1)));
                            } catch (NumberFormatException ignored) {}
                        }
                        break;

                    case RPL_LUSERUNKNOWN:
                        if (!msg.getParams().isEmpty()) {
                            try {
                                statsBuilder.setUnknownConnections(Integer.parseInt(msg.getParams().get(msg.getParams().size() - 1)));
                            } catch (NumberFormatException ignored) {}
                        }
                        break;

                    case RPL_LOCALUSERS:
                        if (msg.getTrailing() != null) {
                            Pattern localPattern = Pattern.compile("Current local users:?\\s*(\\d+).*Max:?\\s*(\\d+)", Pattern.CASE_INSENSITIVE);
                            Matcher localMatcher = localPattern.matcher(msg.getTrailing());
                            if (localMatcher.find()) {
                                statsBuilder.setLocalUsers(Integer.parseInt(localMatcher.group(1)));
                                statsBuilder.setLocalUsersMax(Integer.parseInt(localMatcher.group(2)));
                            }
                        }
                        break;

                    case RPL_GLOBALUSERS:
                        if (msg.getTrailing() != null) {
                            Pattern globalPattern = Pattern.compile("Current global users:?\\s*(\\d+).*Max:?\\s*(\\d+)", Pattern.CASE_INSENSITIVE);
                            Matcher globalMatcher = globalPattern.matcher(msg.getTrailing());
                            if (globalMatcher.find()) {
                                statsBuilder.setGlobalUsers(Integer.parseInt(globalMatcher.group(1)));
                                statsBuilder.setGlobalUsersMax(Integer.parseInt(globalMatcher.group(2)));
                            }
                        }
                        break;

                    case RPL_MOTD:
                    case RPL_MOTDSTART:
                        if (msg.getTrailing() != null) {
                            motdBuilder.append(msg.getTrailing()).append("\n");
                        }
                        break;

                    case RPL_ENDOFMOTD:
                        // MOTD complete, request more info
                        writer.write(CMD_ADMIN + "\r\n");
                        writer.flush();
                        break;

                    case RPL_ADMINLOC1:
                        adminLoc1 = msg.getTrailing();
                        break;

                    case RPL_ADMINLOC2:
                        adminLoc2 = msg.getTrailing();
                        break;

                    case RPL_ADMINEMAIL:
                        adminEmail = msg.getTrailing();
                        break;
                }

                // Exit after collecting enough info
                if (connected && linesRead > 100) {
                    break;
                }
            }

            // Quit gracefully
            writer.write(CMD_QUIT + " :Scan complete\r\n");
            writer.flush();

            // Build final objects
            if (motdBuilder.length() > 0) {
                builder.setMotd(motdBuilder.toString());
            }

            if (adminLoc1 != null || adminLoc2 != null || adminEmail != null) {
                builder.setAdminInfo(new AdminInfo(adminLoc1, adminLoc2, adminEmail));
            }

            builder.setStats(statsBuilder.build());

        } catch (IOException e) {
            // Connection failed
        }

        return builder.build();
    }

    /**
     * Performs a security assessment.
     */
    @NonNull
    public static SecurityAssessment assessSecurity(@NonNull String host) {
        return assessSecurity(host, DEFAULT_IRC_PORT, DEFAULT_TIMEOUT_MS);
    }

    /**
     * Performs a security assessment with custom settings.
     */
    @NonNull
    public static SecurityAssessment assessSecurity(@NonNull String host, int port, int timeout) {
        SecurityAssessment.Builder builder = new SecurityAssessment.Builder();
        ServerInfo serverInfo = getServerInfo(host, port, timeout);

        int riskScore = 0;

        // Check for plaintext connection
        if (port == DEFAULT_IRC_PORT) {
            builder.addVulnerability("Connection is unencrypted (plaintext)");
            builder.addRecommendation("Use IRC over TLS/SSL (typically port 6697)");
            riskScore += 2;
        }

        // Check version disclosure
        if (serverInfo.getVersion() != null && !serverInfo.getVersion().isEmpty()) {
            builder.addVulnerability("Server version disclosed: " + serverInfo.getVersion());
            builder.addRecommendation("Consider hiding version information");
            riskScore += 1;
        }

        // Check for admin info disclosure
        AdminInfo adminInfo = serverInfo.getAdminInfo();
        if (adminInfo != null) {
            if (adminInfo.getEmail() != null) {
                builder.addVulnerability("Admin email disclosed: " + adminInfo.getEmail());
                riskScore += 1;
            }
            if (adminInfo.getLocation1() != null || adminInfo.getLocation2() != null) {
                builder.addVulnerability("Admin location information disclosed");
                riskScore += 1;
            }
        }

        // Check MOTD for sensitive info
        String motd = serverInfo.getMotd();
        if (motd != null) {
            if (motd.toLowerCase(Locale.US).contains("password") ||
                motd.toLowerCase(Locale.US).contains("register")) {
                builder.addRecommendation("MOTD contains authentication-related information");
            }
        }

        // Check for known vulnerable IRCd
        String ircdType = serverInfo.getIrcdType();
        if (ircdType != null) {
            if (ircdType.contains("Unreal") && serverInfo.getVersion() != null) {
                Pattern versionPattern = Pattern.compile("([0-9]+)\\.([0-9]+)");
                Matcher versionMatcher = versionPattern.matcher(serverInfo.getVersion());
                if (versionMatcher.find()) {
                    int major = Integer.parseInt(versionMatcher.group(1));
                    if (major < 5) {
                        builder.addVulnerability("Potentially outdated UnrealIRCd version");
                        riskScore += 2;
                    }
                }
            }
        }

        // Determine risk level
        if (riskScore >= 4) {
            builder.setRiskLevel("HIGH");
        } else if (riskScore >= 2) {
            builder.setRiskLevel("MEDIUM");
        } else if (riskScore > 0) {
            builder.setRiskLevel("LOW");
        } else {
            builder.setRiskLevel("MINIMAL");
        }

        return builder.build();
    }

    /**
     * Detects IRCD type from version string.
     */
    @Nullable
    private static String detectIrcdType(@NonNull String version) {
        String upperVersion = version.toUpperCase(Locale.US);
        
        for (Map.Entry<String, String> entry : IRCD_SIGNATURES.entrySet()) {
            if (upperVersion.contains(entry.getKey().toUpperCase(Locale.US))) {
                return entry.getValue();
            }
        }
        
        return null;
    }

    /**
     * Generates a random nick for scanning.
     */
    @NonNull
    private static String generateRandomNick() {
        StringBuilder nick = new StringBuilder("scan");
        for (int i = 0; i < 5; i++) {
            nick.append((int) (Math.random() * 10));
        }
        return nick.toString();
    }

    /**
     * Tests if IRC server is reachable.
     */
    public static boolean isReachable(@NonNull String host) {
        return isReachable(host, DEFAULT_IRC_PORT, DEFAULT_TIMEOUT_MS);
    }

    /**
     * Tests if IRC server is reachable.
     */
    public static boolean isReachable(@NonNull String host, int port, int timeout) {
        try (Socket socket = new Socket()) {
            socket.connect(new java.net.InetSocketAddress(host, port), timeout);
            socket.setSoTimeout(timeout);
            
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(socket.getInputStream(), StandardCharsets.UTF_8));
            
            // IRC servers typically send a response immediately
            String response = reader.readLine();
            return response != null;
        } catch (IOException e) {
            return false;
        }
    }

    /**
     * Generates a report for IRC server.
     */
    @NonNull
    public static String generateReport(@NonNull ServerInfo serverInfo) {
        StringBuilder report = new StringBuilder();
        
        report.append("IRC Server Information\n");
        report.append("======================\n\n");
        
        if (serverInfo.getServerName() != null) {
            report.append("Server: ").append(serverInfo.getServerName()).append("\n");
        }
        
        if (serverInfo.getNetwork() != null) {
            report.append("Network: ").append(serverInfo.getNetwork()).append("\n");
        }
        
        if (serverInfo.getVersion() != null) {
            report.append("Version: ").append(serverInfo.getVersion()).append("\n");
        }
        
        if (serverInfo.getIrcdType() != null) {
            report.append("IRCd: ").append(serverInfo.getIrcdType()).append("\n");
        }
        
        ServerStats stats = serverInfo.getStats();
        if (stats != null) {
            report.append("\nServer Statistics:\n");
            report.append("------------------\n");
            if (stats.getLocalUsers() > 0) {
                report.append(String.format(Locale.US, "Local Users: %d (max: %d)\n", 
                        stats.getLocalUsers(), stats.getLocalUsersMax()));
            }
            if (stats.getGlobalUsers() > 0) {
                report.append(String.format(Locale.US, "Global Users: %d (max: %d)\n", 
                        stats.getGlobalUsers(), stats.getGlobalUsersMax()));
            }
            if (stats.getChannels() > 0) {
                report.append(String.format(Locale.US, "Channels: %d\n", stats.getChannels()));
            }
            if (stats.getOperators() > 0) {
                report.append(String.format(Locale.US, "Operators: %d\n", stats.getOperators()));
            }
        }
        
        AdminInfo admin = serverInfo.getAdminInfo();
        if (admin != null) {
            report.append("\nAdmin Information:\n");
            report.append("------------------\n");
            if (admin.getLocation1() != null) {
                report.append("Location: ").append(admin.getLocation1()).append("\n");
            }
            if (admin.getLocation2() != null) {
                report.append("          ").append(admin.getLocation2()).append("\n");
            }
            if (admin.getEmail() != null) {
                report.append("Email: ").append(admin.getEmail()).append("\n");
            }
        }
        
        if (!serverInfo.getIsupport().isEmpty()) {
            report.append("\nISUPPORT Tokens:\n");
            report.append("----------------\n");
            for (Map.Entry<String, String> entry : serverInfo.getIsupport().entrySet()) {
                report.append(String.format(Locale.US, "  %s=%s\n", entry.getKey(), entry.getValue()));
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
        
        report.append("IRC Security Assessment\n");
        report.append("=======================\n\n");
        
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
