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

import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
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
 * Helper class for Telnet protocol operations and analysis.
 * Provides utilities for Telnet banner grabbing, option negotiation,
 * and server fingerprinting.
 */
public final class TelnetHelper {

    private static final String TAG = "TelnetHelper";

    // Default ports
    public static final int DEFAULT_TELNET_PORT = 23;
    public static final int DEFAULT_TIMEOUT_MS = 10000;

    // Telnet command codes
    public static final byte IAC = (byte) 255;   // Interpret As Command
    public static final byte DONT = (byte) 254;  // Don't do option
    public static final byte DO = (byte) 253;    // Do option
    public static final byte WONT = (byte) 252;  // Won't do option
    public static final byte WILL = (byte) 251;  // Will do option
    public static final byte SB = (byte) 250;    // Sub-negotiation Begin
    public static final byte GA = (byte) 249;    // Go Ahead
    public static final byte EL = (byte) 248;    // Erase Line
    public static final byte EC = (byte) 247;    // Erase Character
    public static final byte AYT = (byte) 246;   // Are You There
    public static final byte AO = (byte) 245;    // Abort Output
    public static final byte IP = (byte) 244;    // Interrupt Process
    public static final byte BREAK = (byte) 243; // Break
    public static final byte DM = (byte) 242;    // Data Mark
    public static final byte NOP = (byte) 241;   // No Operation
    public static final byte SE = (byte) 240;    // Sub-negotiation End

    // Telnet options
    public static final byte OPT_BINARY = 0;          // Binary Transmission
    public static final byte OPT_ECHO = 1;            // Echo
    public static final byte OPT_RCP = 2;             // Reconnection
    public static final byte OPT_SGA = 3;             // Suppress Go Ahead
    public static final byte OPT_NAMS = 4;            // Approx Message Size Negotiation
    public static final byte OPT_STATUS = 5;          // Status
    public static final byte OPT_TM = 6;              // Timing Mark
    public static final byte OPT_RCTE = 7;            // Remote Controlled Trans and Echo
    public static final byte OPT_NAOL = 8;            // Output Line Width
    public static final byte OPT_NAOP = 9;            // Output Page Size
    public static final byte OPT_NAOCRD = 10;         // Output Carriage-Return Disposition
    public static final byte OPT_NAOHTS = 11;         // Output Horizontal Tab Stops
    public static final byte OPT_NAOHTD = 12;         // Output Horizontal Tab Disposition
    public static final byte OPT_NAOFFD = 13;         // Output Formfeed Disposition
    public static final byte OPT_NAOVTS = 14;         // Output Vertical Tabstops
    public static final byte OPT_NAOVTD = 15;         // Output Vertical Tab Disposition
    public static final byte OPT_NAOLFD = 16;         // Output Linefeed Disposition
    public static final byte OPT_XASCII = 17;         // Extended ASCII
    public static final byte OPT_LOGOUT = 18;         // Logout
    public static final byte OPT_BM = 19;             // Byte Macro
    public static final byte OPT_DET = 20;            // Data Entry Terminal
    public static final byte OPT_SUPDUP = 21;         // SUPDUP
    public static final byte OPT_SUPDUPOUTPUT = 22;   // SUPDUP Output
    public static final byte OPT_SNDLOC = 23;         // Send Location
    public static final byte OPT_TTYPE = 24;          // Terminal Type
    public static final byte OPT_EOR = 25;            // End of Record
    public static final byte OPT_TUID = 26;           // TACACS User Identification
    public static final byte OPT_OUTMRK = 27;         // Output Marking
    public static final byte OPT_TTYLOC = 28;         // Terminal Location Number
    public static final byte OPT_3270REGIME = 29;     // Telnet 3270 Regime
    public static final byte OPT_X3PAD = 30;          // X.3 PAD
    public static final byte OPT_NAWS = 31;           // Window Size
    public static final byte OPT_TSPEED = 32;         // Terminal Speed
    public static final byte OPT_LFLOW = 33;          // Remote Flow Control
    public static final byte OPT_LINEMODE = 34;       // Linemode
    public static final byte OPT_XDISPLOC = 35;       // X Display Location
    public static final byte OPT_OLD_ENVIRON = 36;    // Environment Option
    public static final byte OPT_AUTHENTICATION = 37; // Authentication
    public static final byte OPT_ENCRYPT = 38;        // Encryption Option
    public static final byte OPT_NEW_ENVIRON = 39;    // New Environment Option

    // Known server signatures
    private static final Map<String, String> SERVER_SIGNATURES = new LinkedHashMap<>();
    static {
        SERVER_SIGNATURES.put("cisco", "Cisco IOS");
        SERVER_SIGNATURES.put("mikrotik", "MikroTik RouterOS");
        SERVER_SIGNATURES.put("linux", "Linux");
        SERVER_SIGNATURES.put("freebsd", "FreeBSD");
        SERVER_SIGNATURES.put("netbsd", "NetBSD");
        SERVER_SIGNATURES.put("openbsd", "OpenBSD");
        SERVER_SIGNATURES.put("windows", "Windows");
        SERVER_SIGNATURES.put("unix", "Unix");
        SERVER_SIGNATURES.put("hp-ux", "HP-UX");
        SERVER_SIGNATURES.put("aix", "IBM AIX");
        SERVER_SIGNATURES.put("solaris", "Sun Solaris");
        SERVER_SIGNATURES.put("sunos", "SunOS");
        SERVER_SIGNATURES.put("busybox", "BusyBox");
        SERVER_SIGNATURES.put("juniper", "Juniper");
        SERVER_SIGNATURES.put("fortigate", "FortiGate");
        SERVER_SIGNATURES.put("dell", "Dell");
        SERVER_SIGNATURES.put("hp ", "HP");
        SERVER_SIGNATURES.put("dlink", "D-Link");
        SERVER_SIGNATURES.put("netgear", "Netgear");
        SERVER_SIGNATURES.put("linksys", "Linksys");
        SERVER_SIGNATURES.put("zyxel", "ZyXEL");
    }

    private TelnetHelper() {
        // Private constructor to prevent instantiation
    }

    /**
     * Represents a Telnet option negotiation.
     */
    public static class TelnetOption {
        private final byte command;
        private final byte option;

        public TelnetOption(byte command, byte option) {
            this.command = command;
            this.option = option;
        }

        public byte getCommand() {
            return command;
        }

        public byte getOption() {
            return option;
        }

        @NonNull
        public String getCommandName() {
            switch (command) {
                case WILL: return "WILL";
                case WONT: return "WONT";
                case DO: return "DO";
                case DONT: return "DONT";
                default: return String.format(Locale.US, "CMD_%d", command & 0xFF);
            }
        }

        @NonNull
        public String getOptionName() {
            return TelnetHelper.getOptionName(option);
        }

        @Override
        public String toString() {
            return String.format(Locale.US, "IAC %s %s", getCommandName(), getOptionName());
        }
    }

    /**
     * Represents Telnet server information.
     */
    public static class TelnetServerInfo {
        private final String banner;
        private final String serverType;
        private final String osType;
        private final List<TelnetOption> negotiatedOptions;
        private final boolean supportsEncryption;
        private final boolean supportsAuthentication;
        private final long responseTime;
        private final Map<String, String> additionalInfo;

        private TelnetServerInfo(Builder builder) {
            this.banner = builder.banner;
            this.serverType = builder.serverType;
            this.osType = builder.osType;
            this.negotiatedOptions = new ArrayList<>(builder.negotiatedOptions);
            this.supportsEncryption = builder.supportsEncryption;
            this.supportsAuthentication = builder.supportsAuthentication;
            this.responseTime = builder.responseTime;
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
        public String getOsType() {
            return osType;
        }

        @NonNull
        public List<TelnetOption> getNegotiatedOptions() {
            return Collections.unmodifiableList(negotiatedOptions);
        }

        public boolean supportsEncryption() {
            return supportsEncryption;
        }

        public boolean supportsAuthentication() {
            return supportsAuthentication;
        }

        public long getResponseTime() {
            return responseTime;
        }

        @NonNull
        public Map<String, String> getAdditionalInfo() {
            return Collections.unmodifiableMap(additionalInfo);
        }

        public static class Builder {
            private String banner;
            private String serverType;
            private String osType;
            private List<TelnetOption> negotiatedOptions = new ArrayList<>();
            private boolean supportsEncryption;
            private boolean supportsAuthentication;
            private long responseTime;
            private Map<String, String> additionalInfo = new HashMap<>();

            public Builder setBanner(String banner) {
                this.banner = banner;
                return this;
            }

            public Builder setServerType(String serverType) {
                this.serverType = serverType;
                return this;
            }

            public Builder setOsType(String osType) {
                this.osType = osType;
                return this;
            }

            public Builder addNegotiatedOption(TelnetOption option) {
                this.negotiatedOptions.add(option);
                return this;
            }

            public Builder setSupportsEncryption(boolean supports) {
                this.supportsEncryption = supports;
                return this;
            }

            public Builder setSupportsAuthentication(boolean supports) {
                this.supportsAuthentication = supports;
                return this;
            }

            public Builder setResponseTime(long responseTime) {
                this.responseTime = responseTime;
                return this;
            }

            public Builder addInfo(String key, String value) {
                this.additionalInfo.put(key, value);
                return this;
            }

            public TelnetServerInfo build() {
                return new TelnetServerInfo(this);
            }
        }
    }

    /**
     * Simple Telnet client for banner grabbing and fingerprinting.
     */
    public static class SimpleTelnetClient implements AutoCloseable {
        private Socket socket;
        private InputStream inputStream;
        private OutputStream outputStream;
        private final String host;
        private final int port;
        private final int timeout;
        private final List<TelnetOption> receivedOptions = new ArrayList<>();

        public SimpleTelnetClient(@NonNull String host) {
            this(host, DEFAULT_TELNET_PORT, DEFAULT_TIMEOUT_MS);
        }

        public SimpleTelnetClient(@NonNull String host, int port) {
            this(host, port, DEFAULT_TIMEOUT_MS);
        }

        public SimpleTelnetClient(@NonNull String host, int port, int timeout) {
            this.host = host;
            this.port = port;
            this.timeout = timeout;
        }

        /**
         * Connects to the Telnet server.
         */
        public void connect() throws IOException {
            socket = new Socket();
            socket.connect(new InetSocketAddress(host, port), timeout);
            socket.setSoTimeout(timeout);
            inputStream = socket.getInputStream();
            outputStream = socket.getOutputStream();
        }

        /**
         * Reads data, handling IAC commands.
         */
        @NonNull
        public String readBanner() throws IOException {
            StringBuilder banner = new StringBuilder();
            byte[] buffer = new byte[4096];
            int bytesRead;

            long endTime = System.currentTimeMillis() + 3000; // 3 second read timeout
            
            while (System.currentTimeMillis() < endTime) {
                if (inputStream.available() > 0) {
                    bytesRead = inputStream.read(buffer);
                    if (bytesRead == -1) {
                        break;
                    }

                    int i = 0;
                    while (i < bytesRead) {
                        byte b = buffer[i];

                        if (b == IAC && i + 2 < bytesRead) {
                            // Handle IAC command
                            byte cmd = buffer[i + 1];
                            byte opt = buffer[i + 2];

                            TelnetOption telnetOpt = new TelnetOption(cmd, opt);
                            receivedOptions.add(telnetOpt);

                            // Respond to option negotiation
                            handleOption(cmd, opt);

                            i += 3;
                        } else if (b != IAC) {
                            // Regular data
                            if (b >= 32 || b == '\r' || b == '\n' || b == '\t') {
                                banner.append((char) (b & 0xFF));
                            }
                            i++;
                        } else {
                            i++;
                        }
                    }
                } else {
                    try {
                        Thread.sleep(100);
                    } catch (InterruptedException e) {
                        Thread.currentThread().interrupt();
                        break;
                    }
                }

                // Check if we have enough data
                if (banner.length() > 100) {
                    break;
                }
            }

            return banner.toString().trim();
        }

        /**
         * Handles Telnet option negotiation.
         */
        private void handleOption(byte command, byte option) throws IOException {
            byte[] response = new byte[3];
            response[0] = IAC;

            switch (command) {
                case DO:
                    // Respond with WONT (we don't support any options)
                    response[1] = WONT;
                    response[2] = option;
                    outputStream.write(response);
                    outputStream.flush();
                    break;
                case WILL:
                    // Respond with DONT
                    response[1] = DONT;
                    response[2] = option;
                    outputStream.write(response);
                    outputStream.flush();
                    break;
                default:
                    // Ignore WONT and DONT
                    break;
            }
        }

        /**
         * Gets received options.
         */
        @NonNull
        public List<TelnetOption> getReceivedOptions() {
            return Collections.unmodifiableList(receivedOptions);
        }

        /**
         * Sends raw data.
         */
        public void send(@NonNull String data) throws IOException {
            outputStream.write(data.getBytes());
            outputStream.flush();
        }

        /**
         * Sends raw bytes.
         */
        public void send(@NonNull byte[] data) throws IOException {
            outputStream.write(data);
            outputStream.flush();
        }

        @Override
        public void close() {
            try {
                if (inputStream != null) inputStream.close();
                if (outputStream != null) outputStream.close();
                if (socket != null && !socket.isClosed()) socket.close();
            } catch (IOException ignored) {
                // Ignore close errors
            }
        }
    }

    /**
     * Gets option name from option code.
     */
    @NonNull
    public static String getOptionName(byte option) {
        int opt = option & 0xFF;
        switch (opt) {
            case 0: return "BINARY";
            case 1: return "ECHO";
            case 2: return "RCP";
            case 3: return "SGA";
            case 5: return "STATUS";
            case 6: return "TIMING-MARK";
            case 24: return "TERMINAL-TYPE";
            case 25: return "END-OF-RECORD";
            case 31: return "WINDOW-SIZE";
            case 32: return "TERMINAL-SPEED";
            case 33: return "REMOTE-FLOW-CONTROL";
            case 34: return "LINEMODE";
            case 35: return "X-DISPLAY-LOCATION";
            case 36: return "OLD-ENVIRON";
            case 37: return "AUTHENTICATION";
            case 38: return "ENCRYPT";
            case 39: return "NEW-ENVIRON";
            default: return String.format(Locale.US, "OPTION-%d", opt);
        }
    }

    /**
     * Identifies server type from banner.
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
     * Fingerprints a Telnet server.
     */
    @NonNull
    public static TelnetServerInfo fingerprintServer(@NonNull String host) throws IOException {
        return fingerprintServer(host, DEFAULT_TELNET_PORT, DEFAULT_TIMEOUT_MS);
    }

    /**
     * Fingerprints a Telnet server with custom settings.
     */
    @NonNull
    public static TelnetServerInfo fingerprintServer(@NonNull String host, int port, int timeout) 
            throws IOException {
        TelnetServerInfo.Builder builder = new TelnetServerInfo.Builder();
        long startTime = System.currentTimeMillis();

        try (SimpleTelnetClient client = new SimpleTelnetClient(host, port, timeout)) {
            client.connect();
            
            String banner = client.readBanner();
            builder.setBanner(banner);
            builder.setResponseTime(System.currentTimeMillis() - startTime);

            // Identify server
            String serverType = identifyServer(banner);
            if (serverType != null) {
                builder.setServerType(serverType);
                builder.setOsType(serverType);
            }

            // Process received options
            for (TelnetOption opt : client.getReceivedOptions()) {
                builder.addNegotiatedOption(opt);
                
                if (opt.getOption() == OPT_ENCRYPT) {
                    builder.setSupportsEncryption(true);
                }
                if (opt.getOption() == OPT_AUTHENTICATION) {
                    builder.setSupportsAuthentication(true);
                }
            }
        }

        return builder.build();
    }

    /**
     * Grabs banner from a Telnet server.
     */
    @Nullable
    public static String grabBanner(@NonNull String host) {
        return grabBanner(host, DEFAULT_TELNET_PORT, DEFAULT_TIMEOUT_MS);
    }

    /**
     * Grabs banner from a Telnet server with custom settings.
     */
    @Nullable
    public static String grabBanner(@NonNull String host, int port, int timeout) {
        try (SimpleTelnetClient client = new SimpleTelnetClient(host, port, timeout)) {
            client.connect();
            return client.readBanner();
        } catch (IOException e) {
            return null;
        }
    }

    /**
     * Tests if a host has a Telnet server.
     */
    public static boolean isPortOpen(@NonNull String host, int port) {
        return isPortOpen(host, port, DEFAULT_TIMEOUT_MS);
    }

    /**
     * Tests if a host has a Telnet server with custom timeout.
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
     * Checks for vulnerabilities.
     */
    @NonNull
    public static List<String> checkVulnerabilities(@NonNull TelnetServerInfo serverInfo) {
        List<String> vulnerabilities = new ArrayList<>();

        // Telnet is inherently insecure
        vulnerabilities.add("CRITICAL: Telnet transmits data in cleartext (use SSH instead)");

        // Check encryption support
        if (!serverInfo.supportsEncryption()) {
            vulnerabilities.add("No encryption support available");
        }

        // Check authentication
        if (!serverInfo.supportsAuthentication()) {
            vulnerabilities.add("No advanced authentication support");
        }

        // Check for default credentials patterns
        String banner = serverInfo.getBanner();
        if (banner != null) {
            String lowerBanner = banner.toLowerCase(Locale.US);
            
            if (lowerBanner.contains("login:") || lowerBanner.contains("username:")) {
                vulnerabilities.add("Server prompts for credentials over unencrypted connection");
            }

            if (lowerBanner.contains("busybox")) {
                vulnerabilities.add("BusyBox telnetd detected - often has weak/default credentials");
            }

            if (lowerBanner.contains("default") || lowerBanner.contains("admin")) {
                vulnerabilities.add("Banner may indicate default credentials in use");
            }
        }

        return vulnerabilities;
    }

    /**
     * Generates a report.
     */
    @NonNull
    public static String generateReport(@NonNull TelnetServerInfo serverInfo) {
        StringBuilder report = new StringBuilder();

        report.append("Telnet Server Analysis Report\n");
        report.append("=============================\n\n");

        if (serverInfo.getBanner() != null) {
            String banner = serverInfo.getBanner();
            if (banner.length() > 200) {
                banner = banner.substring(0, 200) + "...";
            }
            report.append("Banner:\n").append(banner).append("\n\n");
        }

        if (serverInfo.getServerType() != null) {
            report.append("Server Type: ").append(serverInfo.getServerType()).append("\n");
        }

        if (serverInfo.getOsType() != null) {
            report.append("OS Type: ").append(serverInfo.getOsType()).append("\n");
        }

        report.append("Response Time: ").append(serverInfo.getResponseTime()).append(" ms\n");
        report.append("Encryption: ").append(serverInfo.supportsEncryption() ? "Supported" : "Not supported").append("\n");
        report.append("Authentication: ").append(serverInfo.supportsAuthentication() ? "Supported" : "Basic only").append("\n");

        List<TelnetOption> options = serverInfo.getNegotiatedOptions();
        if (!options.isEmpty()) {
            report.append("\nNegotiated Options:\n");
            for (TelnetOption opt : options) {
                report.append("  • ").append(opt.toString()).append("\n");
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
