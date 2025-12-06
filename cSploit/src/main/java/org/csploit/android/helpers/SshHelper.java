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
import android.os.Build;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStreamWriter;
import java.io.PrintWriter;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
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
 * Helper class for SSH protocol operations and analysis.
 * Provides utilities for SSH banner parsing, key exchange analysis,
 * and protocol fingerprinting.
 */
public final class SshHelper {

    private static final String TAG = "SshHelper";

    // Default SSH port
    public static final int DEFAULT_SSH_PORT = 22;
    public static final int DEFAULT_TIMEOUT_MS = 10000;
    public static final int SSH_MAX_BANNER_LENGTH = 255;

    // SSH Protocol versions
    public static final String SSH_VERSION_1 = "1.0";
    public static final String SSH_VERSION_1_5 = "1.5";
    public static final String SSH_VERSION_1_99 = "1.99";
    public static final String SSH_VERSION_2 = "2.0";

    // SSH Message types
    public static final byte SSH_MSG_DISCONNECT = 1;
    public static final byte SSH_MSG_IGNORE = 2;
    public static final byte SSH_MSG_UNIMPLEMENTED = 3;
    public static final byte SSH_MSG_DEBUG = 4;
    public static final byte SSH_MSG_SERVICE_REQUEST = 5;
    public static final byte SSH_MSG_SERVICE_ACCEPT = 6;
    public static final byte SSH_MSG_KEXINIT = 20;
    public static final byte SSH_MSG_NEWKEYS = 21;

    // Patterns
    private static final Pattern BANNER_PATTERN = Pattern.compile(
            "^SSH-(\\d+\\.\\d+)-(.+?)(?:\\s+(.*))?$");
    private static final Pattern VERSION_PATTERN = Pattern.compile(
            "([\\w-]+)[_\\s]*(\\d+\\.\\d+(?:\\.\\d+)?(?:p\\d+)?)?");
    private static final Pattern DROPBEAR_PATTERN = Pattern.compile(
            "dropbear[_-]?(\\d+\\.\\d+)?", Pattern.CASE_INSENSITIVE);

    // Known SSH server signatures
    private static final Map<String, String> SERVER_SIGNATURES = new LinkedHashMap<>();
    static {
        SERVER_SIGNATURES.put("openssh", "OpenSSH");
        SERVER_SIGNATURES.put("dropbear", "Dropbear");
        SERVER_SIGNATURES.put("libssh", "libssh");
        SERVER_SIGNATURES.put("paramiko", "Paramiko");
        SERVER_SIGNATURES.put("cisco", "Cisco");
        SERVER_SIGNATURES.put("routeros", "MikroTik RouterOS");
        SERVER_SIGNATURES.put("fortigate", "FortiGate");
        SERVER_SIGNATURES.put("tectia", "Tectia SSH");
        SERVER_SIGNATURES.put("bitvise", "Bitvise SSH");
        SERVER_SIGNATURES.put("freesshd", "freeSSHd");
        SERVER_SIGNATURES.put("winsshd", "WinSSHD");
        SERVER_SIGNATURES.put("lshd", "lshd");
        SERVER_SIGNATURES.put("sshlib", "sshlib");
        SERVER_SIGNATURES.put("asyncssh", "AsyncSSH");
        SERVER_SIGNATURES.put("ssh2", "SSH Communications Security");
    }

    // Key exchange algorithms
    public static final String[] SECURE_KEX_ALGORITHMS = {
            "curve25519-sha256",
            "curve25519-sha256@libssh.org",
            "ecdh-sha2-nistp521",
            "ecdh-sha2-nistp384",
            "ecdh-sha2-nistp256",
            "diffie-hellman-group18-sha512",
            "diffie-hellman-group16-sha512",
            "diffie-hellman-group14-sha256"
    };

    public static final String[] WEAK_KEX_ALGORITHMS = {
            "diffie-hellman-group1-sha1",
            "diffie-hellman-group14-sha1",
            "diffie-hellman-group-exchange-sha1"
    };

    // Encryption algorithms
    public static final String[] SECURE_CIPHERS = {
            "chacha20-poly1305@openssh.com",
            "aes256-gcm@openssh.com",
            "aes128-gcm@openssh.com",
            "aes256-ctr",
            "aes192-ctr",
            "aes128-ctr"
    };

    public static final String[] WEAK_CIPHERS = {
            "3des-cbc",
            "aes256-cbc",
            "aes192-cbc",
            "aes128-cbc",
            "blowfish-cbc",
            "cast128-cbc",
            "arcfour",
            "arcfour128",
            "arcfour256"
    };

    // MAC algorithms
    public static final String[] SECURE_MACS = {
            "hmac-sha2-512-etm@openssh.com",
            "hmac-sha2-256-etm@openssh.com",
            "umac-128-etm@openssh.com",
            "hmac-sha2-512",
            "hmac-sha2-256"
    };

    public static final String[] WEAK_MACS = {
            "hmac-sha1",
            "hmac-sha1-96",
            "hmac-md5",
            "hmac-md5-96",
            "umac-64@openssh.com"
    };

    private SshHelper() {
        // Private constructor to prevent instantiation
    }

    /**
     * Represents an SSH server banner.
     */
    public static class SshBanner {
        private final String raw;
        private final String protocolVersion;
        private final String softwareVersion;
        private final String comments;
        private final String serverType;
        private final String serverVersion;

        public SshBanner(@NonNull String raw, @Nullable String protocolVersion,
                        @Nullable String softwareVersion, @Nullable String comments,
                        @Nullable String serverType, @Nullable String serverVersion) {
            this.raw = raw;
            this.protocolVersion = protocolVersion;
            this.softwareVersion = softwareVersion;
            this.comments = comments;
            this.serverType = serverType;
            this.serverVersion = serverVersion;
        }

        @NonNull
        public String getRaw() {
            return raw;
        }

        @Nullable
        public String getProtocolVersion() {
            return protocolVersion;
        }

        @Nullable
        public String getSoftwareVersion() {
            return softwareVersion;
        }

        @Nullable
        public String getComments() {
            return comments;
        }

        @Nullable
        public String getServerType() {
            return serverType;
        }

        @Nullable
        public String getServerVersion() {
            return serverVersion;
        }

        public boolean supportsSSHv1() {
            return SSH_VERSION_1.equals(protocolVersion) || 
                   SSH_VERSION_1_5.equals(protocolVersion) ||
                   SSH_VERSION_1_99.equals(protocolVersion);
        }

        public boolean supportsSSHv2() {
            return SSH_VERSION_2.equals(protocolVersion) || 
                   SSH_VERSION_1_99.equals(protocolVersion);
        }

        @Override
        public String toString() {
            return raw;
        }
    }

    /**
     * Represents SSH server information.
     */
    public static class SshServerInfo {
        private final SshBanner banner;
        private final List<String> kexAlgorithms;
        private final List<String> serverHostKeyAlgorithms;
        private final List<String> encryptionAlgorithmsClientToServer;
        private final List<String> encryptionAlgorithmsServerToClient;
        private final List<String> macAlgorithmsClientToServer;
        private final List<String> macAlgorithmsServerToClient;
        private final List<String> compressionAlgorithmsClientToServer;
        private final List<String> compressionAlgorithmsServerToClient;
        private final Map<String, String> additionalInfo;

        private SshServerInfo(Builder builder) {
            this.banner = builder.banner;
            this.kexAlgorithms = new ArrayList<>(builder.kexAlgorithms);
            this.serverHostKeyAlgorithms = new ArrayList<>(builder.serverHostKeyAlgorithms);
            this.encryptionAlgorithmsClientToServer = new ArrayList<>(builder.encryptionAlgorithmsClientToServer);
            this.encryptionAlgorithmsServerToClient = new ArrayList<>(builder.encryptionAlgorithmsServerToClient);
            this.macAlgorithmsClientToServer = new ArrayList<>(builder.macAlgorithmsClientToServer);
            this.macAlgorithmsServerToClient = new ArrayList<>(builder.macAlgorithmsServerToClient);
            this.compressionAlgorithmsClientToServer = new ArrayList<>(builder.compressionAlgorithmsClientToServer);
            this.compressionAlgorithmsServerToClient = new ArrayList<>(builder.compressionAlgorithmsServerToClient);
            this.additionalInfo = new HashMap<>(builder.additionalInfo);
        }

        @Nullable
        public SshBanner getBanner() {
            return banner;
        }

        @NonNull
        public List<String> getKexAlgorithms() {
            return Collections.unmodifiableList(kexAlgorithms);
        }

        @NonNull
        public List<String> getServerHostKeyAlgorithms() {
            return Collections.unmodifiableList(serverHostKeyAlgorithms);
        }

        @NonNull
        public List<String> getEncryptionAlgorithmsClientToServer() {
            return Collections.unmodifiableList(encryptionAlgorithmsClientToServer);
        }

        @NonNull
        public List<String> getEncryptionAlgorithmsServerToClient() {
            return Collections.unmodifiableList(encryptionAlgorithmsServerToClient);
        }

        @NonNull
        public List<String> getMacAlgorithmsClientToServer() {
            return Collections.unmodifiableList(macAlgorithmsClientToServer);
        }

        @NonNull
        public List<String> getMacAlgorithmsServerToClient() {
            return Collections.unmodifiableList(macAlgorithmsServerToClient);
        }

        @NonNull
        public List<String> getCompressionAlgorithmsClientToServer() {
            return Collections.unmodifiableList(compressionAlgorithmsClientToServer);
        }

        @NonNull
        public List<String> getCompressionAlgorithmsServerToClient() {
            return Collections.unmodifiableList(compressionAlgorithmsServerToClient);
        }

        @NonNull
        public Map<String, String> getAdditionalInfo() {
            return Collections.unmodifiableMap(additionalInfo);
        }

        public static class Builder {
            private SshBanner banner;
            private List<String> kexAlgorithms = new ArrayList<>();
            private List<String> serverHostKeyAlgorithms = new ArrayList<>();
            private List<String> encryptionAlgorithmsClientToServer = new ArrayList<>();
            private List<String> encryptionAlgorithmsServerToClient = new ArrayList<>();
            private List<String> macAlgorithmsClientToServer = new ArrayList<>();
            private List<String> macAlgorithmsServerToClient = new ArrayList<>();
            private List<String> compressionAlgorithmsClientToServer = new ArrayList<>();
            private List<String> compressionAlgorithmsServerToClient = new ArrayList<>();
            private Map<String, String> additionalInfo = new HashMap<>();

            public Builder setBanner(SshBanner banner) {
                this.banner = banner;
                return this;
            }

            public Builder setKexAlgorithms(List<String> algorithms) {
                this.kexAlgorithms = new ArrayList<>(algorithms);
                return this;
            }

            public Builder setServerHostKeyAlgorithms(List<String> algorithms) {
                this.serverHostKeyAlgorithms = new ArrayList<>(algorithms);
                return this;
            }

            public Builder setEncryptionAlgorithmsClientToServer(List<String> algorithms) {
                this.encryptionAlgorithmsClientToServer = new ArrayList<>(algorithms);
                return this;
            }

            public Builder setEncryptionAlgorithmsServerToClient(List<String> algorithms) {
                this.encryptionAlgorithmsServerToClient = new ArrayList<>(algorithms);
                return this;
            }

            public Builder setMacAlgorithmsClientToServer(List<String> algorithms) {
                this.macAlgorithmsClientToServer = new ArrayList<>(algorithms);
                return this;
            }

            public Builder setMacAlgorithmsServerToClient(List<String> algorithms) {
                this.macAlgorithmsServerToClient = new ArrayList<>(algorithms);
                return this;
            }

            public Builder setCompressionAlgorithmsClientToServer(List<String> algorithms) {
                this.compressionAlgorithmsClientToServer = new ArrayList<>(algorithms);
                return this;
            }

            public Builder setCompressionAlgorithmsServerToClient(List<String> algorithms) {
                this.compressionAlgorithmsServerToClient = new ArrayList<>(algorithms);
                return this;
            }

            public Builder addInfo(String key, String value) {
                this.additionalInfo.put(key, value);
                return this;
            }

            public SshServerInfo build() {
                return new SshServerInfo(this);
            }
        }
    }

    /**
     * Parses an SSH banner string.
     */
    @Nullable
    public static SshBanner parseBanner(@NonNull String bannerStr) {
        bannerStr = bannerStr.trim();
        
        Matcher matcher = BANNER_PATTERN.matcher(bannerStr);
        if (matcher.matches()) {
            String protocolVersion = matcher.group(1);
            String softwareVersion = matcher.group(2);
            String comments = matcher.group(3);
            
            String serverType = identifyServer(softwareVersion);
            String serverVersion = extractVersion(softwareVersion);
            
            return new SshBanner(bannerStr, protocolVersion, softwareVersion, 
                                comments, serverType, serverVersion);
        }
        
        return null;
    }

    /**
     * Identifies the SSH server type from software version string.
     */
    @Nullable
    public static String identifyServer(@NonNull String softwareVersion) {
        String lowerSoftware = softwareVersion.toLowerCase(Locale.US);
        
        for (Map.Entry<String, String> entry : SERVER_SIGNATURES.entrySet()) {
            if (lowerSoftware.contains(entry.getKey())) {
                return entry.getValue();
            }
        }
        
        return null;
    }

    /**
     * Extracts version number from software version string.
     */
    @Nullable
    public static String extractVersion(@NonNull String softwareVersion) {
        // Try Dropbear pattern first
        Matcher dropbearMatcher = DROPBEAR_PATTERN.matcher(softwareVersion);
        if (dropbearMatcher.find() && dropbearMatcher.group(1) != null) {
            return dropbearMatcher.group(1);
        }
        
        // Try generic version pattern
        Matcher matcher = VERSION_PATTERN.matcher(softwareVersion);
        if (matcher.find() && matcher.group(2) != null) {
            return matcher.group(2);
        }
        
        return null;
    }

    /**
     * Grabs the SSH banner from a host.
     */
    @Nullable
    public static SshBanner grabBanner(@NonNull String host) throws IOException {
        return grabBanner(host, DEFAULT_SSH_PORT, DEFAULT_TIMEOUT_MS);
    }

    /**
     * Grabs the SSH banner from a host with custom port.
     */
    @Nullable
    public static SshBanner grabBanner(@NonNull String host, int port) throws IOException {
        return grabBanner(host, port, DEFAULT_TIMEOUT_MS);
    }

    /**
     * Grabs the SSH banner from a host with custom port and timeout.
     */
    @Nullable
    public static SshBanner grabBanner(@NonNull String host, int port, int timeout) 
            throws IOException {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(host, port), timeout);
            socket.setSoTimeout(timeout);

            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(socket.getInputStream()));
            
            String banner = reader.readLine();
            if (banner != null) {
                return parseBanner(banner);
            }
        }
        
        return null;
    }

    /**
     * Fingerprints an SSH server.
     */
    @NonNull
    public static SshServerInfo fingerprintServer(@NonNull String host) throws IOException {
        return fingerprintServer(host, DEFAULT_SSH_PORT, DEFAULT_TIMEOUT_MS);
    }

    /**
     * Fingerprints an SSH server with custom settings.
     */
    @NonNull
    public static SshServerInfo fingerprintServer(@NonNull String host, int port, int timeout) 
            throws IOException {
        SshServerInfo.Builder builder = new SshServerInfo.Builder();
        
        // Get banner
        SshBanner banner = grabBanner(host, port, timeout);
        if (banner != null) {
            builder.setBanner(banner);
        }
        
        // Note: Full key exchange parsing requires sending a proper KEXINIT packet
        // which is complex for a helper. Basic banner info is sufficient for most use cases.
        
        return builder.build();
    }

    /**
     * Checks for weak algorithms in a list.
     */
    @NonNull
    public static List<String> findWeakKexAlgorithms(@NonNull List<String> algorithms) {
        List<String> weak = new ArrayList<>();
        for (String algo : algorithms) {
            for (String weakAlgo : WEAK_KEX_ALGORITHMS) {
                if (algo.equalsIgnoreCase(weakAlgo)) {
                    weak.add(algo);
                    break;
                }
            }
        }
        return weak;
    }

    /**
     * Checks for weak ciphers.
     */
    @NonNull
    public static List<String> findWeakCiphers(@NonNull List<String> ciphers) {
        List<String> weak = new ArrayList<>();
        for (String cipher : ciphers) {
            for (String weakCipher : WEAK_CIPHERS) {
                if (cipher.equalsIgnoreCase(weakCipher)) {
                    weak.add(cipher);
                    break;
                }
            }
        }
        return weak;
    }

    /**
     * Checks for weak MAC algorithms.
     */
    @NonNull
    public static List<String> findWeakMacs(@NonNull List<String> macs) {
        List<String> weak = new ArrayList<>();
        for (String mac : macs) {
            for (String weakMac : WEAK_MACS) {
                if (mac.equalsIgnoreCase(weakMac)) {
                    weak.add(mac);
                    break;
                }
            }
        }
        return weak;
    }

    /**
     * Checks for vulnerabilities based on server info.
     */
    @NonNull
    public static List<String> checkVulnerabilities(@NonNull SshServerInfo serverInfo) {
        List<String> vulnerabilities = new ArrayList<>();
        
        SshBanner banner = serverInfo.getBanner();
        if (banner != null) {
            // Check protocol version
            if (banner.supportsSSHv1()) {
                vulnerabilities.add("SSH Protocol 1 supported - vulnerable to attacks");
            }
            
            // Check for known vulnerable versions
            String serverType = banner.getServerType();
            String version = banner.getServerVersion();
            
            if (serverType != null && version != null) {
                // OpenSSH vulnerabilities
                if ("OpenSSH".equals(serverType)) {
                    if (compareVersions(version, "7.2") < 0) {
                        vulnerabilities.add("OpenSSH < 7.2 may be vulnerable to user enumeration (CVE-2016-6210)");
                    }
                    if (compareVersions(version, "7.4") < 0) {
                        vulnerabilities.add("OpenSSH < 7.4 may be vulnerable to agent forwarding attack");
                    }
                    if (compareVersions(version, "8.4") < 0) {
                        vulnerabilities.add("OpenSSH < 8.4 may be vulnerable to certain attacks");
                    }
                }
                
                // Dropbear vulnerabilities
                if ("Dropbear".equals(serverType)) {
                    if (compareVersions(version, "2018.76") < 0) {
                        vulnerabilities.add("Dropbear < 2018.76 has known vulnerabilities");
                    }
                }
            }
        }
        
        // Check algorithms
        List<String> weakKex = findWeakKexAlgorithms(serverInfo.getKexAlgorithms());
        if (!weakKex.isEmpty()) {
            vulnerabilities.add("Weak key exchange algorithms: " + String.join(", ", weakKex));
        }
        
        List<String> weakCiphers = findWeakCiphers(serverInfo.getEncryptionAlgorithmsClientToServer());
        if (!weakCiphers.isEmpty()) {
            vulnerabilities.add("Weak ciphers: " + String.join(", ", weakCiphers));
        }
        
        List<String> weakMacs = findWeakMacs(serverInfo.getMacAlgorithmsClientToServer());
        if (!weakMacs.isEmpty()) {
            vulnerabilities.add("Weak MAC algorithms: " + String.join(", ", weakMacs));
        }
        
        return vulnerabilities;
    }

    /**
     * Compares two version strings.
     */
    private static int compareVersions(@NonNull String v1, @NonNull String v2) {
        String[] parts1 = v1.replaceAll("[^0-9.]", ".").split("\\.");
        String[] parts2 = v2.replaceAll("[^0-9.]", ".").split("\\.");
        
        int length = Math.max(parts1.length, parts2.length);
        for (int i = 0; i < length; i++) {
            int num1 = i < parts1.length && !parts1[i].isEmpty() ? 
                    Integer.parseInt(parts1[i]) : 0;
            int num2 = i < parts2.length && !parts2[i].isEmpty() ? 
                    Integer.parseInt(parts2[i]) : 0;
            
            if (num1 != num2) {
                return Integer.compare(num1, num2);
            }
        }
        return 0;
    }

    /**
     * Generates a summary report for SSH server.
     */
    @NonNull
    public static String generateReport(@NonNull SshServerInfo serverInfo) {
        StringBuilder report = new StringBuilder();
        
        report.append("SSH Server Analysis Report\n");
        report.append("==========================\n\n");
        
        SshBanner banner = serverInfo.getBanner();
        if (banner != null) {
            report.append("Banner: ").append(banner.getRaw()).append("\n");
            
            if (banner.getServerType() != null) {
                report.append("Server Type: ").append(banner.getServerType()).append("\n");
            }
            
            if (banner.getServerVersion() != null) {
                report.append("Version: ").append(banner.getServerVersion()).append("\n");
            }
            
            report.append("Protocol Version: SSH-").append(banner.getProtocolVersion()).append("\n");
            report.append("SSH v1 Support: ").append(banner.supportsSSHv1() ? "Yes (INSECURE)" : "No").append("\n");
            report.append("SSH v2 Support: ").append(banner.supportsSSHv2() ? "Yes" : "No").append("\n");
        }
        
        List<String> kex = serverInfo.getKexAlgorithms();
        if (!kex.isEmpty()) {
            report.append("\nKey Exchange Algorithms:\n");
            for (String algo : kex) {
                String marker = isWeakKex(algo) ? " [WEAK]" : "";
                report.append("  • ").append(algo).append(marker).append("\n");
            }
        }
        
        List<String> hostKeys = serverInfo.getServerHostKeyAlgorithms();
        if (!hostKeys.isEmpty()) {
            report.append("\nHost Key Algorithms:\n");
            for (String algo : hostKeys) {
                report.append("  • ").append(algo).append("\n");
            }
        }
        
        List<String> ciphers = serverInfo.getEncryptionAlgorithmsClientToServer();
        if (!ciphers.isEmpty()) {
            report.append("\nEncryption Algorithms:\n");
            for (String cipher : ciphers) {
                String marker = isWeakCipher(cipher) ? " [WEAK]" : "";
                report.append("  • ").append(cipher).append(marker).append("\n");
            }
        }
        
        List<String> macs = serverInfo.getMacAlgorithmsClientToServer();
        if (!macs.isEmpty()) {
            report.append("\nMAC Algorithms:\n");
            for (String mac : macs) {
                String marker = isWeakMac(mac) ? " [WEAK]" : "";
                report.append("  • ").append(mac).append(marker).append("\n");
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
     * Checks if a KEX algorithm is weak.
     */
    private static boolean isWeakKex(@NonNull String algo) {
        for (String weak : WEAK_KEX_ALGORITHMS) {
            if (algo.equalsIgnoreCase(weak)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Checks if a cipher is weak.
     */
    private static boolean isWeakCipher(@NonNull String cipher) {
        for (String weak : WEAK_CIPHERS) {
            if (cipher.equalsIgnoreCase(weak)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Checks if a MAC algorithm is weak.
     */
    private static boolean isWeakMac(@NonNull String mac) {
        for (String weak : WEAK_MACS) {
            if (mac.equalsIgnoreCase(weak)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Tests if a host has an SSH server.
     */
    public static boolean isPortOpen(@NonNull String host, int port) {
        return isPortOpen(host, port, DEFAULT_TIMEOUT_MS);
    }

    /**
     * Tests if a host has an SSH server with custom timeout.
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
     * Calculates SSH host key fingerprint.
     */
    @NonNull
    public static String calculateFingerprint(@NonNull byte[] publicKey, @NonNull String algorithm) 
            throws NoSuchAlgorithmException {
        MessageDigest digest;
        if ("MD5".equalsIgnoreCase(algorithm)) {
            digest = MessageDigest.getInstance("MD5");
        } else {
            digest = MessageDigest.getInstance("SHA-256");
        }
        
        byte[] hash = digest.digest(publicKey);
        StringBuilder sb = new StringBuilder();
        
        if ("MD5".equalsIgnoreCase(algorithm)) {
            for (int i = 0; i < hash.length; i++) {
                if (i > 0) sb.append(':');
                sb.append(String.format(Locale.US, "%02x", hash[i]));
            }
        } else {
            sb.append("SHA256:");
            sb.append(android.util.Base64.encodeToString(hash, 
                    android.util.Base64.NO_WRAP | android.util.Base64.NO_PADDING));
        }
        
        return sb.toString();
    }

    /**
     * Gets recommended hardening settings.
     */
    @NonNull
    public static List<String> getHardeningRecommendations(@NonNull SshServerInfo serverInfo) {
        List<String> recommendations = new ArrayList<>();
        
        SshBanner banner = serverInfo.getBanner();
        if (banner != null && banner.supportsSSHv1()) {
            recommendations.add("Disable SSH Protocol 1 support");
        }
        
        List<String> weakKex = findWeakKexAlgorithms(serverInfo.getKexAlgorithms());
        if (!weakKex.isEmpty()) {
            recommendations.add("Disable weak key exchange: " + String.join(", ", weakKex));
        }
        
        List<String> weakCiphers = findWeakCiphers(serverInfo.getEncryptionAlgorithmsClientToServer());
        if (!weakCiphers.isEmpty()) {
            recommendations.add("Disable weak ciphers: " + String.join(", ", weakCiphers));
        }
        
        List<String> weakMacs = findWeakMacs(serverInfo.getMacAlgorithmsClientToServer());
        if (!weakMacs.isEmpty()) {
            recommendations.add("Disable weak MAC algorithms: " + String.join(", ", weakMacs));
        }
        
        // General recommendations
        recommendations.add("Use key-based authentication instead of passwords");
        recommendations.add("Disable root login or use key-only root login");
        recommendations.add("Use fail2ban or similar to prevent brute force attacks");
        recommendations.add("Change default SSH port if possible");
        recommendations.add("Keep SSH server software up to date");
        
        return recommendations;
    }
}
