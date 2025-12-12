/*
 * This file is part of the cSploit.
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

import java.io.IOException;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketTimeoutException;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * Port knocking utility for security testing.
 *
 * Port knocking is a method of externally opening ports on a firewall by
 * generating a sequence of connection attempts on a set of pre-specified
 * closed ports.
 *
 * Provides:
 * - TCP port knocking
 * - UDP port knocking
 * - Mixed protocol sequences
 * - Configurable timing
 * - Sequence verification
 */
public final class PortKnocker {

    private static final String TAG = "PortKnocker";

    // Protocol types for knocking
    public enum Protocol {
        TCP,
        UDP
    }

    // Knock sequence element
    public static class Knock {
        public final int port;
        public final Protocol protocol;
        public final int delayMs;

        public Knock(int port, Protocol protocol, int delayMs) {
            this.port = port;
            this.protocol = protocol;
            this.delayMs = delayMs;
        }

        public Knock(int port, Protocol protocol) {
            this(port, protocol, 100);
        }

        public Knock(int port) {
            this(port, Protocol.TCP, 100);
        }

        @Override
        public String toString() {
            return String.format(Locale.US, "%s:%d", protocol.name(), port);
        }
    }

    // Result of a knock operation
    public static class KnockResult {
        public final boolean success;
        public final String host;
        public final List<Knock> sequence;
        public final long totalDurationMs;
        public final String message;
        public final List<String> errors;

        private KnockResult(boolean success, String host, List<Knock> sequence,
                           long durationMs, String message, List<String> errors) {
            this.success = success;
            this.host = host;
            this.sequence = sequence;
            this.totalDurationMs = durationMs;
            this.message = message;
            this.errors = errors;
        }

        public static KnockResult success(String host, List<Knock> sequence, long durationMs) {
            return new KnockResult(true, host, sequence, durationMs,
                "Knock sequence completed successfully", new ArrayList<>());
        }

        public static KnockResult failure(String host, List<Knock> sequence,
                                         long durationMs, List<String> errors) {
            return new KnockResult(false, host, sequence, durationMs,
                "Knock sequence had errors", errors);
        }

        public String getSummary() {
            StringBuilder sb = new StringBuilder();
            sb.append("Host: ").append(host).append("\n");
            sb.append("Sequence: ");
            for (int i = 0; i < sequence.size(); i++) {
                if (i > 0) sb.append(" -> ");
                sb.append(sequence.get(i).toString());
            }
            sb.append("\n");
            sb.append("Duration: ").append(totalDurationMs).append("ms\n");
            sb.append("Result: ").append(message);
            return sb.toString();
        }
    }

    private static final int DEFAULT_TIMEOUT_MS = 500;
    private static final int DEFAULT_DELAY_MS = 100;

    private PortKnocker() {}

    // ==================== Basic Knocking ====================

    /**
     * Perform TCP knock on a single port
     *
     * @param host target host
     * @param port target port
     * @param timeoutMs connection timeout
     * @return true if knock was sent (doesn't mean port is open)
     */
    public static boolean knockTcp(String host, int port, int timeoutMs) {
        Socket socket = null;
        try {
            socket = new Socket();
            socket.connect(new InetSocketAddress(host, port), timeoutMs);
            return true;
        } catch (SocketTimeoutException e) {
            // Timeout is expected for closed ports - knock was still sent
            return true;
        } catch (IOException e) {
            // Connection refused is expected for closed ports - knock was still sent
            return e.getMessage() != null &&
                   e.getMessage().toLowerCase().contains("refused");
        } finally {
            CloseableHelper.close(socket);
        }
    }

    /**
     * Perform UDP knock on a single port
     *
     * @param host target host
     * @param port target port
     * @return true if knock was sent
     */
    public static boolean knockUdp(String host, int port) {
        DatagramSocket socket = null;
        try {
            InetAddress address = InetAddress.getByName(host);
            socket = new DatagramSocket();

            // Send empty UDP packet
            byte[] data = new byte[1];
            DatagramPacket packet = new DatagramPacket(data, data.length, address, port);
            socket.send(packet);
            return true;
        } catch (IOException e) {
            LoggingHelper.d(TAG, "UDP knock failed: " + e.getMessage());
            return false;
        } finally {
            if (socket != null) {
                socket.close();
            }
        }
    }

    /**
     * Perform a single knock
     *
     * @param host target host
     * @param knock knock specification
     * @return true if knock was sent
     */
    public static boolean knock(String host, Knock knock) {
        if (knock.protocol == Protocol.TCP) {
            return knockTcp(host, knock.port, DEFAULT_TIMEOUT_MS);
        } else {
            return knockUdp(host, knock.port);
        }
    }

    // ==================== Sequence Knocking ====================

    /**
     * Execute a knock sequence
     *
     * @param host target host
     * @param sequence list of knocks to perform
     * @return KnockResult with details
     */
    public static KnockResult knockSequence(String host, List<Knock> sequence) {
        if (sequence == null || sequence.isEmpty()) {
            return KnockResult.failure(host, sequence, 0,
                List.of("Empty knock sequence"));
        }

        List<String> errors = new ArrayList<>();
        long startTime = System.currentTimeMillis();

        for (int i = 0; i < sequence.size(); i++) {
            Knock k = sequence.get(i);

            boolean sent = knock(host, k);
            if (!sent) {
                errors.add(String.format(Locale.US,
                    "Failed to send knock %d (%s:%d)", i + 1, k.protocol, k.port));
            }

            // Delay before next knock (except for last one)
            if (i < sequence.size() - 1 && k.delayMs > 0) {
                try {
                    Thread.sleep(k.delayMs);
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    errors.add("Sequence interrupted");
                    break;
                }
            }
        }

        long duration = System.currentTimeMillis() - startTime;

        if (errors.isEmpty()) {
            return KnockResult.success(host, sequence, duration);
        } else {
            return KnockResult.failure(host, sequence, duration, errors);
        }
    }

    /**
     * Execute a TCP-only knock sequence on given ports
     *
     * @param host target host
     * @param ports array of ports to knock
     * @return KnockResult with details
     */
    public static KnockResult knockTcpSequence(String host, int[] ports) {
        return knockTcpSequence(host, ports, DEFAULT_DELAY_MS);
    }

    /**
     * Execute a TCP-only knock sequence with custom delay
     *
     * @param host target host
     * @param ports array of ports to knock
     * @param delayMs delay between knocks
     * @return KnockResult with details
     */
    public static KnockResult knockTcpSequence(String host, int[] ports, int delayMs) {
        List<Knock> sequence = new ArrayList<>();
        for (int port : ports) {
            sequence.add(new Knock(port, Protocol.TCP, delayMs));
        }
        return knockSequence(host, sequence);
    }

    /**
     * Execute a UDP-only knock sequence on given ports
     *
     * @param host target host
     * @param ports array of ports to knock
     * @return KnockResult with details
     */
    public static KnockResult knockUdpSequence(String host, int[] ports) {
        return knockUdpSequence(host, ports, DEFAULT_DELAY_MS);
    }

    /**
     * Execute a UDP-only knock sequence with custom delay
     *
     * @param host target host
     * @param ports array of ports to knock
     * @param delayMs delay between knocks
     * @return KnockResult with details
     */
    public static KnockResult knockUdpSequence(String host, int[] ports, int delayMs) {
        List<Knock> sequence = new ArrayList<>();
        for (int port : ports) {
            sequence.add(new Knock(port, Protocol.UDP, delayMs));
        }
        return knockSequence(host, sequence);
    }

    // ==================== Sequence Builder ====================

    /**
     * Builder for creating knock sequences
     */
    public static class SequenceBuilder {
        private final List<Knock> sequence = new ArrayList<>();
        private int defaultDelay = DEFAULT_DELAY_MS;

        public SequenceBuilder() {}

        /**
         * Set default delay between knocks
         */
        public SequenceBuilder setDefaultDelay(int delayMs) {
            this.defaultDelay = delayMs;
            return this;
        }

        /**
         * Add a TCP knock
         */
        public SequenceBuilder addTcp(int port) {
            sequence.add(new Knock(port, Protocol.TCP, defaultDelay));
            return this;
        }

        /**
         * Add a TCP knock with custom delay
         */
        public SequenceBuilder addTcp(int port, int delayMs) {
            sequence.add(new Knock(port, Protocol.TCP, delayMs));
            return this;
        }

        /**
         * Add a UDP knock
         */
        public SequenceBuilder addUdp(int port) {
            sequence.add(new Knock(port, Protocol.UDP, defaultDelay));
            return this;
        }

        /**
         * Add a UDP knock with custom delay
         */
        public SequenceBuilder addUdp(int port, int delayMs) {
            sequence.add(new Knock(port, Protocol.UDP, delayMs));
            return this;
        }

        /**
         * Add multiple TCP knocks
         */
        public SequenceBuilder addTcpPorts(int... ports) {
            for (int port : ports) {
                addTcp(port);
            }
            return this;
        }

        /**
         * Add multiple UDP knocks
         */
        public SequenceBuilder addUdpPorts(int... ports) {
            for (int port : ports) {
                addUdp(port);
            }
            return this;
        }

        /**
         * Build and return the sequence
         */
        public List<Knock> build() {
            return new ArrayList<>(sequence);
        }

        /**
         * Execute the built sequence
         */
        public KnockResult execute(String host) {
            return knockSequence(host, build());
        }
    }

    /**
     * Create a new sequence builder
     */
    public static SequenceBuilder builder() {
        return new SequenceBuilder();
    }

    // ==================== Verification ====================

    /**
     * Check if a port opened after knocking
     *
     * @param host target host
     * @param port port to check
     * @param timeoutMs connection timeout
     * @return true if port is now open
     */
    public static boolean verifyPortOpen(String host, int port, int timeoutMs) {
        Socket socket = null;
        try {
            socket = new Socket();
            socket.connect(new InetSocketAddress(host, port), timeoutMs);
            return true;
        } catch (IOException e) {
            return false;
        } finally {
            CloseableHelper.close(socket);
        }
    }

    /**
     * Knock and verify a port opened
     *
     * @param host target host
     * @param sequence knock sequence
     * @param targetPort port expected to open
     * @param verifyTimeoutMs timeout for verification
     * @return true if port opened after knocking
     */
    public static boolean knockAndVerify(String host, List<Knock> sequence,
                                         int targetPort, int verifyTimeoutMs) {
        KnockResult result = knockSequence(host, sequence);
        if (!result.success) {
            return false;
        }

        // Small delay before verification
        try {
            Thread.sleep(500);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }

        return verifyPortOpen(host, targetPort, verifyTimeoutMs);
    }

    /**
     * Knock and verify with TCP sequence
     *
     * @param host target host
     * @param knockPorts ports to knock
     * @param targetPort port expected to open
     * @return true if port opened after knocking
     */
    public static boolean knockAndVerify(String host, int[] knockPorts, int targetPort) {
        return knockAndVerify(host,
            builder().addTcpPorts(knockPorts).build(),
            targetPort,
            5000);
    }

    // ==================== Common Sequences ====================

    /**
     * Try common knock sequence patterns
     *
     * @param host target host
     * @param targetPort port expected to open
     * @return sequence that worked, or null if none worked
     */
    public static List<Knock> tryCommonSequences(String host, int targetPort) {
        int[][] commonPatterns = {
            {7000, 8000, 9000},
            {1234, 2345, 3456},
            {100, 200, 300},
            {7, 8, 9},
            {123, 456, 789}
        };

        for (int[] pattern : commonPatterns) {
            List<Knock> sequence = builder().addTcpPorts(pattern).build();
            if (knockAndVerify(host, sequence, targetPort, 3000)) {
                LoggingHelper.debug("Found working sequence: " + sequence);
                return sequence;
            }
        }

        return null;
    }

    // ==================== Utility Methods ====================

    /**
     * Parse a knock sequence from string format
     * Format: "TCP:1234,UDP:5678,TCP:9012" or "1234,5678,9012" (defaults to TCP)
     *
     * @param sequenceStr sequence string
     * @return list of knocks
     */
    public static List<Knock> parseSequence(String sequenceStr) {
        List<Knock> sequence = new ArrayList<>();

        if (sequenceStr == null || sequenceStr.trim().isEmpty()) {
            return sequence;
        }

        String[] parts = sequenceStr.split(",");
        for (String part : parts) {
            part = part.trim().toUpperCase();

            Protocol protocol = Protocol.TCP;
            int port;

            if (part.contains(":")) {
                String[] subParts = part.split(":");
                if (subParts[0].equals("UDP")) {
                    protocol = Protocol.UDP;
                }
                port = Integer.parseInt(subParts[1].trim());
            } else {
                port = Integer.parseInt(part);
            }

            if (NetworkHelper.isValidPort(port)) {
                sequence.add(new Knock(port, protocol));
            }
        }

        return sequence;
    }

    /**
     * Format a knock sequence to string
     *
     * @param sequence knock sequence
     * @return formatted string
     */
    public static String formatSequence(List<Knock> sequence) {
        if (sequence == null || sequence.isEmpty()) {
            return "";
        }

        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < sequence.size(); i++) {
            if (i > 0) sb.append(",");
            Knock k = sequence.get(i);
            sb.append(k.protocol.name()).append(":").append(k.port);
        }
        return sb.toString();
    }
}
