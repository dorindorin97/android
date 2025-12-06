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
import android.text.TextUtils;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Helper class for TCP/IP packet analysis and construction.
 * Provides utilities for parsing and building network packets,
 * calculating checksums, and protocol analysis.
 */
public final class PacketHelper {

    private static final String TAG = "PacketHelper";

    // Ethernet frame constants
    public static final int ETHERNET_HEADER_SIZE = 14;
    public static final int ETHERNET_TYPE_IPV4 = 0x0800;
    public static final int ETHERNET_TYPE_IPV6 = 0x86DD;
    public static final int ETHERNET_TYPE_ARP = 0x0806;
    public static final int ETHERNET_TYPE_VLAN = 0x8100;

    // IP protocol numbers
    public static final int IP_PROTOCOL_ICMP = 1;
    public static final int IP_PROTOCOL_TCP = 6;
    public static final int IP_PROTOCOL_UDP = 17;
    public static final int IP_PROTOCOL_GRE = 47;
    public static final int IP_PROTOCOL_ICMPV6 = 58;

    // IP header constants
    public static final int IP_HEADER_MIN_SIZE = 20;
    public static final int IP_VERSION_4 = 4;
    public static final int IP_VERSION_6 = 6;

    // TCP header constants
    public static final int TCP_HEADER_MIN_SIZE = 20;
    public static final int TCP_FLAG_FIN = 0x01;
    public static final int TCP_FLAG_SYN = 0x02;
    public static final int TCP_FLAG_RST = 0x04;
    public static final int TCP_FLAG_PSH = 0x08;
    public static final int TCP_FLAG_ACK = 0x10;
    public static final int TCP_FLAG_URG = 0x20;
    public static final int TCP_FLAG_ECE = 0x40;
    public static final int TCP_FLAG_CWR = 0x80;

    // UDP header constants
    public static final int UDP_HEADER_SIZE = 8;

    // ICMP types
    public static final int ICMP_TYPE_ECHO_REPLY = 0;
    public static final int ICMP_TYPE_DEST_UNREACHABLE = 3;
    public static final int ICMP_TYPE_SOURCE_QUENCH = 4;
    public static final int ICMP_TYPE_REDIRECT = 5;
    public static final int ICMP_TYPE_ECHO_REQUEST = 8;
    public static final int ICMP_TYPE_TIME_EXCEEDED = 11;
    public static final int ICMP_TYPE_TIMESTAMP_REQUEST = 13;
    public static final int ICMP_TYPE_TIMESTAMP_REPLY = 14;

    private PacketHelper() {
        // Private constructor to prevent instantiation
    }

    /**
     * Represents an Ethernet frame header.
     */
    public static class EthernetHeader {
        private final byte[] destMac;
        private final byte[] srcMac;
        private final int etherType;
        private final int vlanId;

        public EthernetHeader(@NonNull byte[] destMac, @NonNull byte[] srcMac, int etherType) {
            this(destMac, srcMac, etherType, -1);
        }

        public EthernetHeader(@NonNull byte[] destMac, @NonNull byte[] srcMac, 
                             int etherType, int vlanId) {
            this.destMac = Arrays.copyOf(destMac, 6);
            this.srcMac = Arrays.copyOf(srcMac, 6);
            this.etherType = etherType;
            this.vlanId = vlanId;
        }

        @NonNull
        public byte[] getDestMac() {
            return Arrays.copyOf(destMac, 6);
        }

        @NonNull
        public byte[] getSrcMac() {
            return Arrays.copyOf(srcMac, 6);
        }

        public int getEtherType() {
            return etherType;
        }

        public int getVlanId() {
            return vlanId;
        }

        public boolean hasVlan() {
            return vlanId >= 0;
        }

        @NonNull
        public String getDestMacString() {
            return formatMac(destMac);
        }

        @NonNull
        public String getSrcMacString() {
            return formatMac(srcMac);
        }

        @NonNull
        public String getEtherTypeString() {
            return getEtherTypeName(etherType);
        }
    }

    /**
     * Represents an IPv4 header.
     */
    public static class IPv4Header {
        private final int version;
        private final int headerLength;
        private final int tos;
        private final int totalLength;
        private final int identification;
        private final int flags;
        private final int fragmentOffset;
        private final int ttl;
        private final int protocol;
        private final int checksum;
        private final byte[] srcAddress;
        private final byte[] destAddress;
        private final byte[] options;

        public IPv4Header(int version, int headerLength, int tos, int totalLength,
                         int identification, int flags, int fragmentOffset, int ttl,
                         int protocol, int checksum, @NonNull byte[] srcAddress, 
                         @NonNull byte[] destAddress, @Nullable byte[] options) {
            this.version = version;
            this.headerLength = headerLength;
            this.tos = tos;
            this.totalLength = totalLength;
            this.identification = identification;
            this.flags = flags;
            this.fragmentOffset = fragmentOffset;
            this.ttl = ttl;
            this.protocol = protocol;
            this.checksum = checksum;
            this.srcAddress = Arrays.copyOf(srcAddress, 4);
            this.destAddress = Arrays.copyOf(destAddress, 4);
            this.options = options != null ? Arrays.copyOf(options, options.length) : null;
        }

        public int getVersion() {
            return version;
        }

        public int getHeaderLength() {
            return headerLength;
        }

        public int getHeaderLengthBytes() {
            return headerLength * 4;
        }

        public int getTos() {
            return tos;
        }

        public int getTotalLength() {
            return totalLength;
        }

        public int getIdentification() {
            return identification;
        }

        public int getFlags() {
            return flags;
        }

        public int getFragmentOffset() {
            return fragmentOffset;
        }

        public int getTtl() {
            return ttl;
        }

        public int getProtocol() {
            return protocol;
        }

        public int getChecksum() {
            return checksum;
        }

        @NonNull
        public byte[] getSrcAddress() {
            return Arrays.copyOf(srcAddress, 4);
        }

        @NonNull
        public byte[] getDestAddress() {
            return Arrays.copyOf(destAddress, 4);
        }

        @Nullable
        public byte[] getOptions() {
            return options != null ? Arrays.copyOf(options, options.length) : null;
        }

        @NonNull
        public String getSrcAddressString() {
            return formatIPv4(srcAddress);
        }

        @NonNull
        public String getDestAddressString() {
            return formatIPv4(destAddress);
        }

        @NonNull
        public String getProtocolName() {
            return PacketHelper.getProtocolName(protocol);
        }

        public boolean isDontFragment() {
            return (flags & 0x02) != 0;
        }

        public boolean isMoreFragments() {
            return (flags & 0x01) != 0;
        }

        public int getPayloadLength() {
            return totalLength - getHeaderLengthBytes();
        }
    }

    /**
     * Represents a TCP header.
     */
    public static class TcpHeader {
        private final int srcPort;
        private final int destPort;
        private final long sequenceNumber;
        private final long acknowledgmentNumber;
        private final int dataOffset;
        private final int flags;
        private final int window;
        private final int checksum;
        private final int urgentPointer;
        private final byte[] options;

        public TcpHeader(int srcPort, int destPort, long sequenceNumber, 
                        long acknowledgmentNumber, int dataOffset, int flags,
                        int window, int checksum, int urgentPointer, 
                        @Nullable byte[] options) {
            this.srcPort = srcPort;
            this.destPort = destPort;
            this.sequenceNumber = sequenceNumber;
            this.acknowledgmentNumber = acknowledgmentNumber;
            this.dataOffset = dataOffset;
            this.flags = flags;
            this.window = window;
            this.checksum = checksum;
            this.urgentPointer = urgentPointer;
            this.options = options != null ? Arrays.copyOf(options, options.length) : null;
        }

        public int getSrcPort() {
            return srcPort;
        }

        public int getDestPort() {
            return destPort;
        }

        public long getSequenceNumber() {
            return sequenceNumber;
        }

        public long getAcknowledgmentNumber() {
            return acknowledgmentNumber;
        }

        public int getDataOffset() {
            return dataOffset;
        }

        public int getHeaderLengthBytes() {
            return dataOffset * 4;
        }

        public int getFlags() {
            return flags;
        }

        public int getWindow() {
            return window;
        }

        public int getChecksum() {
            return checksum;
        }

        public int getUrgentPointer() {
            return urgentPointer;
        }

        @Nullable
        public byte[] getOptions() {
            return options != null ? Arrays.copyOf(options, options.length) : null;
        }

        public boolean isFin() {
            return (flags & TCP_FLAG_FIN) != 0;
        }

        public boolean isSyn() {
            return (flags & TCP_FLAG_SYN) != 0;
        }

        public boolean isRst() {
            return (flags & TCP_FLAG_RST) != 0;
        }

        public boolean isPsh() {
            return (flags & TCP_FLAG_PSH) != 0;
        }

        public boolean isAck() {
            return (flags & TCP_FLAG_ACK) != 0;
        }

        public boolean isUrg() {
            return (flags & TCP_FLAG_URG) != 0;
        }

        @NonNull
        public String getFlagsString() {
            StringBuilder sb = new StringBuilder();
            if (isFin()) sb.append("FIN ");
            if (isSyn()) sb.append("SYN ");
            if (isRst()) sb.append("RST ");
            if (isPsh()) sb.append("PSH ");
            if (isAck()) sb.append("ACK ");
            if (isUrg()) sb.append("URG ");
            return sb.toString().trim();
        }
    }

    /**
     * Represents a UDP header.
     */
    public static class UdpHeader {
        private final int srcPort;
        private final int destPort;
        private final int length;
        private final int checksum;

        public UdpHeader(int srcPort, int destPort, int length, int checksum) {
            this.srcPort = srcPort;
            this.destPort = destPort;
            this.length = length;
            this.checksum = checksum;
        }

        public int getSrcPort() {
            return srcPort;
        }

        public int getDestPort() {
            return destPort;
        }

        public int getLength() {
            return length;
        }

        public int getChecksum() {
            return checksum;
        }

        public int getPayloadLength() {
            return length - UDP_HEADER_SIZE;
        }
    }

    /**
     * Represents an ICMP header.
     */
    public static class IcmpHeader {
        private final int type;
        private final int code;
        private final int checksum;
        private final int identifier;
        private final int sequenceNumber;

        public IcmpHeader(int type, int code, int checksum, 
                         int identifier, int sequenceNumber) {
            this.type = type;
            this.code = code;
            this.checksum = checksum;
            this.identifier = identifier;
            this.sequenceNumber = sequenceNumber;
        }

        public int getType() {
            return type;
        }

        public int getCode() {
            return code;
        }

        public int getChecksum() {
            return checksum;
        }

        public int getIdentifier() {
            return identifier;
        }

        public int getSequenceNumber() {
            return sequenceNumber;
        }

        @NonNull
        public String getTypeName() {
            return PacketHelper.getIcmpTypeName(type);
        }
    }

    /**
     * Parses an Ethernet frame header.
     */
    @Nullable
    public static EthernetHeader parseEthernetHeader(@NonNull byte[] data) {
        if (data.length < ETHERNET_HEADER_SIZE) {
            return null;
        }

        byte[] destMac = Arrays.copyOfRange(data, 0, 6);
        byte[] srcMac = Arrays.copyOfRange(data, 6, 12);
        int etherType = ((data[12] & 0xFF) << 8) | (data[13] & 0xFF);
        int vlanId = -1;

        // Check for VLAN tag
        if (etherType == ETHERNET_TYPE_VLAN && data.length >= 18) {
            vlanId = ((data[14] & 0x0F) << 8) | (data[15] & 0xFF);
            etherType = ((data[16] & 0xFF) << 8) | (data[17] & 0xFF);
        }

        return new EthernetHeader(destMac, srcMac, etherType, vlanId);
    }

    /**
     * Parses an IPv4 header.
     */
    @Nullable
    public static IPv4Header parseIPv4Header(@NonNull byte[] data) {
        return parseIPv4Header(data, 0);
    }

    /**
     * Parses an IPv4 header from a specific offset.
     */
    @Nullable
    public static IPv4Header parseIPv4Header(@NonNull byte[] data, int offset) {
        if (data.length - offset < IP_HEADER_MIN_SIZE) {
            return null;
        }

        int versionIhl = data[offset] & 0xFF;
        int version = (versionIhl >> 4) & 0x0F;
        int headerLength = versionIhl & 0x0F;

        if (version != IP_VERSION_4) {
            return null;
        }

        int headerBytes = headerLength * 4;
        if (data.length - offset < headerBytes) {
            return null;
        }

        int tos = data[offset + 1] & 0xFF;
        int totalLength = ((data[offset + 2] & 0xFF) << 8) | (data[offset + 3] & 0xFF);
        int identification = ((data[offset + 4] & 0xFF) << 8) | (data[offset + 5] & 0xFF);
        int flagsFragment = ((data[offset + 6] & 0xFF) << 8) | (data[offset + 7] & 0xFF);
        int flags = (flagsFragment >> 13) & 0x07;
        int fragmentOffset = flagsFragment & 0x1FFF;
        int ttl = data[offset + 8] & 0xFF;
        int protocol = data[offset + 9] & 0xFF;
        int checksum = ((data[offset + 10] & 0xFF) << 8) | (data[offset + 11] & 0xFF);
        byte[] srcAddress = Arrays.copyOfRange(data, offset + 12, offset + 16);
        byte[] destAddress = Arrays.copyOfRange(data, offset + 16, offset + 20);

        byte[] options = null;
        if (headerBytes > IP_HEADER_MIN_SIZE) {
            options = Arrays.copyOfRange(data, offset + 20, offset + headerBytes);
        }

        return new IPv4Header(version, headerLength, tos, totalLength, identification,
                flags, fragmentOffset, ttl, protocol, checksum, srcAddress, destAddress, options);
    }

    /**
     * Parses a TCP header.
     */
    @Nullable
    public static TcpHeader parseTcpHeader(@NonNull byte[] data, int offset) {
        if (data.length - offset < TCP_HEADER_MIN_SIZE) {
            return null;
        }

        ByteBuffer buffer = ByteBuffer.wrap(data, offset, data.length - offset);
        buffer.order(ByteOrder.BIG_ENDIAN);

        int srcPort = buffer.getShort() & 0xFFFF;
        int destPort = buffer.getShort() & 0xFFFF;
        long sequenceNumber = buffer.getInt() & 0xFFFFFFFFL;
        long acknowledgmentNumber = buffer.getInt() & 0xFFFFFFFFL;
        int dataOffsetFlags = buffer.getShort() & 0xFFFF;
        int dataOffset = (dataOffsetFlags >> 12) & 0x0F;
        int flags = dataOffsetFlags & 0x3F;
        int window = buffer.getShort() & 0xFFFF;
        int checksum = buffer.getShort() & 0xFFFF;
        int urgentPointer = buffer.getShort() & 0xFFFF;

        byte[] options = null;
        int headerBytes = dataOffset * 4;
        if (headerBytes > TCP_HEADER_MIN_SIZE) {
            options = Arrays.copyOfRange(data, offset + 20, offset + headerBytes);
        }

        return new TcpHeader(srcPort, destPort, sequenceNumber, acknowledgmentNumber,
                dataOffset, flags, window, checksum, urgentPointer, options);
    }

    /**
     * Parses a UDP header.
     */
    @Nullable
    public static UdpHeader parseUdpHeader(@NonNull byte[] data, int offset) {
        if (data.length - offset < UDP_HEADER_SIZE) {
            return null;
        }

        ByteBuffer buffer = ByteBuffer.wrap(data, offset, UDP_HEADER_SIZE);
        buffer.order(ByteOrder.BIG_ENDIAN);

        int srcPort = buffer.getShort() & 0xFFFF;
        int destPort = buffer.getShort() & 0xFFFF;
        int length = buffer.getShort() & 0xFFFF;
        int checksum = buffer.getShort() & 0xFFFF;

        return new UdpHeader(srcPort, destPort, length, checksum);
    }

    /**
     * Parses an ICMP header.
     */
    @Nullable
    public static IcmpHeader parseIcmpHeader(@NonNull byte[] data, int offset) {
        if (data.length - offset < 8) {
            return null;
        }

        int type = data[offset] & 0xFF;
        int code = data[offset + 1] & 0xFF;
        int checksum = ((data[offset + 2] & 0xFF) << 8) | (data[offset + 3] & 0xFF);
        int identifier = ((data[offset + 4] & 0xFF) << 8) | (data[offset + 5] & 0xFF);
        int sequenceNumber = ((data[offset + 6] & 0xFF) << 8) | (data[offset + 7] & 0xFF);

        return new IcmpHeader(type, code, checksum, identifier, sequenceNumber);
    }

    /**
     * Calculates IP checksum.
     */
    public static int calculateChecksum(@NonNull byte[] data, int offset, int length) {
        int sum = 0;

        // Sum 16-bit words
        for (int i = 0; i < length - 1; i += 2) {
            sum += ((data[offset + i] & 0xFF) << 8) | (data[offset + i + 1] & 0xFF);
        }

        // Add remaining byte if odd length
        if (length % 2 != 0) {
            sum += (data[offset + length - 1] & 0xFF) << 8;
        }

        // Fold 32-bit sum to 16 bits
        while ((sum >> 16) != 0) {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }

        return ~sum & 0xFFFF;
    }

    /**
     * Calculates TCP/UDP pseudo-header checksum.
     */
    public static int calculateTcpUdpChecksum(@NonNull byte[] srcAddr, @NonNull byte[] destAddr,
                                               int protocol, @NonNull byte[] segment) {
        int pseudoLength = 12 + segment.length + (segment.length % 2);
        byte[] pseudo = new byte[pseudoLength];

        // Copy source address
        System.arraycopy(srcAddr, 0, pseudo, 0, 4);
        // Copy destination address
        System.arraycopy(destAddr, 0, pseudo, 4, 4);
        // Zero byte
        pseudo[8] = 0;
        // Protocol
        pseudo[9] = (byte) protocol;
        // Segment length (big-endian)
        pseudo[10] = (byte) ((segment.length >> 8) & 0xFF);
        pseudo[11] = (byte) (segment.length & 0xFF);
        // Copy segment
        System.arraycopy(segment, 0, pseudo, 12, segment.length);

        return calculateChecksum(pseudo, 0, pseudoLength);
    }

    /**
     * Formats MAC address as string.
     */
    @NonNull
    public static String formatMac(@NonNull byte[] mac) {
        return String.format(Locale.US, "%02X:%02X:%02X:%02X:%02X:%02X",
                mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
    }

    /**
     * Parses MAC address string to bytes.
     */
    @Nullable
    public static byte[] parseMac(@NonNull String mac) {
        String[] parts = mac.split("[:-]");
        if (parts.length != 6) {
            return null;
        }

        byte[] result = new byte[6];
        try {
            for (int i = 0; i < 6; i++) {
                result[i] = (byte) Integer.parseInt(parts[i], 16);
            }
        } catch (NumberFormatException e) {
            return null;
        }

        return result;
    }

    /**
     * Formats IPv4 address as string.
     */
    @NonNull
    public static String formatIPv4(@NonNull byte[] addr) {
        return String.format(Locale.US, "%d.%d.%d.%d",
                addr[0] & 0xFF, addr[1] & 0xFF, addr[2] & 0xFF, addr[3] & 0xFF);
    }

    /**
     * Parses IPv4 address string to bytes.
     */
    @Nullable
    public static byte[] parseIPv4(@NonNull String ip) {
        String[] parts = ip.split("\\.");
        if (parts.length != 4) {
            return null;
        }

        byte[] result = new byte[4];
        try {
            for (int i = 0; i < 4; i++) {
                int val = Integer.parseInt(parts[i]);
                if (val < 0 || val > 255) {
                    return null;
                }
                result[i] = (byte) val;
            }
        } catch (NumberFormatException e) {
            return null;
        }

        return result;
    }

    /**
     * Gets protocol name from number.
     */
    @NonNull
    public static String getProtocolName(int protocol) {
        switch (protocol) {
            case IP_PROTOCOL_ICMP: return "ICMP";
            case IP_PROTOCOL_TCP: return "TCP";
            case IP_PROTOCOL_UDP: return "UDP";
            case IP_PROTOCOL_GRE: return "GRE";
            case IP_PROTOCOL_ICMPV6: return "ICMPv6";
            default: return String.format(Locale.US, "Protocol %d", protocol);
        }
    }

    /**
     * Gets EtherType name from value.
     */
    @NonNull
    public static String getEtherTypeName(int etherType) {
        switch (etherType) {
            case ETHERNET_TYPE_IPV4: return "IPv4";
            case ETHERNET_TYPE_IPV6: return "IPv6";
            case ETHERNET_TYPE_ARP: return "ARP";
            case ETHERNET_TYPE_VLAN: return "VLAN";
            default: return String.format(Locale.US, "0x%04X", etherType);
        }
    }

    /**
     * Gets ICMP type name.
     */
    @NonNull
    public static String getIcmpTypeName(int type) {
        switch (type) {
            case ICMP_TYPE_ECHO_REPLY: return "Echo Reply";
            case ICMP_TYPE_DEST_UNREACHABLE: return "Destination Unreachable";
            case ICMP_TYPE_SOURCE_QUENCH: return "Source Quench";
            case ICMP_TYPE_REDIRECT: return "Redirect";
            case ICMP_TYPE_ECHO_REQUEST: return "Echo Request";
            case ICMP_TYPE_TIME_EXCEEDED: return "Time Exceeded";
            case ICMP_TYPE_TIMESTAMP_REQUEST: return "Timestamp Request";
            case ICMP_TYPE_TIMESTAMP_REPLY: return "Timestamp Reply";
            default: return String.format(Locale.US, "Type %d", type);
        }
    }

    /**
     * Builds TCP flags byte from individual flags.
     */
    public static int buildTcpFlags(boolean fin, boolean syn, boolean rst, 
                                     boolean psh, boolean ack, boolean urg) {
        int flags = 0;
        if (fin) flags |= TCP_FLAG_FIN;
        if (syn) flags |= TCP_FLAG_SYN;
        if (rst) flags |= TCP_FLAG_RST;
        if (psh) flags |= TCP_FLAG_PSH;
        if (ack) flags |= TCP_FLAG_ACK;
        if (urg) flags |= TCP_FLAG_URG;
        return flags;
    }

    /**
     * Generates a packet summary string.
     */
    @NonNull
    public static String generatePacketSummary(@NonNull byte[] packet) {
        StringBuilder summary = new StringBuilder();

        // Try to parse as Ethernet + IP
        EthernetHeader eth = parseEthernetHeader(packet);
        if (eth != null) {
            summary.append(String.format(Locale.US, "ETH: %s -> %s [%s]\n",
                    eth.getSrcMacString(), eth.getDestMacString(), eth.getEtherTypeString()));

            if (eth.getEtherType() == ETHERNET_TYPE_IPV4) {
                IPv4Header ip = parseIPv4Header(packet, ETHERNET_HEADER_SIZE);
                if (ip != null) {
                    summary.append(String.format(Locale.US, " IP: %s -> %s [%s] TTL=%d\n",
                            ip.getSrcAddressString(), ip.getDestAddressString(),
                            ip.getProtocolName(), ip.getTtl()));

                    int ipHeaderSize = ETHERNET_HEADER_SIZE + ip.getHeaderLengthBytes();

                    if (ip.getProtocol() == IP_PROTOCOL_TCP) {
                        TcpHeader tcp = parseTcpHeader(packet, ipHeaderSize);
                        if (tcp != null) {
                            summary.append(String.format(Locale.US, "TCP: %d -> %d [%s] Seq=%d Ack=%d Win=%d\n",
                                    tcp.getSrcPort(), tcp.getDestPort(), tcp.getFlagsString(),
                                    tcp.getSequenceNumber(), tcp.getAcknowledgmentNumber(),
                                    tcp.getWindow()));
                        }
                    } else if (ip.getProtocol() == IP_PROTOCOL_UDP) {
                        UdpHeader udp = parseUdpHeader(packet, ipHeaderSize);
                        if (udp != null) {
                            summary.append(String.format(Locale.US, "UDP: %d -> %d Len=%d\n",
                                    udp.getSrcPort(), udp.getDestPort(), udp.getLength()));
                        }
                    } else if (ip.getProtocol() == IP_PROTOCOL_ICMP) {
                        IcmpHeader icmp = parseIcmpHeader(packet, ipHeaderSize);
                        if (icmp != null) {
                            summary.append(String.format(Locale.US, "ICMP: %s Code=%d Id=%d Seq=%d\n",
                                    icmp.getTypeName(), icmp.getCode(),
                                    icmp.getIdentifier(), icmp.getSequenceNumber()));
                        }
                    }
                }
            }
        }

        return summary.toString();
    }

    /**
     * Converts bytes to hex string.
     */
    @NonNull
    public static String bytesToHex(@NonNull byte[] data) {
        return bytesToHex(data, 0, data.length);
    }

    /**
     * Converts bytes to hex string with offset and length.
     */
    @NonNull
    public static String bytesToHex(@NonNull byte[] data, int offset, int length) {
        StringBuilder sb = new StringBuilder();
        for (int i = offset; i < offset + length && i < data.length; i++) {
            sb.append(String.format(Locale.US, "%02X ", data[i] & 0xFF));
        }
        return sb.toString().trim();
    }

    /**
     * Generates hex dump of data.
     */
    @NonNull
    public static String hexDump(@NonNull byte[] data) {
        return hexDump(data, 0, data.length);
    }

    /**
     * Generates hex dump of data with offset and length.
     */
    @NonNull
    public static String hexDump(@NonNull byte[] data, int offset, int length) {
        StringBuilder sb = new StringBuilder();
        int end = Math.min(offset + length, data.length);

        for (int i = offset; i < end; i += 16) {
            // Offset
            sb.append(String.format(Locale.US, "%08X  ", i));

            // Hex bytes
            StringBuilder hexPart = new StringBuilder();
            StringBuilder asciiPart = new StringBuilder();

            for (int j = 0; j < 16; j++) {
                if (i + j < end) {
                    int b = data[i + j] & 0xFF;
                    hexPart.append(String.format(Locale.US, "%02X ", b));
                    asciiPart.append(b >= 32 && b < 127 ? (char) b : '.');
                } else {
                    hexPart.append("   ");
                }

                if (j == 7) {
                    hexPart.append(" ");
                }
            }

            sb.append(hexPart).append(" |").append(asciiPart).append("|\n");
        }

        return sb.toString();
    }
}
