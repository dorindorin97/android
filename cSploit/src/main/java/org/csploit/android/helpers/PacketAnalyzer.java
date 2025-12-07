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
import androidx.annotation.Nullable;

import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;
import java.util.Locale;

/**
 * PacketAnalyzer - Network packet analysis utilities.
 * 
 * Provides methods for parsing and analyzing network packets including:
 * - Ethernet frame parsing
 * - IP header parsing (IPv4/IPv6)
 * - TCP/UDP header parsing
 * - Protocol identification
 * - Packet statistics
 */
public final class PacketAnalyzer {
    
    public static final String TAG = "PacketAnalyzer";
    
    // Ethernet types
    public static final int ETHERTYPE_IPV4 = 0x0800;
    public static final int ETHERTYPE_ARP = 0x0806;
    public static final int ETHERTYPE_IPV6 = 0x86DD;
    public static final int ETHERTYPE_VLAN = 0x8100;
    
    // IP protocols
    public static final int IPPROTO_ICMP = 1;
    public static final int IPPROTO_TCP = 6;
    public static final int IPPROTO_UDP = 17;
    public static final int IPPROTO_ICMPV6 = 58;
    
    // Common ports
    public static final int PORT_FTP = 21;
    public static final int PORT_SSH = 22;
    public static final int PORT_TELNET = 23;
    public static final int PORT_SMTP = 25;
    public static final int PORT_DNS = 53;
    public static final int PORT_HTTP = 80;
    public static final int PORT_POP3 = 110;
    public static final int PORT_IMAP = 143;
    public static final int PORT_HTTPS = 443;
    public static final int PORT_SMB = 445;
    public static final int PORT_IMAPS = 993;
    public static final int PORT_MYSQL = 3306;
    public static final int PORT_RDP = 3389;
    public static final int PORT_POSTGRESQL = 5432;
    public static final int PORT_REDIS = 6379;
    public static final int PORT_HTTP_ALT = 8080;
    
    private PacketAnalyzer() {}
    
    /**
     * Parsed Ethernet frame information.
     */
    public static class EthernetFrame {
        public final byte[] destMac;
        public final byte[] srcMac;
        public final int etherType;
        public final byte[] payload;
        
        public EthernetFrame(byte[] destMac, byte[] srcMac, int etherType, byte[] payload) {
            this.destMac = destMac;
            this.srcMac = srcMac;
            this.etherType = etherType;
            this.payload = payload;
        }
        
        @NonNull
        public String getDestMacString() {
            return MacAddressHelper.bytesToMac(destMac);
        }
        
        @NonNull
        public String getSrcMacString() {
            return MacAddressHelper.bytesToMac(srcMac);
        }
        
        @NonNull
        public String getEtherTypeString() {
            return getEtherTypeName(etherType);
        }
    }
    
    /**
     * Parsed IPv4 header information.
     */
    public static class IPv4Header {
        public final int version;
        public final int headerLength;
        public final int tos;
        public final int totalLength;
        public final int identification;
        public final int flags;
        public final int fragmentOffset;
        public final int ttl;
        public final int protocol;
        public final int checksum;
        public final byte[] srcAddress;
        public final byte[] destAddress;
        public final byte[] payload;
        
        public IPv4Header(int version, int headerLength, int tos, int totalLength,
                          int identification, int flags, int fragmentOffset, int ttl,
                          int protocol, int checksum, byte[] srcAddress, byte[] destAddress,
                          byte[] payload) {
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
            this.srcAddress = srcAddress;
            this.destAddress = destAddress;
            this.payload = payload;
        }
        
        @NonNull
        public String getSrcAddressString() {
            return IpAddressHelper.bytesToIp(srcAddress);
        }
        
        @NonNull
        public String getDestAddressString() {
            return IpAddressHelper.bytesToIp(destAddress);
        }
        
        @NonNull
        public String getProtocolString() {
            return getProtocolName(protocol);
        }
    }
    
    /**
     * Parsed TCP header information.
     */
    public static class TcpHeader {
        public final int srcPort;
        public final int destPort;
        public final long seqNumber;
        public final long ackNumber;
        public final int dataOffset;
        public final int flags;
        public final int windowSize;
        public final int checksum;
        public final int urgentPointer;
        public final byte[] payload;
        
        // TCP flags
        public static final int FLAG_FIN = 0x01;
        public static final int FLAG_SYN = 0x02;
        public static final int FLAG_RST = 0x04;
        public static final int FLAG_PSH = 0x08;
        public static final int FLAG_ACK = 0x10;
        public static final int FLAG_URG = 0x20;
        public static final int FLAG_ECE = 0x40;
        public static final int FLAG_CWR = 0x80;
        
        public TcpHeader(int srcPort, int destPort, long seqNumber, long ackNumber,
                         int dataOffset, int flags, int windowSize, int checksum,
                         int urgentPointer, byte[] payload) {
            this.srcPort = srcPort;
            this.destPort = destPort;
            this.seqNumber = seqNumber;
            this.ackNumber = ackNumber;
            this.dataOffset = dataOffset;
            this.flags = flags;
            this.windowSize = windowSize;
            this.checksum = checksum;
            this.urgentPointer = urgentPointer;
            this.payload = payload;
        }
        
        public boolean isSyn() { return (flags & FLAG_SYN) != 0; }
        public boolean isAck() { return (flags & FLAG_ACK) != 0; }
        public boolean isFin() { return (flags & FLAG_FIN) != 0; }
        public boolean isRst() { return (flags & FLAG_RST) != 0; }
        public boolean isPsh() { return (flags & FLAG_PSH) != 0; }
        public boolean isUrg() { return (flags & FLAG_URG) != 0; }
        
        @NonNull
        public String getFlagsString() {
            StringBuilder sb = new StringBuilder();
            if (isSyn()) sb.append("SYN ");
            if (isAck()) sb.append("ACK ");
            if (isFin()) sb.append("FIN ");
            if (isRst()) sb.append("RST ");
            if (isPsh()) sb.append("PSH ");
            if (isUrg()) sb.append("URG ");
            return sb.toString().trim();
        }
    }
    
    /**
     * Parsed UDP header information.
     */
    public static class UdpHeader {
        public final int srcPort;
        public final int destPort;
        public final int length;
        public final int checksum;
        public final byte[] payload;
        
        public UdpHeader(int srcPort, int destPort, int length, int checksum, byte[] payload) {
            this.srcPort = srcPort;
            this.destPort = destPort;
            this.length = length;
            this.checksum = checksum;
            this.payload = payload;
        }
    }
    
    /**
     * Parse an Ethernet frame.
     * 
     * @param data Raw frame data
     * @return Parsed frame or null if invalid
     */
    @Nullable
    public static EthernetFrame parseEthernetFrame(@NonNull byte[] data) {
        if (data.length < 14) {
            return null;
        }
        
        byte[] destMac = new byte[6];
        byte[] srcMac = new byte[6];
        System.arraycopy(data, 0, destMac, 0, 6);
        System.arraycopy(data, 6, srcMac, 0, 6);
        
        int etherType = ((data[12] & 0xFF) << 8) | (data[13] & 0xFF);
        
        byte[] payload = new byte[data.length - 14];
        System.arraycopy(data, 14, payload, 0, payload.length);
        
        return new EthernetFrame(destMac, srcMac, etherType, payload);
    }
    
    /**
     * Parse an IPv4 header.
     * 
     * @param data Raw IP packet data
     * @return Parsed header or null if invalid
     */
    @Nullable
    public static IPv4Header parseIPv4Header(@NonNull byte[] data) {
        if (data.length < 20) {
            return null;
        }
        
        ByteBuffer buffer = ByteBuffer.wrap(data);
        buffer.order(ByteOrder.BIG_ENDIAN);
        
        int versionIhl = buffer.get() & 0xFF;
        int version = (versionIhl >> 4) & 0x0F;
        int headerLength = (versionIhl & 0x0F) * 4;
        
        if (version != 4 || headerLength < 20 || data.length < headerLength) {
            return null;
        }
        
        int tos = buffer.get() & 0xFF;
        int totalLength = buffer.getShort() & 0xFFFF;
        int identification = buffer.getShort() & 0xFFFF;
        int flagsFragment = buffer.getShort() & 0xFFFF;
        int flags = (flagsFragment >> 13) & 0x07;
        int fragmentOffset = flagsFragment & 0x1FFF;
        int ttl = buffer.get() & 0xFF;
        int protocol = buffer.get() & 0xFF;
        int checksum = buffer.getShort() & 0xFFFF;
        
        byte[] srcAddress = new byte[4];
        byte[] destAddress = new byte[4];
        buffer.get(srcAddress);
        buffer.get(destAddress);
        
        int payloadLength = Math.min(totalLength - headerLength, data.length - headerLength);
        byte[] payload = new byte[Math.max(0, payloadLength)];
        if (payloadLength > 0 && data.length > headerLength) {
            System.arraycopy(data, headerLength, payload, 0, payloadLength);
        }
        
        return new IPv4Header(version, headerLength, tos, totalLength, identification,
                flags, fragmentOffset, ttl, protocol, checksum, srcAddress, destAddress, payload);
    }
    
    /**
     * Parse a TCP header.
     * 
     * @param data Raw TCP segment data
     * @return Parsed header or null if invalid
     */
    @Nullable
    public static TcpHeader parseTcpHeader(@NonNull byte[] data) {
        if (data.length < 20) {
            return null;
        }
        
        ByteBuffer buffer = ByteBuffer.wrap(data);
        buffer.order(ByteOrder.BIG_ENDIAN);
        
        int srcPort = buffer.getShort() & 0xFFFF;
        int destPort = buffer.getShort() & 0xFFFF;
        long seqNumber = buffer.getInt() & 0xFFFFFFFFL;
        long ackNumber = buffer.getInt() & 0xFFFFFFFFL;
        
        int dataOffsetFlags = buffer.getShort() & 0xFFFF;
        int dataOffset = ((dataOffsetFlags >> 12) & 0x0F) * 4;
        int flags = dataOffsetFlags & 0x3F;
        
        int windowSize = buffer.getShort() & 0xFFFF;
        int checksum = buffer.getShort() & 0xFFFF;
        int urgentPointer = buffer.getShort() & 0xFFFF;
        
        byte[] payload = new byte[0];
        if (data.length > dataOffset) {
            payload = new byte[data.length - dataOffset];
            System.arraycopy(data, dataOffset, payload, 0, payload.length);
        }
        
        return new TcpHeader(srcPort, destPort, seqNumber, ackNumber, dataOffset,
                flags, windowSize, checksum, urgentPointer, payload);
    }
    
    /**
     * Parse a UDP header.
     * 
     * @param data Raw UDP datagram data
     * @return Parsed header or null if invalid
     */
    @Nullable
    public static UdpHeader parseUdpHeader(@NonNull byte[] data) {
        if (data.length < 8) {
            return null;
        }
        
        ByteBuffer buffer = ByteBuffer.wrap(data);
        buffer.order(ByteOrder.BIG_ENDIAN);
        
        int srcPort = buffer.getShort() & 0xFFFF;
        int destPort = buffer.getShort() & 0xFFFF;
        int length = buffer.getShort() & 0xFFFF;
        int checksum = buffer.getShort() & 0xFFFF;
        
        byte[] payload = new byte[0];
        if (data.length > 8) {
            payload = new byte[data.length - 8];
            System.arraycopy(data, 8, payload, 0, payload.length);
        }
        
        return new UdpHeader(srcPort, destPort, length, checksum, payload);
    }
    
    /**
     * Get the name of an Ethernet type.
     */
    @NonNull
    public static String getEtherTypeName(int etherType) {
        switch (etherType) {
            case ETHERTYPE_IPV4: return "IPv4";
            case ETHERTYPE_ARP: return "ARP";
            case ETHERTYPE_IPV6: return "IPv6";
            case ETHERTYPE_VLAN: return "802.1Q VLAN";
            default: return String.format(Locale.US, "0x%04X", etherType);
        }
    }
    
    /**
     * Get the name of an IP protocol.
     */
    @NonNull
    public static String getProtocolName(int protocol) {
        switch (protocol) {
            case IPPROTO_ICMP: return "ICMP";
            case IPPROTO_TCP: return "TCP";
            case IPPROTO_UDP: return "UDP";
            case IPPROTO_ICMPV6: return "ICMPv6";
            default: return String.valueOf(protocol);
        }
    }
    
    /**
     * Get service name for a well-known port.
     */
    @NonNull
    public static String getServiceName(int port) {
        switch (port) {
            case PORT_FTP: return "FTP";
            case PORT_SSH: return "SSH";
            case PORT_TELNET: return "Telnet";
            case PORT_SMTP: return "SMTP";
            case PORT_DNS: return "DNS";
            case PORT_HTTP: return "HTTP";
            case PORT_POP3: return "POP3";
            case PORT_IMAP: return "IMAP";
            case PORT_HTTPS: return "HTTPS";
            case PORT_SMB: return "SMB";
            case PORT_IMAPS: return "IMAPS";
            case PORT_MYSQL: return "MySQL";
            case PORT_RDP: return "RDP";
            case PORT_POSTGRESQL: return "PostgreSQL";
            case PORT_REDIS: return "Redis";
            case PORT_HTTP_ALT: return "HTTP-Alt";
            default: return String.valueOf(port);
        }
    }
    
    /**
     * Check if a port is a well-known privileged port.
     */
    public static boolean isPrivilegedPort(int port) {
        return port > 0 && port < 1024;
    }
    
    /**
     * Check if a port is commonly used for web traffic.
     */
    public static boolean isWebPort(int port) {
        return port == PORT_HTTP || port == PORT_HTTPS || port == PORT_HTTP_ALT;
    }
    
    /**
     * Check if a port is commonly used for database services.
     */
    public static boolean isDatabasePort(int port) {
        return port == PORT_MYSQL || port == PORT_POSTGRESQL || port == PORT_REDIS || port == 27017; // MongoDB
    }
    
    /**
     * Check if a port is commonly used for remote access.
     */
    public static boolean isRemoteAccessPort(int port) {
        return port == PORT_SSH || port == PORT_TELNET || port == PORT_RDP || port == 5900; // VNC
    }
    
    /**
     * Convert bytes to hex string for display.
     */
    @NonNull
    public static String bytesToHex(@NonNull byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            sb.append(String.format("%02X ", b & 0xFF));
        }
        return sb.toString().trim();
    }
    
    /**
     * Convert bytes to ASCII string (printable chars only).
     */
    @NonNull
    public static String bytesToAscii(@NonNull byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (byte b : bytes) {
            char c = (char) (b & 0xFF);
            sb.append(c >= 32 && c < 127 ? c : '.');
        }
        return sb.toString();
    }
    
    /**
     * Format packet data in hex dump format.
     */
    @NonNull
    public static String hexDump(@NonNull byte[] data, int bytesPerLine) {
        StringBuilder sb = new StringBuilder();
        
        for (int i = 0; i < data.length; i += bytesPerLine) {
            // Offset
            sb.append(String.format("%08X  ", i));
            
            // Hex values
            for (int j = 0; j < bytesPerLine; j++) {
                if (i + j < data.length) {
                    sb.append(String.format("%02X ", data[i + j] & 0xFF));
                } else {
                    sb.append("   ");
                }
                if (j == bytesPerLine / 2 - 1) {
                    sb.append(" ");
                }
            }
            
            sb.append(" |");
            
            // ASCII
            for (int j = 0; j < bytesPerLine && i + j < data.length; j++) {
                char c = (char) (data[i + j] & 0xFF);
                sb.append(c >= 32 && c < 127 ? c : '.');
            }
            
            sb.append("|\n");
        }
        
        return sb.toString();
    }
}
