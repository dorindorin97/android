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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with cSploit. If not, see <http://www.gnu.org/licenses/>.
 */

package org.csploit.android.helpers;

import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.List;

/**
 * PcapHelper - PCAP (packet capture) file utilities.
 * 
 * Provides:
 * - PCAP file reading/writing
 * - Packet parsing
 * - Capture statistics
 * - File validation
 * 
 * Supports standard PCAP format (not PCAPNG).
 * 
 * Usage:
 * {@code
 * // Create new capture file
 * PcapHelper.PcapWriter writer = new PcapHelper.PcapWriter(new File("capture.pcap"));
 * writer.writePacket(packetData);
 * writer.close();
 * 
 * // Read capture file
 * PcapHelper.PcapReader reader = new PcapHelper.PcapReader(new File("capture.pcap"));
 * PcapHelper.PcapPacket packet;
 * while ((packet = reader.readPacket()) != null) {
 *     processPacket(packet);
 * }
 * reader.close();
 * }
 */
public final class PcapHelper {
    
    private static final String TAG = "PcapHelper";
    
    // PCAP magic numbers
    public static final int PCAP_MAGIC = 0xa1b2c3d4;
    public static final int PCAP_MAGIC_SWAPPED = 0xd4c3b2a1;
    public static final int PCAP_MAGIC_NS = 0xa1b23c4d;  // Nanosecond resolution
    public static final int PCAP_MAGIC_NS_SWAPPED = 0x4d3cb2a1;
    
    // PCAP version
    public static final short PCAP_VERSION_MAJOR = 2;
    public static final short PCAP_VERSION_MINOR = 4;
    
    // Link-layer types
    public static final int DLT_NULL = 0;
    public static final int DLT_EN10MB = 1;      // Ethernet
    public static final int DLT_IEEE802_11 = 105; // WiFi
    public static final int DLT_RAW = 101;        // Raw IP
    public static final int DLT_LINUX_SLL = 113;  // Linux cooked capture
    
    // Default values
    public static final int DEFAULT_SNAPLEN = 65535;
    
    private PcapHelper() {}
    
    /**
     * PCAP global header.
     */
    public static class PcapHeader {
        public int magicNumber;
        public short versionMajor;
        public short versionMinor;
        public int thiszone;      // GMT to local correction
        public int sigfigs;       // Accuracy of timestamps
        public int snaplen;       // Max length of captured packets
        public int network;       // Link-layer type
        
        public boolean isSwapped() {
            return magicNumber == PCAP_MAGIC_SWAPPED || magicNumber == PCAP_MAGIC_NS_SWAPPED;
        }
        
        public boolean isNanosecond() {
            return magicNumber == PCAP_MAGIC_NS || magicNumber == PCAP_MAGIC_NS_SWAPPED;
        }
        
        @NonNull
        @Override
        public String toString() {
            return String.format("PcapHeader{version=%d.%d, snaplen=%d, network=%d}",
                    versionMajor, versionMinor, snaplen, network);
        }
    }
    
    /**
     * PCAP packet header.
     */
    public static class PcapPacketHeader {
        public long tsSec;        // Timestamp seconds
        public long tsUsec;       // Timestamp microseconds (or nanoseconds)
        public int capturedLength; // Number of bytes captured
        public int originalLength; // Original length of packet
        
        /**
         * Get timestamp in milliseconds.
         */
        public long getTimestampMs() {
            return tsSec * 1000 + tsUsec / 1000;
        }
        
        @NonNull
        @Override
        public String toString() {
            return String.format("PacketHeader{ts=%d.%06d, len=%d/%d}",
                    tsSec, tsUsec, capturedLength, originalLength);
        }
    }
    
    /**
     * PCAP packet with header and data.
     */
    public static class PcapPacket {
        public PcapPacketHeader header;
        public byte[] data;
        public int packetNumber;
        
        public PcapPacket(PcapPacketHeader header, byte[] data, int number) {
            this.header = header;
            this.data = data;
            this.packetNumber = number;
        }
        
        @NonNull
        @Override
        public String toString() {
            return String.format("PcapPacket{#%d, len=%d}", packetNumber, data.length);
        }
    }
    
    /**
     * PCAP file reader.
     */
    public static class PcapReader implements AutoCloseable {
        private final FileInputStream fis;
        private final PcapHeader header;
        private final ByteOrder byteOrder;
        private int packetCount;
        
        public PcapReader(@NonNull File file) throws IOException {
            fis = new FileInputStream(file);
            header = readHeader();
            byteOrder = header.isSwapped() ? ByteOrder.LITTLE_ENDIAN : ByteOrder.BIG_ENDIAN;
            packetCount = 0;
        }
        
        private PcapHeader readHeader() throws IOException {
            byte[] headerBytes = new byte[24];
            if (fis.read(headerBytes) != 24) {
                throw new IOException("Invalid PCAP file: header too short");
            }
            
            ByteBuffer buffer = ByteBuffer.wrap(headerBytes);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            
            int magic = buffer.getInt();
            if (magic != PCAP_MAGIC && magic != PCAP_MAGIC_SWAPPED &&
                magic != PCAP_MAGIC_NS && magic != PCAP_MAGIC_NS_SWAPPED) {
                // Try big endian
                buffer.order(ByteOrder.BIG_ENDIAN);
                buffer.rewind();
                magic = buffer.getInt();
            }
            
            if (magic != PCAP_MAGIC && magic != PCAP_MAGIC_SWAPPED &&
                magic != PCAP_MAGIC_NS && magic != PCAP_MAGIC_NS_SWAPPED) {
                throw new IOException("Invalid PCAP file: bad magic number");
            }
            
            PcapHeader header = new PcapHeader();
            header.magicNumber = magic;
            header.versionMajor = buffer.getShort();
            header.versionMinor = buffer.getShort();
            header.thiszone = buffer.getInt();
            header.sigfigs = buffer.getInt();
            header.snaplen = buffer.getInt();
            header.network = buffer.getInt();
            
            return header;
        }
        
        /**
         * Read next packet.
         * 
         * @return packet or null if EOF
         */
        @Nullable
        public PcapPacket readPacket() throws IOException {
            byte[] headerBytes = new byte[16];
            int bytesRead = fis.read(headerBytes);
            
            if (bytesRead == -1) {
                return null; // EOF
            }
            
            if (bytesRead != 16) {
                throw new IOException("Incomplete packet header");
            }
            
            ByteBuffer buffer = ByteBuffer.wrap(headerBytes);
            buffer.order(byteOrder);
            
            PcapPacketHeader packetHeader = new PcapPacketHeader();
            packetHeader.tsSec = Integer.toUnsignedLong(buffer.getInt());
            packetHeader.tsUsec = Integer.toUnsignedLong(buffer.getInt());
            packetHeader.capturedLength = buffer.getInt();
            packetHeader.originalLength = buffer.getInt();
            
            if (packetHeader.capturedLength < 0 || packetHeader.capturedLength > header.snaplen) {
                throw new IOException("Invalid captured length: " + packetHeader.capturedLength);
            }
            
            byte[] data = new byte[packetHeader.capturedLength];
            bytesRead = fis.read(data);
            
            if (bytesRead != packetHeader.capturedLength) {
                throw new IOException("Incomplete packet data");
            }
            
            return new PcapPacket(packetHeader, data, ++packetCount);
        }
        
        /**
         * Read all packets.
         */
        @NonNull
        public List<PcapPacket> readAllPackets() throws IOException {
            List<PcapPacket> packets = new ArrayList<>();
            PcapPacket packet;
            while ((packet = readPacket()) != null) {
                packets.add(packet);
            }
            return packets;
        }
        
        public PcapHeader getHeader() {
            return header;
        }
        
        public int getPacketCount() {
            return packetCount;
        }
        
        @Override
        public void close() throws IOException {
            fis.close();
        }
    }
    
    /**
     * PCAP file writer.
     */
    public static class PcapWriter implements AutoCloseable {
        private final FileOutputStream fos;
        private final int linkType;
        private int packetCount;
        
        public PcapWriter(@NonNull File file) throws IOException {
            this(file, DLT_EN10MB);
        }
        
        public PcapWriter(@NonNull File file, int linkType) throws IOException {
            this.fos = new FileOutputStream(file);
            this.linkType = linkType;
            this.packetCount = 0;
            writeHeader();
        }
        
        private void writeHeader() throws IOException {
            ByteBuffer buffer = ByteBuffer.allocate(24);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            
            buffer.putInt(PCAP_MAGIC);
            buffer.putShort(PCAP_VERSION_MAJOR);
            buffer.putShort(PCAP_VERSION_MINOR);
            buffer.putInt(0); // thiszone
            buffer.putInt(0); // sigfigs
            buffer.putInt(DEFAULT_SNAPLEN);
            buffer.putInt(linkType);
            
            fos.write(buffer.array());
        }
        
        /**
         * Write a packet.
         * 
         * @param data packet data
         */
        public void writePacket(@NonNull byte[] data) throws IOException {
            writePacket(data, java.lang.System.currentTimeMillis());
        }
        
        /**
         * Write a packet with timestamp.
         * 
         * @param data packet data
         * @param timestampMs timestamp in milliseconds
         */
        public void writePacket(@NonNull byte[] data, long timestampMs) throws IOException {
            ByteBuffer buffer = ByteBuffer.allocate(16);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            
            long tsSec = timestampMs / 1000;
            long tsUsec = (timestampMs % 1000) * 1000;
            
            buffer.putInt((int) tsSec);
            buffer.putInt((int) tsUsec);
            buffer.putInt(data.length); // captured length
            buffer.putInt(data.length); // original length
            
            fos.write(buffer.array());
            fos.write(data);
            packetCount++;
        }
        
        public int getPacketCount() {
            return packetCount;
        }
        
        @Override
        public void close() throws IOException {
            fos.close();
        }
    }
    
    /**
     * Validate PCAP file.
     */
    public static boolean isValidPcap(@NonNull File file) {
        try (FileInputStream fis = new FileInputStream(file)) {
            byte[] magicBytes = new byte[4];
            if (fis.read(magicBytes) != 4) {
                return false;
            }
            
            ByteBuffer buffer = ByteBuffer.wrap(magicBytes);
            buffer.order(ByteOrder.LITTLE_ENDIAN);
            int magic = buffer.getInt();
            
            return magic == PCAP_MAGIC || magic == PCAP_MAGIC_SWAPPED ||
                   magic == PCAP_MAGIC_NS || magic == PCAP_MAGIC_NS_SWAPPED;
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Get PCAP file statistics.
     */
    @Nullable
    public static PcapStats getStats(@NonNull File file) {
        try (PcapReader reader = new PcapReader(file)) {
            PcapStats stats = new PcapStats();
            stats.header = reader.getHeader();
            
            PcapPacket packet;
            while ((packet = reader.readPacket()) != null) {
                stats.packetCount++;
                stats.totalBytes += packet.data.length;
                stats.totalOriginalBytes += packet.header.originalLength;
                
                if (stats.firstTimestamp == 0) {
                    stats.firstTimestamp = packet.header.getTimestampMs();
                }
                stats.lastTimestamp = packet.header.getTimestampMs();
            }
            
            if (stats.packetCount > 0) {
                stats.averagePacketSize = stats.totalBytes / stats.packetCount;
                stats.durationMs = stats.lastTimestamp - stats.firstTimestamp;
            }
            
            return stats;
        } catch (Exception e) {
            Log.e(TAG, "Failed to get stats for: " + file.getName(), e);
            return null;
        }
    }
    
    /**
     * PCAP file statistics.
     */
    public static class PcapStats {
        public PcapHeader header;
        public int packetCount;
        public long totalBytes;
        public long totalOriginalBytes;
        public long averagePacketSize;
        public long firstTimestamp;
        public long lastTimestamp;
        public long durationMs;
        
        @NonNull
        @Override
        public String toString() {
            return String.format("PcapStats{packets=%d, bytes=%d, duration=%dms}",
                    packetCount, totalBytes, durationMs);
        }
    }
    
    /**
     * Get link-layer type name.
     */
    @NonNull
    public static String getLinkTypeName(int linkType) {
        switch (linkType) {
            case DLT_NULL: return "NULL";
            case DLT_EN10MB: return "Ethernet";
            case DLT_IEEE802_11: return "IEEE 802.11 (WiFi)";
            case DLT_RAW: return "Raw IP";
            case DLT_LINUX_SLL: return "Linux cooked capture";
            default: return "Unknown (" + linkType + ")";
        }
    }
    
    /**
     * Merge multiple PCAP files.
     */
    public static boolean mergePcaps(@NonNull List<File> inputFiles, @NonNull File outputFile) {
        try {
            // Determine link type from first file
            int linkType = DLT_EN10MB;
            if (!inputFiles.isEmpty()) {
                try (PcapReader reader = new PcapReader(inputFiles.get(0))) {
                    linkType = reader.getHeader().network;
                }
            }
            
            try (PcapWriter writer = new PcapWriter(outputFile, linkType)) {
                for (File inputFile : inputFiles) {
                    try (PcapReader reader = new PcapReader(inputFile)) {
                        PcapPacket packet;
                        while ((packet = reader.readPacket()) != null) {
                            writer.writePacket(packet.data, packet.header.getTimestampMs());
                        }
                    }
                }
            }
            
            return true;
        } catch (Exception e) {
            Log.e(TAG, "Failed to merge PCAP files", e);
            return false;
        }
    }
}
