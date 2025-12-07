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
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.SocketTimeoutException;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Random;

/**
 * Helper class for DNS protocol operations and analysis.
 * Provides utilities for DNS query construction, response parsing,
 * DNS enumeration, and security analysis.
 */
public final class DnsProtocolHelper {

    private static final String TAG = "DnsProtocolHelper";

    // Default DNS port
    public static final int DEFAULT_DNS_PORT = 53;
    public static final int DEFAULT_TIMEOUT_MS = 5000;

    // DNS record types
    public static final int TYPE_A = 1;        // IPv4 address
    public static final int TYPE_NS = 2;       // Name server
    public static final int TYPE_CNAME = 5;    // Canonical name
    public static final int TYPE_SOA = 6;      // Start of authority
    public static final int TYPE_PTR = 12;     // Pointer (reverse DNS)
    public static final int TYPE_MX = 15;      // Mail exchange
    public static final int TYPE_TXT = 16;     // Text record
    public static final int TYPE_AAAA = 28;    // IPv6 address
    public static final int TYPE_SRV = 33;     // Service record
    public static final int TYPE_ANY = 255;    // Any type

    // DNS classes
    public static final int CLASS_IN = 1;      // Internet
    public static final int CLASS_CH = 3;      // Chaos
    public static final int CLASS_HS = 4;      // Hesiod
    public static final int CLASS_ANY = 255;   // Any class

    // DNS response codes
    public static final int RCODE_NO_ERROR = 0;
    public static final int RCODE_FORMAT_ERROR = 1;
    public static final int RCODE_SERVER_FAILURE = 2;
    public static final int RCODE_NAME_ERROR = 3;    // NXDOMAIN
    public static final int RCODE_NOT_IMPLEMENTED = 4;
    public static final int RCODE_REFUSED = 5;

    // DNS header flags
    public static final int FLAG_QR = 0x8000;      // Query/Response
    public static final int FLAG_AA = 0x0400;      // Authoritative Answer
    public static final int FLAG_TC = 0x0200;      // Truncated
    public static final int FLAG_RD = 0x0100;      // Recursion Desired
    public static final int FLAG_RA = 0x0080;      // Recursion Available
    public static final int FLAG_AD = 0x0020;      // Authenticated Data
    public static final int FLAG_CD = 0x0010;      // Checking Disabled

    private static final Random random = new Random();

    private DnsProtocolHelper() {
        // Private constructor to prevent instantiation
    }

    /**
     * Represents a DNS query.
     */
    public static class DnsQuery {
        private final int transactionId;
        private final String name;
        private final int type;
        private final int queryClass;
        private final boolean recursionDesired;

        public DnsQuery(@NonNull String name, int type) {
            this(name, type, CLASS_IN, true);
        }

        public DnsQuery(@NonNull String name, int type, int queryClass, boolean recursionDesired) {
            this.transactionId = random.nextInt(0xFFFF);
            this.name = name;
            this.type = type;
            this.queryClass = queryClass;
            this.recursionDesired = recursionDesired;
        }

        public int getTransactionId() {
            return transactionId;
        }

        @NonNull
        public String getName() {
            return name;
        }

        public int getType() {
            return type;
        }

        public int getQueryClass() {
            return queryClass;
        }

        public boolean isRecursionDesired() {
            return recursionDesired;
        }

        /**
         * Builds the DNS query packet.
         */
        @NonNull
        public byte[] build() {
            ByteBuffer buffer = ByteBuffer.allocate(512);
            buffer.order(ByteOrder.BIG_ENDIAN);

            // Transaction ID
            buffer.putShort((short) transactionId);

            // Flags
            int flags = 0;
            if (recursionDesired) {
                flags |= FLAG_RD;
            }
            buffer.putShort((short) flags);

            // Counts
            buffer.putShort((short) 1);  // Questions
            buffer.putShort((short) 0);  // Answers
            buffer.putShort((short) 0);  // Authority
            buffer.putShort((short) 0);  // Additional

            // Question section
            encodeName(buffer, name);
            buffer.putShort((short) type);
            buffer.putShort((short) queryClass);

            byte[] result = new byte[buffer.position()];
            buffer.flip();
            buffer.get(result);
            return result;
        }

        /**
         * Encodes a domain name into DNS format.
         */
        private void encodeName(@NonNull ByteBuffer buffer, @NonNull String name) {
            String[] labels = name.split("\\.");
            for (String label : labels) {
                buffer.put((byte) label.length());
                buffer.put(label.getBytes());
            }
            buffer.put((byte) 0);  // Null terminator
        }
    }

    /**
     * Represents a DNS resource record.
     */
    public static class DnsRecord {
        private final String name;
        private final int type;
        private final int recordClass;
        private final int ttl;
        private final String data;

        public DnsRecord(@NonNull String name, int type, int recordClass, int ttl, @NonNull String data) {
            this.name = name;
            this.type = type;
            this.recordClass = recordClass;
            this.ttl = ttl;
            this.data = data;
        }

        @NonNull
        public String getName() {
            return name;
        }

        public int getType() {
            return type;
        }

        @NonNull
        public String getTypeName() {
            return DnsProtocolHelper.getTypeName(type);
        }

        public int getRecordClass() {
            return recordClass;
        }

        public int getTtl() {
            return ttl;
        }

        @NonNull
        public String getData() {
            return data;
        }

        @Override
        public String toString() {
            return String.format(Locale.US, "%s %d %s %s %s",
                    name, ttl, getClassName(recordClass), getTypeName(), data);
        }
    }

    /**
     * Represents a DNS response.
     */
    public static class DnsResponse {
        private final int transactionId;
        private final int flags;
        private final int responseCode;
        private final List<DnsRecord> answers;
        private final List<DnsRecord> authorities;
        private final List<DnsRecord> additionals;
        private final long responseTime;

        private DnsResponse(Builder builder) {
            this.transactionId = builder.transactionId;
            this.flags = builder.flags;
            this.responseCode = builder.responseCode;
            this.answers = new ArrayList<>(builder.answers);
            this.authorities = new ArrayList<>(builder.authorities);
            this.additionals = new ArrayList<>(builder.additionals);
            this.responseTime = builder.responseTime;
        }

        public int getTransactionId() {
            return transactionId;
        }

        public int getFlags() {
            return flags;
        }

        public int getResponseCode() {
            return responseCode;
        }

        public boolean isSuccess() {
            return responseCode == RCODE_NO_ERROR;
        }

        public boolean isAuthoritative() {
            return (flags & FLAG_AA) != 0;
        }

        public boolean isTruncated() {
            return (flags & FLAG_TC) != 0;
        }

        public boolean isRecursionAvailable() {
            return (flags & FLAG_RA) != 0;
        }

        @NonNull
        public List<DnsRecord> getAnswers() {
            return Collections.unmodifiableList(answers);
        }

        @NonNull
        public List<DnsRecord> getAuthorities() {
            return Collections.unmodifiableList(authorities);
        }

        @NonNull
        public List<DnsRecord> getAdditionals() {
            return Collections.unmodifiableList(additionals);
        }

        public long getResponseTime() {
            return responseTime;
        }

        @NonNull
        public String getResponseCodeName() {
            return DnsProtocolHelper.getResponseCodeName(responseCode);
        }

        public static class Builder {
            private int transactionId;
            private int flags;
            private int responseCode;
            private List<DnsRecord> answers = new ArrayList<>();
            private List<DnsRecord> authorities = new ArrayList<>();
            private List<DnsRecord> additionals = new ArrayList<>();
            private long responseTime;

            public Builder setTransactionId(int transactionId) {
                this.transactionId = transactionId;
                return this;
            }

            public Builder setFlags(int flags) {
                this.flags = flags;
                return this;
            }

            public Builder setResponseCode(int responseCode) {
                this.responseCode = responseCode;
                return this;
            }

            public Builder addAnswer(DnsRecord record) {
                this.answers.add(record);
                return this;
            }

            public Builder addAuthority(DnsRecord record) {
                this.authorities.add(record);
                return this;
            }

            public Builder addAdditional(DnsRecord record) {
                this.additionals.add(record);
                return this;
            }

            public Builder setResponseTime(long responseTime) {
                this.responseTime = responseTime;
                return this;
            }

            public DnsResponse build() {
                return new DnsResponse(this);
            }
        }
    }

    /**
     * Sends a DNS query and receives the response.
     */
    @NonNull
    public static DnsResponse query(@NonNull String server, @NonNull DnsQuery query) 
            throws IOException {
        return query(server, DEFAULT_DNS_PORT, query, DEFAULT_TIMEOUT_MS);
    }

    /**
     * Sends a DNS query with custom settings.
     */
    @NonNull
    public static DnsResponse query(@NonNull String server, int port, 
                                    @NonNull DnsQuery query, int timeout) throws IOException {
        long startTime = System.currentTimeMillis();
        
        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(timeout);
            
            InetAddress address = InetAddress.getByName(server);
            byte[] queryData = query.build();
            
            DatagramPacket sendPacket = new DatagramPacket(queryData, queryData.length, address, port);
            socket.send(sendPacket);
            
            byte[] receiveData = new byte[512];
            DatagramPacket receivePacket = new DatagramPacket(receiveData, receiveData.length);
            socket.receive(receivePacket);
            
            long responseTime = System.currentTimeMillis() - startTime;
            
            return parseResponse(receiveData, receivePacket.getLength(), responseTime);
        }
    }

    /**
     * Resolves a hostname to IP addresses.
     */
    @NonNull
    public static List<String> resolve(@NonNull String hostname, @NonNull String server) 
            throws IOException {
        DnsQuery query = new DnsQuery(hostname, TYPE_A);
        DnsResponse response = query(server, query);
        
        List<String> addresses = new ArrayList<>();
        for (DnsRecord record : response.getAnswers()) {
            if (record.getType() == TYPE_A || record.getType() == TYPE_AAAA) {
                addresses.add(record.getData());
            }
        }
        
        return addresses;
    }

    /**
     * Performs reverse DNS lookup.
     */
    @Nullable
    public static String reverseLookup(@NonNull String ip, @NonNull String server) 
            throws IOException {
        String[] parts = ip.split("\\.");
        if (parts.length != 4) {
            throw new IllegalArgumentException("Invalid IPv4 address");
        }
        
        String ptrName = String.format(Locale.US, "%s.%s.%s.%s.in-addr.arpa",
                parts[3], parts[2], parts[1], parts[0]);
        
        DnsQuery query = new DnsQuery(ptrName, TYPE_PTR);
        DnsResponse response = query(server, query);
        
        for (DnsRecord record : response.getAnswers()) {
            if (record.getType() == TYPE_PTR) {
                return record.getData();
            }
        }
        
        return null;
    }

    /**
     * Gets MX records for a domain.
     */
    @NonNull
    public static List<DnsRecord> getMxRecords(@NonNull String domain, @NonNull String server) 
            throws IOException {
        DnsQuery query = new DnsQuery(domain, TYPE_MX);
        DnsResponse response = query(server, query);
        
        List<DnsRecord> mxRecords = new ArrayList<>();
        for (DnsRecord record : response.getAnswers()) {
            if (record.getType() == TYPE_MX) {
                mxRecords.add(record);
            }
        }
        
        return mxRecords;
    }

    /**
     * Gets NS records for a domain.
     */
    @NonNull
    public static List<DnsRecord> getNsRecords(@NonNull String domain, @NonNull String server) 
            throws IOException {
        DnsQuery query = new DnsQuery(domain, TYPE_NS);
        DnsResponse response = query(server, query);
        
        List<DnsRecord> nsRecords = new ArrayList<>();
        for (DnsRecord record : response.getAnswers()) {
            if (record.getType() == TYPE_NS) {
                nsRecords.add(record);
            }
        }
        
        return nsRecords;
    }

    /**
     * Gets TXT records for a domain.
     */
    @NonNull
    public static List<String> getTxtRecords(@NonNull String domain, @NonNull String server) 
            throws IOException {
        DnsQuery query = new DnsQuery(domain, TYPE_TXT);
        DnsResponse response = query(server, query);
        
        List<String> txtRecords = new ArrayList<>();
        for (DnsRecord record : response.getAnswers()) {
            if (record.getType() == TYPE_TXT) {
                txtRecords.add(record.getData());
            }
        }
        
        return txtRecords;
    }

    /**
     * Parses a DNS response packet.
     */
    @NonNull
    private static DnsResponse parseResponse(@NonNull byte[] data, int length, long responseTime) {
        ByteBuffer buffer = ByteBuffer.wrap(data, 0, length);
        buffer.order(ByteOrder.BIG_ENDIAN);

        DnsResponse.Builder builder = new DnsResponse.Builder();
        builder.setResponseTime(responseTime);

        // Header
        int transactionId = buffer.getShort() & 0xFFFF;
        int flags = buffer.getShort() & 0xFFFF;
        int questionCount = buffer.getShort() & 0xFFFF;
        int answerCount = buffer.getShort() & 0xFFFF;
        int authorityCount = buffer.getShort() & 0xFFFF;
        int additionalCount = buffer.getShort() & 0xFFFF;

        builder.setTransactionId(transactionId);
        builder.setFlags(flags);
        builder.setResponseCode(flags & 0x0F);

        // Skip questions
        for (int i = 0; i < questionCount; i++) {
            skipName(buffer);
            buffer.getShort();  // Type
            buffer.getShort();  // Class
        }

        // Parse answers
        for (int i = 0; i < answerCount; i++) {
            DnsRecord record = parseRecord(buffer, data);
            if (record != null) {
                builder.addAnswer(record);
            }
        }

        // Parse authorities
        for (int i = 0; i < authorityCount; i++) {
            DnsRecord record = parseRecord(buffer, data);
            if (record != null) {
                builder.addAuthority(record);
            }
        }

        // Parse additionals
        for (int i = 0; i < additionalCount; i++) {
            DnsRecord record = parseRecord(buffer, data);
            if (record != null) {
                builder.addAdditional(record);
            }
        }

        return builder.build();
    }

    /**
     * Parses a DNS resource record.
     */
    @Nullable
    private static DnsRecord parseRecord(@NonNull ByteBuffer buffer, @NonNull byte[] data) {
        try {
            String name = decodeName(buffer, data);
            int type = buffer.getShort() & 0xFFFF;
            int recordClass = buffer.getShort() & 0xFFFF;
            int ttl = buffer.getInt();
            int dataLength = buffer.getShort() & 0xFFFF;

            String recordData = parseRecordData(buffer, data, type, dataLength);

            return new DnsRecord(name, type, recordClass, ttl, recordData);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Parses record data based on type.
     */
    @NonNull
    private static String parseRecordData(@NonNull ByteBuffer buffer, @NonNull byte[] data, 
                                          int type, int length) {
        int startPos = buffer.position();

        switch (type) {
            case TYPE_A:
                if (length == 4) {
                    return String.format(Locale.US, "%d.%d.%d.%d",
                            buffer.get() & 0xFF, buffer.get() & 0xFF,
                            buffer.get() & 0xFF, buffer.get() & 0xFF);
                }
                break;

            case TYPE_AAAA:
                if (length == 16) {
                    StringBuilder sb = new StringBuilder();
                    for (int i = 0; i < 8; i++) {
                        if (i > 0) sb.append(':');
                        sb.append(String.format(Locale.US, "%04x", buffer.getShort() & 0xFFFF));
                    }
                    return sb.toString();
                }
                break;

            case TYPE_NS:
            case TYPE_CNAME:
            case TYPE_PTR:
                return decodeName(buffer, data);

            case TYPE_MX:
                int preference = buffer.getShort() & 0xFFFF;
                String exchange = decodeName(buffer, data);
                return String.format(Locale.US, "%d %s", preference, exchange);

            case TYPE_TXT:
                StringBuilder txt = new StringBuilder();
                int remaining = length;
                while (remaining > 0) {
                    int txtLen = buffer.get() & 0xFF;
                    remaining--;
                    byte[] txtBytes = new byte[txtLen];
                    buffer.get(txtBytes);
                    remaining -= txtLen;
                    txt.append(new String(txtBytes));
                }
                return txt.toString();

            case TYPE_SOA:
                String mname = decodeName(buffer, data);
                String rname = decodeName(buffer, data);
                int serial = buffer.getInt();
                int refresh = buffer.getInt();
                int retry = buffer.getInt();
                int expire = buffer.getInt();
                int minimum = buffer.getInt();
                return String.format(Locale.US, "%s %s %d %d %d %d %d",
                        mname, rname, serial, refresh, retry, expire, minimum);
        }

        // Skip unknown types
        buffer.position(startPos + length);
        return "[unknown data]";
    }

    /**
     * Decodes a DNS name with compression support.
     */
    @NonNull
    private static String decodeName(@NonNull ByteBuffer buffer, @NonNull byte[] data) {
        StringBuilder name = new StringBuilder();
        int length;
        boolean jumped = false;
        int savedPos = -1;

        while ((length = buffer.get() & 0xFF) != 0) {
            // Check for compression pointer
            if ((length & 0xC0) == 0xC0) {
                if (!jumped) {
                    savedPos = buffer.position();
                }
                int offset = ((length & 0x3F) << 8) | (buffer.get() & 0xFF);
                buffer.position(offset);
                jumped = true;
            } else {
                if (name.length() > 0) {
                    name.append('.');
                }
                byte[] label = new byte[length];
                buffer.get(label);
                name.append(new String(label));
            }
        }

        if (savedPos != -1) {
            buffer.position(savedPos + 1);
        }

        return name.toString();
    }

    /**
     * Skips a DNS name in the buffer.
     */
    private static void skipName(@NonNull ByteBuffer buffer) {
        int length;
        while ((length = buffer.get() & 0xFF) != 0) {
            if ((length & 0xC0) == 0xC0) {
                buffer.get();  // Skip second byte of pointer
                return;
            }
            buffer.position(buffer.position() + length);
        }
    }

    /**
     * Gets type name from type code.
     */
    @NonNull
    public static String getTypeName(int type) {
        switch (type) {
            case TYPE_A: return "A";
            case TYPE_NS: return "NS";
            case TYPE_CNAME: return "CNAME";
            case TYPE_SOA: return "SOA";
            case TYPE_PTR: return "PTR";
            case TYPE_MX: return "MX";
            case TYPE_TXT: return "TXT";
            case TYPE_AAAA: return "AAAA";
            case TYPE_SRV: return "SRV";
            case TYPE_ANY: return "ANY";
            default: return String.format(Locale.US, "TYPE%d", type);
        }
    }

    /**
     * Gets class name from class code.
     */
    @NonNull
    public static String getClassName(int queryClass) {
        switch (queryClass) {
            case CLASS_IN: return "IN";
            case CLASS_CH: return "CH";
            case CLASS_HS: return "HS";
            case CLASS_ANY: return "ANY";
            default: return String.format(Locale.US, "CLASS%d", queryClass);
        }
    }

    /**
     * Gets response code name.
     */
    @NonNull
    public static String getResponseCodeName(int rcode) {
        switch (rcode) {
            case RCODE_NO_ERROR: return "NOERROR";
            case RCODE_FORMAT_ERROR: return "FORMERR";
            case RCODE_SERVER_FAILURE: return "SERVFAIL";
            case RCODE_NAME_ERROR: return "NXDOMAIN";
            case RCODE_NOT_IMPLEMENTED: return "NOTIMP";
            case RCODE_REFUSED: return "REFUSED";
            default: return String.format(Locale.US, "RCODE%d", rcode);
        }
    }

    /**
     * Tests if a DNS server supports zone transfers (AXFR).
     */
    public static boolean supportsZoneTransfer(@NonNull String domain, @NonNull String server) {
        // AXFR requires TCP, simplified check
        return false;  // Not implemented - would require TCP DNS
    }

    /**
     * Tests if a DNS server is recursive.
     */
    public static boolean isRecursive(@NonNull String server) {
        try {
            DnsQuery query = new DnsQuery("google.com", TYPE_A);
            DnsResponse response = query(server, query);
            return response.isRecursionAvailable();
        } catch (IOException e) {
            return false;
        }
    }

    /**
     * Generates DNS analysis report.
     */
    @NonNull
    public static String generateReport(@NonNull DnsResponse response) {
        StringBuilder report = new StringBuilder();

        report.append("DNS Response Analysis\n");
        report.append("=====================\n\n");

        report.append("Transaction ID: 0x").append(String.format(Locale.US, "%04X", response.getTransactionId())).append("\n");
        report.append("Response Code: ").append(response.getResponseCodeName()).append("\n");
        report.append("Response Time: ").append(response.getResponseTime()).append(" ms\n");
        report.append("Authoritative: ").append(response.isAuthoritative() ? "Yes" : "No").append("\n");
        report.append("Truncated: ").append(response.isTruncated() ? "Yes" : "No").append("\n");
        report.append("Recursion Available: ").append(response.isRecursionAvailable() ? "Yes" : "No").append("\n\n");

        List<DnsRecord> answers = response.getAnswers();
        if (!answers.isEmpty()) {
            report.append("Answers (").append(answers.size()).append("):\n");
            for (DnsRecord record : answers) {
                report.append("  ").append(record.toString()).append("\n");
            }
            report.append("\n");
        }

        List<DnsRecord> authorities = response.getAuthorities();
        if (!authorities.isEmpty()) {
            report.append("Authority Records (").append(authorities.size()).append("):\n");
            for (DnsRecord record : authorities) {
                report.append("  ").append(record.toString()).append("\n");
            }
            report.append("\n");
        }

        List<DnsRecord> additionals = response.getAdditionals();
        if (!additionals.isEmpty()) {
            report.append("Additional Records (").append(additionals.size()).append("):\n");
            for (DnsRecord record : additionals) {
                report.append("  ").append(record.toString()).append("\n");
            }
        }

        return report.toString();
    }
}
