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
import java.util.Date;
import java.util.HashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * Helper class for SNMP protocol operations and analysis.
 * Provides utilities for SNMP queries, community string testing,
 * and device enumeration.
 */
public final class SnmpHelper {

    private static final String TAG = "SnmpHelper";

    // Default SNMP port
    public static final int DEFAULT_SNMP_PORT = 161;
    public static final int DEFAULT_TRAP_PORT = 162;
    public static final int DEFAULT_TIMEOUT_MS = 5000;

    // SNMP versions
    public static final int VERSION_1 = 0;
    public static final int VERSION_2C = 1;
    public static final int VERSION_3 = 3;

    // ASN.1 BER types
    public static final byte ASN_INTEGER = 0x02;
    public static final byte ASN_OCTET_STRING = 0x04;
    public static final byte ASN_NULL = 0x05;
    public static final byte ASN_OBJECT_ID = 0x06;
    public static final byte ASN_SEQUENCE = 0x30;

    // SNMP specific types
    public static final byte SNMP_IPADDRESS = (byte) 0x40;
    public static final byte SNMP_COUNTER = (byte) 0x41;
    public static final byte SNMP_GAUGE = (byte) 0x42;
    public static final byte SNMP_TIMETICKS = (byte) 0x43;
    public static final byte SNMP_OPAQUE = (byte) 0x44;
    public static final byte SNMP_COUNTER64 = (byte) 0x46;

    // PDU types
    public static final byte PDU_GET_REQUEST = (byte) 0xA0;
    public static final byte PDU_GET_NEXT_REQUEST = (byte) 0xA1;
    public static final byte PDU_GET_RESPONSE = (byte) 0xA2;
    public static final byte PDU_SET_REQUEST = (byte) 0xA3;
    public static final byte PDU_TRAP = (byte) 0xA4;
    public static final byte PDU_GET_BULK_REQUEST = (byte) 0xA5;
    public static final byte PDU_INFORM_REQUEST = (byte) 0xA6;
    public static final byte PDU_TRAP_V2 = (byte) 0xA7;

    // Error status codes
    public static final int ERROR_NO_ERROR = 0;
    public static final int ERROR_TOO_BIG = 1;
    public static final int ERROR_NO_SUCH_NAME = 2;
    public static final int ERROR_BAD_VALUE = 3;
    public static final int ERROR_READ_ONLY = 4;
    public static final int ERROR_GENERAL_ERROR = 5;
    public static final int ERROR_NO_ACCESS = 6;
    public static final int ERROR_WRONG_TYPE = 7;
    public static final int ERROR_WRONG_LENGTH = 8;
    public static final int ERROR_WRONG_ENCODING = 9;
    public static final int ERROR_WRONG_VALUE = 10;
    public static final int ERROR_NO_CREATION = 11;
    public static final int ERROR_INCONSISTENT_VALUE = 12;
    public static final int ERROR_RESOURCE_UNAVAILABLE = 13;
    public static final int ERROR_COMMIT_FAILED = 14;
    public static final int ERROR_UNDO_FAILED = 15;
    public static final int ERROR_AUTHORIZATION_ERROR = 16;
    public static final int ERROR_NOT_WRITABLE = 17;
    public static final int ERROR_INCONSISTENT_NAME = 18;

    // Common OIDs
    public static final String OID_SYSTEM = "1.3.6.1.2.1.1";
    public static final String OID_SYS_DESCR = "1.3.6.1.2.1.1.1.0";
    public static final String OID_SYS_OBJECT_ID = "1.3.6.1.2.1.1.2.0";
    public static final String OID_SYS_UPTIME = "1.3.6.1.2.1.1.3.0";
    public static final String OID_SYS_CONTACT = "1.3.6.1.2.1.1.4.0";
    public static final String OID_SYS_NAME = "1.3.6.1.2.1.1.5.0";
    public static final String OID_SYS_LOCATION = "1.3.6.1.2.1.1.6.0";
    public static final String OID_SYS_SERVICES = "1.3.6.1.2.1.1.7.0";
    public static final String OID_INTERFACES = "1.3.6.1.2.1.2";
    public static final String OID_IF_NUMBER = "1.3.6.1.2.1.2.1.0";

    // Common community strings to test
    private static final String[] COMMON_COMMUNITIES = {
            "public", "private", "community", "admin", "manager",
            "default", "snmp", "monitor", "test", "guest",
            "cisco", "router", "switch", "secret", "write",
            "read", "net", "network", "system", "security"
    };

    private static int requestId = 0;

    private SnmpHelper() {
        // Private constructor to prevent instantiation
    }

    /**
     * Represents an SNMP variable binding.
     */
    public static class VarBind {
        private final String oid;
        private final byte type;
        private final Object value;

        public VarBind(@NonNull String oid, byte type, @Nullable Object value) {
            this.oid = oid;
            this.type = type;
            this.value = value;
        }

        @NonNull
        public String getOid() {
            return oid;
        }

        public byte getType() {
            return type;
        }

        @Nullable
        public Object getValue() {
            return value;
        }

        @NonNull
        public String getValueString() {
            if (value == null) {
                return "null";
            }
            if (value instanceof byte[]) {
                return new String((byte[]) value);
            }
            return value.toString();
        }

        @Override
        public String toString() {
            return String.format(Locale.US, "%s = %s", oid, getValueString());
        }
    }

    /**
     * Represents an SNMP response.
     */
    public static class SnmpResponse {
        private final int version;
        private final String community;
        private final int requestId;
        private final int errorStatus;
        private final int errorIndex;
        private final List<VarBind> varBinds;
        private final long responseTime;

        private SnmpResponse(Builder builder) {
            this.version = builder.version;
            this.community = builder.community;
            this.requestId = builder.requestId;
            this.errorStatus = builder.errorStatus;
            this.errorIndex = builder.errorIndex;
            this.varBinds = new ArrayList<>(builder.varBinds);
            this.responseTime = builder.responseTime;
        }

        public int getVersion() {
            return version;
        }

        @NonNull
        public String getCommunity() {
            return community;
        }

        public int getRequestId() {
            return requestId;
        }

        public int getErrorStatus() {
            return errorStatus;
        }

        public int getErrorIndex() {
            return errorIndex;
        }

        public boolean isSuccess() {
            return errorStatus == ERROR_NO_ERROR;
        }

        @NonNull
        public List<VarBind> getVarBinds() {
            return Collections.unmodifiableList(varBinds);
        }

        public long getResponseTime() {
            return responseTime;
        }

        @NonNull
        public String getErrorName() {
            return SnmpHelper.getErrorName(errorStatus);
        }

        public static class Builder {
            private int version;
            private String community = "";
            private int requestId;
            private int errorStatus;
            private int errorIndex;
            private List<VarBind> varBinds = new ArrayList<>();
            private long responseTime;

            public Builder setVersion(int version) {
                this.version = version;
                return this;
            }

            public Builder setCommunity(String community) {
                this.community = community;
                return this;
            }

            public Builder setRequestId(int requestId) {
                this.requestId = requestId;
                return this;
            }

            public Builder setErrorStatus(int errorStatus) {
                this.errorStatus = errorStatus;
                return this;
            }

            public Builder setErrorIndex(int errorIndex) {
                this.errorIndex = errorIndex;
                return this;
            }

            public Builder addVarBind(VarBind varBind) {
                this.varBinds.add(varBind);
                return this;
            }

            public Builder setResponseTime(long responseTime) {
                this.responseTime = responseTime;
                return this;
            }

            public SnmpResponse build() {
                return new SnmpResponse(this);
            }
        }
    }

    /**
     * Represents SNMP device information.
     */
    public static class DeviceInfo {
        private final String description;
        private final String objectId;
        private final long uptime;
        private final String contact;
        private final String name;
        private final String location;
        private final int services;
        private final String community;
        private final Map<String, String> additionalInfo;

        private DeviceInfo(Builder builder) {
            this.description = builder.description;
            this.objectId = builder.objectId;
            this.uptime = builder.uptime;
            this.contact = builder.contact;
            this.name = builder.name;
            this.location = builder.location;
            this.services = builder.services;
            this.community = builder.community;
            this.additionalInfo = new HashMap<>(builder.additionalInfo);
        }

        @Nullable
        public String getDescription() {
            return description;
        }

        @Nullable
        public String getObjectId() {
            return objectId;
        }

        public long getUptime() {
            return uptime;
        }

        @NonNull
        public String getUptimeString() {
            if (uptime <= 0) {
                return "Unknown";
            }
            long seconds = uptime / 100;
            long days = seconds / 86400;
            long hours = (seconds % 86400) / 3600;
            long minutes = (seconds % 3600) / 60;
            long secs = seconds % 60;
            return String.format(Locale.US, "%d days, %02d:%02d:%02d", days, hours, minutes, secs);
        }

        @Nullable
        public String getContact() {
            return contact;
        }

        @Nullable
        public String getName() {
            return name;
        }

        @Nullable
        public String getLocation() {
            return location;
        }

        public int getServices() {
            return services;
        }

        @Nullable
        public String getCommunity() {
            return community;
        }

        @NonNull
        public Map<String, String> getAdditionalInfo() {
            return Collections.unmodifiableMap(additionalInfo);
        }

        public static class Builder {
            private String description;
            private String objectId;
            private long uptime;
            private String contact;
            private String name;
            private String location;
            private int services;
            private String community;
            private Map<String, String> additionalInfo = new HashMap<>();

            public Builder setDescription(String description) {
                this.description = description;
                return this;
            }

            public Builder setObjectId(String objectId) {
                this.objectId = objectId;
                return this;
            }

            public Builder setUptime(long uptime) {
                this.uptime = uptime;
                return this;
            }

            public Builder setContact(String contact) {
                this.contact = contact;
                return this;
            }

            public Builder setName(String name) {
                this.name = name;
                return this;
            }

            public Builder setLocation(String location) {
                this.location = location;
                return this;
            }

            public Builder setServices(int services) {
                this.services = services;
                return this;
            }

            public Builder setCommunity(String community) {
                this.community = community;
                return this;
            }

            public Builder addInfo(String key, String value) {
                this.additionalInfo.put(key, value);
                return this;
            }

            public DeviceInfo build() {
                return new DeviceInfo(this);
            }
        }
    }

    /**
     * Performs an SNMP GET request.
     */
    @NonNull
    public static SnmpResponse get(@NonNull String host, @NonNull String community, 
                                    @NonNull String oid) throws IOException {
        return get(host, DEFAULT_SNMP_PORT, community, oid, DEFAULT_TIMEOUT_MS);
    }

    /**
     * Performs an SNMP GET request with custom settings.
     */
    @NonNull
    public static SnmpResponse get(@NonNull String host, int port, @NonNull String community,
                                    @NonNull String oid, int timeout) throws IOException {
        return query(host, port, community, oid, PDU_GET_REQUEST, timeout);
    }

    /**
     * Performs an SNMP GET-NEXT request.
     */
    @NonNull
    public static SnmpResponse getNext(@NonNull String host, @NonNull String community,
                                        @NonNull String oid) throws IOException {
        return query(host, DEFAULT_SNMP_PORT, community, oid, PDU_GET_NEXT_REQUEST, DEFAULT_TIMEOUT_MS);
    }

    /**
     * Performs an SNMP query.
     */
    @NonNull
    private static SnmpResponse query(@NonNull String host, int port, @NonNull String community,
                                       @NonNull String oid, byte pduType, int timeout) 
            throws IOException {
        long startTime = System.currentTimeMillis();
        int reqId = ++requestId;

        byte[] packet = buildGetRequest(community, oid, pduType, reqId);

        try (DatagramSocket socket = new DatagramSocket()) {
            socket.setSoTimeout(timeout);

            InetAddress address = InetAddress.getByName(host);
            DatagramPacket sendPacket = new DatagramPacket(packet, packet.length, address, port);
            socket.send(sendPacket);

            byte[] receiveData = new byte[65535];
            DatagramPacket receivePacket = new DatagramPacket(receiveData, receiveData.length);
            socket.receive(receivePacket);

            long responseTime = System.currentTimeMillis() - startTime;

            return parseResponse(receiveData, receivePacket.getLength(), community, responseTime);
        }
    }

    /**
     * Builds an SNMP GET request packet.
     */
    @NonNull
    private static byte[] buildGetRequest(@NonNull String community, @NonNull String oid,
                                          byte pduType, int requestId) {
        ByteBuffer buffer = ByteBuffer.allocate(512);

        // Build from inside out
        // OID
        byte[] oidBytes = encodeOid(oid);
        
        // VarBind: SEQUENCE { oid, NULL }
        byte[] varBind = buildSequence(concat(oidBytes, new byte[]{ASN_NULL, 0}));
        
        // VarBindList: SEQUENCE { varBind }
        byte[] varBindList = buildSequence(varBind);
        
        // PDU content: requestId, error-status, error-index, varBindList
        byte[] reqIdBytes = encodeInteger(requestId);
        byte[] errorStatus = encodeInteger(0);
        byte[] errorIndex = encodeInteger(0);
        byte[] pduContent = concat(reqIdBytes, errorStatus, errorIndex, varBindList);
        
        // PDU
        byte[] pdu = buildTlv(pduType, pduContent);
        
        // Community
        byte[] communityBytes = buildTlv(ASN_OCTET_STRING, community.getBytes());
        
        // Version (0 = SNMPv1, 1 = SNMPv2c)
        byte[] versionBytes = encodeInteger(VERSION_2C);
        
        // Message: SEQUENCE { version, community, pdu }
        byte[] message = buildSequence(concat(versionBytes, communityBytes, pdu));

        return message;
    }

    /**
     * Parses an SNMP response.
     */
    @NonNull
    private static SnmpResponse parseResponse(@NonNull byte[] data, int length,
                                               @NonNull String community, long responseTime) {
        SnmpResponse.Builder builder = new SnmpResponse.Builder();
        builder.setCommunity(community);
        builder.setResponseTime(responseTime);

        try {
            ByteBuffer buffer = ByteBuffer.wrap(data, 0, length);
            
            // Message SEQUENCE
            readTlv(buffer);  // Tag and length
            
            // Version
            int version = (int) readInteger(buffer);
            builder.setVersion(version);
            
            // Community
            readOctetString(buffer);
            
            // PDU
            byte pduTag = buffer.get();
            int pduLength = readLength(buffer);
            
            // Request ID
            int reqId = (int) readInteger(buffer);
            builder.setRequestId(reqId);
            
            // Error status
            int errorStatus = (int) readInteger(buffer);
            builder.setErrorStatus(errorStatus);
            
            // Error index
            int errorIndex = (int) readInteger(buffer);
            builder.setErrorIndex(errorIndex);
            
            // VarBindList
            readTlv(buffer);  // SEQUENCE tag and length
            
            // Parse VarBinds
            while (buffer.hasRemaining()) {
                try {
                    VarBind varBind = parseVarBind(buffer);
                    if (varBind != null) {
                        builder.addVarBind(varBind);
                    }
                } catch (Exception e) {
                    break;
                }
            }
        } catch (Exception e) {
            // Parsing error - return partial result
        }

        return builder.build();
    }

    /**
     * Parses a VarBind.
     */
    @Nullable
    private static VarBind parseVarBind(@NonNull ByteBuffer buffer) {
        try {
            // VarBind SEQUENCE
            readTlv(buffer);
            
            // OID
            String oid = readOid(buffer);
            
            // Value
            byte type = buffer.get();
            int length = readLength(buffer);
            
            Object value = null;
            switch (type) {
                case ASN_INTEGER:
                case SNMP_COUNTER:
                case SNMP_GAUGE:
                case SNMP_TIMETICKS:
                    value = readIntegerValue(buffer, length);
                    break;
                case ASN_OCTET_STRING:
                case SNMP_IPADDRESS:
                case SNMP_OPAQUE:
                    byte[] bytes = new byte[length];
                    buffer.get(bytes);
                    value = bytes;
                    break;
                case ASN_OBJECT_ID:
                    value = readOidValue(buffer, length);
                    break;
                case ASN_NULL:
                    value = null;
                    break;
                default:
                    buffer.position(buffer.position() + length);
                    break;
            }
            
            return new VarBind(oid, type, value);
        } catch (Exception e) {
            return null;
        }
    }

    /**
     * Tests if a community string is valid.
     */
    public static boolean testCommunity(@NonNull String host, @NonNull String community) {
        return testCommunity(host, DEFAULT_SNMP_PORT, community, DEFAULT_TIMEOUT_MS);
    }

    /**
     * Tests if a community string is valid with custom settings.
     */
    public static boolean testCommunity(@NonNull String host, int port, 
                                        @NonNull String community, int timeout) {
        try {
            SnmpResponse response = get(host, port, community, OID_SYS_DESCR, timeout);
            return response.isSuccess() && !response.getVarBinds().isEmpty();
        } catch (IOException e) {
            return false;
        }
    }

    /**
     * Discovers valid community strings.
     */
    @NonNull
    public static List<String> discoverCommunities(@NonNull String host) {
        return discoverCommunities(host, DEFAULT_SNMP_PORT, DEFAULT_TIMEOUT_MS);
    }

    /**
     * Discovers valid community strings with custom settings.
     */
    @NonNull
    public static List<String> discoverCommunities(@NonNull String host, int port, int timeout) {
        List<String> validCommunities = new ArrayList<>();
        
        for (String community : COMMON_COMMUNITIES) {
            if (testCommunity(host, port, community, timeout)) {
                validCommunities.add(community);
            }
        }
        
        return validCommunities;
    }

    /**
     * Gets device information.
     */
    @NonNull
    public static DeviceInfo getDeviceInfo(@NonNull String host, @NonNull String community) 
            throws IOException {
        DeviceInfo.Builder builder = new DeviceInfo.Builder();
        builder.setCommunity(community);

        try {
            SnmpResponse descr = get(host, community, OID_SYS_DESCR);
            if (descr.isSuccess() && !descr.getVarBinds().isEmpty()) {
                builder.setDescription(descr.getVarBinds().get(0).getValueString());
            }
        } catch (IOException e) {
            LoggingHelper.d(TAG, "Failed to get SNMP description: " + e.getMessage());
        }

        try {
            SnmpResponse name = get(host, community, OID_SYS_NAME);
            if (name.isSuccess() && !name.getVarBinds().isEmpty()) {
                builder.setName(name.getVarBinds().get(0).getValueString());
            }
        } catch (IOException e) {
            LoggingHelper.d(TAG, "Failed to get SNMP name: " + e.getMessage());
        }

        try {
            SnmpResponse uptime = get(host, community, OID_SYS_UPTIME);
            if (uptime.isSuccess() && !uptime.getVarBinds().isEmpty()) {
                Object value = uptime.getVarBinds().get(0).getValue();
                if (value instanceof Long) {
                    builder.setUptime((Long) value);
                }
            }
        } catch (IOException e) {
            LoggingHelper.d(TAG, "Failed to get SNMP uptime: " + e.getMessage());
        }

        try {
            SnmpResponse location = get(host, community, OID_SYS_LOCATION);
            if (location.isSuccess() && !location.getVarBinds().isEmpty()) {
                builder.setLocation(location.getVarBinds().get(0).getValueString());
            }
        } catch (IOException e) {
            LoggingHelper.d(TAG, "Failed to get SNMP location: " + e.getMessage());
        }

        try {
            SnmpResponse contact = get(host, community, OID_SYS_CONTACT);
            if (contact.isSuccess() && !contact.getVarBinds().isEmpty()) {
                builder.setContact(contact.getVarBinds().get(0).getValueString());
            }
        } catch (IOException e) {
            LoggingHelper.d(TAG, "Failed to get SNMP contact: " + e.getMessage());
        }

        return builder.build();
    }

    // Helper methods for encoding/decoding

    private static byte[] encodeInteger(long value) {
        ByteBuffer buffer = ByteBuffer.allocate(16);
        buffer.put(ASN_INTEGER);
        
        if (value == 0) {
            buffer.put((byte) 1);
            buffer.put((byte) 0);
        } else {
            int bytes = (64 - Long.numberOfLeadingZeros(value) + 8) / 8;
            buffer.put((byte) bytes);
            for (int i = bytes - 1; i >= 0; i--) {
                buffer.put((byte) ((value >> (i * 8)) & 0xFF));
            }
        }
        
        byte[] result = new byte[buffer.position()];
        buffer.flip();
        buffer.get(result);
        return result;
    }

    private static byte[] encodeOid(String oid) {
        String[] parts = oid.split("\\.");
        ByteBuffer buffer = ByteBuffer.allocate(128);
        
        // First two numbers are encoded specially
        int first = Integer.parseInt(parts[0]);
        int second = Integer.parseInt(parts[1]);
        buffer.put((byte) (first * 40 + second));
        
        for (int i = 2; i < parts.length; i++) {
            int value = Integer.parseInt(parts[i]);
            encodeOidComponent(buffer, value);
        }
        
        byte[] oidContent = new byte[buffer.position()];
        buffer.flip();
        buffer.get(oidContent);
        
        return buildTlv(ASN_OBJECT_ID, oidContent);
    }

    private static void encodeOidComponent(ByteBuffer buffer, int value) {
        if (value < 128) {
            buffer.put((byte) value);
        } else {
            int numBytes = (32 - Integer.numberOfLeadingZeros(value) + 6) / 7;
            for (int i = numBytes - 1; i >= 0; i--) {
                byte b = (byte) ((value >> (i * 7)) & 0x7F);
                if (i > 0) {
                    b |= 0x80;
                }
                buffer.put(b);
            }
        }
    }

    private static byte[] buildTlv(byte tag, byte[] content) {
        ByteBuffer buffer = ByteBuffer.allocate(content.length + 4);
        buffer.put(tag);
        encodeLength(buffer, content.length);
        buffer.put(content);
        
        byte[] result = new byte[buffer.position()];
        buffer.flip();
        buffer.get(result);
        return result;
    }

    private static byte[] buildSequence(byte[] content) {
        return buildTlv(ASN_SEQUENCE, content);
    }

    private static void encodeLength(ByteBuffer buffer, int length) {
        if (length < 128) {
            buffer.put((byte) length);
        } else if (length < 256) {
            buffer.put((byte) 0x81);
            buffer.put((byte) length);
        } else {
            buffer.put((byte) 0x82);
            buffer.putShort((short) length);
        }
    }

    private static byte[] concat(byte[]... arrays) {
        int totalLength = 0;
        for (byte[] array : arrays) {
            totalLength += array.length;
        }
        
        byte[] result = new byte[totalLength];
        int pos = 0;
        for (byte[] array : arrays) {
            System.arraycopy(array, 0, result, pos, array.length);
            pos += array.length;
        }
        return result;
    }

    private static void readTlv(ByteBuffer buffer) {
        buffer.get();  // tag
        readLength(buffer);
    }

    private static int readLength(ByteBuffer buffer) {
        int firstByte = buffer.get() & 0xFF;
        if (firstByte < 128) {
            return firstByte;
        }
        int numBytes = firstByte & 0x7F;
        int length = 0;
        for (int i = 0; i < numBytes; i++) {
            length = (length << 8) | (buffer.get() & 0xFF);
        }
        return length;
    }

    private static long readInteger(ByteBuffer buffer) {
        buffer.get();  // tag
        int length = readLength(buffer);
        return readIntegerValue(buffer, length);
    }

    private static long readIntegerValue(ByteBuffer buffer, int length) {
        long value = 0;
        for (int i = 0; i < length; i++) {
            value = (value << 8) | (buffer.get() & 0xFF);
        }
        return value;
    }

    private static String readOctetString(ByteBuffer buffer) {
        buffer.get();  // tag
        int length = readLength(buffer);
        byte[] bytes = new byte[length];
        buffer.get(bytes);
        return new String(bytes);
    }

    private static String readOid(ByteBuffer buffer) {
        buffer.get();  // tag
        int length = readLength(buffer);
        return readOidValue(buffer, length);
    }

    private static String readOidValue(ByteBuffer buffer, int length) {
        StringBuilder oid = new StringBuilder();
        int endPos = buffer.position() + length;
        
        // First byte encodes first two components
        int firstByte = buffer.get() & 0xFF;
        oid.append(firstByte / 40).append('.').append(firstByte % 40);
        
        while (buffer.position() < endPos) {
            int value = 0;
            byte b;
            do {
                b = buffer.get();
                value = (value << 7) | (b & 0x7F);
            } while ((b & 0x80) != 0);
            oid.append('.').append(value);
        }
        
        return oid.toString();
    }

    /**
     * Gets error name from error code.
     */
    @NonNull
    public static String getErrorName(int errorStatus) {
        switch (errorStatus) {
            case ERROR_NO_ERROR: return "noError";
            case ERROR_TOO_BIG: return "tooBig";
            case ERROR_NO_SUCH_NAME: return "noSuchName";
            case ERROR_BAD_VALUE: return "badValue";
            case ERROR_READ_ONLY: return "readOnly";
            case ERROR_GENERAL_ERROR: return "genErr";
            case ERROR_NO_ACCESS: return "noAccess";
            case ERROR_WRONG_TYPE: return "wrongType";
            case ERROR_WRONG_LENGTH: return "wrongLength";
            case ERROR_AUTHORIZATION_ERROR: return "authorizationError";
            default: return String.format(Locale.US, "error(%d)", errorStatus);
        }
    }

    /**
     * Generates SNMP report.
     */
    @NonNull
    public static String generateReport(@NonNull DeviceInfo deviceInfo) {
        StringBuilder report = new StringBuilder();

        report.append("SNMP Device Information\n");
        report.append("=======================\n\n");

        if (deviceInfo.getName() != null) {
            report.append("Name: ").append(deviceInfo.getName()).append("\n");
        }
        if (deviceInfo.getDescription() != null) {
            report.append("Description: ").append(deviceInfo.getDescription()).append("\n");
        }
        if (deviceInfo.getLocation() != null) {
            report.append("Location: ").append(deviceInfo.getLocation()).append("\n");
        }
        if (deviceInfo.getContact() != null) {
            report.append("Contact: ").append(deviceInfo.getContact()).append("\n");
        }
        report.append("Uptime: ").append(deviceInfo.getUptimeString()).append("\n");
        if (deviceInfo.getCommunity() != null) {
            report.append("Community: ").append(deviceInfo.getCommunity()).append("\n");
        }

        return report.toString();
    }

    /**
     * Checks for vulnerabilities.
     */
    @NonNull
    public static List<String> checkVulnerabilities(@NonNull String host, @NonNull String community) {
        List<String> vulnerabilities = new ArrayList<>();

        // Check for default community
        if ("public".equals(community) || "private".equals(community)) {
            vulnerabilities.add("Default community string '" + community + "' in use");
        }

        // Check for write access
        if ("private".equals(community)) {
            vulnerabilities.add("Write-enabled community string detected");
        }

        // SNMP v1/v2c is inherently insecure
        vulnerabilities.add("SNMP v1/v2c transmits community strings in cleartext");
        vulnerabilities.add("Consider upgrading to SNMPv3 with authentication and encryption");

        return vulnerabilities;
    }
}
