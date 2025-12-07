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
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Helper class for LDAP protocol operations and analysis.
 * Provides utilities for LDAP enumeration, anonymous binding,
 * and directory information gathering.
 */
public final class LdapHelper {

    private static final String TAG = "LdapHelper";

    // Default LDAP ports
    public static final int DEFAULT_LDAP_PORT = 389;
    public static final int DEFAULT_LDAPS_PORT = 636;
    public static final int DEFAULT_TIMEOUT_MS = 10000;

    // LDAP protocol version
    public static final int LDAP_VERSION_3 = 3;

    // LDAP operation codes
    public static final int OP_BIND_REQUEST = 0;
    public static final int OP_BIND_RESPONSE = 1;
    public static final int OP_UNBIND_REQUEST = 2;
    public static final int OP_SEARCH_REQUEST = 3;
    public static final int OP_SEARCH_RESULT_ENTRY = 4;
    public static final int OP_SEARCH_RESULT_DONE = 5;
    public static final int OP_MODIFY_REQUEST = 6;
    public static final int OP_MODIFY_RESPONSE = 7;
    public static final int OP_ADD_REQUEST = 8;
    public static final int OP_ADD_RESPONSE = 9;
    public static final int OP_DELETE_REQUEST = 10;
    public static final int OP_DELETE_RESPONSE = 11;

    // Search scope
    public static final int SCOPE_BASE = 0;
    public static final int SCOPE_ONE_LEVEL = 1;
    public static final int SCOPE_SUBTREE = 2;

    // LDAP result codes
    public static final int RESULT_SUCCESS = 0;
    public static final int RESULT_OPERATIONS_ERROR = 1;
    public static final int RESULT_PROTOCOL_ERROR = 2;
    public static final int RESULT_TIME_LIMIT_EXCEEDED = 3;
    public static final int RESULT_SIZE_LIMIT_EXCEEDED = 4;
    public static final int RESULT_AUTH_METHOD_NOT_SUPPORTED = 7;
    public static final int RESULT_STRONGER_AUTH_REQUIRED = 8;
    public static final int RESULT_NO_SUCH_OBJECT = 32;
    public static final int RESULT_INVALID_CREDENTIALS = 49;
    public static final int RESULT_INSUFFICIENT_ACCESS = 50;
    public static final int RESULT_UNWILLING_TO_PERFORM = 53;

    // Common LDAP attributes
    public static final String ATTR_NAMING_CONTEXTS = "namingContexts";
    public static final String ATTR_DEFAULT_NAMING_CONTEXT = "defaultNamingContext";
    public static final String ATTR_ROOT_DOMAIN_NAMING_CONTEXT = "rootDomainNamingContext";
    public static final String ATTR_SUPPORTED_LDAP_VERSION = "supportedLDAPVersion";
    public static final String ATTR_SUPPORTED_CONTROLS = "supportedControl";
    public static final String ATTR_SUPPORTED_EXTENSIONS = "supportedExtension";
    public static final String ATTR_SUPPORTED_SASL_MECHANISMS = "supportedSASLMechanisms";
    public static final String ATTR_DNS_HOST_NAME = "dnsHostName";
    public static final String ATTR_LDAP_SERVICE_NAME = "ldapServiceName";
    public static final String ATTR_SERVER_NAME = "serverName";
    public static final String ATTR_CURRENT_TIME = "currentTime";
    public static final String ATTR_FOREST_FUNCTIONALITY = "forestFunctionality";
    public static final String ATTR_DOMAIN_FUNCTIONALITY = "domainFunctionality";
    public static final String ATTR_DOMAIN_CONTROLLER_FUNCTIONALITY = "domainControllerFunctionality";

    // Common OIDs
    public static final String OID_PAGED_RESULTS = "1.2.840.113556.1.4.319";
    public static final String OID_SECURITY_DESCRIPTOR = "1.2.840.113556.1.4.801";
    public static final String OID_DOMAIN_SCOPE = "1.2.840.113556.1.4.1339";
    public static final String OID_SEARCH_OPTIONS = "1.2.840.113556.1.4.1340";
    public static final String OID_PASSWORD_POLICY = "1.3.6.1.4.1.42.2.27.8.5.1";

    private LdapHelper() {
        // Private constructor to prevent instantiation
    }

    /**
     * Represents LDAP server root DSE information.
     */
    public static class RootDse {
        private final List<String> namingContexts;
        private final String defaultNamingContext;
        private final List<Integer> supportedLdapVersions;
        private final List<String> supportedControls;
        private final List<String> supportedExtensions;
        private final List<String> supportedSaslMechanisms;
        private final String dnsHostName;
        private final String serverName;
        private final String ldapServiceName;
        private final String currentTime;
        private final Map<String, String> additionalAttributes;

        private RootDse(Builder builder) {
            this.namingContexts = new ArrayList<>(builder.namingContexts);
            this.defaultNamingContext = builder.defaultNamingContext;
            this.supportedLdapVersions = new ArrayList<>(builder.supportedLdapVersions);
            this.supportedControls = new ArrayList<>(builder.supportedControls);
            this.supportedExtensions = new ArrayList<>(builder.supportedExtensions);
            this.supportedSaslMechanisms = new ArrayList<>(builder.supportedSaslMechanisms);
            this.dnsHostName = builder.dnsHostName;
            this.serverName = builder.serverName;
            this.ldapServiceName = builder.ldapServiceName;
            this.currentTime = builder.currentTime;
            this.additionalAttributes = new HashMap<>(builder.additionalAttributes);
        }

        @NonNull
        public List<String> getNamingContexts() {
            return Collections.unmodifiableList(namingContexts);
        }

        @Nullable
        public String getDefaultNamingContext() {
            return defaultNamingContext;
        }

        @NonNull
        public List<Integer> getSupportedLdapVersions() {
            return Collections.unmodifiableList(supportedLdapVersions);
        }

        @NonNull
        public List<String> getSupportedControls() {
            return Collections.unmodifiableList(supportedControls);
        }

        @NonNull
        public List<String> getSupportedExtensions() {
            return Collections.unmodifiableList(supportedExtensions);
        }

        @NonNull
        public List<String> getSupportedSaslMechanisms() {
            return Collections.unmodifiableList(supportedSaslMechanisms);
        }

        @Nullable
        public String getDnsHostName() {
            return dnsHostName;
        }

        @Nullable
        public String getServerName() {
            return serverName;
        }

        @Nullable
        public String getLdapServiceName() {
            return ldapServiceName;
        }

        @Nullable
        public String getCurrentTime() {
            return currentTime;
        }

        @NonNull
        public Map<String, String> getAdditionalAttributes() {
            return Collections.unmodifiableMap(additionalAttributes);
        }

        public boolean isActiveDirectory() {
            return defaultNamingContext != null || 
                   (ldapServiceName != null && ldapServiceName.contains("@"));
        }

        public static class Builder {
            private List<String> namingContexts = new ArrayList<>();
            private String defaultNamingContext;
            private List<Integer> supportedLdapVersions = new ArrayList<>();
            private List<String> supportedControls = new ArrayList<>();
            private List<String> supportedExtensions = new ArrayList<>();
            private List<String> supportedSaslMechanisms = new ArrayList<>();
            private String dnsHostName;
            private String serverName;
            private String ldapServiceName;
            private String currentTime;
            private Map<String, String> additionalAttributes = new HashMap<>();

            public Builder addNamingContext(String namingContext) {
                this.namingContexts.add(namingContext);
                return this;
            }

            public Builder setDefaultNamingContext(String defaultNamingContext) {
                this.defaultNamingContext = defaultNamingContext;
                return this;
            }

            public Builder addSupportedLdapVersion(int version) {
                this.supportedLdapVersions.add(version);
                return this;
            }

            public Builder addSupportedControl(String control) {
                this.supportedControls.add(control);
                return this;
            }

            public Builder addSupportedExtension(String extension) {
                this.supportedExtensions.add(extension);
                return this;
            }

            public Builder addSupportedSaslMechanism(String mechanism) {
                this.supportedSaslMechanisms.add(mechanism);
                return this;
            }

            public Builder setDnsHostName(String dnsHostName) {
                this.dnsHostName = dnsHostName;
                return this;
            }

            public Builder setServerName(String serverName) {
                this.serverName = serverName;
                return this;
            }

            public Builder setLdapServiceName(String ldapServiceName) {
                this.ldapServiceName = ldapServiceName;
                return this;
            }

            public Builder setCurrentTime(String currentTime) {
                this.currentTime = currentTime;
                return this;
            }

            public Builder addAttribute(String name, String value) {
                this.additionalAttributes.put(name, value);
                return this;
            }

            public RootDse build() {
                return new RootDse(this);
            }
        }
    }

    /**
     * Represents an LDAP entry.
     */
    public static class LdapEntry {
        private final String dn;
        private final Map<String, List<String>> attributes;

        public LdapEntry(@NonNull String dn) {
            this.dn = dn;
            this.attributes = new HashMap<>();
        }

        @NonNull
        public String getDn() {
            return dn;
        }

        public void addAttribute(@NonNull String name, @NonNull String value) {
            attributes.computeIfAbsent(name, k -> new ArrayList<>()).add(value);
        }

        @Nullable
        public String getAttribute(@NonNull String name) {
            List<String> values = attributes.get(name);
            return values != null && !values.isEmpty() ? values.get(0) : null;
        }

        @NonNull
        public List<String> getAttributeValues(@NonNull String name) {
            return attributes.getOrDefault(name, Collections.emptyList());
        }

        @NonNull
        public Map<String, List<String>> getAllAttributes() {
            return Collections.unmodifiableMap(attributes);
        }

        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append("DN: ").append(dn).append("\n");
            for (Map.Entry<String, List<String>> entry : attributes.entrySet()) {
                for (String value : entry.getValue()) {
                    sb.append(entry.getKey()).append(": ").append(value).append("\n");
                }
            }
            return sb.toString();
        }
    }

    /**
     * Represents an LDAP search result.
     */
    public static class SearchResult {
        private final List<LdapEntry> entries;
        private final int resultCode;
        private final String errorMessage;
        private final long searchTime;

        private SearchResult(Builder builder) {
            this.entries = new ArrayList<>(builder.entries);
            this.resultCode = builder.resultCode;
            this.errorMessage = builder.errorMessage;
            this.searchTime = builder.searchTime;
        }

        @NonNull
        public List<LdapEntry> getEntries() {
            return Collections.unmodifiableList(entries);
        }

        public int getResultCode() {
            return resultCode;
        }

        public boolean isSuccess() {
            return resultCode == RESULT_SUCCESS;
        }

        @Nullable
        public String getErrorMessage() {
            return errorMessage;
        }

        public long getSearchTime() {
            return searchTime;
        }

        public int getEntryCount() {
            return entries.size();
        }

        public static class Builder {
            private List<LdapEntry> entries = new ArrayList<>();
            private int resultCode;
            private String errorMessage;
            private long searchTime;

            public Builder addEntry(LdapEntry entry) {
                this.entries.add(entry);
                return this;
            }

            public Builder setResultCode(int resultCode) {
                this.resultCode = resultCode;
                return this;
            }

            public Builder setErrorMessage(String errorMessage) {
                this.errorMessage = errorMessage;
                return this;
            }

            public Builder setSearchTime(long searchTime) {
                this.searchTime = searchTime;
                return this;
            }

            public SearchResult build() {
                return new SearchResult(this);
            }
        }
    }

    /**
     * Represents LDAP server information.
     */
    public static class ServerInfo {
        private final String host;
        private final int port;
        private final boolean anonymous;
        private final boolean activeDirectory;
        private final RootDse rootDse;
        private final List<String> vulnerabilities;

        private ServerInfo(Builder builder) {
            this.host = builder.host;
            this.port = builder.port;
            this.anonymous = builder.anonymous;
            this.activeDirectory = builder.activeDirectory;
            this.rootDse = builder.rootDse;
            this.vulnerabilities = new ArrayList<>(builder.vulnerabilities);
        }

        @NonNull
        public String getHost() {
            return host;
        }

        public int getPort() {
            return port;
        }

        public boolean isAnonymous() {
            return anonymous;
        }

        public boolean isActiveDirectory() {
            return activeDirectory;
        }

        @Nullable
        public RootDse getRootDse() {
            return rootDse;
        }

        @NonNull
        public List<String> getVulnerabilities() {
            return Collections.unmodifiableList(vulnerabilities);
        }

        public static class Builder {
            private String host;
            private int port;
            private boolean anonymous;
            private boolean activeDirectory;
            private RootDse rootDse;
            private List<String> vulnerabilities = new ArrayList<>();

            public Builder setHost(String host) {
                this.host = host;
                return this;
            }

            public Builder setPort(int port) {
                this.port = port;
                return this;
            }

            public Builder setAnonymous(boolean anonymous) {
                this.anonymous = anonymous;
                return this;
            }

            public Builder setActiveDirectory(boolean activeDirectory) {
                this.activeDirectory = activeDirectory;
                return this;
            }

            public Builder setRootDse(RootDse rootDse) {
                this.rootDse = rootDse;
                return this;
            }

            public Builder addVulnerability(String vulnerability) {
                this.vulnerabilities.add(vulnerability);
                return this;
            }

            public ServerInfo build() {
                return new ServerInfo(this);
            }
        }
    }

    /**
     * Tests if an LDAP server supports anonymous binding.
     */
    public static boolean supportsAnonymousBind(@NonNull String host) {
        return supportsAnonymousBind(host, DEFAULT_LDAP_PORT, DEFAULT_TIMEOUT_MS);
    }

    /**
     * Tests if an LDAP server supports anonymous binding.
     */
    public static boolean supportsAnonymousBind(@NonNull String host, int port, int timeout) {
        try (Socket socket = new Socket()) {
            socket.connect(new java.net.InetSocketAddress(host, port), timeout);
            socket.setSoTimeout(timeout);

            // Send anonymous bind request
            byte[] bindRequest = buildAnonymousBindRequest(1);
            socket.getOutputStream().write(bindRequest);
            socket.getOutputStream().flush();

            // Read response
            byte[] response = new byte[1024];
            int bytesRead = socket.getInputStream().read(response);

            if (bytesRead > 0) {
                // Check if bind was successful (result code 0)
                return parseBindResult(response, bytesRead) == RESULT_SUCCESS;
            }
        } catch (IOException e) {
            // Connection failed or timeout
        }
        return false;
    }

    /**
     * Gets root DSE information from LDAP server.
     */
    @Nullable
    public static RootDse getRootDse(@NonNull String host) {
        return getRootDse(host, DEFAULT_LDAP_PORT, DEFAULT_TIMEOUT_MS);
    }

    /**
     * Gets root DSE information from LDAP server.
     */
    @Nullable
    public static RootDse getRootDse(@NonNull String host, int port, int timeout) {
        try (Socket socket = new Socket()) {
            socket.connect(new java.net.InetSocketAddress(host, port), timeout);
            socket.setSoTimeout(timeout);

            // Anonymous bind first
            byte[] bindRequest = buildAnonymousBindRequest(1);
            socket.getOutputStream().write(bindRequest);
            socket.getOutputStream().flush();

            byte[] response = new byte[1024];
            socket.getInputStream().read(response);

            // Search for root DSE
            byte[] searchRequest = buildRootDseSearchRequest(2);
            socket.getOutputStream().write(searchRequest);
            socket.getOutputStream().flush();

            // Read search results
            byte[] searchResponse = new byte[65535];
            int bytesRead = socket.getInputStream().read(searchResponse);

            if (bytesRead > 0) {
                return parseRootDseResponse(searchResponse, bytesRead);
            }
        } catch (IOException e) {
            // Connection failed
        }
        return null;
    }

    /**
     * Gets LDAP server information.
     */
    @NonNull
    public static ServerInfo getServerInfo(@NonNull String host) {
        return getServerInfo(host, DEFAULT_LDAP_PORT, DEFAULT_TIMEOUT_MS);
    }

    /**
     * Gets LDAP server information with vulnerability assessment.
     */
    @NonNull
    public static ServerInfo getServerInfo(@NonNull String host, int port, int timeout) {
        ServerInfo.Builder builder = new ServerInfo.Builder();
        builder.setHost(host);
        builder.setPort(port);

        // Test anonymous bind
        boolean anonymous = supportsAnonymousBind(host, port, timeout);
        builder.setAnonymous(anonymous);

        if (anonymous) {
            builder.addVulnerability("Anonymous LDAP binding is enabled");
        }

        // Get root DSE
        RootDse rootDse = getRootDse(host, port, timeout);
        if (rootDse != null) {
            builder.setRootDse(rootDse);
            builder.setActiveDirectory(rootDse.isActiveDirectory());

            // Check for vulnerabilities
            if (rootDse.isActiveDirectory()) {
                builder.addVulnerability("Active Directory server detected - potential for enumeration");
            }

            if (rootDse.getSupportedSaslMechanisms().isEmpty()) {
                builder.addVulnerability("No SASL mechanisms supported - potential cleartext auth");
            }

            if (!rootDse.getSupportedSaslMechanisms().contains("GSSAPI")) {
                builder.addVulnerability("Kerberos (GSSAPI) not supported");
            }
        }

        return builder.build();
    }

    /**
     * Builds an anonymous LDAP bind request.
     */
    @NonNull
    private static byte[] buildAnonymousBindRequest(int messageId) {
        // Simple anonymous bind: version 3, empty name, simple auth with empty password
        byte[] version = berEncodeInteger(LDAP_VERSION_3);
        byte[] name = berEncodeOctetString(new byte[0]);
        byte[] auth = new byte[]{(byte) 0x80, 0x00};  // Context-specific [0] with empty value

        byte[] bindRequest = concat(version, name, auth);
        byte[] bindRequestTagged = berEncodeTagged(0x60, bindRequest);  // BIND REQUEST [APPLICATION 0]

        byte[] messageIdEncoded = berEncodeInteger(messageId);
        byte[] message = concat(messageIdEncoded, bindRequestTagged);

        return berEncodeSequence(message);
    }

    /**
     * Builds a root DSE search request.
     */
    @NonNull
    private static byte[] buildRootDseSearchRequest(int messageId) {
        // Search base: empty (root)
        byte[] baseObject = berEncodeOctetString(new byte[0]);
        
        // Scope: base (0)
        byte[] scope = berEncodeEnumerated(SCOPE_BASE);
        
        // Deref aliases: never (0)
        byte[] derefAliases = berEncodeEnumerated(0);
        
        // Size limit: 0 (unlimited)
        byte[] sizeLimit = berEncodeInteger(0);
        
        // Time limit: 0 (unlimited)
        byte[] timeLimit = berEncodeInteger(0);
        
        // Types only: false
        byte[] typesOnly = berEncodeBoolean(false);
        
        // Filter: (objectClass=*)
        byte[] filter = berEncodePresent("objectClass");
        
        // Attributes: none (return all)
        byte[] attributes = berEncodeSequence(new byte[0]);

        byte[] searchRequest = concat(
                baseObject, scope, derefAliases, sizeLimit,
                timeLimit, typesOnly, filter, attributes);
        
        byte[] searchRequestTagged = berEncodeTagged(0x63, searchRequest);  // SEARCH REQUEST [APPLICATION 3]

        byte[] messageIdEncoded = berEncodeInteger(messageId);
        byte[] message = concat(messageIdEncoded, searchRequestTagged);

        return berEncodeSequence(message);
    }

    /**
     * Parses bind result from response.
     */
    private static int parseBindResult(@NonNull byte[] data, int length) {
        try {
            // Skip message sequence tag and length
            int pos = 2;
            if ((data[1] & 0x80) != 0) {
                pos += (data[1] & 0x7F);
            }
            
            // Skip message ID
            pos++;  // tag
            int idLen = data[pos++] & 0xFF;
            pos += idLen;
            
            // Check for bind response tag
            if (data[pos] == 0x61) {  // BIND RESPONSE [APPLICATION 1]
                pos++;
                int respLen = data[pos++] & 0xFF;
                if ((respLen & 0x80) != 0) {
                    int lenBytes = respLen & 0x7F;
                    pos += lenBytes;
                }
                
                // Result code
                if (data[pos] == 0x0A) {  // ENUMERATED
                    pos++;
                    int resultLen = data[pos++] & 0xFF;
                    if (resultLen > 0) {
                        return data[pos] & 0xFF;
                    }
                }
            }
        } catch (Exception e) {
            // Parse error
        }
        return -1;
    }

    /**
     * Parses root DSE response.
     */
    @Nullable
    private static RootDse parseRootDseResponse(@NonNull byte[] data, int length) {
        RootDse.Builder builder = new RootDse.Builder();
        
        try {
            // This is a simplified parser - full implementation would need complete BER decoder
            String response = new String(data, 0, length, StandardCharsets.ISO_8859_1);
            
            // Extract naming contexts
            Pattern ncPattern = Pattern.compile("namingContexts[\\x00-\\x1f]+([\\w=,\\s]+)");
            Matcher ncMatcher = ncPattern.matcher(response);
            while (ncMatcher.find()) {
                builder.addNamingContext(ncMatcher.group(1).trim());
            }
            
            // Extract DNS host name
            Pattern dnsPattern = Pattern.compile("dnsHostName[\\x00-\\x1f]+([\\w.\\-]+)");
            Matcher dnsMatcher = dnsPattern.matcher(response);
            if (dnsMatcher.find()) {
                builder.setDnsHostName(dnsMatcher.group(1));
            }
            
            // Look for AD-specific attributes
            if (response.contains("defaultNamingContext") || response.contains("rootDomainNamingContext")) {
                Pattern defaultNcPattern = Pattern.compile("defaultNamingContext[\\x00-\\x1f]+([\\w=,\\s]+)");
                Matcher defaultNcMatcher = defaultNcPattern.matcher(response);
                if (defaultNcMatcher.find()) {
                    builder.setDefaultNamingContext(defaultNcMatcher.group(1).trim());
                }
            }
            
        } catch (Exception e) {
            // Parse error
        }
        
        return builder.build();
    }

    // BER encoding helpers

    private static byte[] berEncodeInteger(int value) {
        if (value < 128) {
            return new byte[]{0x02, 0x01, (byte) value};
        } else if (value < 256) {
            return new byte[]{0x02, 0x02, 0x00, (byte) value};
        } else if (value < 65536) {
            return new byte[]{0x02, 0x03, 0x00, (byte) (value >> 8), (byte) value};
        } else {
            return new byte[]{0x02, 0x04, (byte) (value >> 24), (byte) (value >> 16), 
                    (byte) (value >> 8), (byte) value};
        }
    }

    private static byte[] berEncodeEnumerated(int value) {
        byte[] encoded = berEncodeInteger(value);
        encoded[0] = 0x0A;  // Change tag to ENUMERATED
        return encoded;
    }

    private static byte[] berEncodeBoolean(boolean value) {
        return new byte[]{0x01, 0x01, value ? (byte) 0xFF : 0x00};
    }

    private static byte[] berEncodeOctetString(byte[] value) {
        byte[] header = berEncodeLength(value.length);
        byte[] result = new byte[1 + header.length + value.length];
        result[0] = 0x04;  // OCTET STRING
        System.arraycopy(header, 0, result, 1, header.length);
        System.arraycopy(value, 0, result, 1 + header.length, value.length);
        return result;
    }

    private static byte[] berEncodeSequence(byte[] content) {
        return berEncodeTagged(0x30, content);
    }

    private static byte[] berEncodeTagged(int tag, byte[] content) {
        byte[] header = berEncodeLength(content.length);
        byte[] result = new byte[1 + header.length + content.length];
        result[0] = (byte) tag;
        System.arraycopy(header, 0, result, 1, header.length);
        System.arraycopy(content, 0, result, 1 + header.length, content.length);
        return result;
    }

    private static byte[] berEncodePresent(String attribute) {
        byte[] attrBytes = attribute.getBytes(StandardCharsets.UTF_8);
        byte[] result = new byte[2 + attrBytes.length];
        result[0] = (byte) 0x87;  // Context-specific [7] - present filter
        result[1] = (byte) attrBytes.length;
        System.arraycopy(attrBytes, 0, result, 2, attrBytes.length);
        return result;
    }

    private static byte[] berEncodeLength(int length) {
        if (length < 128) {
            return new byte[]{(byte) length};
        } else if (length < 256) {
            return new byte[]{(byte) 0x81, (byte) length};
        } else {
            return new byte[]{(byte) 0x82, (byte) (length >> 8), (byte) length};
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

    /**
     * Parses a distinguished name into its components.
     */
    @NonNull
    public static Map<String, String> parseDn(@NonNull String dn) {
        Map<String, String> components = new HashMap<>();
        String[] parts = dn.split(",");
        
        for (String part : parts) {
            String trimmed = part.trim();
            int equalPos = trimmed.indexOf('=');
            if (equalPos > 0) {
                String key = trimmed.substring(0, equalPos).toUpperCase(Locale.US);
                String value = trimmed.substring(equalPos + 1);
                components.put(key, value);
            }
        }
        
        return components;
    }

    /**
     * Extracts domain from a DN.
     */
    @Nullable
    public static String extractDomain(@NonNull String dn) {
        StringBuilder domain = new StringBuilder();
        String[] parts = dn.split(",");
        
        for (String part : parts) {
            String trimmed = part.trim();
            if (trimmed.toUpperCase(Locale.US).startsWith("DC=")) {
                if (domain.length() > 0) {
                    domain.append(".");
                }
                domain.append(trimmed.substring(3));
            }
        }
        
        return domain.length() > 0 ? domain.toString() : null;
    }

    /**
     * Generates a report for LDAP server.
     */
    @NonNull
    public static String generateReport(@NonNull ServerInfo serverInfo) {
        StringBuilder report = new StringBuilder();
        
        report.append("LDAP Server Information\n");
        report.append("=======================\n\n");
        
        report.append(String.format(Locale.US, "Host: %s:%d\n", serverInfo.getHost(), serverInfo.getPort()));
        report.append(String.format(Locale.US, "Anonymous Bind: %s\n", serverInfo.isAnonymous() ? "Yes" : "No"));
        report.append(String.format(Locale.US, "Active Directory: %s\n", serverInfo.isActiveDirectory() ? "Yes" : "No"));
        
        RootDse rootDse = serverInfo.getRootDse();
        if (rootDse != null) {
            report.append("\nRoot DSE Information:\n");
            report.append("---------------------\n");
            
            if (rootDse.getDnsHostName() != null) {
                report.append("DNS Hostname: ").append(rootDse.getDnsHostName()).append("\n");
            }
            
            if (rootDse.getDefaultNamingContext() != null) {
                report.append("Default NC: ").append(rootDse.getDefaultNamingContext()).append("\n");
            }
            
            if (!rootDse.getNamingContexts().isEmpty()) {
                report.append("Naming Contexts:\n");
                for (String nc : rootDse.getNamingContexts()) {
                    report.append("  - ").append(nc).append("\n");
                }
            }
            
            if (!rootDse.getSupportedSaslMechanisms().isEmpty()) {
                report.append("SASL Mechanisms: ");
                report.append(String.join(", ", rootDse.getSupportedSaslMechanisms()));
                report.append("\n");
            }
        }
        
        if (!serverInfo.getVulnerabilities().isEmpty()) {
            report.append("\nVulnerabilities:\n");
            report.append("----------------\n");
            for (String vuln : serverInfo.getVulnerabilities()) {
                report.append("  [!] ").append(vuln).append("\n");
            }
        }
        
        return report.toString();
    }

    /**
     * Gets result code description.
     */
    @NonNull
    public static String getResultCodeDescription(int resultCode) {
        switch (resultCode) {
            case RESULT_SUCCESS: return "Success";
            case RESULT_OPERATIONS_ERROR: return "Operations Error";
            case RESULT_PROTOCOL_ERROR: return "Protocol Error";
            case RESULT_TIME_LIMIT_EXCEEDED: return "Time Limit Exceeded";
            case RESULT_SIZE_LIMIT_EXCEEDED: return "Size Limit Exceeded";
            case RESULT_AUTH_METHOD_NOT_SUPPORTED: return "Auth Method Not Supported";
            case RESULT_STRONGER_AUTH_REQUIRED: return "Stronger Auth Required";
            case RESULT_NO_SUCH_OBJECT: return "No Such Object";
            case RESULT_INVALID_CREDENTIALS: return "Invalid Credentials";
            case RESULT_INSUFFICIENT_ACCESS: return "Insufficient Access Rights";
            case RESULT_UNWILLING_TO_PERFORM: return "Unwilling To Perform";
            default: return String.format(Locale.US, "Unknown (%d)", resultCode);
        }
    }
}
