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

import java.io.IOException;
import java.net.Socket;
import java.security.KeyManagementException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLPeerUnverifiedException;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * SslHelper - SSL/TLS certificate inspection and analysis utilities.
 * 
 * Provides:
 * - Certificate chain retrieval
 * - Certificate fingerprint calculation
 * - Certificate validation checking
 * - SSL/TLS version detection
 * - Cipher suite inspection
 * 
 * Usage:
 * {@code
 * // Get certificate info
 * CertificateInfo info = SslHelper.getCertificateInfo("example.com", 443);
 * 
 * // Check SSL version
 * String protocol = SslHelper.getSSLProtocol("example.com", 443);
 * 
 * // Get fingerprint
 * String fingerprint = SslHelper.getSHA256Fingerprint(cert);
 * }
 */
public final class SslHelper {
    
    private static final String TAG = "SslHelper";
    private static final int DEFAULT_TIMEOUT = 10000; // 10 seconds
    
    /**
     * SSL/TLS protocol versions.
     */
    public enum TlsVersion {
        SSL_3_0("SSLv3", false),
        TLS_1_0("TLSv1", false),
        TLS_1_1("TLSv1.1", false),
        TLS_1_2("TLSv1.2", true),
        TLS_1_3("TLSv1.3", true);
        
        private final String protocol;
        private final boolean secure;
        
        TlsVersion(String protocol, boolean secure) {
            this.protocol = protocol;
            this.secure = secure;
        }
        
        public String getProtocol() {
            return protocol;
        }
        
        public boolean isSecure() {
            return secure;
        }
        
        @Nullable
        public static TlsVersion fromString(String protocol) {
            for (TlsVersion v : values()) {
                if (v.protocol.equalsIgnoreCase(protocol)) {
                    return v;
                }
            }
            return null;
        }
    }
    
    /**
     * Certificate information.
     */
    public static class CertificateInfo {
        public String subjectDN;
        public String issuerDN;
        public String serialNumber;
        public Date notBefore;
        public Date notAfter;
        public String sha256Fingerprint;
        public String sha1Fingerprint;
        public List<String> subjectAltNames;
        public String signatureAlgorithm;
        public int version;
        public boolean isSelfSigned;
        public boolean isExpired;
        public boolean isNotYetValid;
        public int daysUntilExpiry;
        
        @NonNull
        @Override
        public String toString() {
            return String.format("Certificate{subject='%s', issuer='%s', expires=%s, valid=%s}",
                    subjectDN, issuerDN, notAfter, !isExpired && !isNotYetValid);
        }
    }
    
    /**
     * SSL connection information.
     */
    public static class SslConnectionInfo {
        public String protocol;
        public String cipherSuite;
        public List<CertificateInfo> certificateChain;
        public boolean peerVerified;
        public TlsVersion tlsVersion;
        
        @NonNull
        @Override
        public String toString() {
            return String.format("SSLConnection{protocol='%s', cipher='%s', certs=%d}",
                    protocol, cipherSuite, certificateChain != null ? certificateChain.size() : 0);
        }
    }
    
    private SslHelper() {}
    
    /**
     * Get SSL connection information for a host.
     * 
     * @param host hostname
     * @param port port number (typically 443)
     * @return SSL connection info or null if failed
     */
    @Nullable
    public static SslConnectionInfo getConnectionInfo(@NonNull String host, int port) {
        SSLSocket socket = null;
        try {
            SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            socket = (SSLSocket) factory.createSocket(host, port);
            socket.setSoTimeout(DEFAULT_TIMEOUT);
            socket.startHandshake();
            
            SSLSession session = socket.getSession();
            SslConnectionInfo info = new SslConnectionInfo();
            
            info.protocol = session.getProtocol();
            info.cipherSuite = session.getCipherSuite();
            info.tlsVersion = TlsVersion.fromString(info.protocol);
            
            try {
                session.getPeerCertificates();
                info.peerVerified = true;
            } catch (SSLPeerUnverifiedException e) {
                info.peerVerified = false;
            }
            
            // Get certificate chain
            info.certificateChain = getCertificateChain(host, port);
            
            return info;
        } catch (Exception e) {
            Log.e(TAG, "Failed to get SSL info for " + host + ":" + port, e);
            return null;
        } finally {
            if (socket != null) {
                try {
                    socket.close();
                } catch (IOException e) {
                    Log.d(TAG, "Failed to close SSL socket: " + e.getMessage());
                }
            }
        }
    }

    /**
     * Get certificate chain for a host (accepts all certificates for inspection).
     */
    @NonNull
    public static List<CertificateInfo> getCertificateChain(@NonNull String host, int port) {
        List<CertificateInfo> chain = new ArrayList<>();
        SSLSocket socket = null;
        
        try {
            // Create trust-all SSL context for inspection purposes
            TrustManager[] trustAllCerts = new TrustManager[]{
                new X509TrustManager() {
                    @Override
                    public void checkClientTrusted(X509Certificate[] certs, String authType) {}
                    @Override
                    public void checkServerTrusted(X509Certificate[] certs, String authType) {}
                    @Override
                    public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                }
            };
            
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, trustAllCerts, new java.security.SecureRandom());
            SSLSocketFactory factory = sc.getSocketFactory();
            
            socket = (SSLSocket) factory.createSocket(host, port);
            socket.setSoTimeout(DEFAULT_TIMEOUT);
            socket.startHandshake();
            
            Certificate[] certs = socket.getSession().getPeerCertificates();
            
            for (Certificate cert : certs) {
                if (cert instanceof X509Certificate) {
                    chain.add(parseCertificate((X509Certificate) cert));
                }
            }
        } catch (Exception e) {
            Log.e(TAG, "Failed to get certificate chain for " + host + ":" + port, e);
        } finally {
            if (socket != null) {
                try {
                    socket.close();
                } catch (IOException e) {
                    Log.d(TAG, "Failed to close SSL socket during cert chain retrieval: " + e.getMessage());
                }
            }
        }

        return chain;
    }
    
    /**
     * Parse X509 certificate into CertificateInfo.
     */
    @NonNull
    public static CertificateInfo parseCertificate(@NonNull X509Certificate cert) {
        CertificateInfo info = new CertificateInfo();
        
        info.subjectDN = cert.getSubjectDN().getName();
        info.issuerDN = cert.getIssuerDN().getName();
        info.serialNumber = cert.getSerialNumber().toString(16);
        info.notBefore = cert.getNotBefore();
        info.notAfter = cert.getNotAfter();
        info.signatureAlgorithm = cert.getSigAlgName();
        info.version = cert.getVersion();
        
        // Check if self-signed
        info.isSelfSigned = cert.getSubjectDN().equals(cert.getIssuerDN());
        
        // Check validity
        Date now = new Date();
        info.isExpired = now.after(info.notAfter);
        info.isNotYetValid = now.before(info.notBefore);
        
        // Days until expiry
        if (!info.isExpired) {
            long diff = info.notAfter.getTime() - now.getTime();
            info.daysUntilExpiry = (int) (diff / (1000 * 60 * 60 * 24));
        } else {
            info.daysUntilExpiry = 0;
        }
        
        // Fingerprints
        info.sha256Fingerprint = getSHA256Fingerprint(cert);
        info.sha1Fingerprint = getSHA1Fingerprint(cert);
        
        // Subject alternative names
        info.subjectAltNames = getSubjectAltNames(cert);
        
        return info;
    }
    
    /**
     * Get SHA-256 fingerprint of certificate.
     */
    @Nullable
    public static String getSHA256Fingerprint(@NonNull X509Certificate cert) {
        return getFingerprint(cert, "SHA-256");
    }
    
    /**
     * Get SHA-1 fingerprint of certificate.
     */
    @Nullable
    public static String getSHA1Fingerprint(@NonNull X509Certificate cert) {
        return getFingerprint(cert, "SHA-1");
    }
    
    /**
     * Get fingerprint using specified algorithm.
     */
    @Nullable
    private static String getFingerprint(@NonNull X509Certificate cert, @NonNull String algorithm) {
        try {
            MessageDigest md = MessageDigest.getInstance(algorithm);
            byte[] digest = md.digest(cert.getEncoded());
            return bytesToHex(digest, ":");
        } catch (NoSuchAlgorithmException | CertificateEncodingException e) {
            Log.e(TAG, "Failed to calculate fingerprint", e);
            return null;
        }
    }
    
    /**
     * Get subject alternative names from certificate.
     */
    @NonNull
    public static List<String> getSubjectAltNames(@NonNull X509Certificate cert) {
        List<String> altNames = new ArrayList<>();
        try {
            if (cert.getSubjectAlternativeNames() != null) {
                for (List<?> san : cert.getSubjectAlternativeNames()) {
                    if (san.size() >= 2) {
                        Object value = san.get(1);
                        if (value instanceof String) {
                            altNames.add((String) value);
                        }
                    }
                }
            }
        } catch (Exception e) {
            Log.w(TAG, "Failed to get subject alt names", e);
        }
        return altNames;
    }
    
    /**
     * Check if certificate is valid for hostname.
     */
    public static boolean isValidForHost(@NonNull X509Certificate cert, @NonNull String hostname) {
        // Check subject CN
        String cn = extractCN(cert.getSubjectDN().getName());
        if (cn != null && matchesHostname(cn, hostname)) {
            return true;
        }
        
        // Check SANs
        for (String san : getSubjectAltNames(cert)) {
            if (matchesHostname(san, hostname)) {
                return true;
            }
        }
        
        return false;
    }
    
    /**
     * Extract CN from DN string.
     */
    @Nullable
    private static String extractCN(@NonNull String dn) {
        String[] parts = dn.split(",");
        for (String part : parts) {
            String trimmed = part.trim();
            if (trimmed.toLowerCase().startsWith("cn=")) {
                return trimmed.substring(3);
            }
        }
        return null;
    }
    
    /**
     * Check if pattern matches hostname (supports wildcards).
     */
    private static boolean matchesHostname(@NonNull String pattern, @NonNull String hostname) {
        pattern = pattern.toLowerCase();
        hostname = hostname.toLowerCase();
        
        if (pattern.startsWith("*.")) {
            // Wildcard match
            String suffix = pattern.substring(2);
            return hostname.endsWith(suffix) && 
                   hostname.indexOf('.') >= hostname.length() - suffix.length();
        }
        
        return pattern.equals(hostname);
    }
    
    /**
     * Get SSL protocol version for host.
     */
    @Nullable
    public static String getSSLProtocol(@NonNull String host, int port) {
        SslConnectionInfo info = getConnectionInfo(host, port);
        return info != null ? info.protocol : null;
    }
    
    /**
     * Check if host uses secure TLS version (1.2+).
     */
    public static boolean usesSecureTls(@NonNull String host, int port) {
        SslConnectionInfo info = getConnectionInfo(host, port);
        return info != null && info.tlsVersion != null && info.tlsVersion.isSecure();
    }
    
    /**
     * Get supported cipher suites.
     */
    @NonNull
    public static String[] getSupportedCipherSuites() {
        try {
            SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            return factory.getSupportedCipherSuites();
        } catch (Exception e) {
            return new String[0];
        }
    }
    
    /**
     * Get default cipher suites.
     */
    @NonNull
    public static String[] getDefaultCipherSuites() {
        try {
            SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            return factory.getDefaultCipherSuites();
        } catch (Exception e) {
            return new String[0];
        }
    }
    
    /**
     * Check if cipher suite is considered weak.
     */
    public static boolean isWeakCipher(@NonNull String cipherSuite) {
        String cs = cipherSuite.toUpperCase();
        return cs.contains("NULL") ||
               cs.contains("ANON") ||
               cs.contains("EXPORT") ||
               cs.contains("DES") ||
               cs.contains("RC4") ||
               cs.contains("MD5") ||
               cs.contains("CBC");
    }
    
    /**
     * Convert bytes to hex string.
     */
    @NonNull
    private static String bytesToHex(@NonNull byte[] bytes, @NonNull String separator) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            if (i > 0) sb.append(separator);
            sb.append(String.format("%02X", bytes[i]));
        }
        return sb.toString();
    }
}
