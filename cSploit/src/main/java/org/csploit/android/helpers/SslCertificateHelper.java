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

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.io.ByteArrayInputStream;
import java.net.URL;
import java.security.MessageDigest;
import java.security.cert.Certificate;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;
import java.util.concurrent.TimeUnit;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * SslCertificateHelper - SSL/TLS certificate analysis and validation utilities.
 *
 * Provides:
 * - Certificate chain retrieval
 * - Certificate validation and analysis
 * - SSL/TLS version detection
 * - Certificate fingerprinting
 * - Expiration checking
 * - Cipher suite enumeration
 *
 * Usage:
 * {@code
 * // Get certificate info
 * CertificateInfo info = SslCertificateHelper.getCertificateInfo("example.com", 443);
 *
 * // Check expiration
 * boolean expiring = SslCertificateHelper.isExpiringSoon(info.certificate, 30);
 *
 * // Get fingerprint
 * String fingerprint = SslCertificateHelper.getFingerprint(info.certificate, "SHA-256");
 * }
 */
public final class SslCertificateHelper {

    private static final String TAG = "SslCertificateHelper";
    private static final int DEFAULT_TIMEOUT = 10000; // 10 seconds

    // Common SSL/TLS protocols
    public static final String TLS_1_0 = "TLSv1";
    public static final String TLS_1_1 = "TLSv1.1";
    public static final String TLS_1_2 = "TLSv1.2";
    public static final String TLS_1_3 = "TLSv1.3";
    public static final String SSL_3_0 = "SSLv3";

    private SslCertificateHelper() {}

    /**
     * Certificate information container.
     */
    public static class CertificateInfo {
        public X509Certificate certificate;
        public X509Certificate[] chain;
        public String subject;
        public String issuer;
        public Date notBefore;
        public Date notAfter;
        public String serialNumber;
        public String signatureAlgorithm;
        public int version;
        public List<String> subjectAltNames;
        public boolean isValid;
        public boolean isSelfSigned;
        public boolean isExpired;
        public boolean isNotYetValid;
        public long daysUntilExpiry;
        public String sha256Fingerprint;
        public String sha1Fingerprint;
        public String publicKeyAlgorithm;
        public int publicKeySize;
        public String protocol;
        public String[] supportedCipherSuites;
        public String[] enabledCipherSuites;
        public long connectionTimeMs;
        public String error;

        @NonNull
        @Override
        public String toString() {
            return String.format("CertInfo{subject='%s', issuer='%s', expires='%s', valid=%b}",
                    subject, issuer, notAfter, isValid);
        }
    }

    /**
     * Get comprehensive certificate information for a host.
     */
    @NonNull
    public static CertificateInfo getCertificateInfo(@NonNull String host, int port) {
        return getCertificateInfo(host, port, DEFAULT_TIMEOUT);
    }

    /**
     * Get certificate information with custom timeout.
     */
    @NonNull
    public static CertificateInfo getCertificateInfo(@NonNull String host, int port, int timeoutMs) {
        CertificateInfo info = new CertificateInfo();
        long startTime = java.lang.System.currentTimeMillis();

        SSLSocket socket = null;
        try {
            // Create a trust-all trust manager to capture the certificate
            TrustManager[] trustAll = new TrustManager[]{
                new X509TrustManager() {
                    @Override
                    public void checkClientTrusted(X509Certificate[] chain, String authType) {}
                    @Override
                    public void checkServerTrusted(X509Certificate[] chain, String authType) {}
                    @Override
                    public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
                }
            };

            SSLContext sslContext = SSLContext.getInstance("TLS");
            sslContext.init(null, trustAll, new java.security.SecureRandom());
            SSLSocketFactory factory = sslContext.getSocketFactory();

            socket = (SSLSocket) factory.createSocket(host, port);
            socket.setSoTimeout(timeoutMs);
            socket.startHandshake();

            // Get protocol and cipher info
            info.protocol = socket.getSession().getProtocol();
            info.supportedCipherSuites = socket.getSupportedCipherSuites();
            info.enabledCipherSuites = socket.getEnabledCipherSuites();

            // Get certificate chain
            Certificate[] certs = socket.getSession().getPeerCertificates();
            if (certs != null && certs.length > 0 && certs[0] instanceof X509Certificate) {
                info.certificate = (X509Certificate) certs[0];
                info.chain = new X509Certificate[certs.length];
                for (int i = 0; i < certs.length; i++) {
                    info.chain[i] = (X509Certificate) certs[i];
                }

                populateCertificateDetails(info);
            }

        } catch (Exception e) {
            info.error = e.getMessage();
            info.isValid = false;
            LoggingHelper.w(TAG, "Failed to get certificate for " + host + ":" + port, e);
        } finally {
            if (socket != null) {
                try { socket.close(); } catch (Exception e) { /* ignore */ }
            }
        }

        info.connectionTimeMs = java.lang.System.currentTimeMillis() - startTime;
        return info;
    }

    /**
     * Populate certificate details from X509Certificate.
     */
    private static void populateCertificateDetails(@NonNull CertificateInfo info) {
        X509Certificate cert = info.certificate;
        if (cert == null) return;

        Date now = new Date();

        info.subject = cert.getSubjectX500Principal().getName();
        info.issuer = cert.getIssuerX500Principal().getName();
        info.notBefore = cert.getNotBefore();
        info.notAfter = cert.getNotAfter();
        info.serialNumber = cert.getSerialNumber().toString(16);
        info.signatureAlgorithm = cert.getSigAlgName();
        info.version = cert.getVersion();
        info.publicKeyAlgorithm = cert.getPublicKey().getAlgorithm();

        // Get key size
        try {
            if (cert.getPublicKey() instanceof java.security.interfaces.RSAPublicKey) {
                info.publicKeySize = ((java.security.interfaces.RSAPublicKey) cert.getPublicKey()).getModulus().bitLength();
            } else if (cert.getPublicKey() instanceof java.security.interfaces.ECPublicKey) {
                info.publicKeySize = ((java.security.interfaces.ECPublicKey) cert.getPublicKey()).getParams().getOrder().bitLength();
            }
        } catch (Exception e) {
            info.publicKeySize = -1;
        }

        // Get fingerprints
        info.sha256Fingerprint = getFingerprint(cert, "SHA-256");
        info.sha1Fingerprint = getFingerprint(cert, "SHA-1");

        // Validity checks
        info.isExpired = now.after(cert.getNotAfter());
        info.isNotYetValid = now.before(cert.getNotBefore());
        info.isSelfSigned = cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal());

        // Calculate days until expiry
        long diffMs = cert.getNotAfter().getTime() - now.getTime();
        info.daysUntilExpiry = TimeUnit.MILLISECONDS.toDays(diffMs);

        // Get subject alternative names
        info.subjectAltNames = new ArrayList<>();
        try {
            java.util.Collection<java.util.List<?>> sans = cert.getSubjectAlternativeNames();
            if (sans != null) {
                for (java.util.List<?> san : sans) {
                    if (san.size() >= 2) {
                        info.subjectAltNames.add(san.get(1).toString());
                    }
                }
            }
        } catch (Exception e) {
            // SANs not available
        }

        // Check overall validity
        try {
            cert.checkValidity();
            info.isValid = true;
        } catch (Exception e) {
            info.isValid = false;
        }
    }

    /**
     * Get certificate fingerprint.
     */
    @NonNull
    public static String getFingerprint(@Nullable X509Certificate cert, @NonNull String algorithm) {
        if (cert == null) return "";
        try {
            MessageDigest md = MessageDigest.getInstance(algorithm);
            byte[] der = cert.getEncoded();
            byte[] digest = md.digest(der);
            return bytesToHex(digest);
        } catch (Exception e) {
            LoggingHelper.w(TAG, "Failed to calculate fingerprint", e);
            return "";
        }
    }

    /**
     * Check if certificate is expiring within specified days.
     */
    public static boolean isExpiringSoon(@Nullable X509Certificate cert, int days) {
        if (cert == null) return true;
        Date futureDate = new Date(java.lang.System.currentTimeMillis() + TimeUnit.DAYS.toMillis(days));
        return futureDate.after(cert.getNotAfter());
    }

    /**
     * Check if certificate is currently valid.
     */
    public static boolean isCurrentlyValid(@Nullable X509Certificate cert) {
        if (cert == null) return false;
        try {
            cert.checkValidity();
            return true;
        } catch (Exception e) {
            return false;
        }
    }

    /**
     * Check which SSL/TLS protocols are supported.
     */
    @NonNull
    public static List<String> checkSupportedProtocols(@NonNull String host, int port) {
        List<String> supported = new ArrayList<>();
        String[] protocols = {SSL_3_0, TLS_1_0, TLS_1_1, TLS_1_2, TLS_1_3};

        for (String protocol : protocols) {
            if (isProtocolSupported(host, port, protocol)) {
                supported.add(protocol);
            }
        }

        return supported;
    }

    /**
     * Check if a specific protocol is supported.
     */
    public static boolean isProtocolSupported(@NonNull String host, int port, @NonNull String protocol) {
        SSLSocket socket = null;
        try {
            SSLContext sslContext = SSLContext.getInstance(protocol);
            sslContext.init(null, null, null);
            SSLSocketFactory factory = sslContext.getSocketFactory();

            socket = (SSLSocket) factory.createSocket(host, port);
            socket.setSoTimeout(5000);
            socket.setEnabledProtocols(new String[]{protocol});
            socket.startHandshake();
            return true;
        } catch (Exception e) {
            return false;
        } finally {
            if (socket != null) {
                try { socket.close(); } catch (Exception e) { /* ignore */ }
            }
        }
    }

    /**
     * Get supported cipher suites for a host.
     */
    @NonNull
    public static List<String> getSupportedCipherSuites(@NonNull String host, int port) {
        List<String> supported = new ArrayList<>();
        SSLSocket socket = null;
        try {
            SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            socket = (SSLSocket) factory.createSocket(host, port);
            socket.setSoTimeout(DEFAULT_TIMEOUT);

            String[] ciphers = socket.getSupportedCipherSuites();
            for (String cipher : ciphers) {
                if (isCipherSupported(host, port, cipher)) {
                    supported.add(cipher);
                }
            }
        } catch (Exception e) {
            LoggingHelper.w(TAG, "Failed to enumerate cipher suites", e);
        } finally {
            if (socket != null) {
                try { socket.close(); } catch (Exception e) { /* ignore */ }
            }
        }
        return supported;
    }

    /**
     * Check if a specific cipher is supported.
     */
    public static boolean isCipherSupported(@NonNull String host, int port, @NonNull String cipher) {
        SSLSocket socket = null;
        try {
            SSLSocketFactory factory = (SSLSocketFactory) SSLSocketFactory.getDefault();
            socket = (SSLSocket) factory.createSocket(host, port);
            socket.setSoTimeout(3000);
            socket.setEnabledCipherSuites(new String[]{cipher});
            socket.startHandshake();
            return true;
        } catch (Exception e) {
            return false;
        } finally {
            if (socket != null) {
                try { socket.close(); } catch (Exception e) { /* ignore */ }
            }
        }
    }

    /**
     * Classify cipher suite security level.
     */
    @NonNull
    public static String classifyCipher(@NonNull String cipher) {
        String upper = cipher.toUpperCase();

        if (upper.contains("NULL") || upper.contains("ANON") || upper.contains("EXPORT")) {
            return "INSECURE";
        }
        if (upper.contains("RC4") || upper.contains("DES") || upper.contains("MD5")) {
            return "WEAK";
        }
        if (upper.contains("3DES")) {
            return "DEPRECATED";
        }
        if (upper.contains("AES_256") && upper.contains("GCM") && upper.contains("SHA384")) {
            return "STRONG";
        }
        if (upper.contains("AES") && upper.contains("GCM")) {
            return "GOOD";
        }
        if (upper.contains("CHACHA20")) {
            return "STRONG";
        }

        return "ACCEPTABLE";
    }

    /**
     * Parse a PEM-encoded certificate.
     */
    @Nullable
    public static X509Certificate parsePemCertificate(@NonNull String pem) {
        try {
            String cleaned = pem
                    .replace("-----BEGIN CERTIFICATE-----", "")
                    .replace("-----END CERTIFICATE-----", "")
                    .replaceAll("\\s", "");

            byte[] decoded = android.util.Base64.decode(cleaned, android.util.Base64.DEFAULT);
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            return (X509Certificate) cf.generateCertificate(new ByteArrayInputStream(decoded));
        } catch (Exception e) {
            LoggingHelper.w(TAG, "Failed to parse PEM certificate", e);
            return null;
        }
    }

    /**
     * Export certificate to PEM format.
     */
    @NonNull
    public static String exportToPem(@Nullable X509Certificate cert) {
        if (cert == null) return "";
        try {
            byte[] encoded = cert.getEncoded();
            String base64 = android.util.Base64.encodeToString(encoded, android.util.Base64.DEFAULT);
            return "-----BEGIN CERTIFICATE-----\n" + base64 + "-----END CERTIFICATE-----\n";
        } catch (Exception e) {
            LoggingHelper.w(TAG, "Failed to export certificate to PEM", e);
            return "";
        }
    }

    /**
     * Check for common SSL/TLS misconfigurations.
     */
    @NonNull
    public static List<String> checkMisconfigurations(@NonNull String host, int port) {
        List<String> issues = new ArrayList<>();

        CertificateInfo info = getCertificateInfo(host, port);

        if (info.error != null) {
            issues.add("Connection error: " + info.error);
            return issues;
        }

        // Check certificate issues
        if (info.isExpired) {
            issues.add("Certificate has expired");
        }
        if (info.isNotYetValid) {
            issues.add("Certificate is not yet valid");
        }
        if (info.isSelfSigned) {
            issues.add("Certificate is self-signed");
        }
        if (info.daysUntilExpiry >= 0 && info.daysUntilExpiry < 30) {
            issues.add("Certificate expires in " + info.daysUntilExpiry + " days");
        }
        if (info.publicKeySize > 0 && info.publicKeySize < 2048) {
            issues.add("Weak key size: " + info.publicKeySize + " bits");
        }
        if (info.signatureAlgorithm != null && info.signatureAlgorithm.contains("SHA1")) {
            issues.add("Uses weak SHA-1 signature algorithm");
        }

        // Check protocol issues
        List<String> protocols = checkSupportedProtocols(host, port);
        if (protocols.contains(SSL_3_0)) {
            issues.add("Supports deprecated SSLv3 (POODLE vulnerability)");
        }
        if (protocols.contains(TLS_1_0)) {
            issues.add("Supports deprecated TLSv1.0");
        }
        if (protocols.contains(TLS_1_1)) {
            issues.add("Supports deprecated TLSv1.1");
        }
        if (!protocols.contains(TLS_1_2) && !protocols.contains(TLS_1_3)) {
            issues.add("Does not support modern TLS (1.2 or 1.3)");
        }

        return issues;
    }

    private static String bytesToHex(byte[] bytes) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < bytes.length; i++) {
            if (i > 0) sb.append(':');
            sb.append(String.format("%02X", bytes[i]));
        }
        return sb.toString();
    }
}
