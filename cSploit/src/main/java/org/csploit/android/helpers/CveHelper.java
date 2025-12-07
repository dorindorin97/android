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

import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * CveHelper - CVE (Common Vulnerabilities and Exposures) utilities.
 *
 * Provides:
 * - CVE ID validation and parsing
 * - CVSS score interpretation
 * - Known vulnerability lookup
 * - Severity classification
 *
 * Usage:
 * {@code
 * // Validate CVE ID
 * boolean valid = CveHelper.isValidCveId("CVE-2021-44228");
 *
 * // Get severity
 * Severity sev = CveHelper.getSeverity(9.8);
 *
 * // Lookup known CVE
 * CveInfo info = CveHelper.getKnownCve("CVE-2021-44228");
 * }
 */
public final class CveHelper {

    private static final String TAG = "CveHelper";

    // CVE ID pattern (CVE-YYYY-NNNNN+)
    private static final Pattern CVE_PATTERN = Pattern.compile(
            "CVE-\\d{4}-\\d{4,}", Pattern.CASE_INSENSITIVE);

    // Known critical CVEs (subset for quick reference)
    private static final Map<String, CveInfo> KNOWN_CVES = new HashMap<>();

    static {
        // Log4Shell
        addKnownCve("CVE-2021-44228", "Log4Shell", 10.0f, Severity.CRITICAL,
                "Apache Log4j", "Remote code execution via JNDI lookup",
                new String[]{"Java applications using Log4j 2.x"});

        // Eternal Blue
        addKnownCve("CVE-2017-0144", "EternalBlue", 9.8f, Severity.CRITICAL,
                "Microsoft SMBv1", "Remote code execution in SMBv1",
                new String[]{"Windows Vista-10, Server 2008-2016"});

        // Heartbleed
        addKnownCve("CVE-2014-0160", "Heartbleed", 7.5f, Severity.HIGH,
                "OpenSSL", "Memory disclosure via TLS heartbeat",
                new String[]{"OpenSSL 1.0.1 - 1.0.1f"});

        // Shellshock
        addKnownCve("CVE-2014-6271", "Shellshock", 9.8f, Severity.CRITICAL,
                "GNU Bash", "Remote code execution via environment variables",
                new String[]{"Bash through 4.3"});

        // BlueKeep
        addKnownCve("CVE-2019-0708", "BlueKeep", 9.8f, Severity.CRITICAL,
                "Microsoft RDP", "Remote code execution in RDP",
                new String[]{"Windows 7, Server 2008/2008 R2"});

        // ProxyLogon
        addKnownCve("CVE-2021-26855", "ProxyLogon", 9.8f, Severity.CRITICAL,
                "Microsoft Exchange", "SSRF leading to RCE",
                new String[]{"Exchange Server 2013-2019"});

        // PrintNightmare
        addKnownCve("CVE-2021-34527", "PrintNightmare", 8.8f, Severity.HIGH,
                "Windows Print Spooler", "Remote code execution",
                new String[]{"Windows 7-11, Server 2008-2022"});

        // Apache Struts
        addKnownCve("CVE-2017-5638", "Apache Struts", 10.0f, Severity.CRITICAL,
                "Apache Struts 2", "Remote code execution via Content-Type header",
                new String[]{"Struts 2.3.x, 2.5.x"});

        // Dirty COW
        addKnownCve("CVE-2016-5195", "Dirty COW", 7.8f, Severity.HIGH,
                "Linux Kernel", "Local privilege escalation",
                new String[]{"Linux Kernel 2.x - 4.x"});

        // SambaCry
        addKnownCve("CVE-2017-7494", "SambaCry", 9.8f, Severity.CRITICAL,
                "Samba", "Remote code execution via writable share",
                new String[]{"Samba 3.5.0 - 4.6.4"});

        // Spring4Shell
        addKnownCve("CVE-2022-22965", "Spring4Shell", 9.8f, Severity.CRITICAL,
                "Spring Framework", "Remote code execution via data binding",
                new String[]{"Spring Framework 5.3.0-17, 5.2.0-19"});

        // Sudo Baron Samedit
        addKnownCve("CVE-2021-3156", "Baron Samedit", 7.8f, Severity.HIGH,
                "Sudo", "Heap buffer overflow privilege escalation",
                new String[]{"Sudo 1.8.2-1.9.5p1"});

        // Zerologon
        addKnownCve("CVE-2020-1472", "Zerologon", 10.0f, Severity.CRITICAL,
                "Microsoft Netlogon", "Privilege escalation via cryptographic flaw",
                new String[]{"Windows Server 2008-2019"});
    }

    private CveHelper() {}

    /**
     * CVE information container.
     */
    public static class CveInfo {
        public String cveId;
        public String commonName;
        public float cvssScore;
        public Severity severity;
        public String affectedProduct;
        public String description;
        public String[] affectedVersions;
        public String[] references;
        public String[] mitigations;
        public boolean hasExploit;
        public boolean isPatchAvailable;

        @NonNull
        @Override
        public String toString() {
            return String.format("CVE{id='%s', name='%s', cvss=%.1f, severity=%s}",
                    cveId, commonName, cvssScore, severity);
        }
    }

    /**
     * Severity levels based on CVSS.
     */
    public enum Severity {
        NONE(0.0f, 0.0f),
        LOW(0.1f, 3.9f),
        MEDIUM(4.0f, 6.9f),
        HIGH(7.0f, 8.9f),
        CRITICAL(9.0f, 10.0f);

        public final float minScore;
        public final float maxScore;

        Severity(float min, float max) {
            this.minScore = min;
            this.maxScore = max;
        }
    }

    /**
     * Validate CVE ID format.
     */
    public static boolean isValidCveId(@Nullable String cveId) {
        return cveId != null && CVE_PATTERN.matcher(cveId).matches();
    }

    /**
     * Normalize CVE ID to standard format.
     */
    @Nullable
    public static String normalizeCveId(@Nullable String cveId) {
        if (cveId == null) return null;
        Matcher m = CVE_PATTERN.matcher(cveId.toUpperCase());
        return m.find() ? m.group() : null;
    }

    /**
     * Extract all CVE IDs from text.
     */
    @NonNull
    public static List<String> extractCveIds(@NonNull String text) {
        List<String> cves = new ArrayList<>();
        Matcher m = CVE_PATTERN.matcher(text.toUpperCase());
        while (m.find()) {
            cves.add(m.group());
        }
        return cves;
    }

    /**
     * Get severity level from CVSS score.
     */
    @NonNull
    public static Severity getSeverity(float cvssScore) {
        if (cvssScore >= 9.0f) return Severity.CRITICAL;
        if (cvssScore >= 7.0f) return Severity.HIGH;
        if (cvssScore >= 4.0f) return Severity.MEDIUM;
        if (cvssScore >= 0.1f) return Severity.LOW;
        return Severity.NONE;
    }

    /**
     * Get severity label with color indicator.
     */
    @NonNull
    public static String getSeverityLabel(@NonNull Severity severity) {
        switch (severity) {
            case CRITICAL: return "CRITICAL";
            case HIGH: return "HIGH";
            case MEDIUM: return "MEDIUM";
            case LOW: return "LOW";
            default: return "NONE";
        }
    }

    /**
     * Get known CVE info.
     */
    @Nullable
    public static CveInfo getKnownCve(@NonNull String cveId) {
        String normalized = normalizeCveId(cveId);
        return normalized != null ? KNOWN_CVES.get(normalized) : null;
    }

    /**
     * Check if CVE is in known critical list.
     */
    public static boolean isKnownCritical(@NonNull String cveId) {
        CveInfo info = getKnownCve(cveId);
        return info != null && info.severity == Severity.CRITICAL;
    }

    /**
     * Search known CVEs by product name.
     */
    @NonNull
    public static List<CveInfo> searchByProduct(@NonNull String product) {
        List<CveInfo> results = new ArrayList<>();
        String lower = product.toLowerCase();

        for (CveInfo info : KNOWN_CVES.values()) {
            if (info.affectedProduct != null &&
                info.affectedProduct.toLowerCase().contains(lower)) {
                results.add(info);
            }
        }

        return results;
    }

    /**
     * Get all known CVEs with severity at or above threshold.
     */
    @NonNull
    public static List<CveInfo> getByMinSeverity(@NonNull Severity minSeverity) {
        List<CveInfo> results = new ArrayList<>();

        for (CveInfo info : KNOWN_CVES.values()) {
            if (info.cvssScore >= minSeverity.minScore) {
                results.add(info);
            }
        }

        return results;
    }

    /**
     * Check if a version might be affected by a CVE.
     */
    public static boolean mightBeAffected(@NonNull CveInfo cve, @NonNull String version) {
        if (cve.affectedVersions == null) return false;

        String lower = version.toLowerCase();
        for (String affected : cve.affectedVersions) {
            if (affected.toLowerCase().contains(lower) ||
                lower.contains(affected.toLowerCase())) {
                return true;
            }
        }

        return false;
    }

    /**
     * Get CVE year from ID.
     */
    public static int getCveYear(@NonNull String cveId) {
        String normalized = normalizeCveId(cveId);
        if (normalized == null) return -1;

        try {
            return Integer.parseInt(normalized.substring(4, 8));
        } catch (Exception e) {
            return -1;
        }
    }

    /**
     * Check if CVE is recent (within last N years).
     */
    public static boolean isRecent(@NonNull String cveId, int years) {
        int cveYear = getCveYear(cveId);
        if (cveYear < 0) return false;

        int currentYear = java.util.Calendar.getInstance().get(java.util.Calendar.YEAR);
        return (currentYear - cveYear) <= years;
    }

    /**
     * Generate a report for a CVE.
     */
    @NonNull
    public static String generateReport(@NonNull CveInfo cve) {
        StringBuilder sb = new StringBuilder();
        sb.append("=== ").append(cve.cveId).append(" ===\n\n");

        if (cve.commonName != null) {
            sb.append("Common Name: ").append(cve.commonName).append("\n");
        }

        sb.append("Severity: ").append(cve.severity).append(" (CVSS: ").append(cve.cvssScore).append(")\n");
        sb.append("Affected Product: ").append(cve.affectedProduct).append("\n\n");

        if (cve.description != null) {
            sb.append("Description:\n").append(cve.description).append("\n\n");
        }

        if (cve.affectedVersions != null && cve.affectedVersions.length > 0) {
            sb.append("Affected Versions:\n");
            for (String v : cve.affectedVersions) {
                sb.append("  - ").append(v).append("\n");
            }
            sb.append("\n");
        }

        sb.append("Exploit Available: ").append(cve.hasExploit ? "Yes" : "Unknown").append("\n");
        sb.append("Patch Available: ").append(cve.isPatchAvailable ? "Yes" : "Unknown").append("\n");

        return sb.toString();
    }

    /**
     * Get all known CVEs.
     */
    @NonNull
    public static List<CveInfo> getAllKnownCves() {
        return new ArrayList<>(KNOWN_CVES.values());
    }

    // Helper to add known CVE
    private static void addKnownCve(String id, String name, float cvss, Severity severity,
            String product, String description, String[] affected) {
        CveInfo info = new CveInfo();
        info.cveId = id;
        info.commonName = name;
        info.cvssScore = cvss;
        info.severity = severity;
        info.affectedProduct = product;
        info.description = description;
        info.affectedVersions = affected;
        info.hasExploit = true;
        info.isPatchAvailable = true;
        KNOWN_CVES.put(id, info);
    }
}
