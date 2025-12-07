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

import java.util.HashMap;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * ServiceVersionHelper - Parse and compare software version strings.
 *
 * Provides:
 * - Version string parsing
 * - Version comparison
 * - Vulnerability version range checking
 * - Software version normalization
 *
 * Usage:
 * {@code
 * // Parse version
 * Version v = ServiceVersionHelper.parseVersion("2.4.51");
 *
 * // Compare versions
 * int cmp = ServiceVersionHelper.compareVersions("2.4.51", "2.4.49");
 *
 * // Check if vulnerable
 * boolean vuln = ServiceVersionHelper.isVersionInRange("2.4.51", "2.4.0", "2.4.50");
 * }
 */
public final class ServiceVersionHelper {

    private static final Pattern VERSION_PATTERN = Pattern.compile(
            "(\\d+)(?:\\.(\\d+))?(?:\\.(\\d+))?(?:\\.(\\d+))?(?:[._-]?(\\w+))?");

    /**
     * Parsed version information.
     */
    public static class Version implements Comparable<Version> {
        public int major;
        public int minor;
        public int patch;
        public int build;
        public String suffix; // alpha, beta, rc, p, etc.
        public String original;

        public Version() {}

        public Version(int major, int minor, int patch) {
            this.major = major;
            this.minor = minor;
            this.patch = patch;
        }

        @Override
        public int compareTo(@NonNull Version other) {
            int cmp = Integer.compare(major, other.major);
            if (cmp != 0) return cmp;

            cmp = Integer.compare(minor, other.minor);
            if (cmp != 0) return cmp;

            cmp = Integer.compare(patch, other.patch);
            if (cmp != 0) return cmp;

            cmp = Integer.compare(build, other.build);
            if (cmp != 0) return cmp;

            // Handle suffix comparison (alpha < beta < rc < release)
            return compareSuffix(suffix, other.suffix);
        }

        @NonNull
        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append(major).append(".").append(minor).append(".").append(patch);
            if (build > 0) sb.append(".").append(build);
            if (suffix != null && !suffix.isEmpty()) sb.append("-").append(suffix);
            return sb.toString();
        }

        public boolean isNewerThan(@NonNull Version other) {
            return compareTo(other) > 0;
        }

        public boolean isOlderThan(@NonNull Version other) {
            return compareTo(other) < 0;
        }

        public boolean equals(@NonNull Version other) {
            return compareTo(other) == 0;
        }
    }

    /**
     * Known vulnerable version ranges.
     */
    public static class VulnerabilityRange {
        public String cveId;
        public String product;
        public Version minVersion;
        public Version maxVersion;
        public String description;

        public boolean isVulnerable(@NonNull Version version) {
            boolean afterMin = minVersion == null || version.compareTo(minVersion) >= 0;
            boolean beforeMax = maxVersion == null || version.compareTo(maxVersion) <= 0;
            return afterMin && beforeMax;
        }

        @NonNull
        @Override
        public String toString() {
            return String.format("%s: %s (%s - %s)",
                    cveId, product,
                    minVersion != null ? minVersion : "*",
                    maxVersion != null ? maxVersion : "*");
        }
    }

    private ServiceVersionHelper() {}

    /**
     * Parse a version string.
     */
    @Nullable
    public static Version parseVersion(@Nullable String versionString) {
        if (versionString == null || versionString.isEmpty()) {
            return null;
        }

        Version version = new Version();
        version.original = versionString;

        Matcher matcher = VERSION_PATTERN.matcher(versionString);
        if (matcher.find()) {
            try {
                if (matcher.group(1) != null) {
                    version.major = Integer.parseInt(matcher.group(1));
                }
                if (matcher.group(2) != null) {
                    version.minor = Integer.parseInt(matcher.group(2));
                }
                if (matcher.group(3) != null) {
                    version.patch = Integer.parseInt(matcher.group(3));
                }
                if (matcher.group(4) != null) {
                    version.build = Integer.parseInt(matcher.group(4));
                }
                if (matcher.group(5) != null) {
                    version.suffix = matcher.group(5).toLowerCase();
                }
            } catch (NumberFormatException e) {
                return null;
            }
        } else {
            return null;
        }

        return version;
    }

    /**
     * Compare two version strings.
     *
     * @return negative if v1 < v2, positive if v1 > v2, 0 if equal
     */
    public static int compareVersions(@NonNull String version1, @NonNull String version2) {
        Version v1 = parseVersion(version1);
        Version v2 = parseVersion(version2);

        if (v1 == null && v2 == null) return 0;
        if (v1 == null) return -1;
        if (v2 == null) return 1;

        return v1.compareTo(v2);
    }

    /**
     * Check if version is in range [minVersion, maxVersion].
     */
    public static boolean isVersionInRange(@NonNull String version,
                                           @Nullable String minVersion,
                                           @Nullable String maxVersion) {
        Version v = parseVersion(version);
        if (v == null) return false;

        Version min = minVersion != null ? parseVersion(minVersion) : null;
        Version max = maxVersion != null ? parseVersion(maxVersion) : null;

        boolean afterMin = min == null || v.compareTo(min) >= 0;
        boolean beforeMax = max == null || v.compareTo(max) <= 0;

        return afterMin && beforeMax;
    }

    /**
     * Compare version suffixes.
     * Order: alpha < beta < rc < (empty/release) < p (patch)
     */
    private static int compareSuffix(@Nullable String s1, @Nullable String s2) {
        int priority1 = getSuffixPriority(s1);
        int priority2 = getSuffixPriority(s2);
        return Integer.compare(priority1, priority2);
    }

    /**
     * Get numeric priority for version suffix.
     */
    private static int getSuffixPriority(@Nullable String suffix) {
        if (suffix == null || suffix.isEmpty()) return 100;

        String lower = suffix.toLowerCase();
        if (lower.startsWith("alpha") || lower.startsWith("a")) return 10;
        if (lower.startsWith("beta") || lower.startsWith("b")) return 20;
        if (lower.startsWith("rc") || lower.startsWith("cr")) return 30;
        if (lower.startsWith("pre")) return 25;
        if (lower.startsWith("dev")) return 5;
        if (lower.startsWith("snapshot")) return 1;
        if (lower.startsWith("p") && lower.length() <= 3) return 110; // patch

        return 100; // release
    }

    /**
     * Normalize version string for comparison.
     */
    @NonNull
    public static String normalizeVersion(@NonNull String version) {
        Version v = parseVersion(version);
        if (v == null) return version;
        return v.toString();
    }

    /**
     * Extract version from banner/text.
     */
    @Nullable
    public static String extractVersion(@NonNull String text, @NonNull String product) {
        // Common patterns for version extraction
        String[] patterns = {
                product + "[/\\s_-]?v?([\\d.]+[\\w-]*)",
                "version[:\\s]+([\\d.]+[\\w-]*)",
                "v([\\d.]+[\\w-]*)"
        };

        for (String patternStr : patterns) {
            try {
                Pattern pattern = Pattern.compile(patternStr, Pattern.CASE_INSENSITIVE);
                Matcher matcher = pattern.matcher(text);
                if (matcher.find()) {
                    return matcher.group(1);
                }
            } catch (Exception ignored) {}
        }

        return null;
    }

    /**
     * Common known vulnerable versions.
     */
    private static final Map<String, VulnerabilityRange[]> KNOWN_VULNERABILITIES = new HashMap<>();

    static {
        // Apache HTTP Server
        KNOWN_VULNERABILITIES.put("apache", new VulnerabilityRange[]{
                createRange("CVE-2021-41773", "Apache", "2.4.49", "2.4.49",
                        "Path traversal and file disclosure"),
                createRange("CVE-2021-42013", "Apache", "2.4.49", "2.4.50",
                        "Path traversal (incomplete fix for CVE-2021-41773)"),
                createRange("CVE-2022-22720", "Apache", "2.4.0", "2.4.52",
                        "HTTP request smuggling")
        });

        // OpenSSH
        KNOWN_VULNERABILITIES.put("openssh", new VulnerabilityRange[]{
                createRange("CVE-2023-38408", "OpenSSH", "5.5", "9.3",
                        "Remote code execution via ssh-agent"),
                createRange("CVE-2021-41617", "OpenSSH", "6.2", "8.7",
                        "Privilege escalation")
        });

        // nginx
        KNOWN_VULNERABILITIES.put("nginx", new VulnerabilityRange[]{
                createRange("CVE-2021-23017", "nginx", "0.6.18", "1.20.0",
                        "DNS resolver vulnerabilities")
        });

        // vsftpd
        KNOWN_VULNERABILITIES.put("vsftpd", new VulnerabilityRange[]{
                createRange("CVE-2011-2523", "vsftpd", "2.3.4", "2.3.4",
                        "Backdoor command execution")
        });

        // ProFTPD
        KNOWN_VULNERABILITIES.put("proftpd", new VulnerabilityRange[]{
                createRange("CVE-2019-12815", "ProFTPD", "1.3.0", "1.3.5b",
                        "Remote code execution via mod_copy")
        });
    }

    /**
     * Create a vulnerability range.
     */
    private static VulnerabilityRange createRange(String cve, String product,
                                                   String min, String max, String desc) {
        VulnerabilityRange range = new VulnerabilityRange();
        range.cveId = cve;
        range.product = product;
        range.minVersion = parseVersion(min);
        range.maxVersion = parseVersion(max);
        range.description = desc;
        return range;
    }

    /**
     * Check for known vulnerabilities based on product and version.
     */
    @NonNull
    public static java.util.List<VulnerabilityRange> checkKnownVulnerabilities(
            @NonNull String product, @NonNull String version) {

        java.util.List<VulnerabilityRange> vulns = new java.util.ArrayList<>();
        Version v = parseVersion(version);
        if (v == null) return vulns;

        String productLower = product.toLowerCase();

        for (Map.Entry<String, VulnerabilityRange[]> entry : KNOWN_VULNERABILITIES.entrySet()) {
            if (productLower.contains(entry.getKey())) {
                for (VulnerabilityRange range : entry.getValue()) {
                    if (range.isVulnerable(v)) {
                        vulns.add(range);
                    }
                }
            }
        }

        return vulns;
    }

    /**
     * Get software version status (outdated, current, etc.).
     */
    @NonNull
    public static String getVersionStatus(@NonNull String version, @Nullable String latestVersion) {
        if (latestVersion == null) return "unknown";

        int cmp = compareVersions(version, latestVersion);
        if (cmp == 0) return "current";
        if (cmp < 0) return "outdated";
        return "newer"; // Running version newer than known latest
    }
}
