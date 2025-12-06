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

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * WhoIsHelper - WHOIS lookup and domain information utilities.
 * 
 * Provides:
 * - WHOIS query execution
 * - Domain info parsing
 * - Registrar information
 * - Domain expiration checking
 * 
 * Usage:
 * {@code
 * // Get WHOIS info
 * WhoIsResult result = WhoIsHelper.lookup("example.com");
 * 
 * // Get registrar
 * String registrar = result.registrar;
 * 
 * // Check expiration
 * Date expires = result.expirationDate;
 * }
 */
public final class WhoIsHelper {
    
    private static final String TAG = "WhoIsHelper";
    private static final int WHOIS_PORT = 43;
    private static final int DEFAULT_TIMEOUT = 10000; // 10 seconds
    
    // WHOIS servers by TLD
    private static final Map<String, String> WHOIS_SERVERS = new HashMap<>();
    
    static {
        // Generic TLDs
        WHOIS_SERVERS.put("com", "whois.verisign-grs.com");
        WHOIS_SERVERS.put("net", "whois.verisign-grs.com");
        WHOIS_SERVERS.put("org", "whois.pir.org");
        WHOIS_SERVERS.put("info", "whois.afilias.net");
        WHOIS_SERVERS.put("biz", "whois.biz");
        WHOIS_SERVERS.put("name", "whois.nic.name");
        WHOIS_SERVERS.put("mobi", "whois.dotmobiregistry.net");
        WHOIS_SERVERS.put("pro", "whois.registrypro.pro");
        WHOIS_SERVERS.put("edu", "whois.educause.edu");
        WHOIS_SERVERS.put("gov", "whois.dotgov.gov");
        WHOIS_SERVERS.put("mil", "whois.nic.mil");
        WHOIS_SERVERS.put("int", "whois.iana.org");
        
        // New gTLDs
        WHOIS_SERVERS.put("io", "whois.nic.io");
        WHOIS_SERVERS.put("co", "whois.nic.co");
        WHOIS_SERVERS.put("me", "whois.nic.me");
        WHOIS_SERVERS.put("tv", "whois.nic.tv");
        WHOIS_SERVERS.put("cc", "ccwhois.verisign-grs.com");
        WHOIS_SERVERS.put("app", "whois.nic.google");
        WHOIS_SERVERS.put("dev", "whois.nic.google");
        
        // Country code TLDs
        WHOIS_SERVERS.put("uk", "whois.nic.uk");
        WHOIS_SERVERS.put("de", "whois.denic.de");
        WHOIS_SERVERS.put("fr", "whois.nic.fr");
        WHOIS_SERVERS.put("it", "whois.nic.it");
        WHOIS_SERVERS.put("es", "whois.nic.es");
        WHOIS_SERVERS.put("nl", "whois.domain-registry.nl");
        WHOIS_SERVERS.put("be", "whois.dns.be");
        WHOIS_SERVERS.put("at", "whois.nic.at");
        WHOIS_SERVERS.put("ch", "whois.nic.ch");
        WHOIS_SERVERS.put("ru", "whois.tcinet.ru");
        WHOIS_SERVERS.put("pl", "whois.dns.pl");
        WHOIS_SERVERS.put("cz", "whois.nic.cz");
        WHOIS_SERVERS.put("se", "whois.iis.se");
        WHOIS_SERVERS.put("no", "whois.norid.no");
        WHOIS_SERVERS.put("fi", "whois.fi");
        WHOIS_SERVERS.put("dk", "whois.dk-hostmaster.dk");
        WHOIS_SERVERS.put("au", "whois.auda.org.au");
        WHOIS_SERVERS.put("nz", "whois.srs.net.nz");
        WHOIS_SERVERS.put("jp", "whois.jprs.jp");
        WHOIS_SERVERS.put("kr", "whois.kr");
        WHOIS_SERVERS.put("cn", "whois.cnnic.cn");
        WHOIS_SERVERS.put("hk", "whois.hkirc.hk");
        WHOIS_SERVERS.put("tw", "whois.twnic.net.tw");
        WHOIS_SERVERS.put("in", "whois.registry.in");
        WHOIS_SERVERS.put("br", "whois.registro.br");
        WHOIS_SERVERS.put("mx", "whois.mx");
        WHOIS_SERVERS.put("ca", "whois.cira.ca");
        WHOIS_SERVERS.put("us", "whois.nic.us");
    }
    
    /**
     * WHOIS lookup result.
     */
    public static class WhoIsResult {
        public String domain;
        public String registrar;
        public String registrant;
        public String registrantOrg;
        public String registrantEmail;
        public String creationDate;
        public String expirationDate;
        public String updatedDate;
        public List<String> nameServers;
        public String status;
        public String rawResponse;
        public boolean isAvailable;
        public long queryTimeMs;
        
        public WhoIsResult() {
            nameServers = new ArrayList<>();
        }
        
        @NonNull
        @Override
        public String toString() {
            return String.format("WhoIs{domain='%s', registrar='%s', expires='%s'}",
                    domain, registrar, expirationDate);
        }
    }
    
    private WhoIsHelper() {}
    
    /**
     * Perform WHOIS lookup for a domain.
     */
    @NonNull
    public static WhoIsResult lookup(@NonNull String domain) {
        return lookup(domain, DEFAULT_TIMEOUT);
    }
    
    /**
     * Perform WHOIS lookup with custom timeout.
     */
    @NonNull
    public static WhoIsResult lookup(@NonNull String domain, int timeoutMs) {
        WhoIsResult result = new WhoIsResult();
        result.domain = domain.toLowerCase().trim();
        
        long startTime = java.lang.System.currentTimeMillis();
        
        // Get TLD and find appropriate WHOIS server
        String tld = getTld(result.domain);
        String whoisServer = WHOIS_SERVERS.getOrDefault(tld, "whois.iana.org");
        
        // Perform query
        String rawResponse = queryWhoisServer(whoisServer, result.domain, timeoutMs);
        result.rawResponse = rawResponse;
        result.queryTimeMs = java.lang.System.currentTimeMillis() - startTime;
        
        if (rawResponse != null && !rawResponse.isEmpty()) {
            parseWhoisResponse(result, rawResponse);
        }
        
        return result;
    }
    
    /**
     * Query a WHOIS server.
     */
    @Nullable
    private static String queryWhoisServer(@NonNull String server, @NonNull String domain, int timeoutMs) {
        java.net.Socket socket = null;
        BufferedReader reader = null;
        java.io.PrintWriter writer = null;
        
        try {
            socket = new java.net.Socket();
            socket.connect(new java.net.InetSocketAddress(server, WHOIS_PORT), timeoutMs);
            socket.setSoTimeout(timeoutMs);
            
            writer = new java.io.PrintWriter(socket.getOutputStream(), true);
            reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            
            // Send query
            writer.println(domain);
            
            // Read response
            StringBuilder response = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                response.append(line).append("\n");
            }
            
            return response.toString();
            
        } catch (Exception e) {
            Log.w(TAG, "WHOIS query failed for " + domain + " on " + server, e);
            return null;
        } finally {
            try { if (reader != null) reader.close(); } catch (Exception ignored) {}
            try { if (writer != null) writer.close(); } catch (Exception ignored) {}
            try { if (socket != null) socket.close(); } catch (Exception ignored) {}
        }
    }
    
    /**
     * Parse WHOIS response.
     */
    private static void parseWhoisResponse(@NonNull WhoIsResult result, @NonNull String response) {
        String lower = response.toLowerCase();
        
        // Check if domain is available
        result.isAvailable = lower.contains("no match") || 
                             lower.contains("not found") ||
                             lower.contains("no entries found") ||
                             lower.contains("status: free");
        
        if (result.isAvailable) {
            return;
        }
        
        // Parse registrar
        result.registrar = extractField(response, 
                "Registrar:", "Registrar Name:", "Sponsoring Registrar:");
        
        // Parse registrant
        result.registrant = extractField(response, 
                "Registrant Name:", "Registrant:", "Owner:");
        result.registrantOrg = extractField(response, 
                "Registrant Organization:", "Registrant Organisation:", "Organization:");
        result.registrantEmail = extractField(response, 
                "Registrant Email:", "Admin Email:", "Tech Email:");
        
        // Parse dates
        result.creationDate = extractField(response, 
                "Creation Date:", "Created:", "Created On:", "Registration Date:", "Registered:");
        result.expirationDate = extractField(response, 
                "Expiration Date:", "Expiry Date:", "Registry Expiry Date:", "Expires:", "Renewal Date:");
        result.updatedDate = extractField(response, 
                "Updated Date:", "Last Updated:", "Last Modified:", "Modified:");
        
        // Parse name servers
        Pattern nsPattern = Pattern.compile("(?:Name Server|nserver|NS):\\s*([\\w.-]+)", Pattern.CASE_INSENSITIVE);
        Matcher nsMatcher = nsPattern.matcher(response);
        while (nsMatcher.find()) {
            String ns = nsMatcher.group(1).toLowerCase();
            if (!result.nameServers.contains(ns)) {
                result.nameServers.add(ns);
            }
        }
        
        // Parse status
        result.status = extractField(response, "Domain Status:", "Status:");
    }
    
    /**
     * Extract field value from WHOIS response.
     */
    @Nullable
    private static String extractField(@NonNull String response, @NonNull String... fieldNames) {
        for (String fieldName : fieldNames) {
            Pattern pattern = Pattern.compile(
                    Pattern.quote(fieldName) + "\\s*(.+?)(?:\\r?\\n|$)",
                    Pattern.CASE_INSENSITIVE);
            Matcher matcher = pattern.matcher(response);
            if (matcher.find()) {
                return matcher.group(1).trim();
            }
        }
        return null;
    }
    
    /**
     * Get TLD from domain name.
     */
    @NonNull
    private static String getTld(@NonNull String domain) {
        String[] parts = domain.split("\\.");
        if (parts.length >= 2) {
            // Handle second-level TLDs like co.uk, com.au
            String lastTwo = parts[parts.length - 2] + "." + parts[parts.length - 1];
            if (isSecondLevelTld(lastTwo)) {
                return lastTwo;
            }
            return parts[parts.length - 1];
        }
        return domain;
    }
    
    /**
     * Check if it's a known second-level TLD.
     */
    private static boolean isSecondLevelTld(@NonNull String tld) {
        String[] secondLevelTlds = {
            "co.uk", "org.uk", "me.uk", "ltd.uk",
            "com.au", "net.au", "org.au",
            "co.nz", "net.nz", "org.nz",
            "co.jp", "or.jp", "ne.jp",
            "com.br", "org.br", "net.br",
            "co.in", "net.in", "org.in"
        };
        
        for (String slt : secondLevelTlds) {
            if (tld.equalsIgnoreCase(slt)) {
                return true;
            }
        }
        return false;
    }
    
    /**
     * Get WHOIS server for a TLD.
     */
    @NonNull
    public static String getWhoisServer(@NonNull String tld) {
        return WHOIS_SERVERS.getOrDefault(tld.toLowerCase(), "whois.iana.org");
    }
    
    /**
     * Check if domain is available (quick check).
     */
    public static boolean isDomainAvailable(@NonNull String domain) {
        WhoIsResult result = lookup(domain, 5000);
        return result.isAvailable;
    }
    
    /**
     * Get supported TLDs.
     */
    @NonNull
    public static List<String> getSupportedTlds() {
        return new ArrayList<>(WHOIS_SERVERS.keySet());
    }
    
    /**
     * Validate domain name format.
     */
    public static boolean isValidDomainName(@NonNull String domain) {
        // Basic domain validation
        return domain.matches("^[a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?(\\.[a-zA-Z]{2,})+$");
    }
    
    /**
     * Extract domain from URL.
     */
    @Nullable
    public static String extractDomainFromUrl(@NonNull String url) {
        try {
            String domain = url.toLowerCase()
                    .replaceFirst("^(https?://)?", "")
                    .replaceFirst("^www\\.", "")
                    .split("/")[0]
                    .split(":")[0];
            return isValidDomainName(domain) ? domain : null;
        } catch (Exception e) {
            return null;
        }
    }
}
