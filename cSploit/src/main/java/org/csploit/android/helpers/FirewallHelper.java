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
import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * FirewallHelper - iptables/firewall management utilities.
 * 
 * Provides:
 * - iptables rule management
 * - NAT configuration
 * - Port forwarding
 * - Traffic filtering
 * - Firewall state inspection
 * 
 * Note: Most operations require root privileges.
 * 
 * Usage:
 * {@code
 * // Check iptables availability
 * boolean available = FirewallHelper.isIptablesAvailable();
 * 
 * // List rules
 * List<IptablesRule> rules = FirewallHelper.listRules();
 * 
 * // Add port forward
 * FirewallHelper.addPortForward(8080, 80, "192.168.1.100");
 * }
 */
public final class FirewallHelper {
    
    private static final String TAG = "FirewallHelper";
    
    private static final String IPTABLES = "iptables";
    @SuppressWarnings("unused") // Reserved for IPv6 support
    private static final String IP6TABLES = "ip6tables";
    
    /**
     * iptables chains.
     */
    public enum Chain {
        INPUT,
        OUTPUT,
        FORWARD,
        PREROUTING,
        POSTROUTING
    }
    
    /**
     * iptables tables.
     */
    public enum Table {
        FILTER("filter"),
        NAT("nat"),
        MANGLE("mangle"),
        RAW("raw");
        
        private final String name;
        
        Table(String name) {
            this.name = name;
        }
        
        public String getName() {
            return name;
        }
    }
    
    /**
     * iptables targets/actions.
     */
    public enum Target {
        ACCEPT,
        DROP,
        REJECT,
        LOG,
        DNAT,
        SNAT,
        MASQUERADE,
        REDIRECT,
        RETURN
    }
    
    /**
     * Protocol types.
     */
    public enum Protocol {
        TCP("tcp"),
        UDP("udp"),
        ICMP("icmp"),
        ALL("all");
        
        private final String name;
        
        Protocol(String name) {
            this.name = name;
        }
        
        public String getName() {
            return name;
        }
    }
    
    /**
     * Represents an iptables rule.
     */
    public static class IptablesRule {
        public Table table;
        public Chain chain;
        public Protocol protocol;
        public String source;
        public String destination;
        public int sourcePort;
        public int destinationPort;
        public Target target;
        public String comment;
        public int ruleNumber;
        public long packets;
        public long bytes;
        
        @NonNull
        @Override
        public String toString() {
            StringBuilder sb = new StringBuilder();
            sb.append(chain).append(" ");
            if (protocol != null) sb.append("-p ").append(protocol.getName()).append(" ");
            if (source != null) sb.append("-s ").append(source).append(" ");
            if (destination != null) sb.append("-d ").append(destination).append(" ");
            if (sourcePort > 0) sb.append("--sport ").append(sourcePort).append(" ");
            if (destinationPort > 0) sb.append("--dport ").append(destinationPort).append(" ");
            sb.append("-j ").append(target);
            return sb.toString();
        }
    }
    
    private FirewallHelper() {}
    
    /**
     * Check if iptables is available.
     */
    public static boolean isIptablesAvailable() {
        try {
            Process process = Runtime.getRuntime().exec(new String[]{IPTABLES, "-V"});
            process.waitFor();
            return process.exitValue() == 0;
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Execute iptables command.
     * 
     * @param args command arguments
     * @return command output
     */
    @Nullable
    public static String executeIptables(@NonNull String... args) {
        try {
            String[] cmd = new String[args.length + 1];
            cmd[0] = IPTABLES;
            java.lang.System.arraycopy(args, 0, cmd, 1, args.length);
            
            Process process = Runtime.getRuntime().exec(cmd);
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()));
            BufferedReader errorReader = new BufferedReader(
                    new InputStreamReader(process.getErrorStream()));
            
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            
            StringBuilder error = new StringBuilder();
            while ((line = errorReader.readLine()) != null) {
                error.append(line).append("\n");
            }
            
            process.waitFor();
            
            if (process.exitValue() != 0) {
                Log.w(TAG, "iptables error: " + error.toString());
                return null;
            }
            
            return output.toString();
        } catch (Exception e) {
            Log.e(TAG, "Failed to execute iptables", e);
            return null;
        }
    }
    
    /**
     * List all rules in a table.
     */
    @NonNull
    public static List<IptablesRule> listRules(@NonNull Table table) {
        List<IptablesRule> rules = new ArrayList<>();
        String output = executeIptables("-t", table.getName(), "-L", "-n", "-v", "--line-numbers");
        
        if (output == null) {
            return rules;
        }
        
        // Parse output (simplified parsing)
        String[] lines = output.split("\n");
        Chain currentChain = null;
        
        Pattern chainPattern = Pattern.compile("Chain (\\w+)");
        Pattern rulePattern = Pattern.compile("^(\\d+)\\s+(\\d+)\\s+(\\d+)\\s+(\\w+)\\s+([\\w-]+)\\s+--\\s+([\\w*]+)\\s+([\\w*]+)\\s+(\\S+)\\s+(\\S+)");
        
        for (String line : lines) {
            Matcher chainMatcher = chainPattern.matcher(line);
            if (chainMatcher.find()) {
                try {
                    currentChain = Chain.valueOf(chainMatcher.group(1));
                } catch (IllegalArgumentException e) {
                    currentChain = null;
                }
                continue;
            }
            
            if (currentChain != null) {
                // Try to parse rule line
                Matcher ruleMatcher = rulePattern.matcher(line);
                if (ruleMatcher.find()) {
                    IptablesRule rule = new IptablesRule();
                    rule.table = table;
                    rule.chain = currentChain;
                    rule.ruleNumber = Integer.parseInt(ruleMatcher.group(1));
                    rule.packets = Long.parseLong(ruleMatcher.group(2));
                    rule.bytes = Long.parseLong(ruleMatcher.group(3));
                    
                    try {
                        rule.target = Target.valueOf(ruleMatcher.group(4));
                    } catch (IllegalArgumentException e) {
                        // Custom target
                    }
                    
                    try {
                        String proto = ruleMatcher.group(5);
                        if (!proto.equals("all")) {
                            rule.protocol = Protocol.valueOf(proto.toUpperCase());
                        }
                    } catch (IllegalArgumentException e) {
                        rule.protocol = Protocol.ALL;
                    }
                    
                    String src = ruleMatcher.group(8);
                    if (!src.equals("0.0.0.0/0") && !src.equals("*")) {
                        rule.source = src;
                    }
                    
                    String dst = ruleMatcher.group(9);
                    if (!dst.equals("0.0.0.0/0") && !dst.equals("*")) {
                        rule.destination = dst;
                    }
                    
                    rules.add(rule);
                }
            }
        }
        
        return rules;
    }
    
    /**
     * List all rules in filter table.
     */
    @NonNull
    public static List<IptablesRule> listRules() {
        return listRules(Table.FILTER);
    }
    
    /**
     * Add a rule to accept traffic.
     */
    public static boolean acceptTraffic(@NonNull Chain chain, @NonNull Protocol protocol,
                                        @Nullable String source, int port) {
        List<String> args = new ArrayList<>();
        args.add("-A");
        args.add(chain.name());
        args.add("-p");
        args.add(protocol.getName());
        
        if (source != null) {
            args.add("-s");
            args.add(source);
        }
        
        if (port > 0) {
            args.add("--dport");
            args.add(String.valueOf(port));
        }
        
        args.add("-j");
        args.add("ACCEPT");
        
        String result = executeIptables(args.toArray(new String[0]));
        return result != null;
    }
    
    /**
     * Add a rule to drop traffic.
     */
    public static boolean dropTraffic(@NonNull Chain chain, @NonNull Protocol protocol,
                                      @Nullable String source, int port) {
        List<String> args = new ArrayList<>();
        args.add("-A");
        args.add(chain.name());
        args.add("-p");
        args.add(protocol.getName());
        
        if (source != null) {
            args.add("-s");
            args.add(source);
        }
        
        if (port > 0) {
            args.add("--dport");
            args.add(String.valueOf(port));
        }
        
        args.add("-j");
        args.add("DROP");
        
        String result = executeIptables(args.toArray(new String[0]));
        return result != null;
    }
    
    /**
     * Add port forwarding rule.
     */
    public static boolean addPortForward(int externalPort, int internalPort,
                                         @NonNull String internalIp) {
        return addPortForward(Protocol.TCP, externalPort, internalPort, internalIp);
    }
    
    /**
     * Add port forwarding rule with protocol.
     */
    public static boolean addPortForward(@NonNull Protocol protocol, int externalPort,
                                         int internalPort, @NonNull String internalIp) {
        String result = executeIptables(
                "-t", "nat", "-A", "PREROUTING",
                "-p", protocol.getName(),
                "--dport", String.valueOf(externalPort),
                "-j", "DNAT",
                "--to-destination", internalIp + ":" + internalPort
        );
        return result != null;
    }
    
    /**
     * Enable NAT masquerading on interface.
     */
    public static boolean enableMasquerade(@NonNull String outInterface) {
        String result = executeIptables(
                "-t", "nat", "-A", "POSTROUTING",
                "-o", outInterface,
                "-j", "MASQUERADE"
        );
        return result != null;
    }
    
    /**
     * Enable IP forwarding.
     */
    public static boolean enableIpForwarding() {
        try {
            Process process = Runtime.getRuntime().exec(new String[]{
                    "sh", "-c", "echo 1 > /proc/sys/net/ipv4/ip_forward"
            });
            process.waitFor();
            return process.exitValue() == 0;
        } catch (Exception e) {
            Log.e(TAG, "Failed to enable IP forwarding", e);
            return false;
        }
    }
    
    /**
     * Disable IP forwarding.
     */
    public static boolean disableIpForwarding() {
        try {
            Process process = Runtime.getRuntime().exec(new String[]{
                    "sh", "-c", "echo 0 > /proc/sys/net/ipv4/ip_forward"
            });
            process.waitFor();
            return process.exitValue() == 0;
        } catch (Exception e) {
            Log.e(TAG, "Failed to disable IP forwarding", e);
            return false;
        }
    }
    
    /**
     * Check if IP forwarding is enabled.
     */
    public static boolean isIpForwardingEnabled() {
        try {
            Process process = Runtime.getRuntime().exec(new String[]{
                    "cat", "/proc/sys/net/ipv4/ip_forward"
            });
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()));
            String line = reader.readLine();
            process.waitFor();
            return "1".equals(line != null ? line.trim() : null);
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Delete rule by number.
     */
    public static boolean deleteRule(@NonNull Table table, @NonNull Chain chain, int ruleNumber) {
        String result = executeIptables("-t", table.getName(), "-D", chain.name(),
                String.valueOf(ruleNumber));
        return result != null;
    }
    
    /**
     * Flush all rules in a chain.
     */
    public static boolean flushChain(@NonNull Table table, @NonNull Chain chain) {
        String result = executeIptables("-t", table.getName(), "-F", chain.name());
        return result != null;
    }
    
    /**
     * Flush all rules in all chains.
     */
    public static boolean flushAll() {
        boolean success = true;
        success &= executeIptables("-F") != null;
        success &= executeIptables("-t", "nat", "-F") != null;
        success &= executeIptables("-t", "mangle", "-F") != null;
        return success;
    }
    
    /**
     * Save current rules to file.
     */
    @Nullable
    public static String saveRules() {
        try {
            Process process = Runtime.getRuntime().exec(new String[]{"iptables-save"});
            BufferedReader reader = new BufferedReader(
                    new InputStreamReader(process.getInputStream()));
            StringBuilder output = new StringBuilder();
            String line;
            while ((line = reader.readLine()) != null) {
                output.append(line).append("\n");
            }
            process.waitFor();
            return output.toString();
        } catch (Exception e) {
            Log.e(TAG, "Failed to save rules", e);
            return null;
        }
    }
    
    /**
     * Get firewall statistics.
     */
    @NonNull
    public static FirewallStats getStats() {
        FirewallStats stats = new FirewallStats();
        
        for (Table table : Table.values()) {
            List<IptablesRule> rules = listRules(table);
            stats.totalRules += rules.size();
            
            for (IptablesRule rule : rules) {
                stats.totalPackets += rule.packets;
                stats.totalBytes += rule.bytes;
            }
        }
        
        stats.ipForwardingEnabled = isIpForwardingEnabled();
        
        return stats;
    }
    
    /**
     * Firewall statistics.
     */
    public static class FirewallStats {
        public int totalRules;
        public long totalPackets;
        public long totalBytes;
        public boolean ipForwardingEnabled;
        
        @NonNull
        @Override
        public String toString() {
            return String.format("FirewallStats{rules=%d, packets=%d, bytes=%d, forwarding=%s}",
                    totalRules, totalPackets, totalBytes, ipForwardingEnabled);
        }
    }
}
