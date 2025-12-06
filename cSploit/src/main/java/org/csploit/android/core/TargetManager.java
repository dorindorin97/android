/*
 * This file is part of the cSploit.
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
package org.csploit.android.core;

import org.csploit.android.net.Target;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import java.util.function.Predicate;

/**
 * Manager class for target-related operations.
 * Provides utility methods for filtering, searching, and managing targets.
 */
public class TargetManager {

    private static final String TAG = "TargetManager";

    /**
     * Get all targets that match a given predicate.
     *
     * @param predicate the condition to match
     * @return list of matching targets
     */
    public static List<Target> findTargets(Predicate<Target> predicate) {
        List<Target> result = new ArrayList<>();
        for (Target target : System.getTargets()) {
            if (predicate.test(target)) {
                result.add(target);
            }
        }
        return result;
    }

    /**
     * Get all targets that are endpoints (not networks or remote hosts).
     *
     * @return list of endpoint targets
     */
    public static List<Target> getEndpointTargets() {
        return findTargets(t -> t.getType() == Target.Type.ENDPOINT);
    }

    /**
     * Get all targets that are selected for batch operations.
     *
     * @return list of selected targets
     */
    public static List<Target> getSelectedTargets() {
        return findTargets(Target::isSelected);
    }

    /**
     * Get UUIDs of selected targets for use with MultiAttackService.
     *
     * @return array of UUID strings
     */
    public static String[] getSelectedTargetUuids() {
        List<Target> selected = getSelectedTargets();
        String[] uuids = new String[selected.size()];
        for (int i = 0; i < selected.size(); i++) {
            uuids[i] = selected.get(i).getUuid();
        }
        return uuids;
    }

    /**
     * Get all targets that have open ports.
     *
     * @return list of targets with open ports
     */
    public static List<Target> getTargetsWithOpenPorts() {
        return findTargets(Target::hasOpenPorts);
    }

    /**
     * Get all targets that have known vulnerabilities/exploits.
     *
     * @return list of targets with exploits
     */
    public static List<Target> getVulnerableTargets() {
        return findTargets(t -> !t.getExploits().isEmpty());
    }

    /**
     * Get all targets that are currently connected to the network.
     *
     * @return list of connected targets
     */
    public static List<Target> getConnectedTargets() {
        return findTargets(Target::isConnected);
    }

    /**
     * Find a target by its IP address string.
     *
     * @param ipAddress the IP address to search for
     * @return the matching target or null if not found
     */
    public static Target findByIpAddress(String ipAddress) {
        if (ipAddress == null || ipAddress.isEmpty()) {
            return null;
        }
        for (Target target : System.getTargets()) {
            if (target.getAddress() != null &&
                ipAddress.equals(target.getAddress().getHostAddress())) {
                return target;
            }
        }
        return null;
    }

    /**
     * Find a target by its hostname.
     *
     * @param hostname the hostname to search for
     * @return the matching target or null if not found
     */
    public static Target findByHostname(String hostname) {
        if (hostname == null || hostname.isEmpty()) {
            return null;
        }
        for (Target target : System.getTargets()) {
            String targetHostname = target.getHostname();
            if (targetHostname != null && targetHostname.equalsIgnoreCase(hostname)) {
                return target;
            }
        }
        return null;
    }

    /**
     * Find a target by its alias.
     *
     * @param alias the alias to search for
     * @return the matching target or null if not found
     */
    public static Target findByAlias(String alias) {
        if (alias == null || alias.isEmpty()) {
            return null;
        }
        for (Target target : System.getTargets()) {
            if (target.hasAlias() && alias.equalsIgnoreCase(target.getAlias())) {
                return target;
            }
        }
        return null;
    }

    /**
     * Get targets by their device type (e.g., "router", "phone", "computer").
     *
     * @param deviceType the device type to filter by
     * @return list of targets matching the device type
     */
    public static List<Target> getTargetsByDeviceType(String deviceType) {
        if (deviceType == null || deviceType.isEmpty()) {
            return new ArrayList<>();
        }
        return findTargets(t -> {
            String type = t.getDeviceType();
            return type != null && type.toLowerCase().contains(deviceType.toLowerCase());
        });
    }

    /**
     * Get targets by their operating system.
     *
     * @param os the OS to filter by (partial match)
     * @return list of targets running the specified OS
     */
    public static List<Target> getTargetsByOS(String os) {
        if (os == null || os.isEmpty()) {
            return new ArrayList<>();
        }
        return findTargets(t -> {
            String targetOs = t.getDeviceOS();
            return targetOs != null && targetOs.toLowerCase().contains(os.toLowerCase());
        });
    }

    /**
     * Select multiple targets at once.
     *
     * @param targets the targets to select
     */
    public static void selectTargets(Collection<Target> targets) {
        for (Target target : targets) {
            target.setSelected(true);
        }
    }

    /**
     * Deselect all targets.
     */
    public static void deselectAllTargets() {
        for (Target target : System.getTargets()) {
            target.setSelected(false);
        }
    }

    /**
     * Get the count of targets by type.
     *
     * @return array [endpoints, networks, remote]
     */
    public static int[] getTargetCountByType() {
        int endpoints = 0, networks = 0, remote = 0;
        for (Target target : System.getTargets()) {
            switch (target.getType()) {
                case ENDPOINT:
                    endpoints++;
                    break;
                case NETWORK:
                    networks++;
                    break;
                case REMOTE:
                    remote++;
                    break;
            }
        }
        return new int[]{endpoints, networks, remote};
    }

    /**
     * Get summary statistics about discovered targets.
     *
     * @return a TargetStats object with various statistics
     */
    public static TargetStats getStats() {
        return new TargetStats();
    }

    /**
     * Statistics about discovered targets.
     */
    public static class TargetStats {
        public final int total;
        public final int endpoints;
        public final int networks;
        public final int remote;
        public final int connected;
        public final int withOpenPorts;
        public final int withExploits;
        public final int selected;

        TargetStats() {
            List<Target> targets = System.getTargets();
            this.total = targets.size();

            int ep = 0, net = 0, rem = 0, conn = 0, ports = 0, exp = 0, sel = 0;
            for (Target t : targets) {
                switch (t.getType()) {
                    case ENDPOINT: ep++; break;
                    case NETWORK: net++; break;
                    case REMOTE: rem++; break;
                }
                if (t.isConnected()) conn++;
                if (t.hasOpenPorts()) ports++;
                if (!t.getExploits().isEmpty()) exp++;
                if (t.isSelected()) sel++;
            }

            this.endpoints = ep;
            this.networks = net;
            this.remote = rem;
            this.connected = conn;
            this.withOpenPorts = ports;
            this.withExploits = exp;
            this.selected = sel;
        }

        @Override
        public String toString() {
            return String.format(
                "TargetStats{total=%d, endpoints=%d, networks=%d, remote=%d, " +
                "connected=%d, withOpenPorts=%d, withExploits=%d, selected=%d}",
                total, endpoints, networks, remote, connected, withOpenPorts, withExploits, selected
            );
        }
    }
}
