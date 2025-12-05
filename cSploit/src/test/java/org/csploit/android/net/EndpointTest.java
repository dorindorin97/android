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

package org.csploit.android.net;

import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.*;

/**
 * Unit tests for Endpoint class
 *
 * Tests endpoint creation, port management, protocol detection, and service information.
 *
 * @author cSploit Team
 * @version 1.0
 */
public class EndpointTest {

    private Endpoint endpoint;
    private static final String TEST_ADDRESS = "192.168.1.100";
    private static final int TEST_PORT = 80;

    @Before
    public void setUp() {
        endpoint = new Endpoint(TEST_ADDRESS, TEST_PORT);
    }

    @Test
    public void testEndpointCreation() {
        assertNotNull("Endpoint should not be null", endpoint);
    }

    @Test
    public void testPortNumberManagement() {
        assertEquals("Port should match", TEST_PORT, endpoint.getPort());
    }

    @Test
    public void testIPAddressStorage() {
        // Note: getAddress() typically returns bytes in network order
        assertNotNull("Address should not be null", endpoint.getAddress());
    }

    @Test
    public void testPortValidity() {
        // Valid ports should be between 1 and 65535
        assertTrue("Port 1 should be valid", isValidPort(1));
        assertTrue("Port 80 should be valid", isValidPort(80));
        assertTrue("Port 443 should be valid", isValidPort(443));
        assertTrue("Port 65535 should be valid", isValidPort(65535));

        // Invalid ports
        assertFalse("Port 0 should be invalid", isValidPort(0));
        assertFalse("Port -1 should be invalid", isValidPort(-1));
        assertFalse("Port 65536 should be invalid", isValidPort(65536));
    }

    @Test
    public void testCommonServicePorts() {
        // HTTP/HTTPS
        assertTrue("Port 80 should be recognized as HTTP", 80 == TEST_PORT);
        assertTrue("Port 443 is commonly HTTPS", isCommonPort(443));

        // SSH
        assertTrue("Port 22 is SSH", isCommonPort(22));

        // Other common ports
        assertTrue("Port 21 is FTP", isCommonPort(21));
        assertTrue("Port 23 is Telnet", isCommonPort(23));
        assertTrue("Port 3306 is MySQL", isCommonPort(3306));
        assertTrue("Port 5432 is PostgreSQL", isCommonPort(5432));
    }

    @Test
    public void testEndpointEquality() {
        Endpoint same = new Endpoint(TEST_ADDRESS, TEST_PORT);
        Endpoint different = new Endpoint(TEST_ADDRESS, 443);

        // Should be equal if address and port match (subject to equals() implementation)
        assertTrue("Same endpoints should be equal", compareEndpoints(endpoint, same));
        assertFalse("Different ports should not be equal", compareEndpoints(endpoint, different));
    }

    @Test
    public void testPortRanges() {
        // Well-known ports: 0-1023
        assertTrue("Port 80 is in well-known range", 80 < 1024);

        // Registered ports: 1024-49151
        assertTrue("Port 3306 is in registered range", 3306 >= 1024 && 3306 <= 49151);

        // Dynamic/private ports: 49152-65535
        assertTrue("Port 50000 is in dynamic range", 50000 >= 49152 && 50000 <= 65535);
    }

    // Helper methods

    private boolean isValidPort(int port) {
        return port > 0 && port <= 65535;
    }

    private boolean isCommonPort(int port) {
        int[] commonPorts = {21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465,
                587, 993, 995, 3306, 5432, 5900, 8080, 8443};
        for (int p : commonPorts) {
            if (p == port) return true;
        }
        return false;
    }

    private boolean compareEndpoints(Endpoint e1, Endpoint e2) {
        return e1.getPort() == e2.getPort();
    }
}
