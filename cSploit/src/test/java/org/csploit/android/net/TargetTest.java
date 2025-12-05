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
 * Unit tests for Target class
 *
 * Tests target creation, alias management, selection state, and address handling.
 *
 * @author cSploit Team
 * @version 1.0
 */
public class TargetTest {

    private Target target;
    private static final String TEST_ADDRESS = "192.168.1.1";
    private static final String TEST_ALIAS = "TestRouter";

    @Before
    public void setUp() {
        target = new Target(TEST_ADDRESS);
    }

    @Test
    public void testTargetCreation() {
        assertNotNull("Target should not be null", target);
        assertEquals("Address should match", TEST_ADDRESS, target.getDisplayAddress());
    }

    @Test
    public void testAliasMangement() {
        assertFalse("Target should not have alias initially", target.hasAlias());

        target.setAlias(TEST_ALIAS);
        assertTrue("Target should have alias after setting", target.hasAlias());
        assertEquals("Alias should match", TEST_ALIAS, target.getAlias());
    }

    @Test
    public void testSelectionState() {
        assertFalse("Target should not be selected initially", target.isSelected());

        target.setSelected(true);
        assertTrue("Target should be selected after setting", target.isSelected());

        target.setSelected(false);
        assertFalse("Target should not be selected after unsetting", target.isSelected());
    }

    @Test
    public void testConnectionStatus() {
        // Connection status defaults to false for newly created targets
        assertFalse("New target should not be connected", target.isConnected());
    }

    @Test
    public void testAddressFormatting() {
        assertNotNull("Display address should not be null", target.getDisplayAddress());
        assertEquals("Display address should match input", TEST_ADDRESS, target.getDisplayAddress());
    }

    @Test
    public void testOpenPorts() {
        assertNotNull("Open ports list should not be null", target.getOpenPorts());
        assertEquals("Open ports should be empty initially", 0, target.getOpenPorts().size());
    }

    @Test
    public void testSessionManagement() {
        assertNotNull("Sessions list should not be null", target.getSessions());
        assertEquals("Sessions should be empty initially", 0, target.getSessions().size());
    }
}
