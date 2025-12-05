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

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.util.ArrayList;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for SessionManager
 */
public class SessionManagerTest {

    private SessionManager sessionManager;
    private ArrayList<Object> mockTargets;

    @BeforeEach
    void setUp(@TempDir Path tempDir) {
        mockTargets = new ArrayList<>();
        sessionManager = new SessionManager(tempDir.toString(), mockTargets);
    }

    @Test
    void testSessionNameGetterAndSetter() {
        assertThat(sessionManager.getSessionName()).isEmpty();

        sessionManager.setSessionName("TestSession");
        assertThat(sessionManager.getSessionName()).isEqualTo("TestSession");
    }

    @Test
    void testGetAvailableSessionFilesEmpty() {
        ArrayList<String> files = sessionManager.getAvailableSessionFiles();
        assertNotNull(files);
        assertTrue(files.isEmpty());
    }

    @Test
    void testGetAvailableHijackerSessionFilesEmpty() {
        ArrayList<String> files = sessionManager.getAvailableHijackerSessionFiles();
        assertNotNull(files);
        assertTrue(files.isEmpty());
    }

    @Test
    void testLoadSessionFileNotFound(@TempDir Path tempDir) {
        SessionManager manager = new SessionManager(tempDir.toString(), mockTargets);

        assertThatThrownBy(() -> manager.loadSession("nonexistent.dss"))
                .isInstanceOf(Exception.class)
                .hasMessageContaining("does not exist or is empty");
    }
}
