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

import java.io.File;
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

    @TempDir
    Path tempDir;

    @BeforeEach
    void setUp() {
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
    void testLoadSessionFileNotFound(@TempDir Path otherDir) {
        SessionManager manager = new SessionManager(otherDir.toString(), mockTargets);

        assertThatThrownBy(() -> manager.loadSession("nonexistent.dss"))
                .isInstanceOf(Exception.class)
                .hasMessageContaining("does not exist or is empty");
    }

    // ── cleanOldBackups ────────────────────────────────────────────────────────

    @Test
    void cleanOldBackups_deletesExpiredFiles() throws Exception {
        File old = new File(tempDir.toFile(), "old.dss.2020-01-01_00-00-00.bak");
        old.createNewFile();
        old.setLastModified(java.lang.System.currentTimeMillis() - 3 * 24 * 3600 * 1000L);

        File recent = new File(tempDir.toFile(), "recent.dss.2099-01-01_00-00-00.bak");
        recent.createNewFile();

        int deleted = sessionManager.cleanOldBackups(2 * 24 * 3600 * 1000L);

        assertEquals(1, deleted, "Should delete exactly 1 old backup");
        assertFalse(old.exists(), "Old backup must be deleted");
        assertTrue(recent.exists(), "Recent backup must survive");
    }

    @Test
    void cleanOldBackups_emptyDir_returnsZero() {
        assertEquals(0, sessionManager.cleanOldBackups(86_400_000L));
    }

    @Test
    void cleanOldBackups_nonBackupFiles_untouched() throws Exception {
        File session = new File(tempDir.toFile(), "my-session.dss");
        session.createNewFile();
        session.setLastModified(0);

        int deleted = sessionManager.cleanOldBackups(1);
        assertEquals(0, deleted, "Non-.bak files must not be touched");
        assertTrue(session.exists());
    }

    // ── generateSessionName ────────────────────────────────────────────────────

    @Test
    void generateSessionName_prefixedAndNonEmpty() {
        String name = sessionManager.generateSessionName();
        assertNotNull(name);
        assertFalse(name.isEmpty());
        assertTrue(name.startsWith("csploit-session-"));
    }

    // ── shouldAutoSave ─────────────────────────────────────────────────────────

    @Test
    void shouldAutoSave_whenDisabled_returnsFalse() {
        sessionManager.setSessionName("s");
        sessionManager.setAutoSaveEnabled(false);
        assertFalse(sessionManager.shouldAutoSave());
    }

    @Test
    void shouldAutoSave_withLongInterval_returnsFalse() {
        sessionManager.setSessionName("s");
        sessionManager.setAutoSaveEnabled(true);
        sessionManager.setAutoSaveInterval(Long.MAX_VALUE);
        assertFalse(sessionManager.shouldAutoSave());
    }
}
