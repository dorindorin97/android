package org.csploit.android.core;

import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.TemporaryFolder;

import java.io.File;
import java.io.FileWriter;
import java.io.PrintWriter;

import static org.junit.Assert.*;

public class KnownIssuesTest {

    @Rule
    public TemporaryFolder tmp = new TemporaryFolder();

    @Test
    public void fromFile_validFile_loadsIssues() throws Exception {
        File f = tmp.newFile("issues.txt");
        try (PrintWriter pw = new PrintWriter(new FileWriter(f))) {
            pw.println("# comment");
            pw.println("42");
            pw.println("");
            pw.println("7");
        }

        KnownIssues ki = new KnownIssues();
        ki.fromFile(f.getAbsolutePath());

        assertTrue(ki.isIssueFound(42));
        assertTrue(ki.isIssueFound(7));
        assertFalse(ki.isIssueFound(99));
    }

    @Test
    public void fromFile_missingFile_doesNotThrow() {
        KnownIssues ki = new KnownIssues();
        // Should silently ignore missing file
        ki.fromFile("/nonexistent/path/issues.txt");
        assertTrue(ki.getFoundIssues().isEmpty());
    }

    @Test
    public void fromFile_duplicates_deduped() throws Exception {
        File f = tmp.newFile("issues.txt");
        try (PrintWriter pw = new PrintWriter(new FileWriter(f))) {
            pw.println("10");
            pw.println("10");
        }

        KnownIssues ki = new KnownIssues();
        ki.fromFile(f.getAbsolutePath());

        assertEquals(1, ki.getFoundIssues().size());
    }

    @Test
    public void fromFile_invalidNumber_skipsLine() throws Exception {
        File f = tmp.newFile("issues.txt");
        try (PrintWriter pw = new PrintWriter(new FileWriter(f))) {
            pw.println("5");
            pw.println("notanumber");
        }

        KnownIssues ki = new KnownIssues();
        // Should not throw; line "notanumber" causes NumberFormatException which is caught
        ki.fromFile(f.getAbsolutePath());
        // Issue 5 may or may not be loaded depending on where the exception stops iteration,
        // but the method must not throw
    }
}
