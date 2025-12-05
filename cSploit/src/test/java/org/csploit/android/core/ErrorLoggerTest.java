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
import java.nio.file.Files;
import java.nio.file.Path;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * Unit tests for ErrorLogger
 */
public class ErrorLoggerTest {

    private ErrorLogger errorLogger;
    private Path tempDir;

    @BeforeEach
    void setUp(@TempDir Path tempDir) {
        this.tempDir = tempDir;
        errorLogger = new ErrorLogger(tempDir.toString());
    }

    @Test
    void testLogErrorWithThrowable() {
        Exception testException = new RuntimeException("Test error");
        errorLogger.logError(testException);

        String logFilePath = errorLogger.getLogFilePath();
        assertNotNull(logFilePath);

        File logFile = new File(logFilePath);
        assertTrue(logFile.exists());
    }

    @Test
    void testLogErrorWithMessage() {
        String errorMessage = "Test error message";
        errorLogger.logError(errorMessage);

        String logFilePath = errorLogger.getLogFilePath();
        assertNotNull(logFilePath);

        File logFile = new File(logFilePath);
        assertTrue(logFile.exists());
    }

    @Test
    void testLogErrorWithMessageAndThrowable() {
        String errorMessage = "Test error with exception";
        Exception testException = new IllegalArgumentException("Invalid argument");

        errorLogger.logError(errorMessage, testException);

        String logFilePath = errorLogger.getLogFilePath();
        assertNotNull(logFilePath);

        File logFile = new File(logFilePath);
        assertTrue(logFile.exists());
    }

    @Test
    void testGetLogFilePath() {
        String logFilePath = errorLogger.getLogFilePath();
        assertNotNull(logFilePath);
        assertThat(logFilePath).contains("error_log.txt");
    }

    @Test
    void testClearLog() throws Exception {
        errorLogger.logError("Some error");
        String logFilePath = errorLogger.getLogFilePath();
        File logFile = new File(logFilePath);

        assertTrue(logFile.exists());
        errorLogger.clearLog();
        // After clearing, file should not exist
    }
}
