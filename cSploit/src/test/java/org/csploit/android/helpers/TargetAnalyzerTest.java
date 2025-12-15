package org.csploit.android.helpers;

import org.junit.Test;
import org.junit.Before;
import static org.junit.Assert.*;

/**
 * Unit tests for TargetAnalyzer
 */
public class TargetAnalyzerTest {

    private TargetAnalyzer analyzer;

    @Before
    public void setUp() {
        analyzer = new TargetAnalyzer();
    }

    // Port Category Tests

    @Test
    public void testGetPortCategory_web() {
        assertEquals(TargetAnalyzer.PortCategory.WEB, analyzer.getPortCategory(80));
        assertEquals(TargetAnalyzer.PortCategory.WEB, analyzer.getPortCategory(443));
        assertEquals(TargetAnalyzer.PortCategory.WEB, analyzer.getPortCategory(8080));
    }

    @Test
    public void testGetPortCategory_remoteAccess() {
        assertEquals(TargetAnalyzer.PortCategory.REMOTE_ACCESS, analyzer.getPortCategory(22));
        assertEquals(TargetAnalyzer.PortCategory.REMOTE_ACCESS, analyzer.getPortCategory(23));
        assertEquals(TargetAnalyzer.PortCategory.REMOTE_ACCESS, analyzer.getPortCategory(3389));
    }

    @Test
    public void testGetPortCategory_database() {
        assertEquals(TargetAnalyzer.PortCategory.DATABASE, analyzer.getPortCategory(3306));
        assertEquals(TargetAnalyzer.PortCategory.DATABASE, analyzer.getPortCategory(5432));
        assertEquals(TargetAnalyzer.PortCategory.DATABASE, analyzer.getPortCategory(27017));
    }

    @Test
    public void testGetPortCategory_fileSharing() {
        assertEquals(TargetAnalyzer.PortCategory.FILE_SHARING, analyzer.getPortCategory(21));
        assertEquals(TargetAnalyzer.PortCategory.FILE_SHARING, analyzer.getPortCategory(445));
    }

    @Test
    public void testGetPortCategory_mail() {
        assertEquals(TargetAnalyzer.PortCategory.MAIL, analyzer.getPortCategory(25));
        assertEquals(TargetAnalyzer.PortCategory.MAIL, analyzer.getPortCategory(110));
        assertEquals(TargetAnalyzer.PortCategory.MAIL, analyzer.getPortCategory(143));
    }

    @Test
    public void testGetPortCategory_dns() {
        assertEquals(TargetAnalyzer.PortCategory.DNS, analyzer.getPortCategory(53));
    }

    @Test
    public void testGetPortCategory_network() {
        assertEquals(TargetAnalyzer.PortCategory.NETWORK, analyzer.getPortCategory(161));
        assertEquals(TargetAnalyzer.PortCategory.NETWORK, analyzer.getPortCategory(162));
    }

    @Test
    public void testGetPortCategory_other() {
        assertEquals(TargetAnalyzer.PortCategory.OTHER, analyzer.getPortCategory(12345));
        assertEquals(TargetAnalyzer.PortCategory.OTHER, analyzer.getPortCategory(9999));
    }

    // Risk Level Tests

    @Test
    public void testRiskLevel_severity() {
        assertEquals(4, TargetAnalyzer.RiskLevel.CRITICAL.severity);
        assertEquals(3, TargetAnalyzer.RiskLevel.HIGH.severity);
        assertEquals(2, TargetAnalyzer.RiskLevel.MEDIUM.severity);
        assertEquals(1, TargetAnalyzer.RiskLevel.LOW.severity);
        assertEquals(0, TargetAnalyzer.RiskLevel.INFO.severity);
    }

    // Service Detection Tests

    @Test
    public void testGuessServiceName_knownPorts() {
        assertEquals("http", analyzer.guessServiceName(80));
        assertEquals("https", analyzer.guessServiceName(443));
        assertEquals("ssh", analyzer.guessServiceName(22));
        assertEquals("ftp", analyzer.guessServiceName(21));
        assertEquals("telnet", analyzer.guessServiceName(23));
        assertEquals("smtp", analyzer.guessServiceName(25));
        assertEquals("dns", analyzer.guessServiceName(53));
        assertEquals("mysql", analyzer.guessServiceName(3306));
        assertEquals("postgresql", analyzer.guessServiceName(5432));
        assertEquals("mongodb", analyzer.guessServiceName(27017));
        assertEquals("redis", analyzer.guessServiceName(6379));
    }

    @Test
    public void testGuessServiceName_unknown() {
        assertEquals("unknown", analyzer.guessServiceName(12345));
    }

    // Unencrypted Port Tests

    @Test
    public void testIsUnencryptedPort_true() {
        assertTrue(analyzer.isUnencryptedPort(21));   // FTP
        assertTrue(analyzer.isUnencryptedPort(23));   // Telnet
        assertTrue(analyzer.isUnencryptedPort(80));   // HTTP
        assertTrue(analyzer.isUnencryptedPort(110));  // POP3
        assertTrue(analyzer.isUnencryptedPort(143));  // IMAP
    }

    @Test
    public void testIsUnencryptedPort_false() {
        assertFalse(analyzer.isUnencryptedPort(443));  // HTTPS
        assertFalse(analyzer.isUnencryptedPort(22));   // SSH
        assertFalse(analyzer.isUnencryptedPort(993));  // IMAPS
        assertFalse(analyzer.isUnencryptedPort(995));  // POP3S
    }

    // Analysis Summary Tests

    @Test
    public void testAnalysisSummary_toString() {
        TargetAnalyzer.AnalysisSummary summary = new TargetAnalyzer.AnalysisSummary();
        summary.totalTargets = 10;
        summary.criticalRiskCount = 1;
        summary.highRiskCount = 2;
        summary.mediumRiskCount = 3;
        summary.lowRiskCount = 4;
        summary.totalOpenPorts = 50;
        summary.totalExploits = 5;

        String str = summary.toString();
        assertTrue(str.contains("Total Targets: 10"));
        assertTrue(str.contains("Critical Risk: 1"));
        assertTrue(str.contains("High Risk: 2"));
        assertTrue(str.contains("Total Open Ports: 50"));
    }
}
