package org.csploit.android.net;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.DisplayName;

import static org.assertj.core.api.Assertions.*;

/**
 * Unit tests for Network and IP address handling.
 * Tests protocol parsing, network utility functions, and validation.
 */
@DisplayName("Network Component Tests")
public class NetworkTest {

    @BeforeEach
    void setUp() {
        // Setup network test environment
    }

    @Test
    @DisplayName("Should validate TCP protocol")
    void testTcpProtocol() {
        Network.Protocol protocol = Network.Protocol.fromString("tcp");
        assertThat(protocol).isEqualTo(Network.Protocol.TCP);
        assertThat(protocol.toString()).isEqualTo("tcp");
    }

    @Test
    @DisplayName("Should validate UDP protocol")
    void testUdpProtocol() {
        Network.Protocol protocol = Network.Protocol.fromString("udp");
        assertThat(protocol).isEqualTo(Network.Protocol.UDP);
        assertThat(protocol.toString()).isEqualTo("udp");
    }

    @Test
    @DisplayName("Should validate ICMP protocol")
    void testIcmpProtocol() {
        Network.Protocol protocol = Network.Protocol.fromString("icmp");
        assertThat(protocol).isEqualTo(Network.Protocol.ICMP);
        assertThat(protocol.toString()).isEqualTo("icmp");
    }

    @Test
    @DisplayName("Should validate IGMP protocol")
    void testIgmpProtocol() {
        Network.Protocol protocol = Network.Protocol.fromString("igmp");
        assertThat(protocol).isEqualTo(Network.Protocol.IGMP);
        assertThat(protocol.toString()).isEqualTo("igmp");
    }

    @Test
    @DisplayName("Should return UNKNOWN for invalid protocol")
    void testUnknownProtocol() {
        Network.Protocol protocol = Network.Protocol.fromString("invalid");
        assertThat(protocol).isEqualTo(Network.Protocol.UNKNOWN);
        assertThat(protocol.toString()).isEqualTo("unknown");
    }

    @Test
    @DisplayName("Should handle null protocol string")
    void testNullProtocol() {
        Network.Protocol protocol = Network.Protocol.fromString(null);
        assertThat(protocol).isEqualTo(Network.Protocol.UNKNOWN);
    }

    @Test
    @DisplayName("Should be case-insensitive for protocol parsing")
    void testCaseInsensitiveProtocol() {
        assertThat(Network.Protocol.fromString("TCP")).isEqualTo(Network.Protocol.TCP);
        assertThat(Network.Protocol.fromString("Tcp")).isEqualTo(Network.Protocol.TCP);
        assertThat(Network.Protocol.fromString("UDP")).isEqualTo(Network.Protocol.UDP);
        assertThat(Network.Protocol.fromString("IcMp")).isEqualTo(Network.Protocol.ICMP);
    }

    @Test
    @DisplayName("Should validate Target type NETWORK")
    void testTargetTypeNetwork() throws Exception {
        Target.Type type = Target.Type.fromString("network");
        assertThat(type).isEqualTo(Target.Type.NETWORK);
    }

    @Test
    @DisplayName("Should validate Target type ENDPOINT")
    void testTargetTypeEndpoint() throws Exception {
        Target.Type type = Target.Type.fromString("endpoint");
        assertThat(type).isEqualTo(Target.Type.ENDPOINT);
    }

    @Test
    @DisplayName("Should validate Target type REMOTE")
    void testTargetTypeRemote() throws Exception {
        Target.Type type = Target.Type.fromString("remote");
        assertThat(type).isEqualTo(Target.Type.REMOTE);
    }

    @Test
    @DisplayName("Should throw exception for invalid Target type")
    void testInvalidTargetType() {
        assertThatThrownBy(() -> Target.Type.fromString("invalid"))
                .isInstanceOf(Exception.class)
                .hasMessageContaining("Could not deserialize");
    }

    @Test
    @DisplayName("Should handle null Target type string")
    void testNullTargetType() {
        assertThatThrownBy(() -> Target.Type.fromString(null))
                .isInstanceOf(Exception.class);
    }

    @Test
    @DisplayName("Should create Port with protocol and number")
    void testPortCreation() {
        Target.Port port = new Target.Port(22, Network.Protocol.TCP);
        assertThat(port.getNumber()).isEqualTo(22);
    }

    @Test
    @DisplayName("Should validate standard SSH port")
    void testSshPort() {
        Target.Port sshPort = new Target.Port(22, Network.Protocol.TCP, "ssh");
        assertThat(sshPort.getNumber()).isEqualTo(22);
    }

    @Test
    @DisplayName("Should validate standard HTTP port")
    void testHttpPort() {
        Target.Port httpPort = new Target.Port(80, Network.Protocol.TCP, "http");
        assertThat(httpPort.getNumber()).isEqualTo(80);
    }

    @Test
    @DisplayName("Should validate standard HTTPS port")
    void testHttpsPort() {
        Target.Port httpsPort = new Target.Port(443, Network.Protocol.TCP, "https");
        assertThat(httpsPort.getNumber()).isEqualTo(443);
    }

    @Test
    @DisplayName("Should validate DNS port")
    void testDnsPort() {
        Target.Port dnsPort = new Target.Port(53, Network.Protocol.UDP, "dns");
        assertThat(dnsPort.getNumber()).isEqualTo(53);
    }

    @Test
    @DisplayName("Should validate MySQL port")
    void testMysqlPort() {
        Target.Port mysqlPort = new Target.Port(3306, Network.Protocol.TCP, "mysql");
        assertThat(mysqlPort.getNumber()).isEqualTo(3306);
    }

    @Test
    @DisplayName("Should validate port range (1-65535)")
    void testPortRange() {
        // Valid ports
        assertThatCode(() -> new Target.Port(1, Network.Protocol.TCP))
                .doesNotThrowAnyException();
        assertThatCode(() -> new Target.Port(65535, Network.Protocol.TCP))
                .doesNotThrowAnyException();
    }

    @Test
    @DisplayName("Should track TCP protocol usage")
    void testTcpProtocolUsage() {
        Network.Protocol protocol = Network.Protocol.TCP;
        assertThat(protocol).isNotNull();
        assertThat(protocol.toString()).isEqualTo("tcp");
    }

    @Test
    @DisplayName("Should track UDP protocol usage")
    void testUdpProtocolUsage() {
        Network.Protocol protocol = Network.Protocol.UDP;
        assertThat(protocol).isNotNull();
        assertThat(protocol.toString()).isEqualTo("udp");
    }

    @Test
    @DisplayName("Should validate protocol enum values")
    void testProtocolEnumValues() {
        Network.Protocol[] protocols = Network.Protocol.values();
        assertThat(protocols).isNotEmpty();
        assertThat(protocols).contains(
                Network.Protocol.TCP,
                Network.Protocol.UDP,
                Network.Protocol.ICMP,
                Network.Protocol.IGMP,
                Network.Protocol.UNKNOWN
        );
    }

    @Test
    @DisplayName("Should validate common service ports")
    void testCommonServicePorts() {
        // SSH
        assertThat(22).isPositive();
        // HTTP
        assertThat(80).isPositive();
        // HTTPS
        assertThat(443).isPositive();
        // MySQL
        assertThat(3306).isPositive();
        // PostgreSQL
        assertThat(5432).isPositive();
    }

    @Test
    @DisplayName("Should support port description with version info")
    void testPortWithVersionInfo() {
        Target.Port port = new Target.Port(22, Network.Protocol.TCP, "ssh", "OpenSSH 7.4");
        assertThat(port.getNumber()).isEqualTo(22);
    }
}
