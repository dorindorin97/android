package org.csploit.android.debug;

import org.csploit.android.BuildConfig;
import org.csploit.android.core.System;
import org.csploit.android.helpers.LoggingHelper;
import org.csploit.android.net.Network.Protocol;
import org.csploit.android.net.Target;

import java.net.InetAddress;

/**
 * Seeds fake targets with pre-populated ports and services for debug builds.
 *
 * Lets developers exercise the full UI flow (PortScanner, Inspector, ExploitFinder,
 * Sessions, etc.) without needing a live network, root access, or nmap installed.
 *
 * Only active in debug builds — no-ops in release.
 *
 * Usage: call DebugSeeder.seed() once after System.init() in CSploitApplication.
 */
public class DebugSeeder {

  private static final String TAG = "DebugSeeder";

  /** Fake MAC for debug-pc */
  private static final byte[] MAC_PC     = { 0x00, 0x11, 0x22, 0x33, 0x44, 0x55 };
  /** Fake MAC for debug-server */
  private static final byte[] MAC_SERVER = { (byte)0xAA, (byte)0xBB, (byte)0xCC, 0x11, 0x22, 0x33 };

  public static void seed() {
    if (!BuildConfig.DEBUG) return;
    try {
      seedTargets();
      LoggingHelper.d(TAG, "Debug targets seeded");
    } catch (Exception e) {
      LoggingHelper.w(TAG, "Debug seeding failed: " + e.getMessage());
    }
  }

  private static void seedTargets() throws Exception {
    // --- Target 1: general Linux workstation ---
    Target pc = new Target(InetAddress.getByName("192.168.1.105"), MAC_PC);
    pc.setAlias("debug-pc");
    pc.addOpenPort(new Target.Port(22,   Protocol.TCP, "ssh",        "OpenSSH 7.4"));
    pc.addOpenPort(new Target.Port(80,   Protocol.TCP, "http",       "Apache httpd 2.4.6"));
    pc.addOpenPort(new Target.Port(443,  Protocol.TCP, "https",      "nginx 1.12.2"));
    pc.addOpenPort(new Target.Port(8080, Protocol.TCP, "http-proxy", "Apache Tomcat 8.5"));
    pc.setDeviceOS("Linux 4.15");
    System.addOrderedTarget(pc);

    // --- Target 2: Windows server ---
    Target server = new Target(InetAddress.getByName("192.168.1.110"), MAC_SERVER);
    server.setAlias("debug-server");
    server.addOpenPort(new Target.Port(21,   Protocol.TCP, "ftp",            "vsftpd 3.0.3"));
    server.addOpenPort(new Target.Port(22,   Protocol.TCP, "ssh",            "OpenSSH 7.9"));
    server.addOpenPort(new Target.Port(80,   Protocol.TCP, "http",           "Microsoft IIS httpd 10.0"));
    server.addOpenPort(new Target.Port(445,  Protocol.TCP, "microsoft-ds",   "Windows SMB"));
    server.addOpenPort(new Target.Port(3306, Protocol.TCP, "mysql",          "MySQL 5.7.28"));
    server.setDeviceOS("Windows Server 2016");
    System.addOrderedTarget(server);

    // --- Target 3: remote hostname (for REMOTE-only plugins) ---
    Target remote = new Target("debug-remote.example.com", 0);
    remote.setAlias("debug-remote.example.com");
    System.addOrderedTarget(remote);

    // Pre-select the first target so plugins open immediately
    System.setCurrentTarget(pc);
  }
}
