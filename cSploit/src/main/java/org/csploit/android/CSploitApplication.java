/*
 * This file is part of the dSploit.
 *
 * Copyleft of Simone Margaritelli aka evilsocket <evilsocket@gmail.com>
 *
 * dSploit is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * dSploit is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with dSploit.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.csploit.android;

import android.app.Application;
import android.content.Context;
import android.content.SharedPreferences;

import org.acra.ACRA;
import org.acra.config.CoreConfigurationBuilder;
import org.acra.config.HttpSenderConfigurationBuilder;
import org.acra.config.NotificationConfigurationBuilder;
import org.acra.data.StringFormat;
import org.acra.sender.HttpSender;
import org.csploit.android.core.System;
import org.csploit.android.debug.DebugSeeder;
import org.csploit.android.helpers.PreferencesHelper;
import org.csploit.android.helpers.HttpHelper;
import org.csploit.android.helpers.LoggingHelper;
import org.csploit.android.helpers.ConnectionMonitor;
import org.csploit.android.plugins.ExploitFinder;
import org.csploit.android.plugins.Inspector;
import org.csploit.android.plugins.LoginCracker;
import org.csploit.android.plugins.PacketForger;
import org.csploit.android.plugins.PortScanner;
import org.csploit.android.plugins.RouterPwn;
import org.csploit.android.plugins.Sessions;
import org.csploit.android.plugins.Traceroute;
import org.csploit.android.plugins.WebScanner;
import org.csploit.android.plugins.DnsScanner;
import org.csploit.android.plugins.SslInspector;
import org.csploit.android.plugins.NetworkScanner;
import org.csploit.android.plugins.BannerGrabber;
import org.csploit.android.plugins.SubdomainScanner;
import org.csploit.android.plugins.ArpScanner;
import org.csploit.android.plugins.HttpFuzzer;
import org.csploit.android.plugins.WhoisLookup;
import org.csploit.android.plugins.PingTool;
import org.csploit.android.plugins.SshAuditor;
import org.csploit.android.plugins.SnmpScanner;
import org.csploit.android.plugins.HashIdentifier;
import org.csploit.android.plugins.SmbScanner;
import org.csploit.android.plugins.MdnsSsdpDiscovery;
import org.csploit.android.plugins.RdpFingerprinter;
import org.csploit.android.plugins.RpcScanner;
import org.csploit.android.plugins.HttpHeaderAnalyzer;
import org.csploit.android.plugins.DirBruteForcer;
import org.csploit.android.plugins.VhostScanner;
import org.csploit.android.plugins.JwtAnalyzer;
import org.csploit.android.plugins.PasswordGenerator;
import org.csploit.android.plugins.HeartbleedChecker;
import org.csploit.android.plugins.TelnetScanner;
import org.csploit.android.plugins.TftpScanner;
import org.csploit.android.plugins.Ipv6Scanner;
import org.csploit.android.plugins.UdpScanner;
import org.csploit.android.plugins.CertTransparency;
import org.csploit.android.plugins.WifiAnalyzer;
import org.csploit.android.plugins.BluetoothScanner;
import org.csploit.android.plugins.mitm.MITM;
import org.csploit.android.services.Services;

import java.net.NoRouteToHostException;

// ACRA crash reporting configuration moved to programmatic setup in onCreate()
// Note: Annotations removed due to compatibility issues with annotation processors

public class CSploitApplication extends Application {

  private static final String TAG = "CSploitApplication";

  @Override
  public void onCreate() {
    SharedPreferences themePrefs = getSharedPreferences("THEME", 0);
    boolean isDark = themePrefs.getBoolean("isDark", false);
    if (isDark)
      setTheme(R.style.DarkTheme);
    else
      setTheme(R.style.AppTheme);

    super.onCreate();

    // Initialize helper utilities early
    PreferencesHelper.init(this);
    LoggingHelper.d("CSploitApplication", "Helper utilities initialized");

    // Initialize ACRA with configuration from preferences or environment
    // Only enable crash reporting if user opted in and credentials are properly configured
    initializeCrashReporting();
    
    Services.init(this);

    // initialize the system
    try {
      System.init(this);
    } catch (Exception e) {
      // ignore exception when the user has wifi off
      if (!(e instanceof NoRouteToHostException))
        LoggingHelper.e(TAG, "Failed to initialize system", e);
    }

    // Seed fake targets for debug builds so UI can be exercised without real hardware
    DebugSeeder.seed();

    // load system modules even if the initialization failed
    System.registerPlugin(new RouterPwn());
    System.registerPlugin(new Traceroute());
    System.registerPlugin(new PortScanner());
    System.registerPlugin(new Inspector());
    System.registerPlugin(new ExploitFinder());
    System.registerPlugin(new WebScanner());
    System.registerPlugin(new DnsScanner());
    System.registerPlugin(new SslInspector());
    System.registerPlugin(new NetworkScanner());
    System.registerPlugin(new BannerGrabber());
    System.registerPlugin(new SubdomainScanner());
    System.registerPlugin(new ArpScanner());
    System.registerPlugin(new HttpFuzzer());
    System.registerPlugin(new WhoisLookup());
    System.registerPlugin(new PingTool());
    System.registerPlugin(new SshAuditor());
    System.registerPlugin(new SnmpScanner());
    System.registerPlugin(new HashIdentifier());
    System.registerPlugin(new SmbScanner());
    System.registerPlugin(new MdnsSsdpDiscovery());
    System.registerPlugin(new RdpFingerprinter());
    System.registerPlugin(new RpcScanner());
    System.registerPlugin(new HttpHeaderAnalyzer());
    System.registerPlugin(new DirBruteForcer());
    System.registerPlugin(new VhostScanner());
    System.registerPlugin(new JwtAnalyzer());
    System.registerPlugin(new PasswordGenerator());
    System.registerPlugin(new HeartbleedChecker());
    System.registerPlugin(new TelnetScanner());
    System.registerPlugin(new TftpScanner());
    System.registerPlugin(new Ipv6Scanner());
    System.registerPlugin(new UdpScanner());
    System.registerPlugin(new CertTransparency());
    System.registerPlugin(new WifiAnalyzer());
    System.registerPlugin(new BluetoothScanner());
    System.registerPlugin(new LoginCracker());
    System.registerPlugin(new Sessions());
    System.registerPlugin(new MITM());
    System.registerPlugin(new PacketForger());
  }

  /**
   * Initialize crash reporting with secure configuration.
   * Only enables if user has opted in and proper credentials are available.
   */
  private void initializeCrashReporting() {
    try {
      SharedPreferences prefs = getSharedPreferences("CRASH_REPORTING", 0);
      boolean crashReportingEnabled = prefs.getBoolean("enabled", false);
      
      if (!crashReportingEnabled) {
        // User has not opted in to crash reporting
        return;
      }

      CoreConfigurationBuilder builder = new CoreConfigurationBuilder();
      builder.withBuildConfigClass(BuildConfig.class)
             .withReportFormat(StringFormat.JSON);
      
      // Only configure HTTP sender if credentials are available from secure storage
      String reportingUri = prefs.getString("reporting_uri", "");
      if (!reportingUri.isEmpty()) {
        builder.withPluginConfigurations(
            new HttpSenderConfigurationBuilder()
                   .withUri(reportingUri)
                   .withHttpMethod(HttpSender.Method.PUT)
                   .build(),
            new NotificationConfigurationBuilder()
               .withChannelName(getString(R.string.csploitChannelId))
               .withText(getString(R.string.crash_dialog_text))
               .withResIcon(R.drawable.dsploit_icon)
               .withTitle(getString(R.string.crash_dialog_title))
               .build()
        );
      }
      
      ACRA.init(this, builder.build());
    } catch (Exception e) {
      // Log but don't crash if crash reporting setup fails
      LoggingHelper.e(TAG, "Failed to initialize crash reporting", e);
    }

    // Start connection monitoring service for the app
    try {
      ConnectionMonitor.getInstance(this).start();
    } catch (Exception e) {
      LoggingHelper.w(TAG, "Failed to start ConnectionMonitor", e);
    }
  }

  @Override
  public void onTerminate() {
    // Clean up helper resources
    HttpHelper.clearCache();
    LoggingHelper.d("CSploitApplication", "HTTP cache and resources cleaned up");
    // stop ConnectionMonitor if running
    try {
      ConnectionMonitor.getInstance(this).stop();
    } catch (Exception e) {
      LoggingHelper.w(TAG, "Failed to stop ConnectionMonitor cleanly", e);
    }

    super.onTerminate();
  }
}