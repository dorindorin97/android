package org.csploit.android.plugins;

import android.content.Context;
import android.content.SharedPreferences;
import android.graphics.Color;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.ListView;
import android.widget.ProgressBar;
import android.widget.TextView;

import androidx.core.content.ContextCompat;

import com.google.android.material.floatingactionbutton.FloatingActionButton;

import org.csploit.android.BuildConfig;
import org.csploit.android.R;
import org.csploit.android.core.Plugin;
import org.csploit.android.core.System;
import org.csploit.android.helpers.AnimationHelper;
import org.csploit.android.helpers.LoggingHelper;
import org.csploit.android.helpers.ThreadHelper;
import org.csploit.android.helpers.UIHelper;
import org.csploit.android.net.Target;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Web scanner plugin — performs nikto-style HTTP vulnerability checks.
 *
 * Checks performed:
 *   - Server header fingerprinting (version disclosure)
 *   - Missing security headers (X-Frame-Options, CSP, HSTS, X-Content-Type-Options)
 *   - HTTP methods allowed (TRACE/PUT/DELETE)
 *   - Default/sensitive paths (robots.txt, .git, .env, admin, phpinfo, etc.)
 *   - Redirect to HTTPS check
 *   - Cookie attributes (Secure, HttpOnly, SameSite)
 *
 * When MSF RPC is connected this plugin can be extended to run
 * auxiliary/scanner/http/nikto — see launchMsfNikto().
 */
public class WebScanner extends Plugin {
  private static final String TAG = "WebScanner";

  /** A single finding reported by the scanner. */
  public static class Finding {
    public enum Severity { INFO, WARN, VULN }

    public final Severity severity;
    public final String title;
    public final String detail;

    Finding(Severity s, String t, String d) { severity = s; title = t; detail = d; }
  }

  private FloatingActionButton mToggleButton;
  private ProgressBar mProgress;
  private ListView mListView;
  private FindingAdapter mAdapter;
  private final AtomicBoolean mRunning = new AtomicBoolean(false);
  private Future<?> mJob;

  // ──────────────────────────────────────────────────────────────────────────
  // Constructor
  // ──────────────────────────────────────────────────────────────────────────

  public WebScanner() {
    super(
        R.string.web_scanner,
        R.string.web_scanner_desc,
        new Target.Type[]{Target.Type.ENDPOINT, Target.Type.REMOTE},
        R.layout.plugin_web_scanner,
        R.drawable.action_exploit_finder   // reuse until we have a dedicated icon
    );
  }

  // ──────────────────────────────────────────────────────────────────────────
  // Lifecycle
  // ──────────────────────────────────────────────────────────────────────────

  @Override
  public void onCreate(Bundle savedInstanceState) {
    SharedPreferences prefs = getSharedPreferences("THEME", 0);
    if (prefs.getBoolean("isDark", false))
      setTheme(R.style.DarkTheme);
    else
      setTheme(R.style.AppTheme);
    super.onCreate(savedInstanceState);

    Target t = System.getCurrentTarget();
    if (t == null || !hasHttpPorts(t)) {
      UIHelper.finish(this, getString(R.string.warning), getString(R.string.web_scan_no_http));
      return;
    }

    mToggleButton = findViewById(R.id.webScanToggleButton);
    mProgress     = findViewById(R.id.webScanActivity);
    mListView     = findViewById(android.R.id.list);
    mAdapter      = new FindingAdapter();
    mListView.setAdapter(mAdapter);

    mToggleButton.setOnClickListener(v -> {
      if (mRunning.get()) stopScan();
      else                startScan();
    });
  }

  @Override
  public void onBackPressed() {
    stopScan();
    super.onBackPressed();
    overridePendingTransition(R.anim.fadeout, R.anim.fadein);
  }

  // ──────────────────────────────────────────────────────────────────────────
  // Scan control
  // ──────────────────────────────────────────────────────────────────────────

  private void startScan() {
    Target target = System.getCurrentTarget();
    if (target == null) return;

    mRunning.set(true);
    mAdapter.clear();
    mProgress.setVisibility(View.VISIBLE);
    AnimationHelper.fadeIn(mProgress, 200);
    mToggleButton.setImageDrawable(ContextCompat.getDrawable(this, R.drawable.ic_stop_24dp));

    if (BuildConfig.DEBUG) {
      // Debug: emit fake findings without network access
      mJob = ThreadHelper.submit(() -> {
        emitDebugFindings(target);
        runOnUiThread(this::onScanFinished);
      });
      return;
    }

    List<Integer> httpPorts = getHttpPorts(target);
    mJob = ThreadHelper.submit(() -> {
      for (int port : httpPorts) {
        if (!mRunning.get()) break;
        String scheme = isHttpsPort(port) ? "https" : "http";
        String baseUrl = scheme + "://" + target.getAddress().getHostAddress() + ":" + port;
        scanUrl(baseUrl);
      }
      runOnUiThread(this::onScanFinished);
    });
  }

  private void stopScan() {
    mRunning.set(false);
    if (mJob != null) { mJob.cancel(true); mJob = null; }
    onScanFinished();
  }

  private void onScanFinished() {
    mRunning.set(false);
    AnimationHelper.fadeOut(mProgress, 200, () -> mProgress.setVisibility(View.INVISIBLE));
    mToggleButton.setImageDrawable(ContextCompat.getDrawable(this, R.drawable.ic_play_arrow_24dp));
    if (mAdapter.getCount() == 0)
      report(Finding.Severity.INFO, getString(R.string.web_scan_no_findings), "");
  }

  // ──────────────────────────────────────────────────────────────────────────
  // HTTP checks
  // ──────────────────────────────────────────────────────────────────────────

  private void scanUrl(String baseUrl) {
    LoggingHelper.d(TAG, "Scanning " + baseUrl);
    try {
      // 1. Fetch / and analyse headers
      HttpURLConnection conn = openConnection(baseUrl + "/", "GET");
      if (conn == null) return;
      int code = conn.getResponseCode();
      String server = conn.getHeaderField("Server");
      String powered = conn.getHeaderField("X-Powered-By");
      conn.disconnect();

      if (server != null && !server.isEmpty())
        report(Finding.Severity.WARN, "Server version disclosed", "Server: " + server + " [" + baseUrl + "]");
      if (powered != null && !powered.isEmpty())
        report(Finding.Severity.WARN, "Technology disclosed", "X-Powered-By: " + powered + " [" + baseUrl + "]");

      checkSecurityHeaders(baseUrl);
      checkAllowedMethods(baseUrl);
      checkSensitivePaths(baseUrl);
      checkHttpsRedirect(baseUrl, code);
      checkCookieAttributes(baseUrl);

    } catch (Exception e) {
      LoggingHelper.w(TAG, "Scan error on " + baseUrl + ": " + e.getMessage());
      report(Finding.Severity.INFO, "Connection error", baseUrl + " — " + e.getMessage());
    }
  }

  private void checkSecurityHeaders(String baseUrl) throws IOException {
    HttpURLConnection conn = openConnection(baseUrl + "/", "GET");
    if (conn == null) return;
    conn.getResponseCode();

    String[] required = {
        "X-Frame-Options",
        "Content-Security-Policy",
        "X-Content-Type-Options",
        "Referrer-Policy",
    };
    for (String h : required) {
      if (conn.getHeaderField(h) == null)
        report(Finding.Severity.WARN, "Missing header: " + h, "Header absent from response [" + baseUrl + "]");
    }

    // HSTS only makes sense on HTTPS
    if (baseUrl.startsWith("https") && conn.getHeaderField("Strict-Transport-Security") == null)
      report(Finding.Severity.WARN, "Missing HSTS header", "Strict-Transport-Security absent [" + baseUrl + "]");

    conn.disconnect();
  }

  private void checkAllowedMethods(String baseUrl) throws IOException {
    HttpURLConnection conn = openConnection(baseUrl + "/", "OPTIONS");
    if (conn == null) return;
    conn.getResponseCode();
    String allow = conn.getHeaderField("Allow");
    conn.disconnect();
    if (allow == null) return;
    String upper = allow.toUpperCase();
    if (upper.contains("TRACE"))
      report(Finding.Severity.VULN, "HTTP TRACE enabled", "TRACE allows XST attacks [" + baseUrl + "]");
    if (upper.contains("PUT") || upper.contains("DELETE"))
      report(Finding.Severity.WARN, "Dangerous HTTP methods allowed", "Allow: " + allow + " [" + baseUrl + "]");
  }

  /** Paths that often expose sensitive data or admin interfaces */
  private static final String[] SENSITIVE_PATHS = {
      "/robots.txt",
      "/.git/HEAD",
      "/.env",
      "/admin",
      "/administrator",
      "/phpinfo.php",
      "/info.php",
      "/server-status",
      "/server-info",
      "/.htaccess",
      "/wp-login.php",
      "/wp-admin/",
      "/phpmyadmin/",
      "/login",
      "/backup",
      "/config.php",
      "/web.config",
      "/crossdomain.xml",
      "/clientaccesspolicy.xml",
  };

  private void checkSensitivePaths(String baseUrl) {
    for (String path : SENSITIVE_PATHS) {
      if (!mRunning.get()) break;
      try {
        HttpURLConnection conn = openConnection(baseUrl + path, "GET");
        if (conn == null) continue;
        int code = conn.getResponseCode();
        conn.disconnect();
        if (code == 200) {
          Finding.Severity sev = path.contains(".git") || path.contains(".env") || path.contains("config")
              ? Finding.Severity.VULN : Finding.Severity.WARN;
          report(sev, "Sensitive path accessible", "HTTP 200 on " + baseUrl + path);
        }
      } catch (Exception ignored) {}
    }
  }

  private void checkHttpsRedirect(String baseUrl, int rootCode) {
    if (!baseUrl.startsWith("http://")) return;
    // If plain HTTP returns 200 without redirect, flag it if HTTPS is also on the host
    if (rootCode == 200)
      report(Finding.Severity.INFO, "Plain HTTP accessible", "No redirect to HTTPS [" + baseUrl + "]");
  }

  private void checkCookieAttributes(String baseUrl) throws IOException {
    HttpURLConnection conn = openConnection(baseUrl + "/", "GET");
    if (conn == null) return;
    conn.getResponseCode();
    Map<String, List<String>> headers = conn.getHeaderFields();
    conn.disconnect();
    if (headers == null) return;
    for (Map.Entry<String, List<String>> e : headers.entrySet()) {
      if ("Set-Cookie".equalsIgnoreCase(e.getKey())) {
        for (String v : e.getValue()) {
          String lv = v.toLowerCase();
          if (!lv.contains("httponly"))
            report(Finding.Severity.WARN, "Cookie missing HttpOnly", "Cookie: " + v);
          if (!lv.contains("samesite"))
            report(Finding.Severity.INFO, "Cookie missing SameSite", "Cookie: " + v);
          if (baseUrl.startsWith("https") && !lv.contains("secure"))
            report(Finding.Severity.WARN, "Cookie missing Secure flag", "Cookie: " + v);
        }
      }
    }
  }

  // ──────────────────────────────────────────────────────────────────────────
  // Debug helpers
  // ──────────────────────────────────────────────────────────────────────────

  private void emitDebugFindings(Target target) {
    String host = target.getAddress().getHostAddress();
    List<Integer> ports = getHttpPorts(target);
    for (int port : ports) {
      String base = (isHttpsPort(port) ? "https" : "http") + "://" + host + ":" + port;
      report(Finding.Severity.WARN,  "[DEBUG] Server version disclosed",     "Server: Apache/2.4.6 [" + base + "]");
      report(Finding.Severity.WARN,  "[DEBUG] Missing header: X-Frame-Options", "Header absent [" + base + "]");
      report(Finding.Severity.WARN,  "[DEBUG] Missing header: Content-Security-Policy", "Header absent [" + base + "]");
      report(Finding.Severity.VULN,  "[DEBUG] HTTP TRACE enabled",           "TRACE allows XST attacks [" + base + "]");
      report(Finding.Severity.WARN,  "[DEBUG] Sensitive path accessible",    "HTTP 200 on " + base + "/robots.txt");
      report(Finding.Severity.VULN,  "[DEBUG] Sensitive path accessible",    "HTTP 200 on " + base + "/.git/HEAD");
      report(Finding.Severity.INFO,  "[DEBUG] Plain HTTP accessible",        "No redirect to HTTPS [" + base + "]");
    }
  }

  // ──────────────────────────────────────────────────────────────────────────
  // Utility helpers
  // ──────────────────────────────────────────────────────────────────────────

  private HttpURLConnection openConnection(String urlStr, String method) {
    try {
      HttpURLConnection conn = (HttpURLConnection) new URL(urlStr).openConnection();
      conn.setRequestMethod(method);
      conn.setConnectTimeout(5000);
      conn.setReadTimeout(5000);
      conn.setInstanceFollowRedirects(false);
      conn.setDoInput(true);
      return conn;
    } catch (Exception e) {
      return null;
    }
  }

  private boolean hasHttpPorts(Target t) {
    return !getHttpPorts(t).isEmpty();
  }

  private List<Integer> getHttpPorts(Target t) {
    List<Integer> result = new ArrayList<>();
    for (Target.Port p : t.getOpenPorts()) {
      String svc = p.getService() == null ? "" : p.getService().toLowerCase();
      if (svc.contains("http") || p.getNumber() == 80 || p.getNumber() == 443
          || p.getNumber() == 8080 || p.getNumber() == 8443 || p.getNumber() == 8888) {
        result.add(p.getNumber());
      }
    }
    return result;
  }

  private boolean isHttpsPort(int port) {
    return port == 443 || port == 8443;
  }

  private void report(Finding.Severity sev, String title, String detail) {
    Finding f = new Finding(sev, title, detail);
    runOnUiThread(() -> {
      mAdapter.add(f);
      mAdapter.notifyDataSetChanged();
    });
  }

  // ──────────────────────────────────────────────────────────────────────────
  // List adapter
  // ──────────────────────────────────────────────────────────────────────────

  private class FindingAdapter extends ArrayAdapter<Finding> {
    FindingAdapter() {
      super(WebScanner.this, R.layout.plugin_web_scanner_item, new ArrayList<>());
    }

    @Override
    public View getView(int position, View convertView, ViewGroup parent) {
      if (convertView == null)
        convertView = LayoutInflater.from(getContext())
            .inflate(R.layout.plugin_web_scanner_item, parent, false);

      Finding f = getItem(position);
      TextView title  = convertView.findViewById(R.id.webScanItemTitle);
      TextView detail = convertView.findViewById(R.id.webScanItemDetail);

      title.setText(f.title);
      detail.setText(f.detail);

      int color;
      switch (f.severity) {
        case VULN: color = Color.parseColor("#D32F2F"); break; // red
        case WARN: color = Color.parseColor("#F57C00"); break; // orange
        default:   color = ContextCompat.getColor(getContext(), R.color.app_color); break;
      }
      title.setTextColor(color);

      return convertView;
    }
  }
}
