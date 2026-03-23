package org.csploit.android.plugins;

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
import org.csploit.android.net.Target;

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Subdomain Scanner — resolves a list of common subdomain prefixes against the
 * target's hostname.  Discovered subdomains can reveal hidden admin panels,
 * staging environments, and forgotten services.
 *
 * Works on REMOTE targets (hostname-based).
 */
public class SubdomainScanner extends Plugin {
    private static final String TAG = "SubdomainScanner";
    private static final int THREAD_POOL = 20;

    /** Common subdomain prefixes to probe. */
    private static final String[] WORDLIST = {
        "www", "mail", "ftp", "smtp", "pop", "pop3", "imap", "ns1", "ns2",
        "dns", "dns1", "dns2", "mx", "relay", "webmail", "remote",
        "admin", "administrator", "cpanel", "whm", "webdisk", "panel",
        "api", "api2", "dev", "development", "staging", "stage", "test",
        "qa", "uat", "demo", "beta", "alpha", "preview",
        "blog", "shop", "store", "m", "mobile", "wap", "secure",
        "vpn", "gateway", "proxy", "cdn", "static", "assets", "media",
        "img", "images", "upload", "uploads", "files", "download",
        "db", "database", "sql", "mysql", "phpmyadmin", "pma",
        "git", "svn", "repo", "ci", "jenkins", "build", "deploy",
        "jira", "confluence", "wiki", "docs", "help", "support",
        "status", "monitor", "grafana", "kibana", "elastic",
        "old", "backup", "bak", "archive", "legacy", "v1", "v2",
    };

    public static class SubResult {
        public final String subdomain;
        public final String ip;
        SubResult(String s, String ip) { subdomain = s; this.ip = ip; }
    }

    private FloatingActionButton mToggleButton;
    private ProgressBar mProgress;
    private ListView mListView;
    private ResultAdapter mAdapter;
    private TextView mSummary;
    private final AtomicBoolean mRunning = new AtomicBoolean(false);
    private Future<?> mJob;

    public SubdomainScanner() {
        super(
            R.string.subdomain_scanner,
            R.string.subdomain_scanner_desc,
            new Target.Type[]{Target.Type.REMOTE},
            R.layout.plugin_subdomain_scanner,
            R.drawable.action_traceroute
        );
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        SharedPreferences prefs = getSharedPreferences("THEME", 0);
        setTheme(prefs.getBoolean("isDark", false) ? R.style.DarkTheme : R.style.AppTheme);
        super.onCreate(savedInstanceState);

        mToggleButton = findViewById(R.id.subdomainToggleButton);
        mProgress     = findViewById(R.id.subdomainActivity);
        mListView     = findViewById(android.R.id.list);
        mSummary      = findViewById(R.id.subdomainSummary);
        mAdapter      = new ResultAdapter();
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

    // ── Scan control ─────────────────────────────────────────────────────────

    private void startScan() {
        Target target = System.getCurrentTarget();
        if (target == null) return;

        mRunning.set(true);
        mAdapter.clear();
        runOnUiThread(() -> mSummary.setText(getString(R.string.subdomain_scanning)));
        mProgress.setVisibility(View.VISIBLE);
        AnimationHelper.fadeIn(mProgress, 200);
        mToggleButton.setImageDrawable(ContextCompat.getDrawable(this, R.drawable.ic_stop_24dp));

        if (BuildConfig.DEBUG) {
            mJob = ThreadHelper.submit(() -> {
                emitDebugResults();
                runOnUiThread(this::onScanFinished);
            });
            return;
        }

        // Resolve base domain in background
        mJob = ThreadHelper.submit(() -> {
            String host = target.getAddress().getHostName();
            // Strip any leading subdomain to get the base domain
            String base = extractBaseDomain(host);
            runOnUiThread(() -> mSummary.setText("Scanning " + base + "…"));
            scanSubdomains(base);
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
        int count = mAdapter.getCount();
        runOnUiThread(() -> mSummary.setText(
            count == 0 ? getString(R.string.subdomain_none)
                       : count + " " + getString(R.string.subdomain_found)
        ));
    }

    // ── Scan logic ────────────────────────────────────────────────────────────

    private String extractBaseDomain(String host) {
        // Keep last two labels: e.g. "sub.example.com" -> "example.com"
        String[] parts = host.split("\\.");
        if (parts.length >= 2) return parts[parts.length-2] + "." + parts[parts.length-1];
        return host;
    }

    private void scanSubdomains(String base) {
        ExecutorService pool = Executors.newFixedThreadPool(THREAD_POOL);
        AtomicInteger done = new AtomicInteger(0);

        for (String prefix : WORDLIST) {
            if (!mRunning.get()) break;
            final String fqdn = prefix + "." + base;
            pool.submit(() -> {
                if (mRunning.get()) {
                    try {
                        InetAddress addr = InetAddress.getByName(fqdn);
                        report(new SubResult(fqdn, addr.getHostAddress()));
                    } catch (Exception ignored) {}
                }
                int d = done.incrementAndGet();
                final int pct = (d * 100) / WORDLIST.length;
                runOnUiThread(() -> mProgress.setProgress(pct));
            });
        }
        pool.shutdown();
        try { pool.awaitTermination(60, TimeUnit.SECONDS); } catch (InterruptedException ignored) {}
    }

    // ── Debug helpers ─────────────────────────────────────────────────────────

    private void emitDebugResults() {
        String[] fakes = {"www.example.com|93.184.216.34", "mail.example.com|93.184.216.35",
            "api.example.com|93.184.216.36", "dev.example.com|10.0.0.5",
            "admin.example.com|10.0.0.10", "staging.example.com|10.0.0.11"};
        for (String f : fakes) {
            if (!mRunning.get()) break;
            String[] p = f.split("\\|");
            report(new SubResult(p[0], p[1]));
            try { Thread.sleep(150); } catch (InterruptedException ignored) {}
        }
    }

    // ── UI helpers ────────────────────────────────────────────────────────────

    private void report(SubResult r) {
        runOnUiThread(() -> {
            mAdapter.add(r);
            mAdapter.notifyDataSetChanged();
        });
    }

    private class ResultAdapter extends ArrayAdapter<SubResult> {
        ResultAdapter() {
            super(SubdomainScanner.this, R.layout.plugin_subdomain_scanner_item, new ArrayList<>());
        }

        @Override
        public View getView(int position, View convertView, ViewGroup parent) {
            if (convertView == null)
                convertView = LayoutInflater.from(getContext())
                    .inflate(R.layout.plugin_subdomain_scanner_item, parent, false);

            SubResult r = getItem(position);
            TextView tvSub = convertView.findViewById(R.id.subdomainItemName);
            TextView tvIp  = convertView.findViewById(R.id.subdomainItemIp);

            tvSub.setText(r.subdomain);
            tvIp.setText(r.ip);

            // Private IPs are more interesting findings
            boolean isPrivate = r.ip.startsWith("10.") || r.ip.startsWith("192.168.")
                || r.ip.startsWith("172.");
            tvSub.setTextColor(isPrivate
                ? Color.parseColor("#F57C00")
                : ContextCompat.getColor(getContext(), R.color.app_color));

            return convertView;
        }
    }
}
