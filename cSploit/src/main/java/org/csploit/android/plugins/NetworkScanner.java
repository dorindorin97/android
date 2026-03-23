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
 * Network Scanner — discovers live hosts on the local /24 subnet via ICMP ping.
 *
 * Works on NETWORK and ENDPOINT targets.
 * Probes all 254 host addresses in the /24 using a thread pool (32 parallel workers).
 * Falls back to TCP port-80 probe when ICMP is not permitted.
 */
public class NetworkScanner extends Plugin {
    private static final String TAG = "NetworkScanner";
    private static final int THREAD_POOL = 32;
    private static final int PING_TIMEOUT_MS = 1500;
    private static final int TCP_TIMEOUT_MS  = 1500;

    public static class Host {
        public enum Status { UP, UP_TCP }
        public final String ip;
        public final String hostname;
        public final Status status;
        Host(String ip, String hostname, Status status) {
            this.ip       = ip;
            this.hostname = hostname;
            this.status   = status;
        }
    }

    private FloatingActionButton mToggleButton;
    private ProgressBar mProgress;
    private ListView mListView;
    private HostAdapter mAdapter;
    private TextView mSummary;
    private final AtomicBoolean mRunning = new AtomicBoolean(false);
    private Future<?> mJob;

    public NetworkScanner() {
        super(
            R.string.net_scanner,
            R.string.net_scanner_desc,
            new Target.Type[]{Target.Type.NETWORK, Target.Type.ENDPOINT},
            R.layout.plugin_net_scanner,
            R.drawable.action_scanner
        );
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        SharedPreferences prefs = getSharedPreferences("THEME", 0);
        setTheme(prefs.getBoolean("isDark", false) ? R.style.DarkTheme : R.style.AppTheme);
        super.onCreate(savedInstanceState);

        mToggleButton = findViewById(R.id.netScanToggleButton);
        mProgress     = findViewById(R.id.netScanActivity);
        mListView     = findViewById(android.R.id.list);
        mSummary      = findViewById(R.id.netScanSummary);
        mAdapter      = new HostAdapter();
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
        runOnUiThread(() -> mSummary.setText(getString(R.string.net_scan_scanning)));
        mProgress.setVisibility(View.VISIBLE);
        AnimationHelper.fadeIn(mProgress, 200);
        mToggleButton.setImageDrawable(ContextCompat.getDrawable(this, R.drawable.ic_stop_24dp));

        if (BuildConfig.DEBUG) {
            mJob = ThreadHelper.submit(() -> {
                emitDebugHosts();
                runOnUiThread(this::onScanFinished);
            });
            return;
        }

        final String base = getSubnetBase(target);
        mJob = ThreadHelper.submit(() -> {
            scanSubnet(base);
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
            count == 0 ? getString(R.string.net_scan_none)
                       : count + " " + getString(R.string.net_scan_found)
        ));
    }

    // ── Scan logic ────────────────────────────────────────────────────────────

    /** Returns the first three octets, e.g. "192.168.1" */
    private String getSubnetBase(Target t) {
        String ip = t.getAddress().getHostAddress();
        int lastDot = ip.lastIndexOf('.');
        return lastDot >= 0 ? ip.substring(0, lastDot) : ip;
    }

    private void scanSubnet(String base) {
        ExecutorService pool = Executors.newFixedThreadPool(THREAD_POOL);
        final AtomicInteger done = new AtomicInteger(0);

        for (int i = 1; i <= 254; i++) {
            if (!mRunning.get()) break;
            final String ip = base + "." + i;
            pool.submit(() -> {
                if (mRunning.get()) probeHost(ip);
                int d = done.incrementAndGet();
                if (d % 32 == 0) {
                    final int pct = (d * 100) / 254;
                    runOnUiThread(() -> mProgress.setProgress(pct));
                }
            });
        }

        pool.shutdown();
        try { pool.awaitTermination(60, TimeUnit.SECONDS); } catch (InterruptedException ignored) {}
    }

    private void probeHost(String ip) {
        try {
            InetAddress addr = InetAddress.getByName(ip);
            if (addr.isReachable(PING_TIMEOUT_MS)) {
                String hostname = resolveHostname(addr);
                reportHost(new Host(ip, hostname, Host.Status.UP));
                return;
            }
        } catch (Exception ignored) {}

        // Fallback: TCP port 80
        try {
            java.net.Socket s = new java.net.Socket();
            s.connect(new java.net.InetSocketAddress(ip, 80), TCP_TIMEOUT_MS);
            s.close();
            String hostname = resolveHostname(InetAddress.getByName(ip));
            reportHost(new Host(ip, hostname, Host.Status.UP_TCP));
        } catch (Exception ignored) {}
    }

    private String resolveHostname(InetAddress addr) {
        try {
            String h = addr.getCanonicalHostName();
            return h.equals(addr.getHostAddress()) ? "" : h;
        } catch (Exception e) { return ""; }
    }

    // ── Debug helpers ─────────────────────────────────────────────────────────

    private void emitDebugHosts() {
        String[] fakeHosts = {
            "192.168.1.1|router.home|UP",
            "192.168.1.2|desktop.home|UP",
            "192.168.1.5||UP_TCP",
            "192.168.1.10|laptop.home|UP",
            "192.168.1.105||UP",
        };
        for (String h : fakeHosts) {
            if (!mRunning.get()) break;
            String[] parts = h.split("\\|");
            Host.Status st = "UP_TCP".equals(parts[2]) ? Host.Status.UP_TCP : Host.Status.UP;
            reportHost(new Host(parts[0], parts[1], st));
            try { Thread.sleep(200); } catch (InterruptedException ignored) {}
        }
    }

    // ── UI helpers ────────────────────────────────────────────────────────────

    private void reportHost(Host host) {
        runOnUiThread(() -> {
            mAdapter.add(host);
            mAdapter.notifyDataSetChanged();
        });
    }

    private class HostAdapter extends ArrayAdapter<Host> {
        HostAdapter() {
            super(NetworkScanner.this, R.layout.plugin_net_scanner_item, new ArrayList<>());
        }

        @Override
        public View getView(int position, View convertView, ViewGroup parent) {
            if (convertView == null)
                convertView = LayoutInflater.from(getContext())
                    .inflate(R.layout.plugin_net_scanner_item, parent, false);

            Host h = getItem(position);
            TextView tvIp       = convertView.findViewById(R.id.netScanItemIp);
            TextView tvHostname = convertView.findViewById(R.id.netScanItemHostname);
            TextView tvStatus   = convertView.findViewById(R.id.netScanItemStatus);

            tvIp.setText(h.ip);
            tvHostname.setText(h.hostname.isEmpty() ? "" : h.hostname);

            boolean isTcpOnly = h.status == Host.Status.UP_TCP;
            tvStatus.setText(isTcpOnly ? "TCP" : "UP");
            tvStatus.setTextColor(isTcpOnly
                ? Color.parseColor("#F57C00")
                : Color.parseColor("#388E3C"));

            return convertView;
        }
    }
}
