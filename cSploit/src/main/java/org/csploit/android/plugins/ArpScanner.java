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

import java.io.BufferedReader;
import java.io.FileReader;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * ARP Scanner — discovers live hosts by:
 *   1. Sending ICMP pings across the /24 to populate the kernel ARP cache
 *   2. Reading /proc/net/arp for IP→MAC mappings
 *   3. Resolving each MAC's OUI prefix to a vendor name for device identification
 *
 * No root required. Works on NETWORK and ENDPOINT targets.
 */
public class ArpScanner extends Plugin {
    private static final String TAG = "ArpScanner";
    private static final int PING_TIMEOUT_MS = 800;
    private static final int THREAD_POOL     = 32;

    /** OUI prefix → vendor mapping (first 3 octets of MAC). */
    private static final Map<String, String> OUI = new HashMap<String, String>() {{
        put("00:50:56", "VMware");       put("00:0c:29", "VMware");
        put("00:1a:11", "Google");       put("f4:f5:d8", "Google");
        put("00:17:f2", "Apple");        put("3c:d0:f8", "Apple");
        put("a4:83:e7", "Apple");        put("f8:ff:c2", "Apple");
        put("dc:a4:ca", "Apple");
        put("00:1b:63", "Samsung");      put("8c:71:f8", "Samsung");
        put("00:26:37", "Samsung");
        put("00:25:9c", "Cisco");        put("00:1e:13", "Cisco");
        put("70:70:8b", "Cisco");
        put("b8:27:eb", "Raspberry Pi"); put("dc:a6:32", "Raspberry Pi");
        put("e4:5f:01", "Raspberry Pi");
        put("00:e0:4c", "Realtek");      put("52:54:00", "QEMU/KVM");
        put("08:00:27", "VirtualBox");   put("00:15:5d", "Hyper-V");
        put("00:1a:4b", "Huawei");       put("00:18:82", "Huawei");
        put("00:1f:3b", "Intel");        put("8c:8d:28", "Intel");
        put("00:14:22", "Dell");         put("b8:ac:6f", "Dell");
        put("00:26:b9", "Dell");         put("00:0d:60", "HP");
        put("00:17:08", "HP");
    }};

    public static class ArpEntry {
        public final String ip;
        public final String mac;
        public final String vendor;
        public final String hostname;
        ArpEntry(String ip, String mac, String vendor, String hostname) {
            this.ip = ip; this.mac = mac; this.vendor = vendor; this.hostname = hostname;
        }
    }

    private FloatingActionButton mToggleButton;
    private ProgressBar mProgress;
    private ListView mListView;
    private ArpAdapter mAdapter;
    private TextView mSummary;
    private final AtomicBoolean mRunning = new AtomicBoolean(false);
    private Future<?> mJob;

    public ArpScanner() {
        super(
            R.string.arp_scanner,
            R.string.arp_scanner_desc,
            new Target.Type[]{Target.Type.NETWORK, Target.Type.ENDPOINT},
            R.layout.plugin_arp_scanner,
            R.drawable.action_scanner
        );
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        SharedPreferences prefs = getSharedPreferences("THEME", 0);
        setTheme(prefs.getBoolean("isDark", false) ? R.style.DarkTheme : R.style.AppTheme);
        super.onCreate(savedInstanceState);

        mToggleButton = findViewById(R.id.arpToggleButton);
        mProgress     = findViewById(R.id.arpActivity);
        mListView     = findViewById(android.R.id.list);
        mSummary      = findViewById(R.id.arpSummary);
        mAdapter      = new ArpAdapter();
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
        runOnUiThread(() -> mSummary.setText(getString(R.string.arp_scanning)));
        mProgress.setVisibility(View.VISIBLE);
        AnimationHelper.fadeIn(mProgress, 200);
        mToggleButton.setImageDrawable(ContextCompat.getDrawable(this, R.drawable.ic_stop_24dp));

        if (BuildConfig.DEBUG) {
            mJob = ThreadHelper.submit(() -> {
                emitDebugEntries();
                runOnUiThread(this::onScanFinished);
            });
            return;
        }

        final String base = getSubnetBase(target);
        mJob = ThreadHelper.submit(() -> {
            pingSubnet(base);                // populate kernel ARP cache
            List<ArpEntry> entries = readArpTable();
            for (ArpEntry e : entries) {
                if (mRunning.get()) report(e);
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
        int count = mAdapter.getCount();
        runOnUiThread(() -> mSummary.setText(
            count == 0 ? getString(R.string.arp_none)
                       : count + " " + getString(R.string.arp_found)
        ));
    }

    // ── ARP logic ─────────────────────────────────────────────────────────────

    private String getSubnetBase(Target t) {
        String ip = t.getAddress().getHostAddress();
        int lastDot = ip.lastIndexOf('.');
        return lastDot >= 0 ? ip.substring(0, lastDot) : ip;
    }

    /** Quick ping sweep to populate the kernel ARP cache. */
    private void pingSubnet(String base) {
        ExecutorService pool = Executors.newFixedThreadPool(THREAD_POOL);
        for (int i = 1; i <= 254; i++) {
            if (!mRunning.get()) break;
            final String ip = base + "." + i;
            pool.submit(() -> {
                try {
                    InetAddress.getByName(ip).isReachable(PING_TIMEOUT_MS);
                } catch (Exception ignored) {}
            });
        }
        pool.shutdown();
        try { pool.awaitTermination(30, TimeUnit.SECONDS); } catch (InterruptedException ignored) {}
    }

    /** Parse /proc/net/arp — available on all Linux/Android without root. */
    private List<ArpEntry> readArpTable() {
        List<ArpEntry> result = new ArrayList<>();
        try (BufferedReader br = new BufferedReader(new FileReader("/proc/net/arp"))) {
            String line;
            boolean first = true;
            while ((line = br.readLine()) != null) {
                if (first) { first = false; continue; } // skip header
                String[] cols = line.trim().split("\\s+");
                if (cols.length < 4) continue;
                String ip    = cols[0];
                String flags = cols[2]; // 0x2 = complete entry
                String mac   = cols[3];
                if ("00:00:00:00:00:00".equals(mac) || mac.isEmpty()) continue;
                if (!"0x2".equalsIgnoreCase(flags)) continue; // skip incomplete

                String vendor   = resolveVendor(mac);
                String hostname = resolveHostname(ip);
                result.add(new ArpEntry(ip, mac.toLowerCase(), vendor, hostname));
            }
        } catch (Exception e) {
            LoggingHelper.w(TAG, "Cannot read /proc/net/arp: " + e.getMessage());
        }
        return result;
    }

    private String resolveVendor(String mac) {
        if (mac == null || mac.length() < 8) return "Unknown";
        String prefix = mac.substring(0, 8).toLowerCase();
        String v = OUI.get(prefix);
        return v != null ? v : "Unknown";
    }

    private String resolveHostname(String ip) {
        try {
            String h = InetAddress.getByName(ip).getCanonicalHostName();
            return h.equals(ip) ? "" : h;
        } catch (Exception e) { return ""; }
    }

    // ── Debug helpers ─────────────────────────────────────────────────────────

    private void emitDebugEntries() {
        Object[][] fakes = {
            {"192.168.1.1",   "00:25:9c:ab:12:34", "Cisco",        "router.home"},
            {"192.168.1.2",   "8c:8d:28:11:22:33", "Intel",        "desktop.home"},
            {"192.168.1.5",   "b8:27:eb:44:55:66", "Raspberry Pi", "pi.home"},
            {"192.168.1.10",  "a4:83:e7:77:88:99", "Apple",        "macbook.local"},
            {"192.168.1.105", "00:11:22:33:44:55", "Unknown",      ""},
        };
        for (Object[] f : fakes) {
            if (!mRunning.get()) break;
            report(new ArpEntry((String)f[0], (String)f[1], (String)f[2], (String)f[3]));
            try { Thread.sleep(200); } catch (InterruptedException ignored) {}
        }
    }

    // ── UI helpers ────────────────────────────────────────────────────────────

    private void report(ArpEntry e) {
        runOnUiThread(() -> {
            mAdapter.add(e);
            mAdapter.notifyDataSetChanged();
        });
    }

    private class ArpAdapter extends ArrayAdapter<ArpEntry> {
        ArpAdapter() {
            super(ArpScanner.this, R.layout.plugin_arp_scanner_item, new ArrayList<>());
        }

        @Override
        public View getView(int position, View convertView, ViewGroup parent) {
            if (convertView == null)
                convertView = LayoutInflater.from(getContext())
                    .inflate(R.layout.plugin_arp_scanner_item, parent, false);

            ArpEntry e = getItem(position);
            TextView tvIp      = convertView.findViewById(R.id.arpItemIp);
            TextView tvMac     = convertView.findViewById(R.id.arpItemMac);
            TextView tvVendor  = convertView.findViewById(R.id.arpItemVendor);
            TextView tvHost    = convertView.findViewById(R.id.arpItemHostname);

            tvIp.setText(e.ip);
            tvMac.setText(e.mac);
            tvVendor.setText(e.vendor);
            tvHost.setText(e.hostname);

            boolean known = !"Unknown".equals(e.vendor);
            tvVendor.setTextColor(known
                ? ContextCompat.getColor(getContext(), R.color.app_color)
                : Color.parseColor("#757575"));

            return convertView;
        }
    }
}
