package org.csploit.android.plugins;

import android.Manifest;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.net.wifi.ScanResult;
import android.net.wifi.WifiManager;
import android.os.Bundle;
import android.view.View;
import android.widget.ArrayAdapter;
import android.widget.ListView;
import android.widget.TextView;

import androidx.core.content.ContextCompat;

import com.google.android.material.floatingactionbutton.FloatingActionButton;

import org.csploit.android.BuildConfig;
import org.csploit.android.R;
import org.csploit.android.core.Plugin;
import org.csploit.android.helpers.AnimationHelper;
import org.csploit.android.net.Target;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

public class WifiAnalyzer extends Plugin {

    // --------------- result model ---------------
    public static class WifiResult {
        public String ssid;
        public String bssid;
        public String security;
        public String channel;
        public String signal;

        public WifiResult(String ssid, String bssid, String security, String channel, String signal) {
            this.ssid = ssid;
            this.bssid = bssid;
            this.security = security;
            this.channel = channel;
            this.signal = signal;
        }
    }

    // --------------- adapter ---------------
    private class WifiAdapter extends ArrayAdapter<WifiResult> {
        WifiAdapter(List<WifiResult> items) {
            super(WifiAnalyzer.this, R.layout.plugin_wifi_analyzer_item, items);
        }

        @Override
        public View getView(int position, View convertView, android.view.ViewGroup parent) {
            if (convertView == null) {
                convertView = getLayoutInflater().inflate(R.layout.plugin_wifi_analyzer_item, parent, false);
            }
            WifiResult r = getItem(position);
            TextView ssidView     = convertView.findViewById(R.id.wifiItemSsid);
            TextView bssidView    = convertView.findViewById(R.id.wifiItemBssid);
            TextView secView      = convertView.findViewById(R.id.wifiItemSecurity);
            TextView signalView   = convertView.findViewById(R.id.wifiItemSignal);
            if (r != null) {
                ssidView.setText(r.ssid.isEmpty() ? "<hidden>" : r.ssid);
                bssidView.setText(r.bssid);
                secView.setText(r.security + "  ch:" + r.channel);
                signalView.setText(r.signal);

                int color;
                String sec = r.security;
                if (sec.equals("Open") || sec.contains("WEP")) {
                    color = 0xFFD32F2F;
                } else if (sec.contains("WPA3") || sec.contains("WPA2")) {
                    color = 0xFF388E3C;
                } else if (sec.contains("WPA")) {
                    color = 0xFFF57C00;
                } else {
                    color = ContextCompat.getColor(WifiAnalyzer.this, R.color.app_color);
                }
                secView.setTextColor(color);
            }
            return convertView;
        }
    }

    // --------------- fields ---------------
    private FloatingActionButton mFab;
    private View mProgress;
    private ListView mList;
    private final List<WifiResult> mResults = new ArrayList<>();
    private WifiAdapter mAdapter;
    private WifiManager mWifiManager;
    private BroadcastReceiver mScanReceiver;
    private boolean mScanning = false;

    // --------------- constructor ---------------
    public WifiAnalyzer() {
        super(R.string.wifi_analyzer, R.string.wifi_analyzer_desc,
                new Target.Type[]{Target.Type.NETWORK},
                R.layout.plugin_wifi_analyzer, R.drawable.action_scanner);
    }

    // --------------- lifecycle ---------------
    @Override
    public void onCreate(Bundle savedInstanceState) {
        SharedPreferences prefs = getSharedPreferences("THEME", MODE_PRIVATE);
        int theme = prefs.getInt("theme", R.style.AppTheme);
        setTheme(theme);

        super.onCreate(savedInstanceState);

        mFab = findViewById(R.id.wifiScanButton);
        mProgress = findViewById(R.id.wifiActivity);
        mList = findViewById(android.R.id.list);

        mAdapter = new WifiAdapter(mResults);
        mList.setAdapter(mAdapter);

        mWifiManager = (WifiManager) getApplicationContext().getSystemService(WIFI_SERVICE);

        mScanReceiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                boolean success = intent.getBooleanExtra(WifiManager.EXTRA_RESULTS_UPDATED, false);
                processScanResults();
                stopScan();
            }
        };

        mFab.setOnClickListener(v -> {
            if (mScanning) {
                stopScan();
            } else {
                startScan();
            }
        });
    }

    @Override
    public void onDestroy() {
        try {
            unregisterReceiver(mScanReceiver);
        } catch (Exception ignored) {}
        super.onDestroy();
    }

    @Override
    public void onBackPressed() {
        stopScan();
        super.onBackPressed();
        overridePendingTransition(R.anim.fadeout, R.anim.fadein);
    }

    // --------------- scan control ---------------
    private void startScan() {
        if (BuildConfig.DEBUG) {
            emitDebug();
            return;
        }

        // Check permission
        if (ContextCompat.checkSelfPermission(this, Manifest.permission.ACCESS_FINE_LOCATION)
                != PackageManager.PERMISSION_GRANTED) {
            mResults.clear();
            mResults.add(new WifiResult("Permission required", "", "ACCESS_FINE_LOCATION needed", "", ""));
            mAdapter.notifyDataSetChanged();
            return;
        }

        if (mWifiManager == null || !mWifiManager.isWifiEnabled()) {
            mResults.clear();
            mResults.add(new WifiResult("Wi-Fi disabled", "", "Enable Wi-Fi to scan", "", ""));
            mAdapter.notifyDataSetChanged();
            return;
        }

        mScanning = true;
        mResults.clear();
        mAdapter.notifyDataSetChanged();
        mProgress.setVisibility(View.VISIBLE);
        mFab.setImageDrawable(ContextCompat.getDrawable(this, R.drawable.ic_stop_24dp));

        registerReceiver(mScanReceiver,
                new IntentFilter(WifiManager.SCAN_RESULTS_AVAILABLE_ACTION));

        boolean started = mWifiManager.startScan();
        if (!started) {
            // Use cached results on failure
            processScanResults();
            stopScan();
        }
    }

    private void stopScan() {
        mScanning = false;
        try { unregisterReceiver(mScanReceiver); } catch (Exception ignored) {}
        mProgress.setVisibility(View.GONE);
        mFab.setImageDrawable(ContextCompat.getDrawable(this, R.drawable.ic_play_arrow_24dp));
    }

    // --------------- debug ---------------
    private void emitDebug() {
        mResults.clear();
        mResults.add(new WifiResult("HomeNetwork", "AA:BB:CC:DD:EE:01", "WPA2", "6", "-55 dBm"));
        mResults.add(new WifiResult("CoffeeShop", "AA:BB:CC:DD:EE:02", "Open", "11", "-70 dBm"));
        mResults.add(new WifiResult("OldRouter", "AA:BB:CC:DD:EE:03", "WEP", "1", "-80 dBm"));
        mResults.add(new WifiResult("OfficeWifi", "AA:BB:CC:DD:EE:04", "WPA3", "36", "-65 dBm"));
        mResults.add(new WifiResult("GuestNet", "AA:BB:CC:DD:EE:05", "WPA", "6", "-75 dBm"));
        mAdapter.notifyDataSetChanged();
    }

    // --------------- process results ---------------
    private void processScanResults() {
        if (mWifiManager == null) return;
        List<ScanResult> scanResults;
        try {
            scanResults = mWifiManager.getScanResults();
        } catch (Exception e) {
            return;
        }
        if (scanResults == null) return;

        // Sort by signal strength descending
        Collections.sort(scanResults, (a, b) -> b.level - a.level);

        mResults.clear();
        for (ScanResult sr : scanResults) {
            String ssid = sr.SSID != null ? sr.SSID : "";
            String bssid = sr.BSSID != null ? sr.BSSID : "";
            String security = parseSecurity(sr.capabilities);
            String channel = freqToChannel(sr.frequency);
            String signal = sr.level + " dBm";
            mResults.add(new WifiResult(ssid, bssid, security, channel, signal));
        }
        mAdapter.notifyDataSetChanged();
    }

    private String parseSecurity(String caps) {
        if (caps == null || caps.isEmpty()) return "Open";
        if (caps.contains("[WPA3")) return "WPA3";
        if (caps.contains("[WPA2")) return "WPA2";
        if (caps.contains("[WPA")) return "WPA";
        if (caps.contains("[WEP")) return "WEP";
        return "Open";
    }

    private String freqToChannel(int freq) {
        if (freq >= 2412 && freq <= 2484) {
            return String.valueOf((freq - 2407) / 5);
        } else if (freq >= 5170 && freq <= 5825) {
            return String.valueOf((freq - 5000) / 5);
        }
        return "?";
    }
}
