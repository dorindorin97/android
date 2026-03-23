package org.csploit.android.plugins;

import android.content.SharedPreferences;
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
import org.csploit.android.core.System;
import org.csploit.android.helpers.AnimationHelper;
import org.csploit.android.helpers.ThreadHelper;
import org.csploit.android.net.Target;

import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;

public class TelnetScanner extends Plugin {

    // --------------- result model ---------------
    public static class TelnetResult {
        public enum Kind { INFO, WARN, VULN }
        public Kind kind;
        public String label;
        public String value;

        public TelnetResult(Kind kind, String label, String value) {
            this.kind = kind;
            this.label = label;
            this.value = value;
        }
    }

    private static final int[] PORTS = {23, 2323, 992, 107};

    // --------------- adapter ---------------
    private class TelnetAdapter extends ArrayAdapter<TelnetResult> {
        TelnetAdapter(List<TelnetResult> items) {
            super(TelnetScanner.this, R.layout.plugin_telnet_scanner_item, items);
        }

        @Override
        public View getView(int position, View convertView, android.view.ViewGroup parent) {
            if (convertView == null) {
                convertView = getLayoutInflater().inflate(R.layout.plugin_telnet_scanner_item, parent, false);
            }
            TelnetResult r = getItem(position);
            TextView labelView = convertView.findViewById(R.id.telnetItemLabel);
            TextView valueView = convertView.findViewById(R.id.telnetItemValue);
            if (r != null) {
                labelView.setText(r.label);
                valueView.setText(r.value);
                int color;
                switch (r.kind) {
                    case VULN: color = 0xFFD32F2F; break;
                    case WARN: color = 0xFFF57C00; break;
                    default:   color = ContextCompat.getColor(TelnetScanner.this, R.color.app_color); break;
                }
                labelView.setTextColor(color);
            }
            return convertView;
        }
    }

    // --------------- fields ---------------
    private FloatingActionButton mFab;
    private View mProgress;
    private ListView mList;
    private final List<TelnetResult> mResults = new ArrayList<>();
    private TelnetAdapter mAdapter;
    private Future<?> mJob;
    private final AtomicBoolean mRunning = new AtomicBoolean(false);

    // --------------- constructor ---------------
    public TelnetScanner() {
        super(R.string.telnet_scanner, R.string.telnet_scanner_desc,
                new Target.Type[]{Target.Type.ENDPOINT, Target.Type.REMOTE},
                R.layout.plugin_telnet_scanner, R.drawable.action_scanner);
    }

    // --------------- lifecycle ---------------
    @Override
    public void onCreate(Bundle savedInstanceState) {
        SharedPreferences prefs = getSharedPreferences("THEME", MODE_PRIVATE);
        int theme = prefs.getInt("theme", R.style.AppTheme);
        setTheme(theme);

        super.onCreate(savedInstanceState);

        mFab = findViewById(R.id.telnetToggleButton);
        mProgress = findViewById(R.id.telnetActivity);
        mList = findViewById(android.R.id.list);

        mAdapter = new TelnetAdapter(mResults);
        mList.setAdapter(mAdapter);

        mFab.setOnClickListener(v -> {
            if (mRunning.get()) {
                stopScan();
            } else {
                startScan();
            }
        });
    }

    @Override
    public void onBackPressed() {
        stopScan();
        super.onBackPressed();
        overridePendingTransition(R.anim.fadeout, R.anim.fadein);
    }

    // --------------- scan control ---------------
    private void startScan() {
        mRunning.set(true);
        mResults.clear();
        mAdapter.notifyDataSetChanged();
        mProgress.setVisibility(View.VISIBLE);
        mFab.setImageDrawable(ContextCompat.getDrawable(this, R.drawable.ic_stop_24dp));

        String ip = System.getCurrentTarget().getAddress().getHostAddress();

        if (BuildConfig.DEBUG) {
            emitDebug();
            stopScan();
            return;
        }

        mJob = ThreadHelper.submit(() -> {
            try {
                scan(ip);
            } catch (Exception ignored) {
            } finally {
                runOnUiThread(this::stopScan);
            }
        });
    }

    private void stopScan() {
        mRunning.set(false);
        if (mJob != null && !mJob.isDone()) {
            mJob.cancel(true);
        }
        runOnUiThread(() -> {
            mProgress.setVisibility(View.GONE);
            mFab.setImageDrawable(ContextCompat.getDrawable(this, R.drawable.ic_play_arrow_24dp));
        });
    }

    // --------------- debug ---------------
    private void emitDebug() {
        addResult(new TelnetResult(TelnetResult.Kind.VULN, "Telnet open: 23",
                "Cleartext protocol — credential exposure risk"));
        addResult(new TelnetResult(TelnetResult.Kind.INFO, "Banner",
                "Cisco IOS Software, Version 15.1 - login:"));
        addResult(new TelnetResult(TelnetResult.Kind.WARN, "Login prompt",
                "Telnet accepting credentials"));
    }

    // --------------- core logic ---------------
    private void scan(String ip) {
        for (int port : PORTS) {
            if (!mRunning.get()) break;
            probePort(ip, port);
        }
    }

    private void probePort(String ip, int port) {
        try (Socket socket = new Socket()) {
            socket.connect(new InetSocketAddress(ip, port), 4000);
            socket.setSoTimeout(4000);
            InputStream in = socket.getInputStream();

            addResult(new TelnetResult(TelnetResult.Kind.VULN,
                    "Telnet open: " + port,
                    "Cleartext protocol — credential exposure risk"));

            // Read banner
            byte[] buf = new byte[512];
            int read = 0;
            try {
                read = in.read(buf);
            } catch (Exception ignored) {}

            if (read > 0) {
                // Strip IAC negotiation bytes (0xFF sequences)
                StringBuilder banner = new StringBuilder();
                for (int i = 0; i < read; i++) {
                    int b = buf[i] & 0xFF;
                    if (b == 0xFF) {
                        // IAC: skip next 2 bytes (command + option)
                        i += 2;
                    } else if (b >= 32 && b < 127) {
                        banner.append((char) b);
                    } else if (b == '\n' || b == '\r') {
                        banner.append(' ');
                    }
                }
                String bannerStr = banner.toString().trim();
                if (!bannerStr.isEmpty()) {
                    addResult(new TelnetResult(TelnetResult.Kind.INFO, "Banner", bannerStr));
                    if (bannerStr.toLowerCase().contains("login:")) {
                        addResult(new TelnetResult(TelnetResult.Kind.WARN, "Login prompt",
                                "Telnet accepting credentials"));
                    }
                }
            }
        } catch (java.net.ConnectException e) {
            addResult(new TelnetResult(TelnetResult.Kind.INFO,
                    "Port " + port, "Not open"));
        } catch (Exception ignored) {
        }
    }

    // --------------- helpers ---------------
    private void addResult(TelnetResult result) {
        runOnUiThread(() -> {
            mResults.add(result);
            mAdapter.notifyDataSetChanged();
        });
    }
}
