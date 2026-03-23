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
import java.io.OutputStream;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;

public class RdpFingerprinter extends Plugin {

    // --------------- result model ---------------
    public static class RdpResult {
        public enum Kind { INFO, WARN, VULN }
        public Kind kind;
        public String label;
        public String value;

        public RdpResult(Kind kind, String label, String value) {
            this.kind = kind;
            this.label = label;
            this.value = value;
        }
    }

    // --------------- adapter ---------------
    private class RdpAdapter extends ArrayAdapter<RdpResult> {
        RdpAdapter(List<RdpResult> items) {
            super(RdpFingerprinter.this, R.layout.plugin_rdp_fingerprinter_item, items);
        }

        @Override
        public View getView(int position, View convertView, android.view.ViewGroup parent) {
            if (convertView == null) {
                convertView = getLayoutInflater().inflate(R.layout.plugin_rdp_fingerprinter_item, parent, false);
            }
            RdpResult r = getItem(position);
            TextView labelView = convertView.findViewById(R.id.rdpItemLabel);
            TextView valueView = convertView.findViewById(R.id.rdpItemValue);
            if (r != null) {
                labelView.setText(r.label);
                valueView.setText(r.value);
                int color;
                switch (r.kind) {
                    case VULN: color = 0xFFD32F2F; break;
                    case WARN:  color = 0xFFF57C00; break;
                    default:    color = ContextCompat.getColor(RdpFingerprinter.this, R.color.app_color); break;
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
    private final List<RdpResult> mResults = new ArrayList<>();
    private RdpAdapter mAdapter;
    private Future<?> mJob;
    private final AtomicBoolean mRunning = new AtomicBoolean(false);

    // --------------- constructor ---------------
    public RdpFingerprinter() {
        super(R.string.rdp_fingerprinter, R.string.rdp_fingerprinter_desc,
                new Target.Type[]{Target.Type.ENDPOINT, Target.Type.REMOTE},
                R.layout.plugin_rdp_fingerprinter, R.drawable.action_scanner);
    }

    // --------------- lifecycle ---------------
    @Override
    public void onCreate(Bundle savedInstanceState) {
        SharedPreferences prefs = getSharedPreferences("THEME", MODE_PRIVATE);
        int theme = prefs.getInt("theme", R.style.AppTheme);
        setTheme(theme);

        super.onCreate(savedInstanceState);

        mFab = findViewById(R.id.rdpToggleButton);
        mProgress = findViewById(R.id.rdpActivity);
        mList = findViewById(android.R.id.list);

        mAdapter = new RdpAdapter(mResults);
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
        addResult(new RdpResult(RdpResult.Kind.VULN, "No NLA",
                "NLA not required — password spray possible without account lockout"));
        addResult(new RdpResult(RdpResult.Kind.INFO, "RDP open",
                "Port 3389 responded to negotiation request"));
        addResult(new RdpResult(RdpResult.Kind.INFO, "TLS selected", "Protocol 0x01"));
    }

    // --------------- core logic ---------------
    private void scan(String ip) {
        // TPKT + X.224 Connection Request (COTP)
        byte[] cotp = {
            0x03, 0x00, 0x00, 0x13,
            0x0E, (byte)0xE0, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x01, 0x00, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00
        };

        try (Socket socket = new Socket()) {
            socket.connect(new java.net.InetSocketAddress(ip, 3389), 5000);
            socket.setSoTimeout(5000);
            OutputStream out = socket.getOutputStream();
            InputStream in = socket.getInputStream();

            out.write(cotp);
            out.flush();

            byte[] response = new byte[64];
            int read = in.read(response);

            if (read < 11) {
                addResult(new RdpResult(RdpResult.Kind.INFO, "Port 3389", "Closed or filtered"));
                return;
            }

            // byte[7] should be 0xD0 for Connection Confirm
            if (response[7] != (byte)0xD0) {
                addResult(new RdpResult(RdpResult.Kind.INFO, "Port 3389",
                        "Responded but unexpected COTP response: 0x" + Integer.toHexString(response[7] & 0xFF)));
                return;
            }

            addResult(new RdpResult(RdpResult.Kind.INFO, "RDP open",
                    "Port 3389 responded to negotiation request"));

            // Parse RDP Negotiation Response at bytes[11..14]
            if (read >= 15) {
                int type = response[11] & 0xFF;
                if (type == 0x02) { // NegRsp
                    int proto = ((response[14] & 0xFF) << 8) | (response[13] & 0xFF);
                    switch (proto) {
                        case 0x00:
                            addResult(new RdpResult(RdpResult.Kind.VULN, "No NLA",
                                    "NLA not required — password spray possible without account lockout"));
                            break;
                        case 0x01:
                            addResult(new RdpResult(RdpResult.Kind.INFO, "TLS only",
                                    "SSL/TLS only selected"));
                            break;
                        case 0x02:
                            addResult(new RdpResult(RdpResult.Kind.INFO, "NLA required",
                                    "Credential Security Support Provider enabled"));
                            break;
                        case 0x03:
                            addResult(new RdpResult(RdpResult.Kind.INFO, "NLA+EUA",
                                    "NLA with Early User Authentication"));
                            break;
                        default:
                            addResult(new RdpResult(RdpResult.Kind.INFO, "Protocol",
                                    "0x" + Integer.toHexString(proto)));
                            break;
                    }
                }
            }
        } catch (java.net.ConnectException e) {
            addResult(new RdpResult(RdpResult.Kind.INFO, "Port 3389", "Not open"));
        } catch (Exception e) {
            String msg = e.getMessage();
            if (msg != null && msg.contains("Connection refused")) {
                addResult(new RdpResult(RdpResult.Kind.INFO, "Port 3389", "Not open"));
            }
        }
    }

    // --------------- helpers ---------------
    private void addResult(RdpResult result) {
        runOnUiThread(() -> {
            mResults.add(result);
            mAdapter.notifyDataSetChanged();
        });
    }
}
