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

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;

public class TftpScanner extends Plugin {

    // --------------- result model ---------------
    public static class TftpResult {
        public enum Kind { INFO, WARN, VULN }
        public Kind kind;
        public String label;
        public String value;

        public TftpResult(Kind kind, String label, String value) {
            this.kind = kind;
            this.label = label;
            this.value = value;
        }
    }

    private static final String[] EXTRA_FILES = {"passwd", "config", "/etc/passwd"};

    // --------------- adapter ---------------
    private class TftpAdapter extends ArrayAdapter<TftpResult> {
        TftpAdapter(List<TftpResult> items) {
            super(TftpScanner.this, R.layout.plugin_tftp_scanner_item, items);
        }

        @Override
        public View getView(int position, View convertView, android.view.ViewGroup parent) {
            if (convertView == null) {
                convertView = getLayoutInflater().inflate(R.layout.plugin_tftp_scanner_item, parent, false);
            }
            TftpResult r = getItem(position);
            TextView labelView = convertView.findViewById(R.id.tftpItemLabel);
            TextView valueView = convertView.findViewById(R.id.tftpItemValue);
            if (r != null) {
                labelView.setText(r.label);
                valueView.setText(r.value);
                int color;
                switch (r.kind) {
                    case VULN: color = 0xFFD32F2F; break;
                    case WARN: color = 0xFFF57C00; break;
                    default:   color = ContextCompat.getColor(TftpScanner.this, R.color.app_color); break;
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
    private final List<TftpResult> mResults = new ArrayList<>();
    private TftpAdapter mAdapter;
    private Future<?> mJob;
    private final AtomicBoolean mRunning = new AtomicBoolean(false);

    // --------------- constructor ---------------
    public TftpScanner() {
        super(R.string.tftp_scanner, R.string.tftp_scanner_desc,
                new Target.Type[]{Target.Type.ENDPOINT, Target.Type.REMOTE},
                R.layout.plugin_tftp_scanner, R.drawable.action_scanner);
    }

    // --------------- lifecycle ---------------
    @Override
    public void onCreate(Bundle savedInstanceState) {
        SharedPreferences prefs = getSharedPreferences("THEME", MODE_PRIVATE);
        int theme = prefs.getInt("theme", R.style.AppTheme);
        setTheme(theme);

        super.onCreate(savedInstanceState);

        mFab = findViewById(R.id.tftpToggleButton);
        mProgress = findViewById(R.id.tftpActivity);
        mList = findViewById(android.R.id.list);

        mAdapter = new TftpAdapter(mResults);
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
        addResult(new TftpResult(TftpResult.Kind.VULN, "TFTP open",
                "Server sent data — unauthenticated file read possible"));
        addResult(new TftpResult(TftpResult.Kind.INFO, "File read",
                "Received 512 bytes for 'config'"));
    }

    // --------------- core logic ---------------
    private void scan(String ip) {
        boolean serverReachable = false;

        // Initial probe with filename "test"
        TftpProbeResult initial = probeTftp(ip, "test");
        if (initial != null) {
            serverReachable = true;
            handleProbeResult(initial, "test");
        }

        if (!mRunning.get()) return;

        if (!serverReachable) {
            addResult(new TftpResult(TftpResult.Kind.INFO, "TFTP",
                    "Port 69 not responding"));
            return;
        }

        // Try additional filenames
        for (String filename : EXTRA_FILES) {
            if (!mRunning.get()) break;
            TftpProbeResult result = probeTftp(ip, filename);
            if (result != null) {
                handleProbeResult(result, filename);
            }
        }
    }

    private void handleProbeResult(TftpProbeResult result, String filename) {
        if (result.opcode == 3) { // DATA
            addResult(new TftpResult(TftpResult.Kind.VULN, "TFTP open",
                    "Server sent data for '" + filename + "' — unauthenticated file read possible"));
        } else if (result.opcode == 5) { // ERROR
            int errCode = result.errorCode;
            String errMsg = result.errorMsg;
            if (errCode == 1) {
                addResult(new TftpResult(TftpResult.Kind.WARN, "TFTP open",
                        "Server reachable (file not found for '" + filename + "') — anonymous access enabled"));
            } else {
                addResult(new TftpResult(TftpResult.Kind.INFO, "TFTP error " + errCode,
                        errMsg + " for '" + filename + "'"));
            }
        }
    }

    private static class TftpProbeResult {
        int opcode;
        int errorCode;
        String errorMsg;
        int dataLength;
    }

    private TftpProbeResult probeTftp(String ip, String filename) {
        try {
            // Build RRQ packet: {0x00, 0x01} + filename + 0x00 + "octet" + 0x00
            byte[] fnBytes = filename.getBytes("UTF-8");
            byte[] mode = "octet".getBytes("UTF-8");
            byte[] pkt = new byte[2 + fnBytes.length + 1 + mode.length + 1];
            pkt[0] = 0x00; pkt[1] = 0x01; // opcode RRQ
            java.lang.System.arraycopy(fnBytes, 0, pkt, 2, fnBytes.length);
            pkt[2 + fnBytes.length] = 0x00;
            java.lang.System.arraycopy(mode, 0, pkt, 2 + fnBytes.length + 1, mode.length);
            pkt[pkt.length - 1] = 0x00;

            DatagramSocket sock = new DatagramSocket();
            sock.setSoTimeout(3000);
            InetAddress addr = InetAddress.getByName(ip);
            sock.send(new DatagramPacket(pkt, pkt.length, addr, 69));

            byte[] buf = new byte[1024];
            DatagramPacket resp = new DatagramPacket(buf, buf.length);
            sock.receive(resp);
            sock.close();

            byte[] data = resp.getData();
            int len = resp.getLength();
            if (len < 2) return null;

            TftpProbeResult result = new TftpProbeResult();
            result.opcode = ((data[0] & 0xFF) << 8) | (data[1] & 0xFF);

            if (result.opcode == 5 && len >= 4) { // ERROR
                result.errorCode = ((data[2] & 0xFF) << 8) | (data[3] & 0xFF);
                // Read error message (null-terminated string starting at byte 4)
                int msgEnd = 4;
                while (msgEnd < len && data[msgEnd] != 0) msgEnd++;
                result.errorMsg = new String(data, 4, msgEnd - 4, "UTF-8");
            } else if (result.opcode == 3) { // DATA
                result.dataLength = len - 4; // minus 4-byte header
            }
            return result;
        } catch (java.net.SocketTimeoutException e) {
            return null;
        } catch (Exception e) {
            return null;
        }
    }

    // --------------- helpers ---------------
    private void addResult(TftpResult result) {
        runOnUiThread(() -> {
            mResults.add(result);
            mAdapter.notifyDataSetChanged();
        });
    }
}
