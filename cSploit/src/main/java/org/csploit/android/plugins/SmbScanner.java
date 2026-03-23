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
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.net.Socket;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;

public class SmbScanner extends Plugin {

    // --------------- result model ---------------
    public static class SmbResult {
        public enum Kind { INFO, WARN, VULN }
        public Kind kind;
        public String label;
        public String value;

        public SmbResult(Kind kind, String label, String value) {
            this.kind = kind;
            this.label = label;
            this.value = value;
        }
    }

    // --------------- adapter ---------------
    private class SmbAdapter extends ArrayAdapter<SmbResult> {
        SmbAdapter(List<SmbResult> items) {
            super(SmbScanner.this, R.layout.plugin_smb_scanner_item, items);
        }

        @Override
        public View getView(int position, View convertView, android.view.ViewGroup parent) {
            if (convertView == null) {
                convertView = getLayoutInflater().inflate(R.layout.plugin_smb_scanner_item, parent, false);
            }
            SmbResult r = getItem(position);
            TextView labelView = convertView.findViewById(R.id.smbItemLabel);
            TextView valueView = convertView.findViewById(R.id.smbItemValue);
            if (r != null) {
                labelView.setText(r.label);
                valueView.setText(r.value);
                int color;
                switch (r.kind) {
                    case VULN: color = 0xFFD32F2F; break;
                    case WARN:  color = 0xFFF57C00; break;
                    default:    color = ContextCompat.getColor(SmbScanner.this, R.color.app_color); break;
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
    private final List<SmbResult> mResults = new ArrayList<>();
    private SmbAdapter mAdapter;
    private Future<?> mJob;
    private final AtomicBoolean mRunning = new AtomicBoolean(false);

    // --------------- constructor ---------------
    public SmbScanner() {
        super(R.string.smb_scanner, R.string.smb_scanner_desc,
                new Target.Type[]{Target.Type.ENDPOINT, Target.Type.REMOTE},
                R.layout.plugin_smb_scanner, R.drawable.action_scanner);
    }

    // --------------- lifecycle ---------------
    @Override
    public void onCreate(Bundle savedInstanceState) {
        SharedPreferences prefs = getSharedPreferences("THEME", MODE_PRIVATE);
        int theme = prefs.getInt("theme", R.style.AppTheme);
        setTheme(theme);

        super.onCreate(savedInstanceState);

        mFab = findViewById(R.id.smbToggleButton);
        mProgress = findViewById(R.id.smbActivity);
        mList = findViewById(android.R.id.list);

        mAdapter = new SmbAdapter(mResults);
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
        addResult(new SmbResult(SmbResult.Kind.VULN, "SMBv1 Active",
                "Port 445 responded to SMBv1 negotiate — potential EternalBlue exposure"));
        addResult(new SmbResult(SmbResult.Kind.INFO, "Hostname", "DEBUG-PC"));
        addResult(new SmbResult(SmbResult.Kind.INFO, "Workgroup", "WORKGROUP"));
    }

    // --------------- core logic ---------------
    private void scan(String ip) throws Exception {
        boolean hasResults = false;

        // Step 1: NetBIOS Name Service UDP 137
        try {
            hasResults |= queryNetbios(ip);
        } catch (Exception ignored) {
        }

        if (!mRunning.get()) return;

        // Step 2: SMB negotiate TCP 445
        try {
            hasResults |= probeSmbv1(ip);
        } catch (Exception ignored) {
        }

        if (!hasResults) {
            addResult(new SmbResult(SmbResult.Kind.INFO, "No NetBIOS/SMB",
                    "Host did not respond"));
        }
    }

    private boolean queryNetbios(String ip) throws Exception {
        // Build 50-byte NBSTAT query
        byte[] query = new byte[50];
        query[0] = 0x12; query[1] = 0x34; // transaction id
        query[2] = 0x00; query[3] = 0x00; // flags
        query[4] = 0x00; query[5] = 0x01; // QDCOUNT=1
        query[6] = 0x00; query[7] = 0x00; // ANCOUNT=0
        query[8] = 0x00; query[9] = 0x00; // NSCOUNT=0
        query[10] = 0x00; query[11] = 0x00; // ARCOUNT=0
        // name: 0x20 + "CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" + 0x00
        query[12] = 0x20;
        byte[] encodedName = "CKAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA".getBytes("ASCII");
        java.lang.System.arraycopy(encodedName, 0, query, 13, encodedName.length);
        query[45] = 0x00;
        query[46] = 0x00; query[47] = 0x21; // type NBSTAT
        query[48] = 0x00; query[49] = 0x01; // class IN

        DatagramSocket sock = new DatagramSocket();
        sock.setSoTimeout(3000);
        InetAddress addr = InetAddress.getByName(ip);
        DatagramPacket pkt = new DatagramPacket(query, query.length, addr, 137);
        sock.send(pkt);

        byte[] buf = new byte[1024];
        DatagramPacket resp = new DatagramPacket(buf, buf.length);
        sock.receive(resp);
        sock.close();

        byte[] data = resp.getData();
        int len = resp.getLength();
        if (len < 57) return false;

        int numNames = data[56] & 0xFF;
        boolean found = false;
        for (int i = 0; i < numNames; i++) {
            int offset = 57 + i * 18;
            if (offset + 18 > len) break;
            String name = new String(data, offset, 15, "ASCII").trim();
            int flags = ((data[offset + 16] & 0xFF) << 8) | (data[offset + 17] & 0xFF);
            boolean isGroup = (flags & 0x8000) != 0;
            String label = isGroup ? "Workgroup" : "Hostname";
            addResult(new SmbResult(SmbResult.Kind.INFO, label, name));
            found = true;
        }
        return found;
    }

    private boolean probeSmbv1(String ip) throws Exception {
        byte[] negotiate = {
            0x00, 0x00, 0x00, 0x54,
            (byte)0xFF, 0x53, 0x4D, 0x42, 0x72, 0x00, 0x00, 0x00, 0x00, 0x18, 0x53, (byte)0xC8,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, (byte)0xFF, (byte)0xFF,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x31, 0x00, 0x02, 0x4C, 0x41, 0x4E, 0x4D,
            0x41, 0x4E, 0x31, 0x2E, 0x30, 0x00, 0x02, 0x4C, 0x4D, 0x31, 0x2E, 0x32, 0x58, 0x30,
            0x30, 0x32, 0x00, 0x02, 0x4E, 0x54, 0x20, 0x4C, 0x41, 0x4E, 0x4D, 0x41, 0x4E, 0x20,
            0x31, 0x2E, 0x30, 0x00, 0x02, 0x4E, 0x54, 0x20, 0x4C, 0x41, 0x4E, 0x4D, 0x41, 0x4E,
            0x20, 0x32, 0x2E, 0x31, 0x00
        };

        try (Socket socket = new Socket()) {
            socket.connect(new java.net.InetSocketAddress(ip, 445), 5000);
            socket.setSoTimeout(5000);
            OutputStream out = socket.getOutputStream();
            InputStream in = socket.getInputStream();
            out.write(negotiate);
            out.flush();

            byte[] response = new byte[200];
            int read = in.read(response);
            if (read >= 12 && response[8] == 0x72) {
                addResult(new SmbResult(SmbResult.Kind.VULN, "SMBv1 Active",
                        "Port 445 responded to SMBv1 negotiate — potential EternalBlue exposure"));
                return true;
            }
        } catch (java.net.ConnectException e) {
            addResult(new SmbResult(SmbResult.Kind.INFO, "SMB port", "445 closed or filtered"));
        }
        return false;
    }

    // --------------- helpers ---------------
    private void addResult(SmbResult result) {
        runOnUiThread(() -> {
            mResults.add(result);
            mAdapter.notifyDataSetChanged();
        });
    }
}
