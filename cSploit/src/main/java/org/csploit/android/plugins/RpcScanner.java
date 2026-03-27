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
import java.nio.ByteBuffer;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;

public class RpcScanner extends Plugin {

    // --------------- result model ---------------
    public static class RpcResult {
        public String program;
        public String version;
        public String protocol;
        public String port;
        public String name;

        public RpcResult(String program, String version, String protocol, String port, String name) {
            this.program = program;
            this.version = version;
            this.protocol = protocol;
            this.port = port;
            this.name = name;
        }
    }

    // --------------- known programs ---------------
    private static final Map<Integer, String> PROGRAMS = new HashMap<>();
    static {
        PROGRAMS.put(100000, "portmapper");
        PROGRAMS.put(100003, "nfs");
        PROGRAMS.put(100005, "mountd");
        PROGRAMS.put(100021, "nlockmgr");
        PROGRAMS.put(100024, "status");
        PROGRAMS.put(100227, "nfs_acl");
        PROGRAMS.put(100011, "rquotad");
        PROGRAMS.put(100001, "rstatd");
        PROGRAMS.put(100002, "rusersd");
        PROGRAMS.put(100004, "ypserv");
        PROGRAMS.put(100007, "ypbind");
        PROGRAMS.put(100008, "walld");
        PROGRAMS.put(100012, "sprayd");
    }

    // --------------- adapter ---------------
    private class RpcAdapter extends ArrayAdapter<RpcResult> {
        RpcAdapter(List<RpcResult> items) {
            super(RpcScanner.this, R.layout.plugin_rpc_scanner_item, items);
        }

        @Override
        public View getView(int position, View convertView, android.view.ViewGroup parent) {
            if (convertView == null) {
                convertView = getLayoutInflater().inflate(R.layout.plugin_rpc_scanner_item, parent, false);
            }
            RpcResult r = getItem(position);
            TextView progView = convertView.findViewById(R.id.rpcItemProg);
            TextView infoView = convertView.findViewById(R.id.rpcItemInfo);
            if (r != null) {
                progView.setText(r.name + " (" + r.program + ")");
                infoView.setText(r.protocol + " port " + r.port + " v" + r.version);
                int color = (r.name != null && r.name.toLowerCase().contains("nfs"))
                        ? 0xFFD32F2F
                        : ContextCompat.getColor(RpcScanner.this, R.color.app_color);
                progView.setTextColor(color);
            }
            return convertView;
        }
    }

    // --------------- fields ---------------
    private FloatingActionButton mFab;
    private View mProgress;
    private ListView mList;
    private final List<RpcResult> mResults = new ArrayList<>();
    private RpcAdapter mAdapter;
    private Future<?> mJob;
    private final AtomicBoolean mRunning = new AtomicBoolean(false);

    // --------------- constructor ---------------
    public RpcScanner() {
        super(R.string.rpc_scanner, R.string.rpc_scanner_desc,
                new Target.Type[]{Target.Type.ENDPOINT, Target.Type.REMOTE},
                R.layout.plugin_rpc_scanner, R.drawable.action_scanner);
    }

    // --------------- lifecycle ---------------
    @Override
    public void onCreate(Bundle savedInstanceState) {
        SharedPreferences prefs = getSharedPreferences("THEME", MODE_PRIVATE);
        int theme = prefs.getInt("theme", R.style.AppTheme);
        setTheme(theme);

        super.onCreate(savedInstanceState);

        mFab = findViewById(R.id.rpcToggleButton);
        mProgress = findViewById(R.id.rpcActivity);
        mList = findViewById(android.R.id.list);

        mAdapter = new RpcAdapter(mResults);
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
            mProgress.setVisibility(View.INVISIBLE);
            mFab.setImageDrawable(ContextCompat.getDrawable(this, R.drawable.ic_play_arrow_24dp));
        });
    }

    // --------------- debug ---------------
    private void emitDebug() {
        addResult(new RpcResult("100000", "2", "TCP", "111", "portmapper"));
        addResult(new RpcResult("100003", "3", "TCP", "2049", "nfs"));
        addResult(new RpcResult("100005", "1", "UDP", "20048", "mountd"));
        addResult(new RpcResult("100021", "4", "TCP", "4045", "nlockmgr"));
    }

    // --------------- core logic ---------------
    private void scan(String ip) {
        byte[] rpcDump = buildRpcDump(false);
        List<RpcResult> results = null;

        // Try TCP first
        try {
            byte[] tcpPayload = buildRpcDump(true);
            try (Socket socket = new Socket()) {
                socket.connect(new java.net.InetSocketAddress(ip, 111), 5000);
                socket.setSoTimeout(5000);
                OutputStream out = socket.getOutputStream();
                InputStream in = socket.getInputStream();
                out.write(tcpPayload);
                out.flush();
                byte[] buf = new byte[8192];
                int read = in.read(buf);
                if (read > 0) {
                    results = parseRpcResponse(buf, read, true);
                }
            }
        } catch (Exception ignored) {
        }

        if (!mRunning.get()) return;

        // Try UDP if TCP failed
        if (results == null || results.isEmpty()) {
            try {
                DatagramSocket sock = new DatagramSocket();
                sock.setSoTimeout(3000);
                InetAddress addr = InetAddress.getByName(ip);
                sock.send(new DatagramPacket(rpcDump, rpcDump.length, addr, 111));
                byte[] buf = new byte[8192];
                DatagramPacket resp = new DatagramPacket(buf, buf.length);
                sock.receive(resp);
                sock.close();
                results = parseRpcResponse(resp.getData(), resp.getLength(), false);
            } catch (Exception ignored) {
            }
        }

        if (results == null || results.isEmpty()) {
            addResult(new RpcResult("111", "", "", "", "Portmapper not responding"));
        } else {
            for (RpcResult r : results) {
                if (!mRunning.get()) break;
                addResult(r);
            }
        }
    }

    private byte[] buildRpcDump(boolean tcp) {
        // XDR RPC DUMP call
        byte[] body = new byte[]{
            0x12, 0x34, 0x56, 0x78, // XID
            0x00, 0x00, 0x00, 0x00, // Call direction
            0x00, 0x00, 0x00, 0x02, // RPC version 2
            0x00, 0x01, (byte)0x86, (byte)0xA0, // Program: portmapper 100000
            0x00, 0x00, 0x00, 0x02, // Version 2
            0x00, 0x00, 0x00, 0x04, // Procedure: DUMP
            0x00, 0x00, 0x00, 0x00, // Credentials: AUTH_NULL flavor
            0x00, 0x00, 0x00, 0x00, // Credentials length 0
            0x00, 0x00, 0x00, 0x00, // Verifier: AUTH_NULL flavor
            0x00, 0x00, 0x00, 0x00  // Verifier length 0
        };
        if (!tcp) return body;
        // Prepend 4-byte record mark for TCP: length | 0x80000000
        int len = body.length;
        byte[] tcpBody = new byte[4 + len];
        int mark = (int)(len | 0x80000000L);
        tcpBody[0] = (byte)(mark >> 24);
        tcpBody[1] = (byte)(mark >> 16);
        tcpBody[2] = (byte)(mark >> 8);
        tcpBody[3] = (byte)(mark);
        java.lang.System.arraycopy(body, 0, tcpBody, 4, len);
        return tcpBody;
    }

    private List<RpcResult> parseRpcResponse(byte[] data, int len, boolean tcp) {
        List<RpcResult> results = new ArrayList<>();
        int offset = tcp ? 4 : 0; // skip record mark for TCP
        offset += 24; // skip XDR reply header (XID, reply, accept, verifier, etc.)
        if (offset >= len) return results;

        while (offset + 4 <= len) {
            int valueFollows = readInt(data, offset); offset += 4;
            if (valueFollows == 0) break;
            if (offset + 16 > len) break;
            int program = readInt(data, offset); offset += 4;
            int version = readInt(data, offset); offset += 4;
            int proto = readInt(data, offset); offset += 4;
            int port = readInt(data, offset); offset += 4;
            String protoStr = (proto == 6) ? "TCP" : (proto == 17 ? "UDP" : String.valueOf(proto));
            String name = PROGRAMS.containsKey(program)
                    ? PROGRAMS.get(program)
                    : "prog-" + program;
            results.add(new RpcResult(
                    String.valueOf(program),
                    String.valueOf(version),
                    protoStr,
                    String.valueOf(port),
                    name
            ));
        }
        return results;
    }

    private int readInt(byte[] data, int offset) {
        return ((data[offset] & 0xFF) << 24)
                | ((data[offset + 1] & 0xFF) << 16)
                | ((data[offset + 2] & 0xFF) << 8)
                | (data[offset + 3] & 0xFF);
    }

    // --------------- helpers ---------------
    private void addResult(RpcResult result) {
        runOnUiThread(() -> {
            mResults.add(result);
            mAdapter.notifyDataSetChanged();
        });
    }
}
