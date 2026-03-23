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
import java.net.MulticastSocket;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;

public class MdnsSsdpDiscovery extends Plugin {

    // --------------- result model ---------------
    public static class DeviceResult {
        public String type;
        public String name;
        public String address;
        public String detail;

        public DeviceResult(String type, String name, String address, String detail) {
            this.type = type;
            this.name = name;
            this.address = address;
            this.detail = detail;
        }
    }

    // --------------- adapter ---------------
    private class DeviceAdapter extends ArrayAdapter<DeviceResult> {
        DeviceAdapter(List<DeviceResult> items) {
            super(MdnsSsdpDiscovery.this, R.layout.plugin_mdns_ssdp_item, items);
        }

        @Override
        public View getView(int position, View convertView, android.view.ViewGroup parent) {
            if (convertView == null) {
                convertView = getLayoutInflater().inflate(R.layout.plugin_mdns_ssdp_item, parent, false);
            }
            DeviceResult r = getItem(position);
            TextView typeView = convertView.findViewById(R.id.mdnsItemType);
            TextView nameView = convertView.findViewById(R.id.mdnsItemName);
            TextView addrView = convertView.findViewById(R.id.mdnsItemAddress);
            if (r != null) {
                typeView.setText(r.type);
                nameView.setText(r.name);
                addrView.setText(r.address);
                int color = "mDNS".equals(r.type)
                        ? ContextCompat.getColor(MdnsSsdpDiscovery.this, R.color.app_color)
                        : 0xFFF57C00;
                typeView.setTextColor(color);
            }
            return convertView;
        }
    }

    // --------------- fields ---------------
    private FloatingActionButton mFab;
    private android.widget.ProgressBar mProgress;
    private ListView mList;
    private final List<DeviceResult> mResults = new ArrayList<>();
    private DeviceAdapter mAdapter;
    private Future<?> mJob;
    private final AtomicBoolean mRunning = new AtomicBoolean(false);

    // --------------- constructor ---------------
    public MdnsSsdpDiscovery() {
        super(R.string.mdns_ssdp_discovery, R.string.mdns_ssdp_discovery_desc,
                new Target.Type[]{Target.Type.NETWORK},
                R.layout.plugin_mdns_ssdp, R.drawable.action_scanner);
    }

    // --------------- lifecycle ---------------
    @Override
    public void onCreate(Bundle savedInstanceState) {
        SharedPreferences prefs = getSharedPreferences("THEME", MODE_PRIVATE);
        int theme = prefs.getInt("theme", R.style.AppTheme);
        setTheme(theme);

        super.onCreate(savedInstanceState);

        mFab = findViewById(R.id.mdnsToggleButton);
        mProgress = findViewById(R.id.mdnsActivity);
        mList = findViewById(android.R.id.list);

        mAdapter = new DeviceAdapter(mResults);
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

        if (BuildConfig.DEBUG) {
            emitDebug();
            stopScan();
            return;
        }

        mJob = ThreadHelper.submit(() -> {
            try {
                scan();
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
        addResult(new DeviceResult("mDNS", "Apple TV._appletv-v2._tcp.local", "192.168.1.10", ""));
        addResult(new DeviceResult("SSDP", "urn:schemas-upnp-org:device:ZonePlayer:1", "192.168.1.11", "Sonos/56.0-direct"));
        addResult(new DeviceResult("SSDP", "urn:dial-multiscreen-org:service:dial:1", "192.168.1.12", "Chromecast/1.0"));
    }

    // --------------- core logic ---------------
    private void scan() {
        boolean hasResults = false;

        // SSDP
        try {
            hasResults |= scanSsdp();
        } catch (Exception ignored) {
        }

        if (!mRunning.get()) return;

        // mDNS
        try {
            hasResults |= scanMdns();
        } catch (Exception ignored) {
        }

        if (!hasResults) {
            addResult(new DeviceResult("INFO", "No devices found", "", "mDNS and SSDP returned no responses"));
        }
    }

    private boolean scanSsdp() throws Exception {
        String msearch = "M-SEARCH * HTTP/1.1\r\n"
                + "HOST: 239.255.255.250:1900\r\n"
                + "MAN: \"ssdp:discover\"\r\n"
                + "MX: 3\r\n"
                + "ST: ssdp:all\r\n\r\n";
        byte[] msearchBytes = msearch.getBytes("UTF-8");
        InetAddress ssdpAddr = InetAddress.getByName("239.255.255.250");

        DatagramSocket sock = new DatagramSocket();
        sock.setSoTimeout(4000);
        sock.send(new DatagramPacket(msearchBytes, msearchBytes.length, ssdpAddr, 1900));

        boolean found = false;
        int count = 0;
        while (mRunning.get() && count < 20) {
            try {
                byte[] buf = new byte[2048];
                DatagramPacket pkt = new DatagramPacket(buf, buf.length);
                sock.receive(pkt);
                String response = new String(pkt.getData(), 0, pkt.getLength(), "UTF-8");
                String srcIp = pkt.getAddress().getHostAddress();
                String location = extractHeader(response, "LOCATION:");
                String server = extractHeader(response, "SERVER:");
                String st = extractHeader(response, "ST:");
                if (st == null) st = extractHeader(response, "ST");
                if (st != null) {
                    addResult(new DeviceResult("SSDP", st.trim(), srcIp, server != null ? server.trim() : ""));
                    found = true;
                    count++;
                }
            } catch (java.net.SocketTimeoutException e) {
                break;
            }
        }
        sock.close();
        return found;
    }

    private boolean scanMdns() throws Exception {
        // Build DNS PTR query for _services._dns-sd._udp.local
        byte[] query = buildMdnsQuery("_services._dns-sd._udp.local");
        InetAddress mdnsAddr = InetAddress.getByName("224.0.0.251");

        MulticastSocket msock = new MulticastSocket(5353);
        msock.joinGroup(mdnsAddr);
        msock.setSoTimeout(4000);
        msock.send(new DatagramPacket(query, query.length, mdnsAddr, 5353));

        boolean found = false;
        long deadline = java.lang.System.currentTimeMillis() + 4000;
        while (mRunning.get() && java.lang.System.currentTimeMillis() < deadline) {
            try {
                byte[] buf = new byte[4096];
                DatagramPacket pkt = new DatagramPacket(buf, buf.length);
                msock.receive(pkt);
                String srcIp = pkt.getAddress().getHostAddress();
                List<String> names = extractPtrNames(pkt.getData(), pkt.getLength());
                for (String name : names) {
                    addResult(new DeviceResult("mDNS", name, srcIp, ""));
                    found = true;
                }
            } catch (java.net.SocketTimeoutException e) {
                break;
            }
        }
        try { msock.leaveGroup(mdnsAddr); } catch (Exception ignored) {}
        msock.close();
        return found;
    }

    private byte[] buildMdnsQuery(String name) {
        // Build minimal DNS question for PTR record
        java.io.ByteArrayOutputStream baos = new java.io.ByteArrayOutputStream();
        // ID=0, flags=0 (standard query), QDCOUNT=1
        baos.write(0x00); baos.write(0x00); // ID
        baos.write(0x00); baos.write(0x00); // flags
        baos.write(0x00); baos.write(0x01); // QDCOUNT=1
        baos.write(0x00); baos.write(0x00); // ANCOUNT=0
        baos.write(0x00); baos.write(0x00); // NSCOUNT=0
        baos.write(0x00); baos.write(0x00); // ARCOUNT=0
        // encode name labels
        for (String label : name.split("\\.")) {
            try {
                byte[] lb = label.getBytes("UTF-8");
                baos.write(lb.length);
                baos.write(lb, 0, lb.length);
            } catch (Exception ignored) {}
        }
        baos.write(0x00); // root label
        // QTYPE=PTR=12, QCLASS=IN=1|0x8000 (QU bit)
        baos.write(0x00); baos.write(0x0C);
        baos.write((byte)0x80); baos.write(0x01);
        return baos.toByteArray();
    }

    private List<String> extractPtrNames(byte[] data, int len) {
        List<String> names = new ArrayList<>();
        if (len < 12) return names;
        int ancount = ((data[6] & 0xFF) << 8) | (data[7] & 0xFF);
        int arcount = ((data[10] & 0xFF) << 8) | (data[11] & 0xFF);
        // Skip question section — simple heuristic: find answers starting at offset 12
        // Walk past questions
        int offset = 12;
        int qdcount = ((data[4] & 0xFF) << 8) | (data[5] & 0xFF);
        for (int q = 0; q < qdcount && offset < len; q++) {
            offset = skipName(data, len, offset);
            offset += 4; // type + class
        }
        for (int a = 0; a < ancount + arcount && offset < len; a++) {
            int nameEnd = skipName(data, len, offset);
            if (nameEnd + 10 > len) break;
            int type = ((data[nameEnd] & 0xFF) << 8) | (data[nameEnd + 1] & 0xFF);
            int rdlen = ((data[nameEnd + 8] & 0xFF) << 8) | (data[nameEnd + 9] & 0xFF);
            int rdataOffset = nameEnd + 10;
            if (type == 12) { // PTR
                String ptrName = readName(data, len, rdataOffset);
                if (ptrName != null && !ptrName.isEmpty()) {
                    names.add(ptrName);
                }
            }
            offset = rdataOffset + rdlen;
        }
        return names;
    }

    private int skipName(byte[] data, int len, int offset) {
        while (offset < len) {
            int b = data[offset] & 0xFF;
            if (b == 0) { return offset + 1; }
            if ((b & 0xC0) == 0xC0) { return offset + 2; }
            offset += b + 1;
        }
        return offset;
    }

    private String readName(byte[] data, int len, int offset) {
        StringBuilder sb = new StringBuilder();
        int jumps = 0;
        while (offset < len && jumps < 10) {
            int b = data[offset] & 0xFF;
            if (b == 0) break;
            if ((b & 0xC0) == 0xC0) {
                int ptr = ((b & 0x3F) << 8) | (data[offset + 1] & 0xFF);
                offset = ptr;
                jumps++;
                continue;
            }
            if (sb.length() > 0) sb.append('.');
            try {
                sb.append(new String(data, offset + 1, b, "UTF-8"));
            } catch (Exception ignored) {}
            offset += b + 1;
        }
        return sb.toString();
    }

    private String extractHeader(String response, String headerName) {
        String lower = response.toLowerCase();
        String lowerHeader = headerName.toLowerCase();
        int idx = lower.indexOf(lowerHeader);
        if (idx < 0) return null;
        int start = idx + headerName.length();
        if (start < response.length() && response.charAt(start) == ' ') start++;
        int end = response.indexOf('\r', start);
        if (end < 0) end = response.indexOf('\n', start);
        if (end < 0) end = response.length();
        return response.substring(start, end);
    }

    // --------------- helpers ---------------
    private void addResult(DeviceResult result) {
        runOnUiThread(() -> {
            mResults.add(result);
            mAdapter.notifyDataSetChanged();
        });
    }
}
