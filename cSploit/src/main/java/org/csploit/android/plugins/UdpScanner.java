package org.csploit.android.plugins;

import android.content.SharedPreferences;
import android.os.Bundle;
import android.view.View;
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
import org.csploit.android.helpers.ThreadHelper;
import org.csploit.android.net.Target;

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;

public class UdpScanner extends Plugin {

    // --------------- result model ---------------
    public static class UdpResult {
        public int port;
        public String service;
        public String status;

        public UdpResult(int port, String service, String status) {
            this.port = port;
            this.service = service;
            this.status = status;
        }
    }

    // --------------- port definitions ---------------
    private static final Map<Integer, String> UDP_PORTS = new LinkedHashMap<>();
    static {
        UDP_PORTS.put(53,   "DNS");
        UDP_PORTS.put(67,   "DHCP");
        UDP_PORTS.put(69,   "TFTP");
        UDP_PORTS.put(111,  "RPC");
        UDP_PORTS.put(123,  "NTP");
        UDP_PORTS.put(137,  "NetBIOS-NS");
        UDP_PORTS.put(138,  "NetBIOS-DGM");
        UDP_PORTS.put(161,  "SNMP");
        UDP_PORTS.put(162,  "SNMP-Trap");
        UDP_PORTS.put(389,  "LDAP");
        UDP_PORTS.put(500,  "IKE");
        UDP_PORTS.put(514,  "Syslog");
        UDP_PORTS.put(520,  "RIP");
        UDP_PORTS.put(623,  "IPMI");
        UDP_PORTS.put(1194, "OpenVPN");
        UDP_PORTS.put(1900, "SSDP");
        UDP_PORTS.put(4500, "IKE-NAT");
        UDP_PORTS.put(5353, "mDNS");
        UDP_PORTS.put(5355, "LLMNR");
        UDP_PORTS.put(6881, "BitTorrent-DHT");
    }

    // --------------- adapter ---------------
    private class UdpAdapter extends ArrayAdapter<UdpResult> {
        UdpAdapter(List<UdpResult> items) {
            super(UdpScanner.this, R.layout.plugin_udp_scanner_item, items);
        }

        @Override
        public View getView(int position, View convertView, android.view.ViewGroup parent) {
            if (convertView == null) {
                convertView = getLayoutInflater().inflate(R.layout.plugin_udp_scanner_item, parent, false);
            }
            UdpResult r = getItem(position);
            TextView portView    = convertView.findViewById(R.id.udpItemPort);
            TextView serviceView = convertView.findViewById(R.id.udpItemService);
            TextView statusView  = convertView.findViewById(R.id.udpItemStatus);
            if (r != null) {
                portView.setText(String.valueOf(r.port));
                serviceView.setText(r.service);
                statusView.setText(r.status);
                int color = r.status.startsWith("open") || r.status.equals("open|filtered")
                        ? ContextCompat.getColor(UdpScanner.this, R.color.app_color)
                        : 0xFF888888;
                portView.setTextColor(color);
                serviceView.setTextColor(color);
            }
            return convertView;
        }
    }

    // --------------- fields ---------------
    private FloatingActionButton mFab;
    private ProgressBar mProgress;
    private ListView mList;
    private final List<UdpResult> mResults = new ArrayList<>();
    private UdpAdapter mAdapter;
    private Future<?> mJob;
    private final AtomicBoolean mRunning = new AtomicBoolean(false);

    // --------------- constructor ---------------
    public UdpScanner() {
        super(R.string.udp_scanner, R.string.udp_scanner_desc,
                new Target.Type[]{Target.Type.ENDPOINT, Target.Type.REMOTE},
                R.layout.plugin_udp_scanner, R.drawable.action_scanner);
    }

    // --------------- lifecycle ---------------
    @Override
    public void onCreate(Bundle savedInstanceState) {
        SharedPreferences prefs = getSharedPreferences("THEME", MODE_PRIVATE);
        int theme = prefs.getInt("theme", R.style.AppTheme);
        setTheme(theme);

        super.onCreate(savedInstanceState);

        mFab = findViewById(R.id.udpToggleButton);
        mProgress = findViewById(R.id.udpActivity);
        mList = findViewById(android.R.id.list);

        mProgress.setMax(UDP_PORTS.size());
        mProgress.setProgress(0);

        mAdapter = new UdpAdapter(mResults);
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
        mProgress.setProgress(0);
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
        addResult(new UdpResult(53,   "DNS",  "open"));
        addResult(new UdpResult(123,  "NTP",  "open|filtered"));
        addResult(new UdpResult(161,  "SNMP", "open"));
        addResult(new UdpResult(1900, "SSDP", "open|filtered"));
    }

    // --------------- core logic ---------------
    private void scan(String ip) throws Exception {
        InetAddress addr = InetAddress.getByName(ip);
        int done = 0;

        for (Map.Entry<Integer, String> entry : UDP_PORTS.entrySet()) {
            if (!mRunning.get()) break;
            int port = entry.getKey();
            String service = entry.getValue();

            String status = probeUdpPort(addr, port, service);
            done++;
            final int finalDone = done;
            runOnUiThread(() -> mProgress.setProgress(finalDone));

            if (!"closed".equals(status)) {
                addResult(new UdpResult(port, service, status));
            }
        }
    }

    private String probeUdpPort(InetAddress addr, int port, String service) {
        try {
            DatagramSocket sock = new DatagramSocket();
            sock.setSoTimeout(1000);

            byte[] probe = buildProbe(port, service);
            sock.send(new DatagramPacket(probe, probe.length, addr, port));

            byte[] buf = new byte[512];
            DatagramPacket resp = new DatagramPacket(buf, buf.length);
            sock.receive(resp);
            sock.close();
            return "open";
        } catch (java.net.SocketException e) {
            String msg = e.getMessage();
            if (msg != null && (msg.contains("ICMP Port Unreachable") || msg.contains("port unreachable"))) {
                return "closed";
            }
            return "open|filtered";
        } catch (java.net.SocketTimeoutException e) {
            return "open|filtered";
        } catch (Exception e) {
            return "open|filtered";
        }
    }

    private byte[] buildProbe(int port, String service) {
        switch (port) {
            case 53: // DNS version.bind query
                return new byte[]{
                    0x00, 0x01, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x07, 0x76, 0x65, 0x72,
                    0x73, 0x69, 0x6F, 0x6E, 0x04, 0x62, 0x69, 0x6E,
                    0x64, 0x00, 0x00, 0x10, 0x00, 0x03
                };
            case 123: // NTP version request
                return new byte[]{
                    (byte)0xE3, 0x00, 0x06, (byte)0xEC,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00
                };
            case 161: // SNMP get-request for sysDescr with public community
                return new byte[]{
                    0x30, 0x26, 0x02, 0x01, 0x00, 0x04, 0x06, 0x70,
                    0x75, 0x62, 0x6C, 0x69, 0x63, (byte)0xA0, 0x19,
                    0x02, 0x01, 0x01, 0x02, 0x01, 0x00, 0x02, 0x01,
                    0x00, 0x30, 0x0E, 0x30, 0x0C, 0x06, 0x08, 0x2B,
                    0x06, 0x01, 0x02, 0x01, 0x01, 0x01, 0x00, 0x05, 0x00
                };
            case 137: // NetBIOS name query
                return new byte[]{
                    0x12, 0x34, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x20, 0x43, 0x4B, 0x41,
                    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                    0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41,
                    0x41, 0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x21,
                    0x00, 0x01
                };
            case 1900: // SSDP M-SEARCH
                try {
                    return ("M-SEARCH * HTTP/1.1\r\n" +
                            "HOST: 239.255.255.250:1900\r\n" +
                            "MAN: \"ssdp:discover\"\r\n" +
                            "MX: 1\r\nST: ssdp:all\r\n\r\n").getBytes("UTF-8");
                } catch (Exception e) { break; }
            case 5353: // mDNS query
                return new byte[]{
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00,
                    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01
                };
            default:
                break;
        }
        // Default: zero-byte probe
        return new byte[0];
    }

    // --------------- helpers ---------------
    private void addResult(UdpResult result) {
        runOnUiThread(() -> {
            mResults.add(result);
            mAdapter.notifyDataSetChanged();
        });
    }
}
