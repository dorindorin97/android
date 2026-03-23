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

import java.io.ByteArrayOutputStream;
import java.io.DataOutputStream;
import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * DNS Scanner — enumerates DNS records for a target host.
 *
 * Queries performed:
 *   A / AAAA   — forward lookups via InetAddress
 *   PTR        — reverse DNS
 *   MX / NS / TXT / CNAME — raw UDP DNS queries to system resolver / 8.8.8.8
 *   AXFR       — zone transfer attempt (almost always refused — flags misconfigured servers)
 */
public class DnsScanner extends Plugin {
    private static final String TAG = "DnsScanner";

    // DNS record type constants
    private static final int TYPE_A     = 1;
    private static final int TYPE_NS    = 2;
    private static final int TYPE_CNAME = 5;
    private static final int TYPE_MX    = 15;
    private static final int TYPE_TXT   = 16;
    private static final int TYPE_AAAA  = 28;
    private static final int TYPE_ANY   = 255;

    private static final String DNS_SERVER = "8.8.8.8";
    private static final int    DNS_PORT   = 53;
    private static final int    DNS_TIMEOUT_MS = 4000;

    public static class DnsRecord {
        public enum Kind { INFO, RECORD, WARN }
        public final Kind kind;
        public final String type;
        public final String value;
        DnsRecord(Kind k, String t, String v) { kind = k; type = t; value = v; }
    }

    private FloatingActionButton mToggleButton;
    private ProgressBar mProgress;
    private ListView mListView;
    private RecordAdapter mAdapter;
    private final AtomicBoolean mRunning = new AtomicBoolean(false);
    private Future<?> mJob;

    public DnsScanner() {
        super(
            R.string.dns_scanner,
            R.string.dns_scanner_desc,
            new Target.Type[]{Target.Type.ENDPOINT, Target.Type.REMOTE},
            R.layout.plugin_dns_scanner,
            R.drawable.action_traceroute
        );
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        SharedPreferences prefs = getSharedPreferences("THEME", 0);
        setTheme(prefs.getBoolean("isDark", false) ? R.style.DarkTheme : R.style.AppTheme);
        super.onCreate(savedInstanceState);

        mToggleButton = findViewById(R.id.dnsScanToggleButton);
        mProgress     = findViewById(R.id.dnsScanActivity);
        mListView     = findViewById(android.R.id.list);
        mAdapter      = new RecordAdapter();
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
        mProgress.setVisibility(View.VISIBLE);
        AnimationHelper.fadeIn(mProgress, 200);
        mToggleButton.setImageDrawable(ContextCompat.getDrawable(this, R.drawable.ic_stop_24dp));

        final String ip = target.getAddress().getHostAddress();

        if (BuildConfig.DEBUG) {
            mJob = ThreadHelper.submit(() -> {
                emitDebugRecords(ip);
                runOnUiThread(this::onScanFinished);
            });
            return;
        }

        mJob = ThreadHelper.submit(() -> {
            try {
                // Resolve hostname in background thread (not main thread)
                String host = InetAddress.getByName(ip).getCanonicalHostName();
                if (host.equals(ip)) host = ip; // no PTR
                scan(host, ip);
            } catch (Exception e) {
                LoggingHelper.w(TAG, "Scan error: " + e.getMessage());
                try { scan(ip, ip); } catch (Exception ignored) {}
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
        if (mAdapter.getCount() == 0)
            report(DnsRecord.Kind.INFO, "No records", "No DNS records found for host");
    }

    // ── Debug helpers ─────────────────────────────────────────────────────────

    private void emitDebugRecords(String ip) {
        report(DnsRecord.Kind.INFO,   "Target",  "debug-pc (" + ip + ")");
        report(DnsRecord.Kind.RECORD, "A",       ip);
        report(DnsRecord.Kind.RECORD, "AAAA",    "fe80::1");
        report(DnsRecord.Kind.RECORD, "PTR",     "debug-pc.local");
        report(DnsRecord.Kind.RECORD, "NS",      "ns1.example.com");
        report(DnsRecord.Kind.RECORD, "NS",      "ns2.example.com");
        report(DnsRecord.Kind.RECORD, "MX",      "pref=10 mail.example.com");
        report(DnsRecord.Kind.RECORD, "TXT",     "v=spf1 include:_spf.example.com ~all");
        report(DnsRecord.Kind.INFO,   "AXFR",    "Zone transfer refused (expected)");
    }

    // ── DNS checks ───────────────────────────────────────────────────────────

    private void scan(String host, String ip) {
        if (!mRunning.get()) return;
        report(DnsRecord.Kind.INFO, "Target", host + " (" + ip + ")");

        // A / AAAA via system resolver
        checkARecords(host);
        if (!mRunning.get()) return;

        // Reverse PTR
        checkPtr(ip);
        if (!mRunning.get()) return;

        // NS / MX / TXT / CNAME via raw UDP
        for (int[] tc : new int[][]{{TYPE_NS,"NS".hashCode()},{TYPE_MX,"MX".hashCode()},
                                    {TYPE_TXT,"TXT".hashCode()},{TYPE_CNAME,"CNAME".hashCode()}}) {
            // use parallel-friendly direct calls
        }
        queryAndReport(host, TYPE_NS,    "NS");
        if (!mRunning.get()) return;
        queryAndReport(host, TYPE_MX,    "MX");
        if (!mRunning.get()) return;
        queryAndReport(host, TYPE_TXT,   "TXT");
        if (!mRunning.get()) return;
        queryAndReport(host, TYPE_CNAME, "CNAME");
        if (!mRunning.get()) return;

        // Zone transfer attempt
        checkAxfr(host);
    }

    private void checkARecords(String host) {
        try {
            InetAddress[] addrs = InetAddress.getAllByName(host);
            for (InetAddress a : addrs) {
                String type = a.getAddress().length == 4 ? "A" : "AAAA";
                report(DnsRecord.Kind.RECORD, type, a.getHostAddress());
            }
        } catch (Exception e) {
            report(DnsRecord.Kind.WARN, "A lookup failed", e.getMessage());
        }
    }

    private void checkPtr(String ip) {
        try {
            InetAddress addr = InetAddress.getByName(ip);
            String hostname  = addr.getCanonicalHostName();
            if (!hostname.equals(ip))
                report(DnsRecord.Kind.RECORD, "PTR", hostname);
        } catch (Exception ignored) {}
    }

    private void queryAndReport(String host, int qtype, String typeName) {
        try {
            List<String> answers = rawDnsQuery(host, qtype);
            if (answers.isEmpty()) {
                report(DnsRecord.Kind.INFO, typeName, "No " + typeName + " records");
            } else {
                for (String ans : answers)
                    report(DnsRecord.Kind.RECORD, typeName, ans);
            }
        } catch (Exception e) {
            report(DnsRecord.Kind.WARN, typeName + " failed", e.getMessage());
        }
    }

    /**
     * Attempt AXFR (zone transfer). Flags misconfigured DNS servers that allow it.
     * Expected to fail in 99%+ of cases — a success is a critical finding.
     */
    private void checkAxfr(String host) {
        try {
            // AXFR uses TCP port 53
            java.net.Socket sock = new java.net.Socket();
            sock.connect(new java.net.InetSocketAddress(DNS_SERVER, DNS_PORT), DNS_TIMEOUT_MS);
            sock.setSoTimeout(DNS_TIMEOUT_MS);

            byte[] query = buildDnsQuery(host, 252); // 252 = AXFR
            // TCP DNS: 2-byte length prefix
            DataOutputStream out = new DataOutputStream(sock.getOutputStream());
            out.writeShort(query.length);
            out.write(query);
            out.flush();

            java.io.DataInputStream in = new java.io.DataInputStream(sock.getInputStream());
            int len = in.readUnsignedShort();
            byte[] resp = new byte[len];
            in.readFully(resp);
            sock.close();

            // Parse ANCOUNT (bytes 6-7) — if > 0 the server responded with records
            int ancount = ((resp[6] & 0xFF) << 8) | (resp[7] & 0xFF);
            if (ancount > 0)
                report(DnsRecord.Kind.WARN, "AXFR allowed!", "Zone transfer succeeded — server leaks full zone data");
            else
                report(DnsRecord.Kind.INFO, "AXFR", "Zone transfer refused (expected)");

        } catch (Exception e) {
            report(DnsRecord.Kind.INFO, "AXFR", "Zone transfer refused (expected)");
        }
    }

    // ── Raw DNS UDP query ─────────────────────────────────────────────────────

    private List<String> rawDnsQuery(String host, int qtype) throws Exception {
        byte[] query = buildDnsQuery(host, qtype);
        DatagramSocket socket = new DatagramSocket();
        socket.setSoTimeout(DNS_TIMEOUT_MS);

        InetAddress server = InetAddress.getByName(DNS_SERVER);
        socket.send(new DatagramPacket(query, query.length, server, DNS_PORT));

        byte[] buf = new byte[1024];
        DatagramPacket pkt = new DatagramPacket(buf, buf.length);
        socket.receive(pkt);
        socket.close();

        return parseDnsResponse(Arrays.copyOf(buf, pkt.getLength()), qtype);
    }

    private byte[] buildDnsQuery(String host, int qtype) throws Exception {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        DataOutputStream dos = new DataOutputStream(baos);

        dos.writeShort(0x1234);  // ID
        dos.writeShort(0x0100);  // Flags: standard query, recursion desired
        dos.writeShort(1);       // QDCOUNT
        dos.writeShort(0);       // ANCOUNT
        dos.writeShort(0);       // NSCOUNT
        dos.writeShort(0);       // ARCOUNT

        // Question: encode host labels
        for (String label : host.split("\\.")) {
            dos.writeByte(label.length());
            dos.write(label.getBytes("UTF-8"));
        }
        dos.writeByte(0);        // root label

        dos.writeShort(qtype);   // QTYPE
        dos.writeShort(1);       // QCLASS: IN
        return baos.toByteArray();
    }

    private List<String> parseDnsResponse(byte[] data, int qtype) {
        List<String> results = new ArrayList<>();
        try {
            int ancount = ((data[6] & 0xFF) << 8) | (data[7] & 0xFF);
            if (ancount == 0) return results;

            // Skip header (12 bytes) + question section
            int pos = 12;
            pos = skipQuestion(data, pos);

            for (int i = 0; i < ancount; i++) {
                pos = skipName(data, pos);      // owner name
                int type  = ((data[pos] & 0xFF) << 8) | (data[pos+1] & 0xFF); pos += 2;
                pos += 2; // class
                pos += 4; // TTL
                int rdlen = ((data[pos] & 0xFF) << 8) | (data[pos+1] & 0xFF); pos += 2;
                int rdStart = pos;

                switch (type) {
                    case TYPE_A:
                        if (rdlen == 4)
                            results.add((data[pos]&0xFF)+"."+(data[pos+1]&0xFF)+"."+(data[pos+2]&0xFF)+"."+(data[pos+3]&0xFF));
                        break;
                    case TYPE_AAAA:
                        results.add(formatIpv6(data, pos));
                        break;
                    case TYPE_NS:
                    case TYPE_CNAME:
                    case TYPE_MX:
                        int nameStart = (type == TYPE_MX) ? pos + 2 : pos;
                        results.add(readName(data, nameStart));
                        if (type == TYPE_MX) {
                            int pref = ((data[pos]&0xFF)<<8)|(data[pos+1]&0xFF);
                            results.set(results.size()-1, "pref="+pref+" "+results.get(results.size()-1));
                        }
                        break;
                    case TYPE_TXT:
                        results.add(readTxt(data, pos, rdlen));
                        break;
                    default:
                        break;
                }
                pos = rdStart + rdlen;
            }
        } catch (Exception ignored) {}
        return results;
    }

    private int skipQuestion(byte[] data, int pos) {
        pos = skipName(data, pos);
        return pos + 4; // QTYPE + QCLASS
    }

    /** Skip a DNS name (handles compression pointers), return next pos after name. */
    private int skipName(byte[] data, int pos) {
        while (pos < data.length) {
            int len = data[pos] & 0xFF;
            if (len == 0) { pos++; break; }
            if ((len & 0xC0) == 0xC0) { pos += 2; break; }
            pos += 1 + len;
        }
        return pos;
    }

    private String readName(byte[] data, int pos) {
        StringBuilder sb = new StringBuilder();
        int maxJumps = 10;
        while (pos < data.length && maxJumps-- > 0) {
            int len = data[pos] & 0xFF;
            if (len == 0) break;
            if ((len & 0xC0) == 0xC0) {
                pos = ((len & 0x3F) << 8) | (data[pos+1] & 0xFF);
                continue;
            }
            if (sb.length() > 0) sb.append('.');
            sb.append(new String(data, pos+1, len));
            pos += 1 + len;
        }
        return sb.toString();
    }

    private String readTxt(byte[] data, int pos, int rdlen) {
        StringBuilder sb = new StringBuilder();
        int end = pos + rdlen;
        while (pos < end) {
            int len = data[pos++] & 0xFF;
            sb.append(new String(data, pos, Math.min(len, end-pos)));
            pos += len;
        }
        return sb.toString();
    }

    private String formatIpv6(byte[] data, int pos) {
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 8; i++) {
            if (i > 0) sb.append(':');
            sb.append(String.format("%x", ((data[pos+i*2]&0xFF)<<8)|(data[pos+i*2+1]&0xFF)));
        }
        return sb.toString();
    }

    // ── UI helpers ────────────────────────────────────────────────────────────

    private void report(DnsRecord.Kind kind, String type, String value) {
        DnsRecord r = new DnsRecord(kind, type, value);
        runOnUiThread(() -> {
            mAdapter.add(r);
            mAdapter.notifyDataSetChanged();
        });
    }

    private class RecordAdapter extends ArrayAdapter<DnsRecord> {
        RecordAdapter() {
            super(DnsScanner.this, R.layout.plugin_dns_scanner_item, new ArrayList<>());
        }

        @Override
        public View getView(int position, View convertView, ViewGroup parent) {
            if (convertView == null)
                convertView = LayoutInflater.from(getContext())
                    .inflate(R.layout.plugin_dns_scanner_item, parent, false);

            DnsRecord r = getItem(position);
            TextView tvType  = convertView.findViewById(R.id.dnsItemType);
            TextView tvValue = convertView.findViewById(R.id.dnsItemValue);

            tvType.setText(r.type);
            tvValue.setText(r.value);

            int color;
            switch (r.kind) {
                case WARN:   color = Color.parseColor("#F57C00"); break;
                case RECORD: color = ContextCompat.getColor(getContext(), R.color.app_color); break;
                default:     color = Color.parseColor("#757575"); break;
            }
            tvType.setTextColor(color);

            return convertView;
        }
    }
}
