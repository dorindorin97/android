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

import java.net.DatagramPacket;
import java.net.DatagramSocket;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * SNMP Scanner — tries common community strings via SNMPv1/v2c GET-REQUEST
 * and reads system MIB objects (sysDescr, sysName, sysLocation, sysContact,
 * sysUpTime) to enumerate device information.
 *
 * No third-party library — builds raw BER-encoded SNMP PDUs.
 * Community strings tried: public, private, manager, admin, cisco,
 *   snmp, community, monitor, read, write, guest, default.
 */
public class SnmpScanner extends Plugin {
    private static final String TAG = "SnmpScanner";
    private static final int    SNMP_PORT   = 161;
    private static final int    TIMEOUT_MS  = 2000;

    private static final String[] COMMUNITIES = {
        "public", "private", "manager", "admin", "cisco",
        "snmp", "community", "monitor", "read", "write",
        "guest", "default", "secret", "password", "internal"
    };

    // OIDs for system group (1.3.6.1.2.1.1.x.0)
    private static final byte[][] SYS_OIDS = {
        new byte[]{0x2b,6,1,2,1,1,1,0}, // sysDescr
        new byte[]{0x2b,6,1,2,1,1,4,0}, // sysContact
        new byte[]{0x2b,6,1,2,1,1,5,0}, // sysName
        new byte[]{0x2b,6,1,2,1,1,6,0}, // sysLocation
        new byte[]{0x2b,6,1,2,1,1,3,0}, // sysUpTime
    };
    private static final String[] SYS_NAMES = {
        "sysDescr", "sysContact", "sysName", "sysLocation", "sysUpTime"
    };

    public static class SnmpResult {
        public enum Kind { COMMUNITY, VALUE, ERROR }
        public final Kind   kind;
        public final String label;
        public final String value;
        SnmpResult(Kind k, String l, String v) { kind = k; label = l; value = v; }
    }

    private FloatingActionButton mToggleButton;
    private ProgressBar mProgress;
    private ListView mListView;
    private ResultAdapter mAdapter;
    private final AtomicBoolean mRunning = new AtomicBoolean(false);
    private Future<?> mJob;

    public SnmpScanner() {
        super(
            R.string.snmp_scanner,
            R.string.snmp_scanner_desc,
            new Target.Type[]{Target.Type.ENDPOINT, Target.Type.REMOTE},
            R.layout.plugin_snmp_scanner,
            R.drawable.action_scanner
        );
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        SharedPreferences prefs = getSharedPreferences("THEME", 0);
        setTheme(prefs.getBoolean("isDark", false) ? R.style.DarkTheme : R.style.AppTheme);
        super.onCreate(savedInstanceState);

        mToggleButton = findViewById(R.id.snmpToggleButton);
        mProgress     = findViewById(R.id.snmpActivity);
        mListView     = findViewById(android.R.id.list);
        mAdapter      = new ResultAdapter();
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

    private void startScan() {
        Target target = System.getCurrentTarget();
        if (target == null) return;

        mRunning.set(true);
        mAdapter.clear();
        mProgress.setVisibility(View.VISIBLE);
        mProgress.setMax(COMMUNITIES.length);
        mProgress.setProgress(0);
        AnimationHelper.fadeIn(mProgress, 200);
        mToggleButton.setImageDrawable(ContextCompat.getDrawable(this, R.drawable.ic_stop_24dp));

        if (BuildConfig.DEBUG) {
            mJob = ThreadHelper.submit(() -> { emitDebug(); runOnUiThread(this::onFinished); });
            return;
        }

        final String ip = target.getAddress().getHostAddress();
        mJob = ThreadHelper.submit(() -> {
            scan(ip);
            runOnUiThread(this::onFinished);
        });
    }

    private void stopScan() {
        mRunning.set(false);
        if (mJob != null) { mJob.cancel(true); mJob = null; }
        onFinished();
    }

    private void onFinished() {
        mRunning.set(false);
        AnimationHelper.fadeOut(mProgress, 200, () -> mProgress.setVisibility(View.INVISIBLE));
        mToggleButton.setImageDrawable(ContextCompat.getDrawable(this, R.drawable.ic_play_arrow_24dp));
        if (mAdapter.getCount() == 0)
            report(new SnmpResult(SnmpResult.Kind.ERROR, "No response", "SNMP not accessible or all community strings rejected"));
    }

    // ── SNMP logic ────────────────────────────────────────────────────────────

    private void scan(String ip) {
        InetAddress addr;
        try { addr = InetAddress.getByName(ip); } catch (Exception e) { return; }

        for (int ci = 0; ci < COMMUNITIES.length; ci++) {
            if (!mRunning.get()) break;
            String community = COMMUNITIES[ci];
            final int prog = ci + 1;
            runOnUiThread(() -> mProgress.setProgress(prog));

            // Try sysDescr get as a probe
            byte[] resp = snmpGet(addr, community, SYS_OIDS[0]);
            if (resp == null) continue;

            String val = parseStringValue(resp);
            if (val == null) continue;

            report(new SnmpResult(SnmpResult.Kind.COMMUNITY, "Community found", "\"" + community + "\""));

            // Now read all system OIDs
            for (int i = 0; i < SYS_OIDS.length; i++) {
                if (!mRunning.get()) break;
                byte[] r = snmpGet(addr, community, SYS_OIDS[i]);
                if (r == null) continue;
                String v = parseValue(r, i == 4); // sysUpTime is timeticks
                if (v != null)
                    report(new SnmpResult(SnmpResult.Kind.VALUE, SYS_NAMES[i], v));
            }
            break; // got one community — stop trying more
        }
    }

    /** Build SNMPv1 GET-REQUEST PDU and send via UDP. Returns raw response or null. */
    private byte[] snmpGet(InetAddress addr, String community, byte[] oid) {
        try {
            byte[] pdu = buildGetRequest(community, oid);
            DatagramSocket sock = new DatagramSocket();
            sock.setSoTimeout(TIMEOUT_MS);
            sock.send(new DatagramPacket(pdu, pdu.length, addr, SNMP_PORT));

            byte[] buf = new byte[1500];
            DatagramPacket resp = new DatagramPacket(buf, buf.length);
            sock.receive(resp);
            sock.close();
            return Arrays.copyOf(buf, resp.getLength());
        } catch (Exception e) {
            return null;
        }
    }

    /** Minimal SNMPv1 GET-REQUEST BER encoding. */
    private byte[] buildGetRequest(String community, byte[] oid) {
        byte[] commBytes = community.getBytes(java.nio.charset.StandardCharsets.UTF_8);

        // VarBind: SEQUENCE { OID, NULL }
        byte[] oidTlv   = tlv(0x06, oid);
        byte[] nullTlv  = new byte[]{0x05, 0x00};
        byte[] varBind  = tlv(0x30, concat(oidTlv, nullTlv));
        byte[] varBindList = tlv(0x30, varBind);

        // PDU: GetRequest-PDU [0] { req-id, err, err-idx, varbinds }
        byte[] reqId    = tlv(0x02, new byte[]{0x01}); // integer 1
        byte[] errStatus= tlv(0x02, new byte[]{0x00});
        byte[] errIdx   = tlv(0x02, new byte[]{0x00});
        byte[] pdu      = tlv(0xA0, concat(reqId, errStatus, errIdx, varBindList));

        // Message: SEQUENCE { version, community, pdu }
        byte[] version  = tlv(0x02, new byte[]{0x00}); // SNMPv1=0
        byte[] commTlv  = tlv(0x04, commBytes);
        return tlv(0x30, concat(version, commTlv, pdu));
    }

    private byte[] tlv(int tag, byte[] value) {
        int len = value.length;
        byte[] result;
        if (len < 128) {
            result = new byte[2 + len];
            result[0] = (byte) tag;
            result[1] = (byte) len;
            java.lang.System.arraycopy(value, 0, result, 2, len);
        } else {
            result = new byte[3 + len];
            result[0] = (byte) tag;
            result[1] = (byte) 0x81;
            result[2] = (byte) len;
            java.lang.System.arraycopy(value, 0, result, 3, len);
        }
        return result;
    }

    private byte[] concat(byte[]... parts) {
        int total = 0;
        for (byte[] p : parts) total += p.length;
        byte[] out = new byte[total];
        int pos = 0;
        for (byte[] p : parts) {
            java.lang.System.arraycopy(p, 0, out, pos, p.length);
            pos += p.length;
        }
        return out;
    }

    /** Extract the string value from an SNMP GET-RESPONSE. */
    private String parseStringValue(byte[] data) {
        return parseValue(data, false);
    }

    private String parseValue(byte[] data, boolean isTicks) {
        try {
            // Walk BER to find the value in the VarBind
            // Response structure: SEQUENCE { version, community, GetResponse-PDU }
            // GetResponse-PDU [2]: { req-id, err, err-idx, SEQUENCE { SEQUENCE { OID, value } } }
            int pos = 0;
            pos = skipTlv(data, pos); // outer SEQUENCE — enter
            pos = 2; // skip tag+len of outer SEQUENCE
            if ((data[pos] & 0xFF) == 0x82) pos += 4; else pos += 2; // handle long form

            // find GetResponse-PDU (tag 0xA2)
            while (pos < data.length && (data[pos] & 0xFF) != 0xA2) pos++;
            if (pos >= data.length) return null;
            pos = enterTlv(data, pos); // enter PDU

            // skip req-id, err-status, err-index
            pos = skipTlv(data, pos);
            pos = skipTlv(data, pos);
            pos = skipTlv(data, pos);

            // VarBindList SEQUENCE
            pos = enterTlv(data, pos);
            // VarBind SEQUENCE
            pos = enterTlv(data, pos);
            // OID — skip it
            pos = skipTlv(data, pos);
            // Value
            int valTag = data[pos] & 0xFF;
            int valLen = tlvLen(data, pos + 1);
            int valOff = tlvOffset(data, pos + 1);

            if (valTag == 0x04 || valTag == 0x06) { // OCTET STRING or OID
                return new String(data, valOff, valLen, java.nio.charset.StandardCharsets.UTF_8).trim();
            } else if (valTag == 0x02 || valTag == 0x43) { // INTEGER or TimeTicks
                long ticks = 0;
                for (int i = 0; i < valLen; i++)
                    ticks = (ticks << 8) | (data[valOff + i] & 0xFF);
                if (isTicks) {
                    long secs = ticks / 100;
                    return String.format("%dd %02dh %02dm %02ds",
                        secs/86400, (secs%86400)/3600, (secs%3600)/60, secs%60);
                }
                return String.valueOf(ticks);
            }
            return null;
        } catch (Exception e) {
            return null;
        }
    }

    private int tlvLen(byte[] d, int pos) {
        int b = d[pos] & 0xFF;
        if (b < 128) return b;
        if (b == 0x81) return d[pos+1] & 0xFF;
        return ((d[pos+1]&0xFF)<<8)|(d[pos+2]&0xFF);
    }

    private int tlvOffset(byte[] d, int pos) {
        int b = d[pos] & 0xFF;
        if (b < 128) return pos + 1;
        if (b == 0x81) return pos + 2;
        return pos + 3;
    }

    private int skipTlv(byte[] d, int pos) {
        int len = tlvLen(d, pos + 1);
        return tlvOffset(d, pos + 1) + len;
    }

    private int enterTlv(byte[] d, int pos) {
        return tlvOffset(d, pos + 1);
    }

    private void emitDebug() {
        report(new SnmpResult(SnmpResult.Kind.COMMUNITY, "Community found", "\"public\""));
        report(new SnmpResult(SnmpResult.Kind.VALUE, "sysDescr",   "Linux router 5.15.0-91-generic #101-Ubuntu SMP Tue Nov 14 13:30:08 UTC 2023 x86_64"));
        report(new SnmpResult(SnmpResult.Kind.VALUE, "sysContact", "admin@example.com"));
        report(new SnmpResult(SnmpResult.Kind.VALUE, "sysName",    "debug-router.local"));
        report(new SnmpResult(SnmpResult.Kind.VALUE, "sysLocation","Server Room A, Rack 3"));
        report(new SnmpResult(SnmpResult.Kind.VALUE, "sysUpTime",  "12d 04h 33m 17s"));
    }

    private void report(SnmpResult r) {
        runOnUiThread(() -> { mAdapter.add(r); mAdapter.notifyDataSetChanged(); });
    }

    private class ResultAdapter extends ArrayAdapter<SnmpResult> {
        ResultAdapter() { super(SnmpScanner.this, R.layout.plugin_snmp_scanner_item, new ArrayList<>()); }

        @Override
        public View getView(int position, View convertView, ViewGroup parent) {
            if (convertView == null)
                convertView = LayoutInflater.from(getContext())
                    .inflate(R.layout.plugin_snmp_scanner_item, parent, false);
            SnmpResult r = getItem(position);
            TextView tvLabel = convertView.findViewById(R.id.snmpItemLabel);
            TextView tvValue = convertView.findViewById(R.id.snmpItemValue);
            tvLabel.setText(r.label);
            tvValue.setText(r.value);
            int color;
            switch (r.kind) {
                case COMMUNITY: color = Color.parseColor("#D32F2F"); break;
                case VALUE:     color = ContextCompat.getColor(getContext(), R.color.app_color); break;
                default:        color = Color.parseColor("#757575"); break;
            }
            tvLabel.setTextColor(color);
            return convertView;
        }
    }
}
