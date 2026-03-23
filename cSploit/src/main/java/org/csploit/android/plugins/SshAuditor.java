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

import java.io.DataInputStream;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * SSH Auditor — connects to SSH port(s), reads the server banner and parses
 * the SSH_MSG_KEXINIT packet (sent before authentication) to enumerate the
 * algorithms the server supports.
 *
 * Flags:
 *   - Weak KEX  : diffie-hellman-group1-sha1, diffie-hellman-group14-sha1
 *   - Weak cipher: 3des-cbc, arcfour, blowfish-cbc, cast128-cbc
 *   - Weak MAC  : hmac-md5, hmac-sha1-96, hmac-md5-96
 *   - Weak host key: ssh-dss, ssh-rsa (SHA-1 based)
 *   - Old banner: anything below OpenSSH 8.x
 */
public class SshAuditor extends Plugin {
    private static final String TAG = "SshAuditor";
    private static final int TIMEOUT_MS = 6000;

    private static final Set<String> WEAK_KEX = new HashSet<>(Arrays.asList(
        "diffie-hellman-group1-sha1",
        "diffie-hellman-group14-sha1",
        "diffie-hellman-group-exchange-sha1",
        "gss-gex-sha1-",
        "gss-group1-sha1-",
        "gss-group14-sha1-"
    ));
    private static final Set<String> WEAK_CIPHER = new HashSet<>(Arrays.asList(
        "3des-cbc", "arcfour", "arcfour128", "arcfour256",
        "blowfish-cbc", "cast128-cbc", "aes128-cbc", "aes192-cbc", "aes256-cbc"
    ));
    private static final Set<String> WEAK_MAC = new HashSet<>(Arrays.asList(
        "hmac-md5", "hmac-md5-96", "hmac-sha1-96", "hmac-ripemd160"
    ));
    private static final Set<String> WEAK_HOSTKEY = new HashSet<>(Arrays.asList(
        "ssh-dss", "ssh-rsa"
    ));

    public static class Finding {
        public enum Severity { INFO, WARN, VULN }
        public final Severity severity;
        public final String label;
        public final String detail;
        Finding(Severity s, String l, String d) { severity = s; label = l; detail = d; }
    }

    private FloatingActionButton mToggleButton;
    private ProgressBar mProgress;
    private ListView mListView;
    private FindingAdapter mAdapter;
    private final AtomicBoolean mRunning = new AtomicBoolean(false);
    private Future<?> mJob;

    public SshAuditor() {
        super(
            R.string.ssh_auditor,
            R.string.ssh_auditor_desc,
            new Target.Type[]{Target.Type.ENDPOINT, Target.Type.REMOTE},
            R.layout.plugin_ssh_auditor,
            R.drawable.action_scanner
        );
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        SharedPreferences prefs = getSharedPreferences("THEME", 0);
        setTheme(prefs.getBoolean("isDark", false) ? R.style.DarkTheme : R.style.AppTheme);
        super.onCreate(savedInstanceState);

        mToggleButton = findViewById(R.id.sshAuditToggleButton);
        mProgress     = findViewById(R.id.sshAuditActivity);
        mListView     = findViewById(android.R.id.list);
        mAdapter      = new FindingAdapter();
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
        AnimationHelper.fadeIn(mProgress, 200);
        mToggleButton.setImageDrawable(ContextCompat.getDrawable(this, R.drawable.ic_stop_24dp));

        if (BuildConfig.DEBUG) {
            mJob = ThreadHelper.submit(() -> { emitDebug(); runOnUiThread(this::onFinished); });
            return;
        }

        final String ip = target.getAddress().getHostAddress();
        final List<Integer> ports = getSshPorts(target);
        mJob = ThreadHelper.submit(() -> {
            if (ports.isEmpty()) ports.add(22);
            for (int port : ports) {
                if (!mRunning.get()) break;
                auditPort(ip, port);
            }
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
    }

    // ── SSH audit logic ───────────────────────────────────────────────────────

    private void auditPort(String ip, int port) {
        report(Finding.Severity.INFO, "Scanning", ip + ":" + port);
        try {
            Socket sock = new Socket();
            sock.connect(new InetSocketAddress(ip, port), TIMEOUT_MS);
            sock.setSoTimeout(TIMEOUT_MS);

            DataInputStream in  = new DataInputStream(sock.getInputStream());
            OutputStream    out = sock.getOutputStream();

            // 1. Read server banner
            StringBuilder bannerSb = new StringBuilder();
            int b;
            while ((b = in.read()) != -1) {
                char c = (char) b;
                if (c == '\n') break;
                if (c != '\r') bannerSb.append(c);
                if (bannerSb.length() > 255) break;
            }
            String banner = bannerSb.toString().trim();
            report(Finding.Severity.INFO, "Banner", banner);
            checkBanner(banner, port);

            // 2. Send our client banner to trigger KEXINIT
            out.write("SSH-2.0-cSploit_auditor\r\n".getBytes(StandardCharsets.UTF_8));
            out.flush();

            // 3. Read SSH_MSG_KEXINIT (packet type 20)
            // SSH packet: uint32 length, byte padding_length, byte[*] payload
            int pktLen     = in.readInt();
            int padLen     = in.readUnsignedByte();
            int payloadLen = pktLen - padLen - 1;
            byte[] payload = new byte[payloadLen];
            in.readFully(payload);

            if (payload[0] != 20) { // SSH_MSG_KEXINIT = 20
                report(Finding.Severity.INFO, "Note", "Unexpected first packet type: " + (payload[0] & 0xFF));
                sock.close();
                return;
            }

            // Skip: msg type (1) + cookie (16) = offset 17
            int offset = 17;
            String[] names = {
                "KEX algorithms", "Host key algorithms",
                "Enc c→s", "Enc s→c",
                "MAC c→s", "MAC s→c",
                "Compression c→s", "Compression s→c"
            };
            for (int i = 0; i < 8 && offset + 4 <= payloadLen; i++) {
                int len = ((payload[offset]&0xFF)<<24)|((payload[offset+1]&0xFF)<<16)|
                          ((payload[offset+2]&0xFF)<<8)|(payload[offset+3]&0xFF);
                offset += 4;
                if (offset + len > payloadLen) break;
                String algList = new String(payload, offset, len, StandardCharsets.UTF_8);
                offset += len;
                report(Finding.Severity.INFO, names[i], algList);
                checkAlgorithms(names[i], algList, port);
            }

            sock.close();
        } catch (Exception e) {
            String msg = e.getMessage();
            if (msg != null && msg.contains("Connection refused"))
                report(Finding.Severity.INFO, "Port " + port, "Not open");
            else
                report(Finding.Severity.WARN, "Error :" + port, msg != null ? msg : e.getClass().getSimpleName());
        }
    }

    private void checkBanner(String banner, int port) {
        String lower = banner.toLowerCase();
        if (lower.contains("openssh")) {
            // Extract version: "SSH-2.0-OpenSSH_8.9p1" → "8.9"
            try {
                String ver = banner.replaceAll(".*OpenSSH_([0-9]+\\.[0-9]+).*", "$1");
                double v = Double.parseDouble(ver);
                if (v < 7.4)
                    report(Finding.Severity.VULN, "Old OpenSSH", banner + " — many CVEs known [:"+port+"]");
                else if (v < 8.0)
                    report(Finding.Severity.WARN, "Outdated OpenSSH", banner + " — upgrade to 9.x [:"+port+"]");
            } catch (Exception ignored) {}
        }
        if (lower.contains("1.99") || lower.contains("ssh-1"))
            report(Finding.Severity.VULN, "SSH v1 supported", "SSHv1 is broken [:"+port+"]");
    }

    private void checkAlgorithms(String category, String algList, int port) {
        String[] algs = algList.split(",");
        for (String alg : algs) {
            alg = alg.trim();
            boolean isWeak = false;
            if (category.startsWith("KEX") && isWeak(alg, WEAK_KEX)) isWeak = true;
            else if (category.startsWith("Enc") && isWeak(alg, WEAK_CIPHER)) isWeak = true;
            else if (category.startsWith("MAC") && isWeak(alg, WEAK_MAC)) isWeak = true;
            else if (category.startsWith("Host") && isWeak(alg, WEAK_HOSTKEY)) isWeak = true;
            if (isWeak)
                report(Finding.Severity.WARN, "Weak: " + alg, category + " [:"+port+"]");
        }
    }

    private boolean isWeak(String alg, Set<String> set) {
        for (String w : set) if (alg.startsWith(w)) return true;
        return false;
    }

    private List<Integer> getSshPorts(Target t) {
        List<Integer> r = new ArrayList<>();
        for (Target.Port p : t.getOpenPorts()) {
            String svc = p.getService() == null ? "" : p.getService().toLowerCase();
            if (svc.contains("ssh") || p.getNumber() == 22 || p.getNumber() == 2222)
                r.add(p.getNumber());
        }
        return r;
    }

    private void emitDebug() {
        report(Finding.Severity.INFO, "Scanning",          "192.168.1.105:22");
        report(Finding.Severity.INFO, "Banner",             "SSH-2.0-OpenSSH_7.4p1 Ubuntu-10+deb9u7");
        report(Finding.Severity.WARN, "Outdated OpenSSH",  "SSH-2.0-OpenSSH_7.4p1 — upgrade to 9.x [:22]");
        report(Finding.Severity.INFO, "KEX algorithms",    "curve25519-sha256,diffie-hellman-group14-sha1,diffie-hellman-group1-sha1");
        report(Finding.Severity.WARN, "Weak: diffie-hellman-group14-sha1", "KEX algorithms [:22]");
        report(Finding.Severity.WARN, "Weak: diffie-hellman-group1-sha1",  "KEX algorithms [:22]");
        report(Finding.Severity.INFO, "Host key algorithms","ssh-rsa,ecdsa-sha2-nistp256,ssh-ed25519");
        report(Finding.Severity.WARN, "Weak: ssh-rsa",     "Host key algorithms [:22]");
        report(Finding.Severity.INFO, "Enc c→s",           "aes128-ctr,aes256-ctr,aes128-cbc,3des-cbc");
        report(Finding.Severity.WARN, "Weak: 3des-cbc",    "Enc c→s [:22]");
        report(Finding.Severity.INFO, "MAC c→s",           "hmac-sha2-256,hmac-sha1,hmac-md5");
        report(Finding.Severity.WARN, "Weak: hmac-md5",    "MAC c→s [:22]");
    }

    private void report(Finding.Severity s, String l, String d) {
        runOnUiThread(() -> { mAdapter.add(new Finding(s, l, d)); mAdapter.notifyDataSetChanged(); });
    }

    private class FindingAdapter extends ArrayAdapter<Finding> {
        FindingAdapter() { super(SshAuditor.this, R.layout.plugin_ssh_auditor_item, new ArrayList<>()); }

        @Override
        public View getView(int position, View convertView, ViewGroup parent) {
            if (convertView == null)
                convertView = LayoutInflater.from(getContext())
                    .inflate(R.layout.plugin_ssh_auditor_item, parent, false);
            Finding f = getItem(position);
            TextView label  = convertView.findViewById(R.id.sshItemLabel);
            TextView detail = convertView.findViewById(R.id.sshItemDetail);
            label.setText(f.label);
            detail.setText(f.detail);
            int color;
            switch (f.severity) {
                case VULN: color = Color.parseColor("#D32F2F"); break;
                case WARN: color = Color.parseColor("#F57C00"); break;
                default:   color = ContextCompat.getColor(getContext(), R.color.app_color); break;
            }
            label.setTextColor(color);
            return convertView;
        }
    }
}
