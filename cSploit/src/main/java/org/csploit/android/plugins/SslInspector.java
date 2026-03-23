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

import org.csploit.android.R;
import org.csploit.android.core.Plugin;
import org.csploit.android.core.System;
import org.csploit.android.helpers.AnimationHelper;
import org.csploit.android.helpers.LoggingHelper;
import org.csploit.android.helpers.ThreadHelper;
import org.csploit.android.net.Target;

import org.csploit.android.BuildConfig;

import java.net.InetSocketAddress;
import java.security.cert.X509Certificate;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Date;
import java.util.List;
import java.util.Locale;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

/**
 * SSL/TLS Inspector — analyses the TLS stack of a target HTTPS service.
 *
 * Checks performed:
 *   - Certificate subject, issuer, SANs, validity dates
 *   - Self-signed detection
 *   - Expired / expiring-soon warning (< 30 days)
 *   - Weak key size (RSA < 2048, EC < 224)
 *   - Negotiated cipher suite and protocol version
 *   - SSLv3 / TLSv1.0 / TLSv1.1 support (legacy protocol warning)
 *   - All open HTTPS ports are inspected
 */
public class SslInspector extends Plugin {
    private static final String TAG = "SslInspector";
    private static final int CONNECT_TIMEOUT_MS = 6000;
    private static final SimpleDateFormat DATE_FMT =
        new SimpleDateFormat("yyyy-MM-dd", Locale.US);

    public static class SslFinding {
        public enum Severity { INFO, WARN, VULN }
        public final Severity severity;
        public final String label;
        public final String detail;
        SslFinding(Severity s, String l, String d) { severity = s; label = l; detail = d; }
    }

    private FloatingActionButton mToggleButton;
    private ProgressBar mProgress;
    private ListView mListView;
    private FindingAdapter mAdapter;
    private final AtomicBoolean mRunning = new AtomicBoolean(false);
    private Future<?> mJob;

    public SslInspector() {
        super(
            R.string.ssl_inspector,
            R.string.ssl_inspector_desc,
            new Target.Type[]{Target.Type.ENDPOINT, Target.Type.REMOTE},
            R.layout.plugin_ssl_inspector,
            R.drawable.action_exploit_finder
        );
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        SharedPreferences prefs = getSharedPreferences("THEME", 0);
        setTheme(prefs.getBoolean("isDark", false) ? R.style.DarkTheme : R.style.AppTheme);
        super.onCreate(savedInstanceState);

        mToggleButton = findViewById(R.id.sslToggleButton);
        mProgress     = findViewById(R.id.sslActivity);
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

    // ── Scan control ─────────────────────────────────────────────────────────

    private void startScan() {
        Target target = System.getCurrentTarget();
        if (target == null) return;

        List<Integer> sslPorts = getSslPorts(target);
        if (sslPorts.isEmpty()) {
            report(SslFinding.Severity.INFO, "No TLS ports", "No HTTPS/TLS ports found (443, 8443, etc.)");
            return;
        }

        mRunning.set(true);
        mAdapter.clear();
        mProgress.setVisibility(View.VISIBLE);
        AnimationHelper.fadeIn(mProgress, 200);
        mToggleButton.setImageDrawable(ContextCompat.getDrawable(this, R.drawable.ic_stop_24dp));

        if (BuildConfig.DEBUG) {
            mJob = ThreadHelper.submit(() -> {
                emitDebugFindings();
                runOnUiThread(this::onScanFinished);
            });
            return;
        }

        final String host = target.getAddress().getHostAddress();
        mJob = ThreadHelper.submit(() -> {
            for (int port : sslPorts) {
                if (!mRunning.get()) break;
                inspectPort(host, port);
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
    }

    // ── Debug helpers ─────────────────────────────────────────────────────────

    private void emitDebugFindings() {
        report(SslFinding.Severity.INFO, "Scanning",   "192.168.1.105:443");
        report(SslFinding.Severity.INFO, "Protocol",   "TLSv1.2 [:443]");
        report(SslFinding.Severity.WARN, "Legacy TLS (TLSv1.2)", "Prefer TLS 1.3 [:443]");
        report(SslFinding.Severity.INFO, "Cipher",     "TLS_RSA_WITH_AES_128_CBC_SHA");
        report(SslFinding.Severity.INFO, "Non-AEAD cipher", "TLS_RSA_WITH_AES_128_CBC_SHA [:443]");
        report(SslFinding.Severity.INFO, "Subject",    "CN=debug-pc, O=Debug Corp");
        report(SslFinding.Severity.INFO, "Issuer",     "CN=debug-pc, O=Debug Corp");
        report(SslFinding.Severity.WARN, "Self-signed certificate", "Not trusted by browsers [:443]");
        report(SslFinding.Severity.INFO, "Valid from", "2024-01-01");
        report(SslFinding.Severity.INFO, "Valid until","2026-01-01");
        report(SslFinding.Severity.INFO, "Key",        "RSA 2048 bits");
        report(SslFinding.Severity.VULN, "Certificate EXPIRED", "Expired on 2026-01-01 [:443]");
    }

    // ── SSL checks ────────────────────────────────────────────────────────────

    private void inspectPort(String host, int port) {
        report(SslFinding.Severity.INFO, "Scanning", host + ":" + port);
        try {
            SSLSocketFactory factory = buildTrustAllFactory();
            SSLSocket socket = (SSLSocket) factory.createSocket();
            socket.connect(new InetSocketAddress(host, port), CONNECT_TIMEOUT_MS);
            socket.setSoTimeout(CONNECT_TIMEOUT_MS);
            socket.startHandshake();

            // Cipher and protocol
            String cipher   = socket.getSession().getCipherSuite();
            String protocol = socket.getSession().getProtocol();
            report(SslFinding.Severity.INFO, "Protocol", protocol + " [:" + port + "]");
            report(SslFinding.Severity.INFO, "Cipher", cipher);

            // Legacy protocol warnings
            checkProtocol(protocol, port);

            // Weak cipher check
            checkCipher(cipher, port);

            // Certificate analysis
            java.security.cert.Certificate[] chain = socket.getSession().getPeerCertificates();
            if (chain != null && chain.length > 0 && chain[0] instanceof X509Certificate) {
                analyseCert((X509Certificate) chain[0], chain, port);
            }

            socket.close();

        } catch (Exception e) {
            String msg = e.getMessage();
            if (msg != null && msg.contains("Connection refused"))
                report(SslFinding.Severity.INFO, "Port " + port, "Connection refused");
            else if (msg != null && msg.contains("timeout"))
                report(SslFinding.Severity.INFO, "Port " + port, "Connection timed out");
            else
                report(SslFinding.Severity.WARN, "TLS error on :" + port, msg != null ? msg : e.getClass().getSimpleName());
        }
    }

    private void checkProtocol(String protocol, int port) {
        String lp = protocol.toLowerCase(Locale.US);
        if (lp.contains("sslv3"))
            report(SslFinding.Severity.VULN, "SSLv3 (POODLE)", "SSLv3 is broken — disable immediately [:" + port + "]");
        else if (lp.contains("tlsv1.1") || lp.equals("tlsv1") || lp.contains("tls1.0"))
            report(SslFinding.Severity.WARN, "Legacy TLS (" + protocol + ")", "TLS 1.0/1.1 deprecated (RFC 8996) [:" + port + "]");
        else if (lp.contains("tlsv1.2"))
            report(SslFinding.Severity.INFO, "TLS 1.2", "Acceptable — prefer TLS 1.3 [:" + port + "]");
        else if (lp.contains("tlsv1.3"))
            report(SslFinding.Severity.INFO, "TLS 1.3", "Modern protocol — good [:" + port + "]");
    }

    private void checkCipher(String cipher, int port) {
        String lc = cipher.toUpperCase(Locale.US);
        if (lc.contains("_NULL_") || lc.contains("WITH_NULL"))
            report(SslFinding.Severity.VULN, "NULL cipher", "No encryption! [:" + port + "]");
        else if (lc.contains("EXPORT") || lc.contains("_40_") || lc.contains("_56_"))
            report(SslFinding.Severity.VULN, "Export-grade cipher (FREAK)", cipher + " [:" + port + "]");
        else if (lc.contains("RC4"))
            report(SslFinding.Severity.VULN, "RC4 cipher (broken)", cipher + " [:" + port + "]");
        else if (lc.contains("DES") && !lc.contains("3DES"))
            report(SslFinding.Severity.VULN, "DES cipher (broken)", cipher + " [:" + port + "]");
        else if (lc.contains("3DES"))
            report(SslFinding.Severity.WARN, "3DES cipher (weak)", cipher + " [:" + port + "]");
        else if (lc.contains("_ANON_"))
            report(SslFinding.Severity.VULN, "Anonymous cipher (no auth)", cipher + " [:" + port + "]");
        else if (!lc.contains("GCM") && !lc.contains("CHACHA"))
            report(SslFinding.Severity.INFO, "Non-AEAD cipher", cipher + " [:" + port + "]");
    }

    private void analyseCert(X509Certificate cert,
                              java.security.cert.Certificate[] chain, int port) {
        // Subject
        String subject = cert.getSubjectDN().getName();
        report(SslFinding.Severity.INFO, "Subject", subject);

        // Issuer
        String issuer = cert.getIssuerDN().getName();
        report(SslFinding.Severity.INFO, "Issuer", issuer);

        // Self-signed?
        if (cert.getSubjectDN().equals(cert.getIssuerDN()))
            report(SslFinding.Severity.WARN, "Self-signed certificate", "Not trusted by browsers [:" + port + "]");

        // Validity dates
        Date now    = new Date();
        Date notBefore = cert.getNotBefore();
        Date notAfter  = cert.getNotAfter();
        report(SslFinding.Severity.INFO, "Valid from", DATE_FMT.format(notBefore));
        report(SslFinding.Severity.INFO, "Valid until", DATE_FMT.format(notAfter));

        if (now.after(notAfter)) {
            report(SslFinding.Severity.VULN, "Certificate EXPIRED",
                "Expired on " + DATE_FMT.format(notAfter) + " [:" + port + "]");
        } else {
            long daysLeft = (notAfter.getTime() - now.getTime()) / (1000L * 60 * 60 * 24);
            if (daysLeft < 30)
                report(SslFinding.Severity.WARN, "Expiring soon",
                    daysLeft + " days remaining [:" + port + "]");
        }

        // Key size
        checkKeySize(cert, port);

        // SANs
        try {
            Collection<List<?>> sans = cert.getSubjectAlternativeNames();
            if (sans != null) {
                StringBuilder sb = new StringBuilder();
                for (List<?> san : sans) {
                    Object val = san.get(1);
                    if (sb.length() > 0) sb.append(", ");
                    sb.append(val);
                }
                if (sb.length() > 0)
                    report(SslFinding.Severity.INFO, "SANs", sb.toString());
            }
        } catch (Exception ignored) {}
    }

    private void checkKeySize(X509Certificate cert, int port) {
        try {
            java.security.PublicKey key = cert.getPublicKey();
            String alg = key.getAlgorithm().toUpperCase(Locale.US);
            int bits = -1;

            if (alg.equals("RSA") || alg.equals("DSA")) {
                java.security.interfaces.RSAPublicKey rsa = (java.security.interfaces.RSAPublicKey) key;
                bits = rsa.getModulus().bitLength();
                report(SslFinding.Severity.INFO, "Key", alg + " " + bits + " bits");
                if (bits < 2048)
                    report(SslFinding.Severity.VULN, "Weak key (<2048 RSA)", bits + "-bit key [:" + port + "]");
            } else if (alg.contains("EC")) {
                java.security.interfaces.ECPublicKey ec = (java.security.interfaces.ECPublicKey) key;
                bits = ec.getParams().getCurve().getField().getFieldSize();
                report(SslFinding.Severity.INFO, "Key", "EC " + bits + " bits");
                if (bits < 224)
                    report(SslFinding.Severity.WARN, "Short EC key (<224 bits)", bits + "-bit key [:" + port + "]");
            } else {
                report(SslFinding.Severity.INFO, "Key", alg);
            }
        } catch (Exception ignored) {}
    }

    /** Build an SSLSocketFactory that accepts all certificates (for analysis only). */
    private SSLSocketFactory buildTrustAllFactory() throws Exception {
        TrustManager[] tm = new TrustManager[]{
            new X509TrustManager() {
                public void checkClientTrusted(X509Certificate[] c, String a) {}
                public void checkServerTrusted(X509Certificate[] c, String a) {}
                public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
            }
        };
        SSLContext ctx = SSLContext.getInstance("TLS");
        ctx.init(null, tm, null);
        return ctx.getSocketFactory();
    }

    // ── Port helpers ──────────────────────────────────────────────────────────

    private List<Integer> getSslPorts(Target t) {
        List<Integer> result = new ArrayList<>();
        for (Target.Port p : t.getOpenPorts()) {
            String svc = p.getService() == null ? "" : p.getService().toLowerCase(Locale.US);
            int num = p.getNumber();
            if (svc.contains("https") || svc.contains("ssl") || svc.contains("tls")
                || num == 443 || num == 8443 || num == 4443 || num == 9443) {
                result.add(num);
            }
        }
        // If no open ports recorded but target is accessible, try 443
        if (result.isEmpty()) result.add(443);
        return result;
    }

    // ── UI helpers ────────────────────────────────────────────────────────────

    private void report(SslFinding.Severity sev, String label, String detail) {
        SslFinding f = new SslFinding(sev, label, detail);
        runOnUiThread(() -> {
            mAdapter.add(f);
            mAdapter.notifyDataSetChanged();
        });
    }

    private class FindingAdapter extends ArrayAdapter<SslFinding> {
        FindingAdapter() {
            super(SslInspector.this, R.layout.plugin_ssl_inspector_item, new ArrayList<>());
        }

        @Override
        public View getView(int position, View convertView, ViewGroup parent) {
            if (convertView == null)
                convertView = LayoutInflater.from(getContext())
                    .inflate(R.layout.plugin_ssl_inspector_item, parent, false);

            SslFinding f = getItem(position);
            TextView label  = convertView.findViewById(R.id.sslItemLabel);
            TextView detail = convertView.findViewById(R.id.sslItemDetail);

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
