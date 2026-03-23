package org.csploit.android.plugins;

import android.content.SharedPreferences;
import android.os.Bundle;
import android.view.View;
import android.widget.ProgressBar;
import android.widget.ScrollView;
import android.widget.TextView;

import com.google.android.material.floatingactionbutton.FloatingActionButton;

import org.csploit.android.BuildConfig;
import org.csploit.android.R;
import org.csploit.android.core.Plugin;
import org.csploit.android.core.System;
import org.csploit.android.helpers.AnimationHelper;
import org.csploit.android.helpers.LoggingHelper;
import org.csploit.android.helpers.ThreadHelper;
import org.csploit.android.net.Target;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Whois Lookup — queries whois servers over TCP port 43.
 *
 * For IP addresses:  queries whois.arin.net (falls through to RIPE/APNIC/etc.)
 * For hostnames:     extracts the TLD/SLD and selects the right TLD whois server
 *                    (whois.verisign-grs.com for .com/.net, whois.nic.* for ccTLDs)
 *
 * Results are displayed as scrollable plain text.
 */
public class WhoisLookup extends Plugin {
    private static final String TAG = "WhoisLookup";
    private static final int TIMEOUT_MS = 8000;

    // Default whois servers per TLD
    private static final java.util.Map<String, String> TLD_SERVERS =
        new java.util.HashMap<String, String>() {{
            put("com",  "whois.verisign-grs.com");
            put("net",  "whois.verisign-grs.com");
            put("org",  "whois.pir.org");
            put("io",   "whois.nic.io");
            put("co",   "whois.nic.co");
            put("uk",   "whois.nic.uk");
            put("de",   "whois.denic.de");
            put("fr",   "whois.nic.fr");
            put("nl",   "whois.domain-registry.nl");
            put("ru",   "whois.tcinet.ru");
            put("au",   "whois.auda.org.au");
            put("ca",   "whois.cira.ca");
            put("jp",   "whois.jprs.jp");
            put("cn",   "whois.cnnic.cn");
            put("br",   "whois.registro.br");
            put("info", "whois.afilias.net");
            put("biz",  "whois.biz");
            put("app",  "whois.nic.google");
            put("dev",  "whois.nic.google");
        }};

    private FloatingActionButton mToggleButton;
    private ProgressBar mProgress;
    private TextView mOutput;
    private ScrollView mScroll;
    private final AtomicBoolean mRunning = new AtomicBoolean(false);
    private Future<?> mJob;

    public WhoisLookup() {
        super(
            R.string.whois_lookup,
            R.string.whois_lookup_desc,
            new Target.Type[]{Target.Type.ENDPOINT, Target.Type.REMOTE},
            R.layout.plugin_whois_lookup,
            R.drawable.action_traceroute
        );
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        SharedPreferences prefs = getSharedPreferences("THEME", 0);
        setTheme(prefs.getBoolean("isDark", false) ? R.style.DarkTheme : R.style.AppTheme);
        super.onCreate(savedInstanceState);

        mToggleButton = findViewById(R.id.whoisToggleButton);
        mProgress     = findViewById(R.id.whoisActivity);
        mOutput       = findViewById(R.id.whoisOutput);
        mScroll       = findViewById(R.id.whoisScroll);

        mToggleButton.setOnClickListener(v -> {
            if (mRunning.get()) stopLookup();
            else                startLookup();
        });
    }

    @Override
    public void onBackPressed() {
        stopLookup();
        super.onBackPressed();
        overridePendingTransition(R.anim.fadeout, R.anim.fadein);
    }

    // ── Lookup control ────────────────────────────────────────────────────────

    private void startLookup() {
        Target target = System.getCurrentTarget();
        if (target == null) return;

        mRunning.set(true);
        runOnUiThread(() -> mOutput.setText(""));
        mProgress.setVisibility(View.VISIBLE);
        AnimationHelper.fadeIn(mProgress, 200);
        mToggleButton.setImageDrawable(
            androidx.core.content.ContextCompat.getDrawable(this, R.drawable.ic_stop_24dp));

        if (BuildConfig.DEBUG) {
            mJob = ThreadHelper.submit(() -> {
                append(FAKE_WHOIS);
                runOnUiThread(this::onFinished);
            });
            return;
        }

        final String host = target.getAddress().getHostName();
        final String ip   = target.getAddress().getHostAddress();
        mJob = ThreadHelper.submit(() -> {
            query(host, ip);
            runOnUiThread(this::onFinished);
        });
    }

    private void stopLookup() {
        mRunning.set(false);
        if (mJob != null) { mJob.cancel(true); mJob = null; }
        onFinished();
    }

    private void onFinished() {
        mRunning.set(false);
        AnimationHelper.fadeOut(mProgress, 200, () -> mProgress.setVisibility(View.INVISIBLE));
        mToggleButton.setImageDrawable(
            androidx.core.content.ContextCompat.getDrawable(this, R.drawable.ic_play_arrow_24dp));
    }

    // ── Whois logic ───────────────────────────────────────────────────────────

    private void query(String host, String ip) {
        boolean isIp = host.equals(ip) || host.matches("\\d+\\.\\d+\\.\\d+\\.\\d+");

        if (isIp) {
            // IP whois — start with ARIN, it will refer if needed
            String result = rawWhois("whois.arin.net", "n + " + ip);
            if (result == null || result.isEmpty())
                result = rawWhois("whois.arin.net", ip);
            append(result != null ? result : "No response from whois.arin.net");
        } else {
            // Domain whois
            String tld = getTld(host);
            String server = TLD_SERVERS.getOrDefault(tld, "whois.iana.org");
            append("Querying " + server + " for " + host + "\n\n");
            String result = rawWhois(server, host);
            if (result == null || result.isEmpty()) {
                result = rawWhois("whois.iana.org", host);
            }
            append(result != null ? result : "No whois data found");
        }
    }

    private String getTld(String host) {
        String[] parts = host.split("\\.");
        if (parts.length >= 2) return parts[parts.length - 1].toLowerCase();
        return host;
    }

    /** Opens TCP connection to whois server on port 43 and returns the response. */
    private String rawWhois(String server, String query) {
        try {
            Socket sock = new Socket();
            sock.connect(new InetSocketAddress(server, 43), TIMEOUT_MS);
            sock.setSoTimeout(TIMEOUT_MS);

            PrintWriter out = new PrintWriter(sock.getOutputStream(), true);
            out.println(query);

            StringBuilder sb = new StringBuilder();
            BufferedReader in = new BufferedReader(new InputStreamReader(sock.getInputStream()));
            String line;
            while ((line = in.readLine()) != null) {
                sb.append(line).append('\n');
            }
            sock.close();
            return sb.toString();
        } catch (Exception e) {
            LoggingHelper.w(TAG, "Whois error: " + e.getMessage());
            return null;
        }
    }

    private void append(String text) {
        if (text == null) return;
        runOnUiThread(() -> {
            mOutput.append(text);
            mScroll.post(() -> mScroll.fullScroll(View.FOCUS_DOWN));
        });
    }

    private static final String FAKE_WHOIS =
        "Querying whois.verisign-grs.com for example.com\n\n" +
        "Domain Name: EXAMPLE.COM\n" +
        "Registry Domain ID: 2336799_DOMAIN_COM-VRSN\n" +
        "Registrar WHOIS Server: whois.iana.org\n" +
        "Registrar URL: http://res-dom.iana.org\n" +
        "Updated Date: 2023-08-14T07:01:38Z\n" +
        "Creation Date: 1995-08-14T04:00:00Z\n" +
        "Registry Expiry Date: 2024-08-13T04:00:00Z\n" +
        "Registrar: RESERVED-Internet Assigned Numbers Authority\n" +
        "Registrar IANA ID: 376\n" +
        "Domain Status: clientDeleteProhibited\n" +
        "Domain Status: clientTransferProhibited\n" +
        "Domain Status: clientUpdateProhibited\n" +
        "Name Server: A.IANA-SERVERS.NET\n" +
        "Name Server: B.IANA-SERVERS.NET\n" +
        "DNSSEC: signedDelegation\n" +
        "\n" +
        "Registrant Organization: Internet Assigned Numbers Authority\n" +
        "Registrant Country: US\n" +
        "Admin Email: noc@iana.org\n" +
        "Tech Email: noc@iana.org\n";
}
