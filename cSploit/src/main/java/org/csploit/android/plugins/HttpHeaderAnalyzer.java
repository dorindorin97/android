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
import java.net.HttpURLConnection;
import java.net.URL;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManager;
import javax.net.ssl.X509TrustManager;

public class HttpHeaderAnalyzer extends Plugin {

    // --------------- result model ---------------
    public static class HeaderResult {
        public enum Kind { PASS, WARN, FAIL, INFO }
        public Kind kind;
        public String header;
        public String value;

        public HeaderResult(Kind kind, String header, String value) {
            this.kind = kind;
            this.header = header;
            this.value = value;
        }
    }

    // --------------- adapter ---------------
    private class HeaderAdapter extends ArrayAdapter<HeaderResult> {
        HeaderAdapter(List<HeaderResult> items) {
            super(HttpHeaderAnalyzer.this, R.layout.plugin_http_header_analyzer_item, items);
        }

        @Override
        public View getView(int position, View convertView, android.view.ViewGroup parent) {
            if (convertView == null) {
                convertView = getLayoutInflater().inflate(R.layout.plugin_http_header_analyzer_item, parent, false);
            }
            HeaderResult r = getItem(position);
            TextView headerView = convertView.findViewById(R.id.hdrItemHeader);
            TextView valueView = convertView.findViewById(R.id.hdrItemValue);
            if (r != null) {
                headerView.setText(r.header);
                valueView.setText(r.value);
                int color;
                switch (r.kind) {
                    case PASS: color = 0xFF388E3C; break;
                    case WARN: color = 0xFFF57C00; break;
                    case FAIL: color = 0xFFD32F2F; break;
                    default:   color = ContextCompat.getColor(HttpHeaderAnalyzer.this, R.color.app_color); break;
                }
                headerView.setTextColor(color);
            }
            return convertView;
        }
    }

    // --------------- fields ---------------
    private FloatingActionButton mFab;
    private View mProgress;
    private ListView mList;
    private final List<HeaderResult> mResults = new ArrayList<>();
    private HeaderAdapter mAdapter;
    private Future<?> mJob;
    private final AtomicBoolean mRunning = new AtomicBoolean(false);

    // --------------- constructor ---------------
    public HttpHeaderAnalyzer() {
        super(R.string.http_header_analyzer, R.string.http_header_analyzer_desc,
                new Target.Type[]{Target.Type.ENDPOINT, Target.Type.REMOTE},
                R.layout.plugin_http_header_analyzer, R.drawable.action_scanner);
    }

    // --------------- lifecycle ---------------
    @Override
    public void onCreate(Bundle savedInstanceState) {
        SharedPreferences prefs = getSharedPreferences("THEME", MODE_PRIVATE);
        int theme = prefs.getInt("theme", R.style.AppTheme);
        setTheme(theme);

        super.onCreate(savedInstanceState);

        mFab = findViewById(R.id.httpHdrToggleButton);
        mProgress = findViewById(R.id.httpHdrActivity);
        mList = findViewById(android.R.id.list);

        mAdapter = new HeaderAdapter(mResults);
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
        addResult(new HeaderResult(HeaderResult.Kind.PASS, "X-Content-Type-Options", "nosniff"));
        addResult(new HeaderResult(HeaderResult.Kind.WARN, "Content-Security-Policy", "Missing"));
        addResult(new HeaderResult(HeaderResult.Kind.FAIL, "Strict-Transport-Security", "Missing"));
        addResult(new HeaderResult(HeaderResult.Kind.WARN, "Server", "Apache/2.4.41 — exposes version info"));
        addResult(new HeaderResult(HeaderResult.Kind.WARN, "X-Powered-By", "PHP/7.4.3 — exposes technology stack"));
    }

    // --------------- core logic ---------------
    private void scan(String ip) {
        Map<String, String> headers = null;
        boolean isHttps = false;

        // Try HTTPS first
        try {
            String urlStr = "https://" + ip + "/";
            addResult(new HeaderResult(HeaderResult.Kind.INFO, "URL", urlStr));
            headers = fetchHeaders(urlStr, true);
            isHttps = true;
        } catch (Exception ignored) {
        }

        if (!mRunning.get()) return;

        // Fallback to HTTP
        if (headers == null) {
            try {
                String urlStr = "http://" + ip + "/";
                addResult(new HeaderResult(HeaderResult.Kind.INFO, "URL", urlStr));
                headers = fetchHeaders(urlStr, false);
                isHttps = false;
            } catch (Exception ignored) {
            }
        }

        if (headers == null) {
            addResult(new HeaderResult(HeaderResult.Kind.INFO, "Error", "Could not connect to HTTP or HTTPS"));
            return;
        }

        // Normalize keys to lowercase
        Map<String, String> lc = new LinkedHashMap<>();
        for (Map.Entry<String, String> e : headers.entrySet()) {
            if (e.getKey() != null) lc.put(e.getKey().toLowerCase(), e.getValue());
        }

        checkHeader(lc, "strict-transport-security",
                isHttps ? HeaderResult.Kind.FAIL : HeaderResult.Kind.INFO,
                "Strict-Transport-Security");
        checkHeader(lc, "content-security-policy", HeaderResult.Kind.WARN, "Content-Security-Policy");
        checkHeader(lc, "x-frame-options", HeaderResult.Kind.WARN, "X-Frame-Options");

        String xcto = lc.get("x-content-type-options");
        if (xcto != null && xcto.trim().equalsIgnoreCase("nosniff")) {
            addResult(new HeaderResult(HeaderResult.Kind.PASS, "X-Content-Type-Options", xcto));
        } else if (xcto != null) {
            addResult(new HeaderResult(HeaderResult.Kind.WARN, "X-Content-Type-Options", xcto));
        } else {
            addResult(new HeaderResult(HeaderResult.Kind.WARN, "X-Content-Type-Options", "Missing"));
        }

        checkHeader(lc, "referrer-policy", HeaderResult.Kind.WARN, "Referrer-Policy");
        checkHeader(lc, "permissions-policy", HeaderResult.Kind.INFO, "Permissions-Policy");
        checkHeader(lc, "x-xss-protection", HeaderResult.Kind.INFO, "X-XSS-Protection");
        checkHeader(lc, "cache-control", HeaderResult.Kind.INFO, "Cache-Control");

        // Misc checks
        String server = lc.get("server");
        if (server != null) {
            addResult(new HeaderResult(HeaderResult.Kind.WARN, "Server",
                    server + " — exposes version info"));
        }
        String xpb = lc.get("x-powered-by");
        if (xpb != null) {
            addResult(new HeaderResult(HeaderResult.Kind.WARN, "X-Powered-By",
                    xpb + " — exposes technology stack"));
        }
        String acao = lc.get("access-control-allow-origin");
        if ("*".equals(acao)) {
            addResult(new HeaderResult(HeaderResult.Kind.WARN, "Access-Control-Allow-Origin",
                    "* — Wildcard CORS"));
        }
    }

    private void checkHeader(Map<String, String> headers, String key,
                              HeaderResult.Kind missingKind, String displayName) {
        String val = headers.get(key);
        if (val != null) {
            addResult(new HeaderResult(HeaderResult.Kind.PASS, displayName, val));
        } else {
            addResult(new HeaderResult(missingKind, displayName, "Missing"));
        }
    }

    private Map<String, String> fetchHeaders(String urlStr, boolean trustAll) throws Exception {
        URL url = new URL(urlStr);
        HttpURLConnection conn;
        if (trustAll && urlStr.startsWith("https")) {
            SSLContext sc = SSLContext.getInstance("TLS");
            sc.init(null, new TrustManager[]{new X509TrustManager() {
                public void checkClientTrusted(X509Certificate[] c, String a) {}
                public void checkServerTrusted(X509Certificate[] c, String a) {}
                public X509Certificate[] getAcceptedIssuers() { return new X509Certificate[0]; }
            }}, new SecureRandom());
            HttpsURLConnection hc = (HttpsURLConnection) url.openConnection();
            hc.setSSLSocketFactory(sc.getSocketFactory());
            hc.setHostnameVerifier((h, s) -> true);
            conn = hc;
        } else {
            conn = (HttpURLConnection) url.openConnection();
        }
        conn.setConnectTimeout(7000);
        conn.setReadTimeout(7000);
        conn.setRequestMethod("GET");
        conn.setInstanceFollowRedirects(false);
        conn.connect();

        Map<String, String> result = new LinkedHashMap<>();
        for (Map.Entry<String, List<String>> e : conn.getHeaderFields().entrySet()) {
            if (e.getKey() != null && e.getValue() != null && !e.getValue().isEmpty()) {
                result.put(e.getKey(), e.getValue().get(0));
            }
        }
        conn.disconnect();
        return result;
    }

    // --------------- helpers ---------------
    private void addResult(HeaderResult result) {
        runOnUiThread(() -> {
            mResults.add(result);
            mAdapter.notifyDataSetChanged();
        });
    }
}
