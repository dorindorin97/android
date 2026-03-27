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

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.URL;
import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;

public class CertTransparency extends Plugin {

    // --------------- result model ---------------
    public static class CtResult {
        public String subdomain;
        public String issuer;
        public String notBefore;
        public String notAfter;
        public boolean expired;

        public CtResult(String subdomain, String issuer, String notBefore, String notAfter, boolean expired) {
            this.subdomain = subdomain;
            this.issuer = issuer;
            this.notBefore = notBefore;
            this.notAfter = notAfter;
            this.expired = expired;
        }
    }

    // --------------- adapter ---------------
    private class CtAdapter extends ArrayAdapter<CtResult> {
        CtAdapter(List<CtResult> items) {
            super(CertTransparency.this, R.layout.plugin_cert_transparency_item, items);
        }

        @Override
        public View getView(int position, View convertView, android.view.ViewGroup parent) {
            if (convertView == null) {
                convertView = getLayoutInflater().inflate(R.layout.plugin_cert_transparency_item, parent, false);
            }
            CtResult r = getItem(position);
            TextView subdomainView = convertView.findViewById(R.id.ctItemSubdomain);
            TextView metaView      = convertView.findViewById(R.id.ctItemMeta);
            if (r != null) {
                subdomainView.setText(r.subdomain);
                String meta = "";
                if (!r.notBefore.isEmpty()) meta += "From: " + r.notBefore + "  ";
                if (!r.notAfter.isEmpty())  meta += "To: " + r.notAfter;
                if (!r.issuer.isEmpty())    meta += "\n" + r.issuer;
                metaView.setText(meta);
                int color = r.expired
                        ? 0xFFD32F2F
                        : ContextCompat.getColor(CertTransparency.this, R.color.app_color);
                subdomainView.setTextColor(color);
            }
            return convertView;
        }
    }

    // --------------- fields ---------------
    private FloatingActionButton mFab;
    private View mProgress;
    private ListView mList;
    private final List<CtResult> mResults = new ArrayList<>();
    private CtAdapter mAdapter;
    private Future<?> mJob;
    private final AtomicBoolean mRunning = new AtomicBoolean(false);

    // --------------- constructor ---------------
    public CertTransparency() {
        super(R.string.cert_transparency, R.string.cert_transparency_desc,
                new Target.Type[]{Target.Type.REMOTE},
                R.layout.plugin_cert_transparency, R.drawable.action_scanner);
    }

    // --------------- lifecycle ---------------
    @Override
    public void onCreate(Bundle savedInstanceState) {
        SharedPreferences prefs = getSharedPreferences("THEME", MODE_PRIVATE);
        int theme = prefs.getInt("theme", R.style.AppTheme);
        setTheme(theme);

        super.onCreate(savedInstanceState);

        mFab = findViewById(R.id.ctToggleButton);
        mProgress = findViewById(R.id.ctActivity);
        mList = findViewById(android.R.id.list);

        mAdapter = new CtAdapter(mResults);
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

        String domain;
        try {
            String hostname = System.getCurrentTarget().getAddress().getHostName();
            String ip = System.getCurrentTarget().getAddress().getHostAddress();
            domain = hostname.equals(ip) ? ip : hostname;
        } catch (Exception e) {
            domain = "";
        }

        if (BuildConfig.DEBUG) {
            emitDebug();
            stopScan();
            return;
        }

        final String finalDomain = domain;
        mJob = ThreadHelper.submit(() -> {
            try {
                scan(finalDomain);
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
        String today = new SimpleDateFormat("yyyy-MM-dd", Locale.US).format(new Date());
        addResult(new CtResult("www.example.com", "Let's Encrypt", "2025-01-01", today, false));
        addResult(new CtResult("api.example.com", "Let's Encrypt", "2025-01-01", today, false));
        addResult(new CtResult("staging.example.com", "DigiCert", "2024-06-01", today, false));
        addResult(new CtResult("dev.example.com", "DigiCert", "2024-06-01", today, false));
        addResult(new CtResult("mail.example.com", "Comodo", "2023-01-01", today, false));
        addResult(new CtResult("admin.example.com", "Self-Signed", "2019-01-01", "2020-01-01", true));
    }

    // --------------- core logic ---------------
    private void scan(String domain) throws Exception {
        if (domain.isEmpty()) {
            addResult(new CtResult("Error", "", "", "", false));
            return;
        }

        // Check if it looks like an IP
        if (domain.matches("\\d+\\.\\d+\\.\\d+\\.\\d+")) {
            addResult(new CtResult("No results — target is an IP address", "", "", "", false));
            return;
        }

        String urlStr = "https://crt.sh/?q=%25." + domain + "&output=json";
        HttpURLConnection conn = (HttpURLConnection) new URL(urlStr).openConnection();
        conn.setConnectTimeout(10000);
        conn.setReadTimeout(10000);
        conn.setRequestProperty("User-Agent", "Mozilla/5.0");

        if (conn.getResponseCode() != 200) {
            addResult(new CtResult("HTTP error: " + conn.getResponseCode(), "", "", "", false));
            conn.disconnect();
            return;
        }

        StringBuilder sb = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(
                new InputStreamReader(conn.getInputStream(), "UTF-8"))) {
            String line;
            while ((line = reader.readLine()) != null) {
                if (!mRunning.get()) break;
                sb.append(line);
            }
        }
        conn.disconnect();

        if (!mRunning.get()) return;

        String json = sb.toString();

        // Parse JSON manually
        Set<String> seenSubdomains = new HashSet<>();
        // Map subdomain -> {issuer, notBefore, notAfter}
        Map<String, String[]> subdomainData = new HashMap<>();

        // Extract each JSON object entry
        int idx = 0;
        while (idx < json.length()) {
            int nameStart = json.indexOf("\"name_value\":\"", idx);
            if (nameStart < 0) break;
            nameStart += "\"name_value\":\"".length();
            int nameEnd = json.indexOf("\"", nameStart);
            if (nameEnd < 0) break;
            String nameValue = json.substring(nameStart, nameEnd);

            // Find issuer, not_before, not_after in same object
            // Search backwards for start of this object '{'
            int objStart = json.lastIndexOf('{', nameStart);
            // Search forward for end of this object '}'
            int objEnd = json.indexOf('}', nameEnd);
            String obj = (objStart >= 0 && objEnd >= 0 && objEnd > objStart)
                    ? json.substring(objStart, objEnd + 1) : "";

            String issuer    = extractJsonString(obj, "issuer_name");
            String notBefore = extractJsonString(obj, "not_before");
            String notAfter  = extractJsonString(obj, "not_after");

            // Handle wildcard and multi-value entries
            for (String sub : nameValue.split("\\n")) {
                sub = sub.trim().replace("*.", "");
                if (!sub.isEmpty() && !seenSubdomains.contains(sub)) {
                    seenSubdomains.add(sub);
                    subdomainData.put(sub, new String[]{
                            issuer  != null ? issuer  : "",
                            notBefore != null ? notBefore : "",
                            notAfter  != null ? notAfter  : ""
                    });
                }
            }
            idx = nameEnd + 1;
        }

        if (seenSubdomains.isEmpty()) {
            addResult(new CtResult("No results found for " + domain, "", "", "", false));
            return;
        }

        Date now = new Date();
        SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd HH:mm:ss", Locale.US);

        for (String sub : seenSubdomains) {
            if (!mRunning.get()) break;
            String[] data = subdomainData.get(sub);
            boolean expired = false;
            if (data[2] != null && !data[2].isEmpty()) {
                try {
                    Date notAfterDate = sdf.parse(data[2]);
                    if (notAfterDate != null && notAfterDate.before(now)) expired = true;
                } catch (ParseException ignored) {}
            }
            addResult(new CtResult(sub, data[0], data[1], data[2], expired));
        }

        // Summary
        addResult(new CtResult("Total unique subdomains: " + seenSubdomains.size(),
                "", "", "", false));
    }

    private String extractJsonString(String json, String key) {
        String search = "\"" + key + "\":\"";
        int idx = json.indexOf(search);
        if (idx < 0) return null;
        int start = idx + search.length();
        // Find closing quote, respecting backslash escapes
        int end = start;
        while (end < json.length()) {
            char c = json.charAt(end);
            if (c == '\\') { end += 2; continue; }
            if (c == '"') break;
            end++;
        }
        return json.substring(start, end);
    }

    // --------------- helpers ---------------
    private void addResult(CtResult result) {
        runOnUiThread(() -> {
            mResults.add(result);
            mAdapter.notifyDataSetChanged();
        });
    }
}
