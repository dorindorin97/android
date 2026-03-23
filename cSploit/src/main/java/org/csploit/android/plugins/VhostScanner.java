package org.csploit.android.plugins;

import android.content.SharedPreferences;
import android.os.Bundle;
import android.view.View;
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
import org.csploit.android.helpers.ThreadHelper;
import org.csploit.android.net.Target;

import java.net.HttpURLConnection;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;

public class VhostScanner extends Plugin {

    // --------------- result model ---------------
    public static class VhostResult {
        public String host;
        public String statusCode;
        public String detail;
        public boolean different;

        public VhostResult(String host, String statusCode, String detail, boolean different) {
            this.host = host;
            this.statusCode = statusCode;
            this.detail = detail;
            this.different = different;
        }
    }

    private static final String[] PREFIXES = {
        "www", "mail", "smtp", "pop3", "imap", "ftp", "ssh", "vpn", "dev", "staging", "test",
        "api", "admin", "portal", "dashboard", "app", "mobile", "m", "static", "cdn",
        "media", "img", "assets", "blog", "shop", "store", "forum", "wiki", "docs", "help",
        "support", "tickets", "gitlab", "git", "jenkins", "ci", "monitor", "nagios", "zabbix", "grafana"
    };

    // --------------- adapter ---------------
    private class VhostAdapter extends ArrayAdapter<VhostResult> {
        VhostAdapter(List<VhostResult> items) {
            super(VhostScanner.this, R.layout.plugin_vhost_scanner_item, items);
        }

        @Override
        public View getView(int position, View convertView, android.view.ViewGroup parent) {
            if (convertView == null) {
                convertView = getLayoutInflater().inflate(R.layout.plugin_vhost_scanner_item, parent, false);
            }
            VhostResult r = getItem(position);
            TextView hostView = convertView.findViewById(R.id.vhostItemHost);
            TextView statusView = convertView.findViewById(R.id.vhostItemStatus);
            if (r != null) {
                hostView.setText(r.host);
                statusView.setText(r.statusCode + (r.detail.isEmpty() ? "" : " — " + r.detail));
                int color = r.different
                        ? ContextCompat.getColor(VhostScanner.this, R.color.app_color)
                        : 0xFF888888;
                hostView.setTextColor(color);
            }
            return convertView;
        }
    }

    // --------------- fields ---------------
    private FloatingActionButton mFab;
    private ProgressBar mProgress;
    private ListView mList;
    private EditText mIpEdit;
    private final List<VhostResult> mResults = new ArrayList<>();
    private VhostAdapter mAdapter;
    private Future<?> mJob;
    private final AtomicBoolean mRunning = new AtomicBoolean(false);

    // --------------- constructor ---------------
    public VhostScanner() {
        super(R.string.vhost_scanner, R.string.vhost_scanner_desc,
                new Target.Type[]{Target.Type.ENDPOINT, Target.Type.REMOTE},
                R.layout.plugin_vhost_scanner, R.drawable.action_scanner);
    }

    // --------------- lifecycle ---------------
    @Override
    public void onCreate(Bundle savedInstanceState) {
        SharedPreferences prefs = getSharedPreferences("THEME", MODE_PRIVATE);
        int theme = prefs.getInt("theme", R.style.AppTheme);
        setTheme(theme);

        super.onCreate(savedInstanceState);

        mFab = findViewById(R.id.vhostToggleButton);
        mProgress = findViewById(R.id.vhostActivity);
        mList = findViewById(android.R.id.list);
        mIpEdit = findViewById(R.id.vhostIp);

        String ip = System.getCurrentTarget().getAddress().getHostAddress();
        mIpEdit.setText(ip);

        mAdapter = new VhostAdapter(mResults);
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

        String targetIp = mIpEdit.getText().toString().trim();

        mJob = ThreadHelper.submit(() -> {
            try {
                scan(targetIp);
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
        addResult(new VhostResult("api", "200", "content-length differs", true));
        addResult(new VhostResult("admin", "200", "content-length differs", true));
        addResult(new VhostResult("staging", "200", "content-length differs", true));
        addResult(new VhostResult("www", "200", "same as baseline", false));
        addResult(new VhostResult("mail", "200", "same as baseline", false));
    }

    // --------------- core logic ---------------
    private void scan(String targetIp) throws Exception {
        // Baseline request with Host: targetIp
        int baseStatus = -1;
        int baseLength = -1;

        try {
            HttpResponse base = doRequest(targetIp, targetIp);
            baseStatus = base.status;
            baseLength = base.contentLength;
        } catch (Exception ignored) {
        }

        if (!mRunning.get()) return;

        // Reverse-DNS for domain
        String baseDomain;
        try {
            baseDomain = java.net.InetAddress.getByName(targetIp).getHostName();
            if (baseDomain.equals(targetIp)) baseDomain = targetIp;
        } catch (Exception e) {
            baseDomain = targetIp;
        }

        for (String prefix : PREFIXES) {
            if (!mRunning.get()) break;
            String hostHeader = prefix + "." + baseDomain;
            try {
                HttpResponse resp = doRequest(targetIp, hostHeader);
                boolean different = false;
                String detail = resp.status + "";

                if (resp.status != baseStatus) {
                    different = true;
                    detail = "status changed: " + baseStatus + " -> " + resp.status;
                } else if (baseLength > 0 && resp.contentLength > 0) {
                    double ratio = Math.abs(resp.contentLength - baseLength) / (double) baseLength;
                    if (ratio > 0.10) {
                        different = true;
                        detail = "size differs: " + baseLength + " vs " + resp.contentLength;
                    }
                }

                if (different) {
                    addResult(new VhostResult(hostHeader, String.valueOf(resp.status), detail, true));
                }
                // Optionally show same results too (skipped to reduce noise)
            } catch (Exception ignored) {
            }
        }
    }

    private static class HttpResponse {
        int status;
        int contentLength;
    }

    private HttpResponse doRequest(String ip, String hostHeader) throws Exception {
        URL url = new URL("http://" + ip + "/");
        HttpURLConnection conn = (HttpURLConnection) url.openConnection();
        conn.setConnectTimeout(5000);
        conn.setReadTimeout(5000);
        conn.setRequestMethod("GET");
        conn.setInstanceFollowRedirects(false);
        conn.setFollowRedirects(false);
        conn.setRequestProperty("Host", hostHeader);
        conn.connect();
        HttpResponse r = new HttpResponse();
        r.status = conn.getResponseCode();
        String cl = conn.getHeaderField("Content-Length");
        r.contentLength = cl != null ? Integer.parseInt(cl.trim()) : -1;
        conn.disconnect();
        return r;
    }

    // --------------- helpers ---------------
    private void addResult(VhostResult result) {
        runOnUiThread(() -> {
            mResults.add(result);
            mAdapter.notifyDataSetChanged();
        });
    }
}
