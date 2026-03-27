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

public class DirBruteForcer extends Plugin {

    // --------------- result model ---------------
    public static class DirResult {
        public int statusCode;
        public String path;
        public String detail;

        public DirResult(int statusCode, String path, String detail) {
            this.statusCode = statusCode;
            this.path = path;
            this.detail = detail;
        }
    }

    private static final String[] PATHS = {
        "/", "/admin/", "/admin/login", "/administrator/", "/wp-admin/", "/wp-login.php",
        "/phpmyadmin/", "/pma/", "/.env", "/.git/HEAD", "/.git/config", "/robots.txt",
        "/sitemap.xml", "/api/", "/api/v1/", "/api/v2/", "/swagger/", "/swagger-ui.html",
        "/swagger-ui/", "/openapi.json", "/api-docs/", "/actuator/", "/actuator/health",
        "/actuator/env", "/actuator/beans", "/console/", "/manager/", "/server-status",
        "/server-info", "/phpinfo.php", "/info.php", "/test.php", "/backup/", "/backup.zip",
        "/backup.sql", "/db.sql", "/dump.sql", "/config/", "/config.php", "/wp-config.php",
        "/config.yaml", "/config.json", "/settings.php", "/login/", "/login.php",
        "/signin/", "/dashboard/", "/panel/", "/cpanel/", "/webmail/", "/mail/",
        "/upload/", "/uploads/", "/files/", "/static/", "/assets/", "/images/",
        "/img/", "/css/", "/js/", "/lib/", "/vendor/", "/node_modules/",
        "/.htaccess", "/.htpasswd", "/web.config", "/crossdomain.xml", "/security.txt",
        "/.well-known/security.txt", "/CHANGELOG.md", "/README.md", "/LICENSE"
    };

    // --------------- adapter ---------------
    private class DirAdapter extends ArrayAdapter<DirResult> {
        DirAdapter(List<DirResult> items) {
            super(DirBruteForcer.this, R.layout.plugin_dir_brute_forcer_item, items);
        }

        @Override
        public View getView(int position, View convertView, android.view.ViewGroup parent) {
            if (convertView == null) {
                convertView = getLayoutInflater().inflate(R.layout.plugin_dir_brute_forcer_item, parent, false);
            }
            DirResult r = getItem(position);
            TextView statusView = convertView.findViewById(R.id.dirItemStatus);
            TextView pathView = convertView.findViewById(R.id.dirItemPath);
            if (r != null) {
                statusView.setText(String.valueOf(r.statusCode));
                pathView.setText(r.path);
                int color;
                int code = r.statusCode;
                if (code >= 200 && code <= 299) {
                    color = ContextCompat.getColor(DirBruteForcer.this, R.color.app_color);
                } else if (code == 301 || code == 302) {
                    color = 0xFFF57C00;
                } else if (code == 401 || code == 403) {
                    color = 0xFF388E3C;
                } else if (code == 500) {
                    color = 0xFFD32F2F;
                } else if (code == -1) {
                    color = 0xFFD32F2F;
                } else {
                    color = 0xFF888888;
                }
                statusView.setTextColor(color);
            }
            return convertView;
        }
    }

    // --------------- fields ---------------
    private FloatingActionButton mFab;
    private ProgressBar mProgress;
    private ListView mList;
    private EditText mUrlEdit;
    private final List<DirResult> mResults = new ArrayList<>();
    private DirAdapter mAdapter;
    private Future<?> mJob;
    private final AtomicBoolean mRunning = new AtomicBoolean(false);

    // --------------- constructor ---------------
    public DirBruteForcer() {
        super(R.string.dir_brute_forcer, R.string.dir_brute_forcer_desc,
                new Target.Type[]{Target.Type.ENDPOINT, Target.Type.REMOTE},
                R.layout.plugin_dir_brute_forcer, R.drawable.action_scanner);
    }

    // --------------- lifecycle ---------------
    @Override
    public void onCreate(Bundle savedInstanceState) {
        SharedPreferences prefs = getSharedPreferences("THEME", MODE_PRIVATE);
        int theme = prefs.getInt("theme", R.style.AppTheme);
        setTheme(theme);

        super.onCreate(savedInstanceState);

        mFab = findViewById(R.id.dirBruteToggleButton);
        mProgress = findViewById(R.id.dirBruteActivity);
        mList = findViewById(android.R.id.list);
        mUrlEdit = findViewById(R.id.dirBruteUrl);

        String ip = System.getCurrentTarget().getAddress().getHostAddress();
        mUrlEdit.setText("http://" + ip);

        mProgress.setMax(PATHS.length);
        mProgress.setProgress(0);

        mAdapter = new DirAdapter(mResults);
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

        if (BuildConfig.DEBUG) {
            emitDebug();
            stopScan();
            return;
        }

        String baseUrl = mUrlEdit.getText().toString().trim();

        mJob = ThreadHelper.submit(() -> {
            try {
                scan(baseUrl);
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
        addResult(new DirResult(200, "/robots.txt", ""));
        addResult(new DirResult(200, "/.env", ""));
        addResult(new DirResult(301, "/admin/", "Redirect"));
        addResult(new DirResult(200, "/wp-login.php", ""));
        addResult(new DirResult(403, "/phpinfo.php", "Forbidden"));
    }

    // --------------- core logic ---------------
    private void scan(String baseUrl) {
        int done = 0;
        for (String path : PATHS) {
            if (!mRunning.get()) break;
            int code = -2;
            String detail = "";
            try {
                URL url = new URL(baseUrl + path);
                HttpURLConnection conn = (HttpURLConnection) url.openConnection();
                conn.setConnectTimeout(5000);
                conn.setReadTimeout(5000);
                conn.setRequestMethod("GET");
                conn.setFollowRedirects(false);
                conn.setInstanceFollowRedirects(false);
                conn.connect();
                code = conn.getResponseCode();
                conn.disconnect();
            } catch (Exception e) {
                code = -1;
                detail = "ERR";
            }
            done++;
            final int finalDone = done;
            runOnUiThread(() -> mProgress.setProgress(finalDone));

            // Show everything except 404
            if (code != 404 && code != -2) {
                final int finalCode = code;
                final String finalDetail = detail;
                addResult(new DirResult(finalCode, path, finalDetail));
            }
        }
    }

    // --------------- helpers ---------------
    private void addResult(DirResult result) {
        runOnUiThread(() -> {
            mResults.add(result);
            mAdapter.notifyDataSetChanged();
        });
    }
}
