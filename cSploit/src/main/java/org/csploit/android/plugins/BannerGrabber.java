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

import java.io.InputStream;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Banner Grabber — connects to each open port on the target via raw TCP and
 * reads the first bytes the service sends (the "banner").  Banners often
 * reveal exact software versions useful for exploit matching.
 *
 * For ports that do not send a banner automatically an HTTP HEAD request is
 * sent as a probe to elicit a response.
 */
public class BannerGrabber extends Plugin {
    private static final String TAG = "BannerGrabber";
    private static final int CONNECT_TIMEOUT_MS = 4000;
    private static final int READ_TIMEOUT_MS    = 3000;
    private static final int MAX_BANNER_BYTES   = 512;

    public static class Banner {
        public enum Kind { OK, EMPTY, ERROR }
        public final int    port;
        public final Kind   kind;
        public final String text;
        Banner(int p, Kind k, String t) { port = p; kind = k; text = t; }
    }

    private FloatingActionButton mToggleButton;
    private ProgressBar mProgress;
    private ListView mListView;
    private BannerAdapter mAdapter;
    private final AtomicBoolean mRunning = new AtomicBoolean(false);
    private Future<?> mJob;

    public BannerGrabber() {
        super(
            R.string.banner_grabber,
            R.string.banner_grabber_desc,
            new Target.Type[]{Target.Type.ENDPOINT, Target.Type.REMOTE},
            R.layout.plugin_banner_grabber,
            R.drawable.action_scanner
        );
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        SharedPreferences prefs = getSharedPreferences("THEME", 0);
        setTheme(prefs.getBoolean("isDark", false) ? R.style.DarkTheme : R.style.AppTheme);
        super.onCreate(savedInstanceState);

        mToggleButton = findViewById(R.id.bannerToggleButton);
        mProgress     = findViewById(R.id.bannerActivity);
        mListView     = findViewById(android.R.id.list);
        mAdapter      = new BannerAdapter();
        mListView.setAdapter(mAdapter);

        mToggleButton.setOnClickListener(v -> {
            if (mRunning.get()) stopGrab();
            else                startGrab();
        });
    }

    @Override
    public void onBackPressed() {
        stopGrab();
        super.onBackPressed();
        overridePendingTransition(R.anim.fadeout, R.anim.fadein);
    }

    // ── Grab control ─────────────────────────────────────────────────────────

    private void startGrab() {
        Target target = System.getCurrentTarget();
        if (target == null) return;

        mRunning.set(true);
        mAdapter.clear();
        mProgress.setVisibility(View.VISIBLE);
        AnimationHelper.fadeIn(mProgress, 200);
        mToggleButton.setImageDrawable(ContextCompat.getDrawable(this, R.drawable.ic_stop_24dp));

        if (BuildConfig.DEBUG) {
            mJob = ThreadHelper.submit(() -> {
                emitDebugBanners();
                runOnUiThread(this::onGrabFinished);
            });
            return;
        }

        final String ip = target.getAddress().getHostAddress();
        final List<Integer> ports = getPortList(target);

        mJob = ThreadHelper.submit(() -> {
            if (ports.isEmpty()) {
                report(new Banner(0, Banner.Kind.EMPTY, "No open ports recorded — run Port Scanner first"));
            } else {
                for (int port : ports) {
                    if (!mRunning.get()) break;
                    grabPort(ip, port);
                }
            }
            runOnUiThread(this::onGrabFinished);
        });
    }

    private void stopGrab() {
        mRunning.set(false);
        if (mJob != null) { mJob.cancel(true); mJob = null; }
        onGrabFinished();
    }

    private void onGrabFinished() {
        mRunning.set(false);
        AnimationHelper.fadeOut(mProgress, 200, () -> mProgress.setVisibility(View.INVISIBLE));
        mToggleButton.setImageDrawable(ContextCompat.getDrawable(this, R.drawable.ic_play_arrow_24dp));
    }

    // ── Banner grab logic ─────────────────────────────────────────────────────

    private void grabPort(String ip, int port) {
        try {
            Socket sock = new Socket();
            sock.connect(new InetSocketAddress(ip, port), CONNECT_TIMEOUT_MS);
            sock.setSoTimeout(READ_TIMEOUT_MS);

            // For HTTP-like ports, send a probe to get a response
            if (isHttpPort(port)) {
                sock.getOutputStream().write(
                    ("HEAD / HTTP/1.0\r\nHost: " + ip + "\r\n\r\n").getBytes(StandardCharsets.UTF_8));
                sock.getOutputStream().flush();
            }

            InputStream in = sock.getInputStream();
            byte[] buf = new byte[MAX_BANNER_BYTES];
            int n = in.read(buf);
            sock.close();

            if (n <= 0) {
                report(new Banner(port, Banner.Kind.EMPTY, "Connected but no banner received"));
                return;
            }

            String raw = new String(buf, 0, n, StandardCharsets.UTF_8)
                .replaceAll("[\\x00-\\x08\\x0B\\x0C\\x0E-\\x1F\\x7F]", ".")
                .trim();
            report(new Banner(port, Banner.Kind.OK, raw));

        } catch (java.net.ConnectException e) {
            // port refused — skip silently
        } catch (java.net.SocketTimeoutException e) {
            report(new Banner(port, Banner.Kind.EMPTY, "Timeout — no banner"));
        } catch (Exception e) {
            report(new Banner(port, Banner.Kind.ERROR, e.getMessage()));
        }
    }

    private boolean isHttpPort(int port) {
        return port == 80 || port == 8080 || port == 8888 || port == 8000
            || port == 443 || port == 8443;
    }

    private List<Integer> getPortList(Target t) {
        List<Integer> result = new ArrayList<>();
        for (Target.Port p : t.getOpenPorts()) result.add(p.getNumber());
        return result;
    }

    // ── Debug helpers ─────────────────────────────────────────────────────────

    private void emitDebugBanners() {
        report(new Banner(21,  Banner.Kind.OK,    "220 vsftpd 3.0.5"));
        report(new Banner(22,  Banner.Kind.OK,    "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"));
        report(new Banner(25,  Banner.Kind.OK,    "220 mail.example.com ESMTP Postfix (Ubuntu)"));
        report(new Banner(80,  Banner.Kind.OK,    "HTTP/1.1 200 OK\r\nServer: Apache/2.4.57 (Ubuntu)\r\nX-Powered-By: PHP/8.1.2"));
        report(new Banner(443, Banner.Kind.OK,    "HTTP/1.1 200 OK\r\nServer: nginx/1.24.0"));
        report(new Banner(3306,Banner.Kind.OK,    "5.7.42-0ubuntu0.18.04.1 - MySQL Community Server (GPL)"));
        report(new Banner(5432,Banner.Kind.EMPTY, "Timeout — no banner"));
    }

    // ── UI helpers ────────────────────────────────────────────────────────────

    private void report(Banner b) {
        runOnUiThread(() -> {
            mAdapter.add(b);
            mAdapter.notifyDataSetChanged();
        });
    }

    private class BannerAdapter extends ArrayAdapter<Banner> {
        BannerAdapter() {
            super(BannerGrabber.this, R.layout.plugin_banner_grabber_item, new ArrayList<>());
        }

        @Override
        public View getView(int position, View convertView, ViewGroup parent) {
            if (convertView == null)
                convertView = LayoutInflater.from(getContext())
                    .inflate(R.layout.plugin_banner_grabber_item, parent, false);

            Banner b = getItem(position);
            TextView tvPort   = convertView.findViewById(R.id.bannerItemPort);
            TextView tvBanner = convertView.findViewById(R.id.bannerItemBanner);

            tvPort.setText(b.port > 0 ? ":" + b.port : "");
            tvBanner.setText(b.text);

            int color;
            switch (b.kind) {
                case OK:    color = ContextCompat.getColor(getContext(), R.color.app_color); break;
                case ERROR: color = Color.parseColor("#D32F2F"); break;
                default:    color = Color.parseColor("#757575"); break;
            }
            tvPort.setTextColor(color);

            return convertView;
        }
    }
}
