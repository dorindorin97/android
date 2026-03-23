package org.csploit.android.plugins;

import android.content.SharedPreferences;
import android.os.Bundle;
import android.view.View;
import android.widget.EditText;
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

import java.net.InetAddress;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Ping Tool — sends a configurable number of ICMP echo requests using
 * InetAddress.isReachable() and displays per-packet RTT, then prints
 * summary statistics (min/avg/max RTT, packets sent/received, loss %).
 */
public class PingTool extends Plugin {
    private static final String TAG = "PingTool";
    private static final int DEFAULT_COUNT   = 10;
    private static final int TIMEOUT_MS      = 2000;
    private static final int BETWEEN_MS      = 500;

    private FloatingActionButton mToggleButton;
    private ProgressBar mProgress;
    private TextView mOutput;
    private EditText mCountInput;
    private final AtomicBoolean mRunning = new AtomicBoolean(false);
    private Future<?> mJob;

    public PingTool() {
        super(
            R.string.ping_tool,
            R.string.ping_tool_desc,
            new Target.Type[]{Target.Type.ENDPOINT, Target.Type.REMOTE},
            R.layout.plugin_ping_tool,
            R.drawable.action_traceroute
        );
    }

    @Override
    public void onCreate(Bundle savedInstanceState) {
        SharedPreferences prefs = getSharedPreferences("THEME", 0);
        setTheme(prefs.getBoolean("isDark", false) ? R.style.DarkTheme : R.style.AppTheme);
        super.onCreate(savedInstanceState);

        mToggleButton = findViewById(R.id.pingToggleButton);
        mProgress     = findViewById(R.id.pingActivity);
        mOutput       = findViewById(R.id.pingOutput);
        mCountInput   = findViewById(R.id.pingCountInput);

        Target t = System.getCurrentTarget();
        String ip = t != null ? t.getAddress().getHostAddress() : "?";
        mOutput.setText("PING " + ip + " (" + DEFAULT_COUNT + " packets)\n");

        mToggleButton.setOnClickListener(v -> {
            if (mRunning.get()) stopPing();
            else                startPing();
        });
    }

    @Override
    public void onBackPressed() {
        stopPing();
        super.onBackPressed();
        overridePendingTransition(R.anim.fadeout, R.anim.fadein);
    }

    // ── Ping control ──────────────────────────────────────────────────────────

    private void startPing() {
        Target target = System.getCurrentTarget();
        if (target == null) return;

        int count = DEFAULT_COUNT;
        try { count = Integer.parseInt(mCountInput.getText().toString().trim()); }
        catch (NumberFormatException ignored) {}
        count = Math.max(1, Math.min(count, 100));

        mRunning.set(true);
        runOnUiThread(() -> mOutput.setText(""));
        mProgress.setVisibility(View.VISIBLE);
        mProgress.setMax(count);
        mProgress.setProgress(0);
        AnimationHelper.fadeIn(mProgress, 200);
        mToggleButton.setImageDrawable(
            ContextCompat.getDrawable(this, R.drawable.ic_stop_24dp));

        final String ip = target.getAddress().getHostAddress();
        final int finalCount = count;

        if (BuildConfig.DEBUG) {
            mJob = ThreadHelper.submit(() -> {
                emitDebugPing(ip, finalCount);
                runOnUiThread(this::onPingFinished);
            });
            return;
        }

        mJob = ThreadHelper.submit(() -> {
            doPing(ip, finalCount);
            runOnUiThread(this::onPingFinished);
        });
    }

    private void stopPing() {
        mRunning.set(false);
        if (mJob != null) { mJob.cancel(true); mJob = null; }
        onPingFinished();
    }

    private void onPingFinished() {
        mRunning.set(false);
        AnimationHelper.fadeOut(mProgress, 200, () -> mProgress.setVisibility(View.INVISIBLE));
        mToggleButton.setImageDrawable(
            ContextCompat.getDrawable(this, R.drawable.ic_play_arrow_24dp));
    }

    // ── Ping logic ────────────────────────────────────────────────────────────

    private void doPing(String ip, int count) {
        append("PING " + ip + ": " + count + " packets\n\n");

        List<Long> rtts  = new ArrayList<>();
        int lost = 0;

        try {
            InetAddress addr = InetAddress.getByName(ip);
            for (int i = 1; i <= count; i++) {
                if (!mRunning.get()) break;
                long start = java.lang.System.currentTimeMillis();
                boolean reachable = addr.isReachable(TIMEOUT_MS);
                long rtt = java.lang.System.currentTimeMillis() - start;

                final int seq = i;
                if (reachable) {
                    rtts.add(rtt);
                    final long fRtt = rtt;
                    append(String.format("seq=%-3d  time=%d ms\n", seq, fRtt));
                } else {
                    lost++;
                    append(String.format("seq=%-3d  timeout\n", seq));
                }

                final int progress = i;
                runOnUiThread(() -> mProgress.setProgress(progress));

                if (i < count && mRunning.get()) {
                    try { Thread.sleep(BETWEEN_MS); } catch (InterruptedException ignored) { break; }
                }
            }
        } catch (Exception e) {
            append("Error: " + e.getMessage() + "\n");
        }

        // Summary
        int sent     = rtts.size() + lost;
        int received = rtts.size();
        double loss  = sent > 0 ? (lost * 100.0 / sent) : 100.0;

        append("\n--- " + ip + " ping statistics ---\n");
        append(String.format("%d packets transmitted, %d received, %.0f%% packet loss\n",
            sent, received, loss));

        if (!rtts.isEmpty()) {
            long min = rtts.stream().mapToLong(Long::longValue).min().orElse(0);
            long max = rtts.stream().mapToLong(Long::longValue).max().orElse(0);
            double avg = rtts.stream().mapToLong(Long::longValue).average().orElse(0);
            append(String.format("rtt min/avg/max = %d/%.1f/%d ms\n", min, avg, max));
        }
    }

    // ── Debug helpers ─────────────────────────────────────────────────────────

    private void emitDebugPing(String ip, int count) {
        append("PING " + ip + ": " + count + " packets\n\n");
        long[] fakertts = {12, 14, 11, 13, 15, 12, 14, 11, 100, 13};
        for (int i = 1; i <= Math.min(count, fakertts.length); i++) {
            if (!mRunning.get()) break;
            final long rtt = fakertts[i-1];
            final int seq = i;
            append(String.format("seq=%-3d  time=%d ms\n", seq, rtt));
            final int p = i;
            runOnUiThread(() -> mProgress.setProgress(p));
            try { Thread.sleep(200); } catch (InterruptedException ignored) { break; }
        }
        append("\n--- " + ip + " ping statistics ---\n");
        append("10 packets transmitted, 10 received, 0% packet loss\n");
        append("rtt min/avg/max = 11/12.5/100 ms\n");
    }

    // ── UI helpers ────────────────────────────────────────────────────────────

    private void append(String text) {
        runOnUiThread(() -> mOutput.append(text));
    }
}
