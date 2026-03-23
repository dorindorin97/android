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
import org.csploit.android.helpers.AnimationHelper;
import org.csploit.android.helpers.ThreadHelper;
import org.csploit.android.net.Target;

import java.net.Inet6Address;
import java.net.InetAddress;
import java.net.NetworkInterface;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;

public class Ipv6Scanner extends Plugin {

    // --------------- result model ---------------
    public static class Ipv6Result {
        public String address;
        public String hostname;
        public String detail;

        public Ipv6Result(String address, String hostname, String detail) {
            this.address = address;
            this.hostname = hostname;
            this.detail = detail;
        }
    }

    // --------------- adapter ---------------
    private class Ipv6Adapter extends ArrayAdapter<Ipv6Result> {
        Ipv6Adapter(List<Ipv6Result> items) {
            super(Ipv6Scanner.this, R.layout.plugin_ipv6_scanner_item, items);
        }

        @Override
        public View getView(int position, View convertView, android.view.ViewGroup parent) {
            if (convertView == null) {
                convertView = getLayoutInflater().inflate(R.layout.plugin_ipv6_scanner_item, parent, false);
            }
            Ipv6Result r = getItem(position);
            TextView addrView = convertView.findViewById(R.id.ipv6ItemAddress);
            TextView detailView = convertView.findViewById(R.id.ipv6ItemDetail);
            if (r != null) {
                addrView.setText(r.address + (r.hostname.isEmpty() ? "" : " (" + r.hostname + ")"));
                detailView.setText(r.detail);
                addrView.setTextColor(ContextCompat.getColor(Ipv6Scanner.this, R.color.app_color));
            }
            return convertView;
        }
    }

    // --------------- fields ---------------
    private FloatingActionButton mFab;
    private View mProgress;
    private ListView mList;
    private final List<Ipv6Result> mResults = new ArrayList<>();
    private Ipv6Adapter mAdapter;
    private Future<?> mJob;
    private final AtomicBoolean mRunning = new AtomicBoolean(false);

    // --------------- constructor ---------------
    public Ipv6Scanner() {
        super(R.string.ipv6_scanner, R.string.ipv6_scanner_desc,
                new Target.Type[]{Target.Type.NETWORK},
                R.layout.plugin_ipv6_scanner, R.drawable.action_scanner);
    }

    // --------------- lifecycle ---------------
    @Override
    public void onCreate(Bundle savedInstanceState) {
        SharedPreferences prefs = getSharedPreferences("THEME", MODE_PRIVATE);
        int theme = prefs.getInt("theme", R.style.AppTheme);
        setTheme(theme);

        super.onCreate(savedInstanceState);

        mFab = findViewById(R.id.ipv6ToggleButton);
        mProgress = findViewById(R.id.ipv6Activity);
        mList = findViewById(android.R.id.list);

        mAdapter = new Ipv6Adapter(mResults);
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

        mJob = ThreadHelper.submit(() -> {
            try {
                scan();
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
        addResult(new Ipv6Result("fe80::1a2b:3c4d:5e6f:7890", "", "Local address (this device)"));
        addResult(new Ipv6Result("fe80::1", "router.local", "Reachable"));
        addResult(new Ipv6Result("fe80::2", "desktop.local", "Reachable"));
        addResult(new Ipv6Result("fe80::42", "", "Reachable"));
    }

    // --------------- core logic ---------------
    private void scan() throws Exception {
        // Find local IPv6 link-local addresses and interface name
        String ifaceName = null;
        List<String> localAddrs = new ArrayList<>();

        for (NetworkInterface iface : Collections.list(NetworkInterface.getNetworkInterfaces())) {
            if (iface.isLoopback() || !iface.isUp()) continue;
            for (java.net.InterfaceAddress ia : iface.getInterfaceAddresses()) {
                InetAddress addr = ia.getAddress();
                if (addr instanceof Inet6Address) {
                    String addrStr = addr.getHostAddress();
                    if (addrStr.startsWith("fe80:") || addrStr.startsWith("FE80:")) {
                        localAddrs.add(addrStr);
                        ifaceName = iface.getName();
                        addResult(new Ipv6Result(addrStr, "", "Local address (this device)"));
                    }
                }
            }
        }

        if (!mRunning.get()) return;

        // Probe multicast addresses
        String[] multicasts = {"ff02::1", "ff02::2", "ff02::fb"};
        String[] multicastNames = {"All nodes", "All routers", "mDNS"};
        for (int i = 0; i < multicasts.length; i++) {
            if (!mRunning.get()) break;
            try {
                InetAddress mc = InetAddress.getByName(multicasts[i]);
                boolean reachable = mc.isReachable(1000);
                if (reachable) {
                    addResult(new Ipv6Result(multicasts[i], multicastNames[i], "Multicast reachable"));
                }
            } catch (Exception ignored) {}
        }

        if (!mRunning.get()) return;

        final String iface = ifaceName;
        // Probe fe80::1 through fe80::ff in parallel
        ExecutorService pool = Executors.newFixedThreadPool(32);
        final Set<String> seen = new HashSet<>(localAddrs);

        for (int i = 1; i <= 0xFF; i++) {
            if (!mRunning.get()) break;
            final String suffix = String.format("%x", i);
            final String addrStr = (iface != null)
                    ? "fe80::" + suffix + "%" + iface
                    : "fe80::" + suffix;
            pool.submit(() -> {
                if (!mRunning.get()) return;
                try {
                    InetAddress addr = InetAddress.getByName(addrStr);
                    if (addr.isReachable(500)) {
                        String display = addr.getHostAddress();
                        synchronized (seen) {
                            if (seen.contains(display)) return;
                            seen.add(display);
                        }
                        String hostname = "";
                        try {
                            String canon = addr.getCanonicalHostName();
                            if (!canon.equals(display)) hostname = canon;
                        } catch (Exception ignored) {}
                        addResult(new Ipv6Result(display, hostname, "Reachable"));
                    }
                } catch (Exception ignored) {}
            });
        }

        pool.shutdown();
        try {
            pool.awaitTermination(30, TimeUnit.SECONDS);
        } catch (InterruptedException ignored) {}
    }

    // --------------- helpers ---------------
    private void addResult(Ipv6Result result) {
        runOnUiThread(() -> {
            mResults.add(result);
            mAdapter.notifyDataSetChanged();
        });
    }
}
