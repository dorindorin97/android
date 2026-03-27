package org.csploit.android.plugins;

import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothClass;
import android.bluetooth.BluetoothDevice;
import android.content.BroadcastReceiver;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
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
import org.csploit.android.net.Target;

import java.util.ArrayList;
import java.util.List;

public class BluetoothScanner extends Plugin {

    // --------------- result model ---------------
    public static class BtResult {
        public String name;
        public String address;
        public String deviceClass;
        public String bondState;

        public BtResult(String name, String address, String deviceClass, String bondState) {
            this.name = name;
            this.address = address;
            this.deviceClass = deviceClass;
            this.bondState = bondState;
        }
    }

    // --------------- adapter ---------------
    private class BtAdapter extends ArrayAdapter<BtResult> {
        BtAdapter(List<BtResult> items) {
            super(BluetoothScanner.this, R.layout.plugin_bluetooth_scanner_item, items);
        }

        @Override
        public View getView(int position, View convertView, android.view.ViewGroup parent) {
            if (convertView == null) {
                convertView = getLayoutInflater().inflate(R.layout.plugin_bluetooth_scanner_item, parent, false);
            }
            BtResult r = getItem(position);
            TextView nameView  = convertView.findViewById(R.id.btItemName);
            TextView addrView  = convertView.findViewById(R.id.btItemAddress);
            TextView classView = convertView.findViewById(R.id.btItemClass);
            if (r != null) {
                nameView.setText(r.name.isEmpty() ? "<unknown>" : r.name);
                addrView.setText(r.address);
                classView.setText(r.deviceClass + "  [" + r.bondState + "]");
                boolean bonded = "BONDED".equals(r.bondState);
                int color = bonded
                        ? ContextCompat.getColor(BluetoothScanner.this, R.color.app_color)
                        : 0xFF555555;
                nameView.setTextColor(color);
            }
            return convertView;
        }
    }

    // --------------- fields ---------------
    private FloatingActionButton mFab;
    private View mProgress;
    private ListView mList;
    private final List<BtResult> mResults = new ArrayList<>();
    private BtAdapter mAdapter;
    private BluetoothAdapter mBluetoothAdapter;
    private BroadcastReceiver mReceiver;
    private boolean mDiscovering = false;

    // --------------- constructor ---------------
    public BluetoothScanner() {
        super(R.string.bluetooth_scanner, R.string.bluetooth_scanner_desc,
                new Target.Type[]{Target.Type.NETWORK},
                R.layout.plugin_bluetooth_scanner, R.drawable.action_scanner);
    }

    // --------------- lifecycle ---------------
    @Override
    public void onCreate(Bundle savedInstanceState) {
        SharedPreferences prefs = getSharedPreferences("THEME", MODE_PRIVATE);
        int theme = prefs.getInt("theme", R.style.AppTheme);
        setTheme(theme);

        super.onCreate(savedInstanceState);

        mFab = findViewById(R.id.btToggleButton);
        mProgress = findViewById(R.id.btActivity);
        mList = findViewById(android.R.id.list);

        mAdapter = new BtAdapter(mResults);
        mList.setAdapter(mAdapter);

        mBluetoothAdapter = BluetoothAdapter.getDefaultAdapter();

        mReceiver = new BroadcastReceiver() {
            @Override
            public void onReceive(Context context, Intent intent) {
                String action = intent.getAction();
                if (BluetoothDevice.ACTION_FOUND.equals(action)) {
                    BluetoothDevice device = intent.getParcelableExtra(BluetoothDevice.EXTRA_DEVICE);
                    if (device != null) {
                        String name = device.getName() != null ? device.getName() : "";
                        String address = device.getAddress() != null ? device.getAddress() : "";
                        String devClass = resolveClass(device);
                        String bond = resolveBondState(device.getBondState());
                        BtResult result = new BtResult(name, address, devClass, bond);
                        // Avoid duplicates
                        boolean dup = false;
                        for (BtResult r : mResults) {
                            if (r.address.equals(address)) { dup = true; break; }
                        }
                        if (!dup) addResult(result);
                    }
                } else if (BluetoothAdapter.ACTION_DISCOVERY_STARTED.equals(action)) {
                    runOnUiThread(() -> {
                        mProgress.setVisibility(View.VISIBLE);
                        mFab.setImageDrawable(ContextCompat.getDrawable(BluetoothScanner.this, R.drawable.ic_stop_24dp));
                    });
                } else if (BluetoothAdapter.ACTION_DISCOVERY_FINISHED.equals(action)) {
                    stopScan();
                }
            }
        };

        mFab.setOnClickListener(v -> {
            if (mDiscovering) {
                stopScan();
            } else {
                startScan();
            }
        });
    }

    @Override
    public void onDestroy() {
        stopScan();
        super.onDestroy();
    }

    @Override
    public void onBackPressed() {
        stopScan();
        super.onBackPressed();
        overridePendingTransition(R.anim.fadeout, R.anim.fadein);
    }

    // --------------- scan control ---------------
    private void startScan() {
        if (BuildConfig.DEBUG) {
            emitDebug();
            return;
        }

        if (mBluetoothAdapter == null) {
            addResult(new BtResult("Bluetooth not supported", "", "", ""));
            return;
        }
        if (!mBluetoothAdapter.isEnabled()) {
            addResult(new BtResult("Bluetooth disabled", "", "Enable Bluetooth to scan", ""));
            return;
        }

        mDiscovering = true;
        mResults.clear();
        mAdapter.notifyDataSetChanged();

        IntentFilter filter = new IntentFilter();
        filter.addAction(BluetoothDevice.ACTION_FOUND);
        filter.addAction(BluetoothAdapter.ACTION_DISCOVERY_STARTED);
        filter.addAction(BluetoothAdapter.ACTION_DISCOVERY_FINISHED);
        registerReceiver(mReceiver, filter);

        if (mBluetoothAdapter.isDiscovering()) {
            mBluetoothAdapter.cancelDiscovery();
        }
        mBluetoothAdapter.startDiscovery();
    }

    private void stopScan() {
        mDiscovering = false;
        if (mBluetoothAdapter != null) {
            try { mBluetoothAdapter.cancelDiscovery(); } catch (Exception ignored) {}
        }
        try { unregisterReceiver(mReceiver); } catch (Exception ignored) {}
        runOnUiThread(() -> {
            mProgress.setVisibility(View.INVISIBLE);
            mFab.setImageDrawable(ContextCompat.getDrawable(BluetoothScanner.this, R.drawable.ic_play_arrow_24dp));
        });
    }

    // --------------- debug ---------------
    private void emitDebug() {
        mResults.clear();
        mResults.add(new BtResult("iPhone 14", "AA:BB:CC:11:22:33", "PHONE", "NOT_BONDED"));
        mResults.add(new BtResult("MacBook Pro", "AA:BB:CC:44:55:66", "COMPUTER", "BONDED"));
        mResults.add(new BtResult("AirPods Pro", "AA:BB:CC:77:88:99", "AUDIO_VIDEO", "BONDED"));
        mResults.add(new BtResult("", "AA:BB:CC:AA:BB:CC", "UNCATEGORIZED", "NOT_BONDED"));
        mAdapter.notifyDataSetChanged();
    }

    // --------------- helpers ---------------
    private String resolveClass(BluetoothDevice device) {
        try {
            BluetoothClass btClass = device.getBluetoothClass();
            if (btClass == null) return "UNCATEGORIZED";
            int major = btClass.getMajorDeviceClass();
            switch (major) {
                case BluetoothClass.Device.Major.PHONE:       return "PHONE";
                case BluetoothClass.Device.Major.COMPUTER:    return "COMPUTER";
                case BluetoothClass.Device.Major.AUDIO_VIDEO: return "AUDIO_VIDEO";
                case BluetoothClass.Device.Major.NETWORKING:  return "NETWORKING";
                case BluetoothClass.Device.Major.PERIPHERAL:  return "PERIPHERAL";
                case BluetoothClass.Device.Major.IMAGING:     return "IMAGING";
                case BluetoothClass.Device.Major.WEARABLE:    return "WEARABLE";
                case BluetoothClass.Device.Major.TOY:         return "TOY";
                case BluetoothClass.Device.Major.HEALTH:      return "HEALTH";
                default:                                       return "UNCATEGORIZED";
            }
        } catch (Exception e) {
            return "UNCATEGORIZED";
        }
    }

    private String resolveBondState(int state) {
        switch (state) {
            case BluetoothDevice.BOND_BONDED:  return "BONDED";
            case BluetoothDevice.BOND_BONDING: return "BONDING";
            default:                            return "NOT_BONDED";
        }
    }

    private void addResult(BtResult result) {
        runOnUiThread(() -> {
            mResults.add(result);
            mAdapter.notifyDataSetChanged();
        });
    }
}
