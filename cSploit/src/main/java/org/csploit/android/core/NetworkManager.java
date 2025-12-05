package org.csploit.android.core;

import android.content.Context;
import android.net.ConnectivityManager;
import android.net.NetworkInfo;
import android.net.wifi.WifiInfo;
import android.net.wifi.WifiManager;
import android.util.Log;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import org.csploit.android.net.Network;
import org.csploit.android.net.Target;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Manages network operations and target management.
 * Extracted from System.java to improve separation of concerns.
 * Handles network connectivity checks, target tracking, and network utilities.
 */
public class NetworkManager {
    private static final String TAG = "NetworkManager";

    private final Context context;
    private final List<Target> targets;
    private final List<NetworkStateListener> stateListeners;
    private Network currentNetwork;
    private Target currentTarget;

    /**
     * Listener for network state changes.
     */
    public interface NetworkStateListener {
        void onNetworkConnected(@NonNull Network network);
        void onNetworkDisconnected();
        void onTargetAdded(@NonNull Target target);
        void onTargetRemoved(@NonNull Target target);
    }

    /**
     * Initialize network manager.
     *
     * @param context Application context
     */
    public NetworkManager(@NonNull Context context) {
        this.context = context;
        this.targets = new CopyOnWriteArrayList<>();
        this.stateListeners = new CopyOnWriteArrayList<>();
    }

    /**
     * Check if device is connected to network.
     *
     * @return true if connected to WiFi or mobile network
     */
    public boolean isNetworkConnected() {
        ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        if (cm == null) {
            return false;
        }

        NetworkInfo activeNetwork = cm.getActiveNetworkInfo();
        return activeNetwork != null && activeNetwork.isConnectedOrConnecting();
    }

    /**
     * Check if device is connected to WiFi.
     *
     * @return true if connected to WiFi
     */
    public boolean isWiFiConnected() {
        ConnectivityManager cm = (ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
        if (cm == null) {
            return false;
        }

        NetworkInfo wifiNetwork = cm.getNetworkInfo(ConnectivityManager.TYPE_WIFI);
        return wifiNetwork != null && wifiNetwork.isConnectedOrConnecting();
    }

    /**
     * Get current WiFi information.
     *
     * @return WifiInfo or null if not connected
     */
    @Nullable
    public WifiInfo getWiFiInfo() {
        WifiManager wm = (WifiManager) context.getApplicationContext().getSystemService(Context.WIFI_SERVICE);
        if (wm == null) {
            return null;
        }

        WifiInfo info = wm.getConnectionInfo();
        if (info != null && info.getNetworkId() != -1) {
            return info;
        }
        return null;
    }

    /**
     * Set the current network.
     *
     * @param network The network to set as current
     */
    public void setCurrentNetwork(@Nullable Network network) {
        this.currentNetwork = network;
        if (network != null) {
            Log.d(TAG, "Network changed: " + network.getLocalAddressAsString());
            notifyNetworkConnected(network);
        } else {
            Log.d(TAG, "Network disconnected");
            notifyNetworkDisconnected();
        }
    }

    /**
     * Get the current network.
     *
     * @return The current network or null
     */
    @Nullable
    public Network getCurrentNetwork() {
        return currentNetwork;
    }

    /**
     * Add a target to tracking.
     *
     * @param target The target to add
     */
    public void addTarget(@NonNull Target target) {
        if (target == null) {
            throw new IllegalArgumentException("Target cannot be null");
        }

        if (!targets.contains(target)) {
            targets.add(target);
            Log.d(TAG, "Target added: " + target.toString());
            notifyTargetAdded(target);
        }
    }

    /**
     * Remove a target from tracking.
     *
     * @param target The target to remove
     * @return true if target was tracked and removed
     */
    public boolean removeTarget(@NonNull Target target) {
        boolean removed = targets.remove(target);
        if (removed) {
            if (currentTarget == target) {
                currentTarget = null;
            }
            Log.d(TAG, "Target removed: " + target.toString());
            notifyTargetRemoved(target);
        }
        return removed;
    }

    /**
     * Get all tracked targets.
     *
     * @return Unmodifiable list of targets
     */
    @NonNull
    public List<Target> getAllTargets() {
        return Collections.unmodifiableList(new ArrayList<>(targets));
    }

    /**
     * Get current target.
     *
     * @return The current target or null
     */
    @Nullable
    public Target getCurrentTarget() {
        return currentTarget;
    }

    /**
     * Set current target.
     *
     * @param target The target to set as current
     * @return true if successfully set
     */
    public boolean setCurrentTarget(@Nullable Target target) {
        if (target != null && !targets.contains(target)) {
            Log.w(TAG, "Attempting to set untracked target as current");
            return false;
        }

        this.currentTarget = target;
        if (target != null) {
            Log.d(TAG, "Current target set: " + target.toString());
        }
        return true;
    }

    /**
     * Get target count.
     *
     * @return Number of tracked targets
     */
    public int getTargetCount() {
        return targets.size();
    }

    /**
     * Clear all targets.
     */
    public void clearAllTargets() {
        targets.clear();
        currentTarget = null;
        Log.d(TAG, "All targets cleared");
    }

    /**
     * Add a network state listener.
     *
     * @param listener The listener to add
     */
    public void addStateListener(@NonNull NetworkStateListener listener) {
        if (listener == null) {
            throw new IllegalArgumentException("Listener cannot be null");
        }

        stateListeners.add(listener);
        Log.d(TAG, "Network state listener added");
    }

    /**
     * Remove a network state listener.
     *
     * @param listener The listener to remove
     * @return true if listener was registered and removed
     */
    public boolean removeStateListener(@NonNull NetworkStateListener listener) {
        boolean removed = stateListeners.remove(listener);
        if (removed) {
            Log.d(TAG, "Network state listener removed");
        }
        return removed;
    }

    /**
     * Notify all listeners of network connection.
     */
    private void notifyNetworkConnected(@NonNull Network network) {
        for (NetworkStateListener listener : stateListeners) {
            try {
                listener.onNetworkConnected(network);
            } catch (Exception e) {
                Log.e(TAG, "Error notifying network connected", e);
            }
        }
    }

    /**
     * Notify all listeners of network disconnection.
     */
    private void notifyNetworkDisconnected() {
        for (NetworkStateListener listener : stateListeners) {
            try {
                listener.onNetworkDisconnected();
            } catch (Exception e) {
                Log.e(TAG, "Error notifying network disconnected", e);
            }
        }
    }

    /**
     * Notify all listeners of target addition.
     */
    private void notifyTargetAdded(@NonNull Target target) {
        for (NetworkStateListener listener : stateListeners) {
            try {
                listener.onTargetAdded(target);
            } catch (Exception e) {
                Log.e(TAG, "Error notifying target added", e);
            }
        }
    }

    /**
     * Notify all listeners of target removal.
     */
    private void notifyTargetRemoved(@NonNull Target target) {
        for (NetworkStateListener listener : stateListeners) {
            try {
                listener.onTargetRemoved(target);
            } catch (Exception e) {
                Log.e(TAG, "Error notifying target removed", e);
            }
        }
    }

    /**
     * Get status summary.
     *
     * @return A string describing the current state
     */
    @NonNull
    public String getStatusSummary() {
        return String.format(
                "NetworkManager [Network: %s, Targets: %d, Listeners: %d]",
                currentNetwork != null ? currentNetwork.getLocalAddressAsString() : "None",
                targets.size(),
                stateListeners.size()
        );
    }
}
