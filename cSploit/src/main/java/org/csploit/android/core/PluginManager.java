package org.csploit.android.core;

import android.util.Log;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import org.csploit.android.net.Target;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Manages plugin registration, lookup, and lifecycle management.
 * Extracted from System.java to improve separation of concerns.
 */
public class PluginManager {
    private static final String TAG = "PluginManager";

    private final List<IPlugin> registeredPlugins;
    private volatile IPlugin currentPlugin;

    public PluginManager() {
        this.registeredPlugins = new CopyOnWriteArrayList<>();
        this.currentPlugin = null;
    }

    /**
     * Register a plugin.
     *
     * @param plugin The plugin to register
     * @throws IllegalArgumentException if plugin is null
     */
    public void registerPlugin(@NonNull IPlugin plugin) {
        if (plugin == null) {
            throw new IllegalArgumentException("Plugin cannot be null");
        }

        if (!registeredPlugins.contains(plugin)) {
            registeredPlugins.add(plugin);
            Log.d(TAG, "Plugin registered: " + plugin.getClass().getSimpleName());
        }
    }

    /**
     * Unregister a plugin.
     *
     * @param plugin The plugin to unregister
     * @return true if plugin was registered and removed, false otherwise
     */
    public boolean unregisterPlugin(@NonNull IPlugin plugin) {
        if (plugin == null) {
            return false;
        }

        boolean removed = registeredPlugins.remove(plugin);
        if (removed) {
            if (currentPlugin == plugin) {
                currentPlugin = null;
            }
            Log.d(TAG, "Plugin unregistered: " + plugin.getClass().getSimpleName());
        }
        return removed;
    }

    /**
     * Get all registered plugins.
     *
     * @return Unmodifiable list of registered plugins
     */
    @NonNull
    public List<IPlugin> getAllPlugins() {
        return Collections.unmodifiableList(new ArrayList<>(registeredPlugins));
    }

    /**
     * Get the currently active plugin.
     *
     * @return The current plugin or null if none is active
     */
    @Nullable
    public IPlugin getCurrentPlugin() {
        return currentPlugin;
    }

    /**
     * Set the current active plugin.
     *
     * @param plugin The plugin to set as current
     * @return true if successfully set, false otherwise
     */
    public boolean setCurrentPlugin(@Nullable IPlugin plugin) {
        if (plugin != null && !registeredPlugins.contains(plugin)) {
            Log.w(TAG, "Attempting to set unregistered plugin as current");
            return false;
        }

        this.currentPlugin = plugin;
        if (plugin != null) {
            Log.d(TAG, "Current plugin set to: " + plugin.getClass().getSimpleName());
        }
        return true;
    }

    /**
     * Get total count of registered plugins.
     *
     * @return Number of registered plugins
     */
    public int getPluginCount() {
        return registeredPlugins.size();
    }

    /**
     * Check if a specific plugin is registered.
     *
     * @param plugin The plugin to check
     * @return true if plugin is registered
     */
    public boolean isPluginRegistered(@NonNull IPlugin plugin) {
        return registeredPlugins.contains(plugin);
    }

    /**
     * Clear all registered plugins.
     */
    public void clearAllPlugins() {
        registeredPlugins.clear();
        currentPlugin = null;
        Log.d(TAG, "All plugins cleared");
    }

    /**
     * Find a plugin by class name.
     *
     * @param className The fully qualified class name
     * @return The plugin if found, null otherwise
     */
    @Nullable
    public IPlugin findPluginByClass(@NonNull String className) {
        for (IPlugin plugin : registeredPlugins) {
            if (plugin.getClass().getName().equals(className)) {
                return plugin;
            }
        }
        return null;
    }

    /**
     * Find a plugin by simple class name.
     *
     * @param simpleName The simple class name (e.g., "LoginCracker")
     * @return The plugin if found, null otherwise
     */
    @Nullable
    public IPlugin findPluginBySimpleName(@NonNull String simpleName) {
        for (IPlugin plugin : registeredPlugins) {
            if (plugin.getClass().getSimpleName().equals(simpleName)) {
                return plugin;
            }
        }
        return null;
    }

    /**
     * Get plugin count by target type.
     *
     * @param targetType The target type to filter by
     * @return Number of plugins supporting the target type
     */
    public int getPluginCountByTargetType(@NonNull String targetType) {
        int count = 0;
        for (IPlugin plugin : registeredPlugins) {
            if (plugin instanceof Plugin) {
                for (Target.Type type : ((Plugin) plugin).getAllowedTargetTypes()) {
                    if (type.name().equals(targetType)) {
                        count++;
                        break;
                    }
                }
            } else if (plugin.supportsTargetType(targetType)) {
                count++;
            }
        }
        return count;
    }

    /**
     * Get plugin status summary.
     *
     * @return A string describing the current plugin management state
     */
    @NonNull
    public String getStatusSummary() {
        return String.format(
                "PluginManager [Registered: %d, Current: %s]",
                registeredPlugins.size(),
                currentPlugin != null ? currentPlugin.getClass().getSimpleName() : "None"
        );
    }
}
