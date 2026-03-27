package org.csploit.android.core;

/**
 * Interface for cSploit plugins, enabling testable plugin management
 * without depending on Android Activity lifecycle.
 */
public interface IPlugin {
    void onTargetSelected(Object target);
    boolean supportsTargetType(String targetType);
    String getPluginName();
}
