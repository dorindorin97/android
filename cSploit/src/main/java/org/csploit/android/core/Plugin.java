/*
 * This file is part of the dSploit.
 *
 * Copyleft of Simone Margaritelli aka evilsocket <evilsocket@gmail.com>
 *
 * dSploit is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * dSploit is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with dSploit.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.csploit.android.core;

import android.content.Context;
import android.os.Bundle;
import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.appcompat.app.ActionBar;
import androidx.appcompat.app.AppCompatActivity;
import android.view.MenuItem;

import org.csploit.android.R;
import org.csploit.android.helpers.LoggingHelper;
import org.csploit.android.net.Target;
import org.csploit.android.net.metasploit.RPCClient;

import java.util.Arrays;

/**
 * Base class for all cSploit plugins.
 * Provides common functionality for plugin activities.
 */
public abstract class Plugin extends AppCompatActivity implements IPlugin {
  public static final int NO_LAYOUT = -1;
  protected static final String TAG = "Plugin";

  private final int mNameStringId;
  private final int mDescriptionStringId;
  private final Target.Type[] mAllowedTargetTypes;
  private final int mLayoutId;
  private final int mIconId;
  protected Child mProcess = null;
  private boolean mIsActive = false;

  public Plugin(int nameStringId, int descStringId, Target.Type[] allowedTargetTypes, int layoutId, int iconResourceId) {
    mNameStringId = nameStringId;
    mDescriptionStringId = descStringId;
    mAllowedTargetTypes = Arrays.copyOf(allowedTargetTypes, allowedTargetTypes.length);
    mLayoutId = layoutId;
    mIconId = iconResourceId;
  }

  public Plugin(int nameStringId, int descStringId, Target.Type[] allowedTargetTypes, int layoutId) {
    this(nameStringId, descStringId, allowedTargetTypes, layoutId, R.drawable.action_plugin);
  }

  public int getName() {
    return mNameStringId;
  }

  public int getDescription() {
    return mDescriptionStringId;
  }

  @NonNull
  public Target.Type[] getAllowedTargetTypes() {
    return Arrays.copyOf(mAllowedTargetTypes, mAllowedTargetTypes.length);
  }

  public int getIconResourceId() {
    return mIconId;
  }

  public boolean isAllowedTarget(@Nullable Target target) {
    if (target == null) {
      return false;
    }
    for (Target.Type type : mAllowedTargetTypes) {
      if (type == target.getType()) {
        return true;
      }
    }
    return false;
  }

  public boolean hasLayoutToShow() {
    return mLayoutId != NO_LAYOUT;
  }

  /**
   * Check if this plugin is currently active/running
   * @return true if the plugin has an active process
   */
  public boolean isActive() {
    return mIsActive && mProcess != null;
  }

  /**
   * Stop any running process
   */
  protected void stopProcess() {
    if (mProcess != null) {
      try {
        mProcess.kill();
      } catch (Exception e) {
        LoggingHelper.w(TAG, "Error stopping process", e);
      }
      mProcess = null;
    }
    mIsActive = false;
  }

  /**
   * Called when the plugin is started (process begins)
   */
  protected void onPluginStarted() {
    mIsActive = true;
    LoggingHelper.d(TAG, getString(mNameStringId) + " started");
  }

  /**
   * Called when the plugin is stopped
   */
  protected void onPluginStopped() {
    mIsActive = false;
    LoggingHelper.d(TAG, getString(mNameStringId) + " stopped");
  }

  @Override
  protected void onResume() {
    super.onResume();
  }

  @Override
  protected void onPause() {
    super.onPause();
  }

  @Override
  protected void onDestroy() {
    stopProcess();
    super.onDestroy();
  }

  @Override
  public void onTargetSelected(Object target) {
    // Override in subclasses that need target selection notification
  }

  @Override
  public boolean supportsTargetType(String targetType) {
    for (Target.Type type : mAllowedTargetTypes) {
      if (type.name().equalsIgnoreCase(targetType)) return true;
    }
    return false;
  }

  @Override
  public String getPluginName() {
    return getClass().getSimpleName();
  }

  public void onActionClick(Context context) {
    // Override in subclasses
  }

  @Override
  public void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    
    Target currentTarget = System.getCurrentTarget();
    String targetName = currentTarget != null ? currentTarget.toString() : "Unknown";
    setTitle(targetName + " > " + getString(mNameStringId));
    
    if (mLayoutId != NO_LAYOUT) {
      setContentView(mLayoutId);
    }
    
    ActionBar actionBar = getSupportActionBar();
    if (actionBar != null) {
      actionBar.setDisplayHomeAsUpEnabled(true);
    }
  }

  @Override
  public boolean onOptionsItemSelected(@NonNull MenuItem item) {
    if (item.getItemId() == android.R.id.home) {
      onBackPressed();
      return true;
    }
    return super.onOptionsItemSelected(item);
  }

  @Override
  public void onBackPressed() {
    stopProcess();
    super.onBackPressed();
    overridePendingTransition(R.anim.slide_in_left, R.anim.slide_out_left);
  }

  /**
   * Called when RPC client connection state changes
   * @param currentValue new RPC client or null if disconnected
   */
  public void onRpcChange(@Nullable RPCClient currentValue) {
    // Override in subclasses that need RPC notifications
  }
}
