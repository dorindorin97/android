
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
package org.csploit.android;

import android.Manifest;
import android.app.NotificationChannel;
import android.app.NotificationManager;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.Environment;
import android.provider.Settings;

import java.util.ArrayList;
import androidx.core.app.ActivityCompat;
import androidx.core.content.ContextCompat;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;

import org.csploit.android.helpers.LoggingHelper;
import org.csploit.android.helpers.ToastHelper;

public class MainActivity extends AppCompatActivity {
  private static final String TAG = "MainActivity";

  MainFragment f;
  final static int MY_PERMISSIONS_WANTED = 1;
  final static int MANAGE_STORAGE_REQUEST = 2;
  private boolean mFragmentLoaded = false;

  @Override
  protected void onCreate(Bundle savedInstanceState) {
    super.onCreate(savedInstanceState);
    
    // Create notification channel for Android O+
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
      NotificationChannel mChannel = new NotificationChannel(getString(R.string.csploitChannelId),
              getString(R.string.cSploitChannelDescription), NotificationManager.IMPORTANCE_DEFAULT);
      NotificationManager mNotificationManager =
              (NotificationManager) getSystemService(Context.NOTIFICATION_SERVICE);
      if (mNotificationManager != null) {
          mNotificationManager.createNotificationChannel(mChannel);
      }
    }
    
    // Apply theme
    SharedPreferences themePrefs = getSharedPreferences("THEME", 0);
    if (themePrefs.getBoolean("isDark", false))
      setTheme(R.style.DarkTheme);
    else
      setTheme(R.style.AppTheme);
    
    setContentView(R.layout.main);
    
    // Check permissions before loading fragment
    if (savedInstanceState == null) {
      checkAndRequestPermissions();
    } else {
      // Fragment already exists from saved state
      mFragmentLoaded = true;
    }
  }

  private void checkAndRequestPermissions() {
    // First check storage permission (most important for app functionality)
    if (!hasStoragePermission()) {
      requestStoragePermission();
      return;
    }
    
    // Then check other runtime permissions
    ArrayList<String> requiredPermissions = new ArrayList<>();
    
    // POST_NOTIFICATIONS permission for SDK >= 33
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.TIRAMISU) {
      if (ContextCompat.checkSelfPermission(this, Manifest.permission.POST_NOTIFICATIONS)
              != PackageManager.PERMISSION_GRANTED) {
        requiredPermissions.add(Manifest.permission.POST_NOTIFICATIONS);
      }
    }
    
    if (!requiredPermissions.isEmpty()) {
      ActivityCompat.requestPermissions(this,
              requiredPermissions.toArray(new String[0]),
              MY_PERMISSIONS_WANTED);
    } else {
      // All permissions granted, load the app
      loadMainFragment();
    }
  }
  
  private boolean hasStoragePermission() {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
      // Android 11+ requires MANAGE_EXTERNAL_STORAGE
      return Environment.isExternalStorageManager();
    } else {
      // Android 10 and below uses WRITE_EXTERNAL_STORAGE
      return ContextCompat.checkSelfPermission(this, Manifest.permission.WRITE_EXTERNAL_STORAGE)
              == PackageManager.PERMISSION_GRANTED;
    }
  }
  
  private void requestStoragePermission() {
    if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.R) {
      // Android 11+ - need to open special settings page
      new AlertDialog.Builder(this)
              .setTitle(R.string.storage_permission_title)
              .setMessage(R.string.storage_permission_message)
              .setPositiveButton(R.string.grant_permission, (dialog, which) -> {
                try {
                  Intent intent = new Intent(Settings.ACTION_MANAGE_APP_ALL_FILES_ACCESS_PERMISSION);
                  intent.setData(Uri.parse("package:" + getPackageName()));
                  startActivityForResult(intent, MANAGE_STORAGE_REQUEST);
                } catch (Exception e) {
                  // Fallback for devices that don't support the direct intent
                  Intent intent = new Intent(Settings.ACTION_MANAGE_ALL_FILES_ACCESS_PERMISSION);
                  startActivityForResult(intent, MANAGE_STORAGE_REQUEST);
                }
              })
              .setNegativeButton(android.R.string.cancel, (dialog, which) -> {
                ToastHelper.error(this, getString(R.string.permissions_fail));
                finish();
              })
              .setCancelable(false)
              .show();
    } else {
      // Android 10 and below - use standard permission request
      ActivityCompat.requestPermissions(this,
              new String[]{Manifest.permission.WRITE_EXTERNAL_STORAGE},
              MY_PERMISSIONS_WANTED);
    }
  }
  
  private void loadMainFragment() {
    if (mFragmentLoaded || isFinishing()) {
      return;
    }
    
    if (findViewById(R.id.mainframe) != null) {
      f = new MainFragment();
      getSupportFragmentManager().beginTransaction()
              .add(R.id.mainframe, f).commitAllowingStateLoss();
      mFragmentLoaded = true;
    }
  }

  @Override
  protected void onActivityResult(int requestCode, int resultCode, Intent data) {
    super.onActivityResult(requestCode, resultCode, data);
    
    if (requestCode == MANAGE_STORAGE_REQUEST) {
      // Check if storage permission was granted
      if (hasStoragePermission()) {
        // Continue with other permissions
        checkAndRequestPermissions();
      } else {
        ToastHelper.error(this, getString(R.string.permissions_fail));
        finish();
      }
    }
  }

  @Override
  public void onRequestPermissionsResult(int requestCode,
                                         String permissions[], int[] grantResults) {
    super.onRequestPermissionsResult(requestCode, permissions, grantResults);
    
    if (requestCode == MY_PERMISSIONS_WANTED) {
      if (grantResults.length == 0) {
        // Request was cancelled, try again
        LoggingHelper.w(TAG, "Permission request was cancelled");
        checkAndRequestPermissions();
        return;
      }
      
      // Check if storage permission was in this request (Android < 11)
      boolean storageRequested = false;
      boolean storageGranted = true;
      for (int i = 0; i < permissions.length; i++) {
        if (Manifest.permission.WRITE_EXTERNAL_STORAGE.equals(permissions[i])) {
          storageRequested = true;
          storageGranted = (grantResults[i] == PackageManager.PERMISSION_GRANTED);
          break;
        }
      }
      
      if (storageRequested && !storageGranted) {
        // Storage permission denied - this is required
        ToastHelper.error(this, getString(R.string.permissions_fail));
        finish();
        return;
      }
      
      // For other permissions (like notifications), we continue even if denied
      ToastHelper.success(this, getString(R.string.permissions_succeed));
      loadMainFragment();
    }
  }
}