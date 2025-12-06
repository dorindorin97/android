/*
 * This file is part of cSploit.
 *
 * cSploit is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * cSploit is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with cSploit. If not, see <http://www.gnu.org/licenses/>.
 */

package org.csploit.android.helpers;

import android.content.Context;
import android.content.pm.ApplicationInfo;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.Signature;
import android.os.Build;
import android.provider.Settings;

import androidx.annotation.NonNull;

import java.io.BufferedReader;
import java.io.File;
import java.io.InputStreamReader;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.List;

/**
 * SecurityChecker - Device and app security validation utilities
 * 
 * Provides:
 * - Root detection
 * - Debug mode detection
 * - Emulator detection
 * - APK integrity verification
 * - Developer options detection
 * 
 * Usage:
 * {@code
 * SecurityChecker checker = new SecurityChecker(context);
 * if (!checker.isRooted()) {
 *     showRootRequiredDialog();
 * }
 * }
 */
public final class SecurityChecker {
    private static final String TAG = "SecurityChecker";
    
    // Common su binary locations
    private static final String[] SU_PATHS = {
            "/system/app/Superuser.apk",
            "/sbin/su",
            "/system/bin/su",
            "/system/xbin/su",
            "/data/local/xbin/su",
            "/data/local/bin/su",
            "/system/sd/xbin/su",
            "/system/bin/failsafe/su",
            "/data/local/su",
            "/su/bin/su"
    };
    
    // Known rooting apps
    private static final String[] ROOT_PACKAGES = {
            "com.topjohnwu.magisk",
            "com.koushikdutta.superuser",
            "com.noshufou.android.su",
            "eu.chainfire.supersu",
            "com.thirdparty.superuser",
            "com.yellowes.su"
    };
    
    // Known emulator indicators
    private static final String[] EMULATOR_FILES = {
            "/dev/socket/qemud",
            "/dev/qemu_pipe",
            "/system/lib/libc_malloc_debug_qemu.so",
            "/sys/qemu_trace"
    };
    
    private final Context mContext;
    
    public SecurityChecker(@NonNull Context context) {
        mContext = context.getApplicationContext();
    }
    
    /**
     * Check if device is rooted (comprehensive check)
     * @return true if device appears to be rooted
     */
    public boolean isRooted() {
        return checkSuBinary() || checkRootPackages() || checkRootExec();
    }
    
    /**
     * Quick check for root (less comprehensive but faster)
     * @return true if su binary is found
     */
    public boolean hasRootBinary() {
        return checkSuBinary();
    }
    
    /**
     * Check if running in debug mode
     * @return true if app is debuggable
     */
    public boolean isDebuggable() {
        try {
            return (mContext.getApplicationInfo().flags & ApplicationInfo.FLAG_DEBUGGABLE) != 0;
        } catch (Exception e) {
            LoggingHelper.w(TAG, "Failed to check debuggable flag", e);
            return false;
        }
    }
    
    /**
     * Check if running on an emulator
     * @return true if appears to be an emulator
     */
    public boolean isEmulator() {
        return checkEmulatorFiles() || checkEmulatorBuild() || checkEmulatorProperties();
    }
    
    /**
     * Check if developer options are enabled
     * @return true if developer options are enabled
     */
    public boolean isDeveloperOptionsEnabled() {
        try {
            return Settings.Secure.getInt(mContext.getContentResolver(),
                    Settings.Global.DEVELOPMENT_SETTINGS_ENABLED, 0) != 0;
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Check if USB debugging is enabled
     * @return true if USB debugging is enabled
     */
    public boolean isUsbDebuggingEnabled() {
        try {
            return Settings.Secure.getInt(mContext.getContentResolver(),
                    Settings.Global.ADB_ENABLED, 0) != 0;
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Get APK signature hash (for integrity verification)
     * @return SHA-256 hash of the APK signature
     */
    @NonNull
    public String getApkSignatureHash() {
        try {
            PackageInfo packageInfo;
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                packageInfo = mContext.getPackageManager().getPackageInfo(
                        mContext.getPackageName(),
                        PackageManager.GET_SIGNING_CERTIFICATES
                );
                Signature[] signatures = packageInfo.signingInfo.getApkContentsSigners();
                if (signatures != null && signatures.length > 0) {
                    return sha256(signatures[0].toByteArray());
                }
            } else {
                packageInfo = mContext.getPackageManager().getPackageInfo(
                        mContext.getPackageName(),
                        PackageManager.GET_SIGNATURES
                );
                Signature[] signatures = packageInfo.signatures;
                if (signatures != null && signatures.length > 0) {
                    return sha256(signatures[0].toByteArray());
                }
            }
        } catch (Exception e) {
            LoggingHelper.w(TAG, "Failed to get APK signature", e);
        }
        return "";
    }
    
    /**
     * Get list of security issues found
     * @return list of security issue descriptions
     */
    @NonNull
    public List<String> getSecurityIssues() {
        List<String> issues = new ArrayList<>();
        
        if (!isRooted()) {
            issues.add("Device is not rooted (required for cSploit)");
        }
        
        if (isDebuggable()) {
            issues.add("App is running in debug mode");
        }
        
        if (isEmulator()) {
            issues.add("Running on emulator (some features may not work)");
        }
        
        return issues;
    }
    
    /**
     * Perform comprehensive security check
     * @return SecurityReport with all findings
     */
    @NonNull
    public SecurityReport performSecurityCheck() {
        SecurityReport report = new SecurityReport();
        report.isRooted = isRooted();
        report.isDebuggable = isDebuggable();
        report.isEmulator = isEmulator();
        report.isDeveloperMode = isDeveloperOptionsEnabled();
        report.isUsbDebugging = isUsbDebuggingEnabled();
        report.signatureHash = getApkSignatureHash();
        report.androidVersion = Build.VERSION.SDK_INT;
        report.deviceModel = Build.MODEL;
        report.manufacturer = Build.MANUFACTURER;
        return report;
    }
    
    // --- Private Methods ---
    
    private boolean checkSuBinary() {
        for (String path : SU_PATHS) {
            if (new File(path).exists()) {
                LoggingHelper.d(TAG, "Found su binary at: " + path);
                return true;
            }
        }
        return false;
    }
    
    private boolean checkRootPackages() {
        PackageManager pm = mContext.getPackageManager();
        for (String packageName : ROOT_PACKAGES) {
            try {
                pm.getPackageInfo(packageName, 0);
                LoggingHelper.d(TAG, "Found root package: " + packageName);
                return true;
            } catch (PackageManager.NameNotFoundException ignored) {
            }
        }
        return false;
    }
    
    private boolean checkRootExec() {
        Process process = null;
        try {
            process = Runtime.getRuntime().exec(new String[]{"which", "su"});
            BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
            String line = reader.readLine();
            return line != null && !line.isEmpty();
        } catch (Exception e) {
            return false;
        } finally {
            if (process != null) {
                process.destroy();
            }
        }
    }
    
    private boolean checkEmulatorFiles() {
        for (String path : EMULATOR_FILES) {
            if (new File(path).exists()) {
                return true;
            }
        }
        return false;
    }
    
    private boolean checkEmulatorBuild() {
        return Build.FINGERPRINT.startsWith("generic")
                || Build.FINGERPRINT.startsWith("unknown")
                || Build.MODEL.contains("google_sdk")
                || Build.MODEL.contains("Emulator")
                || Build.MODEL.contains("Android SDK built for x86")
                || Build.MANUFACTURER.contains("Genymotion")
                || Build.BRAND.startsWith("generic")
                || Build.DEVICE.startsWith("generic")
                || "google_sdk".equals(Build.PRODUCT);
    }
    
    private boolean checkEmulatorProperties() {
        try {
            String qemu = System.getProperty("ro.kernel.qemu", "0");
            return "1".equals(qemu);
        } catch (Exception e) {
            return false;
        }
    }
    
    private String sha256(byte[] data) {
        try {
            MessageDigest md = MessageDigest.getInstance("SHA-256");
            byte[] hash = md.digest(data);
            StringBuilder sb = new StringBuilder();
            for (byte b : hash) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();
        } catch (Exception e) {
            return "";
        }
    }
    
    /**
     * Security report data class
     */
    public static class SecurityReport {
        public boolean isRooted;
        public boolean isDebuggable;
        public boolean isEmulator;
        public boolean isDeveloperMode;
        public boolean isUsbDebugging;
        public String signatureHash;
        public int androidVersion;
        public String deviceModel;
        public String manufacturer;
        
        @NonNull
        @Override
        public String toString() {
            return "SecurityReport{" +
                    "isRooted=" + isRooted +
                    ", isDebuggable=" + isDebuggable +
                    ", isEmulator=" + isEmulator +
                    ", isDeveloperMode=" + isDeveloperMode +
                    ", isUsbDebugging=" + isUsbDebugging +
                    ", androidVersion=" + androidVersion +
                    ", deviceModel='" + deviceModel + '\'' +
                    ", manufacturer='" + manufacturer + '\'' +
                    '}';
        }
    }
}
