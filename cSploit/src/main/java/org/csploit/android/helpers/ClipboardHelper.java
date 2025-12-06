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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with cSploit.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.csploit.android.helpers;

import android.app.Activity;
import android.content.ClipData;
import android.content.ClipboardManager;
import android.content.Context;
import android.os.Build;
import android.view.View;
import android.view.inputmethod.InputMethodManager;
import android.widget.Toast;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.StringRes;

/**
 * Helper class for clipboard and keyboard operations.
 * Provides utilities for copying/pasting text and managing keyboard.
 */
public class ClipboardHelper {
    
    private static final String CLIPBOARD_LABEL = "cSploit";
    
    /**
     * Copy text to clipboard.
     * 
     * @param context Context
     * @param text Text to copy
     * @return true if successful
     */
    public static boolean copyToClipboard(@NonNull Context context, @Nullable String text) {
        return copyToClipboard(context, CLIPBOARD_LABEL, text);
    }
    
    /**
     * Copy text to clipboard with label.
     * 
     * @param context Context
     * @param label Clipboard label
     * @param text Text to copy
     * @return true if successful
     */
    public static boolean copyToClipboard(@NonNull Context context, @NonNull String label, @Nullable String text) {
        try {
            ClipboardManager clipboard = (ClipboardManager) context.getSystemService(Context.CLIPBOARD_SERVICE);
            if (clipboard == null) {
                return false;
            }
            
            ClipData clip = ClipData.newPlainText(label, text != null ? text : "");
            clipboard.setPrimaryClip(clip);
            return true;
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Copy text to clipboard and show toast.
     * 
     * @param context Context
     * @param text Text to copy
     * @param successMessage Success message
     */
    public static void copyToClipboardWithToast(@NonNull Context context, @Nullable String text, 
                                                 @NonNull String successMessage) {
        if (copyToClipboard(context, text)) {
            Toast.makeText(context, successMessage, Toast.LENGTH_SHORT).show();
        } else {
            Toast.makeText(context, "Failed to copy", Toast.LENGTH_SHORT).show();
        }
    }
    
    /**
     * Copy text to clipboard and show toast.
     * 
     * @param context Context
     * @param text Text to copy
     * @param successMessageRes Success message resource ID
     */
    public static void copyToClipboardWithToast(@NonNull Context context, @Nullable String text,
                                                 @StringRes int successMessageRes) {
        copyToClipboardWithToast(context, text, context.getString(successMessageRes));
    }
    
    /**
     * Get text from clipboard.
     * 
     * @param context Context
     * @return Clipboard text, or null if empty
     */
    @Nullable
    public static String getFromClipboard(@NonNull Context context) {
        try {
            ClipboardManager clipboard = (ClipboardManager) context.getSystemService(Context.CLIPBOARD_SERVICE);
            if (clipboard == null || !clipboard.hasPrimaryClip()) {
                return null;
            }
            
            ClipData clipData = clipboard.getPrimaryClip();
            if (clipData == null || clipData.getItemCount() == 0) {
                return null;
            }
            
            ClipData.Item item = clipData.getItemAt(0);
            if (item == null) {
                return null;
            }
            
            CharSequence text = item.getText();
            return text != null ? text.toString() : null;
        } catch (Exception e) {
            return null;
        }
    }
    
    /**
     * Check if clipboard has text.
     * 
     * @param context Context
     * @return true if clipboard has text
     */
    public static boolean hasClipboardText(@NonNull Context context) {
        try {
            ClipboardManager clipboard = (ClipboardManager) context.getSystemService(Context.CLIPBOARD_SERVICE);
            if (clipboard == null) {
                return false;
            }
            
            if (!clipboard.hasPrimaryClip()) {
                return false;
            }
            
            ClipData clipData = clipboard.getPrimaryClip();
            if (clipData == null || clipData.getItemCount() == 0) {
                return false;
            }
            
            ClipData.Item item = clipData.getItemAt(0);
            return item != null && item.getText() != null;
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Clear clipboard.
     * 
     * @param context Context
     * @return true if successful
     */
    public static boolean clearClipboard(@NonNull Context context) {
        try {
            ClipboardManager clipboard = (ClipboardManager) context.getSystemService(Context.CLIPBOARD_SERVICE);
            if (clipboard == null) {
                return false;
            }
            
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.P) {
                clipboard.clearPrimaryClip();
            } else {
                ClipData clip = ClipData.newPlainText("", "");
                clipboard.setPrimaryClip(clip);
            }
            return true;
        } catch (Exception e) {
            return false;
        }
    }
    
    /**
     * Show keyboard for view.
     * 
     * @param context Context
     * @param view View to focus
     */
    public static void showKeyboard(@NonNull Context context, @NonNull View view) {
        view.requestFocus();
        InputMethodManager imm = (InputMethodManager) context.getSystemService(Context.INPUT_METHOD_SERVICE);
        if (imm != null) {
            imm.showSoftInput(view, InputMethodManager.SHOW_IMPLICIT);
        }
    }
    
    /**
     * Hide keyboard.
     * 
     * @param activity Activity
     */
    public static void hideKeyboard(@NonNull Activity activity) {
        View view = activity.getCurrentFocus();
        if (view == null) {
            view = new View(activity);
        }
        hideKeyboard(activity, view);
    }
    
    /**
     * Hide keyboard from view.
     * 
     * @param context Context
     * @param view View
     */
    public static void hideKeyboard(@NonNull Context context, @NonNull View view) {
        InputMethodManager imm = (InputMethodManager) context.getSystemService(Context.INPUT_METHOD_SERVICE);
        if (imm != null) {
            imm.hideSoftInputFromWindow(view.getWindowToken(), 0);
        }
    }
    
    /**
     * Toggle keyboard visibility.
     * 
     * @param context Context
     */
    public static void toggleKeyboard(@NonNull Context context) {
        InputMethodManager imm = (InputMethodManager) context.getSystemService(Context.INPUT_METHOD_SERVICE);
        if (imm != null) {
            imm.toggleSoftInput(InputMethodManager.SHOW_FORCED, 0);
        }
    }
    
    /**
     * Check if keyboard is visible.
     * Note: This is an approximation, as there's no reliable way to detect this.
     * 
     * @param context Context
     * @return true if keyboard is likely visible
     */
    public static boolean isKeyboardVisible(@NonNull Context context) {
        InputMethodManager imm = (InputMethodManager) context.getSystemService(Context.INPUT_METHOD_SERVICE);
        return imm != null && imm.isAcceptingText();
    }
    
    private ClipboardHelper() {
        // Prevent instantiation
    }
}
