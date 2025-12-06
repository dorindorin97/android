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
import android.app.AlertDialog;
import android.content.Context;
import android.content.DialogInterface;
import android.view.View;
import android.widget.EditText;
import android.widget.ProgressBar;
import android.widget.LinearLayout;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;
import androidx.annotation.StringRes;

/**
 * Helper class for creating common dialogs.
 * Provides utilities for alert, confirm, input, and progress dialogs.
 */
public class DialogHelper {
    
    /**
     * Simple click listener callback.
     */
    public interface OnClickCallback {
        void onClick();
    }
    
    /**
     * Input dialog callback.
     */
    public interface OnInputCallback {
        void onInput(@NonNull String input);
    }
    
    /**
     * Show an alert dialog with single OK button.
     * 
     * @param context Context
     * @param title Dialog title
     * @param message Dialog message
     * @return AlertDialog instance
     */
    @NonNull
    public static AlertDialog alert(@NonNull Context context, @NonNull String title, @NonNull String message) {
        return alert(context, title, message, null);
    }
    
    /**
     * Show an alert dialog with single OK button.
     * 
     * @param context Context
     * @param title Dialog title
     * @param message Dialog message
     * @param onOk Callback when OK is clicked
     * @return AlertDialog instance
     */
    @NonNull
    public static AlertDialog alert(@NonNull Context context, @NonNull String title, @NonNull String message,
                                    @Nullable OnClickCallback onOk) {
        AlertDialog dialog = new AlertDialog.Builder(context)
                .setTitle(title)
                .setMessage(message)
                .setPositiveButton(android.R.string.ok, (d, which) -> {
                    if (onOk != null) {
                        onOk.onClick();
                    }
                })
                .create();
        dialog.show();
        return dialog;
    }
    
    /**
     * Show an alert dialog with single OK button.
     * 
     * @param context Context
     * @param titleRes Title resource ID
     * @param messageRes Message resource ID
     * @return AlertDialog instance
     */
    @NonNull
    public static AlertDialog alert(@NonNull Context context, @StringRes int titleRes, @StringRes int messageRes) {
        return alert(context, context.getString(titleRes), context.getString(messageRes));
    }
    
    /**
     * Show an error dialog.
     * 
     * @param context Context
     * @param message Error message
     * @return AlertDialog instance
     */
    @NonNull
    public static AlertDialog error(@NonNull Context context, @NonNull String message) {
        return alert(context, "Error", message);
    }
    
    /**
     * Show an error dialog.
     * 
     * @param context Context
     * @param messageRes Message resource ID
     * @return AlertDialog instance
     */
    @NonNull
    public static AlertDialog error(@NonNull Context context, @StringRes int messageRes) {
        return error(context, context.getString(messageRes));
    }
    
    /**
     * Show a success dialog.
     * 
     * @param context Context
     * @param message Success message
     * @return AlertDialog instance
     */
    @NonNull
    public static AlertDialog success(@NonNull Context context, @NonNull String message) {
        return alert(context, "Success", message);
    }
    
    /**
     * Show a warning dialog.
     * 
     * @param context Context
     * @param message Warning message
     * @return AlertDialog instance
     */
    @NonNull
    public static AlertDialog warning(@NonNull Context context, @NonNull String message) {
        return alert(context, "Warning", message);
    }
    
    /**
     * Show a confirmation dialog with Yes/No buttons.
     * 
     * @param context Context
     * @param title Dialog title
     * @param message Dialog message
     * @param onYes Callback when Yes is clicked
     * @return AlertDialog instance
     */
    @NonNull
    public static AlertDialog confirm(@NonNull Context context, @NonNull String title, @NonNull String message,
                                       @NonNull OnClickCallback onYes) {
        return confirm(context, title, message, onYes, null);
    }
    
    /**
     * Show a confirmation dialog with Yes/No buttons.
     * 
     * @param context Context
     * @param title Dialog title
     * @param message Dialog message
     * @param onYes Callback when Yes is clicked
     * @param onNo Callback when No is clicked
     * @return AlertDialog instance
     */
    @NonNull
    public static AlertDialog confirm(@NonNull Context context, @NonNull String title, @NonNull String message,
                                       @Nullable OnClickCallback onYes, @Nullable OnClickCallback onNo) {
        AlertDialog dialog = new AlertDialog.Builder(context)
                .setTitle(title)
                .setMessage(message)
                .setPositiveButton(android.R.string.yes, (d, which) -> {
                    if (onYes != null) {
                        onYes.onClick();
                    }
                })
                .setNegativeButton(android.R.string.no, (d, which) -> {
                    if (onNo != null) {
                        onNo.onClick();
                    }
                })
                .create();
        dialog.show();
        return dialog;
    }
    
    /**
     * Show a confirmation dialog with OK/Cancel buttons.
     * 
     * @param context Context
     * @param title Dialog title
     * @param message Dialog message
     * @param onOk Callback when OK is clicked
     * @return AlertDialog instance
     */
    @NonNull
    public static AlertDialog confirmOkCancel(@NonNull Context context, @NonNull String title, @NonNull String message,
                                               @NonNull OnClickCallback onOk) {
        return confirmOkCancel(context, title, message, onOk, null);
    }
    
    /**
     * Show a confirmation dialog with OK/Cancel buttons.
     * 
     * @param context Context
     * @param title Dialog title
     * @param message Dialog message
     * @param onOk Callback when OK is clicked
     * @param onCancel Callback when Cancel is clicked
     * @return AlertDialog instance
     */
    @NonNull
    public static AlertDialog confirmOkCancel(@NonNull Context context, @NonNull String title, @NonNull String message,
                                               @Nullable OnClickCallback onOk, @Nullable OnClickCallback onCancel) {
        AlertDialog dialog = new AlertDialog.Builder(context)
                .setTitle(title)
                .setMessage(message)
                .setPositiveButton(android.R.string.ok, (d, which) -> {
                    if (onOk != null) {
                        onOk.onClick();
                    }
                })
                .setNegativeButton(android.R.string.cancel, (d, which) -> {
                    if (onCancel != null) {
                        onCancel.onClick();
                    }
                })
                .create();
        dialog.show();
        return dialog;
    }
    
    /**
     * Show a delete confirmation dialog.
     * 
     * @param context Context
     * @param itemName Name of item to delete
     * @param onDelete Callback when delete is confirmed
     * @return AlertDialog instance
     */
    @NonNull
    public static AlertDialog confirmDelete(@NonNull Context context, @NonNull String itemName,
                                             @NonNull OnClickCallback onDelete) {
        return confirm(context, "Delete", "Are you sure you want to delete " + itemName + "?", onDelete);
    }
    
    /**
     * Show an input dialog.
     * 
     * @param context Context
     * @param title Dialog title
     * @param hint Input hint
     * @param onInput Callback with input text
     * @return AlertDialog instance
     */
    @NonNull
    public static AlertDialog input(@NonNull Context context, @NonNull String title, @Nullable String hint,
                                     @NonNull OnInputCallback onInput) {
        return input(context, title, hint, "", onInput);
    }
    
    /**
     * Show an input dialog with initial value.
     * 
     * @param context Context
     * @param title Dialog title
     * @param hint Input hint
     * @param initialValue Initial value
     * @param onInput Callback with input text
     * @return AlertDialog instance
     */
    @NonNull
    public static AlertDialog input(@NonNull Context context, @NonNull String title, @Nullable String hint,
                                     @Nullable String initialValue, @NonNull OnInputCallback onInput) {
        EditText editText = new EditText(context);
        editText.setHint(hint);
        if (initialValue != null) {
            editText.setText(initialValue);
            editText.selectAll();
        }
        
        // Add padding
        int padding = DisplayHelper.dpToPx(context, 16);
        LinearLayout container = new LinearLayout(context);
        container.setPadding(padding, padding / 2, padding, 0);
        container.addView(editText, new LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
        ));
        
        AlertDialog dialog = new AlertDialog.Builder(context)
                .setTitle(title)
                .setView(container)
                .setPositiveButton(android.R.string.ok, (d, which) -> {
                    String text = editText.getText().toString().trim();
                    onInput.onInput(text);
                })
                .setNegativeButton(android.R.string.cancel, null)
                .create();
        
        dialog.show();
        
        // Show keyboard
        editText.requestFocus();
        ClipboardHelper.showKeyboard(context, editText);
        
        return dialog;
    }
    
    /**
     * Show a single-choice list dialog.
     * 
     * @param context Context
     * @param title Dialog title
     * @param items Items to choose from
     * @param onSelect Callback with selected index
     * @return AlertDialog instance
     */
    @NonNull
    public static AlertDialog choose(@NonNull Context context, @NonNull String title,
                                      @NonNull String[] items, @NonNull OnSelectCallback onSelect) {
        AlertDialog dialog = new AlertDialog.Builder(context)
                .setTitle(title)
                .setItems(items, (d, which) -> onSelect.onSelect(which))
                .create();
        dialog.show();
        return dialog;
    }
    
    /**
     * Selection callback.
     */
    public interface OnSelectCallback {
        void onSelect(int index);
    }
    
    /**
     * Show a single-choice dialog with radio buttons.
     * 
     * @param context Context
     * @param title Dialog title
     * @param items Items to choose from
     * @param selectedIndex Initially selected index
     * @param onSelect Callback with selected index
     * @return AlertDialog instance
     */
    @NonNull
    public static AlertDialog chooseSingle(@NonNull Context context, @NonNull String title,
                                            @NonNull String[] items, int selectedIndex,
                                            @NonNull OnSelectCallback onSelect) {
        final int[] selected = {selectedIndex};
        AlertDialog dialog = new AlertDialog.Builder(context)
                .setTitle(title)
                .setSingleChoiceItems(items, selectedIndex, (d, which) -> selected[0] = which)
                .setPositiveButton(android.R.string.ok, (d, which) -> onSelect.onSelect(selected[0]))
                .setNegativeButton(android.R.string.cancel, null)
                .create();
        dialog.show();
        return dialog;
    }
    
    /**
     * Show a multi-choice dialog with checkboxes.
     * 
     * @param context Context
     * @param title Dialog title
     * @param items Items to choose from
     * @param checkedItems Initially checked items
     * @param onSelect Callback with checked state array
     * @return AlertDialog instance
     */
    @NonNull
    public static AlertDialog chooseMultiple(@NonNull Context context, @NonNull String title,
                                              @NonNull String[] items, @NonNull boolean[] checkedItems,
                                              @NonNull OnMultiSelectCallback onSelect) {
        AlertDialog dialog = new AlertDialog.Builder(context)
                .setTitle(title)
                .setMultiChoiceItems(items, checkedItems, (d, which, isChecked) -> checkedItems[which] = isChecked)
                .setPositiveButton(android.R.string.ok, (d, which) -> onSelect.onSelect(checkedItems))
                .setNegativeButton(android.R.string.cancel, null)
                .create();
        dialog.show();
        return dialog;
    }
    
    /**
     * Multi-selection callback.
     */
    public interface OnMultiSelectCallback {
        void onSelect(boolean[] checkedItems);
    }
    
    /**
     * Show a progress dialog.
     * 
     * @param context Context
     * @param title Dialog title
     * @param message Progress message
     * @param cancelable Whether dialog can be cancelled
     * @return AlertDialog instance
     */
    @NonNull
    public static AlertDialog progress(@NonNull Context context, @Nullable String title,
                                        @NonNull String message, boolean cancelable) {
        return progress(context, title, message, cancelable, null);
    }
    
    /**
     * Show a progress dialog.
     * 
     * @param context Context
     * @param title Dialog title
     * @param message Progress message
     * @param cancelable Whether dialog can be cancelled
     * @param onCancel Callback when cancelled
     * @return AlertDialog instance
     */
    @NonNull
    public static AlertDialog progress(@NonNull Context context, @Nullable String title,
                                        @NonNull String message, boolean cancelable,
                                        @Nullable OnClickCallback onCancel) {
        // Create progress bar
        ProgressBar progressBar = new ProgressBar(context);
        progressBar.setIndeterminate(true);
        
        int padding = DisplayHelper.dpToPx(context, 16);
        LinearLayout container = new LinearLayout(context);
        container.setOrientation(LinearLayout.HORIZONTAL);
        container.setPadding(padding, padding, padding, padding);
        container.addView(progressBar);
        
        AlertDialog.Builder builder = new AlertDialog.Builder(context)
                .setTitle(title)
                .setMessage(message)
                .setCancelable(cancelable);
        
        if (cancelable && onCancel != null) {
            builder.setNegativeButton(android.R.string.cancel, (d, which) -> onCancel.onClick());
        }
        
        AlertDialog dialog = builder.create();
        dialog.show();
        return dialog;
    }
    
    /**
     * Show a loading dialog.
     * 
     * @param context Context
     * @param message Loading message
     * @return AlertDialog instance
     */
    @NonNull
    public static AlertDialog loading(@NonNull Context context, @NonNull String message) {
        return progress(context, null, message, false);
    }
    
    /**
     * Show a loading dialog.
     * 
     * @param context Context
     * @return AlertDialog instance
     */
    @NonNull
    public static AlertDialog loading(@NonNull Context context) {
        return loading(context, "Loading...");
    }
    
    /**
     * Dismiss dialog safely.
     * 
     * @param dialog Dialog to dismiss
     */
    public static void dismiss(@Nullable AlertDialog dialog) {
        if (dialog != null && dialog.isShowing()) {
            try {
                dialog.dismiss();
            } catch (Exception e) {
                // Ignore
            }
        }
    }
    
    /**
     * Check if dialog is showing.
     * 
     * @param dialog Dialog to check
     * @return true if showing
     */
    public static boolean isShowing(@Nullable AlertDialog dialog) {
        return dialog != null && dialog.isShowing();
    }
    
    private DialogHelper() {
        // Prevent instantiation
    }
}
