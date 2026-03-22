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
package org.csploit.android.gui.dialogs;

import androidx.appcompat.app.AlertDialog;
import androidx.fragment.app.FragmentActivity;

import com.google.android.material.dialog.MaterialAlertDialogBuilder;

import org.csploit.android.R;

public class ConfirmDialog {
  public interface ConfirmDialogListener {
    void onConfirm();

    void onCancel();
  }

  private final AlertDialog dialog;

  public ConfirmDialog(String title, CharSequence message, FragmentActivity activity, ConfirmDialogListener confirmDialogListener) {
    final ConfirmDialogListener listener = confirmDialogListener;

    dialog = new MaterialAlertDialogBuilder(activity)
        .setTitle(title)
        .setMessage(message)
        .setPositiveButton(activity.getString(R.string.yes), (d, which) -> listener.onConfirm())
        .setNegativeButton(activity.getString(R.string.no), (d, which) -> {
          d.dismiss();
          listener.onCancel();
        })
        .create();
  }

  public void show() {
    dialog.show();
  }
}
