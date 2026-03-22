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

import android.view.View;
import android.widget.AdapterView;
import android.widget.AdapterView.OnItemSelectedListener;
import android.widget.ArrayAdapter;
import android.widget.Spinner;

import androidx.appcompat.app.AlertDialog;
import androidx.fragment.app.FragmentActivity;

import com.google.android.material.dialog.MaterialAlertDialogBuilder;

import org.csploit.android.R;

public class SpinnerDialog {
  private int mSelected = 0;
  private final AlertDialog dialog;

  public SpinnerDialog(String title, String message, String[] items, int default_index, FragmentActivity activity, final SpinnerDialogListener listener) {
    Spinner mSpinner = new Spinner(activity);
    mSpinner.setAdapter(new ArrayAdapter<String>(activity, android.R.layout.simple_spinner_item, items));

    mSpinner.setOnItemSelectedListener(new OnItemSelectedListener() {
      public void onItemSelected(AdapterView<?> adapter, View view, int position, long id) {
        mSelected = position;
      }

      public void onNothingSelected(AdapterView<?> arg0) {
      }
    });

    mSpinner.setSelection(default_index);

    dialog = new MaterialAlertDialogBuilder(activity)
        .setTitle(title)
        .setMessage(message)
        .setView(mSpinner)
        .setPositiveButton("Ok", (d, which) -> listener.onItemSelected(mSelected))
        .setNegativeButton(activity.getString(R.string.cancel_dialog), (d, which) -> d.dismiss())
        .create();
  }

  public SpinnerDialog(String title, String message, String[] items, FragmentActivity activity, final SpinnerDialogListener listener) {
    this(title, message, items, 0, activity, listener);
  }

  public void show() {
    dialog.show();
  }

  public interface SpinnerDialogListener {
    void onItemSelected(int index);
  }
}
