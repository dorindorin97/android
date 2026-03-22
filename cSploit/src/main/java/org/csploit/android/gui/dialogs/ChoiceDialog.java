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
import android.widget.Button;
import android.widget.LinearLayout;
import android.widget.LinearLayout.LayoutParams;

import androidx.appcompat.app.AlertDialog;
import androidx.fragment.app.FragmentActivity;

import com.google.android.material.dialog.MaterialAlertDialogBuilder;

import org.csploit.android.R;

public class ChoiceDialog {
  public interface ChoiceDialogListener {
    void onChoice(int choice);
  }

  private final AlertDialog dialog;

  public ChoiceDialog(final FragmentActivity activity, String title, String[] choices, final ChoiceDialogListener listener) {
    LinearLayout layout = new LinearLayout(activity);
    layout.setPadding(10, 10, 10, 10);

    MaterialAlertDialogBuilder builder = new MaterialAlertDialogBuilder(activity)
        .setTitle(title)
        .setNegativeButton(activity.getString(R.string.cancel_dialog), (d, which) -> d.dismiss());

    dialog = builder.create();

    for (int i = 0; i < choices.length; i++) {
      Button choice = new Button(activity);
      choice.setLayoutParams(new LayoutParams(LayoutParams.MATCH_PARENT, LayoutParams.MATCH_PARENT, 0.5f));
      choice.setTag("" + i);
      choice.setOnClickListener(new View.OnClickListener() {
        @Override
        public void onClick(View v) {
          dialog.dismiss();
          listener.onChoice(Integer.parseInt((String) v.getTag()));
        }
      });
      choice.setText(choices[i]);
      layout.addView(choice);
    }

    dialog.setView(layout);
  }

  public void show() {
    dialog.show();
  }
}
