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
import androidx.core.text.HtmlCompat;
import androidx.fragment.app.FragmentActivity;

import android.widget.TextView;
import android.text.method.LinkMovementMethod;

import com.google.android.material.dialog.MaterialAlertDialogBuilder;

public class FatalDialog {
  private final AlertDialog dialog;

  public FatalDialog(String title, String message, boolean html, final FragmentActivity activity) {
    MaterialAlertDialogBuilder builder = new MaterialAlertDialogBuilder(activity)
        .setTitle(title)
        .setCancelable(false)
        .setPositiveButton("Ok", (d, which) -> activity.finish());

    if (!html) {
      builder.setMessage(message);
    } else {
      TextView text = new TextView(activity);
      text.setMovementMethod(LinkMovementMethod.getInstance());
      text.setText(HtmlCompat.fromHtml(message, HtmlCompat.FROM_HTML_MODE_LEGACY));
      text.setPadding(10, 10, 10, 10);
      builder.setView(text);
    }

    dialog = builder.create();
  }

  public FatalDialog(String title, String message, final FragmentActivity activity) {
    this(title, message, false, activity);
  }

  public void show() {
    dialog.show();
  }
}
