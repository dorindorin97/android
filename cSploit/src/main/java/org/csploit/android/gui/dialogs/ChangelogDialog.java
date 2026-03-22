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

import android.annotation.SuppressLint;
import android.widget.ProgressBar;
import android.widget.TextView;

import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import androidx.core.text.HtmlCompat;

import com.google.android.material.dialog.MaterialAlertDialogBuilder;

import org.csploit.android.R;
import org.csploit.android.helpers.LoggingHelper;
import org.csploit.android.core.System;
import org.csploit.android.net.GitHubParser;
import org.json.JSONException;

import java.io.IOException;

public class ChangelogDialog {
  private static final String TAG = "ChangelogDialog";

  private final AlertDialog dialog;

  @SuppressLint("SetJavaScriptEnabled")
  public ChangelogDialog(final AppCompatActivity activity) {
    final String ERROR_HTML = activity.getString(R.string.something_went_wrong_changelog);

    AlertDialog mLoader = new MaterialAlertDialogBuilder(activity)
        .setTitle("")
        .setMessage(activity.getString(R.string.loading_changelog))
        .setCancelable(false)
        .setView(new ProgressBar(activity))
        .create();
    mLoader.show();

    TextView view = new TextView(activity);

    try {
      view.setText(GitHubParser.getcSploitRepo().getReleaseBody(System.getAppVersionName()));
    } catch (JSONException e) {
      view.setText(HtmlCompat.fromHtml(ERROR_HTML.replace("{DESCRIPTION}", e.getMessage()), HtmlCompat.FROM_HTML_MODE_LEGACY));
      LoggingHelper.e(TAG, "Failed to load changelog", e);
    } catch (IOException e) {
      view.setText(HtmlCompat.fromHtml(ERROR_HTML.replace("{DESCRIPTION}", e.getMessage()), HtmlCompat.FROM_HTML_MODE_LEGACY));
      LoggingHelper.e(TAG, "Failed to load changelog", e);
    }

    mLoader.dismiss();

    dialog = new MaterialAlertDialogBuilder(activity)
        .setTitle("Changelog")
        .setView(view)
        .setCancelable(false)
        .setPositiveButton("Ok", (d, which) -> d.dismiss())
        .create();
  }

  public void show() {
    dialog.show();
  }
}
