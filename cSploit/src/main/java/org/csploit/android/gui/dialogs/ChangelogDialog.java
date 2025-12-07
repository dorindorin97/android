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
import android.content.DialogInterface;
import androidx.appcompat.app.AlertDialog;
import androidx.appcompat.app.AppCompatActivity;
import android.text.Html;
import androidx.core.text.HtmlCompat;
import android.widget.ProgressBar;
import android.widget.TextView;

import org.csploit.android.R;
import org.csploit.android.core.Logger;
import org.csploit.android.core.System;
import org.csploit.android.helpers.LoggingHelper;
import org.csploit.android.net.GitHubParser;
import org.json.JSONException;

import java.io.IOException;

public class ChangelogDialog extends AlertDialog
{
  private static final String TAG = "ChangelogDialog";
  private final String ERROR_HTML = getContext().getString(R.string.something_went_wrong_changelog);

  private AlertDialog mLoader = null;

  @SuppressLint("SetJavaScriptEnabled")
  public ChangelogDialog(final AppCompatActivity activity){
    super(activity);

    this.setTitle("Changelog");


    TextView view = new TextView(activity);

    this.setView(view);

    if(mLoader == null) {
      AlertDialog.Builder loaderBuilder = new AlertDialog.Builder(activity);
      loaderBuilder.setTitle("")
                   .setMessage(getContext().getString(R.string.loading_changelog))
                   .setCancelable(false)
                   .setView(new ProgressBar(activity));
      mLoader = loaderBuilder.create();
      mLoader.show();
    }

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

    this.setCancelable(false);
    this.setButton(BUTTON_POSITIVE, "Ok", new DialogInterface.OnClickListener(){
      public void onClick(DialogInterface dialog, int id){
        dialog.dismiss();
      }
    });
  }
}
