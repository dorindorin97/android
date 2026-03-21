package org.csploit.android.update;

import android.content.Context;
import android.content.Intent;
import android.net.Uri;

import androidx.core.content.FileProvider;

import org.csploit.android.R;
import org.csploit.android.core.System;

import java.io.File;

/**
 * an APK update
 */
public class ApkUpdate extends Update {

  // Application context stored to build the FileProvider URI in buildIntent()
  private final transient Context mContext;

  public ApkUpdate(Context context, String url, String version) {
    mContext = context.getApplicationContext();
    this.url = url;
    this.version = version;
    name = String.format("cSploit-%s.apk", version);
    path = String.format("%s/%s", System.getStoragePath(), name);
    prompt = String.format(context.getString(R.string.new_apk_found), version);
  }

  @Override
  public boolean haveIntent() {
    return true;
  }

  @Override
  public Intent buildIntent() {
    File apkFile = new File(path);
    Uri apkUri = FileProvider.getUriForFile(mContext,
        mContext.getPackageName() + ".provider", apkFile);
    Intent intent = new Intent(Intent.ACTION_VIEW);
    intent.setDataAndType(apkUri, "application/vnd.android.package-archive");
    intent.setFlags(Intent.FLAG_ACTIVITY_NEW_TASK | Intent.FLAG_GRANT_READ_URI_PERMISSION);
    return intent;
  }
}
