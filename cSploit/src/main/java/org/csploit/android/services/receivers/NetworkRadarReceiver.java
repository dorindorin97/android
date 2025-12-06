package org.csploit.android.services.receivers;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;

import org.csploit.android.R;
import org.csploit.android.core.ManagedReceiver;
import org.csploit.android.services.NetworkRadar;
import org.csploit.android.helpers.ToastHelper;

/**
 * receive notifications from NetworkRadar
 */
public class NetworkRadarReceiver extends ManagedReceiver {

  private final IntentFilter filter;

  public NetworkRadarReceiver() {
    filter = new IntentFilter();

    filter.addAction(NetworkRadar.NRDR_STARTED);
    filter.addAction(NetworkRadar.NRDR_START_FAILED);
    filter.addAction(NetworkRadar.NRDR_STOPPED);
  }

  @Override
  public IntentFilter getFilter() {
    return filter;
  }

  @Override
  public void onReceive(final Context context, final Intent intent) {
    if(context instanceof Activity) {
      ((Activity) context).runOnUiThread(new Runnable() {
        @Override
        public void run() {
          notifyIntent(context, intent);
        }
      });
    } else {
      notifyIntent(context, intent);
    }
  }

  private void notifyIntent(Context context, Intent intent) {
    String action = intent.getAction();

    switch (action) {
      case NetworkRadar.NRDR_STARTED:
        ToastHelper.status(context, context.getString(R.string.net_discovery_started));
        break;
      case NetworkRadar.NRDR_STOPPED:
        ToastHelper.status(context, context.getString(R.string.net_discovery_stopped));
        break;
      case NetworkRadar.NRDR_START_FAILED:
        ToastHelper.error(context, context.getString(R.string.net_discovery_start_failed));
        break;
    }
  }
}
