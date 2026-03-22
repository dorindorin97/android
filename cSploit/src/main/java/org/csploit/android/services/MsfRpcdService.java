package org.csploit.android.services;

import android.app.Activity;
import android.content.Context;
import android.view.MenuItem;

import org.csploit.android.R;
import org.csploit.android.core.ChildManager;
import org.csploit.android.helpers.LoggingHelper;
import org.csploit.android.core.System;
import org.csploit.android.helpers.SecureCredentialsHelper;
import org.csploit.android.net.metasploit.RPCClient;
import org.csploit.android.tools.MsfRpcd;

/**
 * The MSFRPC daemon manager.
 * Manages secure RPC daemon connection and credentials storage.
 */
public class MsfRpcdService extends NativeService implements MenuControllableService {

  public static final String STATUS_ACTION = "MsfRpcdService.action.STATUS";
  public static final String STATUS = "MsfRpcdService.data.STATUS";

  // Credential storage keys
  private static final String CRED_KEY_HOST = "MSF_RPC_HOST";
  private static final String CRED_KEY_USER = "MSF_RPC_USER";
  private static final String CRED_KEY_PASSWORD = "MSF_RPC_PASSWORD";
  private static final String CRED_KEY_PORT = "MSF_RPC_PORT";
  private static final String CRED_KEY_SSL = "MSF_RPC_SSL";

  final String host, user, password;
  final int port;
  final boolean ssl;

  @Override
  public void onMenuClick(Activity activity, final MenuItem item) {
    if(isLocal()) {
      if(isRunning()) {
        stop();
      } else {
        start();
      }
    } else {
      if(isConnected()) {
        disconnect();
      } else {
        connect();
      }
    }

    activity.runOnUiThread(new Runnable() {
      @Override
      public void run() {
        buildMenuItem(item);
      }
    });
  }

  @Override
  public void buildMenuItem(MenuItem item) {
    item.setTitle(
            isLocal() ?
                    (isRunning() ? R.string.stop_msfrpcd : R.string.start_msfrpcd) :
                    (isConnected() ? R.string.connect_msf : R.string.disconnect_msf));
    item.setEnabled(isAvailable());
  }

  public enum Status {
    STARTING(R.string.rpcd_starting, R.color.selectable_blue),
    CONNECTED(R.string.connected_msf, R.color.green),
    DISCONNECTED(R.string.msfrpc_disconnected, R.color.purple),
    STOPPED(R.string.rpcd_stopped, R.color.purple),
    KILLED(R.string.msfrpcd_killed, R.color.purple),
    START_FAILED(R.string.msfrcd_start_failed, R.color.red),
    CONNECTION_FAILED(R.string.msf_connection_failed, R.color.red);

    private final int text;
    private final int color;

    Status(int text, int color) {
      this.text = text;
      this.color = color;
    }

    public boolean inProgress() {
      return text == R.string.rpcd_starting;
    }

    public boolean isError() {
      return color == R.color.red;
    }

    public int getText() {
      return text;
    }

    public int getColor() {
      return color;
    }
  }

  public MsfRpcdService(Context context) {
    SecureCredentialsHelper credHelper = new SecureCredentialsHelper(context);

    host = credHelper.retrieveCredential(CRED_KEY_HOST, "127.0.0.1");
    user = credHelper.retrieveCredential(CRED_KEY_USER, "msf");
    password = credHelper.retrieveCredential(CRED_KEY_PASSWORD, "msf");
    port = credHelper.retrieveCredential(CRED_KEY_PORT, System.MSF_RPC_PORT);
    ssl = credHelper.retrieveCredential(CRED_KEY_SSL, false);

    this.context = context;
  }

  private boolean isLocal() {
    return "127.0.0.1".equals(host);
  }

  public boolean isAvailable() {
    return !isLocal() || (
              System.getLocalMsfVersion() != null &&
              System.getTools() != null &&
              System.getTools().msfrpcd.isEnabled() &&
              !System.isServiceRunning("org.csploit.android.services.UpdateService"));
  }

  @Override
  protected int getStopSignal() {
    return 2;
  }

  @Override
  public boolean start() {
    if(isConnected())
      return true;

    stop();

    if(connect(isLocal())) {
      if(isLocal()) {
        LoggingHelper.warning("connected to a lost instance of the msfrpcd");
      }
      return true;
    }

    if(!isLocal()) {
      return false;
    }

    if (System.getTools() == null) {
      sendIntent(STATUS_ACTION, STATUS, Status.START_FAILED);
      return false;
    }

    try {
      nativeProcess = System.getTools().msfrpcd.async(user, password, port, ssl, new Receiver());
      return true;
    } catch (ChildManager.ChildNotStartedException e) {
      LoggingHelper.error(e.getMessage());
      sendIntent(STATUS_ACTION, STATUS, Status.START_FAILED);
    }
    return false;
  }

  /**
   * connect to this msfrpcd instance
   * @param silent quietly fail if true
   * @return true if connection succeeded, false otherwise
   */
  private boolean connect(boolean silent) {
    do {
      try {
        System.setMsfRpc(new RPCClient(host, user, password, port, ssl));
        LoggingHelper.info("successfully connected to MSF RPC Daemon ");
        sendIntent(STATUS_ACTION, STATUS, Status.CONNECTED);
        return true;
      } catch (Exception e) {
        LoggingHelper.warning(e.getClass().getName() + ": " + e.getMessage());
      }

      if(isRunning()) {
        try {
          Thread.sleep(1000);
        } catch (InterruptedException e) {
          stop();
        }
      }
    } while(isRunning() && !isConnected());

    if(!silent)
      sendIntent(STATUS_ACTION, STATUS, Status.CONNECTION_FAILED);

    return false;
  }

  /**
   * connect to this msfrpcd instance
   * @return true if connection succeeded, false otherwise
   */
  public boolean connect() {
    return connect(false);
  }

  public void disconnect() {
    System.setMsfRpc(null);
    if(!isLocal()) {
      sendIntent(STATUS_ACTION, STATUS, Status.DISCONNECTED);
    }
  }

  private boolean isConnected() {
    RPCClient client = System.getMsfRpc();
    return client != null && client.isConnected();
  }

  @Override
  public boolean stop() {
    disconnect();
    return super.stop();
  }

  private class Receiver extends MsfRpcd.MsfRpcdReceiver {
    @Override
    public void onReady() {
      connect();
    }

    @Override
    public void onStart(String cmd) {
      sendIntent(STATUS_ACTION, STATUS, Status.STARTING);
    }

    @Override
    public void onDeath(int signal) {
      if(!isConnected())
        disconnect();
      sendIntent(STATUS_ACTION, STATUS, Status.KILLED);
    }

    @Override
    public void onEnd(int exitValue) {
      if(!isConnected())
        disconnect();
      sendIntent(STATUS_ACTION, STATUS, Status.STOPPED);
    }
  }
}
