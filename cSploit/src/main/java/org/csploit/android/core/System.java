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
package org.csploit.android.core;

import android.app.ActivityManager;
import android.app.ActivityManager.RunningServiceInfo;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.content.pm.PackageInfo;
import android.content.pm.PackageManager;
import android.content.pm.PackageManager.NameNotFoundException;
import android.net.wifi.WifiManager;
import android.net.wifi.WifiManager.WifiLock;
import android.os.Build;
import android.os.Environment;
import android.os.PowerManager;
import android.os.PowerManager.WakeLock;
import android.preference.PreferenceManager;
import androidx.annotation.Nullable;
import androidx.fragment.app.FragmentActivity;
import androidx.appcompat.app.AppCompatActivity;
import android.util.SparseIntArray;

import org.apache.commons.compress.utils.IOUtils;
import org.csploit.android.R;
import org.csploit.android.WifiScannerFragment;
import org.csploit.android.gui.dialogs.FatalDialog;
import org.csploit.android.helpers.NetworkHelper;
import org.csploit.android.helpers.ThreadHelper;
import org.csploit.android.net.GitHubParser;
import org.csploit.android.net.Network;
import org.csploit.android.net.RemoteReader;
import org.csploit.android.net.Target;
import org.csploit.android.net.Target.Exploit;
import org.csploit.android.net.http.proxy.HTTPSRedirector;
import org.csploit.android.net.http.proxy.Proxy;
import org.csploit.android.net.http.server.Server;
import org.csploit.android.net.metasploit.MsfExploit;
import org.csploit.android.net.metasploit.Payload;
import org.csploit.android.net.metasploit.RPCClient;
import org.csploit.android.net.metasploit.Session;
import org.csploit.android.services.Services;
import org.csploit.android.tools.ToolBox;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.DataInputStream;
import java.io.DataOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.StringWriter;
import java.io.Writer;
import java.lang.ref.WeakReference;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.NoRouteToHostException;
import java.net.Socket;
import java.net.SocketException;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Observer;
import java.util.SortedSet;
import java.util.TreeSet;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

public class System {
  public static final String SESSION_MAGIC = "cSploitSession";

  private static final String ERROR_LOG_FILENAME = "csploit-debug-error.log";
  private static final Pattern SERVICE_PARSER = Pattern.compile("^([^\\s]+)\\s+(\\d+).*$", Pattern.CASE_INSENSITIVE);
  public static int HTTP_PROXY_PORT = 8080;
  public static int HTTP_SERVER_PORT = 8081;
  public static int HTTPS_REDIR_PORT = 8082;
  public static int MSF_RPC_PORT = 55553;

  public static final String IPV4_FORWARD_FILEPATH = "/proc/sys/net/ipv4/ip_forward";

  private static boolean mInitialized = false;
  private static String mLastError = "";
  private static WeakReference<Context> mContext = null;
  private static volatile WifiLock mWifiLock = null;
  private static volatile WakeLock mWakeLock = null;
  private static Network mNetwork = null;
  private static final SortedSet<Target> mTargets = new TreeSet<>();
  private static Target mCurrentTarget = null;
  private static Map<String, String> mServices = null;
  private static Map<String, String> mPorts = null;
  private static Map<Integer, String> mVendors = null;
  private static SparseIntArray mOpenPorts = null;

  // registered plugins
  private static ArrayList<Plugin> mPlugins = null;
  private static Plugin mCurrentPlugin = null;
  // toolbox singleton
  private static ToolBox mTools = null;

  private static volatile HTTPSRedirector mRedirector = null;
  private static volatile Proxy mProxy = null;
  private static volatile Server mServer = null;

  private static String mIfname = null;
  private static String mStoragePath = null;
  private static String mSessionName = null;

  private static String mApkVersion = null;

  private static Object mCustomData = null;

  private static RPCClient mMsfRpc = null;
  private static Exploit mExploit = null;
  private static Payload mPayload = null;
  private static Session mMsfSession = null;

  private static boolean mCoreInitialized = false;

  private static KnownIssues mKnownIssues = null;

  private static Observer targetListObserver = null;

  private final static LinkedList<SettingReceiver> mSettingReceivers = new LinkedList<SettingReceiver>();

  public static void init(Context context) throws Exception {
    mContext = new WeakReference<>(context);
    try {
      Logger.debug("initializing System...");
      Context ctx = getContextSafe();
      if (ctx == null) {
        throw new IllegalStateException("Context is null during initialization");
      }
      mStoragePath = getSettings().getString("PREF_SAVE_PATH", Environment.getExternalStorageDirectory().toString());
      mSessionName = "csploit-session-" + java.lang.System.currentTimeMillis();
      mKnownIssues = new KnownIssues();
      mPlugins = new ArrayList<>();
      mOpenPorts = new SparseIntArray(3);
      mServices = new HashMap<>();
      mPorts = new HashMap<>();

      // if we are here, network initialization didn't throw any error, lock wifi
      WifiManager wifiManager = (WifiManager) ctx.getSystemService(Context.WIFI_SERVICE);

      if (mWifiLock == null)
        mWifiLock = wifiManager.createWifiLock(WifiManager.WIFI_MODE_FULL, "wifiLock");

      if (!mWifiLock.isHeld())
        mWifiLock.acquire();

      // wake lock if enabled
      if (getSettings().getBoolean("PREF_WAKE_LOCK", true)) {
        PowerManager powerManager = (PowerManager) ctx.getSystemService(Context.POWER_SERVICE);

        if (mWakeLock == null)
          mWakeLock = powerManager.newWakeLock(PowerManager.FULL_WAKE_LOCK, "wakeLock");

        if (!mWakeLock.isHeld())
          mWakeLock.acquire();
      }

      // set ports
      try {
        HTTP_PROXY_PORT = Integer.parseInt(getSettings().getString("PREF_HTTP_PROXY_PORT", "8080"));
        HTTP_SERVER_PORT = Integer.parseInt(getSettings().getString("PREF_HTTP_SERVER_PORT", "8081"));
        HTTPS_REDIR_PORT = Integer.parseInt(getSettings().getString("PREF_HTTPS_REDIRECTOR_PORT", "8082"));
        MSF_RPC_PORT = Integer.parseInt(getSettings().getString("MSF_RPC_PORT", "55553"));
      } catch (NumberFormatException e) {
        HTTP_PROXY_PORT = 8080;
        HTTP_SERVER_PORT = 8081;
        HTTPS_REDIR_PORT = 8082;
        MSF_RPC_PORT = 55553;
      }

      // initialize network data at the end
      uncaughtReloadNetworkMapping();

      if(isCoreInstalled())
        beginLoadServicesAndVendors();
    } catch (Exception e) {
      if (!(e instanceof NoRouteToHostException))
        errorLogging(e);

      throw e;
    }
  }

  /**
   * Safely retrieve the Context from WeakReference.
   * Returns null if the Context has been garbage collected.
   *
   * @return The Context or null if garbage collected
   */
  @Nullable
  private static Context getContextSafe() {
    return mContext != null ? mContext.get() : null;
  }

  private static void beginLoadServicesAndVendors() {
    ThreadHelper.getSharedExecutor().execute(new Runnable() {
      @Override
      public void run() {
        preloadVendors();
        preloadServices();
      }
    });
  }

  public static void onCoreInstalled() {
    beginLoadServicesAndVendors();
  }

  public static void reloadTools() {
    getTools().reload();
  }

  public static class SuException extends Exception {
    public SuException() {
      super("super user access denied");
    }
  }

  public static class DaemonException extends Exception {
    public DaemonException(String message) {
      super(message);
    }
  }

  private static void startCoreDaemon() throws SuException, DaemonException {
    boolean access_granted = false;
    DataOutputStream writer = null;
    BufferedReader reader = null;
    String line;
    int ret = -1;

    try {
      Process shell = Runtime.getRuntime().exec("su");
      writer = new DataOutputStream(shell.getOutputStream());
      String cmd;

      cmd = String.format("{ echo 'ACCESS GRANTED' >&2; cd '%s' && exec ./start_daemon.sh ;} || exit 1\n",
              System.getCorePath());

      writer.write(cmd.getBytes());
      writer.flush();

      ret = shell.waitFor();

      if (ret != 0) {
        reader = new BufferedReader(new InputStreamReader(shell.getErrorStream()));

        while ((line = reader.readLine()) != null) {
          if (line.equals("ACCESS GRANTED")) {
            access_granted = true;
            Logger.debug("'ACCESS GRANTED' found");
          } else
            Logger.warning("STDERR: " + line);
        }
      } else
        access_granted = true;

    } catch (IOException e) {
      // command "su" not found or cannot write to it's stdin
      Logger.error(e.getMessage());
    } catch (InterruptedException e) {
      // interrupted while waiting for shell exit value
      Logger.error(e.getMessage());
    } finally {
      if (writer != null)
        try {
          writer.close();
        } catch (IOException ignored) {
        }
      if (reader != null)
        try {
          reader.close();
        } catch (IOException ignored) {
        }
    }

    mKnownIssues.fromFile(String.format("%s/issues", getCorePath()));

    if (!access_granted)
      throw new SuException();

    if (ret != 0) {
      File log = new File(System.getCorePath(), "cSploitd.log");
      DaemonException daemonException = new DaemonException("core daemon returned " + ret);
   /*   if (log.exists() && log.canRead()) {
        ACRAConfiguration conf = ACRA.getConfig();
        conf.setApplicationLogFile(log.getAbsolutePath());
        ACRA.setConfig(conf);
        ACRA.getErrorReporter().handleException(daemonException, false);
      }*/
      throw daemonException;
    }
  }

  /**
   * shutdown the core daemon
   */
  public static void shutdownCoreDaemon() {
    if (!Client.isConnected() && !Client.Connect(getCorePath() + "/cSploitd.sock")) {
      return; // daemon is not running
    }
    if (!Client.isAuthenticated() && !Client.Login("android", "DEADBEEF")) {
      Logger.error("cannot login to daemon");
    }
    Client.Shutdown();
    Client.Disconnect();

    mCoreInitialized = false;
    Services.getNetworkRadar().onAutoScanChanged();
  }

  public static void initCore() throws DaemonException, SuException {

    if (mCoreInitialized)
      return;

    String socket_path = getCorePath() + "/cSploitd.sock";

    if (!Client.isConnected()) {
      if (!Client.Connect(socket_path)) {
        startCoreDaemon();
        if (!Client.Connect(socket_path))
          throw new DaemonException("cannot connect to core daemon");
      }
    }

    if (!Client.isAuthenticated() && !Client.Login("android", "DEADBEEF")) {
      throw new DaemonException("cannot login to core daemon");
    }

    if (!Client.LoadHandlers()) {
      throw new DaemonException("cannot load handlers");
    }

    ChildManager.storeHandlers();

    reloadTools();

    mCoreInitialized = true;
    Services.getNetworkRadar().onAutoScanChanged();
    getNetwork().onCoreAttached();
  }

  public static void setIfname(String ifname) {
    mIfname = ifname;
  }

  public static String getIfname() {
    return mIfname;
  }

  public static boolean reloadNetworkMapping() {
    try {
      uncaughtReloadNetworkMapping();
      return true;
    } catch (NoRouteToHostException nrthe) {
      // swallow bitch
    } catch (Exception e) {
      errorLogging(e);
    }
    return false;
  }

  private static void uncaughtReloadNetworkMapping() throws UnknownHostException, SocketException {
    Context ctx = mContext != null ? mContext.get() : null;
    if (ctx == null) {
      throw new IllegalStateException("Context is null");
    }
    mNetwork = new Network(ctx, mIfname);
    mIfname = mNetwork.getInterface().getName();

    reset();

    mInitialized = true;
  }

  public static boolean checkNetworking(final FragmentActivity current) {
    if (!mNetwork.isConnected()) {

      Intent intent = new Intent();
      intent.putExtra(WifiScannerFragment.CONNECTED, false);
      current.setResult(AppCompatActivity.RESULT_OK, intent);

      String title = current.getString(R.string.error);
      String message = current.getString(R.string.wifi_went_down);

      new FatalDialog(title, message, current).show();

      return false;
    }

    return true;
  }

  public synchronized static void setTargetListObserver(Observer targetListObserver) {
    System.targetListObserver = targetListObserver;
  }

  /**
   * notify that a specific target of the list has been changed
   *
   * @param target the changed target
   */
  public static void notifyTargetListChanged(Target target) {
    Observer o;
    synchronized (System.class) {
      o = targetListObserver;
    }

    if (o == null)
      return;

    o.update(null, target);
  }

  /**
   * notify that the targets list has been changed
   */
  public static void notifyTargetListChanged() {
    notifyTargetListChanged(null);
  }

  public static void setLastError(String error) {
    mLastError = error;
  }

  public static String getLastError() {
    return mLastError;
  }

  public static synchronized void errorLogging(Throwable e) {
    String message = "Unknown error.";
    String trace = "Unknown trace.";
    String filename = new File(Environment.getExternalStorageDirectory().toString(), ERROR_LOG_FILENAME).getAbsolutePath();

    if (e != null) {
      if (e.getMessage() != null && !e.getMessage().isEmpty()) {
        message = e.getMessage();
      } else if (e.toString() != null) {
        message = e.toString();
      }

      if (message.equals(mLastError)) {
        return;
      }

      try (StringWriter sWriter = new StringWriter();
           PrintWriter pWriter = new PrintWriter(sWriter)) {
        e.printStackTrace(pWriter);
        trace = sWriter.toString();
      } catch (IOException ignored) {
        // StringWriter close doesn't actually throw
      }

      if (mContext != null && getSettings().getBoolean("PREF_DEBUG_ERROR_LOGGING", false)) {
        try (BufferedWriter bWriter = new BufferedWriter(new FileWriter(filename, true))) {
          bWriter.write(trace);
        } catch (IOException ioe) {
          Logger.error(ioe.toString());
        }
      }
    }

    setLastError(message);
    Logger.error(message);
    Logger.error(trace);
  }

  public static String getPlatform() {
    int api = org.csploit.android.helpers.DeviceHelper.getApiLevel();
    String abi = Build.CPU_ABI;

    return String.format("android%d.%s", api, abi);
  }

  public static String getCompatiblePlatform() {
    int currentApi = org.csploit.android.helpers.DeviceHelper.getApiLevel();
    int minApi = (currentApi >= Build.VERSION_CODES.JELLY_BEAN ?
            Build.VERSION_CODES.JELLY_BEAN : Build.VERSION_CODES.GINGERBREAD);
    String abi = Build.CPU_ABI;

    return String.format("android%d.%s", minApi, abi);
  }

  public static boolean isARM() {
    String abi = Build.CPU_ABI;

    Logger.debug("Build.CPU_ABI = " + abi);

    return Build.CPU_ABI.toLowerCase().startsWith("armeabi");
  }

  public static synchronized void setCustomData(Object data) {
    mCustomData = data;
  }

  public static Object getCustomData() {
    return mCustomData;
  }

  public static InputStream getRawResource(int id) {
    Context ctx = getContextSafe();
    if (ctx == null) {
      throw new IllegalStateException("Context has been garbage collected");
    }
    return ctx.getResources().openRawResource(id);
  }

  public static String getDefaultRubyPath() {
    Context ctx = getContextSafe();
    if (ctx == null) {
      throw new IllegalStateException("Context has been garbage collected");
    }
    return ctx.getFilesDir().getAbsolutePath() + "/ruby";
  }

  public static String getRubyPath() {
    return getSettings().getString("RUBY_DIR", getDefaultRubyPath());
  }

  public static String getDefaultMsfPath() {
    Context ctx = getContextSafe();
    if (ctx == null) {
      throw new IllegalStateException("Context has been garbage collected");
    }
    return ctx.getFilesDir().getAbsolutePath() + "/msf";
  }

  public static String getMsfPath() {
    return getSettings().getString("MSF_DIR", getDefaultMsfPath());
  }

  public static String getToolsPath() {
    Context ctx = getContextSafe();
    if (ctx == null) {
      throw new IllegalStateException("Context has been garbage collected");
    }
    return ctx.getFilesDir().getAbsolutePath() + "/tools/";
  }

  public static String getCorePath() {
    Context ctx = getContextSafe();
    if (ctx == null) {
      throw new IllegalStateException("Context has been garbage collected");
    }
    return ctx.getFilesDir().getAbsolutePath();
  }

  public static void registerSettingListener(SettingReceiver receiver) {
    if (mSettingReceivers != null) {
      synchronized (mSettingReceivers) {
        if (!mSettingReceivers.contains(receiver)) {
          mSettingReceivers.add(receiver);
        }
      }
    }
  }

  public static void onSettingChanged(String key) {
    synchronized (mSettingReceivers) {
      for (SettingReceiver r : mSettingReceivers) {
        if (r.getFilter().contains(key))
          r.onSettingChanged(key);
      }
    }
  }

  public static void unregisterSettingListener(SettingReceiver receiver) {
    synchronized (mSettingReceivers) {
      mSettingReceivers.remove(receiver);
    }
  }

  public static void preloadServices() {
    if (!mServices.isEmpty())
      return;

    Context ctx = getContextSafe();
    if (ctx == null) {
      Logger.error("Context has been garbage collected in preloadServices");
      return;
    }
    String servicesFilePath = ctx.getFilesDir().getAbsolutePath() + "/tools/nmap/nmap-services";

    try (BufferedReader reader = new BufferedReader(new FileReader(servicesFilePath))) {
      String line;
      Matcher matcher;

      while ((line = reader.readLine()) != null) {
        if ((matcher = SERVICE_PARSER.matcher(line)) != null && matcher.find()) {
          String proto = matcher.group(1);
          String port = matcher.group(2);

          mServices.put(proto, port);
          mPorts.put(port, proto);
        }
      }
    } catch (Exception e) {
      mServices.clear();
      mPorts.clear();
      errorLogging(e);
    }
  }

  private static synchronized void preloadVendors() {
    if (mVendors == null) {
      mVendors = new HashMap<>();
      Context ctx = getContextSafe();
      if (ctx == null) {
        Logger.error("Context has been garbage collected in preloadVendors");
        return;
      }
      String vendorFilePath = ctx.getFilesDir().getAbsolutePath() + "/tools/nmap/nmap-mac-prefixes";

      try (BufferedReader reader = new BufferedReader(
              new InputStreamReader(new FileInputStream(vendorFilePath)))) {
        String line;
        while ((line = reader.readLine()) != null) {
          line = line.trim();
          if (!line.startsWith("#") && !line.isEmpty()) {
            String[] tokens = line.split(" ", 2);
            if (tokens.length == 2) {
              mVendors.put(NetworkHelper.getOUICode(tokens[0]), tokens[1]);
            }
          }
        }
      } catch (Exception e) {
        errorLogging(e);
      }
    }
  }

  public static String getSessionName() {
    return mSessionName;
  }

  public static String getStoragePath() {
    return mStoragePath;
  }

  public static SharedPreferences getSettings() {
    Context ctx = getContextSafe();
    if (ctx == null) {
      throw new IllegalStateException("Context has been garbage collected");
    }
    return PreferenceManager.getDefaultSharedPreferences(ctx);
  }

  public static String getAppVersionName() {
    if (mApkVersion != null)
      return mApkVersion;
    Context ctx = mContext != null ? mContext.get() : null;
    if (ctx == null) {
      return "unknown";
    }
    return (mApkVersion = org.csploit.android.helpers.AppHelper.getVersionName(ctx));
  }

  /**
   * reade the first line of a file
   *
   * @param filePath path of the file to read from
   * @return the first line of the file or {@code null} if an error occurs
   */
  private static String readFirstLine(String filePath) {
    BufferedReader reader = null;

    if (filePath == null)
      return null;

    try {
      reader = new BufferedReader(new FileReader(filePath));
      return reader.readLine().trim();
    } catch (IOException e) {
      Logger.debug(e.getMessage());
    } finally {
      try {
        if (reader != null)
          reader.close();
      } catch (IOException e) {
        //ignored
      }
    }
    return null;
  }

  /**
   * get currently installed core version
   *
   * @return the version of the core, null if not present.
   */
  public static String getCoreVersion() {
    return readFirstLine(getCorePath() + "/VERSION");
  }

  /**
   * get version of installed ruby
   *
   * @return the installed version of ruby
   */
  public static String getLocalRubyVersion() {
    return readFirstLine(getRubyPath() + "/VERSION");
  }

  /**
   * get version of installed MetaSploit Framework
   *
   * @return the version of installed MetaSploit Framework
   */
  public static String getLocalMsfVersion() {
    return readFirstLine(getMsfPath() + "/VERSION");
  }

  public static boolean isServiceRunning(String name) {
    Context ctx = getContextSafe();
    if (ctx == null) {
      Logger.error("Context has been garbage collected in isServiceRunning");
      return false;
    }
    ActivityManager manager = (ActivityManager) ctx.getSystemService(Context.ACTIVITY_SERVICE);

    //noinspection ConstantConditions
    for (RunningServiceInfo service : manager.getRunningServices(Integer.MAX_VALUE)) {
      if (name.equals(service.service.getClassName()))
        return true;
    }

    return false;
  }

  public static boolean isPortAvailable(int port) {
    boolean available = true;

    int available_code = mOpenPorts.get(port);

    if (available_code != 0)
      return available_code != 1;

    try {
      // attempt 3 times since proxy and server could be still releasing
      // their ports
      for (int i = 0; i < 3; i++) {
        Socket channel = new Socket();
        InetSocketAddress address = new InetSocketAddress(InetAddress.getByName(mNetwork.getLocalAddressAsString()), port);

        channel.connect(address, 200);

        available = !channel.isConnected();

        channel.close();

        if (available)
          break;

        Thread.sleep(200);
      }
    } catch (Exception e) {
      available = true;
    }

    mOpenPorts.put(port, available ? 2 : 1);

    return available;
  }

  public static ArrayList<String> getAvailableSessionFiles() {
    ArrayList<String> files = new ArrayList<String>();
    File storage = new File(mStoragePath);

    if (storage.exists()) {
      String[] children = storage.list();

      if (children != null && children.length > 0) {
        for (String child : children) {
          if (child.endsWith(".dss"))
            files.add(child);
        }
      }
    }

    return files;
  }

  public static String saveSession(String sessionName) throws IOException {
    StringBuilder builder = new StringBuilder();
    String filename = mStoragePath + '/' + sessionName + ".dss",
            session;

    builder.append(SESSION_MAGIC + "\n");

    // skip the network target
    synchronized (mTargets) {
      builder.append(mTargets.size() - 1).append("\n");
      for (Target target : mTargets) {
        if (target.getType() != Target.Type.NETWORK)
          target.serialize(builder);
      }
    }

    session = builder.toString();

    try (GZIPOutputStream gzip = new GZIPOutputStream(new FileOutputStream(filename))) {
      gzip.write(session.getBytes());
    }

    mSessionName = sessionName;

    return filename;
  }

  public static ArrayList<String> getAvailableHijackerSessionFiles() {
    ArrayList<String> files = new ArrayList<String>();
    File storage = new File(mStoragePath);

    if (storage.exists()) {
      String[] children = storage.list();

      if (children != null && children.length > 0) {
        for (String child : children) {
          if (child.endsWith(".dhs"))
            files.add(child);
        }
      }
    }

    return files;
  }

  public static void loadSession(String filename) throws Exception {
    File file = new File(mStoragePath + '/' + filename);

    if (file.exists() && file.length() > 0) {
      try (BufferedReader reader = new BufferedReader(new InputStreamReader(new GZIPInputStream(new FileInputStream(file))))) {
        String line = reader.readLine();
        if (line == null || !line.equals(SESSION_MAGIC))
          throw new Exception("Not a cSploit session file.");

        reset();

        // read targets
        int targets = Integer.parseInt(reader.readLine());

        synchronized (mTargets) {
          for (int i = 0; i < targets; i++) {
            Target target = new Target(reader);
            mTargets.add(target);
          }
        }

      } catch (Exception e) {
        reset();
        throw e;
      } finally {
        notifyTargetListChanged();
      }
    } else
      throw new Exception(filename + " does not exists or is empty.");
  }

  public synchronized static ToolBox getTools() {
    if (mTools == null) {
      mTools = new ToolBox();
      mTools.reload();
    }
    return mTools;
  }

  public static RPCClient getMsfRpc() {
    return mMsfRpc;
  }

  public static void setMsfRpc(RPCClient value) {
    if (value == mMsfRpc)
      return;
    mMsfRpc = value;
    // refresh all exploits
    // NOTE: this method is usually called by the RPCServer Thread, which will not block the UI
    for (Target t : getTargets()) { // use a copy of the targets to avoid deadlocks.
      for (Exploit e : t.getExploits()) {
        if (e instanceof MsfExploit) {
          ((MsfExploit) e).refresh();
        }
      }
    }
    for (Plugin plugin : getPluginsForTarget()) {
      plugin.onRpcChange(value);
    }

  }

  public static Proxy getProxy() {
    try {
      if (mProxy == null)
        mProxy = new Proxy(getNetwork().getLocalAddress(), HTTP_PROXY_PORT);
    } catch (Exception e) {
      errorLogging(e);
    }

    return mProxy;
  }

  public static HTTPSRedirector getHttpsRedirector() {
    try {
      if (mRedirector == null) {
        Context ctx = mContext != null ? mContext.get() : null;
        mRedirector = new HTTPSRedirector(ctx, getNetwork().getLocalAddress(), HTTPS_REDIR_PORT);
      }
    } catch (Exception e) {
      errorLogging(e);
    }

    return mRedirector;
  }

  public static Server getServer() {
    try {
      if (mServer == null)
        mServer = new Server(getNetwork().getLocalAddress(), HTTP_SERVER_PORT);
    } catch (Exception e) {
      errorLogging(e);
    }

    return mServer;
  }

  public static String getImageMimeType(String fileName) {
    String type = "image/jpeg",
            name = fileName.toLowerCase();

    if (name.endsWith(".jpeg") || name.endsWith(".jpg"))
      type = "image/jpeg";

    else if (name.endsWith(".png"))
      type = "image/png";

    else if (name.endsWith(".gif"))
      type = "image/gif";

    else if (name.endsWith(".tiff"))
      type = "image/tiff";

    return type;
  }

  public static void reset() {
    mCurrentTarget = null;

    synchronized (mTargets) {
      mTargets.clear();

      Target network, gateway, device;

      network = new Target(mNetwork);
      device = new Target(mNetwork.getLocalAddress(), mNetwork.getLocalHardware());


      device.setAlias(android.os.Build.MODEL);

      mTargets.add(network);

      if(mNetwork.haveGateway()) {
        gateway = new Target(mNetwork.getGatewayAddress(), mNetwork.getGatewayHardware());
        gateway.setAlias(mNetwork.getSSID());
        mTargets.add(gateway);
      }

      mTargets.add(device);

      scanThemAll();
    }

    notifyTargetListChanged();
  }

  public static void scanThemAll() {
    if (!Services.getNetworkRadar().isAutoScanEnabled()) {
      return;
    }
    synchronized (mTargets) {
      for (Target t : mTargets) {
        Services.getNetworkRadar().onNewTargetFound(t);
      }
    }
  }

  public static void markNetworkAsDisconnected() {
    synchronized (mTargets) {
      for (Target t : mTargets) {
        switch (t.getType()) {
          case NETWORK:
            if (t.getNetwork() == mNetwork) {
              t.setConneced(false);
            }
            break;
          case ENDPOINT:
            if (mNetwork.isInternal(t.getAddress())) {
              t.setConneced(false);
            }
            break;
        }
      }
    }
    notifyTargetListChanged();
  }

  public static void markInitialNetworkTargetsAsConnected() {
    InetAddress localAddress = mNetwork.getLocalAddress();
    boolean haveGateway = mNetwork.haveGateway();
    InetAddress gatewayAddress = mNetwork.getGatewayAddress();

    synchronized (mTargets) {
      for (Target t : mTargets) {
        switch (t.getType()) {
          case NETWORK:
            if (t.getNetwork() == mNetwork) {
              t.setConneced(true);
            }
          default:
            if (localAddress.equals(t.getAddress()) ||
                    (haveGateway && gatewayAddress.equals(t.getAddress()))) {
              t.setConneced(true);
            }
            break;
        }
      }
    }
    notifyTargetListChanged();
  }

  public static boolean isInitialized() {
    return mInitialized;
  }

  public static boolean isCoreInstalled() {
    return new File(getCorePath() + "/VERSION").exists();
  }

  public static boolean isCoreInitialized() {
    return mCoreInitialized;
  }

  public static KnownIssues getKnownIssues() {
    return mKnownIssues;
  }

  public static String getMacVendor(@Nullable byte[] mac) {
    if (mac != null && mVendors != null && mac.length >= 3)
      return mVendors.get(NetworkHelper.getOUICode(mac));
    else
      return null;
  }

  public static String getProtocolByPort(String port) {

    return mPorts.containsKey(port) ? mPorts.get(port) : null;
  }

  public static String getProtocolByPort(int port) {
    return getProtocolByPort(Integer.toString(port));
  }

  public static int getPortByProtocol(String protocol) {

    return mServices.containsKey(protocol) ? Integer.parseInt(mServices.get(protocol)) : 0;
  }

  public static Context getContext() {
    return getContextSafe();
  }

  public static Network getNetwork() {
    return mNetwork;
  }

  /**
   * get a copy of the current targets
   *
   * @return a copy of the target list
   */
  public static List<Target> getTargets() {
    synchronized (mTargets) {
      return new ArrayList<>(mTargets);
    }
  }

  /**
   * Get a target by its unique identifier (UUID).
   * This is a safer alternative to index-based access as UUIDs remain stable
   * even when the target list is modified.
   *
   * @param uuid the unique identifier of the target
   * @return the target with the given UUID, or null if not found
   */
  public static Target getTargetByUuid(String uuid) {
    if (uuid == null) return null;
    synchronized (mTargets) {
      for (Target target : mTargets) {
        if (uuid.equals(target.getUuid())) {
          return target;
        }
      }
    }
    return null;
  }

  /**
   * add a target to the list keeping it sorted.
   *
   * @param target the target to add
   * @return true if target is added, false if already present
   */
  public static boolean addOrderedTarget(Target target) {
    if (target == null)
      return false;

    boolean changed;

    synchronized (mTargets) {
      changed = mTargets.add(target);
      if(changed) {
        Services.getNetworkRadar().onNewTargetFound(target);
        notifyTargetListChanged();
      }
    }
    return changed;
  }

  public static boolean hasTarget(Target target) {
    synchronized (mTargets) {
      return mTargets.contains(target);
    }
  }

  public static void setCurrentTarget(Target target) {
    mCurrentTarget = target;
  }

  public static Target getCurrentTarget() {
    return mCurrentTarget;
  }

  public static Target getTargetByAddress(String address) {
    try {
      return getTargetByAddress(InetAddress.getByName(address));
    } catch (UnknownHostException e) {
      Logger.error("cannot convert '" + address + "' to InetAddress: " + e.getMessage());
    }
    return null;
  }

  public static Target getTargetByAddress(InetAddress address) {
    synchronized (mTargets) {
      for(Target t : mTargets) {
        if (t != null && t.getAddress() != null && t.getAddress().equals(address)) {
          return t;
        }
      }
    }

    return null;
  }

  public static void registerPlugin(Plugin plugin) {
    if (mPlugins.contains(plugin)) {
      Logger.warning("registerPlugin() plugin " + plugin.getName() + " already added");
    } else
      mPlugins.add(plugin);
  }

  public static ArrayList<Plugin> getPlugins() {
    return mPlugins;
  }

  public static ArrayList<Plugin> getPluginsForTarget(Target target) {
    ArrayList<Plugin> filtered = new ArrayList<Plugin>();

    if (target != null) {
      for (Plugin plugin : mPlugins)
        if (plugin.isAllowedTarget(target))
          filtered.add(plugin);
    }

    return filtered;
  }

  public static ArrayList<Plugin> getPluginsForTarget() {
    return getPluginsForTarget(getCurrentTarget());
  }

  public static void setCurrentPlugin(Plugin plugin) {
    Context ctx = getContextSafe();
    String pluginName = (ctx != null) ? ctx.getString(plugin.getName()) : "unknown";
    Logger.debug("Setting current plugin : " + pluginName);

    mCurrentPlugin = plugin;
  }

  public static Plugin getCurrentPlugin() {
    return mCurrentPlugin;
  }

  public static void setCurrentExploit(Exploit exploit) {
    mExploit = exploit;
  }

  public static Exploit getCurrentExploit() {
    return mExploit;
  }

  public static void setCurrentPayload(Payload payload) {
    mPayload = payload;
  }

  public static Payload getCurrentPayload() {
    return mPayload;
  }

  public static void setCurrentSession(Session s) {
    mMsfSession = s;
  }

  public static Session getCurrentSession() {
    return mMsfSession;
  }

  public static Collection<Exploit> getCurrentExploits() {
    return getCurrentTarget().getExploits();
  }

  public static boolean isForwardingEnabled() {
    try (BufferedReader reader = new BufferedReader(new FileReader(IPV4_FORWARD_FILEPATH))) {
      String line = reader.readLine();
      return line != null && line.trim().equals("1");
    } catch (IOException e) {
      Logger.warning(e.toString());
      return false;
    }
  }

  public static void setForwarding(boolean enabled) {
    Logger.debug("Setting ipv4 forwarding to " + enabled);

    String status = (enabled ? "1" : "0"),
            cmd = "echo " + status + " > " + IPV4_FORWARD_FILEPATH;

    try {
      getTools().shell.run(cmd);
    } catch (Exception e) {
      Logger.error(e.getMessage());
    }
  }

  public static void clean(boolean releaseLocks) {
    setForwarding(false);

    try {
      if (releaseLocks) {
        Logger.debug("Releasing locks.");

        if (mWifiLock != null && mWifiLock.isHeld())
          mWifiLock.release();

        if (mWakeLock != null && mWakeLock.isHeld())
          mWakeLock.release();
      }

      RemoteReader.terminateAll();

      GitHubParser.resetAll();

      synchronized (mTargets) {

        for (Target t : mTargets)
          for (Session s : t.getSessions())
            s.stopSession();

        mTargets.clear();
      }

      Client.Disconnect();
      mCoreInitialized = false;
      mInitialized = false;
      Services.getNetworkRadar().onAutoScanChanged();
    } catch (Exception e) {
      errorLogging(e);
    }
  }

}
