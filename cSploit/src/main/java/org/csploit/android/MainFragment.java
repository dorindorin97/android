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
package org.csploit.android;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.Intent;
import android.content.IntentFilter;
import android.content.SharedPreferences;
import android.graphics.Typeface;
import android.net.ConnectivityManager;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import androidx.core.content.ContextCompat;
import androidx.appcompat.app.AppCompatActivity;
import androidx.appcompat.view.ActionMode;
import androidx.core.text.HtmlCompat;
import android.view.LayoutInflater;
import android.view.Menu;
import android.view.MenuInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.BaseAdapter;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.TextView;

import org.csploit.android.core.Child;
import org.csploit.android.core.Client;
import org.csploit.android.core.CrashReporter;
import org.csploit.android.helpers.LoggingHelper;
import org.csploit.android.core.ManagedReceiver;
import org.csploit.android.core.MultiAttackService;
import org.csploit.android.core.Plugin;
import org.csploit.android.core.System;
import org.csploit.android.events.Event;
import org.csploit.android.gui.dialogs.AboutDialog;
import org.csploit.android.gui.dialogs.ChoiceDialog;
import org.csploit.android.gui.dialogs.ConfirmDialog;
import org.csploit.android.gui.dialogs.ConfirmDialog.ConfirmDialogListener;
import org.csploit.android.gui.dialogs.FatalDialog;
import org.csploit.android.gui.dialogs.InputDialog;
import org.csploit.android.gui.dialogs.InputDialog.InputDialogListener;
import org.csploit.android.gui.dialogs.ListChoiceDialog;
import org.csploit.android.gui.dialogs.MultipleChoiceDialog;
import org.csploit.android.gui.dialogs.SpinnerDialog;
import org.csploit.android.helpers.ToastHelper;
import org.csploit.android.helpers.UIHelper;
import org.csploit.android.gui.dialogs.SpinnerDialog.SpinnerDialogListener;
import org.csploit.android.helpers.ConcurrencyHelper;
import org.csploit.android.helpers.DeviceHelper;
import org.csploit.android.helpers.ThreadHelper;
import org.csploit.android.net.Network;
import org.csploit.android.net.Target;
import org.csploit.android.plugins.ExploitFinder;
import org.csploit.android.plugins.Inspector;
import org.csploit.android.plugins.LoginCracker;
import org.csploit.android.plugins.PacketForger;
import org.csploit.android.plugins.PortScanner;
import org.csploit.android.plugins.RouterPwn;
import org.csploit.android.plugins.Sessions;
import org.csploit.android.plugins.Traceroute;
import org.csploit.android.plugins.mitm.MITM;
import org.csploit.android.services.Services;
import org.csploit.android.services.UpdateChecker;
import org.csploit.android.services.UpdateService;
import org.csploit.android.services.receivers.MsfRpcdServiceReceiver;
import org.csploit.android.services.receivers.NetworkRadarReceiver;
import org.csploit.android.update.CoreUpdate;
import org.csploit.android.update.MsfUpdate;
import org.csploit.android.update.RubyUpdate;
import org.csploit.android.update.Update;

import java.io.IOException;
import java.net.NoRouteToHostException;
import java.util.ArrayList;
import java.util.List;
import java.util.Timer;
import java.util.TimerTask;

import static org.csploit.android.services.UpdateChecker.UPDATE_AVAILABLE;
import static org.csploit.android.services.UpdateChecker.UPDATE_CHECKING;
import static org.csploit.android.services.UpdateChecker.UPDATE_NOT_AVAILABLE;

@SuppressLint("NewApi")
public class MainFragment extends Fragment {
    private static final String TAG = "MainFragment";
    private String EMPTY_LIST_MESSAGE = "";
    private static final int WIFI_CONNECTION_REQUEST = 1012;
    private boolean isAnyNetInterfaceAvailable = false;
    private TargetAdapter mTargetAdapter = null;
    private NetworkRadarReceiver mRadarReceiver = new NetworkRadarReceiver();
    private UpdateReceiver mUpdateReceiver = new UpdateReceiver();
    private WipeReceiver mWipeReceiver = new WipeReceiver();
    private MsfRpcdServiceReceiver mMsfReceiver = new MsfRpcdServiceReceiver();
    private ConnectivityReceiver mConnectivityReceiver = new ConnectivityReceiver();
    private Menu mMenu = null;
    private TextView mEmptyTextView = null;
    private TextView mTextView = null;
    private long mLastBackPressTime = 0;
    private ActionMode mActionMode = null;
    private ListView lv;
    private String[] mIfaces = null;
    private boolean mIsCoreInstalled = false;
    private boolean mIsDaemonBeating = false;
    private boolean mIsConnectivityAvailable = false;
    private boolean mIsUpdateDownloading = false;
    private boolean mHaveAnyWifiInterface = false;  // Will be set in onCreateView based on device capabilities
    private boolean mOfflineMode = false;

    @Override
    public void onActivityResult(int requestCode, int resultCode,
                                 Intent intent) {
        if (requestCode == WIFI_CONNECTION_REQUEST && resultCode == AppCompatActivity.RESULT_OK
                && intent.hasExtra(WifiScannerFragment.CONNECTED)) {
            init();
        }
    }

    private void onInitializationError(final String message) {
        android.app.Activity activity = getActivity();
        if (activity == null || !isAdded()) {
            LoggingHelper.error("Cannot show initialization error - fragment not attached: " + message);
            return;
        }
        activity.runOnUiThread(new Runnable() {
            @Override
            public void run() {
                androidx.fragment.app.FragmentActivity currentActivity = (androidx.fragment.app.FragmentActivity) getActivity();
                if (currentActivity == null || !isAdded()) {
                    return;
                }
                new FatalDialog(getString(R.string.initialization_error),
                        message, message.contains(">"),
                        currentActivity);
            }
        });
    }

    private void onCoreUpdated() {
        System.onCoreInstalled();
        android.app.Activity activity = getActivity();
        if (activity == null || !isAdded()) {
            return;
        }
        activity.runOnUiThread(new Runnable() {
            @Override
            public void run() {
                if (getActivity() == null || !isAdded()) {
                    return;
                }
                init();
                startAllServices();
                notifyMenuChanged();
            }
        });
    }

    @Nullable
    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setHasOptionsMenu(true);
        
        // Check if device has WiFi interface
        if (getActivity() != null) {
            mHaveAnyWifiInterface = DeviceHelper.hasWiFi(getActivity());
        }
        
        return inflater.inflate(R.layout.target_layout, container, false);
    }

    @Override
    public void onViewCreated(View v, Bundle savedInstanceState) {
        android.app.Activity activity = getActivity();
        if (activity != null) {
            SharedPreferences themePrefs = activity.getSharedPreferences("THEME", 0);
            Boolean isDark = themePrefs.getBoolean("isDark", false);
            if (isDark) {
                activity.setTheme(R.style.DarkTheme);
                v.setBackgroundColor(ContextCompat.getColor(activity, R.color.background_window_dark));
            } else {
                activity.setTheme(R.style.AppTheme);
                v.setBackgroundColor(ContextCompat.getColor(activity, R.color.background_window));
            }
        }
        mEmptyTextView = (TextView) v.findViewById(R.id.emptyTextView);
        lv = (ListView) v.findViewById(R.id.android_list);
        mTextView = (TextView) v.findViewById(R.id.textView);

        lv.setOnItemClickListener(new ListView.OnItemClickListener() {

            @Override
            public void onItemClick(AdapterView<?> parent, View view, int position, long id) {

                if (mActionMode != null) {
                    mTargetAdapter.toggleSelection(position);
                    return;
                }

                Target target = (Target) mTargetAdapter.getItem(position);
                System.setCurrentTarget(target);

                android.app.Activity clickActivity = getActivity();
                if (clickActivity != null) {
                    startActivityForResult(new Intent(clickActivity,
                            ActionActivity.class), WIFI_CONNECTION_REQUEST);
                    clickActivity.overridePendingTransition(R.anim.fadeout, R.anim.fadein);
                }

                ToastHelper.status(getActivity(),
                        getString(R.string.selected_) + System.getCurrentTarget());

            }
        });
        lv.setOnItemLongClickListener(new AdapterView.OnItemLongClickListener() {
            @Override
            public boolean onItemLongClick(AdapterView<?> parent, View view, int position, long id) {
                Target t = (Target) mTargetAdapter.getItem(position);
                if (t.getType() == Target.Type.NETWORK) {
                    if (mActionMode == null)
                        targetAliasPrompt(t);
                    return true;
                }
                if (mActionMode == null) {
                    mTargetAdapter.clearSelection();
                    mActionMode = ((AppCompatActivity) getActivity()).startSupportActionMode(mActionModeCallback);
                }
                mTargetAdapter.toggleSelection(position);
                return true;
            }
        });
        mTargetAdapter = new TargetAdapter();

        lv.setEmptyView(v.findViewById(android.R.id.empty));
        lv.setAdapter(mTargetAdapter);

        System.setTargetListObserver(mTargetAdapter);

        android.app.Activity regActivity = getActivity();
        if (regActivity != null) {
            mRadarReceiver.register(regActivity);
            mUpdateReceiver.register(regActivity);
            mWipeReceiver.register(regActivity);
            mMsfReceiver.register(regActivity);
            mConnectivityReceiver.register(regActivity);
        }

        init();
        startAllServices();
    }

    private void startAllServices() {
        startNetworkRadar();
        startUpdateChecker();
        startRPCServer();
    }

    private void notifyMenuChanged() {
        android.app.Activity a = getActivity();
        if (a != null) a.invalidateOptionsMenu();
    }

    /**
     * Performs the firsts actions when the app starts.
     * called also when the user connects to a wifi from the app, and when the core is updated.
     */
    public void init() {
        loadInterfaces();
        isAnyNetInterfaceAvailable = (mIfaces.length > 0);
        mIsConnectivityAvailable = isConnectivityAvailable();

        mIsCoreInstalled = System.isCoreInstalled();
        mIsDaemonBeating = System.isCoreInitialized();
        
        // Log core status for debugging
        LoggingHelper.debug("Core installation status:\n" + System.getCoreInstallStatus());

        // check minimum requirements for system initialization

        if (!mIsCoreInstalled) {
            EMPTY_LIST_MESSAGE = mIsConnectivityAvailable ?
                    getString(R.string.missing_core_update) :
                    getString(R.string.no_connectivity);
            LoggingHelper.warning("Core not installed. Status: " + System.getCoreInstallStatus());
            return;
        } else if (!mIsDaemonBeating) {
            try {
                System.initCore();
                mIsDaemonBeating = true;

                if (Client.hadCrashed()) {
                    LoggingHelper.warning("Client has previously crashed, building a crash report.");
                    CrashReporter.notifyNativeLibraryCrash();
                    onInitializationError(getString(R.string.JNI_crash_detected));
                    return;
                }
            } catch (UnsatisfiedLinkError e) {
                onInitializationError("hi developer, you missed to build JNI stuff, thanks for playing with me :)");
                return;
            } catch (System.SuException e) {
                LoggingHelper.error("Root access denied. Make sure:\n1. Device is rooted\n2. Root manager (Magisk/SuperSU) is working\n3. cSploit has root permission granted");
                if (!org.csploit.android.BuildConfig.DEBUG) {
                    onInitializationError(getString(R.string.only_4_root));
                    return;
                }
                // Debug: pretend daemon is up so we reach initSystem() and DebugSeeder runs
                mIsDaemonBeating = true;
            } catch (System.DaemonException e) {
                LoggingHelper.error("Daemon exception: " + e.getMessage());
                onInitializationError(e.getMessage());
                return;
            }

            if (!mIsDaemonBeating) {
                if (mIsConnectivityAvailable) {
                    EMPTY_LIST_MESSAGE = getString(R.string.heart_attack_update);
                } else {
                    onInitializationError(getString(R.string.heart_attack));
                }
                return;
            }
        }

        // if all is initialized, configure the network
        initSystem();
    }

    @Override
    public void onCreateOptionsMenu(Menu menu, MenuInflater inflater) {
        inflater.inflate(R.menu.main, menu);

        mMenu = menu;
        configureMenu();
        super.onCreateOptionsMenu(menu, inflater);
        if (getActivity() != null) getActivity().onCreateOptionsMenu(menu);
    }

    private boolean isConnectivityAvailable() {
        android.app.Activity a = getActivity();
        return a != null && (Network.isConnectivityAvailable(a) || Network.isWifiConnected(a));
    }

    public void configureMenu() {
        if (mMenu == null)
            return;
        mMenu.findItem(R.id.add).setVisible(isAnyNetInterfaceAvailable);
        mMenu.findItem(R.id.scan).setVisible(mHaveAnyWifiInterface);
        mMenu.findItem(R.id.wifi_ifaces).setEnabled(canChangeInterface());
        mMenu.findItem(R.id.new_session).setEnabled(isAnyNetInterfaceAvailable);
        mMenu.findItem(R.id.save_session).setEnabled(isAnyNetInterfaceAvailable);
        mMenu.findItem(R.id.restore_session).setEnabled(isAnyNetInterfaceAvailable);
    }

    @Override
    public void onPrepareOptionsMenu(Menu menu) {
        super.onPrepareOptionsMenu(menu);
        MenuItem item = menu.findItem(R.id.ss_monitor);

        Services.getNetworkRadar().buildMenuItem(item);

        item = menu.findItem(R.id.ss_msfrpcd);

        Services.getMsfRpcdService().buildMenuItem(item);

        mMenu = menu;
        if (getActivity() != null) getActivity().onPrepareOptionsMenu(menu);
    }

    private boolean initSystem() {
        // retry
        try {
            if (getActivity() == null) return false;
            System.init(getActivity().getApplicationContext());
        } catch (Exception e) {
            boolean isFatal = !(e instanceof NoRouteToHostException);

            if (isFatal) {
                LoggingHelper.e(TAG, "Failed to initialize system", e);
                onInitializationError(System.getLastError());
            }

            return !isFatal;
        }

        // Re-seed debug targets after every System.init() since it clears mTargets
        org.csploit.android.debug.DebugSeeder.seed();

        registerPlugins();
        return true;
    }

    private void registerPlugins() {
        if (!System.getPlugins().isEmpty())
            return;

        System.registerPlugin(new RouterPwn());
        System.registerPlugin(new Traceroute());
        System.registerPlugin(new PortScanner());
        System.registerPlugin(new Inspector());
        System.registerPlugin(new ExploitFinder());
        System.registerPlugin(new LoginCracker());
        System.registerPlugin(new Sessions());
        System.registerPlugin(new MITM());
        System.registerPlugin(new PacketForger());
    }

    private void loadInterfaces() {
        boolean menuChanged;
        List<String> interfaces = Network.getAvailableInterfaces();
        int size = interfaces.size();

        if (mIfaces != null) {
            menuChanged = mIfaces.length != size;
            menuChanged &= mIfaces.length <= 1 || size <= 1;
        } else {
            menuChanged = true;
        }

        mIfaces = new String[size];
        interfaces.toArray(mIfaces);
        isAnyNetInterfaceAvailable = mIfaces.length > 0;

        if (menuChanged) {
            android.app.Activity activity = getActivity();
            if (activity != null && isAdded()) {
                activity.runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        if (getActivity() != null && isAdded()) {
                            notifyMenuChanged();
                        }
                    }
                });
            }
        }
    }

    private boolean canChangeInterface() {
        return mIfaces.length > 1 || (mOfflineMode && isAnyNetInterfaceAvailable);
    }

    private boolean haveInterface(String ifname) {
        for (String s : mIfaces) {
            if (s.equals(ifname))
                return true;
        }
        return false;
    }

    private void onNetworkInterfaceChanged() {
        String toastMessage = null;

        stopNetworkRadar();

        if (!System.reloadNetworkMapping()) {
            String ifname = System.getIfname();

            ifname = ifname == null ? getString(R.string.any_interface) : ifname;

            toastMessage = String.format(getString(R.string.error_initializing_interface), ifname);
        } else {
            startNetworkRadar();
            registerPlugins();
        }

        final String msg = toastMessage;

        android.app.Activity activity = getActivity();
        if (activity == null || !isAdded()) {
            return;
        }
        activity.runOnUiThread(new Runnable() {
            @Override
            public void run() {
                android.app.Activity currentActivity = getActivity();
                if (currentActivity == null || !isAdded()) {
                    return;
                }
                if (msg != null) {
                    ToastHelper.status(currentActivity, msg);
                }
                notifyMenuChanged();
            }
        });
    }

    private void onConnectionLost() {
        if (mOfflineMode)
            return;

        mOfflineMode = true;

        stopNetworkRadar();
        System.markNetworkAsDisconnected();

        android.app.Activity activity = getActivity();
        if (activity == null || !isAdded()) {
            return;
        }
        activity.runOnUiThread(new Runnable() {
            @Override
            public void run() {
                androidx.fragment.app.FragmentActivity currentActivity = (androidx.fragment.app.FragmentActivity) getActivity();
                if (currentActivity == null || !isAdded()) {
                    return;
                }
                new ConfirmDialog(getString(R.string.connection_lost),
                        getString(R.string.connection_lost_prompt), currentActivity,
                        new ConfirmDialogListener() {
                            @Override
                            public void onConfirm() {
                                mOfflineMode = false;
                                System.setIfname(null);
                                onNetworkInterfaceChanged();
                            }

                            @Override
                            public void onCancel() {
                            }
                        });
            }
        });
    }

    private void onConnectionResumed() {
        if (!mOfflineMode)
            return;
        mOfflineMode = false;
        System.markInitialNetworkTargetsAsConnected();
        startNetworkRadar();
    }

    /**
     * Displays a dialog for choose a network interface
     *
     * @param forceDialog forces to show the dialog even if there's only one interface
     */
    private void displayNetworkInterfaces(final boolean forceDialog) {
        // reload the interfaces list if we've invoked the dialog from the menu
        loadInterfaces();
        boolean autoload = !forceDialog && mIfaces.length == 1;

        if (autoload) {
            System.setIfname(mIfaces[0]);
            onNetworkInterfaceChanged();
        } else if (isAnyNetInterfaceAvailable) {
            String title = getString(R.string.iface_dialog_title);

            new ListChoiceDialog(title, mIfaces, getActivity(), new ChoiceDialog.ChoiceDialogListener() {
                @Override
                public void onChoice(int index) {
                    System.setIfname(mIfaces[index]);
                    onNetworkInterfaceChanged();
                }
            });
        } else {
            UIHelper.error(getActivity(), getString(android.R.string.dialog_alert_title),
                    getString(R.string.iface_error_no_available));
        }
    }

    private void targetAliasPrompt(final Target target) {

        new InputDialog(getString(R.string.target_alias),
                getString(R.string.set_alias),
                target.hasAlias() ? target.getAlias() : "", true,
                false, getActivity(), new InputDialogListener() {
            @Override
            public void onInputEntered(String input) {
                target.setAlias(input);
                mTargetAdapter.notifyDataSetChanged();
            }
        });
    }

    private ActionMode.Callback mActionModeCallback = new ActionMode.Callback() {

        public boolean onCreateActionMode(ActionMode mode, Menu menu) {
            MenuInflater inflater = mode.getMenuInflater();
            inflater.inflate(R.menu.main_multi, menu);
            return true;
        }

        public boolean onPrepareActionMode(ActionMode mode, Menu menu) {
            int i = mTargetAdapter.getSelectedCount();
            mode.setTitle(i + " " + getString((i > 1 ? R.string.targets_selected : R.string.target_selected)));
            MenuItem item = menu.findItem(R.id.multi_action);
            if (item != null)
                item.setIcon((i > 1 ? android.R.drawable.ic_dialog_dialer : android.R.drawable.ic_menu_edit));
            return false;
        }

        public boolean onActionItemClicked(ActionMode mode, MenuItem item) {
            ArrayList<Plugin> commonPlugins = null;

            int itemId = item.getItemId();
            if (itemId == R.id.multi_action) {
                final int[] selected = mTargetAdapter.getSelectedPositions();
                if (selected.length > 1) {
                    Target target = (Target) mTargetAdapter.getItem(selected[0]);
                    commonPlugins = System.getPluginsForTarget(target);
                    for (int i = 1; i < selected.length; i++) {
                        target = (Target) mTargetAdapter.getItem(selected[i]);
                        ArrayList<Plugin> targetPlugins = System.getPluginsForTarget(target);
                        ArrayList<Plugin> removeThem = new ArrayList<Plugin>();
                        for (Plugin p : commonPlugins) {
                            if (!targetPlugins.contains(p))
                                removeThem.add(p);
                        }
                        for (Plugin p : removeThem) {
                            commonPlugins.remove(p);
                        }
                    }
                    if (!commonPlugins.isEmpty()) {
                        final int[] actions = new int[commonPlugins.size()];
                        for (int i = 0; i < actions.length; i++)
                            actions[i] = commonPlugins.get(i).getName();

                        new MultipleChoiceDialog(R.string.choose_method, actions, getActivity(), new MultipleChoiceDialog.MultipleChoiceDialogListener() {
                            @Override
                            public void onChoice(int[] choices) {
                                Intent intent = new Intent(getActivity(), MultiAttackService.class);
                                int[] selectedActions = new int[choices.length];

                                for (int i = 0; i < selectedActions.length; i++)
                                    selectedActions[i] = actions[choices[i]];

                                // Use UUID-based targeting for stability (preferred)
                                String[] targetUuids = new String[selected.length];
                                for (int i = 0; i < selected.length; i++) {
                                    Target t = (Target) mTargetAdapter.getItem(selected[i]);
                                    targetUuids[i] = t.getUuid();
                                }
                                intent.putExtra(MultiAttackService.MULTI_TARGET_UUIDS, targetUuids);
                                intent.putExtra(MultiAttackService.MULTI_ACTIONS, selectedActions);

                                getActivity().startService(intent);
                            }
                        });
                    } else {
                        UIHelper.error(getActivity(), getString(R.string.error), "no common actions found");
                    }
                } else {
                    targetAliasPrompt((Target) mTargetAdapter.getItem(selected[0]));
                }
                mode.finish(); // Action picked, so close the CAB
                return true;
            }
            return false;
        }

        // called when the user exits the action mode
        public void onDestroyActionMode(ActionMode mode) {
            mActionMode = null;
            mTargetAdapter.clearSelection();
        }
    };

    public void startUpdateChecker() {
        if (!isConnectivityAvailable() || mIsUpdateDownloading)
            return;
        if (System.getSettings().getBoolean("PREF_CHECK_UPDATES", true)) {
            new UpdateChecker(getActivity()).start();
            mIsUpdateDownloading = true;
        } else {
            android.app.Activity ucActivity = getActivity();
            if (ucActivity != null) {
                Intent ucIntent = new Intent(UPDATE_NOT_AVAILABLE);
                ucIntent.setPackage(ucActivity.getPackageName());
                ucActivity.sendBroadcast(ucIntent);
            }
            mIsUpdateDownloading = false;
        }
    }

    public void startNetworkRadar() {
        if (!isAnyNetInterfaceAvailable || !mIsDaemonBeating) {
            return;
        }
        ThreadHelper.getSharedExecutor().execute(new Runnable() {
            @Override
            public void run() {
                Services.getNetworkRadar().start();
            }
        });
    }

    public void stopNetworkRadar() {
        ThreadHelper.getSharedExecutor().execute(new Runnable() {
            @Override
            public void run() {
                Services.getNetworkRadar().stop();
            }
        });
    }

    /**
     * start MSF RPC Daemon
     */
    public void startRPCServer() {
        ThreadHelper.getSharedExecutor().execute(new Runnable() {
            @Override
            public void run() {
                if (Services.getMsfRpcdService().isAvailable())
                    Services.getMsfRpcdService().start();
            }
        });
    }

    /**
     * stop MSF RPC Daemon
     */
    public void stopRPCServer() {
        ThreadHelper.getSharedExecutor().execute(new Runnable() {
            @Override
            public void run() {
                Services.getMsfRpcdService().stop();
            }
        });
    }

    @Override
    public boolean onOptionsItemSelected(final MenuItem item) {
        int itemId = item.getItemId();
        if (itemId == R.id.add) {
            new InputDialog(getString(R.string.add_custom_target),
                    getString(R.string.enter_url), getActivity(),
                    new InputDialogListener() {
                        @Override
                        public void onInputEntered(String input) {
                            final Target target = Target.getFromString(input);
                            if (target != null) {
                                ThreadHelper.getSharedExecutor().execute(new Runnable() {
                                    @Override
                                    public void run() {
                                        System.addOrderedTarget(target);
                                    }
                                });
                            } else
                                UIHelper.error(getActivity(), getString(R.string.error),
                                        getString(R.string.invalid_target));
                        }
                    });
            return true;
        } else if (itemId == R.id.scan) {
            startNetworkRadar();
            return true;
        } else if (itemId == R.id.wifi_ifaces) {
            displayNetworkInterfaces(true);
            return true;
        } else if (itemId == R.id.wifi_scan) {
            stopNetworkRadar();

            mRadarReceiver.unregister();
            mUpdateReceiver.unregister();
            mWipeReceiver.unregister();
            mMsfReceiver.unregister();
            mConnectivityReceiver.unregister();

            android.app.Activity wifiActivity = getActivity();
            if (wifiActivity != null) {
                startActivityForResult(new Intent(wifiActivity,
                        WifiScannerActivity.class), WIFI_CONNECTION_REQUEST);
                wifiActivity.overridePendingTransition(R.anim.fadeout, R.anim.fadein);
            }
            return true;
        } else if (itemId == R.id.new_session) {
            new ConfirmDialog(getString(R.string.warning),
                    getString(R.string.warning_new_session), getActivity(),
                    new ConfirmDialogListener() {
                        @Override
                        public void onConfirm() {
                            try {
                                System.reset();

                                ToastHelper.status(
                                        getActivity(),
                                        getString(R.string.new_session_started));
                            } catch (Exception e) {
                                new FatalDialog(getString(R.string.error), e
                                        .toString(), getActivity());
                            }
                        }

                        @Override
                        public void onCancel() {
                        }

                    });

            return true;
        } else if (itemId == R.id.save_session) {
            new InputDialog(getString(R.string.save_session),
                    getString(R.string.enter_session_name),
                    System.getSessionName(), true, false, getActivity(),
                    new InputDialogListener() {
                        @Override
                        public void onInputEntered(String input) {
                            String name = input.trim().replace("/", "")
                                    .replace("..", "");

                            if (!name.isEmpty()) {
                                try {
                                    String filename = System.saveSession(name);

                                    ToastHelper.success(
                                            getActivity(),
                                            getString(R.string.session_saved_to)
                                                    + filename + " .");
                                } catch (IOException e) {
                                    UIHelper.error(getActivity(), getString(R.string.error),
                                            e.toString());
                                }
                            } else
                                UIHelper.error(getActivity(), getString(R.string.error),
                                        getString(R.string.invalid_session));
                        }
                    });
            return true;
        } else if (itemId == R.id.restore_session) {
            final ArrayList<String> sessions = System
                    .getAvailableSessionFiles();

            if (sessions != null && !sessions.isEmpty()) {
                new SpinnerDialog(getString(R.string.select_session),
                        getString(R.string.select_session_file),
                        sessions.toArray(new String[sessions.size()]),
                        getActivity(), new SpinnerDialogListener() {
                    @Override
                    public void onItemSelected(int index) {
                        String session = sessions.get(index);

                        try {
                            System.loadSession(session);
                        } catch (Exception e) {
                            LoggingHelper.e(TAG, "Failed to load session", e);
                            UIHelper.error(getActivity(), getString(R.string.error),
                                    e.getMessage());
                        }
                    }
                });
            } else
                UIHelper.error(getActivity(), getString(R.string.error),
                        getString(R.string.no_session_found));
            return true;
        } else if (itemId == R.id.settings) {
            startActivity(new Intent(getActivity(), SettingsActivity.class));
            getActivity().overridePendingTransition(R.anim.fadeout, R.anim.fadein);
            return true;
        } else if (itemId == R.id.ss_monitor) {
            ConcurrencyHelper.submitAsync(() -> {
                Services.getNetworkRadar().onMenuClick(getActivity(), item);
                return null;
            });
            return true;
        } else if (itemId == R.id.ss_msfrpcd) {
            ConcurrencyHelper.submitAsync(() -> {
                Services.getMsfRpcdService().onMenuClick(getActivity(), item);
                return null;
            });
            return true;
        } else if (itemId == R.id.submit_issue) {
            String uri = getString(R.string.github_new_issue_url);
            Intent browser = new Intent(Intent.ACTION_VIEW, Uri.parse(uri));
            startActivity(browser);
            // for fat-tire:
            //   String.format(getString(R.string.issue_message), getString(R.string.github_issues_url), getString(R.string.github_new_issue_url));
            return true;
        } else if (itemId == R.id.about) {
            new AboutDialog(getActivity());
            return true;
        } else if (itemId == R.id.security_check) {
            // Show security check results in a dialog
            org.csploit.android.helpers.SecurityChecker checker = new org.csploit.android.helpers.SecurityChecker(getActivity());
            StringBuilder sb = new StringBuilder();
            sb.append("Rooted: ").append(checker.isRooted() ? "Yes" : "No").append("\n");
            sb.append("Emulator: ").append(checker.isEmulator() ? "Yes" : "No").append("\n");
            sb.append("Debuggable: ").append(checker.isDebuggable() ? "Yes" : "No").append("\n");
            sb.append("Developer Options: ").append(checker.isDeveloperOptionsEnabled() ? "Yes" : "No").append("\n");
            sb.append("APK Signature: ").append(checker.getApkSignatureHash());
            new android.app.AlertDialog.Builder(getActivity())
                .setTitle("Security Check")
                .setMessage(sb.toString())
                .setPositiveButton("Share", (dialog, whichButton) -> {
                    Intent send = new Intent(Intent.ACTION_SEND);
                    send.setType("text/plain");
                    send.putExtra(Intent.EXTRA_SUBJECT, "cSploit Security Check Report");
                    send.putExtra(Intent.EXTRA_TEXT, sb.toString());
                    startActivity(Intent.createChooser(send, "Share security report"));
                })
                .setNegativeButton(android.R.string.ok, null)
                .show();
            return true;
        } else if (itemId == R.id.export_targets) {
            // Export targets using ScanResultExporter
            final String[] exportFormats = {"JSON", "CSV", "HTML", "TXT"};
            new android.app.AlertDialog.Builder(getActivity())
                    .setTitle("Export Targets")
                    .setItems(exportFormats, (dialog, which) -> {
                        java.util.List<org.csploit.android.net.Target> targets = org.csploit.android.core.System.getTargets();
                        if (targets == null || targets.size() == 0) {
                            ToastHelper.info(getActivity(), "No targets available to export");
                            return;
                        }

                        java.io.File exportFile = null;
                        org.csploit.android.helpers.ScanResultExporter exporter = new org.csploit.android.helpers.ScanResultExporter(getActivity());
                        String mime = "text/plain";
                        String baseName = "scan_report_" + java.lang.System.currentTimeMillis();
                        if (which == 0) {
                            exportFile = exporter.exportToJson(targets, baseName);
                            mime = "application/json";
                        } else if (which == 1) {
                            exportFile = exporter.exportToCsv(targets, baseName);
                            mime = "text/csv";
                        } else if (which == 2) {
                            exportFile = exporter.exportToHtml(targets, baseName);
                            mime = "text/html";
                        } else if (which == 3) {
                            exportFile = exporter.exportToTxt(targets, baseName);
                            mime = "text/plain";
                        }

                        if (exportFile != null && exportFile.exists()) {
                            ToastHelper.success(getActivity(), "Exported to: " + exportFile.getAbsolutePath());
                            exporter.shareFile(exportFile, mime);
                        } else {
                            ToastHelper.error(getActivity(), "Export failed");
                        }
                    })
                    .setNegativeButton(android.R.string.cancel, null)
                    .show();
            return true;
        }
        return super.onOptionsItemSelected(item);
    }

    public void onBackPressed() {
        if (mLastBackPressTime < java.lang.System.currentTimeMillis() - 4000) {
            ToastHelper.info(getActivity(), getString(R.string.press_back));
            mLastBackPressTime = java.lang.System.currentTimeMillis();
        } else {
            new ConfirmDialog(getString(R.string.exit),
                    getString(R.string.close_confirm), getActivity(),
                    new ConfirmDialogListener() {
                        @Override
                        public void onConfirm() {
                            getActivity().finish();
                        }

                        @Override
                        public void onCancel() {
                        }
                    });

            mLastBackPressTime = 0;
        }
    }

    @Override
    public void onDestroy() {
        stopNetworkRadar();
        stopRPCServer();

        mRadarReceiver.unregister();
        mUpdateReceiver.unregister();
        mWipeReceiver.unregister();
        mMsfReceiver.unregister();
        mConnectivityReceiver.unregister();

        // make sure no zombie process is running before destroying the activity
        System.clean(true);

        super.onDestroy();
    }

    public class TargetAdapter extends BaseAdapter implements Runnable, System.TargetListListener {

        private List<Target> list = System.getTargets();
        private boolean isDark;
        private final Context mContext;

        TargetAdapter() {
            mContext = requireContext();
            isDark = mContext.getSharedPreferences("THEME", 0).getBoolean("isDark", false);
        }

        @Override
        public int getCount() {
            synchronized (this) {
                return list.size();
            }
        }

        @Override
        public Object getItem(int position) {
            synchronized (this) {
                return list.get(position);
            }
        }

        @Override
        public long getItemId(int position) {
            return R.layout.target_list_item;
        }

        @Override
        public View getView(int position, View convertView, ViewGroup parent) {
            View row = convertView;
            TargetHolder holder;

            if (row == null) {
                LayoutInflater inflater = (LayoutInflater) mContext
                        .getSystemService(Context.LAYOUT_INFLATER_SERVICE);
                row = inflater.inflate(R.layout.target_list_item, parent, false);

                if (isDark)
                    row.setBackgroundResource(R.drawable.card_background_dark);

                holder = new TargetHolder();
                holder.itemImage = (ImageView) (row != null ? row
                        .findViewById(R.id.itemIcon) : null);
                holder.itemTitle = (TextView) (row != null ? row
                        .findViewById(R.id.itemTitle) : null);
                holder.itemDescription = (TextView) (row != null ? row
                        .findViewById(R.id.itemDescription) : null);
                holder.portCount = (TextView) (row != null ? row
                        .findViewById(R.id.portCount) : null);
                holder.portCountLayout = (LinearLayout) (row != null ? row
                        .findViewById(R.id.portCountLayout) : null);
                if (isDark)
                    holder.portCountLayout.setBackgroundResource(R.drawable.rounded_square_grey);
                if (row != null)
                    row.setTag(holder);
            } else
                holder = (TargetHolder) row.getTag();

            final Target target = list.get(position);

            if (target.hasAlias()) {
                holder.itemTitle.setText(HtmlCompat.fromHtml("<b>"
                        + target.getAlias() + "</b> <small>( "
                        + target.getDisplayAddress() + " )</small>", HtmlCompat.FROM_HTML_MODE_LEGACY));
            } else {
                holder.itemTitle.setText(target.toString());
            }
            holder.itemTitle.setTextColor(ContextCompat.getColor(getActivity().getApplicationContext(), (target.isConnected() ? R.color.app_color : R.color.gray_text)));

            holder.itemTitle.setTypeface(null, Typeface.NORMAL);
            holder.itemImage.setImageResource(target.getDrawableResourceId());
            holder.itemDescription.setText(target.getDescription());

            int openedPorts = target.getOpenPorts().size();

            holder.portCount.setText(String.format("%d", openedPorts));
            holder.portCountLayout.setVisibility(openedPorts < 1 ? View.GONE : View.VISIBLE);
            return row;
        }

        public void clearSelection() {
            synchronized (this) {
                for (Target t : list)
                    t.setSelected(false);
            }
            notifyDataSetChanged();
            if (mActionMode != null)
                mActionMode.finish();
        }

        public void toggleSelection(int position) {
            synchronized (this) {
                Target t = list.get(position);
                t.setSelected(!t.isSelected());
            }
            notifyDataSetChanged();
            if (mActionMode != null) {
                if (getSelectedCount() > 0)
                    mActionMode.invalidate();
                else
                    mActionMode.finish();
            }
        }

        public int getSelectedCount() {
            int i = 0;
            synchronized (this) {
                for (Target t : list)
                    if (t.isSelected())
                        i++;
            }
            return i;
        }

        public ArrayList<Target> getSelected() {
            ArrayList<Target> result = new ArrayList<Target>();
            synchronized (this) {
                for (Target t : list)
                    if (t.isSelected())
                        result.add(t);
            }
            return result;
        }

        public int[] getSelectedPositions() {
            int[] res;
            int j = 0;

            synchronized (this) {
                res = new int[getSelectedCount()];
                for (int i = 0; i < list.size(); i++)
                    if (list.get(i).isSelected())
                        res[j++] = i;
            }
            return res;
        }

        @Override
        public void onTargetsChanged(final Target changedTarget) {
            android.app.Activity activity = getActivity();
            if (activity == null || !isAdded()) {
                return;
            }

            if (changedTarget == null) {
                // update the whole list
                activity.runOnUiThread(this);
                return;
            }

            // update only a row, if it's displayed
            activity.runOnUiThread(new Runnable() {
                @Override
                public void run() {
                    if (lv == null || getActivity() == null || !isAdded())
                        return;
                    int start = lv.getFirstVisiblePosition();
                    // list.size() - 1: avoid IOOBE when end == list.size()
                    int end = Math.min(lv.getLastVisiblePosition(), list.size() - 1);
                    for (int i = start; i <= end; i++)
                        if (changedTarget == list.get(i)) {
                            View view = lv.getChildAt(i - start);
                            getView(i, view, lv);
                            break;
                        }
                }
            });
        }

        @Override
        public void run() {
            synchronized (this) {
                list = System.getTargets();
            }
            notifyDataSetChanged();
        }

        class TargetHolder {
            ImageView itemImage;
            TextView itemTitle;
            TextView itemDescription;
            TextView portCount;
            LinearLayout portCountLayout;
        }
    }

    private class WipeReceiver extends ManagedReceiver {
        private IntentFilter mFilter = null;

        public WipeReceiver() {
            mFilter = new IntentFilter();

            mFilter.addAction(SettingsFragment.SETTINGS_WIPE_START);
        }

        public IntentFilter getFilter() {
            return mFilter;
        }

        @Override
        public void onReceive(Context context, Intent intent) {

            if (intent.getAction().equals(SettingsFragment.SETTINGS_WIPE_START)) {
                try {
                    String path;

                    if (intent.hasExtra(SettingsFragment.SETTINGS_WIPE_DIR)) {
                        path = intent.getStringExtra(SettingsFragment.SETTINGS_WIPE_DIR);
                    } else {
                        path = System.getRubyPath() + "' '" + System.getMsfPath();
                    }

                    stopRPCServer();
                    System.getTools().raw.async("rm -rf '" + path + "'", new Child.EventReceiver() {
                        @Override
                        public void onEnd(int exitCode) {
                            android.app.Activity a = getActivity();
                            if (a != null) {
                                Intent wi = new Intent(SettingsFragment.SETTINGS_WIPE_DONE);
                                wi.setPackage(a.getPackageName());
                                a.sendBroadcast(wi);
                            }
                        }

                        @Override
                        public void onDeath(int signal) {
                            android.app.Activity a = getActivity();
                            if (a != null) {
                                Intent wi = new Intent(SettingsFragment.SETTINGS_WIPE_DONE);
                                wi.setPackage(a.getPackageName());
                                a.sendBroadcast(wi);
                            }
                        }

                        @Override
                        public void onEvent(Event e) {
                        }
                    });
                } catch (Exception e) {
                    LoggingHelper.e(TAG, "Failed to add event listener", e);
                }
            }
        }
    }

    private class UpdateReceiver extends ManagedReceiver {
        private IntentFilter mFilter = null;

        public UpdateReceiver() {
            mFilter = new IntentFilter();

            mFilter.addAction(UPDATE_CHECKING);
            mFilter.addAction(UPDATE_AVAILABLE);
            mFilter.addAction(UPDATE_NOT_AVAILABLE);
            mFilter.addAction(UpdateService.ERROR);
            mFilter.addAction(UpdateService.DONE);
        }

        public IntentFilter getFilter() {
            return mFilter;
        }

        private void onUpdateAvailable(final Update update, final boolean mandatory) {
            android.app.Activity activity = getActivity();
            if (activity == null || !isAdded()) {
                return;
            }
            activity.runOnUiThread(new Runnable() {
                @Override
                public void run() {
                    androidx.fragment.app.FragmentActivity currentActivity = (androidx.fragment.app.FragmentActivity) getActivity();
                    if (currentActivity == null || !isAdded()) {
                        return;
                    }
                    new ConfirmDialog(getString(R.string.update_available),
                            update.prompt, currentActivity, new ConfirmDialogListener() {
                        @Override
                        public void onConfirm() {
                            android.app.Activity activity = getActivity();
                            if (activity == null || !isAdded()) {
                                return;
                            }
                            stopRPCServer();
                            Intent i = new Intent(activity, UpdateService.class);
                            i.setAction(UpdateService.START);
                            i.putExtra(UpdateService.UPDATE, update);

                            activity.startService(i);
                            mIsUpdateDownloading = true;
                        }

                        @Override
                        public void onCancel() {
                            mIsUpdateDownloading = false;
                            if (!mandatory) {
                                return;
                            }

                            onInitializationError(getString(R.string.mandatory_update));
                        }
                    }
                    ).show();
                }
            });
        }

        private void onUpdateAvailable(Update update) {
            onUpdateAvailable(update, (update instanceof CoreUpdate) && !System.isCoreInstalled());
        }

        private void onUpdateDone(Update update) {

            mIsUpdateDownloading = false;

            System.reloadTools();

            if ((update instanceof MsfUpdate) || (update instanceof RubyUpdate)) {
                startRPCServer();
            }

            if (update instanceof CoreUpdate) {
                onCoreUpdated();
            }

            // restart update checker after a successful update
            startUpdateChecker();
        }

        private void onUpdateError(final Update update, final int message) {

            mIsUpdateDownloading = false;

            if (update instanceof CoreUpdate) {
                onInitializationError(getString(message));
                return;
            }

            android.app.Activity activity = getActivity();
            if (activity != null && isAdded()) {
                activity.runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        android.app.Activity currentActivity = getActivity();
                        if (currentActivity != null && isAdded()) {
                            UIHelper.error(currentActivity, getString(R.string.error),
                                    getString(message));
                        }
                    }
                });
            }

            System.reloadTools();
        }

        @SuppressWarnings("ConstantConditions")
        @Override
        public void onReceive(Context context, Intent intent) {
            String action = intent.getAction();
            Update update = null;

            if (intent.hasExtra(UpdateService.UPDATE)) {
                update = (Update) intent.getSerializableExtra(UpdateService.UPDATE);
            }

            switch (action) {
                case UPDATE_CHECKING:
                    if (mEmptyTextView != null)
                        mEmptyTextView.setText(EMPTY_LIST_MESSAGE.replace(
                                "#STATUS#", getString(R.string.checking)));
                    break;
                case UPDATE_NOT_AVAILABLE:
                    if (mEmptyTextView != null)
                        mEmptyTextView.setText(EMPTY_LIST_MESSAGE.replace(
                                "#STATUS#", getString(R.string.no_updates_available)));

                    if (!System.isCoreInstalled()) {
                        onInitializationError(getString(R.string.no_core_found));
                    }
                    break;
                case UPDATE_AVAILABLE:
                    onUpdateAvailable(update);
                    break;
                case UpdateService.DONE:
                    onUpdateDone(update);
                    break;
                case UpdateService.ERROR:
                    int message = intent.getIntExtra(UpdateService.MESSAGE, R.string.error_occured);
                    onUpdateError(update, message);
                    break;
            }
        }
    }

    private class ConnectivityReceiver extends ManagedReceiver {
        private static final int CHECK_DELAY = 2000;

        private final IntentFilter mFilter;
        private TimerTask mTask = null;

        public ConnectivityReceiver() {
            mFilter = new IntentFilter();
            mFilter.addAction(ConnectivityManager.CONNECTIVITY_ACTION);
        }

        @Override
        public IntentFilter getFilter() {
            return mFilter;
        }

        private String ifacesToString() {
            StringBuilder sb = new StringBuilder();
            for (String iface : mIfaces) {
                if (sb.length() > 0) {
                    sb.append(", ");
                }
                sb.append(iface);
            }
            return sb.toString();
        }

        @Override
        public void onReceive(Context context, Intent intent) {
            android.app.Activity activity = getActivity();
            if (activity == null || !isAdded()) {
                return;
            }
            synchronized (ConnectivityReceiver.this) {
                if (mTask != null) {
                    mTask.cancel();
                }
                mTask = new TimerTask() {
                    @Override
                    public void run() {
                        check();
                    }
                };
                new Timer().schedule(mTask, CHECK_DELAY);
            }
        }

        @Override
        public void unregister() {
            super.unregister();
            synchronized (ConnectivityReceiver.this) {
                if (mTask != null) {
                    mTask.cancel();
                    mTask = null;
                }
            }
        }

        private void check() {
            android.app.Activity activity = getActivity();
            if (activity == null || !isAdded()) {
                return;
            }
            synchronized (ConnectivityReceiver.this) {
                activity.runOnUiThread(new Runnable() {
                    @Override
                    public void run() {
                        if (getActivity() == null || !isAdded()) {
                            return;
                        }
                        loadInterfaces();

                        String current = System.getIfname();

                        LoggingHelper.debug(String.format("current='%s', ifaces=[%s], haveInterface=%s, isAnyNetInterfaceAvailable=%s",
                                current != null ? current : "(null)",
                                ifacesToString(), haveInterface(current), isAnyNetInterfaceAvailable));

                        if (haveInterface(current)) {
                            onConnectionResumed();
                        } else if (current != null) {
                            onConnectionLost();
                        } else if (isAnyNetInterfaceAvailable) {
                            onNetworkInterfaceChanged();
                        }

                    }
                });

                mTask = null;
            }
        }
    }
}