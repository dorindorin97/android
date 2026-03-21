/*
 * This file is part of the dSploit.
 *
 * Copyleft of Simone Margaritelli aka evilsocket <evilsocket@gmail.com>
 *             Massimo Dragano aka tux_mind <massimo.dragano@gmail.com>
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
package org.csploit.android.plugins;

import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import android.view.View;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.ListView;
import android.widget.Toast;

import org.csploit.android.R;
import org.csploit.android.core.Plugin;
import org.csploit.android.core.System;
import org.csploit.android.gui.Console;
import org.csploit.android.gui.dialogs.ChoiceDialog;
import org.csploit.android.gui.dialogs.ErrorDialog;
import org.csploit.android.gui.dialogs.ListChoiceDialog;
import org.csploit.android.helpers.ConcurrencyHelper;
import org.csploit.android.helpers.ToastHelper;
import org.csploit.android.helpers.UIHelper;
import org.csploit.android.net.Target;
import org.csploit.android.net.metasploit.RPCClient;
import org.csploit.android.net.metasploit.Session;
import org.csploit.android.net.metasploit.ShellSession;

import java.util.ArrayList;

public class Sessions extends Plugin {
	private ListView mListView = null;
  private ArrayList<Session> mResults;
  private ArrayAdapter<Session> mAdapter = null;
  private volatile Sessions     UIThread = null;

	public Sessions() {
		super(R.string.sessions, R.string.sessions_desc,

		new Target.Type[] { Target.Type.ENDPOINT, Target.Type.REMOTE },
				R.layout.plugin_sessions_layout, R.drawable.action_session);
	}

  private AdapterView.OnItemLongClickListener longClickListener = new AdapterView.OnItemLongClickListener() {
    @Override
    public boolean onItemLongClick(AdapterView<?> parent, View view, int position, long id) {
      final Session s = mAdapter.getItem(position);
      if (s == null) return false;
      final ArrayList<Integer> availableChoices = new ArrayList<Integer>();
      availableChoices.add(R.string.show_full_description);
      if(s.haveShell())
        availableChoices.add(R.string.open_shell);
      if(s.isMeterpreter()) {
        String deviceOS = System.getCurrentTarget().getDeviceOS();
        if(deviceOS != null && deviceOS.toLowerCase().contains("windows"))
          availableChoices.add(R.string.clear_event_log);
      }
      availableChoices.add(R.string.delete);

      new ListChoiceDialog(R.string.choose_an_option,availableChoices.toArray(new Integer[availableChoices.size()]),Sessions.this, new ChoiceDialog.ChoiceDialogListener() {
        @Override
        public void onChoice(int choice) {
          int selectedChoice = availableChoices.get(choice);
          if (selectedChoice == R.string.open_shell) {
              System.setCurrentSession(s);
              startActivity(new Intent(Sessions.this, Console.class));
              overridePendingTransition(R.anim.fadeout, R.anim.fadein);
          } else if (selectedChoice == R.string.show_full_description) {
              StringBuilder message = new StringBuilder(s.getDescription());
              if(s.getInfo().length()>0)
                message.append("\n\nInfo:\n").append(s.getInfo());
              UIHelper.error(Sessions.this, s.getName(), message.toString());
          } else if (selectedChoice == R.string.clear_event_log) {
              ((ShellSession)s).addCommand("clearev", new ShellSession.RpcShellReceiver() {
                @Override
                public void onNewLine(String line) { }

                @Override
                public void onEnd(int exitValue) {
                  ToastHelper.status(Sessions.this,"command returned "+exitValue);
                }

                @Override
                public void onRpcClosed() {
                  ToastHelper.status(Sessions.this,"RPC channel has been closed");
                }

                @Override
                public void onTimedOut() {
                  ToastHelper.error(Sessions.this,"command timed out");
                }
              });
          } else if (selectedChoice == R.string.delete) {
              s.stopSession();
              System.getCurrentTarget().getSessions().remove(s);
              mAdapter.notifyDataSetChanged();
          }
        }
      }).show();
      return true;
    }
  };

  private AdapterView.OnItemClickListener clickListener = new AdapterView.OnItemClickListener() {
    @Override
    public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
      Session s = mAdapter.getItem(position);
      if(s == null) return;
      if(s.haveShell()) {
        System.setCurrentSession(s);
        startActivity(new Intent(Sessions.this,Console.class));
        overridePendingTransition(R.anim.fadeout, R.anim.fadein);
      } else {
        longClickListener.onItemLongClick(parent, view, position, id);
      }
    }
  };

	@Override
	public void onCreate(Bundle savedInstanceState) {
		SharedPreferences themePrefs = getSharedPreferences("THEME", 0);
		Boolean isDark = themePrefs.getBoolean("isDark", false);
		if (isDark)
			setTheme(R.style.DarkTheme);
		else
			setTheme(R.style.AppTheme);
		super.onCreate(savedInstanceState);

    UIThread = this;

    if(System.getMsfRpc()==null) {
      UIHelper.finish(Sessions.this, getString(R.string.error), "MSF RPC not connected");
      return;
		}

    if(System.getCurrentTarget() == null) {
      UIHelper.finish(Sessions.this, getString(R.string.error), getString(R.string.error));
      return;
    }
    mResults = System.getCurrentTarget().getSessions();

    mListView = (ListView) findViewById(android.R.id.list);
    mAdapter  = new ArrayAdapter<>(this, android.R.layout.simple_list_item_1, mResults);

    mListView.setAdapter(mAdapter);

    mListView.setOnItemClickListener(clickListener);

    mListView.setOnItemLongClickListener(longClickListener);

    ConcurrencyHelper.submitAsync(() -> {
      RPCClient rpc = System.getMsfRpc();
      if(rpc == null) return null;
      rpc.updateSessions();
      runOnUiThread(new Runnable() {
        @Override
        public void run() {
          if(mResults.isEmpty()) {
            UIHelper.finish(Sessions.this, getString(R.string.warning), getString(R.string.no_opened_sessions));
          } else {
            mAdapter.notifyDataSetChanged();
          }
        }
      });
      return null;
    });
	}

  @Override
  public void onRpcChange(RPCClient currentValue) {
    if(UIThread==null)
      return;
    if(this!=UIThread)
      UIThread.onRpcChange(currentValue);
    else if(currentValue == null)
      UIHelper.finish(Sessions.this, getString(R.string.error), getString(R.string.msfrpc_disconnected));
	}

  @Override
  public void onBackPressed() {
    super.onBackPressed();
    overridePendingTransition(R.anim.fadeout, R.anim.fadein);
  }
}