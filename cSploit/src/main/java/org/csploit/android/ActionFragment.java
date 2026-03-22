package org.csploit.android;

import android.annotation.SuppressLint;
import android.content.Context;
import android.content.Intent;
import android.content.SharedPreferences;
import android.os.Bundle;
import androidx.annotation.Nullable;
import androidx.fragment.app.Fragment;
import androidx.core.content.ContextCompat;
import androidx.appcompat.app.AppCompatActivity;
import android.view.LayoutInflater;
import android.view.MenuItem;
import android.view.View;
import android.view.ViewGroup;
import android.widget.AdapterView;
import android.widget.ArrayAdapter;
import android.widget.ImageView;
import android.widget.ListView;
import android.widget.TextView;
import android.widget.Toast;

import org.csploit.android.core.Plugin;
import org.csploit.android.core.System;
import org.csploit.android.helpers.UIHelper;
import org.csploit.android.net.Target;
import org.csploit.android.helpers.ToastHelper;

import java.util.ArrayList;

public class ActionFragment extends Fragment {
    private static final String TAG = "ActionFragment";

    private ArrayList<Plugin> mAvailable = null;
    private ListView theList;
    private Target mTarget;


    @Nullable
    @Override
    public View onCreateView(LayoutInflater inflater, ViewGroup container, Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setHasOptionsMenu(true);
        return inflater.inflate(R.layout.actions_layout, container, false);
    }

    @Override
    public void onViewCreated(View v, Bundle savedInstanceState) {
        android.app.Activity activity = getActivity();
        if (activity != null) {
            SharedPreferences themePrefs = activity.getSharedPreferences("THEME", 0);
            if (themePrefs.getBoolean("isDark", false)) {
                activity.setTheme(R.style.DarkTheme);
                v.setBackgroundColor(ContextCompat.getColor(activity, R.color.background_window_dark));
            } else {
                activity.setTheme(R.style.AppTheme);
                v.setBackgroundColor(ContextCompat.getColor(activity, R.color.background_window));
            }
        }
        mTarget = org.csploit.android.core.System.getCurrentTarget();

        if (mTarget != null) {
            if (activity != null) {
                activity.setTitle("cSploit > " + mTarget);
                androidx.appcompat.app.ActionBar ab = ((AppCompatActivity) activity).getSupportActionBar();
                if (ab != null) ab.setDisplayHomeAsUpEnabled(true);
                theList = (ListView) activity.findViewById(R.id.android_list);
            }
            mAvailable = System.getPluginsForTarget();
            ActionsAdapter mActionsAdapter = new ActionsAdapter();
            if (theList != null) theList.setAdapter(mActionsAdapter);
            if (theList != null) theList.setOnItemClickListener(new ListView.OnItemClickListener() {
                @Override
                public void onItemClick(AdapterView<?> parent, View view, int position, long id) {
                    android.app.Activity a = getActivity();
                    if (a == null || !(a instanceof androidx.fragment.app.FragmentActivity)) return;
                    if (System.checkNetworking((androidx.fragment.app.FragmentActivity) a)) {
                        Plugin plugin = mAvailable.get(position);
                        System.setCurrentPlugin(plugin);

                        if (plugin.hasLayoutToShow()) {
                            ToastHelper.status(a, getString(R.string.selected) + getString(plugin.getName()));

                            startActivity(new Intent(a, plugin.getClass()));
                            a.overridePendingTransition(R.anim.fadeout, R.anim.fadein);
                        } else
                            plugin.onActionClick(a.getApplicationContext());
                    }
                }
            });
        } else {
            UIHelper.finish(activity, getString(R.string.warning), getString(R.string.something_went_wrong));
        }
    }


    @Override
    public boolean onOptionsItemSelected(MenuItem item) {
        switch (item.getItemId()) {
            case android.R.id.home:

                getActivity().onBackPressed();

                return true;

            default:
                return super.onOptionsItemSelected(item);
        }
    }

    public void onBackPressed() {
        getActivity().finish();
        getActivity().overridePendingTransition(R.anim.fadeout, R.anim.fadein);
    }

    public class ActionsAdapter extends ArrayAdapter<Plugin> {
        private final Context mContext;
        private final boolean mIsDark;

        public ActionsAdapter() {
            super(requireContext(), R.layout.actions_list_item, mAvailable);
            mContext = requireContext();
            mIsDark = mContext.getSharedPreferences("THEME", 0).getBoolean("isDark", false);
        }

        @SuppressLint("NewApi")
        @Override
        public View getView(int position, View convertView, ViewGroup parent) {
            View row = convertView;
            ActionHolder holder;

            if (row == null) {
                LayoutInflater inflater = (LayoutInflater) mContext.getSystemService(Context.LAYOUT_INFLATER_SERVICE);
                row = inflater.inflate(R.layout.actions_list_item, parent, false);
                if (mIsDark)
                    row.setBackgroundResource(R.drawable.card_background_dark);
                holder = new ActionHolder();

                holder.icon = (ImageView) (row != null ? row.findViewById(R.id.actionIcon) : null);
                holder.name = (TextView) (row != null ? row.findViewById(R.id.actionName) : null);
                holder.description = (TextView) (row != null ? row.findViewById(R.id.actionDescription) : null);
                if (row != null) row.setTag(holder);

            } else holder = (ActionHolder) row.getTag();

            Plugin action = mAvailable.get(position);

            holder.icon.setImageResource(action.getIconResourceId());
            holder.name.setText(getString(action.getName()));
            holder.description.setText(getString(action.getDescription()));

            return row;
        }

        public class ActionHolder {
            ImageView icon;
            TextView name;
            TextView description;
        }
    }

}