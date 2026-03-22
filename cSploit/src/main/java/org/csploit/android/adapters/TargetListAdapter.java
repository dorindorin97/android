/*
 * This file is part of cSploit.
 *
 * cSploit is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * cSploit is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with cSploit. If not, see <http://www.gnu.org/licenses/>.
 */

package org.csploit.android.adapters;

import android.content.Context;
import android.graphics.Typeface;
import android.view.LayoutInflater;
import android.view.View;
import android.view.ViewGroup;
import android.widget.BaseAdapter;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ListView;
import android.widget.TextView;

import androidx.core.content.ContextCompat;
import androidx.core.text.HtmlCompat;

import org.csploit.android.R;
import org.csploit.android.core.System;
import org.csploit.android.net.Target;

import java.util.ArrayList;
import java.util.List;

/**
 * TargetListAdapter - Adapter for displaying network targets in ListView
 *
 * Responsible for:
 * - Rendering target list items with device info, alias, and open port count
 * - Managing target selection state for multi-select operations
 * - Observing target changes and updating UI accordingly
 * - Supporting dark theme styling
 * - Efficient view recycling with ViewHolder pattern
 *
 * Features:
 * - Multi-select support for batch operations
 * - Observer pattern integration for reactive updates
 * - Theme-aware styling (light/dark mode)
 * - Port count badge with conditional visibility
 * - Alias display with fallback to address
 * - Thread-safe selection management with synchronization
 *
 * @author cSploit Team
 * @version 1.0
 */
public class TargetListAdapter extends BaseAdapter implements Runnable, System.TargetListListener {

    private static final String TAG = "TargetListAdapter";

    private List<Target> targetList = System.getTargets();
    private boolean isDarkTheme;
    private Context context;
    private ListView listView;
    private ActionModeCallback actionModeCallback;

    /**
     * Interface for action mode callbacks (multi-select operations)
     */
    public interface ActionModeCallback {
        void onActionModeStateChanged(ActionMode mode);
    }

    /**
     * Simple ActionMode holder for multi-select context
     */
    public static class ActionMode {
        public void finish() {}
        public void invalidate() {}
    }

    /**
     * Constructor
     *
     * @param context Android context
     * @param listView ListView to attach adapter to
     * @param isDarkTheme whether dark theme is enabled
     */
    public TargetListAdapter(Context context, ListView listView, boolean isDarkTheme) {
        this.context = context;
        this.listView = listView;
        this.isDarkTheme = isDarkTheme;
        this.targetList = System.getTargets();
    }

    /**
     * Set action mode callback for multi-select operations
     *
     * @param callback callback instance
     */
    public void setActionModeCallback(ActionModeCallback callback) {
        this.actionModeCallback = callback;
    }

    @Override
    public int getCount() {
        return targetList.size();
    }

    @Override
    public Object getItem(int position) {
        return targetList.get(position);
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
            LayoutInflater inflater = (LayoutInflater) context
                    .getSystemService(Context.LAYOUT_INFLATER_SERVICE);
            if (inflater == null) {
                inflater = LayoutInflater.from(context);
            }
            row = inflater.inflate(R.layout.target_list_item, parent, false);

            if (isDarkTheme) {
                row.setBackgroundResource(R.drawable.card_background_dark);
            }

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

            if (isDarkTheme && holder.portCountLayout != null) {
                holder.portCountLayout.setBackgroundResource(R.drawable.rounded_square_grey);
            }

            if (row != null) {
                row.setTag(holder);
            }
        } else {
            holder = (TargetHolder) row.getTag();
        }

        final Target target = targetList.get(position);

        // Set title with alias or address
        if (target.hasAlias()) {
            holder.itemTitle.setText(HtmlCompat.fromHtml("<b>"
                    + target.getAlias() + "</b> <small>( "
                    + target.getDisplayAddress() + " )</small>", HtmlCompat.FROM_HTML_MODE_LEGACY));
        } else {
            holder.itemTitle.setText(target.toString());
        }

        // Set title color based on connection status
        int titleColor = target.isConnected() ? R.color.app_color : R.color.gray_text;
        holder.itemTitle.setTextColor(ContextCompat.getColor(context, titleColor));

        // Set icon and description
        holder.itemTitle.setTypeface(null, Typeface.NORMAL);
        holder.itemImage.setImageResource(target.getDrawableResourceId());
        holder.itemDescription.setText(target.getDescription());

        // Show port count badge if ports are open
        int openedPorts = target.getOpenPorts().size();
        holder.portCount.setText(String.format("%d", openedPorts));
        holder.portCountLayout.setVisibility(openedPorts < 1 ? View.GONE : View.VISIBLE);

        return row;
    }

    /**
     * Clear all target selections
     */
    public void clearSelection() {
        synchronized (this) {
            for (Target t : targetList) {
                t.setSelected(false);
            }
        }
        notifyDataSetChanged();
    }

    /**
     * Toggle selection for target at position
     *
     * @param position list position
     */
    public void toggleSelection(int position) {
        synchronized (this) {
            if (position >= 0 && position < targetList.size()) {
                Target t = targetList.get(position);
                t.setSelected(!t.isSelected());
            }
        }
        notifyDataSetChanged();
    }

    /**
     * Get count of selected targets
     *
     * @return number of selected targets
     */
    public int getSelectedCount() {
        int count = 0;
        synchronized (this) {
            for (Target t : targetList) {
                if (t.isSelected()) {
                    count++;
                }
            }
        }
        return count;
    }

    /**
     * Get list of selected targets
     *
     * @return ArrayList of selected Target objects
     */
    public ArrayList<Target> getSelected() {
        ArrayList<Target> result = new ArrayList<>();
        synchronized (this) {
            for (Target t : targetList) {
                if (t.isSelected()) {
                    result.add(t);
                }
            }
        }
        return result;
    }

    /**
     * Get array of selected target positions
     *
     * @return int array of selected positions
     */
    public int[] getSelectedPositions() {
        int[] result;
        int index = 0;

        synchronized (this) {
            result = new int[getSelectedCount()];
            for (int i = 0; i < targetList.size(); i++) {
                if (targetList.get(i).isSelected()) {
                    result[index++] = i;
                }
            }
        }
        return result;
    }

    @Override
    public void onTargetsChanged(final Target changedTarget) {
        if (changedTarget == null) {
            // Full list refresh
            if (context instanceof android.app.Activity) {
                ((android.app.Activity) context).runOnUiThread(this);
            } else {
                notifyDataSetChanged();
            }
            return;
        }

        // Update only the visible row containing this target
        if (context instanceof android.app.Activity) {
            ((android.app.Activity) context).runOnUiThread(new Runnable() {
                @Override
                public void run() {
                    if (listView == null) return;
                    int start = listView.getFirstVisiblePosition();
                    int end = Math.min(listView.getLastVisiblePosition(), targetList.size());
                    for (int i = start; i <= end; i++) {
                        if (i >= 0 && i < targetList.size() && changedTarget == targetList.get(i)) {
                            View view = listView.getChildAt(i - start);
                            getView(i, view, listView);
                            break;
                        }
                    }
                }
            });
        }
    }

    @Override
    public void run() {
        synchronized (this) {
            targetList = System.getTargets();
        }
        notifyDataSetChanged();
    }

    /**
     * ViewHolder pattern implementation for efficient view recycling
     */
    static class TargetHolder {
        ImageView itemImage;
        TextView itemTitle;
        TextView itemDescription;
        TextView portCount;
        LinearLayout portCountLayout;
    }
}
