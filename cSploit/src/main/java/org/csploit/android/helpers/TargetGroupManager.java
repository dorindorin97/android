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
package org.csploit.android.helpers;

import android.content.Context;
import org.csploit.android.helpers.LoggingHelper;
import android.content.SharedPreferences;
import org.csploit.android.helpers.LoggingHelper;

import androidx.annotation.NonNull;
import org.csploit.android.helpers.LoggingHelper;
import androidx.annotation.Nullable;
import org.csploit.android.helpers.LoggingHelper;

import org.csploit.android.net.Target;
import org.csploit.android.helpers.LoggingHelper;
import org.json.JSONArray;
import org.csploit.android.helpers.LoggingHelper;
import org.json.JSONException;
import org.csploit.android.helpers.LoggingHelper;
import org.json.JSONObject;
import org.csploit.android.helpers.LoggingHelper;

import java.util.ArrayList;
import org.csploit.android.helpers.LoggingHelper;
import java.util.Collections;
import org.csploit.android.helpers.LoggingHelper;
import java.util.HashMap;
import org.csploit.android.helpers.LoggingHelper;
import java.util.HashSet;
import org.csploit.android.helpers.LoggingHelper;
import java.util.List;
import org.csploit.android.helpers.LoggingHelper;
import java.util.Map;
import org.csploit.android.helpers.LoggingHelper;
import java.util.Set;
import org.csploit.android.helpers.LoggingHelper;
import java.util.UUID;
import org.csploit.android.helpers.LoggingHelper;
import java.util.concurrent.ConcurrentHashMap;
import org.csploit.android.helpers.LoggingHelper;
import java.util.concurrent.CopyOnWriteArrayList;
import org.csploit.android.helpers.LoggingHelper;

/**
 * TargetGroupManager - Organize and manage target groups
 *
 * Provides functionality to organize network targets into logical groups for:
 * - Batch operations on multiple targets
 * - Organizing targets by location, department, or function
 * - Saving and loading group configurations
 * - Quick target selection and filtering
 *
 * Features:
 * - Create, edit, and delete groups
 * - Add/remove targets from groups
 * - Persist groups across sessions
 * - Group-based batch operations
 * - Color coding and tagging
 *
 * Usage:
 * {@code
 * TargetGroupManager manager = TargetGroupManager.getInstance();
 * manager.createGroup("Servers", "Production servers");
 * manager.addTargetToGroup(target, "Servers");
 * List<Target> servers = manager.getTargetsInGroup("Servers");
 * }
 */
public final class TargetGroupManager {

    private static final String TAG = "TargetGroupManager";
    private static final String PREFS_NAME = "target_groups";
    private static final String GROUPS_KEY = "groups_data";

    private static volatile TargetGroupManager instance;

    private final Map<String, TargetGroup> groups = new ConcurrentHashMap<>();
    private final Map<String, Set<String>> targetToGroups = new ConcurrentHashMap<>();
    private final List<GroupChangeListener> listeners = new CopyOnWriteArrayList<>();
    private Context context;

    /**
     * Represents a group of targets
     */
    public static class TargetGroup {
        private final String id;
        private String name;
        private String description;
        private int color;
        private final Set<String> targetIds;
        private final long createdAt;
        private long modifiedAt;
        private final Map<String, String> metadata;

        public TargetGroup(String name, String description) {
            this.id = UUID.randomUUID().toString();
            this.name = name;
            this.description = description;
            this.color = 0xFF4CAF50; // Default green color
            this.targetIds = Collections.synchronizedSet(new HashSet<>());
            this.createdAt = System.currentTimeMillis();
            this.modifiedAt = createdAt;
            this.metadata = new ConcurrentHashMap<>();
        }

        private TargetGroup(String id, String name, String description, int color,
                           Set<String> targetIds, long createdAt, long modifiedAt,
                           Map<String, String> metadata) {
            this.id = id;
            this.name = name;
            this.description = description;
            this.color = color;
            this.targetIds = Collections.synchronizedSet(new HashSet<>(targetIds));
            this.createdAt = createdAt;
            this.modifiedAt = modifiedAt;
            this.metadata = new ConcurrentHashMap<>(metadata);
        }

        // Getters
        public String getId() { return id; }
        public String getName() { return name; }
        public String getDescription() { return description; }
        public int getColor() { return color; }
        public Set<String> getTargetIds() { return Collections.unmodifiableSet(targetIds); }
        public long getCreatedAt() { return createdAt; }
        public long getModifiedAt() { return modifiedAt; }
        public int getTargetCount() { return targetIds.size(); }

        // Setters
        public void setName(String name) {
            this.name = name;
            this.modifiedAt = System.currentTimeMillis();
        }

        public void setDescription(String description) {
            this.description = description;
            this.modifiedAt = System.currentTimeMillis();
        }

        public void setColor(int color) {
            this.color = color;
            this.modifiedAt = System.currentTimeMillis();
        }

        public void setMetadata(String key, String value) {
            metadata.put(key, value);
            modifiedAt = System.currentTimeMillis();
        }

        public String getMetadata(String key) {
            return metadata.get(key);
        }

        boolean addTarget(String targetId) {
            boolean added = targetIds.add(targetId);
            if (added) {
                modifiedAt = System.currentTimeMillis();
            }
            return added;
        }

        boolean removeTarget(String targetId) {
            boolean removed = targetIds.remove(targetId);
            if (removed) {
                modifiedAt = System.currentTimeMillis();
            }
            return removed;
        }

        boolean containsTarget(String targetId) {
            return targetIds.contains(targetId);
        }

        @NonNull
        @Override
        public String toString() {
            return String.format("%s (%d targets)", name, targetIds.size());
        }

        JSONObject toJson() throws JSONException {
            JSONObject json = new JSONObject();
            json.put("id", id);
            json.put("name", name);
            json.put("description", description);
            json.put("color", color);
            json.put("createdAt", createdAt);
            json.put("modifiedAt", modifiedAt);
            json.put("targetIds", new JSONArray(targetIds));

            JSONObject metaJson = new JSONObject();
            for (Map.Entry<String, String> entry : metadata.entrySet()) {
                metaJson.put(entry.getKey(), entry.getValue());
            }
            json.put("metadata", metaJson);

            return json;
        }

        static TargetGroup fromJson(JSONObject json) throws JSONException {
            String id = json.getString("id");
            String name = json.getString("name");
            String description = json.optString("description", "");
            int color = json.optInt("color", 0xFF4CAF50);
            long createdAt = json.optLong("createdAt", System.currentTimeMillis());
            long modifiedAt = json.optLong("modifiedAt", createdAt);

            Set<String> targetIds = new HashSet<>();
            JSONArray targetsArray = json.optJSONArray("targetIds");
            if (targetsArray != null) {
                for (int i = 0; i < targetsArray.length(); i++) {
                    targetIds.add(targetsArray.getString(i));
                }
            }

            Map<String, String> metadata = new HashMap<>();
            JSONObject metaJson = json.optJSONObject("metadata");
            if (metaJson != null) {
                for (java.util.Iterator<String> it = metaJson.keys(); it.hasNext(); ) {
                    String key = it.next();
                    metadata.put(key, metaJson.getString(key));
                }
            }

            return new TargetGroup(id, name, description, color, targetIds,
                    createdAt, modifiedAt, metadata);
        }
    }

    /**
     * Listener for group changes
     */
    public interface GroupChangeListener {
        void onGroupCreated(TargetGroup group);
        void onGroupUpdated(TargetGroup group);
        void onGroupDeleted(String groupId);
        void onTargetAddedToGroup(String targetId, TargetGroup group);
        void onTargetRemovedFromGroup(String targetId, TargetGroup group);
    }

    private TargetGroupManager() {}

    public static TargetGroupManager getInstance() {
        if (instance == null) {
            synchronized (TargetGroupManager.class) {
                if (instance == null) {
                    instance = new TargetGroupManager();
                }
            }
        }
        return instance;
    }

    /**
     * Initialize with context for persistence
     */
    public void init(@NonNull Context context) {
        this.context = context.getApplicationContext();
        loadGroups();
    }

    /**
     * Create a new target group
     */
    @NonNull
    public TargetGroup createGroup(@NonNull String name, @Nullable String description) {
        TargetGroup group = new TargetGroup(name, description != null ? description : "");
        groups.put(group.getId(), group);
        saveGroups();
        notifyGroupCreated(group);
        LoggingHelper.d(TAG, "Created group: " + name);
        return group;
    }

    /**
     * Get a group by ID
     */
    @Nullable
    public TargetGroup getGroup(@NonNull String groupId) {
        return groups.get(groupId);
    }

    /**
     * Get a group by name
     */
    @Nullable
    public TargetGroup getGroupByName(@NonNull String name) {
        for (TargetGroup group : groups.values()) {
            if (group.getName().equals(name)) {
                return group;
            }
        }
        return null;
    }

    /**
     * Get all groups
     */
    @NonNull
    public List<TargetGroup> getAllGroups() {
        return new ArrayList<>(groups.values());
    }

    /**
     * Update a group's properties
     */
    public boolean updateGroup(@NonNull String groupId, @Nullable String name,
                               @Nullable String description, @Nullable Integer color) {
        TargetGroup group = groups.get(groupId);
        if (group == null) {
            return false;
        }

        if (name != null) group.setName(name);
        if (description != null) group.setDescription(description);
        if (color != null) group.setColor(color);

        saveGroups();
        notifyGroupUpdated(group);
        return true;
    }

    /**
     * Delete a group
     */
    public boolean deleteGroup(@NonNull String groupId) {
        TargetGroup group = groups.remove(groupId);
        if (group == null) {
            return false;
        }

        // Remove group references from target mapping
        for (String targetId : group.getTargetIds()) {
            Set<String> targetGroups = targetToGroups.get(targetId);
            if (targetGroups != null) {
                targetGroups.remove(groupId);
            }
        }

        saveGroups();
        notifyGroupDeleted(groupId);
        LoggingHelper.d(TAG, "Deleted group: " + group.getName());
        return true;
    }

    /**
     * Add a target to a group
     */
    public boolean addTargetToGroup(@NonNull Target target, @NonNull String groupId) {
        return addTargetToGroup(target.getUuid(), groupId);
    }

    /**
     * Add a target ID to a group
     */
    public boolean addTargetToGroup(@NonNull String targetId, @NonNull String groupId) {
        TargetGroup group = groups.get(groupId);
        if (group == null) {
            return false;
        }

        if (group.addTarget(targetId)) {
            targetToGroups.computeIfAbsent(targetId, k ->
                    Collections.synchronizedSet(new HashSet<>())).add(groupId);
            saveGroups();
            notifyTargetAddedToGroup(targetId, group);
            return true;
        }
        return false;
    }

    /**
     * Remove a target from a group
     */
    public boolean removeTargetFromGroup(@NonNull Target target, @NonNull String groupId) {
        return removeTargetFromGroup(target.getUuid(), groupId);
    }

    /**
     * Remove a target ID from a group
     */
    public boolean removeTargetFromGroup(@NonNull String targetId, @NonNull String groupId) {
        TargetGroup group = groups.get(groupId);
        if (group == null) {
            return false;
        }

        if (group.removeTarget(targetId)) {
            Set<String> targetGroups = targetToGroups.get(targetId);
            if (targetGroups != null) {
                targetGroups.remove(groupId);
            }
            saveGroups();
            notifyTargetRemovedFromGroup(targetId, group);
            return true;
        }
        return false;
    }

    /**
     * Get all groups a target belongs to
     */
    @NonNull
    public List<TargetGroup> getGroupsForTarget(@NonNull Target target) {
        return getGroupsForTarget(target.getUuid());
    }

    /**
     * Get all groups a target ID belongs to
     */
    @NonNull
    public List<TargetGroup> getGroupsForTarget(@NonNull String targetId) {
        List<TargetGroup> result = new ArrayList<>();
        Set<String> groupIds = targetToGroups.get(targetId);
        if (groupIds != null) {
            for (String groupId : groupIds) {
                TargetGroup group = groups.get(groupId);
                if (group != null) {
                    result.add(group);
                }
            }
        }
        return result;
    }

    /**
     * Check if a target is in a specific group
     */
    public boolean isTargetInGroup(@NonNull String targetId, @NonNull String groupId) {
        TargetGroup group = groups.get(groupId);
        return group != null && group.containsTarget(targetId);
    }

    /**
     * Get all target IDs in a group
     */
    @NonNull
    public Set<String> getTargetIdsInGroup(@NonNull String groupId) {
        TargetGroup group = groups.get(groupId);
        return group != null ? group.getTargetIds() : Collections.emptySet();
    }

    /**
     * Filter targets by group membership
     */
    @NonNull
    public List<Target> filterTargetsByGroup(@NonNull List<Target> targets, @NonNull String groupId) {
        Set<String> groupTargetIds = getTargetIdsInGroup(groupId);
        List<Target> result = new ArrayList<>();
        for (Target target : targets) {
            if (groupTargetIds.contains(target.getUuid())) {
                result.add(target);
            }
        }
        return result;
    }

    /**
     * Get count of targets in a group
     */
    public int getTargetCountInGroup(@NonNull String groupId) {
        TargetGroup group = groups.get(groupId);
        return group != null ? group.getTargetCount() : 0;
    }

    /**
     * Search groups by name
     */
    @NonNull
    public List<TargetGroup> searchGroups(@NonNull String query) {
        String lowerQuery = query.toLowerCase();
        List<TargetGroup> result = new ArrayList<>();
        for (TargetGroup group : groups.values()) {
            if (group.getName().toLowerCase().contains(lowerQuery) ||
                group.getDescription().toLowerCase().contains(lowerQuery)) {
                result.add(group);
            }
        }
        return result;
    }

    /**
     * Add listener for group changes
     */
    public void addListener(@NonNull GroupChangeListener listener) {
        if (!listeners.contains(listener)) {
            listeners.add(listener);
        }
    }

    /**
     * Remove listener
     */
    public void removeListener(@NonNull GroupChangeListener listener) {
        listeners.remove(listener);
    }

    /**
     * Clear all groups
     */
    public void clearAllGroups() {
        groups.clear();
        targetToGroups.clear();
        saveGroups();
        LoggingHelper.d(TAG, "All groups cleared");
    }

    /**
     * Get total number of groups
     */
    public int getGroupCount() {
        return groups.size();
    }

    // Persistence methods
    private void saveGroups() {
        if (context == null) {
            LoggingHelper.w(TAG, "Context not initialized, cannot save groups");
            return;
        }

        try {
            JSONArray jsonArray = new JSONArray();
            for (TargetGroup group : groups.values()) {
                jsonArray.put(group.toJson());
            }

            SharedPreferences prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
            prefs.edit().putString(GROUPS_KEY, jsonArray.toString()).apply();
            LoggingHelper.d(TAG, "Saved " + groups.size() + " groups");
        } catch (JSONException e) {
            LoggingHelper.e(TAG, "Error saving groups", e);
        }
    }

    private void loadGroups() {
        if (context == null) {
            LoggingHelper.w(TAG, "Context not initialized, cannot load groups");
            return;
        }

        try {
            SharedPreferences prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
            String data = prefs.getString(GROUPS_KEY, null);
            if (data == null) {
                return;
            }

            JSONArray jsonArray = new JSONArray(data);
            for (int i = 0; i < jsonArray.length(); i++) {
                JSONObject json = jsonArray.getJSONObject(i);
                TargetGroup group = TargetGroup.fromJson(json);
                groups.put(group.getId(), group);

                // Rebuild target-to-groups mapping
                for (String targetId : group.getTargetIds()) {
                    targetToGroups.computeIfAbsent(targetId, k ->
                            Collections.synchronizedSet(new HashSet<>())).add(group.getId());
                }
            }
            LoggingHelper.d(TAG, "Loaded " + groups.size() + " groups");
        } catch (JSONException e) {
            LoggingHelper.e(TAG, "Error loading groups", e);
        }
    }

    // Notification methods
    private void notifyGroupCreated(TargetGroup group) {
        for (GroupChangeListener listener : listeners) {
            listener.onGroupCreated(group);
        }
    }

    private void notifyGroupUpdated(TargetGroup group) {
        for (GroupChangeListener listener : listeners) {
            listener.onGroupUpdated(group);
        }
    }

    private void notifyGroupDeleted(String groupId) {
        for (GroupChangeListener listener : listeners) {
            listener.onGroupDeleted(groupId);
        }
    }

    private void notifyTargetAddedToGroup(String targetId, TargetGroup group) {
        for (GroupChangeListener listener : listeners) {
            listener.onTargetAddedToGroup(targetId, group);
        }
    }

    private void notifyTargetRemovedFromGroup(String targetId, TargetGroup group) {
        for (GroupChangeListener listener : listeners) {
            listener.onTargetRemovedFromGroup(targetId, group);
        }
    }
}
