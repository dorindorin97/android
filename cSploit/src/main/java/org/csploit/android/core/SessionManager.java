/*
 * This file is part of the cSploit.
 *
 * cSploit is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * cSploit is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with cSploit.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.csploit.android.core;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStreamReader;
import java.io.IOException;
import java.util.ArrayList;
import java.util.zip.GZIPInputStream;
import java.util.zip.GZIPOutputStream;

import org.csploit.android.net.Target;

/**
 * Manages session persistence operations for the application.
 * Handles loading and saving of session files with compression.
 */
public class SessionManager {
    private static final String SESSION_MAGIC = "cSploitSession";
    private static final String SESSION_EXT = ".dss";
    private static final String HIJACKER_SESSION_EXT = ".dhs";

    private String mSessionName;
    private String mStoragePath;
    private ArrayList<Target> mTargets;

    /**
     * Creates a SessionManager instance
     *
     * @param storagePath Path where session files are stored
     * @param targets Reference to the targets list for session data
     */
    public SessionManager(String storagePath, ArrayList<Target> targets) {
        this.mStoragePath = storagePath;
        this.mTargets = targets;
    }

    /**
     * Save current session to a compressed file
     *
     * @param sessionName Name of the session to save
     * @return Path to the saved session file
     * @throws IOException if file operations fail
     */
    public String saveSession(String sessionName) throws IOException {
        StringBuilder builder = new StringBuilder();
        String filename = mStoragePath + '/' + sessionName + SESSION_EXT;

        builder.append(SESSION_MAGIC + "\n");

        // Skip the network target
        synchronized (mTargets) {
            builder.append(mTargets.size() - 1).append("\n");
            for (Target target : mTargets) {
                if (target.getType() != Target.Type.NETWORK)
                    target.serialize(builder);
            }
        }

        String session = builder.toString();

        try (GZIPOutputStream gzip = new GZIPOutputStream(new FileOutputStream(filename))) {
            gzip.write(session.getBytes());
        }

        mSessionName = sessionName;
        return filename;
    }

    /**
     * Load a session from a compressed file
     *
     * @param filename Name of the session file to load
     * @throws Exception if file is invalid or cannot be read
     */
    public void loadSession(String filename) throws Exception {
        File file = new File(mStoragePath + '/' + filename);

        if (file.exists() && file.length() > 0) {
            try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                    new GZIPInputStream(new FileInputStream(file))))) {
                String line = reader.readLine();
                if (line == null || !line.equals(SESSION_MAGIC))
                    throw new Exception("Not a cSploit session file.");

                // Read targets
                int targets = Integer.parseInt(reader.readLine());

                synchronized (mTargets) {
                    mTargets.clear();
                    for (int i = 0; i < targets; i++) {
                        Target target = new Target(reader);
                        mTargets.add(target);
                    }
                }

            } catch (Exception e) {
                mTargets.clear();
                throw e;
            }
        } else {
            throw new Exception(filename + " does not exist or is empty.");
        }
    }

    /**
     * Get list of available session files
     *
     * @return ArrayList of session file names
     */
    public ArrayList<String> getAvailableSessionFiles() {
        ArrayList<String> files = new ArrayList<String>();
        File storage = new File(mStoragePath);

        if (storage.exists()) {
            String[] children = storage.list();

            if (children != null && children.length > 0) {
                for (String child : children) {
                    if (child.endsWith(SESSION_EXT))
                        files.add(child);
                }
            }
        }

        return files;
    }

    /**
     * Get list of available hijacker session files
     *
     * @return ArrayList of hijacker session file names
     */
    public ArrayList<String> getAvailableHijackerSessionFiles() {
        ArrayList<String> files = new ArrayList<String>();
        File storage = new File(mStoragePath);

        if (storage.exists()) {
            String[] children = storage.list();

            if (children != null && children.length > 0) {
                for (String child : children) {
                    if (child.endsWith(HIJACKER_SESSION_EXT))
                        files.add(child);
                }
            }
        }

        return files;
    }

    /**
     * Get the name of the current session
     *
     * @return Current session name or empty string if none loaded
     */
    public String getSessionName() {
        return mSessionName != null ? mSessionName : "";
    }

    /**
     * Set the current session name
     *
     * @param sessionName Name to set
     */
    public void setSessionName(String sessionName) {
        this.mSessionName = sessionName;
    }
}
