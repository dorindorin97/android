package org.csploit.android.core;

import java.util.ArrayList;

/**
 * this interface is used to notify objects about a changed property in settings
 */
public abstract class SettingReceiver {

  protected ArrayList<String> mFilter = new ArrayList<String>();

  /**
   * return an list of preferences keys to listen on
   * @return an ArrayList containing all preference keys to listen on, null if no filter
   */
  public ArrayList<String> getFilter() {
    return mFilter;
  }

  public void setFilter(ArrayList<String> filter) {
    mFilter = filter;
  }

  public void addFilter(String filter) {
    mFilter.add(filter);
  }

  /**
   * callback function called whence a setting has changed
   */
  public abstract void onSettingChanged(String key);

  /**
   * Cleanup method called during garbage collection.
   *
   * Note: finalize() is deprecated in Java 9+. This exists as a safety net
   * to unregister the listener. Prefer explicitly unregistering when done.
   */
  @SuppressWarnings("deprecation")
  @Override
  protected void finalize() throws Throwable {
    try {
      System.unregisterSettingListener(this);
    } finally {
      super.finalize();
    }
  }
}
