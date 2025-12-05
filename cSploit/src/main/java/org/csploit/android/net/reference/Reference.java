package org.csploit.android.net.reference;

/**
 * a reference to something
 * 
 * Represents a generic reference with name and summary display information.
 * Implementations can optionally provide drawable resource IDs for visual display.
 */
public interface Reference {
  String getName();
  String getSummary();
  
  /**
   * Get the drawable resource ID for this reference (if any).
   * Default implementation returns 0 (no drawable).
   * Implementations may override to provide custom drawable icons.
   * 
   * @return drawable resource ID or 0 if no drawable available
   */
  default int getDrawableResourceId() {
    return 0;
  }
}
