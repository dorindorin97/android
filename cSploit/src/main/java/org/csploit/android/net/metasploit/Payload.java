package org.csploit.android.net.metasploit;

import org.csploit.android.core.System;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

/**
 * This class stores MSF payload metadata
 *
 * TODO: REFACTORING - Extend MsfModule base class
 * PROBLEM: Payload class has similar functionality to other MSF module types (Exploit, etc.)
 * but doesn't inherit from a common base. Code for refreshing options and handling
 * RPC connections is duplicated across module types.
 * CURRENT WORKAROUND: Each module type implements its own refresh/RPC logic independently.
 * PROPOSED SOLUTION: Create abstract MsfModule base class:
 *
 * public abstract class MsfModule {
 *   protected RPCClient mRpc;
 *   protected String mName;
 *
 *   public void onRpcConnected() {
 *     refresh();
 *   }
 *
 *   protected abstract void refresh() throws IOException, MSFException;
 *   public abstract Collection<Option> getOptions();
 * }
 *
 * BENEFITS:
 * - Centralized module lifecycle management
 * - Automatic refresh when RPC connection established
 * - Common interface for all module types
 * - Reduced code duplication
 * IMPACT: Medium - Requires refactoring Payload and other module classes
 * NOTE: Would improve maintainability and consistency across module implementations
 */
public class Payload {

  private Collection<Option> options = new ArrayList<Option>();
  private String mName = null;

  public Payload(String name){
    mName = name;
    try {
      retrieveOptions();
    } catch (RPCClient.MSFException e) {
      LoggingHelper.e(TAG, "Failed to retrieve payload options", e);
    } catch (IOException e) {
      LoggingHelper.e(TAG, "Payload IO error", e);
    }
  }

  @SuppressWarnings("unchecked")
  private void retrieveOptions() throws IOException, RPCClient.MSFException {
    Object res;

    res = System.getMsfRpc().call("module.options", "payload", mName);

    if(res == null)
      return;

    for(Map.Entry<String, Map<String, Object>> entry :
            ((Map<String,Map<String, Object>>)res).entrySet()) {
      Option o;

      try {
        o = new Option(entry.getKey(), entry.getValue());
      } catch (IllegalArgumentException e) {
        LoggingHelper.e(TAG, "Failed to parse payload option", e);
        continue;
      }

      if(entry.getKey().equals("LHOST")) {
        o.setValue(System.getNetwork().getLocalAddress().getHostAddress());
      }

      options.add(o);
    }
  }

  public Collection<Option> getOptions() {
    return options;
  }

  public String getName() {
    return mName;
  }

  public String toString() {
    return mName;
  }

}
