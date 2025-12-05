package org.csploit.android.net.metasploit;

import org.csploit.android.core.System;

import java.io.IOException;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Map;

/**
 * this class store MSF payload metadata
 *
 * TODO: extends MsfModule
 *
 * public abstract class MsfModule {
 *   public onRpcConnected() {
 *     refresh();
 *   }
 *   void refresh();
 * }
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
