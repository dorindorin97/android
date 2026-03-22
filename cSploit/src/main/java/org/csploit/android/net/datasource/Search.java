package org.csploit.android.net.datasource;

import org.csploit.android.BuildConfig;
import org.csploit.android.helpers.ThreadHelper;
import org.csploit.android.net.RemoteReader;
import org.csploit.android.net.Target;

import java.util.concurrent.Future;

/**
 * Searcher manager
 *
 * it handle multiple searchers
 */
public class Search {
  private static final Rapid7 RAPID7 = new Rapid7();
  private static final ExploitDb EXPLOIT_DB = new ExploitDb();

  public interface Receiver<T> extends RemoteReader.EndReceiver {
    void onItemFound(T item);
    /* TODO: ARCHITECTURAL IMPROVEMENT - Make (Target|Exploit|Reference) extend Observable.
     * PROBLEM: Current implementation requires manual notification of item changes via
     * separate onFoundItemChanged() callback. If items are updated after initial discovery,
     * UI components are not automatically notified.
     * CURRENT WORKAROUND: Code must explicitly call onFoundItemChanged() when items change.
     * SOLUTION: Implement Observer pattern where:
     * - Target, Exploit, and Reference extend Observable
     * - UI components register as Observers on specific items
     * - When item data changes, automatic notification is triggered
     * - No need for explicit onFoundItemChanged() callback
     * BENEFITS:
     * - Automatic UI updates when items change
     * - Cleaner API; items manage their own change notifications
     * - Easier to add multiple observers to same item
     * IMPACT: Medium - Architecture improvement; requires refactoring model classes
     * NOTE: Could use Android's LiveData/MutableLiveData for modern implementation
     */
    void onFoundItemChanged(T item);
  }

  public static Future searchExploitForServices(Target target, Receiver<Target.Exploit> receiver) {
    // In debug builds, both Rapid7 (Next.js migration) and ExploitDB (SPA/AJAX migration)
    // no longer serve parseable HTML. Fire fake results immediately so the full UI flow
    // can be exercised without network access.
    if (BuildConfig.DEBUG) {
      ThreadHelper.getSharedExecutor().execute(() -> {
        int seq = 0;
        for (Target.Port p : target.getOpenPorts()) {
          String svc = p.getService();
          if (svc == null) continue;
          Target.Exploit rce = new Target.Exploit(
              "[DEBUG] " + svc + " Remote Code Execution",
              "https://www.exploit-db.com/exploits/99999/",
              "Fake exploit for debug: " + svc + " service.",
              p);
          rce.setId("DBG-" + (seq++));
          receiver.onItemFound(rce);
          Target.Exploit privesc = new Target.Exploit(
              "[DEBUG] " + svc + " Privilege Escalation",
              "https://www.exploit-db.com/exploits/99998/",
              "Fake privilege escalation for debug: " + svc + " service.",
              p);
          privesc.setId("DBG-" + (seq++));
          receiver.onItemFound(privesc);
        }
        receiver.onEnd();
      });
      return null;
    }

    RemoteReader.Job job = null;

    for(Target.Port p : target.getOpenPorts()) {
      String service = p.getService();

      if(service == null)
        continue;

      if(job == null) {
        job = new RemoteReader.Job(receiver);
      }

      String pref = org.csploit.android.core.System.getSettings().getString("SEARCH_EXDB", "BOTH");

      boolean useRapid7 = !pref.equals("EXDB");
      boolean useExploitDb = !pref.equals("MSF");

      if(useRapid7) RAPID7.beginSearch(job, service, p, receiver);
      if(useExploitDb) EXPLOIT_DB.beginSearch(job, service, p, receiver);
    }

    if (job == null) {
      // No ports with known services — notify immediately so callers can update UI
      receiver.onEnd();
    }

    return job;
  }
}
