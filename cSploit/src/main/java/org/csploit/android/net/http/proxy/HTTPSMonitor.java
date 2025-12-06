/*
 * This file is part of the dSploit.
 *
 * Copyleft of Simone Margaritelli aka evilsocket <evilsocket@gmail.com>
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
package org.csploit.android.net.http.proxy;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class HTTPSMonitor{
  private static volatile HTTPSMonitor mInstance = null;

  private final Map<String, List<String>> mMap;

  public static HTTPSMonitor getInstance(){
    if(mInstance == null){
      synchronized(HTTPSMonitor.class){
        if(mInstance == null)
          mInstance = new HTTPSMonitor();
      }
    }
    return mInstance;
  }

  public HTTPSMonitor(){
    mMap = new ConcurrentHashMap<>();
  }

  public void addURL(String client, String url){
    mMap.computeIfAbsent(client, k -> new ArrayList<>()).add(url);
  }

  public boolean hasURL(String client, String url){
    List<String> urls = mMap.get(client);
    return urls != null && urls.contains(url);
  }

  public void clear(){
    mMap.clear();
  }
}
