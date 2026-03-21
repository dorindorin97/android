/*
 * This file is part of the cSploit.
 *
 * Copyleft of Massimo Dragano aka tux_mind <tux_mind@csploit.org>
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
package org.csploit.android.tools;

import org.csploit.android.core.System;
import org.csploit.android.helpers.LoggingHelper;

public class IPTables extends Tool
{
  private static final String TAG = "IPTables";
  private static final java.util.regex.Pattern IP_PORT_PATTERN =
      java.util.regex.Pattern.compile("^\\d{1,3}(\\.\\d{1,3}){3}:\\d{1,5}$");

  public IPTables(){
    mHandler = "raw";
    mCmdPrefix = "iptables";
  }

  private static void validateIpPort(String ipPort) throws IllegalArgumentException {
    if (ipPort == null || !IP_PORT_PATTERN.matcher(ipPort).matches())
      throw new IllegalArgumentException("Invalid IP:port format: " + ipPort);
  }

  private static void validatePort(int port) throws IllegalArgumentException {
    if (port < 1 || port > 65535)
      throw new IllegalArgumentException("Invalid port: " + port);
  }

  public void trafficRedirect(String to){
    LoggingHelper.debug("Redirecting traffic to " + to);

    try{
      validateIpPort(to);
      super.run("-t nat -A PREROUTING -j DNAT -p tcp --to " + to);
    }
    catch(Exception e){
      LoggingHelper.e(TAG, "Failed to redirect traffic", e);
    }
  }

  public void undoTrafficRedirect(String to){
    LoggingHelper.debug("Undoing traffic redirection");

    try{
      validateIpPort(to);
      super.run("-t nat -D PREROUTING -j DNAT -p tcp --to " + to);
    }
    catch(Exception e){
      LoggingHelper.e(TAG, "Failed to undo traffic redirection", e);
    }
  }

  public void portRedirect(int from, int to, boolean cleanRules){
    LoggingHelper.debug("Redirecting traffic from port " + from + " to port " + to);

    try{
      validatePort(from);
      validatePort(to);
      if (cleanRules) {
        // clear nat
        super.run("-t nat -F");
        // clear
        super.run("-F");
        // post route
        super.run("-t nat -I POSTROUTING -s 0/0 -j MASQUERADE");
        // accept all
        super.run("-P FORWARD ACCEPT");
      }
      // add rule
      org.csploit.android.net.Network net = System.getNetwork();
      if (net == null) throw new IllegalStateException("network not initialized");
      super.run("-t nat -A PREROUTING -j DNAT -p tcp --dport " + from + " --to " + net.getLocalAddressAsString() + ":" + to);
    }
    catch(Exception e){
      LoggingHelper.e(TAG, "Failed to redirect port", e);
    }
  }

  public void undoPortRedirect(int from, int to){
    LoggingHelper.debug("Undoing port redirection");

    try{
      validatePort(from);
      validatePort(to);
      // clear nat
      super.run("-t nat -F");
      // clear
      super.run("-F");
      // remove post route
      super.run("-t nat -D POSTROUTING -s 0/0 -j MASQUERADE");
      // remove rule
      org.csploit.android.net.Network net = System.getNetwork();
      if (net == null) throw new IllegalStateException("network not initialized");
      super.run("-t nat -D PREROUTING -j DNAT -p tcp --dport " + from + " --to " + net.getLocalAddressAsString() + ":" + to);
    }
    catch(Exception e){
      LoggingHelper.e(TAG, "Failed to undo port redirection", e);
    }
  }
}
