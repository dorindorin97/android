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

import android.text.TextUtils;

import org.csploit.android.core.Child;
import org.csploit.android.core.ChildManager;
import org.csploit.android.helpers.LoggingHelper;
import org.csploit.android.events.Event;
import org.csploit.android.events.Hop;
import org.csploit.android.events.Os;
import org.csploit.android.events.Port;
import org.csploit.android.net.Network;
import org.csploit.android.net.Target;

import java.util.LinkedList;

public class NMap extends Tool {

  public static abstract class TraceReceiver extends Child.EventReceiver
  {
    public void onEnd( int exitCode ) {
      if( exitCode != 0 )
        LoggingHelper.error("nmap exited with code " + exitCode );
    }

    public void onDeath( int signal ) {
      LoggingHelper.error("nmap killed by signal " + signal);
    }

    public void onEvent(Event e) {
      if(e instanceof Hop) {
        Hop hop = (Hop)e;
        onHop(hop.hop, hop.usec, hop.node.getHostAddress(), hop.name);
      } else {
        LoggingHelper.error("unknown event: " + e);
      }
    }

    public abstract void onHop( int hop, long usec, String address, String name );
  }

  public static abstract class SynScanReceiver extends Child.EventReceiver
  {

    public void onEnd( int exitCode ) {
      if( exitCode != 0 )
        LoggingHelper.error( "nmap exited with code " + exitCode );
    }

    public void onDeath(int signal) {
      LoggingHelper.error("nmap killed by signal " + signal);
    }

    public void onEvent( Event e) {
      if(e instanceof Port) {
        Port p = (Port)e;
        onPortFound(p.port, p.protocol);
      } else {
        LoggingHelper.error("unkown event: " + e);
      }
    }

    public abstract void onPortFound( int port, String protocol );
  }

  public static abstract class InspectionReceiver extends Child.EventReceiver
  {

    public void onEnd( int exitCode ) {
      if( exitCode != 0 )
        LoggingHelper.error( "nmap exited with code " + exitCode );
    }

    public void onDeath(int signal) {
      LoggingHelper.error( "nmap killed by signal " + signal);
    }

    public void onEvent(Event e) {
      if(e instanceof Port) {
        Port p = (Port)e;
        if(p.service == null) {
          onOpenPortFound(p.port, p.protocol);
        } else {
          onServiceFound(p.port, p.protocol, p.service, p.version);
        }
      } else if(e instanceof Os) {
        Os os = (Os) e;
        onOsFound(os.os);
        onDeviceFound(os.type);
      } else {
        LoggingHelper.error("unknown event: " + e);
      }
    }

    public abstract void onOpenPortFound( int port, String protocol );
    public abstract void onServiceFound( int port, String protocol, String service, String version );
    public abstract void onOsFound( String os );
    public abstract void onDeviceFound( String device );
  }

  public NMap() {
    mHandler = "nmap";
    mCmdPrefix = null;
  }

  private static void validatePortSpec(String spec) throws ChildManager.ChildNotStartedException {
    // Allow digits, commas, hyphens, and T:/U: protocol prefixes only
    if (spec != null && !spec.matches("[TU]?:?[0-9]+([-,][0-9]+)*([,][TU]?:?[0-9]+([-,][0-9]+)*)*"))
      throw new ChildManager.ChildNotStartedException("Invalid port specification: " + spec);
  }

  private static void validateCustomFlags(String flags) throws ChildManager.ChildNotStartedException {
    if (flags != null && flags.matches(".*[;&|`$(){}\n\r].*"))
      throw new ChildManager.ChildNotStartedException("Custom flags contain unsafe characters");
  }

  public Child trace( Target target, boolean resolve, TraceReceiver receiver ) throws ChildManager.ChildNotStartedException {

    String cmd = String.format("-sn --traceroute --privileged --send-ip --system-dns -%c %s",
            (resolve ? 'R' : 'n'), target.getCommandLineRepresentation());

    return super.async(cmd, receiver );
  }

  public Child synScan( Target target, SynScanReceiver receiver, String custom ) throws ChildManager.ChildNotStartedException {
    validatePortSpec(custom);
    StringBuilder command = new StringBuilder("-sS -Pn --privileged --send-ip --system-dns -vvv ");

    if( custom != null )
      command.append("-p ").append(custom).append(" ");

    command.append(target.getCommandLineRepresentation());

    LoggingHelper.debug( "synScan - " + command.toString() );

    return super.async( command.toString(), receiver );
  }

  public Child synScan( Target target, SynScanReceiver receiver) throws ChildManager.ChildNotStartedException {
    return synScan(target, receiver, null);
  }

  public Child customScan( Target target, SynScanReceiver receiver, String custom ) throws ChildManager.ChildNotStartedException {
    validateCustomFlags(custom);
    StringBuilder command = new StringBuilder("-vvv ");

    if( custom != null )
      command.append(custom).append(" ");

    command.append(target.getCommandLineRepresentation());

    LoggingHelper.debug( "customScan - " + command.toString() );

    return super.async( command.toString(), receiver );
  }

  public Child inspect( Target target, InspectionReceiver receiver, boolean focusedScan ) throws ChildManager.ChildNotStartedException {
    String cmd;
    LinkedList<Integer> tcp,udp;
    Network.Protocol protocol;
    int pNumber;

    if(focusedScan)
    {
      tcp = new LinkedList<Integer>();
      udp = new LinkedList<Integer>();
      for( Target.Port p : target.getOpenPorts()) {
        protocol = p.getProtocol();
        pNumber = p.getNumber();

        if(protocol.equals(Network.Protocol.TCP)) {
          if(!tcp.contains(pNumber))
            tcp.add(pNumber);
        } else if(protocol.equals(Network.Protocol.UDP)) {
          if(!udp.contains(pNumber))
            udp.add(pNumber);
        }
      }
      cmd = "-T4 -sV -O --privileged --send-ip --system-dns -Pn -oX - ";
      if(!tcp.isEmpty() || !udp.isEmpty()) {
        cmd+= "-p ";
        if(!tcp.isEmpty())
          cmd+= "T:" + TextUtils.join(",",tcp);
        if(!udp.isEmpty())
          cmd+= "U:" + TextUtils.join(",", udp);
        cmd+= " ";
      }
      cmd+= target.getCommandLineRepresentation();
    }
    else
      cmd = "-T4 -F -O -sV --privileged --send-ip --system-dns -oX - " + target.getCommandLineRepresentation();

    LoggingHelper.debug( "Inspect - " + cmd );

    return super.async( cmd, receiver);
  }

  // -------------------------------------------------------------------------
  // Mock scan methods — instant fake results for debug builds.
  // Fires the same receiver callbacks a real scan would, just immediately.
  // Returns null (no process to kill); callers already guard with != null.
  // -------------------------------------------------------------------------

  /** Fires fake port-found results then onEnd, bypassing the nmap binary. */
  public Child mockSynScan(Target target, SynScanReceiver receiver) {
    org.csploit.android.helpers.ThreadHelper.getSharedExecutor().execute(() -> {
      receiver.onStart("mock nmap -sS " + target.getCommandLineRepresentation());
      for (Target.Port p : target.getOpenPorts()) {
        receiver.onPortFound(p.getNumber(), p.getProtocol().name().toLowerCase());
      }
      // If no ports pre-seeded, emit a sensible default set
      if (target.getOpenPorts().isEmpty()) {
        receiver.onPortFound(22,   "tcp");
        receiver.onPortFound(80,   "tcp");
        receiver.onPortFound(443,  "tcp");
        receiver.onPortFound(8080, "tcp");
      }
      receiver.onEnd(0);
    });
    return null;
  }

  /** Fires fake service/OS results then onEnd, bypassing the nmap binary. */
  public Child mockInspect(Target target, InspectionReceiver receiver) {
    org.csploit.android.helpers.ThreadHelper.getSharedExecutor().execute(() -> {
      receiver.onStart("mock nmap -sV -O " + target.getCommandLineRepresentation());
      if (!target.getOpenPorts().isEmpty()) {
        for (Target.Port p : target.getOpenPorts()) {
          String svc     = p.getService()  != null && !p.getService().isEmpty()  ? p.getService()  : "unknown";
          String version = p.getVersion()  != null && !p.getVersion().isEmpty()  ? p.getVersion()  : "";
          receiver.onServiceFound(p.getNumber(), p.getProtocol().name().toLowerCase(), svc, version);
        }
      } else {
        receiver.onServiceFound(22,   "tcp", "ssh",  "OpenSSH 7.4");
        receiver.onServiceFound(80,   "tcp", "http", "Apache httpd 2.4.6");
        receiver.onServiceFound(443,  "tcp", "https","nginx 1.12");
        receiver.onServiceFound(8080, "tcp", "http", "Apache Tomcat 8.5");
      }
      String os = target.getDeviceOS();
      receiver.onOsFound(os != null && !os.isEmpty() ? os : "Linux 4.x");
      receiver.onDeviceFound("general purpose");
      receiver.onEnd(0);
    });
    return null;
  }

  /** Fires fake traceroute hops then onEnd, bypassing the nmap binary. */
  public Child mockTrace(Target target, TraceReceiver receiver) {
    org.csploit.android.helpers.ThreadHelper.getSharedExecutor().execute(() -> {
      receiver.onStart("mock nmap --traceroute " + target.getCommandLineRepresentation());
      receiver.onHop(1, 1_200,  "192.168.1.1", "gateway.local");
      receiver.onHop(2, 8_500,  "10.0.0.1",   "isp-edge.net");
      receiver.onHop(3, 14_000, target.getCommandLineRepresentation(), target.toString());
      receiver.onEnd(0);
    });
    return null;
  }
}