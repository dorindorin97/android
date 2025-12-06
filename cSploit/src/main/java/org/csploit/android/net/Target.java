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
package org.csploit.android.net;

import org.csploit.android.R;
import org.csploit.android.core.Logger;
import org.csploit.android.core.System;
import org.csploit.android.helpers.LoggingHelper;
import org.csploit.android.helpers.ThreadHelper;
import org.csploit.android.net.Network.Protocol;
import org.csploit.android.net.metasploit.MsfExploit;
import org.csploit.android.net.metasploit.Session;
import org.csploit.android.net.reference.Reference;

import java.io.BufferedReader;
import java.net.InetAddress;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Locale;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

public class Target implements Comparable<Target>
{
  private static final String TAG = "Target";

  public enum Type{
    NETWORK,
    ENDPOINT,
    REMOTE;

    public static Type fromString(String type) throws Exception{
      if(type != null){
        type = type.trim().toLowerCase(Locale.US);
        if(type.equals("network"))
          return Type.NETWORK;

        else if(type.equals("endpoint"))
          return Type.ENDPOINT;

        else if(type.equals("remote"))
          return Type.REMOTE;
      }

      throw new Exception("Could not deserialize target type from string.");
    }
  }

  public static class Port{
    private Protocol protocol;
    private int number;
    private String service = null;
    private String	version = null;

    public Port( int port, Protocol proto, String service, String version) {
      this.number = port;
      this.protocol = proto;
      this.service = service;
      this.version = version;
    }

    public Port( int port, Protocol proto, String service ) {
      this(port, proto, service, "");
    }

    public Port( int port, Protocol proto ) {
      this( port, proto, "", "" );
    }

    public String toString(){
      return String.format("Port: { proto: '%s', number: %d, service: '%s', version: '%s' }",
              protocol.toString(), number,
              (service == null ? "(null)" : service),
              (version == null ? "(null)" : version));
    }

    public int getNumber() {
      return number;
    }

    public Protocol getProtocol() {
      return protocol;
    }

    public void setService(String service) {
      this.service = service;
    }

    public String getService() {
      return service;
    }

    public boolean haveService() {
      return service != null && !service.isEmpty();
    }

    public void setVersion(String version) {
      this.version = version;
    }

    public String getVersion() {
      return version;
    }

    public boolean haveVersion() {
      return version != null && !version.isEmpty();
    }

    public boolean equals(Object o) {
      if(o == null || o.getClass() != this.getClass())
        return false;
      Port p = (Port)o;
      return (p.number == this.number && p.protocol == this.protocol);
    }

    /**
     * merge data from this port to another
     * @param other
     */
    public void mergeTo(Port other) {
      if(service != null && !service.equals(other.service)) {
        other.service = service;
      }
      if(version != null && !version.equals(other.version)) {
        other.version = version;
      }
    }
  }

  public static class Exploit {
    protected String id;
    protected String name;
    protected String summary;
    protected String description;
    protected String url;
    protected Port port;
    protected final Collection<Reference> references = new LinkedList<Reference>();
    protected boolean enabled = false;
    protected Target parent;

    public Exploit() {}

    public Exploit(String name, String url, String summary, Port port) {
      this.name = name;
      this.url = url;
      this.summary = summary;
      this.port = port;
    }

    public Exploit(String name, String url, String summary) {
      this(name, url, summary, null);
    }

    public Exploit(String name, String url) {
      this(name, url, name, null);
    }

    public Target getParent() {
      return parent;
    }

    public void setParent(Target parent) {
      this.parent = parent;
    }

    public void setName(String name) {
      this.name = name;
    }

    public String getName() {
      return this.name;
    }

    public void setSummary(String summary) {
      this.summary = summary;
    }

    public String getSummary() {
      return summary;
    }

    public void setDescription(String description) {
      this.description = description;
    }

    public String getDescription() {
      return this.description;
    }

    public void setId(String id) {
      this.id = id;
    }

    public String getId() {
      return id;
    }

    public void setUrl(String url) {
      this.url = url;
    }

    public String getUrl() {
      return this.url;
    }

    public String toString() {
      return name;
    }

    public int getDrawableResourceId() {
      return R.drawable.exploit;
    }

    public boolean equals(Object o) {
      if(o == null || o.getClass() != this.getClass())
        return false;
      Exploit other = (Exploit) o;
      return id == null ? other.id == null : id.equals(other.id);
    }

    public void addReference(Reference ref) {
      synchronized (references) {
        Iterator<Reference> it = references.iterator();

        while(it.hasNext()) {
          if(ref.equals(it.next())) {
            it.remove();
            break;
          }
        }

        references.add(ref);
      }
    }

    public Collection<Reference> getReferences() {
      return references;
    }

    public void setEnabled(boolean enabled) {
      this.enabled = enabled;
    }

    public boolean isEnabled() {
      return enabled;
    }

    public void setPort(Port port) {
      this.port = port;
    }
  }

  private Network mNetwork = null;
  private Endpoint mEndpoint = null;
  private int mPort = 0;
  private String mHostname = null;
  private Type mType = null;
  private InetAddress mAddress = null;
  private final ArrayList<Port> mPorts = new ArrayList<>();
  private String mDeviceType = null;
  private String mDeviceOS = null;
  private String mAlias = null;
  private boolean mConnected = true;
  private boolean mSelected = false;
  private final ArrayList<Exploit> exploits = new ArrayList<Target.Exploit>();
  private ArrayList<Session> mSessions = new ArrayList<Session>();

  /** Unique identifier for this target, used for stable reference across operations */
  private final String mUuid;

  private static final long DNS_LOOKUP_TIMEOUT_MS = 5000;

  /**
   * Resolve hostname to InetAddress asynchronously to avoid NetworkOnMainThread exception.
   * @param hostname the hostname to resolve
   * @return the resolved InetAddress, or null if resolution failed
   */
  private static InetAddress resolveHostnameAsync(String hostname) {
    if (hostname == null || hostname.isEmpty()) {
      return null;
    }

    AtomicReference<InetAddress> result = new AtomicReference<>(null);
    CountDownLatch latch = new CountDownLatch(1);

    ThreadHelper.executeBackground(() -> {
      try {
        result.set(InetAddress.getByName(hostname));
      } catch (Exception e) {
        LoggingHelper.d(TAG, "DNS resolution failed for: " + hostname);
      } finally {
        latch.countDown();
      }
    });

    try {
      if (!latch.await(DNS_LOOKUP_TIMEOUT_MS, TimeUnit.MILLISECONDS)) {
        LoggingHelper.w(TAG, "DNS lookup timeout for: " + hostname);
        return null;
      }
    } catch (InterruptedException e) {
      Thread.currentThread().interrupt();
      return null;
    }

    return result.get();
  }

  public static Target getFromString(String string){
    final Pattern PARSE_PATTERN = Pattern.compile("^(([a-z]+)://)?([0-9a-z\\-\\.]+)(:([\\d]+))?[0-9a-z\\-\\./]*$", Pattern.CASE_INSENSITIVE);
    final Pattern IP_PATTERN = Pattern.compile("^[\\d]{1,3}\\.[\\d]{1,3}\\.[\\d]{1,3}\\.[\\d]{1,3}$");

    Matcher matcher;
    Target target = null;

    try{
      string = string.trim();

      if((matcher = PARSE_PATTERN.matcher(string)) != null && matcher.find()){
        String protocol = matcher.group(2),
          address = matcher.group(3),
          sport = matcher.group(4);

        protocol = protocol != null ? protocol.toLowerCase(Locale.US) : null;
        sport = sport != null ? sport.substring(1) : null;

        if(address != null){
          // attempt to get the port from the protocol or the specified one
          int port = 0;

          if(sport != null)
            port = Integer.parseInt(sport);

          else if(protocol != null)
            port = System.getPortByProtocol(protocol);

          // determine if the 'address' part is an ip address or a host name
          if(IP_PATTERN.matcher(address).find()){
            // internal ip address
            if(System.getNetwork().isInternal(address)){
              target = new Target(new Endpoint(address, null));
              target.setPort(port);
            }
            // external ip address, return as host name
            else{
              target = new Target(address, port);
            }
          }
          // found a host name
          else
            target = new Target(address, port);
        }
      }
    }
    catch(Exception e){
      LoggingHelper.e(TAG, "Failed to parse target", e);
    }

    // Verify the target is reachable using async DNS resolution
    if(target != null){
      InetAddress resolved = resolveHostnameAsync(target.getCommandLineRepresentation());
      if(resolved == null){
        target = null;
      }
    }

    return target;
  }

  public Target(BufferedReader reader) throws Exception{
    mUuid = UUID.randomUUID().toString();
    mType = Type.fromString(reader.readLine());
    mDeviceType = reader.readLine();
    mDeviceType = mDeviceType.equals("null") ? null : mDeviceType;
    mDeviceOS = reader.readLine();
    mDeviceOS = mDeviceOS.equals("null") ? null : mDeviceOS;
    mAlias = reader.readLine();
    mAlias = mAlias.equals("null") ? null : mAlias;

    if(mType == Type.NETWORK){
      return;
    }
    else if(mType == Type.ENDPOINT){
      mEndpoint = new Endpoint(reader);
    }
    else if(mType == Type.REMOTE){
      mHostname = reader.readLine();
      mHostname = mHostname.equals("null") ? null : mHostname;
      if(mHostname != null){
        // Use async DNS resolution to avoid NetworkOnMainThreadException
        mAddress = resolveHostnameAsync(mHostname);
      }
    }

    int ports = Integer.parseInt(reader.readLine());
    for(int i = 0; i < ports; i++){
      String key = reader.readLine();
      String[] parts = key.split("\\|", 4);
      Port port = new Port
      (
        Integer.parseInt(parts[1]),
        Protocol.fromString(parts[0]),
        parts[2],
        parts[3]
      );

      mPorts.add(port);
    }
  }

  public void serialize(StringBuilder builder){
    builder.append(mType).append("\n");
    builder.append(mDeviceType).append("\n");
    builder.append(mDeviceOS).append("\n");
    builder.append(mAlias).append("\n");

    // a network can't be saved in a session file
    if(mType == Type.NETWORK){
      return;
    }
    else if(mType == Type.ENDPOINT){
      mEndpoint.serialize(builder);
    }
    else if(mType == Type.REMOTE){
      builder.append(mHostname).append("\n");
    }

    synchronized (mPorts) {
      builder.append(mPorts.size()).append("\n");

      for(Port p : mPorts) {
        builder.append(p.getProtocol().toString());
        builder.append("|");
        builder.append(p.getNumber());
        builder.append("|");
        if(p.haveService())
          builder.append(p.getService());
        builder.append("|");
        if(p.haveVersion())
          builder.append(p.getVersion());
        builder.append("\n");
      }
    }
  }

  public void setAlias(String alias){
    mAlias = alias != null ? alias.trim() : null;
  }

  public String getAlias(){
    return mAlias;
  }

  public boolean hasAlias(){
    return mAlias != null && !mAlias.isEmpty();
  }

  @Override
  public int compareTo(@NonNull Target another) {
    if(mType != another.mType) {
      if(mType == Type.NETWORK) {
        return -1;
      } else if (mType == Type.REMOTE) {
        return +1;
      } else if (another.mType == Type.NETWORK){
        return +1;
      } else { // another is REMOTE
        return -1;
      }
    }
    if(mType == Type.NETWORK) {
      return mNetwork.compareTo(another.mNetwork);
    } else if(mType == Type.REMOTE){
      return mHostname.compareTo(another.mHostname);
    } else {
      try {
        if (mEndpoint.getAddress().equals(System.getNetwork().getGatewayAddress()))
          return -1;
        else if (mEndpoint.getAddress().equals(System.getNetwork().getLocalAddress()))
          return +1;
      } catch (Exception e) {
        LoggingHelper.e(TAG, "Failed to compare targets", e);
      }
      return mEndpoint.compareTo(another.mEndpoint);
    }
  }

  public Target(Network net){
    mUuid = UUID.randomUUID().toString();
    setNetwork(net);
  }

  public Target(InetAddress address, byte[] hardware){
    mUuid = UUID.randomUUID().toString();
    setEndpoint(address, hardware);
  }

  public Target(Endpoint endpoint){
    mUuid = UUID.randomUUID().toString();
    setEndpoint(endpoint);
  }

  public Target(String hostname, int port){
    mUuid = UUID.randomUUID().toString();
    setHostname(hostname, port);
  }

  /**
   * Get the unique identifier for this target.
   * @return The UUID string uniquely identifying this target instance.
   */
  public String getUuid() {
    return mUuid;
  }

  public InetAddress getAddress(){
    if(mType == Type.ENDPOINT)
      return mEndpoint.getAddress();

    else if(mType == Type.REMOTE)
      return mAddress;

    else
      return null;
  }

  public boolean equals(Target target){
    if(mType == target.getType()){
      if(mType == Type.NETWORK)
        return mNetwork.equals(target.getNetwork());

      else if(mType == Type.ENDPOINT)
        return mEndpoint.equals(target.getEndpoint());

      else if(mType == Type.REMOTE)
        return mHostname.equals(target.getHostname());
    }

    return false;
  }

  public boolean equals(Object o){
    return o instanceof Target && equals((Target) o);
  }

  public String getDisplayAddress(){
    if(mType == Type.NETWORK)
      return mNetwork.getNetworkRepresentation();

    else if(mType == Type.ENDPOINT)
      return mEndpoint.getAddress().getHostAddress() + (mPort == 0 ? "" : ":" + mPort);

    else if(mType == Type.REMOTE)
      return mHostname + (mPort == 0 ? "" : ":" + mPort);

    else
      return "???";
  }

  public String toString(){
    if(hasAlias())
      return mAlias;

    else
      return getDisplayAddress();
  }

  public String getDescription(){
    if(mType == Type.NETWORK)
      return System.getContext().getString(R.string.network_subnet_mask);

    else if(mType == Type.ENDPOINT){
      String vendor = System.getMacVendor(mEndpoint.getHardware()),
        desc = mEndpoint.getHardwareAsString();

      if(vendor != null) desc += " - " + vendor;

      if(mEndpoint.getAddress().equals(System.getNetwork().getGatewayAddress()))
        desc += "\n" + System.getContext().getString(R.string.gateway_router);

      else if(mEndpoint.getAddress().equals(System.getNetwork().getLocalAddress()))
        desc += System.getContext().getString(R.string.this_device);

      return desc.trim();
    } else if(mType == Type.REMOTE)
      return mAddress.getHostAddress();

    return "";
  }

  public String getCommandLineRepresentation(){
    if(mType == Type.NETWORK)
      return mNetwork.getNetworkRepresentation();

    else if(mType == Type.ENDPOINT)
      return mEndpoint.getAddress().getHostAddress();

    else if(mType == Type.REMOTE)
      return mHostname;

    else
      return "???";
  }

  public boolean isRouter(){
    try{
      return (mType == Type.ENDPOINT && mEndpoint.getAddress().equals(System.getNetwork().getGatewayAddress()));
    }
    catch(Exception e){
      LoggingHelper.e(TAG, "Failed to check if router", e);
    }

    return false;
  }

  public int getDrawableResourceId(){
    try{
      if(mType == Type.NETWORK)
        return R.drawable.target_network;

      else if(mType == Type.ENDPOINT)
        if(isRouter())
          return R.drawable.target_router;

        else if(mEndpoint.getAddress().equals(System.getNetwork().getLocalAddress()))
          return R.drawable.target_self;

        else
          return R.drawable.target_endpoint;

      else if(mType == Type.REMOTE)
        return R.drawable.target_remote;
    }
    catch(Exception e){
      LoggingHelper.e(TAG, "Failed to get drawable resource", e);
    }

    return R.drawable.target_network;
  }

  public void setNetwork(Network net){
    mNetwork = net;
    mType = Type.NETWORK;
  }

  public void setEndpoint(Endpoint endpoint){
    mEndpoint = endpoint;
    mType = Type.ENDPOINT;
  }

  public void setEndpoint(InetAddress address, byte[] hardware){
    mEndpoint = new Endpoint(address, hardware);
    mType = Type.ENDPOINT;
  }

  public void setHostname(String hostname, int port){
    mHostname = hostname;
    mPort = port;
    mType = Type.REMOTE;

    // Use async DNS resolution to avoid NetworkOnMainThreadException
    mAddress = resolveHostnameAsync(mHostname);
    if(mAddress == null){
      Logger.debug("Failed to resolve hostname: " + hostname);
    }
  }

  public void setConneced(boolean conneced) {
    mConnected = conneced;
  }

  public boolean isConnected() {
    return mConnected;
  }

  public void setSelected(boolean value) {
    mSelected = value;
  }

  public boolean isSelected() {
    return mSelected;
  }

  public Type getType(){
    return mType;
  }

  public Network getNetwork(){
    return mNetwork;
  }

  public Endpoint getEndpoint(){
    return mEndpoint;
  }

  public void setPort(int port){
    mPort = port;
  }

  public int getPort(){
    return mPort;
  }

  public String getHostname(){
    return mHostname;
  }

  /**
   * Get the hardware (MAC) address for this target.
   * Only applicable for ENDPOINT type targets.
   * @return The MAC address as byte array, or null if not available
   */
  @Nullable
  public byte[] getHardwareAddress(){
    if(mType == Type.ENDPOINT && mEndpoint != null){
      return mEndpoint.getHardware();
    }
    return null;
  }

  public void addOpenPort(Port port){
    boolean notifyList = false;
    synchronized (mPorts) {
      Port existing = null;
      for(Port p : mPorts) {
        if(p.equals(port)) {
          existing = p;
          break;
        }
      }

      if(existing != null) {
        port.mergeTo(existing);
      } else {
        mPorts.add(port);
        notifyList = true;
      }
    }
    if(notifyList)
      System.notifyTargetListChanged(this);
  }

  public void addOpenPort(int port, Protocol protocol){
    addOpenPort(new Port(port, protocol));
  }

  public void addOpenPort(int port, Protocol protocol, String service){
    addOpenPort(new Port(port, protocol, service));
  }

  public List<Port> getOpenPorts(){
    synchronized (mPorts) {
      return (List<Port>) mPorts.clone();
    }
  }

  public boolean hasOpenPorts(){
    synchronized (mPorts) {
      return !mPorts.isEmpty();
    }
  }

  public boolean hasOpenPortsWithService(){
    synchronized (mPorts) {
      if (!mPorts.isEmpty()) {
        for (Port p : mPorts) {
          if (p.service != null && !p.service.isEmpty())
            return true;
        }
      }
    }

    return false;
  }

  public boolean hasOpenPort(int port){
    synchronized (mPorts) {
      for (Port p : mPorts) {
        if (p.number == port)
          return true;
      }
    }

    return false;
  }

  public void setDeviceType(String type){
    mDeviceType = type;
  }

  public String getDeviceType(){
    return mDeviceType;
  }

  public void setDeviceOS(String os){
    mDeviceOS = os;
  }

  public String getDeviceOS(){
    return mDeviceOS;
  }

  public void addExploit(Exploit exploit) {

    exploit.setParent(this);

    synchronized (exploits) {
      Iterator<Exploit> it = exploits.iterator();

      while(it.hasNext()) {
        if(exploit.equals(it.next())) {
          it.remove();
          break;
        }
      }

      exploits.add(exploit);
    }
  }

  public Collection<Exploit> getExploits() {
    return exploits;
  }

  public boolean hasExploits() {
    return exploits.size()>0;
  }

  public boolean hasMsfExploits() {

    synchronized (exploits) {
      for(Exploit e : exploits) {
        if(e instanceof MsfExploit)
          return true;
      }
    }

    return false;
  }

  public ArrayList<Session> getSessions() {
    return mSessions;
  }

  public void addSession(Session s) {
    if(!mSessions.contains(s))
      mSessions.add(s);
  }
}
