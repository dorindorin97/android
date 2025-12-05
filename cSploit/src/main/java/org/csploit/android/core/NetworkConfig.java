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

/**
 * Encapsulates network configuration settings for the application.
 * Provides centralized management of network-related ports and paths.
 */
public class NetworkConfig {
    public static final int HTTP_PROXY_PORT = 8080;
    public static final int HTTP_SERVER_PORT = 8081;
    public static final int HTTPS_REDIR_PORT = 8082;
    public static final int MSF_RPC_PORT = 55553;

    public static final String IPV4_FORWARD_FILEPATH = "/proc/sys/net/ipv4/ip_forward";

    private int mHttpProxyPort = HTTP_PROXY_PORT;
    private int mHttpServerPort = HTTP_SERVER_PORT;
    private int mHttpsRedirPort = HTTPS_REDIR_PORT;
    private int mMsfRpcPort = MSF_RPC_PORT;

    /**
     * Creates a NetworkConfig with default settings
     */
    public NetworkConfig() {
    }

    /**
     * Creates a NetworkConfig with custom port settings
     *
     * @param proxyPort HTTP proxy port
     * @param serverPort HTTP server port
     * @param redirectPort HTTPS redirect port
     * @param rpcPort Metasploit RPC port
     */
    public NetworkConfig(int proxyPort, int serverPort, int redirectPort, int rpcPort) {
        this.mHttpProxyPort = proxyPort;
        this.mHttpServerPort = serverPort;
        this.mHttpsRedirPort = redirectPort;
        this.mMsfRpcPort = rpcPort;
    }

    /**
     * Get HTTP proxy port
     */
    public int getHttpProxyPort() {
        return mHttpProxyPort;
    }

    /**
     * Set HTTP proxy port
     */
    public void setHttpProxyPort(int port) {
        this.mHttpProxyPort = port;
    }

    /**
     * Get HTTP server port
     */
    public int getHttpServerPort() {
        return mHttpServerPort;
    }

    /**
     * Set HTTP server port
     */
    public void setHttpServerPort(int port) {
        this.mHttpServerPort = port;
    }

    /**
     * Get HTTPS redirect port
     */
    public int getHttpsRedirPort() {
        return mHttpsRedirPort;
    }

    /**
     * Set HTTPS redirect port
     */
    public void setHttpsRedirPort(int port) {
        this.mHttpsRedirPort = port;
    }

    /**
     * Get Metasploit RPC port
     */
    public int getMsfRpcPort() {
        return mMsfRpcPort;
    }

    /**
     * Set Metasploit RPC port
     */
    public void setMsfRpcPort(int port) {
        this.mMsfRpcPort = port;
    }

    /**
     * Reset all ports to default values
     */
    public void resetToDefaults() {
        this.mHttpProxyPort = HTTP_PROXY_PORT;
        this.mHttpServerPort = HTTP_SERVER_PORT;
        this.mHttpsRedirPort = HTTPS_REDIR_PORT;
        this.mMsfRpcPort = MSF_RPC_PORT;
    }
}
