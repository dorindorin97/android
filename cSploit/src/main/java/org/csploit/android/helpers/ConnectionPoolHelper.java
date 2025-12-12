/*
 * This file is part of cSploit.
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
package org.csploit.android.helpers;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.util.concurrent.BlockingQueue;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.LinkedBlockingQueue;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * Helper class for managing connection pools.
 * Provides efficient reuse of socket connections to reduce overhead.
 */
public final class ConnectionPoolHelper {

    private static final String TAG = "ConnectionPoolHelper";

    // Default pool settings
    private static final int DEFAULT_MAX_CONNECTIONS_PER_HOST = 5;
    private static final int DEFAULT_MAX_TOTAL_CONNECTIONS = 50;
    private static final long DEFAULT_CONNECTION_TIMEOUT_MS = 30000;
    private static final long DEFAULT_IDLE_TIMEOUT_MS = 60000;
    private static final long DEFAULT_ACQUIRE_TIMEOUT_MS = 5000;

    // Pool state
    private static final ConcurrentHashMap<String, HostPool> hostPools = new ConcurrentHashMap<>();
    private static final AtomicInteger totalConnections = new AtomicInteger(0);
    private static final AtomicBoolean isShutdown = new AtomicBoolean(false);

    // Configuration
    private static volatile int maxConnectionsPerHost = DEFAULT_MAX_CONNECTIONS_PER_HOST;
    private static volatile int maxTotalConnections = DEFAULT_MAX_TOTAL_CONNECTIONS;
    private static volatile long connectionTimeoutMs = DEFAULT_CONNECTION_TIMEOUT_MS;
    private static volatile long idleTimeoutMs = DEFAULT_IDLE_TIMEOUT_MS;
    private static volatile long acquireTimeoutMs = DEFAULT_ACQUIRE_TIMEOUT_MS;

    /**
     * Wrapper for pooled connections.
     */
    public static class PooledConnection implements AutoCloseable {
        private final Socket socket;
        private final String hostKey;
        private final long createdAt;
        private long lastUsedAt;
        private final AtomicBoolean released = new AtomicBoolean(false);

        private PooledConnection(Socket socket, String hostKey) {
            this.socket = socket;
            this.hostKey = hostKey;
            this.createdAt = System.currentTimeMillis();
            this.lastUsedAt = createdAt;
        }

        @NonNull
        public Socket getSocket() {
            lastUsedAt = System.currentTimeMillis();
            return socket;
        }

        public boolean isValid() {
            return socket != null &&
                   socket.isConnected() &&
                   !socket.isClosed() &&
                   (System.currentTimeMillis() - lastUsedAt) < idleTimeoutMs;
        }

        public long getAge() {
            return System.currentTimeMillis() - createdAt;
        }

        public long getIdleTime() {
            return System.currentTimeMillis() - lastUsedAt;
        }

        /**
         * Release the connection back to the pool.
         * If the connection is invalid, it will be closed instead.
         */
        public void release() {
            if (released.compareAndSet(false, true)) {
                releaseConnection(this);
            }
        }

        /**
         * Close the connection without returning to pool.
         */
        @Override
        public void close() {
            if (released.compareAndSet(false, true)) {
                closeConnection(this);
            }
        }
    }

    /**
     * Pool for a specific host.
     */
    private static class HostPool {
        private final String hostKey;
        private final BlockingQueue<PooledConnection> idleConnections;
        private final AtomicInteger activeCount = new AtomicInteger(0);
        private final AtomicInteger totalCount = new AtomicInteger(0);

        HostPool(String hostKey) {
            this.hostKey = hostKey;
            this.idleConnections = new LinkedBlockingQueue<>(maxConnectionsPerHost);
        }

        @Nullable
        PooledConnection acquire(long timeoutMs) throws InterruptedException {
            // Try to get an idle connection
            PooledConnection conn = idleConnections.poll();
            while (conn != null) {
                if (conn.isValid()) {
                    activeCount.incrementAndGet();
                    return conn;
                }
                // Invalid connection, close it
                closeSocket(conn.socket);
                totalCount.decrementAndGet();
                totalConnections.decrementAndGet();
                conn = idleConnections.poll();
            }

            // No idle connections available, try to create new one
            if (totalCount.get() < maxConnectionsPerHost &&
                totalConnections.get() < maxTotalConnections) {
                return null; // Signal to create new connection
            }

            // Wait for a connection to be released
            conn = idleConnections.poll(timeoutMs, TimeUnit.MILLISECONDS);
            if (conn != null && conn.isValid()) {
                activeCount.incrementAndGet();
                return conn;
            }

            if (conn != null) {
                closeSocket(conn.socket);
                totalCount.decrementAndGet();
                totalConnections.decrementAndGet();
            }

            return null;
        }

        void release(PooledConnection conn) {
            activeCount.decrementAndGet();
            if (conn.isValid() && !isShutdown.get()) {
                if (!idleConnections.offer(conn)) {
                    // Pool full, close the connection
                    closeSocket(conn.socket);
                    totalCount.decrementAndGet();
                    totalConnections.decrementAndGet();
                }
            } else {
                closeSocket(conn.socket);
                totalCount.decrementAndGet();
                totalConnections.decrementAndGet();
            }
        }

        void add(PooledConnection conn) {
            totalCount.incrementAndGet();
            activeCount.incrementAndGet();
            totalConnections.incrementAndGet();
        }

        void closeAll() {
            PooledConnection conn;
            while ((conn = idleConnections.poll()) != null) {
                closeSocket(conn.socket);
            }
            totalCount.set(0);
            activeCount.set(0);
        }

        int getIdleCount() {
            return idleConnections.size();
        }

        int getActiveCount() {
            return activeCount.get();
        }

        int getTotalCount() {
            return totalCount.get();
        }
    }

    private ConnectionPoolHelper() {
        // Prevent instantiation
    }

    /**
     * Acquire a connection to the specified host.
     *
     * @param host Host address
     * @param port Port number
     * @return Pooled connection or null if couldn't acquire
     */
    @Nullable
    public static PooledConnection acquire(@NonNull String host, int port) {
        return acquire(host, port, acquireTimeoutMs);
    }

    /**
     * Acquire a connection to the specified host with custom timeout.
     *
     * @param host Host address
     * @param port Port number
     * @param timeoutMs Timeout in milliseconds
     * @return Pooled connection or null if couldn't acquire
     */
    @Nullable
    public static PooledConnection acquire(@NonNull String host, int port, long timeoutMs) {
        if (isShutdown.get()) {
            return null;
        }

        String hostKey = host + ":" + port;
        HostPool pool = hostPools.computeIfAbsent(hostKey, HostPool::new);

        try {
            PooledConnection conn = pool.acquire(timeoutMs);
            if (conn != null) {
                return conn;
            }

            // Need to create new connection
            Socket socket = createConnection(host, port);
            if (socket != null) {
                conn = new PooledConnection(socket, hostKey);
                pool.add(conn);
                return conn;
            }
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            LoggingHelper.debug("Connection acquire interrupted for " + hostKey);
        }

        return null;
    }

    /**
     * Create a new socket connection.
     */
    @Nullable
    private static Socket createConnection(String host, int port) {
        try {
            Socket socket = new Socket();
            socket.connect(new InetSocketAddress(host, port), (int) connectionTimeoutMs);
            socket.setSoTimeout((int) connectionTimeoutMs);
            return socket;
        } catch (IOException e) {
            LoggingHelper.debug("Failed to create connection to " + host + ":" + port + ": " + e.getMessage());
            return null;
        }
    }

    /**
     * Release a connection back to the pool.
     */
    private static void releaseConnection(PooledConnection conn) {
        HostPool pool = hostPools.get(conn.hostKey);
        if (pool != null) {
            pool.release(conn);
        } else {
            closeSocket(conn.socket);
        }
    }

    /**
     * Close a connection without returning to pool.
     */
    private static void closeConnection(PooledConnection conn) {
        closeSocket(conn.socket);
        HostPool pool = hostPools.get(conn.hostKey);
        if (pool != null) {
            pool.totalCount.decrementAndGet();
            pool.activeCount.decrementAndGet();
            totalConnections.decrementAndGet();
        }
    }

    /**
     * Close a socket safely.
     */
    private static void closeSocket(Socket socket) {
        if (socket != null) {
            try {
                socket.close();
            } catch (IOException e) {
                // Ignore close errors
            }
        }
    }

    /**
     * Close all connections for a specific host.
     *
     * @param host Host address
     * @param port Port number
     */
    public static void closeHost(@NonNull String host, int port) {
        String hostKey = host + ":" + port;
        HostPool pool = hostPools.remove(hostKey);
        if (pool != null) {
            int closed = pool.getTotalCount();
            pool.closeAll();
            totalConnections.addAndGet(-closed);
        }
    }

    /**
     * Close all pooled connections.
     */
    public static void closeAll() {
        for (HostPool pool : hostPools.values()) {
            int closed = pool.getTotalCount();
            pool.closeAll();
            totalConnections.addAndGet(-closed);
        }
        hostPools.clear();
    }

    /**
     * Shutdown the connection pool.
     * No new connections will be created after this.
     */
    public static void shutdown() {
        isShutdown.set(true);
        closeAll();
    }

    /**
     * Reset the pool (allows new connections after shutdown).
     */
    public static void reset() {
        closeAll();
        isShutdown.set(false);
    }

    /**
     * Evict idle connections that have exceeded the idle timeout.
     */
    public static void evictIdleConnections() {
        for (HostPool pool : hostPools.values()) {
            PooledConnection conn;
            while ((conn = pool.idleConnections.peek()) != null && !conn.isValid()) {
                conn = pool.idleConnections.poll();
                if (conn != null) {
                    closeSocket(conn.socket);
                    pool.totalCount.decrementAndGet();
                    totalConnections.decrementAndGet();
                }
            }
        }
    }

    // Configuration methods

    /**
     * Set maximum connections per host.
     */
    public static void setMaxConnectionsPerHost(int max) {
        maxConnectionsPerHost = Math.max(1, max);
    }

    /**
     * Set maximum total connections across all hosts.
     */
    public static void setMaxTotalConnections(int max) {
        maxTotalConnections = Math.max(1, max);
    }

    /**
     * Set connection timeout in milliseconds.
     */
    public static void setConnectionTimeout(long timeoutMs) {
        connectionTimeoutMs = Math.max(1000, timeoutMs);
    }

    /**
     * Set idle timeout in milliseconds.
     */
    public static void setIdleTimeout(long timeoutMs) {
        idleTimeoutMs = Math.max(1000, timeoutMs);
    }

    /**
     * Set acquire timeout in milliseconds.
     */
    public static void setAcquireTimeout(long timeoutMs) {
        acquireTimeoutMs = Math.max(100, timeoutMs);
    }

    // Statistics methods

    /**
     * Get total number of connections across all hosts.
     */
    public static int getTotalConnectionCount() {
        return totalConnections.get();
    }

    /**
     * Get idle connection count for a specific host.
     */
    public static int getIdleConnectionCount(@NonNull String host, int port) {
        HostPool pool = hostPools.get(host + ":" + port);
        return pool != null ? pool.getIdleCount() : 0;
    }

    /**
     * Get active connection count for a specific host.
     */
    public static int getActiveConnectionCount(@NonNull String host, int port) {
        HostPool pool = hostPools.get(host + ":" + port);
        return pool != null ? pool.getActiveCount() : 0;
    }

    /**
     * Get number of hosts in the pool.
     */
    public static int getHostCount() {
        return hostPools.size();
    }

    /**
     * Get pool statistics as a formatted string.
     */
    @NonNull
    public static String getPoolStats() {
        StringBuilder sb = new StringBuilder();
        sb.append("Connection Pool Statistics\n");
        sb.append("=========================\n");
        sb.append("Total Connections: ").append(totalConnections.get()).append("\n");
        sb.append("Hosts: ").append(hostPools.size()).append("\n\n");

        for (ConcurrentHashMap.Entry<String, HostPool> entry : hostPools.entrySet()) {
            HostPool pool = entry.getValue();
            sb.append(entry.getKey())
              .append(": active=").append(pool.getActiveCount())
              .append(", idle=").append(pool.getIdleCount())
              .append(", total=").append(pool.getTotalCount())
              .append("\n");
        }

        return sb.toString();
    }
}
