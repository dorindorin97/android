package org.csploit.android.helpers;

import android.content.Context;
import org.csploit.android.helpers.LoggingHelper;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.io.IOException;
import java.io.InputStream;
import java.net.HttpURLConnection;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * HTTP utility helper for making HTTP requests with retry logic, timeout handling, and response caching.
 * 
 * Features:
 * - Unified HTTP client with automatic retry logic
 * - Automatic timeout handling
 * - Request/response interceptors
 * - Connectivity status checking
 * - Response caching for GET requests
 * - Built-in error handling and logging
 * 
 * Example:
 * <pre>
 * HttpHelper.RequestConfig config = new HttpHelper.RequestConfig()
 *     .setUrl("https://api.example.com/data")
 *     .setMethod("GET")
 *     .addHeader("Authorization", "Bearer token")
 *     .setMaxRetries(3)
 *     .setConnectTimeout(10000);
 * 
 * try {
 *     HttpHelper.HttpResponse response = HttpHelper.executeRequest(config);
 *     if (response.isSuccessful()) {
 *         String data = response.getBodyAsString();
 *     }
 * } catch (IOException e) {
 *     LoggingHelper.e("HttpHelper", "Request failed", e);
 * }
 * </pre>
 */
public final class HttpHelper {
    private static final String TAG = "HttpHelper";
    
    // Default timeout values (in milliseconds)
    private static final int DEFAULT_CONNECT_TIMEOUT = 10000;  // 10 seconds
    private static final int DEFAULT_READ_TIMEOUT = 15000;     // 15 seconds
    
    // Retry configuration
    private static final int DEFAULT_MAX_RETRIES = 3;
    private static final long DEFAULT_RETRY_DELAY = 1000;      // 1 second
    
    // Response cache for GET requests
    private static final Map<String, CachedResponse> RESPONSE_CACHE = 
            Collections.synchronizedMap(new HashMap<>());
    
    private static final long CACHE_DURATION = 5 * 60 * 1000;  // 5 minutes
    
    /**
     * HTTP request configuration builder
     */
    public static class RequestConfig {
        private String url;
        private String method = "GET";
        private Map<String, String> headers = new HashMap<>();
        private byte[] body;
        private int connectTimeout = DEFAULT_CONNECT_TIMEOUT;
        private int readTimeout = DEFAULT_READ_TIMEOUT;
        private int maxRetries = DEFAULT_MAX_RETRIES;
        private long retryDelay = DEFAULT_RETRY_DELAY;
        private boolean useCache = true;
        private HttpResponseCallback callback;
        
        public RequestConfig setUrl(@NonNull String url) {
            this.url = url;
            return this;
        }
        
        public RequestConfig setMethod(@NonNull String method) {
            this.method = method.toUpperCase();
            return this;
        }
        
        public RequestConfig addHeader(@NonNull String key, @NonNull String value) {
            this.headers.put(key, value);
            return this;
        }
        
        public RequestConfig setHeaders(@NonNull Map<String, String> headers) {
            this.headers = new HashMap<>(headers);
            return this;
        }
        
        public RequestConfig setBody(@Nullable byte[] body) {
            this.body = body;
            return this;
        }
        
        public RequestConfig setConnectTimeout(int timeoutMs) {
            this.connectTimeout = timeoutMs;
            return this;
        }
        
        public RequestConfig setReadTimeout(int timeoutMs) {
            this.readTimeout = timeoutMs;
            return this;
        }
        
        public RequestConfig setMaxRetries(int maxRetries) {
            this.maxRetries = Math.max(1, maxRetries);
            return this;
        }
        
        public RequestConfig setRetryDelay(long delayMs) {
            this.retryDelay = delayMs;
            return this;
        }
        
        public RequestConfig useCache(boolean useCache) {
            this.useCache = useCache;
            return this;
        }
        
        public RequestConfig setCallback(@NonNull HttpResponseCallback callback) {
            this.callback = callback;
            return this;
        }
    }
    
    /**
     * HTTP response object
     */
    public static class HttpResponse {
        private final int statusCode;
        private final byte[] body;
        private final Map<String, String> headers;
        
        public HttpResponse(int statusCode, byte[] body, Map<String, String> headers) {
            this.statusCode = statusCode;
            this.body = body;
            this.headers = new HashMap<>(headers);
        }
        
        public int getStatusCode() {
            return statusCode;
        }
        
        public byte[] getBody() {
            return body;
        }
        
        public String getBodyAsString() {
            return body != null ? new String(body) : "";
        }
        
        public Map<String, String> getHeaders() {
            return new HashMap<>(headers);
        }
        
        public String getHeader(String key) {
            return headers.get(key);
        }
        
        public boolean isSuccessful() {
            return statusCode >= 200 && statusCode < 300;
        }
    }
    
    /**
     * Callback interface for async HTTP responses
     */
    public interface HttpResponseCallback {
        void onResponse(@NonNull HttpResponse response);
        void onError(@NonNull Exception error);
        void onRetry(int attempt, int maxRetries);
    }
    
    /**
     * Cached response with timestamp
     */
    private static class CachedResponse {
        private final HttpResponse response;
        private final long timestamp;
        
        CachedResponse(HttpResponse response) {
            this.response = response;
            this.timestamp = System.currentTimeMillis();
        }
        
        boolean isExpired() {
            return System.currentTimeMillis() - timestamp > CACHE_DURATION;
        }
    }
    
    /**
     * Make a synchronous HTTP request with retry logic
     * 
     * @param config request configuration
     * @return HTTP response
     * @throws IOException if request fails after all retries
     */
    public static HttpResponse executeRequest(@NonNull RequestConfig config) throws IOException {
        if (config.url == null || config.url.isEmpty()) {
            throw new IllegalArgumentException("URL cannot be null or empty");
        }
        
        IOException lastError = null;
        
        for (int attempt = 0; attempt < config.maxRetries; attempt++) {
            try {
                // Check cache for GET requests
                if ("GET".equals(config.method) && config.useCache) {
                    CachedResponse cached = RESPONSE_CACHE.get(config.url);
                    if (cached != null && !cached.isExpired()) {
                        LoggingHelper.d(TAG, "Returning cached response for: " + config.url);
                        return cached.response;
                    }
                }
                
                HttpResponse response = performRequest(config);
                
                // Cache successful GET responses
                if ("GET".equals(config.method) && response.isSuccessful() && config.useCache) {
                    RESPONSE_CACHE.put(config.url, new CachedResponse(response));
                }
                
                return response;
                
            } catch (SocketTimeoutException e) {
                lastError = e;
                LoggingHelper.w(TAG, "Timeout on attempt " + (attempt + 1) + "/" + config.maxRetries);
                
                if (attempt < config.maxRetries - 1) {
                    try {
                        Thread.sleep(config.retryDelay);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        throw new IOException("Request interrupted", ie);
                    }
                }
            } catch (IOException e) {
                lastError = e;
                LoggingHelper.w(TAG, "IO error on attempt " + (attempt + 1) + "/" + config.maxRetries);
                
                if (attempt < config.maxRetries - 1) {
                    try {
                        Thread.sleep(config.retryDelay);
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        throw new IOException("Request interrupted", ie);
                    }
                }
            }
        }
        
        if (lastError != null) {
            throw lastError;
        }
        
        throw new IOException("Request failed after " + config.maxRetries + " attempts");
    }
    
    /**
     * Make an asynchronous HTTP request with callback
     * 
     * @param config request configuration with callback
     */
    public static void executeRequestAsync(@NonNull RequestConfig config) {
        if (config.callback == null) {
            LoggingHelper.w(TAG, "Callback is null for async request");
            return;
        }
        
        ConcurrencyHelper.executeIOAsync(() -> {
            IOException lastError = null;
            
            for (int attempt = 0; attempt < config.maxRetries; attempt++) {
                try {
                    // Check cache for GET requests
                    if ("GET".equals(config.method) && config.useCache) {
                        CachedResponse cached = RESPONSE_CACHE.get(config.url);
                        if (cached != null && !cached.isExpired()) {
                            LoggingHelper.d(TAG, "Returning cached response for: " + config.url);
                            return cached.response;
                        }
                    }
                    
                    HttpResponse response = performRequest(config);
                    
                    // Cache successful GET responses
                    if ("GET".equals(config.method) && response.isSuccessful() && config.useCache) {
                        RESPONSE_CACHE.put(config.url, new CachedResponse(response));
                    }
                    
                    return response;
                    
                } catch (SocketTimeoutException e) {
                    lastError = e;
                    
                    if (attempt < config.maxRetries - 1) {
                        config.callback.onRetry(attempt + 1, config.maxRetries);
                        try {
                            Thread.sleep(config.retryDelay);
                        } catch (InterruptedException ie) {
                            Thread.currentThread().interrupt();
                            throw ie;
                        }
                    }
                } catch (IOException e) {
                    lastError = e;
                    
                    if (attempt < config.maxRetries - 1) {
                        config.callback.onRetry(attempt + 1, config.maxRetries);
                        try {
                            Thread.sleep(config.retryDelay);
                        } catch (InterruptedException ie) {
                            Thread.currentThread().interrupt();
                            throw ie;
                        }
                    }
                }
            }
            
            if (lastError != null) {
                throw lastError;
            }
            
            throw new IOException("Request failed after " + config.maxRetries + " attempts");
            
        }, new ConcurrencyHelper.AsyncCallback<HttpResponse>() {
            @Override
            public void onSuccess(HttpResponse result) {
                config.callback.onResponse(result);
            }
            
            @Override
            public void onError(Exception error) {
                config.callback.onError(error);
            }
            
            @Override
            public void onCancelled() {
                config.callback.onError(new IOException("Request cancelled"));
            }
        });
    }
    
    /**
     * Perform the actual HTTP request
     */
    private static HttpResponse performRequest(RequestConfig config) throws IOException {
        HttpURLConnection connection = null;
        
        try {
            URL url = new URL(config.url);
            connection = (HttpURLConnection) url.openConnection();
            
            // Set timeouts
            connection.setConnectTimeout(config.connectTimeout);
            connection.setReadTimeout(config.readTimeout);
            
            // Set method and headers
            connection.setRequestMethod(config.method);
            connection.setRequestProperty("User-Agent", "cSploit/1.7.1");
            
            for (Map.Entry<String, String> header : config.headers.entrySet()) {
                connection.setRequestProperty(header.getKey(), header.getValue());
            }
            
            // Set request body for POST/PUT/PATCH
            if (config.body != null) {
                connection.setDoOutput(true);
                OutputStream os = connection.getOutputStream();
                try {
                    os.write(config.body);
                    os.flush();
                } finally {
                    os.close();
                }
            }
            
            // Get response
            int statusCode = connection.getResponseCode();
            byte[] responseBody = readResponse(connection, statusCode);
            Map<String, String> responseHeaders = getResponseHeaders(connection);
            
            return new HttpResponse(statusCode, responseBody, responseHeaders);
            
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }
    
    /**
     * Read response body from connection
     */
    private static byte[] readResponse(HttpURLConnection connection, int statusCode) throws IOException {
        InputStream stream = null;
        
        try {
            stream = statusCode >= 400 ? 
                    connection.getErrorStream() : 
                    connection.getInputStream();
            
            if (stream == null) {
                return new byte[0];
            }
            
            byte[] buffer = new byte[8192];
            List<byte[]> chunks = new ArrayList<>();
            int bytesRead;
            
            while ((bytesRead = stream.read(buffer)) != -1) {
                byte[] chunk = new byte[bytesRead];
                System.arraycopy(buffer, 0, chunk, 0, bytesRead);
                chunks.add(chunk);
            }
            
            int totalSize = 0;
            for (byte[] chunk : chunks) {
                totalSize += chunk.length;
            }
            
            byte[] result = new byte[totalSize];
            int offset = 0;
            for (byte[] chunk : chunks) {
                System.arraycopy(chunk, 0, result, offset, chunk.length);
                offset += chunk.length;
            }
            
            return result;
            
        } finally {
            if (stream != null) {
                try {
                    stream.close();
                } catch (IOException e) {
                    LoggingHelper.w(TAG, "Error closing response stream", e);
                }
            }
        }
    }
    
    /**
     * Extract response headers
     */
    private static Map<String, String> getResponseHeaders(HttpURLConnection connection) {
        Map<String, String> headers = new HashMap<>();
        
        for (Map.Entry<String, java.util.List<String>> entry : connection.getHeaderFields().entrySet()) {
            String key = entry.getKey();
            List<String> values = entry.getValue();
            
            if (key != null && !values.isEmpty()) {
                headers.put(key, values.get(0));
            }
        }
        
        return headers;
    }
    
    /**
     * Check network connectivity
     * 
     * @param context Android context
     * @return true if device has active network connection
     */
    public static boolean isNetworkConnected(@NonNull Context context) {
        ConnectivityManager cm = (ConnectivityManager) 
                context.getSystemService(Context.CONNECTIVITY_SERVICE);
        
        if (cm == null) {
            return false;
        }
        
        Network activeNetwork = cm.getActiveNetwork();
        if (activeNetwork == null) {
            return false;
        }
        
        NetworkCapabilities caps = cm.getNetworkCapabilities(activeNetwork);
        return caps != null && 
               (caps.hasTransport(NetworkCapabilities.TRANSPORT_WIFI) ||
                caps.hasTransport(NetworkCapabilities.TRANSPORT_CELLULAR) ||
                caps.hasTransport(NetworkCapabilities.TRANSPORT_ETHERNET));
    }
    
    /**
     * Check if network is metered (cellular/limited)
     * 
     * @param context Android context
     * @return true if connection is metered
     */
    public static boolean isMeteredConnection(@NonNull Context context) {
        ConnectivityManager cm = (ConnectivityManager) 
                context.getSystemService(Context.CONNECTIVITY_SERVICE);
        
        return cm != null && cm.isActiveNetworkMetered();
    }
    
    /**
     * Clear response cache
     */
    public static void clearCache() {
        RESPONSE_CACHE.clear();
        LoggingHelper.d(TAG, "Response cache cleared");
    }
    
    /**
     * Clear expired cache entries
     */
    public static void cleanExpiredCache() {
        List<String> expiredKeys = new ArrayList<>();
        
        for (Map.Entry<String, CachedResponse> entry : RESPONSE_CACHE.entrySet()) {
            if (entry.getValue().isExpired()) {
                expiredKeys.add(entry.getKey());
            }
        }
        
        for (String key : expiredKeys) {
            RESPONSE_CACHE.remove(key);
        }
        
        LoggingHelper.d(TAG, "Cleaned " + expiredKeys.size() + " expired cache entries");
    }
    
    /**
     * Get cache statistics
     * 
     * @return cache size
     */
    public static int getCacheSize() {
        return RESPONSE_CACHE.size();
    }
}
