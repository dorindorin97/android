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
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with cSploit. If not, see <http://www.gnu.org/licenses/>.
 */

package org.csploit.android.helpers;

import android.util.Base64;
import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

/**
 * CredentialTestHelper - Test credentials against various services.
 *
 * This helper is intended for authorized security testing only.
 * Always ensure proper authorization before testing credentials.
 *
 * Provides:
 * - FTP credential testing
 * - SSH banner detection
 * - HTTP Basic Auth testing
 * - Telnet credential testing
 * - SMTP AUTH testing
 *
 * Usage:
 * {@code
 * // Test FTP credentials
 * boolean valid = CredentialTestHelper.testFtpCredentials("192.168.1.1", 21, "admin", "password");
 *
 * // Test HTTP Basic Auth
 * boolean valid = CredentialTestHelper.testHttpBasicAuth("http://example.com/admin", "admin", "password");
 * }
 */
public final class CredentialTestHelper {

    private static final String TAG = "CredentialTestHelper";
    private static final int DEFAULT_TIMEOUT = 5000;

    /**
     * Credential test result.
     */
    public static class TestResult {
        public boolean success;
        public String message;
        public String protocol;
        public long responseTimeMs;
        public String serverBanner;

        @NonNull
        @Override
        public String toString() {
            return String.format("TestResult{success=%b, protocol='%s', message='%s'}",
                    success, protocol, message);
        }
    }

    /**
     * Common default credentials for various services.
     */
    public static class DefaultCredential {
        public String username;
        public String password;
        public String service;

        public DefaultCredential(String username, String password, String service) {
            this.username = username;
            this.password = password;
            this.service = service;
        }
    }

    private CredentialTestHelper() {}

    /**
     * Test FTP credentials.
     */
    @NonNull
    public static TestResult testFtpCredentials(@NonNull String host, int port,
                                                 @NonNull String username,
                                                 @NonNull String password) {
        TestResult result = new TestResult();
        result.protocol = "FTP";
        long startTime = System.currentTimeMillis();

        Socket socket = null;
        BufferedReader reader = null;
        OutputStream writer = null;

        try {
            socket = new Socket();
            socket.connect(new InetSocketAddress(host, port), DEFAULT_TIMEOUT);
            socket.setSoTimeout(DEFAULT_TIMEOUT);

            reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            writer = socket.getOutputStream();

            // Read banner
            String banner = reader.readLine();
            result.serverBanner = banner;

            if (banner == null || !banner.startsWith("220")) {
                result.success = false;
                result.message = "Invalid FTP server response";
                return result;
            }

            // Send USER
            writer.write(("USER " + username + "\r\n").getBytes());
            writer.flush();

            String userResponse = reader.readLine();
            if (userResponse == null) {
                result.success = false;
                result.message = "No response to USER command";
                return result;
            }

            if (userResponse.startsWith("230")) {
                // Logged in without password
                result.success = true;
                result.message = "Login successful (no password required)";
                return result;
            }

            if (!userResponse.startsWith("331")) {
                result.success = false;
                result.message = "Username rejected: " + userResponse;
                return result;
            }

            // Send PASS
            writer.write(("PASS " + password + "\r\n").getBytes());
            writer.flush();

            String passResponse = reader.readLine();
            if (passResponse != null && passResponse.startsWith("230")) {
                result.success = true;
                result.message = "Login successful";
            } else {
                result.success = false;
                result.message = "Login failed: " + passResponse;
            }

            // Send QUIT
            writer.write("QUIT\r\n".getBytes());
            writer.flush();

        } catch (IOException e) {
            result.success = false;
            result.message = "Connection error: " + e.getMessage();
        } finally {
            result.responseTimeMs = System.currentTimeMillis() - startTime;
            closeQuietly(reader);
            closeQuietly(writer);
            closeQuietly(socket);
        }

        return result;
    }

    /**
     * Test HTTP Basic Authentication.
     */
    @NonNull
    public static TestResult testHttpBasicAuth(@NonNull String urlString,
                                                @NonNull String username,
                                                @NonNull String password) {
        TestResult result = new TestResult();
        result.protocol = "HTTP Basic Auth";
        long startTime = System.currentTimeMillis();

        HttpURLConnection conn = null;

        try {
            URL url = new URL(urlString);
            conn = (HttpURLConnection) url.openConnection();
            conn.setConnectTimeout(DEFAULT_TIMEOUT);
            conn.setReadTimeout(DEFAULT_TIMEOUT);
            conn.setRequestMethod("GET");

            // Add Basic Auth header
            String credentials = username + ":" + password;
            String encoded = Base64.encodeToString(credentials.getBytes(), Base64.NO_WRAP);
            conn.setRequestProperty("Authorization", "Basic " + encoded);

            int responseCode = conn.getResponseCode();
            result.serverBanner = conn.getHeaderField("Server");

            if (responseCode == 200 || responseCode == 302) {
                result.success = true;
                result.message = "Authentication successful";
            } else if (responseCode == 401) {
                result.success = false;
                result.message = "Authentication failed (401 Unauthorized)";
            } else if (responseCode == 403) {
                result.success = false;
                result.message = "Access forbidden (403)";
            } else {
                result.success = false;
                result.message = "HTTP " + responseCode;
            }

        } catch (Exception e) {
            result.success = false;
            result.message = "Connection error: " + e.getMessage();
        } finally {
            result.responseTimeMs = System.currentTimeMillis() - startTime;
            if (conn != null) {
                conn.disconnect();
            }
        }

        return result;
    }

    /**
     * Test Telnet credentials.
     */
    @NonNull
    public static TestResult testTelnetCredentials(@NonNull String host, int port,
                                                    @NonNull String username,
                                                    @NonNull String password) {
        TestResult result = new TestResult();
        result.protocol = "Telnet";
        long startTime = System.currentTimeMillis();

        Socket socket = null;

        try {
            socket = new Socket();
            socket.connect(new InetSocketAddress(host, port), DEFAULT_TIMEOUT);
            socket.setSoTimeout(DEFAULT_TIMEOUT);

            java.io.InputStream in = socket.getInputStream();
            OutputStream out = socket.getOutputStream();

            // Wait for login prompt
            StringBuilder buffer = new StringBuilder();
            long timeout = System.currentTimeMillis() + 5000;

            while (System.currentTimeMillis() < timeout) {
                if (in.available() > 0) {
                    int b = in.read();
                    if (b == -1) break;
                    buffer.append((char) b);

                    String current = buffer.toString().toLowerCase();
                    if (current.contains("login:") || current.contains("username:")) {
                        break;
                    }
                }
                Thread.sleep(50);
            }

            result.serverBanner = buffer.toString().trim();

            // Send username
            out.write((username + "\r\n").getBytes());
            out.flush();

            // Wait for password prompt
            buffer.setLength(0);
            timeout = System.currentTimeMillis() + 3000;

            while (System.currentTimeMillis() < timeout) {
                if (in.available() > 0) {
                    int b = in.read();
                    if (b == -1) break;
                    buffer.append((char) b);

                    String current = buffer.toString().toLowerCase();
                    if (current.contains("password:")) {
                        break;
                    }
                }
                Thread.sleep(50);
            }

            // Send password
            out.write((password + "\r\n").getBytes());
            out.flush();

            // Check response
            buffer.setLength(0);
            timeout = System.currentTimeMillis() + 3000;

            while (System.currentTimeMillis() < timeout) {
                if (in.available() > 0) {
                    int b = in.read();
                    if (b == -1) break;
                    buffer.append((char) b);
                }
                Thread.sleep(50);
            }

            String response = buffer.toString().toLowerCase();
            if (response.contains("incorrect") || response.contains("failed") ||
                    response.contains("invalid") || response.contains("denied")) {
                result.success = false;
                result.message = "Login failed";
            } else if (response.contains("$") || response.contains("#") ||
                    response.contains(">") || response.contains("welcome") ||
                    response.contains("last login")) {
                result.success = true;
                result.message = "Login successful";
            } else {
                result.success = false;
                result.message = "Unknown response";
            }

        } catch (Exception e) {
            result.success = false;
            result.message = "Connection error: " + e.getMessage();
        } finally {
            result.responseTimeMs = System.currentTimeMillis() - startTime;
            closeQuietly(socket);
        }

        return result;
    }

    /**
     * Test SMTP AUTH credentials.
     */
    @NonNull
    public static TestResult testSmtpAuth(@NonNull String host, int port,
                                           @NonNull String username,
                                           @NonNull String password) {
        TestResult result = new TestResult();
        result.protocol = "SMTP AUTH";
        long startTime = System.currentTimeMillis();

        Socket socket = null;
        BufferedReader reader = null;
        OutputStream writer = null;

        try {
            socket = new Socket();
            socket.connect(new InetSocketAddress(host, port), DEFAULT_TIMEOUT);
            socket.setSoTimeout(DEFAULT_TIMEOUT);

            reader = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            writer = socket.getOutputStream();

            // Read banner
            String banner = reader.readLine();
            result.serverBanner = banner;

            // Send EHLO
            writer.write("EHLO test\r\n".getBytes());
            writer.flush();

            // Read EHLO response
            String line;
            boolean authSupported = false;
            while ((line = reader.readLine()) != null) {
                if (line.toUpperCase().contains("AUTH")) {
                    authSupported = true;
                }
                if (line.startsWith("250 ")) break;
            }

            if (!authSupported) {
                result.success = false;
                result.message = "SMTP AUTH not supported";
                return result;
            }

            // Send AUTH LOGIN
            writer.write("AUTH LOGIN\r\n".getBytes());
            writer.flush();

            String authResponse = reader.readLine();
            if (authResponse == null || !authResponse.startsWith("334")) {
                result.success = false;
                result.message = "AUTH LOGIN not accepted";
                return result;
            }

            // Send username (base64)
            String encodedUser = Base64.encodeToString(username.getBytes(), Base64.NO_WRAP);
            writer.write((encodedUser + "\r\n").getBytes());
            writer.flush();

            String userResponse = reader.readLine();
            if (userResponse == null || !userResponse.startsWith("334")) {
                result.success = false;
                result.message = "Username rejected";
                return result;
            }

            // Send password (base64)
            String encodedPass = Base64.encodeToString(password.getBytes(), Base64.NO_WRAP);
            writer.write((encodedPass + "\r\n").getBytes());
            writer.flush();

            String passResponse = reader.readLine();
            if (passResponse != null && passResponse.startsWith("235")) {
                result.success = true;
                result.message = "Authentication successful";
            } else {
                result.success = false;
                result.message = "Authentication failed: " + passResponse;
            }

            // Send QUIT
            writer.write("QUIT\r\n".getBytes());
            writer.flush();

        } catch (Exception e) {
            result.success = false;
            result.message = "Connection error: " + e.getMessage();
        } finally {
            result.responseTimeMs = System.currentTimeMillis() - startTime;
            closeQuietly(reader);
            closeQuietly(writer);
            closeQuietly(socket);
        }

        return result;
    }

    /**
     * Get list of common default credentials for a service.
     */
    @NonNull
    public static List<DefaultCredential> getDefaultCredentials(@NonNull String service) {
        List<DefaultCredential> creds = new ArrayList<>();
        String lower = service.toLowerCase();

        if (lower.contains("ssh") || lower.contains("linux") || lower.contains("unix")) {
            creds.add(new DefaultCredential("root", "root", "SSH/Linux"));
            creds.add(new DefaultCredential("root", "toor", "SSH/Linux"));
            creds.add(new DefaultCredential("root", "password", "SSH/Linux"));
            creds.add(new DefaultCredential("admin", "admin", "SSH/Linux"));
            creds.add(new DefaultCredential("user", "user", "SSH/Linux"));
        }

        if (lower.contains("ftp") || lower.contains("vsftpd") || lower.contains("proftpd")) {
            creds.add(new DefaultCredential("anonymous", "anonymous@", "FTP"));
            creds.add(new DefaultCredential("ftp", "ftp", "FTP"));
            creds.add(new DefaultCredential("admin", "admin", "FTP"));
            creds.add(new DefaultCredential("root", "root", "FTP"));
        }

        if (lower.contains("telnet") || lower.contains("router") || lower.contains("switch")) {
            creds.add(new DefaultCredential("admin", "admin", "Telnet"));
            creds.add(new DefaultCredential("admin", "password", "Telnet"));
            creds.add(new DefaultCredential("admin", "", "Telnet"));
            creds.add(new DefaultCredential("root", "root", "Telnet"));
            creds.add(new DefaultCredential("cisco", "cisco", "Cisco"));
        }

        if (lower.contains("mysql") || lower.contains("mariadb")) {
            creds.add(new DefaultCredential("root", "", "MySQL"));
            creds.add(new DefaultCredential("root", "root", "MySQL"));
            creds.add(new DefaultCredential("root", "mysql", "MySQL"));
            creds.add(new DefaultCredential("admin", "admin", "MySQL"));
        }

        if (lower.contains("postgres")) {
            creds.add(new DefaultCredential("postgres", "postgres", "PostgreSQL"));
            creds.add(new DefaultCredential("postgres", "", "PostgreSQL"));
            creds.add(new DefaultCredential("admin", "admin", "PostgreSQL"));
        }

        if (lower.contains("smb") || lower.contains("windows") || lower.contains("cifs")) {
            creds.add(new DefaultCredential("Administrator", "admin", "Windows/SMB"));
            creds.add(new DefaultCredential("Administrator", "", "Windows/SMB"));
            creds.add(new DefaultCredential("admin", "admin", "Windows/SMB"));
            creds.add(new DefaultCredential("guest", "", "Windows/SMB"));
        }

        if (lower.contains("web") || lower.contains("http") || lower.contains("tomcat")) {
            creds.add(new DefaultCredential("admin", "admin", "Web"));
            creds.add(new DefaultCredential("admin", "password", "Web"));
            creds.add(new DefaultCredential("administrator", "administrator", "Web"));
            creds.add(new DefaultCredential("tomcat", "tomcat", "Tomcat"));
            creds.add(new DefaultCredential("manager", "manager", "Tomcat"));
        }

        return creds;
    }

    /**
     * Close resource quietly.
     */
    private static void closeQuietly(@Nullable java.io.Closeable closeable) {
        if (closeable != null) {
            try {
                closeable.close();
            } catch (IOException e) {
                Log.d(TAG, "Failed to close resource: " + e.getMessage());
            }
        }
    }

    /**
     * Close socket quietly.
     */
    private static void closeQuietly(@Nullable Socket socket) {
        if (socket != null) {
            try {
                socket.close();
            } catch (IOException e) {
                Log.d(TAG, "Failed to close socket: " + e.getMessage());
            }
        }
    }
}
