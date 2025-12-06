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

import android.util.Log;

import androidx.annotation.NonNull;
import androidx.annotation.Nullable;

import java.util.HashMap;
import java.util.Locale;
import java.util.Map;
import java.util.regex.Pattern;

/**
 * MacVendorHelper - MAC address vendor lookup and utilities.
 * 
 * Provides:
 * - MAC address to vendor lookup
 * - MAC address validation
 * - MAC address formatting
 * - Common device type detection
 * 
 * Usage:
 * {@code
 * // Get vendor from MAC
 * String vendor = MacVendorHelper.getVendor("AA:BB:CC:DD:EE:FF");
 * 
 * // Validate MAC
 * boolean valid = MacVendorHelper.isValidMac("AA:BB:CC:DD:EE:FF");
 * 
 * // Format MAC
 * String formatted = MacVendorHelper.formatMac("aabbccddeeff");
 * }
 */
public final class MacVendorHelper {
    
    public static final String TAG = "MacVendorHelper";
    
    // MAC address patterns
    private static final Pattern MAC_PATTERN_COLON = Pattern.compile(
            "^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$");
    private static final Pattern MAC_PATTERN_DASH = Pattern.compile(
            "^([0-9A-Fa-f]{2}-){5}[0-9A-Fa-f]{2}$");
    private static final Pattern MAC_PATTERN_PLAIN = Pattern.compile(
            "^[0-9A-Fa-f]{12}$");
    
    // Common OUI (Organizationally Unique Identifier) database
    private static final Map<String, String> OUI_DATABASE = new HashMap<>();
    
    // Device type hints based on vendor
    private static final Map<String, DeviceType> VENDOR_DEVICE_TYPES = new HashMap<>();
    
    public enum DeviceType {
        ROUTER("Router/Gateway"),
        SMARTPHONE("Smartphone"),
        COMPUTER("Computer"),
        TABLET("Tablet"),
        IOT("IoT Device"),
        PRINTER("Printer"),
        TV("Smart TV"),
        GAMING("Gaming Console"),
        CAMERA("Camera/Security"),
        NETWORK("Network Equipment"),
        UNKNOWN("Unknown");
        
        private final String displayName;
        
        DeviceType(String displayName) {
            this.displayName = displayName;
        }
        
        public String getDisplayName() {
            return displayName;
        }
    }
    
    static {
        // Initialize OUI database with common vendors
        initializeOuiDatabase();
        initializeDeviceTypes();
    }
    
    private static void initializeOuiDatabase() {
        // Apple devices
        OUI_DATABASE.put("00:03:93", "Apple");
        OUI_DATABASE.put("00:05:02", "Apple");
        OUI_DATABASE.put("00:0A:27", "Apple");
        OUI_DATABASE.put("00:0A:95", "Apple");
        OUI_DATABASE.put("00:0D:93", "Apple");
        OUI_DATABASE.put("00:10:FA", "Apple");
        OUI_DATABASE.put("00:11:24", "Apple");
        OUI_DATABASE.put("00:14:51", "Apple");
        OUI_DATABASE.put("00:16:CB", "Apple");
        OUI_DATABASE.put("00:17:F2", "Apple");
        OUI_DATABASE.put("00:19:E3", "Apple");
        OUI_DATABASE.put("00:1B:63", "Apple");
        OUI_DATABASE.put("00:1C:B3", "Apple");
        OUI_DATABASE.put("00:1D:4F", "Apple");
        OUI_DATABASE.put("00:1E:52", "Apple");
        OUI_DATABASE.put("00:1E:C2", "Apple");
        OUI_DATABASE.put("00:1F:5B", "Apple");
        OUI_DATABASE.put("00:1F:F3", "Apple");
        OUI_DATABASE.put("00:21:E9", "Apple");
        OUI_DATABASE.put("00:22:41", "Apple");
        OUI_DATABASE.put("00:23:12", "Apple");
        OUI_DATABASE.put("00:23:32", "Apple");
        OUI_DATABASE.put("00:23:6C", "Apple");
        OUI_DATABASE.put("00:23:DF", "Apple");
        OUI_DATABASE.put("00:24:36", "Apple");
        OUI_DATABASE.put("00:25:00", "Apple");
        OUI_DATABASE.put("00:25:4B", "Apple");
        OUI_DATABASE.put("00:25:BC", "Apple");
        OUI_DATABASE.put("00:26:08", "Apple");
        OUI_DATABASE.put("00:26:4A", "Apple");
        OUI_DATABASE.put("00:26:B0", "Apple");
        OUI_DATABASE.put("00:26:BB", "Apple");
        
        // Samsung
        OUI_DATABASE.put("00:00:F0", "Samsung");
        OUI_DATABASE.put("00:02:78", "Samsung");
        OUI_DATABASE.put("00:09:18", "Samsung");
        OUI_DATABASE.put("00:0D:AE", "Samsung");
        OUI_DATABASE.put("00:12:47", "Samsung");
        OUI_DATABASE.put("00:12:FB", "Samsung");
        OUI_DATABASE.put("00:13:77", "Samsung");
        OUI_DATABASE.put("00:15:99", "Samsung");
        OUI_DATABASE.put("00:15:B9", "Samsung");
        OUI_DATABASE.put("00:16:32", "Samsung");
        OUI_DATABASE.put("00:16:6B", "Samsung");
        OUI_DATABASE.put("00:16:6C", "Samsung");
        OUI_DATABASE.put("00:17:C9", "Samsung");
        OUI_DATABASE.put("00:17:D5", "Samsung");
        OUI_DATABASE.put("00:18:AF", "Samsung");
        OUI_DATABASE.put("00:1A:8A", "Samsung");
        OUI_DATABASE.put("00:1B:98", "Samsung");
        OUI_DATABASE.put("00:1C:43", "Samsung");
        OUI_DATABASE.put("00:1D:25", "Samsung");
        OUI_DATABASE.put("00:1D:F6", "Samsung");
        OUI_DATABASE.put("00:1E:7D", "Samsung");
        OUI_DATABASE.put("00:1F:CC", "Samsung");
        OUI_DATABASE.put("00:1F:CD", "Samsung");
        OUI_DATABASE.put("00:21:19", "Samsung");
        OUI_DATABASE.put("00:21:4C", "Samsung");
        OUI_DATABASE.put("00:21:D1", "Samsung");
        OUI_DATABASE.put("00:21:D2", "Samsung");
        OUI_DATABASE.put("00:23:39", "Samsung");
        OUI_DATABASE.put("00:23:3A", "Samsung");
        OUI_DATABASE.put("00:23:99", "Samsung");
        OUI_DATABASE.put("00:23:D6", "Samsung");
        OUI_DATABASE.put("00:23:D7", "Samsung");
        OUI_DATABASE.put("00:24:54", "Samsung");
        OUI_DATABASE.put("00:24:90", "Samsung");
        OUI_DATABASE.put("00:24:91", "Samsung");
        OUI_DATABASE.put("00:25:66", "Samsung");
        OUI_DATABASE.put("00:25:67", "Samsung");
        OUI_DATABASE.put("00:26:37", "Samsung");
        OUI_DATABASE.put("00:26:5D", "Samsung");
        OUI_DATABASE.put("00:26:5F", "Samsung");
        
        // Google
        OUI_DATABASE.put("00:1A:11", "Google");
        OUI_DATABASE.put("3C:5A:B4", "Google");
        OUI_DATABASE.put("54:60:09", "Google");
        OUI_DATABASE.put("94:EB:2C", "Google");
        OUI_DATABASE.put("F4:F5:D8", "Google");
        OUI_DATABASE.put("F4:F5:E8", "Google");
        
        // Intel
        OUI_DATABASE.put("00:02:B3", "Intel");
        OUI_DATABASE.put("00:03:47", "Intel");
        OUI_DATABASE.put("00:04:23", "Intel");
        OUI_DATABASE.put("00:07:E9", "Intel");
        OUI_DATABASE.put("00:0C:F1", "Intel");
        OUI_DATABASE.put("00:0E:0C", "Intel");
        OUI_DATABASE.put("00:0E:35", "Intel");
        OUI_DATABASE.put("00:11:11", "Intel");
        OUI_DATABASE.put("00:12:F0", "Intel");
        OUI_DATABASE.put("00:13:02", "Intel");
        OUI_DATABASE.put("00:13:20", "Intel");
        OUI_DATABASE.put("00:13:CE", "Intel");
        OUI_DATABASE.put("00:13:E8", "Intel");
        OUI_DATABASE.put("00:15:00", "Intel");
        OUI_DATABASE.put("00:15:17", "Intel");
        OUI_DATABASE.put("00:16:6F", "Intel");
        OUI_DATABASE.put("00:16:76", "Intel");
        OUI_DATABASE.put("00:16:EA", "Intel");
        OUI_DATABASE.put("00:16:EB", "Intel");
        OUI_DATABASE.put("00:18:DE", "Intel");
        OUI_DATABASE.put("00:19:D1", "Intel");
        OUI_DATABASE.put("00:19:D2", "Intel");
        OUI_DATABASE.put("00:1B:21", "Intel");
        OUI_DATABASE.put("00:1B:77", "Intel");
        OUI_DATABASE.put("00:1C:BF", "Intel");
        OUI_DATABASE.put("00:1C:C0", "Intel");
        OUI_DATABASE.put("00:1D:E0", "Intel");
        OUI_DATABASE.put("00:1D:E1", "Intel");
        OUI_DATABASE.put("00:1E:64", "Intel");
        OUI_DATABASE.put("00:1E:65", "Intel");
        OUI_DATABASE.put("00:1E:67", "Intel");
        OUI_DATABASE.put("00:1F:3B", "Intel");
        OUI_DATABASE.put("00:1F:3C", "Intel");
        
        // Cisco/Linksys
        OUI_DATABASE.put("00:00:0C", "Cisco");
        OUI_DATABASE.put("00:01:42", "Cisco");
        OUI_DATABASE.put("00:01:43", "Cisco");
        OUI_DATABASE.put("00:01:63", "Cisco");
        OUI_DATABASE.put("00:01:64", "Cisco");
        OUI_DATABASE.put("00:01:96", "Cisco");
        OUI_DATABASE.put("00:01:97", "Cisco");
        OUI_DATABASE.put("00:02:16", "Cisco");
        OUI_DATABASE.put("00:02:17", "Cisco");
        OUI_DATABASE.put("00:02:3D", "Cisco");
        OUI_DATABASE.put("00:02:4A", "Cisco");
        OUI_DATABASE.put("00:02:4B", "Cisco");
        OUI_DATABASE.put("00:02:7D", "Cisco");
        OUI_DATABASE.put("00:02:7E", "Cisco");
        OUI_DATABASE.put("00:02:B9", "Cisco");
        OUI_DATABASE.put("00:02:BA", "Cisco");
        OUI_DATABASE.put("00:02:FC", "Cisco");
        OUI_DATABASE.put("00:02:FD", "Cisco");
        OUI_DATABASE.put("00:03:31", "Cisco");
        OUI_DATABASE.put("00:03:32", "Cisco");
        OUI_DATABASE.put("00:03:6B", "Cisco");
        OUI_DATABASE.put("00:03:6C", "Cisco");
        OUI_DATABASE.put("00:03:9F", "Cisco");
        OUI_DATABASE.put("00:03:A0", "Cisco");
        OUI_DATABASE.put("00:03:E3", "Cisco");
        OUI_DATABASE.put("00:03:E4", "Cisco");
        OUI_DATABASE.put("00:03:FD", "Cisco");
        OUI_DATABASE.put("00:03:FE", "Cisco");
        
        // TP-Link
        OUI_DATABASE.put("00:1D:0F", "TP-Link");
        OUI_DATABASE.put("00:21:27", "TP-Link");
        OUI_DATABASE.put("00:23:CD", "TP-Link");
        OUI_DATABASE.put("00:25:86", "TP-Link");
        OUI_DATABASE.put("00:27:19", "TP-Link");
        OUI_DATABASE.put("10:FE:ED", "TP-Link");
        OUI_DATABASE.put("14:CC:20", "TP-Link");
        OUI_DATABASE.put("14:CF:92", "TP-Link");
        OUI_DATABASE.put("14:E6:E4", "TP-Link");
        OUI_DATABASE.put("18:A6:F7", "TP-Link");
        OUI_DATABASE.put("1C:3B:F3", "TP-Link");
        OUI_DATABASE.put("20:DC:E6", "TP-Link");
        OUI_DATABASE.put("24:69:68", "TP-Link");
        OUI_DATABASE.put("30:B4:9E", "TP-Link");
        OUI_DATABASE.put("34:E8:94", "TP-Link");
        OUI_DATABASE.put("38:83:45", "TP-Link");
        
        // Netgear
        OUI_DATABASE.put("00:09:5B", "Netgear");
        OUI_DATABASE.put("00:0F:B5", "Netgear");
        OUI_DATABASE.put("00:14:6C", "Netgear");
        OUI_DATABASE.put("00:18:4D", "Netgear");
        OUI_DATABASE.put("00:1B:2F", "Netgear");
        OUI_DATABASE.put("00:1E:2A", "Netgear");
        OUI_DATABASE.put("00:1F:33", "Netgear");
        OUI_DATABASE.put("00:22:3F", "Netgear");
        OUI_DATABASE.put("00:24:B2", "Netgear");
        OUI_DATABASE.put("00:26:F2", "Netgear");
        OUI_DATABASE.put("20:4E:7F", "Netgear");
        OUI_DATABASE.put("28:C6:8E", "Netgear");
        OUI_DATABASE.put("30:46:9A", "Netgear");
        OUI_DATABASE.put("44:94:FC", "Netgear");
        
        // Dell
        OUI_DATABASE.put("00:06:5B", "Dell");
        OUI_DATABASE.put("00:08:74", "Dell");
        OUI_DATABASE.put("00:0B:DB", "Dell");
        OUI_DATABASE.put("00:0D:56", "Dell");
        OUI_DATABASE.put("00:0F:1F", "Dell");
        OUI_DATABASE.put("00:11:43", "Dell");
        OUI_DATABASE.put("00:12:3F", "Dell");
        OUI_DATABASE.put("00:13:72", "Dell");
        OUI_DATABASE.put("00:14:22", "Dell");
        OUI_DATABASE.put("00:15:C5", "Dell");
        OUI_DATABASE.put("00:16:F0", "Dell");
        OUI_DATABASE.put("00:18:8B", "Dell");
        OUI_DATABASE.put("00:19:B9", "Dell");
        OUI_DATABASE.put("00:1A:A0", "Dell");
        OUI_DATABASE.put("00:1C:23", "Dell");
        OUI_DATABASE.put("00:1D:09", "Dell");
        OUI_DATABASE.put("00:1E:4F", "Dell");
        OUI_DATABASE.put("00:1E:C9", "Dell");
        OUI_DATABASE.put("00:21:70", "Dell");
        OUI_DATABASE.put("00:21:9B", "Dell");
        OUI_DATABASE.put("00:22:19", "Dell");
        OUI_DATABASE.put("00:23:AE", "Dell");
        OUI_DATABASE.put("00:24:E8", "Dell");
        OUI_DATABASE.put("00:25:64", "Dell");
        OUI_DATABASE.put("00:26:B9", "Dell");
        
        // HP
        OUI_DATABASE.put("00:00:63", "HP");
        OUI_DATABASE.put("00:01:E6", "HP");
        OUI_DATABASE.put("00:01:E7", "HP");
        OUI_DATABASE.put("00:02:A5", "HP");
        OUI_DATABASE.put("00:04:EA", "HP");
        OUI_DATABASE.put("00:06:0D", "HP");
        OUI_DATABASE.put("00:08:02", "HP");
        OUI_DATABASE.put("00:08:83", "HP");
        OUI_DATABASE.put("00:0A:57", "HP");
        OUI_DATABASE.put("00:0B:CD", "HP");
        OUI_DATABASE.put("00:0D:9D", "HP");
        OUI_DATABASE.put("00:0E:7F", "HP");
        OUI_DATABASE.put("00:0F:20", "HP");
        OUI_DATABASE.put("00:0F:61", "HP");
        OUI_DATABASE.put("00:10:83", "HP");
        OUI_DATABASE.put("00:10:E3", "HP");
        OUI_DATABASE.put("00:11:0A", "HP");
        OUI_DATABASE.put("00:11:85", "HP");
        OUI_DATABASE.put("00:12:79", "HP");
        OUI_DATABASE.put("00:13:21", "HP");
        OUI_DATABASE.put("00:14:38", "HP");
        OUI_DATABASE.put("00:14:C2", "HP");
        OUI_DATABASE.put("00:15:60", "HP");
        OUI_DATABASE.put("00:16:35", "HP");
        OUI_DATABASE.put("00:17:08", "HP");
        OUI_DATABASE.put("00:17:A4", "HP");
        OUI_DATABASE.put("00:18:71", "HP");
        OUI_DATABASE.put("00:18:FE", "HP");
        OUI_DATABASE.put("00:19:BB", "HP");
        OUI_DATABASE.put("00:1A:4B", "HP");
        OUI_DATABASE.put("00:1B:78", "HP");
        OUI_DATABASE.put("00:1C:C4", "HP");
        OUI_DATABASE.put("00:1E:0B", "HP");
        OUI_DATABASE.put("00:1F:29", "HP");
        OUI_DATABASE.put("00:21:5A", "HP");
        OUI_DATABASE.put("00:22:64", "HP");
        OUI_DATABASE.put("00:23:7D", "HP");
        OUI_DATABASE.put("00:24:81", "HP");
        OUI_DATABASE.put("00:25:B3", "HP");
        OUI_DATABASE.put("00:26:55", "HP");
        
        // Microsoft
        OUI_DATABASE.put("00:03:FF", "Microsoft");
        OUI_DATABASE.put("00:0D:3A", "Microsoft");
        OUI_DATABASE.put("00:12:5A", "Microsoft");
        OUI_DATABASE.put("00:15:5D", "Microsoft");
        OUI_DATABASE.put("00:17:FA", "Microsoft");
        OUI_DATABASE.put("00:1D:D8", "Microsoft");
        OUI_DATABASE.put("00:22:48", "Microsoft");
        OUI_DATABASE.put("00:25:AE", "Microsoft");
        OUI_DATABASE.put("00:50:F2", "Microsoft");
        OUI_DATABASE.put("28:18:78", "Microsoft");
        OUI_DATABASE.put("7C:1E:52", "Microsoft");
        OUI_DATABASE.put("7C:ED:8D", "Microsoft");
        
        // Amazon
        OUI_DATABASE.put("00:FC:8B", "Amazon");
        OUI_DATABASE.put("0C:47:C9", "Amazon");
        OUI_DATABASE.put("10:AE:60", "Amazon");
        OUI_DATABASE.put("18:74:2E", "Amazon");
        OUI_DATABASE.put("34:D2:70", "Amazon");
        OUI_DATABASE.put("40:B4:CD", "Amazon");
        OUI_DATABASE.put("44:65:0D", "Amazon");
        OUI_DATABASE.put("50:F5:DA", "Amazon");
        OUI_DATABASE.put("68:37:E9", "Amazon");
        OUI_DATABASE.put("68:54:FD", "Amazon");
        OUI_DATABASE.put("74:C2:46", "Amazon");
        OUI_DATABASE.put("78:E1:03", "Amazon");
        OUI_DATABASE.put("84:D6:D0", "Amazon");
        OUI_DATABASE.put("A0:02:DC", "Amazon");
        OUI_DATABASE.put("AC:63:BE", "Amazon");
        OUI_DATABASE.put("B4:7C:9C", "Amazon");
        OUI_DATABASE.put("F0:27:2D", "Amazon");
        OUI_DATABASE.put("F0:81:73", "Amazon");
        OUI_DATABASE.put("FC:65:DE", "Amazon");
        
        // Sony
        OUI_DATABASE.put("00:01:4A", "Sony");
        OUI_DATABASE.put("00:04:1F", "Sony");
        OUI_DATABASE.put("00:13:A9", "Sony");
        OUI_DATABASE.put("00:15:C1", "Sony");
        OUI_DATABASE.put("00:19:63", "Sony");
        OUI_DATABASE.put("00:1A:80", "Sony");
        OUI_DATABASE.put("00:1D:BA", "Sony");
        OUI_DATABASE.put("00:1E:A4", "Sony");
        OUI_DATABASE.put("00:1F:E4", "Sony");
        OUI_DATABASE.put("00:21:4F", "Sony");
        OUI_DATABASE.put("00:24:BE", "Sony");
        OUI_DATABASE.put("00:EB:2D", "Sony");
        
        // Nintendo
        OUI_DATABASE.put("00:09:BF", "Nintendo");
        OUI_DATABASE.put("00:16:56", "Nintendo");
        OUI_DATABASE.put("00:17:AB", "Nintendo");
        OUI_DATABASE.put("00:19:1D", "Nintendo");
        OUI_DATABASE.put("00:19:FD", "Nintendo");
        OUI_DATABASE.put("00:1A:E9", "Nintendo");
        OUI_DATABASE.put("00:1B:7A", "Nintendo");
        OUI_DATABASE.put("00:1B:EA", "Nintendo");
        OUI_DATABASE.put("00:1C:BE", "Nintendo");
        OUI_DATABASE.put("00:1D:BC", "Nintendo");
        OUI_DATABASE.put("00:1E:35", "Nintendo");
        OUI_DATABASE.put("00:1F:32", "Nintendo");
        OUI_DATABASE.put("00:1F:C5", "Nintendo");
        OUI_DATABASE.put("00:21:47", "Nintendo");
        OUI_DATABASE.put("00:21:BD", "Nintendo");
        OUI_DATABASE.put("00:22:4C", "Nintendo");
        OUI_DATABASE.put("00:22:AA", "Nintendo");
        OUI_DATABASE.put("00:23:31", "Nintendo");
        OUI_DATABASE.put("00:23:CC", "Nintendo");
        OUI_DATABASE.put("00:24:1E", "Nintendo");
        OUI_DATABASE.put("00:24:44", "Nintendo");
        OUI_DATABASE.put("00:24:F3", "Nintendo");
        OUI_DATABASE.put("00:25:A0", "Nintendo");
        
        // LG
        OUI_DATABASE.put("00:05:C9", "LG");
        OUI_DATABASE.put("00:0C:11", "LG");
        OUI_DATABASE.put("00:1C:62", "LG");
        OUI_DATABASE.put("00:1E:75", "LG");
        OUI_DATABASE.put("00:1F:6B", "LG");
        OUI_DATABASE.put("00:1F:E3", "LG");
        OUI_DATABASE.put("00:22:A9", "LG");
        OUI_DATABASE.put("00:25:E5", "LG");
        OUI_DATABASE.put("00:26:E2", "LG");
        OUI_DATABASE.put("10:68:3F", "LG");
        OUI_DATABASE.put("14:C9:13", "LG");
        OUI_DATABASE.put("20:21:A5", "LG");
        OUI_DATABASE.put("2C:54:CF", "LG");
        OUI_DATABASE.put("30:19:66", "LG");
        OUI_DATABASE.put("34:FC:EF", "LG");
        OUI_DATABASE.put("40:B0:FA", "LG");
        
        // Huawei
        OUI_DATABASE.put("00:09:4F", "Huawei");
        OUI_DATABASE.put("00:0F:E2", "Huawei");
        OUI_DATABASE.put("00:18:82", "Huawei");
        OUI_DATABASE.put("00:1E:10", "Huawei");
        OUI_DATABASE.put("00:21:E8", "Huawei");
        OUI_DATABASE.put("00:22:A1", "Huawei");
        OUI_DATABASE.put("00:25:68", "Huawei");
        OUI_DATABASE.put("00:25:9E", "Huawei");
        OUI_DATABASE.put("00:46:4B", "Huawei");
        OUI_DATABASE.put("04:02:1F", "Huawei");
        OUI_DATABASE.put("04:BD:70", "Huawei");
        OUI_DATABASE.put("04:C0:6F", "Huawei");
        OUI_DATABASE.put("04:F9:38", "Huawei");
        OUI_DATABASE.put("08:19:A6", "Huawei");
        OUI_DATABASE.put("08:63:61", "Huawei");
        OUI_DATABASE.put("08:7A:4C", "Huawei");
        OUI_DATABASE.put("0C:37:DC", "Huawei");
        OUI_DATABASE.put("0C:45:BA", "Huawei");
        OUI_DATABASE.put("0C:96:BF", "Huawei");
        OUI_DATABASE.put("10:1B:54", "Huawei");
        OUI_DATABASE.put("10:47:80", "Huawei");
        OUI_DATABASE.put("10:C6:1F", "Huawei");
        OUI_DATABASE.put("14:30:04", "Huawei");
        OUI_DATABASE.put("14:B9:68", "Huawei");
        OUI_DATABASE.put("18:D2:76", "Huawei");
        
        // Xiaomi
        OUI_DATABASE.put("04:CF:8C", "Xiaomi");
        OUI_DATABASE.put("0C:1D:AF", "Xiaomi");
        OUI_DATABASE.put("10:2A:B3", "Xiaomi");
        OUI_DATABASE.put("14:F6:5A", "Xiaomi");
        OUI_DATABASE.put("18:59:36", "Xiaomi");
        OUI_DATABASE.put("20:34:FB", "Xiaomi");
        OUI_DATABASE.put("28:6C:07", "Xiaomi");
        OUI_DATABASE.put("28:E3:1F", "Xiaomi");
        OUI_DATABASE.put("34:CE:00", "Xiaomi");
        OUI_DATABASE.put("38:A4:ED", "Xiaomi");
        OUI_DATABASE.put("3C:BD:D8", "Xiaomi");
        OUI_DATABASE.put("50:64:2B", "Xiaomi");
        OUI_DATABASE.put("58:44:98", "Xiaomi");
        OUI_DATABASE.put("64:09:80", "Xiaomi");
        OUI_DATABASE.put("64:B4:73", "Xiaomi");
        OUI_DATABASE.put("68:DF:DD", "Xiaomi");
        OUI_DATABASE.put("74:23:44", "Xiaomi");
        OUI_DATABASE.put("78:02:F8", "Xiaomi");
        OUI_DATABASE.put("7C:1D:D9", "Xiaomi");
        OUI_DATABASE.put("8C:BE:BE", "Xiaomi");
        
        // Raspberry Pi
        OUI_DATABASE.put("B8:27:EB", "Raspberry Pi");
        OUI_DATABASE.put("DC:A6:32", "Raspberry Pi");
        OUI_DATABASE.put("E4:5F:01", "Raspberry Pi");
        
        // VMware
        OUI_DATABASE.put("00:0C:29", "VMware");
        OUI_DATABASE.put("00:50:56", "VMware");
        OUI_DATABASE.put("00:05:69", "VMware");
        
        // VirtualBox
        OUI_DATABASE.put("08:00:27", "VirtualBox");
        
        Log.d(TAG, "Initialized OUI database with " + OUI_DATABASE.size() + " entries");
    }
    
    private static void initializeDeviceTypes() {
        VENDOR_DEVICE_TYPES.put("Apple", DeviceType.SMARTPHONE);
        VENDOR_DEVICE_TYPES.put("Samsung", DeviceType.SMARTPHONE);
        VENDOR_DEVICE_TYPES.put("Google", DeviceType.SMARTPHONE);
        VENDOR_DEVICE_TYPES.put("Huawei", DeviceType.SMARTPHONE);
        VENDOR_DEVICE_TYPES.put("Xiaomi", DeviceType.SMARTPHONE);
        VENDOR_DEVICE_TYPES.put("LG", DeviceType.SMARTPHONE);
        VENDOR_DEVICE_TYPES.put("Sony", DeviceType.SMARTPHONE);
        VENDOR_DEVICE_TYPES.put("Intel", DeviceType.COMPUTER);
        VENDOR_DEVICE_TYPES.put("Dell", DeviceType.COMPUTER);
        VENDOR_DEVICE_TYPES.put("HP", DeviceType.COMPUTER);
        VENDOR_DEVICE_TYPES.put("Microsoft", DeviceType.COMPUTER);
        VENDOR_DEVICE_TYPES.put("Cisco", DeviceType.ROUTER);
        VENDOR_DEVICE_TYPES.put("Netgear", DeviceType.ROUTER);
        VENDOR_DEVICE_TYPES.put("TP-Link", DeviceType.ROUTER);
        VENDOR_DEVICE_TYPES.put("Nintendo", DeviceType.GAMING);
        VENDOR_DEVICE_TYPES.put("Amazon", DeviceType.IOT);
        VENDOR_DEVICE_TYPES.put("Raspberry Pi", DeviceType.IOT);
        VENDOR_DEVICE_TYPES.put("VMware", DeviceType.COMPUTER);
        VENDOR_DEVICE_TYPES.put("VirtualBox", DeviceType.COMPUTER);
    }
    
    private MacVendorHelper() {}
    
    /**
     * Get vendor name from MAC address.
     * 
     * @param mac MAC address in any format
     * @return vendor name or "Unknown"
     */
    @NonNull
    public static String getVendor(@Nullable String mac) {
        if (mac == null || mac.isEmpty()) {
            return "Unknown";
        }
        
        String oui = extractOui(mac);
        if (oui == null) {
            return "Unknown";
        }
        
        String vendor = OUI_DATABASE.get(oui.toUpperCase(Locale.US));
        return vendor != null ? vendor : "Unknown";
    }
    
    /**
     * Get device type hint from MAC address.
     * 
     * @param mac MAC address
     * @return likely device type
     */
    @NonNull
    public static DeviceType getDeviceType(@Nullable String mac) {
        String vendor = getVendor(mac);
        DeviceType type = VENDOR_DEVICE_TYPES.get(vendor);
        return type != null ? type : DeviceType.UNKNOWN;
    }
    
    /**
     * Validate MAC address format.
     * 
     * @param mac MAC address to validate
     * @return true if valid
     */
    public static boolean isValidMac(@Nullable String mac) {
        if (mac == null || mac.isEmpty()) {
            return false;
        }
        
        return MAC_PATTERN_COLON.matcher(mac).matches() ||
               MAC_PATTERN_DASH.matcher(mac).matches() ||
               MAC_PATTERN_PLAIN.matcher(mac).matches();
    }
    
    /**
     * Format MAC address to standard colon-separated format.
     * 
     * @param mac MAC address in any format
     * @return formatted MAC or original if invalid
     */
    @NonNull
    public static String formatMac(@Nullable String mac) {
        if (mac == null || mac.isEmpty()) {
            return "";
        }
        
        // Remove separators
        String clean = mac.replaceAll("[:-]", "").toUpperCase(Locale.US);
        
        if (clean.length() != 12) {
            return mac; // Return original if invalid
        }
        
        StringBuilder formatted = new StringBuilder();
        for (int i = 0; i < 12; i += 2) {
            if (i > 0) formatted.append(":");
            formatted.append(clean.substring(i, i + 2));
        }
        
        return formatted.toString();
    }
    
    /**
     * Extract OUI (first 3 bytes) from MAC address.
     * 
     * @param mac MAC address
     * @return OUI in XX:XX:XX format or null
     */
    @Nullable
    public static String extractOui(@Nullable String mac) {
        if (mac == null || mac.isEmpty()) {
            return null;
        }
        
        // Remove separators and get first 6 characters
        String clean = mac.replaceAll("[:-]", "").toUpperCase(Locale.US);
        
        if (clean.length() < 6) {
            return null;
        }
        
        return String.format("%s:%s:%s",
                clean.substring(0, 2),
                clean.substring(2, 4),
                clean.substring(4, 6));
    }
    
    /**
     * Check if MAC is a broadcast address.
     * 
     * @param mac MAC address
     * @return true if broadcast
     */
    public static boolean isBroadcast(@Nullable String mac) {
        if (mac == null) return false;
        String clean = mac.replaceAll("[:-]", "").toUpperCase(Locale.US);
        return "FFFFFFFFFFFF".equals(clean);
    }
    
    /**
     * Check if MAC is a multicast address.
     * 
     * @param mac MAC address
     * @return true if multicast
     */
    public static boolean isMulticast(@Nullable String mac) {
        if (mac == null || mac.isEmpty()) return false;
        String clean = mac.replaceAll("[:-]", "").toUpperCase(Locale.US);
        if (clean.length() < 2) return false;
        
        int firstByte = Integer.parseInt(clean.substring(0, 2), 16);
        return (firstByte & 0x01) == 1;
    }
    
    /**
     * Check if MAC is locally administered.
     * 
     * @param mac MAC address
     * @return true if locally administered
     */
    public static boolean isLocallyAdministered(@Nullable String mac) {
        if (mac == null || mac.isEmpty()) return false;
        String clean = mac.replaceAll("[:-]", "").toUpperCase(Locale.US);
        if (clean.length() < 2) return false;
        
        int firstByte = Integer.parseInt(clean.substring(0, 2), 16);
        return (firstByte & 0x02) == 2;
    }
    
    /**
     * Generate random MAC address.
     * 
     * @param locallyAdministered if true, set LA bit
     * @return random MAC address
     */
    @NonNull
    public static String generateRandomMac(boolean locallyAdministered) {
        StringBuilder mac = new StringBuilder();
        java.util.Random random = new java.util.Random();
        
        for (int i = 0; i < 6; i++) {
            int octet = random.nextInt(256);
            
            // First byte: set/clear LA bit and clear multicast bit
            if (i == 0) {
                if (locallyAdministered) {
                    octet |= 0x02; // Set LA bit
                } else {
                    octet &= ~0x02; // Clear LA bit
                }
                octet &= ~0x01; // Clear multicast bit
            }
            
            if (i > 0) mac.append(":");
            mac.append(String.format("%02X", octet));
        }
        
        return mac.toString();
    }
    
    /**
     * Convert MAC address to bytes.
     * 
     * @param mac MAC address string
     * @return byte array or null if invalid
     */
    @Nullable
    public static byte[] macToBytes(@Nullable String mac) {
        if (mac == null || mac.isEmpty()) {
            return null;
        }
        
        String clean = mac.replaceAll("[:-]", "");
        if (clean.length() != 12) {
            return null;
        }
        
        byte[] bytes = new byte[6];
        for (int i = 0; i < 6; i++) {
            bytes[i] = (byte) Integer.parseInt(clean.substring(i * 2, i * 2 + 2), 16);
        }
        return bytes;
    }
    
    /**
     * Convert bytes to MAC address string.
     * 
     * @param bytes byte array (6 bytes)
     * @return MAC address string or null
     */
    @Nullable
    public static String bytesToMac(@Nullable byte[] bytes) {
        if (bytes == null || bytes.length != 6) {
            return null;
        }
        
        StringBuilder mac = new StringBuilder();
        for (int i = 0; i < 6; i++) {
            if (i > 0) mac.append(":");
            mac.append(String.format("%02X", bytes[i] & 0xFF));
        }
        return mac.toString();
    }
}
