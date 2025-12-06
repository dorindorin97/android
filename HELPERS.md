# Helper Utilities Documentation

This document describes the comprehensive helper utilities added to improve code quality and reduce boilerplate.

## Overview

The `org.csploit.android.helpers` package contains **100 utility classes** designed to simplify common operations and improve code quality across the cSploit application.

**Last Updated:** December 6, 2025

## Helper Categories

### Core Utilities (15)
| Helper | Purpose |
|--------|---------|
| `ConcurrencyHelper` | Async operations with callbacks and retry logic |
| `ValidationHelper` | Input validation for IPs, MACs, ports, URLs |
| `LoggingHelper` | Structured logging with levels and formatting |
| `StringHelper` | String operations and formatting |
| `PreferencesHelper` | SharedPreferences wrapper |
| `FileHelper` | File operations and utilities |
| `JsonHelper` | JSON parsing and serialization |
| `CacheHelper` | Memory/disk caching |
| `CollectionHelper` | Collection utilities |
| `TimeHelper` | Date/time formatting and utilities |
| `RetryHelper` | Retry logic with exponential backoff |
| `IdGenerator` | Unique ID generation |
| `InputSanitizer` | Input sanitization and cleaning |
| `EventBus` | Event publish/subscribe pattern |
| `ConfigHelper` | Configuration management |

### Network Utilities (25)
| Helper | Purpose |
|--------|---------|
| `NetworkHelper` | General network utilities |
| `NetworkAnalyzer` | Network traffic analysis |
| `NetworkDiagnostics` | Network troubleshooting |
| `NetworkMonitor` | Network state monitoring |
| `NetworkSpeedHelper` | Speed testing utilities |
| `NetworkStatsHelper` | Network statistics |
| `NetworkTopologyHelper` | Network topology mapping |
| `NetworkInterfaceHelper` | Interface configuration |
| `InterfaceHelper` | Interface management |
| `SubnetHelper` | Subnet calculations and CIDR |
| `IpAddressHelper` | IP address utilities |
| `MacAddressHelper` | MAC address utilities |
| `MacVendorHelper` | MAC vendor lookup (OUI database) |
| `ArpHelper` | ARP table operations |
| `DnsHelper` | DNS resolution with caching |
| `HttpHelper` | HTTP request utilities |
| `ProbeHelper` | Network probing utilities |
| `ConnectivityHelper` | Connectivity checks |
| `ConnectionMonitor` | Connection state monitoring |
| `ConnectionQualityHelper` | Connection quality assessment |
| `BandwidthMonitor` | Bandwidth monitoring |
| `GeoIPHelper` | Geo-location by IP |
| `FirewallHelper` | iptables/firewall management |
| `PacketAnalyzer` | Packet inspection |
| `PcapHelper` | PCAP file read/write |

### Security Utilities (12)
| Helper | Purpose |
|--------|---------|
| `SecurityChecker` | Security assessment |
| `VulnerabilityScanner` | Vulnerability detection |
| `ExploitMatcher` | Exploit matching |
| `ServiceFingerprinter` | Service identification |
| `DeviceFingerprinter` | Device fingerprinting |
| `SecureCredentialsHelper` | Secure credential storage |
| `EncryptedStorageHelper` | Encrypted data storage |
| `AuthTokenHelper` | Token management and sessions |
| `PortScanOptimizer` | Optimized port scanning |
| `BatchScannerHelper` | Batch scanning operations |
| `ServiceDatabase` | Service/port database |
| `HostTracker` | Host discovery tracking |

### Target Management (8)
| Helper | Purpose |
|--------|---------|
| `TargetHelper` | Target operations |
| `TargetGroupManager` | Target grouping |
| `TargetHistoryHelper` | Target scan history |
| `ScanProgressTracker` | Scan progress tracking |
| `ScanResultExporter` | Export scan results |
| `ScheduledScanHelper` | Scheduled scans |
| `ReportGenerator` | Report generation |
| `OutputFormatter` | Output formatting |

### UI Utilities (15)
| Helper | Purpose |
|--------|---------|
| `ToastHelper` | Toast notifications |
| `DialogHelper` | Dialog utilities |
| `NotificationHelper` | Notifications |
| `ModernNotificationHelper` | Modern notification channels |
| `UIHelper` | UI utilities |
| `ViewHelper` | View utilities |
| `DisplayHelper` | Display/screen utilities |
| `AnimationHelper` | Animation utilities |
| `ColorHelper` | Color utilities |
| `ClipboardHelper` | Clipboard operations |
| `VibrationHelper` | Vibration feedback |
| `TextFormattingHelper` | Text formatting |
| `MainThreadHelper` | Main thread operations |
| `PermissionHelper` | Permission handling |
| `RuntimePermissionHelper` | Runtime permissions |

### System Utilities (15)
| Helper | Purpose |
|--------|---------|
| `SystemHelper` | System information |
| `ShellHelper` | Shell command execution |
| `CommandBuilder` | Command building |
| `ProcessHelper` | Process management |
| `DeviceHelper` | Device information |
| `DeviceCapabilityHelper` | Device capabilities |
| `AppHelper` | App utilities |
| `AppInfoHelper` | App information |
| `BatteryStatusHelper` | Battery status |
| `PowerHelper` | Power management |
| `WifiHelper` | WiFi utilities |
| `AssetHelper` | Asset file access |
| `ExportHelper` | Data export |
| `DatabaseHelper` | Database utilities |
| `WorkManagerHelper` | WorkManager utilities |

### Performance Utilities (10)
| Helper | Purpose |
|--------|---------|
| `PerformanceMonitor` | Performance monitoring |
| `MetricsCollector` | Metrics collection |
| `RateLimiter` | Rate limiting |
| `ThreadHelper` | Thread utilities |
| `ThreadPoolManager` | Thread pool management |
| `CloseableHelper` | Resource cleanup |
| `AnalyticsHelper` | Analytics tracking |
| `SessionLogger` | Session logging |
| `SessionStateManager` | Session state management |
| `FeatureFlagsHelper` | Feature flag management |
| `EnhancedPreferencesHelper` | Enhanced preferences |

---

## Detailed Documentation

### 1. **ConcurrencyHelper**
Provides modern async/concurrent operations with callbacks and retry logic.

**Key Features:**
- `executeAsync()` - Run tasks in background with callbacks
- `executeIOAsync()` - Run I/O bound tasks in a dedicated thread pool
- `submitAsync()` - Submit tasks and get Future for manual handling
- `executeWithRetry()` - Retry logic with exponential backoff support
- `executeWithTimeout()` - Execute with timeout handling

**Example:**
```java
ConcurrencyHelper.executeAsync(
    () -> {
        // Long running operation
        return performNetworkRequest();
    },
    new ConcurrencyHelper.AsyncCallback<Result>() {
        @Override
        public void onSuccess(Result result) {
            // Update UI with result
        }

        @Override
        public void onError(Exception error) {
            // Handle error
        }

        @Override
        public void onCancelled() {
            // Handle cancellation
        }
    }
);
```

**Advantages Over AsyncTask:**
- No memory leaks with activity references
- Built-in callback pattern
- Better error handling
- Retry and timeout support
- Cleaner code

### 2. **ValidationHelper**
Input validation utilities for common data types and formats.

**Key Features:**
- `isEmpty()` - Check if string/collection is empty
- `isValidIPv4()` - Validate IPv4 addresses
- `isValidMacAddress()` - Validate MAC addresses
- `isValidPort()` - Validate port numbers
- `isValidUrl()` - Validate URLs
- `isValidHostname()` - Validate hostnames
- `isValidEmail()` - Validate email addresses

**Example:**
```java
if (ValidationHelper.isValidIPv4(ipAddress)) {
    // Process IP
}

if (ValidationHelper.isValidMacAddress(macAddress)) {
    // Process MAC
}
```

### 3. **LoggingHelper**
Enhanced structured logging with log levels and formatting.

**Key Features:**
- Consistent logging across the app
- Log levels: VERBOSE, DEBUG, INFO, WARN, ERROR
- Exception logging with stack traces
- Performance metrics logging
- Method entry/exit logging

**Example:**
```java
LoggingHelper.d("MyTag", "Debug message");
LoggingHelper.e("MyTag", "Error occurred", exception);
LoggingHelper.logPerformance("MyTag", "Operation", durationMs);
```

### 4. **StringHelper**
Common string operations and formatting utilities.

**Key Features:**
- `capitalize()` - Capitalize first letter
- `camelToSnake()` - Convert camelCase to snake_case
- `snakeToCamel()` - Convert snake_case to camelCase
- `repeat()` - Repeat string n times
- `truncate()` - Truncate with ellipsis
- `formatBytes()` - Format bytes to human readable (B, KB, MB, GB, TB)
- `formatDuration()` - Format milliseconds to human readable
- `join()` - Join objects with separator
- `sanitize()` - Remove special characters
- `isPalindrome()` - Check if string is palindrome

**Example:**
```java
String size = StringHelper.formatBytes(1048576); // "1.0 MB"
String duration = StringHelper.formatDuration(125000); // "2m 5s"
String output = StringHelper.join(", ", "apple", "banana", "cherry");
// Output: "apple, banana, cherry"
```

### 5. **PreferencesHelper**
Secure shared preferences wrapper with encryption support.

**Key Features:**
- `getString()` / `setString()` - String preferences
- `getInt()` / `setInt()` - Integer preferences
- `getBoolean()` / `setBoolean()` - Boolean preferences
- `getSecureString()` / `setSecureString()` - Encrypted string preferences
- `remove()` / `removeSecure()` - Remove preferences
- `clear()` / `clearSecure()` - Clear all preferences

**Important:** Must call `PreferencesHelper.init(context)` in Application.onCreate()

**Example:**
```java
// In Application.onCreate()
PreferencesHelper.init(this);

// Use regular preferences
PreferencesHelper.setString("username", "admin");
String username = PreferencesHelper.getString("username", null);

// Use secure (encrypted) preferences
PreferencesHelper.setSecureString("api_key", "secret_key_123");
String apiKey = PreferencesHelper.getSecureString("api_key", null);
```

## Best Practices

### When to Use Each Helper

| Helper | Use Case |
|--------|----------|
| ConcurrencyHelper | Network requests, long operations, I/O tasks |
| ValidationHelper | Input validation, form processing |
| LoggingHelper | Debugging, error tracking, performance monitoring |
| StringHelper | UI formatting, string manipulation |
| PreferencesHelper | Storing settings, user preferences, secrets |

### Common Patterns

#### Network Request with Error Handling
```java
ConcurrencyHelper.executeIOAsync(
    () -> networkClient.fetchData(url),
    new ConcurrencyHelper.AsyncCallback<Data>() {
        @Override
        public void onSuccess(Data result) {
            updateUI(result);
        }

        @Override
        public void onError(Exception error) {
            showErrorDialog("Network error: " + error.getMessage());
            LoggingHelper.e("NetworkTag", "Failed to fetch data", error);
        }

        @Override
        public void onCancelled() {
            showMessage("Request cancelled");
        }
    }
);
```

#### Input Validation
```java
if (!ValidationHelper.isValidIPv4(ipInput)) {
    showError("Invalid IP address");
    return;
}

if (!ValidationHelper.isValidPort(portInput)) {
    showError("Invalid port number (1-65535)");
    return;
}

// Process valid input
```

#### Logging Best Practices
```java
// Don't log sensitive data
LoggingHelper.d("Auth", "Login attempt for user: " + username); // OK
LoggingHelper.d("Auth", "Password: " + password); // BAD - never log passwords

// Use appropriate log levels
LoggingHelper.v("DetailedTag", "Verbose debug info"); // Development only
LoggingHelper.d("Tag", "Debug information");
LoggingHelper.i("Tag", "General info");
LoggingHelper.w("Tag", "Warning condition");
LoggingHelper.e("Tag", "Error occurred", exception);
```

## Migration Guide

### From AsyncTask to ConcurrencyHelper

**Before:**
```java
new AsyncTask<String, Void, String>() {
    @Override
    protected String doInBackground(String... params) {
        try {
            return performLongOperation();
        } catch (Exception e) {
            e.printStackTrace();
            return null;
        }
    }

    @Override
    protected void onPostExecute(String result) {
        if (result != null) {
            updateUI(result);
        }
    }
}.execute();
```

**After:**
```java
ConcurrencyHelper.executeAsync(
    this::performLongOperation,
    new ConcurrencyHelper.AsyncCallback<String>() {
        @Override
        public void onSuccess(String result) {
            updateUI(result);
        }

        @Override
        public void onError(Exception error) {
            LoggingHelper.e("Tag", "Operation failed", error);
        }

        @Override
        public void onCancelled() {}
    }
);
```

## Performance Considerations

- **ConcurrencyHelper** uses fixed thread pools for better resource management
- **StringHelper** operations are fast for typical use cases
- **ValidationHelper** uses regex patterns which are compiled on first use
- **PreferencesHelper** uses encrypted storage (slight performance cost)
- **LoggingHelper** methods are optimized for minimal overhead

## Thread Safety

All helper classes are thread-safe and can be used from any thread.

## Error Handling

Always handle errors appropriately:
- Catch exceptions in callbacks
- Log errors for debugging
- Show user-friendly error messages
- Consider retry logic for network operations

## Future Enhancements

Planned improvements:
- Analytics helper for event tracking
- Network helper with retry/timeout utilities
- File helper for common file operations
- Permission helper for simplified permission checks
- Dialog helper for common UI patterns

## Contributing

When adding new helper utilities:
1. Follow existing naming conventions
2. Add comprehensive JavaDoc comments
3. Include null-safety annotations (@Nullable, @NonNull)
4. Add example usage in comments
5. Consider thread safety
6. Keep methods focused and single-purpose
7. Add tests for complex logic

## FAQ

**Q: When should I use PreferencesHelper vs Database?**
A: Use PreferencesHelper for simple key-value data (settings, preferences). Use a database for complex queries or large amounts of data.

**Q: Is encrypted storage slower?**
A: Yes, slightly. But it's worth it for sensitive data like API keys, tokens, and credentials.

**Q: Can I use ConcurrencyHelper without initialization?**
A: Yes, ConcurrencyHelper works immediately. Only PreferencesHelper requires init().

**Q: What happens if PreferencesHelper.init() is not called?**
A: All PreferencesHelper calls will fail silently and return default values.
