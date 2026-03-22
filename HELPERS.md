# Helper Utilities Documentation

This document describes the helper utilities in `org.csploit.android.helpers`.

## Overview

The `org.csploit.android.helpers` package contains **17 utility classes** designed to
simplify common operations and reduce boilerplate across the cSploit application.

## Helper Categories

### Core Utilities (3)
| Helper | Purpose |
|--------|---------|
| `ConcurrencyHelper` | Async operations with callbacks and retry logic |
| `LoggingHelper` | Structured logging with levels and formatting |
| `PreferencesHelper` | SharedPreferences wrapper |

### Network Utilities (3)
| Helper | Purpose |
|--------|---------|
| `NetworkHelper` | General network utilities |
| `HttpHelper` | HTTP request utilities |
| `ConnectionMonitor` | Connection state monitoring |

### Security Utilities (3)
| Helper | Purpose |
|--------|---------|
| `SecureCredentialsHelper` | Secure credential storage using Android Keystore |
| `EncryptedStorageHelper` | Encrypted data storage |
| `SecurityChecker` | Security assessment utilities |

### Target Management (1)
| Helper | Purpose |
|--------|---------|
| `ScanResultExporter` | Export scan results to file |

### UI Utilities (4)
| Helper | Purpose |
|--------|---------|
| `ToastHelper` | Toast notifications with status indicators |
| `UIHelper` | UI utilities and dialogs |
| `AnimationHelper` | Animation utilities |
| `PendingIntentHelper` | PendingIntent creation (Android 12+ FLAG_IMMUTABLE) |

### System Utilities (3)
| Helper | Purpose |
|--------|---------|
| `DeviceHelper` | Device information |
| `AppHelper` | Application utilities |
| `ThreadHelper` | Thread and executor utilities |

---

## Detailed Documentation

### 1. **ConcurrencyHelper**
Modern async/concurrent operations with callbacks and retry logic. Replaces the
deprecated `AsyncTask`.

**Key Features:**
- `executeAsync()` — Run tasks in background with callbacks
- `executeIOAsync()` — Run I/O-bound tasks in a dedicated thread pool
- `submitAsync()` — Submit tasks and get a `Future` for manual handling
- `executeWithRetry()` — Retry logic with exponential backoff
- `executeWithTimeout()` — Execute with timeout handling

**Example:**
```java
ConcurrencyHelper.executeAsync(
    () -> performNetworkRequest(),
    new ConcurrencyHelper.AsyncCallback<Result>() {
        @Override
        public void onSuccess(Result result) {
            // Update UI on main thread
        }

        @Override
        public void onError(Exception error) {
            LoggingHelper.e("Tag", "Request failed", error);
        }

        @Override
        public void onCancelled() {}
    }
);
```

**Migration from AsyncTask:**
```java
// Before (deprecated AsyncTask)
new AsyncTask<Void, Void, String>() {
    @Override protected String doInBackground(Void... v) { return doWork(); }
    @Override protected void onPostExecute(String r) { updateUI(r); }
}.execute();

// After (ConcurrencyHelper)
ConcurrencyHelper.executeAsync(this::doWork, new ConcurrencyHelper.AsyncCallback<String>() {
    @Override public void onSuccess(String r) { updateUI(r); }
    @Override public void onError(Exception e) { LoggingHelper.e("Tag", "Failed", e); }
    @Override public void onCancelled() {}
});
```

---

### 2. **LoggingHelper**
Enhanced structured logging with consistent formatting across the app.

**Key Features:**
- Methods: `d()`, `i()`, `w()`, `e()`, `error()`, `warning()`, `info()`
- Exception logging with stack traces: `e(tag, message, throwable)`
- Drop-in for `android.util.Log` calls throughout the codebase

**Example:**
```java
LoggingHelper.d("MyTag", "Debug message");
LoggingHelper.e("MyTag", "Error occurred", exception);
LoggingHelper.warning("Something unexpected happened");
```

---

### 3. **PreferencesHelper**
`SharedPreferences` wrapper with support for both plain and encrypted storage.

**Important:** Call `PreferencesHelper.init(context)` in `Application.onCreate()`.

**Example:**
```java
PreferencesHelper.setString("username", "admin");
String username = PreferencesHelper.getString("username", null);

PreferencesHelper.setSecureString("api_key", "secret");
String apiKey = PreferencesHelper.getSecureString("api_key", null);
```

---

### 4. **SecureCredentialsHelper**
Stores and retrieves credentials securely. Used by `MsfRpcdService` for Metasploit
RPC credentials (host, user, password, port, SSL flag).

**Example:**
```java
SecureCredentialsHelper creds = new SecureCredentialsHelper(context);
String host = creds.retrieveCredential("MSF_RPC_HOST", "127.0.0.1");
```

---

### 5. **ToastHelper**
Toast notifications with status indicators. Replaces all direct
`Toast.makeText()` calls.

**Example:**
```java
ToastHelper.success(context, "Scan complete");
ToastHelper.error(context, "Connection failed");
ToastHelper.info(context, "Scanning...");
ToastHelper.warning(context, "No open ports found");
ToastHelper.childNotStarted(context, getString(R.string.child_not_started));
```

---

### 6. **PendingIntentHelper**
Creates `PendingIntent` objects with correct `FLAG_IMMUTABLE` flag required on
Android 12+ (API 31+). Prevents crashes from missing immutability flag.

**Example:**
```java
// Instead of PendingIntent.getActivity(context, code, intent, 0)
PendingIntent pi = PendingIntentHelper.getActivityImmutable(context, code, intent);
PendingIntent broadcast = PendingIntentHelper.getBroadcastImmutable(context, code, intent);
```

---

### 7. **ThreadHelper**
Shared executor service for background tasks.

**Example:**
```java
ThreadHelper.getSharedExecutor().execute(new Runnable() {
    @Override public void run() { doBackgroundWork(); }
});
```

---

## Best Practices

### Null Safety
Always guard `System.getTools()` and `System.getCurrentTarget()` before use —
these return `null` after Android process death:

```java
if (System.getTools() == null) {
    ToastHelper.childNotStarted(this, getString(R.string.child_not_started));
    return;
}
System.getTools().nmap.synScan(target, receiver);
```

### Logging
```java
// Good — generic message, no sensitive data
LoggingHelper.d("Auth", "Login attempt for user: " + username);

// Bad — never log passwords or tokens
LoggingHelper.d("Auth", "Password: " + password);
```

---

## Contributing

When adding new helper utilities:
1. Follow existing naming conventions (`*Helper` or `*Monitor`)
2. Add JavaDoc for public methods
3. Keep methods focused and single-purpose
4. Ensure thread safety
5. Add to this document
