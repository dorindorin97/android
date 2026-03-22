# cSploit Development Guide

Comprehensive guide for building, developing, and contributing to cSploit.

## Table of Contents

1. [Quick Start](#quick-start)
2. [Development Environment](#development-environment)
3. [Building & Running](#building--running)
4. [Project Structure](#project-structure)
5. [Helper Utilities](#helper-utilities)
6. [Code Quality Standards](#code-quality-standards)
7. [Contributing](#contributing)

---

## Quick Start

### Prerequisites

- **Android Studio** Arctic Fox (2020.3.1) or newer
- **JDK 17** or newer
- **Git** installed
- **Android device** (rooted recommended for testing)
- **4GB RAM** minimum (8GB recommended)

### Setup in 5 Minutes

```bash
# 1. Clone repository
git clone https://github.com/cSploit/android.git
cd android

# 2. Build the project
./gradlew assembleDebug

# 3. Install on device
./gradlew installDebug
```

### Android Studio Setup

1. Open Android Studio → Click "Open"
2. Select the `android` directory
3. Wait for Gradle sync (2-5 minutes)
4. Build → Make Project
5. Run → Run 'app' (with device connected)

---

## Development Environment

### Requirements

- **Android SDK**: API level 33+
- **Android Build Tools**: 33.0.2+
- **Gradle**: 8.0+
- **JDK**: 17+

### Environment Configuration

Create `local.properties` in project root (for custom SDK path):
```properties
sdk.dir=/path/to/android-sdk
ndk.dir=/path/to/android-ndk
```

### IDE Plugins (Recommended)

- Android Studio built-ins
- Gradle (bundled)
- Git integration (bundled)

---

## Building & Running

### Command Line Builds

```bash
# Debug build (for development)
./gradlew assembleDebug

# Release build (optimized, obfuscated)
./gradlew assembleRelease

# Run all tests
./gradlew test

# Run lint checks
./gradlew lint

# Clean build
./gradlew clean assembleDebug
```

### Android Studio Builds

| Action | Shortcut |
|--------|----------|
| Make Project | Ctrl+F9 / Cmd+F9 |
| Run App | Shift+F10 / Ctrl+R |
| Debug App | Shift+F9 / Cmd+D |
| Build & Run | Ctrl+Shift+F10 / Cmd+Shift+R |

### Device Setup

```bash
# List connected devices
adb devices

# Install app
adb install -r app/build/outputs/apk/debug/app-debug.apk

# View logs (filtered)
adb logcat | grep cSploit

# Push test files to device
adb push test.txt /sdcard/
```

---

## Project Structure

```
android/
├── cSploit/
│   ├── src/
│   │   └── main/
│   │       ├── java/org/csploit/android/
│   │       │   ├── (root)               # Activities & Fragments (Main, Settings, WiFi*)
│   │       │   ├── adapters/            # List adapters
│   │       │   ├── core/                # Core functionality (System, ChildManager, etc.)
│   │       │   ├── events/              # Event classes
│   │       │   ├── gui/                 # Custom UI components
│   │       │   ├── helpers/             # Utility helpers (17 classes)
│   │       │   ├── net/                 # Networking (Target, Network, metasploit RPC)
│   │       │   ├── plugins/             # Feature plugins (PortScanner, MITM, etc.)
│   │       │   ├── services/            # Background services (NetworkRadar, MsfRpcd)
│   │       │   ├── tools/               # Tool wrappers (NMap, Hydra, etc.)
│   │       │   ├── update/              # Update handling
│   │       │   └── wifi/                # WiFi key generators
│   │       ├── res/
│   │       │   ├── layout/              # XML layouts
│   │       │   ├── drawable/            # Drawable resources
│   │       │   ├── values/              # Strings, colors, styles
│   │       │   └── menu/                # Menu definitions
│   │       └── AndroidManifest.xml
│   ├── build.gradle
│   ├── proguard-project.txt            # ProGuard rules
│   └── lint.xml                        # Lint configuration
├── build.gradle                        # Root build config
├── settings.gradle                     # Project settings
└── gradle.properties                   # Gradle properties
```

---

## Helper Utilities

The `org.csploit.android.helpers` package provides **17 reusable utility classes** organized by category:

### Helper Categories Overview

| Category | Count | Purpose |
|----------|-------|---------|
| Core | 3 | Async operations, logging, preferences |
| Network | 3 | Network utilities, HTTP, connection monitoring |
| Security | 3 | Credential storage, encrypted storage, security checks |
| Target | 1 | Scan result export |
| UI | 4 | Toasts, dialogs, animations, PendingIntent |
| System | 3 | Device info, app utilities, thread management |

See **[HELPERS.md](./HELPERS.md)** for complete documentation.

### Common Helpers

#### ConcurrencyHelper
Background task execution with callbacks:
```java
ConcurrencyHelper.executeAsync(
    () -> performLongTask(),
    new ConcurrencyHelper.AsyncCallback<Result>() {
        @Override
        public void onSuccess(Result result) { /* UI update */ }
        
        @Override
        public void onError(Exception e) { /* Error handling */ }
    }
);
```

#### ValidationHelper
Input validation:
```java
if (ValidationHelper.isValidIPv4(ip)) { /* Valid IP */ }
if (ValidationHelper.isValidPort(port)) { /* Valid port */ }
if (ValidationHelper.isValidMacAddress(mac)) { /* Valid MAC */ }
```

#### LoggingHelper
Structured logging:
```java
LoggingHelper.d("TAG", "Debug message");
LoggingHelper.e("TAG", "Error message", exception);
LoggingHelper.logPerformance("TAG", "Operation", durationMs);
```

#### ToastHelper
Toast notifications with emoji indicators:
```java
ToastHelper.success(context, "Operation successful");
ToastHelper.error(context, "Operation failed");
ToastHelper.info(context, "Information");
ToastHelper.warning(context, "Warning");
```

#### SecurityChecker
```java
SecurityChecker.checkRootAccess();
SecurityChecker.isDeviceRooted();
```

#### UIHelper
Dialog and UI utilities:
```java
UIHelper.showErrorDialog(context, "Title", "Message");
UIHelper.showConfirmDialog(context, "Confirm?", listener);
```

#### AnimationHelper
Smooth animations:
```java
AnimationHelper.fadeIn(view, 300);   // 300ms fade in
AnimationHelper.fadeOut(view, 300);  // 300ms fade out
```

#### PendingIntentHelper
Android 12+ compatible PendingIntent creation:
```java
PendingIntent pi = PendingIntentHelper.getActivityImmutable(context, code, intent);
PendingIntent broadcast = PendingIntentHelper.getBroadcastImmutable(context, code, intent);
```

---

## Code Quality Standards

### Naming Conventions

- **Classes**: PascalCase (e.g., `NetworkScanner`)
- **Methods**: camelCase (e.g., `scanNetwork()`)
- **Constants**: UPPER_SNAKE_CASE (e.g., `SCAN_TIMEOUT`)
- **Variables**: camelCase (e.g., `hostList`)

### Code Style

- **Indentation**: 4 spaces (no tabs)
- **Line length**: Max 120 characters
- **Braces**: Opening on same line (Java style)
- **Comments**: JavaDoc for public methods

### Best Practices

✅ **DO:**
- Use helper utilities (ConcurrencyHelper, ValidationHelper, etc.)
- Add proper error logging (LoggingHelper)
- Validate inputs before processing
- Use Java 8+ features (lambdas, streams)
- Include error handling in try-catch blocks
- Use meaningful variable/method names
- Document complex logic with comments

❌ **DON'T:**
- Use deprecated APIs (AsyncTask, Thread.stop())
- Hardcode strings (use strings.xml)
- Suppress exceptions silently
- Create UI on background threads
- Use direct casts without type checking
- Store sensitive data unencrypted

### Code Review Checklist

- [ ] Compiles without errors/warnings
- [ ] Uses appropriate helper utilities
- [ ] Proper error handling with logging
- [ ] No deprecated API usage
- [ ] Input validation present
- [ ] UI operations on main thread only
- [ ] Security best practices followed
- [ ] Tests pass (if applicable)

---

## Contributing

### Before You Start

1. Check [existing issues](https://github.com/cSploit/android/issues)
2. Fork the repository
3. Create feature branch: `git checkout -b feature/description`

### Making Changes

1. Follow code quality standards above
2. Keep commits focused and descriptive
3. Test your changes thoroughly
4. Update documentation if needed

### Commit Messages

Format: `type: description`

**Types:**
- `feat`: New feature
- `fix`: Bug fix
- `refactor`: Code refactoring
- `docs`: Documentation
- `test`: Tests
- `chore`: Build, CI, dependencies

**Example:**
```
feat: add network discovery timeout option
fix: resolve crash on empty network list
refactor: simplify validation logic
```

### Submitting a Pull Request

1. Push to your fork
2. Open Pull Request on GitHub
3. Fill in PR template
4. Respond to review feedback
5. Ensure CI checks pass

### Security Issues

**Do NOT** open public issues for security vulnerabilities.

Email security concerns to maintainers privately and follow responsible disclosure practices.

---

## Additional Resources

- [GitHub Wiki](https://github.com/cSploit/android/wiki)
- [Security Best Practices](./SECURITY.md)
- [Changelog](./CHANGELOG.md)
- [Android Documentation](https://developer.android.com)
- [Build Configuration Reference](./BUILD.md)

---

**Last Updated**: March 2026
**Maintained By**: cSploit Development Team
