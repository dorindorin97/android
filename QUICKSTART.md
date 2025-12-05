# 🚀 Quick Start Guide - cSploit Development

This guide will get you up and running with cSploit development in minutes.

## Prerequisites

Before you begin, ensure you have:

- ✅ **Android Studio** Arctic Fox (2020.3.1) or newer
- ✅ **JDK 17** or newer
- ✅ **Git** installed
- ✅ **Android device** (rooted recommended for full testing)
- ✅ **4GB RAM** minimum (8GB recommended)

## 🏁 Initial Setup (5 minutes)

### 1. Clone the Repository

```bash
git clone https://github.com/cSploit/android.git
cd android
```

### 2. Open in Android Studio

1. Launch Android Studio
2. Click **"Open"** (not "Import")
3. Navigate to and select the `android` directory
4. Click **OK**
5. Wait for Gradle sync (may take 2-5 minutes)

### 3. Configure Android SDK

Android Studio should prompt you to install missing SDK components. Accept all:
- Android SDK Platform 33
- Android SDK Build-Tools 33.0.2
- Android SDK Platform-Tools
- Android Emulator (optional)

## 🔨 Building the App

### Option A: Using Android Studio (Recommended)

1. Click **Build** → **Make Project** (Ctrl+F9 / Cmd+F9)
2. Wait for build to complete
3. Connect your device via USB
4. Click **Run** → **Run 'app'** (Shift+F10 / Ctrl+R)

### Option B: Using Command Line

```bash
# Debug build
./gradlew assembleDebug

# Install on connected device
./gradlew installDebug

# Build + Install + Run
./gradlew installDebug && adb shell am start -n org.csploit.android/.MainActivity
```

## 🧪 Testing

### Run Unit Tests

```bash
./gradlew test
```

### Run Lint Checks

```bash
./gradlew lint
```

### View Test Reports

After running tests:
```bash
# Linux/Mac
open cSploit/build/reports/tests/testDebugUnitTest/index.html

# Windows
start cSploit/build/reports/tests/testDebugUnitTest/index.html
```

## 📱 Running on Device

### Enable Developer Options

1. Go to **Settings** → **About Phone**
2. Tap **Build Number** 7 times
3. Go back to **Settings** → **Developer Options**
4. Enable **USB Debugging**

### Connect & Verify

```bash
# Check device is connected
adb devices

# You should see something like:
# List of devices attached
# ABC123XYZ    device
```

### Install & Run

```bash
# Install the APK
./gradlew installDebug

# Launch the app
adb shell am start -n org.csploit.android/.MainActivity
```

## 🐛 Debugging

### View Logs

```bash
# View all logs
adb logcat

# Filter cSploit logs only
adb logcat | grep cSploit

# Clear logs first
adb logcat -c && adb logcat | grep cSploit
```

### Debug in Android Studio

1. Set breakpoints by clicking left margin of code editor
2. Click **Run** → **Debug 'app'** (Shift+F9 / Ctrl+D)
3. When breakpoint hits, use debug panel to inspect variables

## 🔧 Common Issues & Solutions

### Issue: "Gradle sync failed"

**Solution:**
```bash
# Clean project
./gradlew clean

# Delete .gradle folders
rm -rf .gradle
rm -rf cSploit/.gradle

# Sync again
./gradlew build --refresh-dependencies
```

### Issue: "SDK not found"

**Solution:**
1. Open **File** → **Project Structure**
2. Ensure **Android SDK Location** is set correctly
3. Click **Apply** and **OK**

### Issue: "Device not authorized"

**Solution:**
1. Check device screen for authorization prompt
2. Tap **Allow**
3. Check "Always allow from this computer"
4. Run `adb devices` again

### Issue: "Build failed with Java version error"

**Solution:**
1. Open **File** → **Settings** → **Build, Execution, Deployment** → **Build Tools** → **Gradle**
2. Set **Gradle JDK** to JDK 17 or newer
3. Click **Apply** and rebuild

### Issue: "Out of memory during build"

**Solution:**
Add to `gradle.properties`:
```properties
org.gradle.jvmargs=-Xmx4096m -XX:MaxMetaspaceSize=512m
```

## 📚 Project Structure Quick Reference

```
android/
├── cSploit/
│   ├── src/main/java/          # Java source code
│   │   └── org/csploit/android/
│   │       ├── core/           # Core functionality
│   │       ├── plugins/        # Feature plugins
│   │       ├── gui/            # UI components
│   │       └── tools/          # Tool wrappers
│   ├── src/main/res/           # Resources
│   │   ├── layout/            # XML layouts
│   │   ├── drawable/          # Images & icons
│   │   └── values/            # Strings, colors, etc.
│   └── build.gradle           # Module build config
├── build.gradle               # Root build config
└── gradle.properties          # Gradle settings
```

## 🎯 Next Steps

1. ✅ Read [CONTRIBUTING.md](CONTRIBUTING.md) for contribution guidelines
2. ✅ Check [SECURITY.md](SECURITY.md) for security best practices
3. ✅ Review [CHANGELOG.md](CHANGELOG.md) for recent changes
4. ✅ Look at existing issues on GitHub
5. ✅ Join the community discussions

## 💡 Useful Commands

```bash
# Clean build
./gradlew clean build

# Debug build with full logging
./gradlew assembleDebug --info

# List all Gradle tasks
./gradlew tasks

# Update Gradle wrapper
./gradlew wrapper --gradle-version 8.0

# Generate release APK (requires signing config)
./gradlew assembleRelease

# Check for dependency updates
./gradlew dependencyUpdates

# Code coverage report
./gradlew jacocoTestReport
```

## 🆘 Getting Help

If you're stuck:

1. **Check Documentation**
   - README.md
   - CONTRIBUTING.md
   - Wiki pages

2. **Search Issues**
   - [Open Issues](https://github.com/cSploit/android/issues)
   - [Closed Issues](https://github.com/cSploit/android/issues?q=is%3Aissue+is%3Aclosed)

3. **Ask for Help**
   - Create a new issue with "question" label
   - Include error messages and logs
   - Describe what you've tried

4. **Common Resources**
   - [Android Developer Docs](https://developer.android.com)
   - [Gradle Documentation](https://docs.gradle.org)
   - [Stack Overflow](https://stackoverflow.com/questions/tagged/android)

## 🎉 Success!

You're now ready to develop cSploit! Happy hacking! 🔐

---

**Pro Tip:** Keep Android Studio and dependencies updated for the best experience.

**Security Reminder:** Only use cSploit on networks you own or have permission to test!
