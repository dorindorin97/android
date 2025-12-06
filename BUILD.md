# Build Configuration Guide

Complete guide to cSploit build system, configuration, and customization.

## Table of Contents

1. [Overview](#overview)
2. [Gradle Configuration](#gradle-configuration)
3. [Build Variants](#build-variants)
4. [Advanced Configuration](#advanced-configuration)
5. [Troubleshooting](#troubleshooting)

---

## Overview

cSploit uses **Gradle 8.0** with **Android Gradle Plugin 7.4.2** for modern, efficient builds.

### Key Configuration Files

| File | Purpose |
|------|---------|
| `build.gradle` | Root build configuration |
| `settings.gradle` | Project structure and plugin management |
| `gradle.properties` | Global Gradle properties and defaults |
| `cSploit/build.gradle` | App module-specific configuration |
| `gradle/wrapper/gradle-wrapper.properties` | Gradle version specification |

---

## Gradle Configuration

### Root build.gradle

```gradle
plugins {
    id 'com.android.application' version '7.4.2'
    id 'com.android.library' version '7.4.2'
}

allprojects {
    repositories {
        google()
        mavenCentral()
    }
}
```

### App Module build.gradle

```gradle
android {
    namespace 'org.csploit.android'
    
    compileSdkVersion 33
    buildToolsVersion '33.0.2'
    
    defaultConfig {
        applicationId 'org.csploit.android'
        minSdkVersion 21
        targetSdkVersion 33
        versionCode 1710
        versionName '1.7.1-stable'
    }
    
    buildTypes {
        debug {
            debuggable true
            minifyEnabled false
        }
        
        release {
            debuggable false
            minifyEnabled true
            shrinkResources true
            proguardFiles getDefaultProguardFile('proguard-android-optimize.txt'), 'proguard-project.txt'
        }
    }
}
```

### gradle.properties

```properties
# Project properties
org.gradle.jvmargs=-Xmx4096m
org.gradle.daemon=true
org.gradle.parallel=true
org.gradle.caching=true

# SDK versions
android.compileSdkVersion=33
android.buildToolsVersion=33.0.2

# Feature flags
android.useAndroidX=true
android.enableJetifier=true
```

---

## Build Variants

### Debug Build

Unoptimized build for development and testing:

```bash
# Via Gradle
./gradlew assembleDebug

# Via Android Studio
Build → Make Project (Ctrl+F9)
Run → Run 'app' (Shift+F10)
```

**Characteristics:**
- Debuggable (can attach debugger)
- No optimization
- No obfuscation
- Larger APK size
- Fast build time

### Release Build

Optimized and obfuscated build for distribution:

```bash
# Via Gradle
./gradlew assembleRelease

# Via Android Studio (requires signing configuration)
Build → Build Bundle(s) / APK(s) → Build APK(s)
```

**Characteristics:**
- Not debuggable
- R8 optimization enabled
- ProGuard obfuscation applied
- Resource shrinking enabled
- Smaller APK size
- Longer build time

### Build Outputs

```
cSploit/build/outputs/
├── apk/
│   ├── debug/
│   │   └── app-debug.apk
│   └── release/
│       └── app-release.apk
└── bundle/
    └── release/
        └── app-release.aab
```

---

## Advanced Configuration

### Signing Configuration

Create `keystore.properties` for automated signing:

```properties
# ~/.gradle/gradle.properties or project root/keystore.properties
storeFile=/path/to/keystore.jks
storePassword=your_keystore_password
keyAlias=your_key_alias
keyPassword=your_key_password
```

Configure in `build.gradle`:

```gradle
android {
    // ... existing config ...
    
    signingConfigs {
        release {
            storeFile = file(project.property('storeFile'))
            storePassword = project.property('storePassword')
            keyAlias = project.property('keyAlias')
            keyPassword = project.property('keyPassword')
        }
    }
    
    buildTypes {
        release {
            signingConfig signingConfigs.release
        }
    }
}
```

### ProGuard Configuration

ProGuard rules for release builds in `proguard-project.txt`:

```proguard
# Keep application classes
-keep class org.csploit.android.** { *; }

# Keep helper utilities
-keep class org.csploit.android.helpers.** { *; }

# Keep native methods
-keepclasseswithmembernames class * {
    native <methods>;
}

# Keep custom views
-keep public class * extends android.view.View {
    public <init>(android.content.Context);
    public <init>(android.content.Context, android.util.AttributeSet);
    public <init>(android.content.Context, android.util.AttributeSet, int);
}

# Keep enums
-keepclassmembers enum * {
    public static **[] values();
    public static ** valueOf(java.lang.String);
}

# Keep Metasploit RPC classes
-keep class * implements java.io.Serializable { *; }
```

### Dependency Management

Check dependency tree:

```bash
./gradlew dependencies
./gradlew dependencyInsight --dependency commons-net
```

Update dependencies:

```bash
./gradlew dependencyUpdates
```

---

## Build Commands

### Complete Build Tasks

```bash
# Full debug build
./gradlew clean assembleDebug

# Full release build
./gradlew clean assembleRelease

# Build and install debug
./gradlew installDebug

# Build and install release
./gradlew installRelease

# Build with verbose output
./gradlew assembleDebug --info

# Build with debug output
./gradlew assembleDebug --debug
```

### Testing & Verification

```bash
# Run all tests
./gradlew test

# Run specific test
./gradlew testDebugUnitTest

# Run lint checks
./gradlew lint

# Check dependencies
./gradlew dependencies

# Generate dependency report
./gradlew dependencyReport
```

### Continuous Integration

```bash
# Build without daemon (for CI/CD)
./gradlew assembleDebug --no-daemon

# Build with coverage
./gradlew testDebugUnitTest --coverage

# Build and fail on warnings
./gradlew build -Dorg.gradle.warning.mode=fail
```

---

## Performance Optimization

### Build Speed

```properties
# gradle.properties
org.gradle.jvmargs=-Xmx4096m -XX:MaxMetaspaceSize=512m
org.gradle.daemon=true
org.gradle.parallel=true
org.gradle.caching=true
org.gradle.configuration-cache=true
```

### Incremental Build

```bash
# Only rebuild changed modules
./gradlew assembleDebug --continue

# Build without tests
./gradlew assembleDebug -x test

# Parallel build
./gradlew assembleDebug --parallel
```

---

## Troubleshooting

### Common Issues

#### Build Fails with SDK Version Mismatch

```
Error: Minimum supported Gradle version is X.X. You are currently using X.X
```

**Solution:**
```bash
# Update Gradle wrapper
./gradlew wrapper --gradle-version 8.0

# Or manually edit gradle/wrapper/gradle-wrapper.properties
distributionUrl=https://services.gradle.org/distributions/gradle-8.0-bin.zip
```

#### Out of Memory During Build

```
Error: Java heap space
```

**Solution:**
```properties
# gradle.properties
org.gradle.jvmargs=-Xmx4096m
```

#### Resource Compilation Fails

```
Error: failed to link references
```

**Solution:**
```bash
# Clean and rebuild
./gradlew clean assembleDebug

# Clear caches
rm -rf .gradle/
./gradlew clean assembleDebug
```

#### ProGuard Build Failures

```
Error: can't find superclass or interface
```

**Solution:** Add keep rules to `proguard-project.txt`

```proguard
-dontwarn java.lang.invoke.**
-keep class java.lang.invoke.** { *; }
```

### Debug Commands

```bash
# Show Gradle configuration
./gradlew properties

# Show build info
./gradlew -v

# Parallel execution analysis
./gradlew assembleDebug --profile

# Generate build cache analysis
./gradlew assembleDebug --build-cache --info | grep "cache"
```

---

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Build

on: [push, pull_request]

jobs:
  build:
    runs-on: ubuntu-latest
    
    steps:
    - uses: actions/checkout@v3
    
    - name: Set up JDK
      uses: actions/setup-java@v3
      with:
        java-version: '17'
        distribution: 'temurin'
    
    - name: Build
      run: ./gradlew assembleDebug
    
    - name: Test
      run: ./gradlew test
    
    - name: Lint
      run: ./gradlew lint
```

---

## Additional Resources

- [Gradle Documentation](https://gradle.org/docs/)
- [Android Gradle Plugin Guide](https://developer.android.com/studio/build)
- [ProGuard Manual](https://www.guardsquare.com/proguard/manual)

---

**Last Updated**: December 6, 2025  
**Version**: 1.8.0-stable  
**Gradle Version**: 8.0  
**AGP Version**: 7.4.2
