# Quick Reference Card

Essential commands, links, and information for cSploit developers.

## 🔗 Documentation

| Need | Link |
|------|------|
| **Where to start** | [DOCS_INDEX.md](./DOCS_INDEX.md) |
| **5-minute setup** | [QUICKSTART.md](./QUICKSTART.md) |
| **Development setup** | [DEVELOPMENT_GUIDE.md](./DEVELOPMENT_GUIDE.md) |
| **Build system** | [BUILD.md](./BUILD.md) |
| **Code standards** | [DEVELOPMENT_GUIDE.md#code-quality-standards](./DEVELOPMENT_GUIDE.md#code-quality-standards) |
| **Contributing** | [CONTRIBUTING.md](./CONTRIBUTING.md) |
| **Security** | [SECURITY.md](./SECURITY.md) |

## 💻 Quick Commands

### Build
```bash
# Debug build
./gradlew assembleDebug

# Release build
./gradlew assembleRelease

# Clean build
./gradlew clean assembleDebug

# Run tests
./gradlew test
```

### Git
```bash
# Create feature branch
git checkout -b feature/description

# Commit with good message
git commit -m "type: description"

# Push changes
git push origin feature/description

# Create PR on GitHub
# Visit: github.com/cSploit/android/compare/develop...feature/description
```

### ADB (Device)
```bash
# List devices
adb devices

# Install app
adb install -r app/build/outputs/apk/debug/app-debug.apk

# View logs
adb logcat | grep cSploit

# Run adb as root
adb root
```

## 📁 Project Structure

```
android/
├── cSploit/
│   ├── src/main/java/org/csploit/android/
│   │   ├── activities/      ← UI screens
│   │   ├── fragments/       ← UI fragments
│   │   ├── helpers/         ← Utilities ⭐
│   │   ├── plugins/         ← Plugin code
│   │   ├── net/             ← Network code
│   │   └── services/        ← Background services
│   ├── src/main/res/
│   │   ├── layout/          ← XML layouts
│   │   ├── drawable/        ← Images
│   │   └── values/          ← Strings, colors
│   └── build.gradle
├── README.md
└── DOCS_INDEX.md            ← Start here!
```

## ✅ Before Submitting Code

- [ ] Compiles without errors: `./gradlew clean assembleDebug`
- [ ] Uses appropriate helper classes (ConcurrencyHelper, ValidationHelper, etc.)
- [ ] Has proper error logging (LoggingHelper, not silent catch blocks)
- [ ] No deprecated APIs used
- [ ] Input validation present
- [ ] Tests pass: `./gradlew test`
- [ ] Follows naming conventions (PascalCase classes, camelCase methods)
- [ ] Code is readable with meaningful names
- [ ] Commit message is descriptive: `type: description`

## 🔍 Helper Classes

| Helper | Use | Example |
|--------|-----|---------|
| **ConcurrencyHelper** | Background tasks | `ConcurrencyHelper.executeAsync(...)` |
| **ValidationHelper** | Input validation | `ValidationHelper.isValidIPv4(ip)` |
| **LoggingHelper** | Logging | `LoggingHelper.d("TAG", "msg")` |
| **ToastHelper** | Toast messages | `ToastHelper.success(ctx, "OK")` |
| **UIHelper** | Dialogs, UI | `UIHelper.showErrorDialog(...)` |
| **AnimationHelper** | Animations | `AnimationHelper.fadeIn(view, 300)` |

See [HELPERS.md](./HELPERS.md) for complete documentation.

## 🏗️ Gradle Build Types

| Build Type | Debug | Optimized | Size | Usage |
|-----------|-------|-----------|------|-------|
| **Debug** | ✅ | ❌ | Large | Development |
| **Release** | ❌ | ✅ | Small | Distribution |

## 📋 File Locations

| What | Where |
|------|-------|
| App manifest | `cSploit/src/main/AndroidManifest.xml` |
| Build config | `cSploit/build.gradle` |
| Gradle config | `build.gradle`, `settings.gradle` |
| ProGuard rules | `cSploit/proguard-project.txt` |
| String resources | `cSploit/src/main/res/values/strings.xml` |
| Layout files | `cSploit/src/main/res/layout/` |

## 🔧 Android Studio Shortcuts

| Action | Shortcut |
|--------|----------|
| Make project | Ctrl+F9 / Cmd+F9 |
| Run app | Shift+F10 / Cmd+R |
| Debug app | Shift+F9 / Cmd+D |
| Reformat code | Ctrl+Alt+L / Cmd+Alt+L |
| Find usages | Alt+F7 / Option+F7 |
| Go to definition | Ctrl+Click / Cmd+Click |

## 🚀 Version Info

| Component | Version |
|-----------|---------|
| **Gradle** | 8.0 |
| **AGP** | 7.4.2 |
| **Min SDK** | 21 (Android 5.0) |
| **Target SDK** | 33 (Android 13) |
| **JDK** | 17+ |
| **cSploit** | 1.7.1-stable |

## 🔗 External Resources

- **[Android Docs](https://developer.android.com)** - Official Android documentation
- **[Gradle Docs](https://gradle.org/docs/)** - Gradle build system
- **[GitHub](https://github.com/cSploit/android)** - Repository
- **[Wiki](https://github.com/cSploit/android/wiki)** - Community wiki
- **[Issues](https://github.com/cSploit/android/issues)** - Bug tracker

## 💡 Tips & Tricks

### Finding Code
```bash
# Find all usage of a class
grep -r "ClassName" cSploit/src/

# Find methods matching pattern
grep -r "methodName" cSploit/src/ | grep -v "\.xml"

# Find TODOs in code
grep -r "TODO" cSploit/src/
```

### Testing
```bash
# Run single test
./gradlew testDebugUnitTest --tests "org.csploit.android.MyTest"

# Run with coverage
./gradlew test --coverage

# Check test results
cat cSploit/build/test-results/testDebugUnitTest/
```

### Performance
```bash
# Profile build
./gradlew assembleDebug --profile

# Show dependency tree
./gradlew dependencies

# Check for vulnerabilities
./gradlew dependencyCheck
```

## ⚠️ Common Issues & Fixes

| Issue | Solution |
|-------|----------|
| Build fails | `./gradlew clean assembleDebug` |
| Gradle cache issue | `rm -rf .gradle/` then rebuild |
| SDK mismatch | Update SDK or check `build.gradle` |
| Memory error | Increase heap: add `org.gradle.jvmargs=-Xmx4096m` to `gradle.properties` |
| Deprecated warning | Check [CODE_QUALITY_IMPROVEMENTS.md](./CODE_QUALITY_IMPROVEMENTS.md) |

## 📞 Getting Help

1. **Check documentation** → [DOCS_INDEX.md](./DOCS_INDEX.md)
2. **Search issues** → [GitHub Issues](https://github.com/cSploit/android/issues)
3. **Ask on GitHub** → [GitHub Discussions](https://github.com/cSploit/android/discussions)
4. **Security issue** → Email maintainers privately (see [SECURITY.md](./SECURITY.md))

---

**Print this page or save as bookmark!** 🚀

**Last Updated**: December 5, 2025  
**Maintained By**: cSploit Development Team
