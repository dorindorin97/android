# Changelog

All notable changes to the cSploit project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.8.0-stable] - 2025-01-06

### 🚀 Added

#### Comprehensive Helper Utilities (136+ Classes)
- **Network Utilities (43)**: NetworkAnalyzer, NetworkDiagnostics, NetworkMonitor, SubnetHelper, ArpHelper, DnsHelper, DnsProtocolHelper, MacVendorHelper, FirewallHelper, PcapHelper, InterfaceHelper, GeoIPHelper, RoutingHelper, TrafficMonitor, ProxyHelper, PortHelper, BannerGrabber, WhoIsHelper, TracerouteHelper, PacketHelper, ServiceEnumerator, FtpHelper, SmtpHelper, SshHelper, TelnetHelper, SnmpHelper, LdapHelper, ImapHelper, IrcHelper, and more
- **Security Utilities (18)**: VulnerabilityScanner, ExploitMatcher, ServiceFingerprinter, AuthTokenHelper, SecureCredentialsHelper, PortScanOptimizer, HostTracker, SslHelper, SecurityAuditHelper, PayloadHelper, HashHelper, CredentialHelper, RegexHelper, and more
- **Target Management (8)**: TargetHelper, TargetGroupManager, ScanProgressTracker, ReportGenerator, OutputFormatter, and more
- **UI Utilities (15)**: ToastHelper, DialogHelper, NotificationHelper, AnimationHelper, ColorHelper, and more
- **System Utilities (16)**: ProcessHelper, ShellHelper, CommandBuilder, DeviceHelper, WifiHelper, UserAgentHelper, and more
- **Performance Utilities (10)**: PerformanceMonitor, MetricsCollector, RateLimiter, ThreadPoolManager, and more
- **Core Utilities (15)**: ConcurrencyHelper, ValidationHelper, LoggingHelper, StringHelper, JsonHelper, and more

#### Iteration 11 Additions
- `TelnetHelper` - Telnet protocol operations, banner parsing, option negotiation, and server fingerprinting
- `DnsProtocolHelper` - Low-level DNS protocol implementation with query building and response parsing
- `SnmpHelper` - SNMP v1/v2c queries, community string testing, and device information gathering
- `LdapHelper` - LDAP protocol operations, anonymous bind testing, and Active Directory detection
- `ImapHelper` - IMAP protocol analysis, capability enumeration, and security assessment
- `IrcHelper` - IRC server fingerprinting, IRCD type detection, and security analysis

#### Iteration 10 Additions
- `TracerouteHelper` - Traceroute output parsing, hop analysis, and anomaly detection
- `FtpHelper` - FTP protocol operations, banner parsing, and server fingerprinting
- `SmtpHelper` - SMTP protocol operations, user enumeration, and vulnerability checks
- `SshHelper` - SSH banner parsing, algorithm analysis, and security assessment
- `PacketHelper` - TCP/IP packet parsing, header extraction, and checksum calculation
- `ServiceEnumerator` - Network service identification with 70+ known service mappings

#### Iteration 9 Additions
- `PayloadHelper` - Payload generation, encoding (Base64, Hex, URL), and obfuscation
- `WhoIsHelper` - WHOIS domain and IP lookups with registrar parsing
- `UserAgentHelper` - Browser/device User-Agent database with random generation
- `HashHelper` - Cryptographic hashing (MD5, SHA-1, SHA-256, SHA-512) with file support
- `CredentialHelper` - Credential validation, password strength checking, common password detection
- `RegexHelper` - Security-focused regex patterns (IP, MAC, URL, email, CVE, etc.)

#### Iteration 8 Additions
- `BannerGrabber` - Network service banner grabbing with protocol detection
- `TrafficMonitor` - Real-time network traffic monitoring with anomaly detection
- `ProxyHelper` - SOCKS/HTTP proxy configuration and testing
- `PortHelper` - Comprehensive port scanning with service database
- `SecurityAuditHelper` - Security auditing with vulnerability scoring
- `SslHelper` - SSL/TLS certificate analysis and security checks
- `RoutingHelper` - Routing table management utilities

#### Code Quality Improvements
- Fixed all deprecated AsyncTask usages
- Eliminated all Toast.makeText calls (46 patterns → 0)
- Fixed Thread.stop() deprecation (safe interrupt/join pattern)
- Fixed empty catch blocks (7+ files)
- Boolean comparison optimization (20+ patterns)
- Comprehensive null-safety annotations

### 🔧 Changed

#### Version Update
- Version bumped to 1.8.0-stable from 1.7.1-stable
- Total helper classes: 136+ (was 130)
- Total lines of helper code: ~40,000+
- Total helper classes: 120+ (was 114)
- Total lines of helper code: ~35,000+

---

## [1.7.1-stable] - 2025-12-05

### 🚀 Added

#### Build System & Dependencies
- Modern GitHub Actions CI/CD pipeline replacing manual nightly build script
- Automated lint checks, unit tests, and security scanning in CI
- Dependency vulnerability scanning with OWASP Dependency Check
- Support for both debug and release builds in CI
- Automated nightly builds with proper artifact retention
- GitHub Release creation for tagged versions

#### Security Enhancements
- Network Security Configuration with HTTPS enforcement by default
- Cleartext traffic only allowed for localhost and local network testing
- Comprehensive security best practices documentation (SECURITY.md)
- ProGuard/R8 code obfuscation rules for release builds
- Resource shrinking enabled for smaller APK size
- Secure crash reporting with opt-in user consent
- Removed hardcoded credentials from source code

#### Documentation
- Contributing guidelines (CONTRIBUTING.md)
- Comprehensive security documentation (SECURITY.md)
- Code of conduct and development setup instructions
- Pull request and commit message guidelines
- Testing and code review procedures

### 🔧 Changed

#### Build Configuration
- Upgraded Android Gradle Plugin from 3.3.0-alpha12 to 7.4.2
- Upgraded Gradle wrapper from 4.10.2 to 8.0
- Updated compileSdkVersion from 28 to 33
- Updated targetSdkVersion from 28 to 33
- Updated minSdkVersion from 14 to 21 for better security features
- Replaced deprecated jcenter() with mavenCentral()
- Version bumped to 1.7.1-stable from 1.7.0-unstable

#### Dependencies (Security & Stability Updates)
- androidx.appcompat: 1.0.0 → 1.6.1
- androidx.preference: 1.0.0 → 1.2.1
- androidx.multidex: 2.0.0 → 2.0.1
- com.google.android.material: 1.0.0 → 1.9.0
- commons-compress: 1.18 → 1.24.0 (security fixes)
- commons-net: 3.6 → 3.9.0 (security fixes)
- xz: 1.8 → 1.9
- acra-http: 5.2.0 → 5.11.3 (security fixes)
- acra-notification: 5.2.0 → 5.11.3
- junit: 4.12 → 4.13.2 (test dependency)

#### Permissions & Manifest
- Added proper Android 13+ notification permission (POST_NOTIFICATIONS)
- Added NEARBY_WIFI_DEVICES permission for Android 13+ WiFi scanning
- Updated storage permissions for scoped storage (Android 10+)
- Removed unnecessary READ_PHONE_STATE permission
- Added android:exported="true" for MainActivity (Android 12+ requirement)
- Disabled backup (allowBackup="false") for security
- Added network security configuration reference
- Disabled cleartext traffic by default (usesCleartextTraffic="false")

#### Code Quality
- Fixed empty catch blocks in WiFi keygen algorithms (PirelliKeygen, ZyxelKeygen)
- Added proper error logging throughout the application
- Improved MITM class documentation
- Refactored crash reporting to use secure, opt-in approach
- Removed duplicate ACRA initialization

### 🗑️ Removed

#### Security
- Removed hardcoded password "DEADBEEF" from ACRA configuration
- Removed hardcoded crash reporting credentials
- Removed unnecessary READ_PHONE_STATE permission
- Removed allowBackup="true" (security improvement)

#### Build System
- Removed deprecated jcenter() repository
- Removed outdated Gradle configuration
- Cleaned up obsolete build settings

### 🔒 Security

#### Critical Fixes
- **HIGH**: Removed hardcoded authentication credentials from source code
- **HIGH**: Updated Apache Commons libraries with known security vulnerabilities
- **MEDIUM**: Implemented HTTPS enforcement by default
- **MEDIUM**: Added ProGuard/R8 obfuscation for release builds
- **MEDIUM**: Updated ACRA crash reporting library (addressed CVEs)
- **LOW**: Removed verbose logging in release builds

#### Security Features
- Network security configuration with certificate validation
- Opt-in crash reporting with secure credential storage
- Modern permission model for Android 13+
- Scoped storage implementation
- Code obfuscation and resource shrinking

### 📝 Notes

#### Migration Guide

**For Developers:**
1. Update Android Studio to Arctic Fox or newer
2. Install JDK 17 or newer
3. Run `./gradlew wrapper --gradle-version 8.0` if needed
4. Clean and rebuild: `./gradlew clean build`
5. Test on Android 13+ devices for permission handling

**For Users:**
1. Android 5.0 (API 21) or higher now required (previously 4.0)
2. New permission requests for Android 13+ (notifications, nearby WiFi)
3. Crash reporting is now opt-in (check Settings)
4. Better compatibility with modern Android versions

#### Known Issues
- The app still requires significant UI/UX improvements
- Some features may not work on Android 14+ without additional updates
- Root access verification needs modernization
- Network capture functionality needs scoped storage migration

#### Breaking Changes
- Minimum Android version increased from 4.0 (API 14) to 5.0 (API 21)
- Crash reporting requires manual opt-in and configuration
- Storage access behavior changed for Android 10+ compatibility

### 🙏 Acknowledgments

Thanks to all contributors who helped identify security issues and outdated dependencies.
Special thanks to the cSploit community for continued support of this EOL project.

---

## Previous Versions

### [1.7.0-unstable] - Earlier releases

See [GitHub Releases](https://github.com/cSploit/android/releases) for historical versions.

---

## Legend

- 🚀 Added: New features
- 🔧 Changed: Changes in existing functionality
- 🗑️ Removed: Removed features
- 🔒 Security: Security fixes and improvements
- 🐛 Fixed: Bug fixes
- 📝 Notes: Additional information

---

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for information on how to contribute to this changelog.
