# cSploit: Android Network Penetration Testing Suite

<img src="http://i.imgur.com/cFll5P9.jpg" width="250" />

> **⚠️ Important**: cSploit is intended for **legal security purposes only**. Ensure you own or have permission to test any networks/systems. See [Disclaimer](#disclaimer) for details.

[cSploit](http://www.csploit.org) is a [free/libre](https://gnu.org/philosophy/free-sw.html) and open source (GPLv3) Android network analysis and penetration suite—**the most complete and advanced professional toolkit** for IT security professionals to perform network security assessments on mobile devices.

**Website**: [www.cSploit.org](http://www.csploit.org) | **Wiki**: [GitHub Wiki](https://github.com/cSploit/android/wiki)

## Features

### Core Network Analysis
- 🗺️ **Network Mapping** - Discover and map local networks
- 🔍 **OS Fingerprinting** - Identify operating systems and open ports
- 📍 **Traceroute** - Integrated route tracing to targets
- 🌐 **External Hosts** - Add custom hosts outside local network

### Advanced Exploitation
- ⚔️ **Metasploit Integration** - Integrated Metasploit framework RPC daemon
  - Search for known vulnerabilities on discovered hosts
  - Adjust exploit parameters and launch attacks
  - Create interactive shell sessions on compromised systems
- 🔫 **Packet Forging** - Craft custom TCP/UDP packets

### Man-in-the-Middle (MITM) Attacks
- 🎨 **Content Replacement** - Replace images, text, and videos on unencrypted pages
- 💉 **JavaScript Injection** - Inject custom JavaScript into web pages
- 🔐 **Password Sniffing** - Capture credentials with protocol dissection
- 📦 **Traffic Capture** - Record PCAP network traffic files
- 🚦 **Real-time Manipulation** - Modify traffic on-the-fly
- 🎯 **DNS Spoofing** - Redirect traffic to different domains
- 🔌 **Connection Control** - Hijack or terminate active connections
- 🍪 **Session Hijacking** - Capture unencrypted cookies and clone sessions

## Quick Links

| Link | Purpose |
|------|---------|
| 📖 [Documentation Index](./DOCS_INDEX.md) | **👈 Start here for all docs** |
| 📚 [Development Guide](./DEVELOPMENT_GUIDE.md) | Building, development, and code standards |
| 🚀 [Quick Start](./QUICKSTART.md) | Get started in 5 minutes |
| 🔐 [Security Best Practices](./SECURITY.md) | Security guidelines for development |
| 📋 [Changelog](./CHANGELOG.md) | Version history and updates |
| 🤝 [Contributing Guide](./CONTRIBUTING.md) | How to contribute to cSploit |
| 🛠️ [Helper Utilities](./HELPERS.md) | Helper class documentation |
| 💾 [Improvements Archive](./IMPROVEMENTS_ARCHIVE.md) | Complete improvement history |
| 🏗️ [Build Guide](./BUILD.md) | Build system and configuration |

## Tutorials

<img src="https://i.imgur.com/c0dxvXv.jpg" width="250" />

- 📚 [Get Root Shell on Metasploitable2](https://github.com/cSploit/android/wiki/%5BTutorial%5D-Use-cSploit-to-get-root-shell-on-Metasploitable2)
- 🕵️ [MITM Security Demonstrations](https://github.com/cSploit/android/wiki/%5BTutorial%5D-Use-cSploit-for-simple-Man-In-The-Middle-(MITM)-security-demos)
- 📖 [More on Wiki](https://github.com/cSploit/android/wiki)

## Requirements

### Device Requirements
- ✅ **Rooted Android Device** - Minimum Android 5.0 (API 21), recommended Android 13+ (API 33)
- ✅ **BusyBox** - Full installation with all utilities (not partial)
  - [BusyBox Free](https://play.google.com/store/apps/details?id=stericson.busybox)
  - [BusyBox Installer](https://play.google.com/store/apps/details?id=com.jrummy.busybox.installer)
  - **Note**: cSploit doesn't endorse any specific installer; choose based on your device
- ✅ **SuperSU** - Required for root access management

### Development Requirements
See [Development Guide](./DEVELOPMENT_GUIDE.md) for build environment setup.

## Installation

### Latest Release
- 📥 **[GitHub Releases](https://github.com/cSploit/android/releases)** - Stable versions
- 🔗 **[Direct Link](https://github.com/cSploit/android/releases/latest)** - Latest release

### Nightly Builds
- 🌙 **[Nightly Builds](http://www.csploit.org/downloads)** - Fresh builds from source
  - **Note**: May contain latest features AND latest bugs—use with caution

### Distribution Channels
- 📱 **[F-Droid Official Repository](https://f-droid.org/repository/browse/?fdid=org.csploit.android)** - Open source app store

## Contributing

All contributions are welcome! See [Contributing Guide](./CONTRIBUTING.md) for details.

### Ways to Contribute
- 💻 **Code** - Bug fixes, features, and optimizations
- 📖 **Documentation** - Tutorials, guides, and examples
- 🎨 **Design** - UI/UX improvements and graphics
- 🐛 **Bug Reports** - Issue reports with reproduction steps
- 💡 **Suggestions** - Feature requests and improvement ideas

### Process
1. Check [existing issues](https://github.com/cSploit/android/issues) to avoid duplicates
2. Fork and create a feature branch
3. Follow [code standards](./DEVELOPMENT_GUIDE.md#code-quality-standards)
4. Submit a Pull Request with clear description
5. Respond to review feedback

### Security Issues
**⚠️ Do NOT open public issues for security vulnerabilities.**  
Email maintainers privately and follow responsible disclosure practices.

## License

This program is free software: you can redistribute it and/or modify it under the terms of the **[GNU General Public License v3](https://www.gnu.org/licenses/gpl-3.0.html)** as published by the [Free Software Foundation](https://www.fsf.org/).

## Copyright & Attribution

**Original Author**: Simone Margaritelli (evilsocket)  
**Continued By**: Fused with zANTI2 by @tux-mind  
**Current Contributors**: Community of security researchers and developers

## Support

### Donate
Help support cSploit development:
- 💰 [Pledgie Campaign](https://pledgie.com/campaigns/30393)
- 🏦 [PayPal Donation](https://www.paypal.com/cgi-bin/webscr?cmd=_donations&business=FTKXDCBEDMW9G&lc=GB&item_name=cSploit&currency_code=EUR&bn=PP%2dDonationsBF%3abtn_donate_LG%2egif%3aNonHosted)

### Get Help
- 📖 [Wiki & Tutorials](https://github.com/cSploit/android/wiki)
- 🐛 [Issue Tracker](https://github.com/cSploit/android/issues)
- 💬 [Discussions](https://github.com/cSploit/android/discussions)

## Disclaimer

**⚠️ IMPORTANT - READ CAREFULLY**

cSploit is intended **exclusively for legal security purposes**. You must:

1. ✅ **Own or have explicit written permission** to test any networks/systems
2. ✅ **Comply with all applicable laws** in your jurisdiction
3. ✅ **Understand legal consequences** of unauthorized network testing
4. ✅ **Use responsibly and ethically**

**Unauthorized access to computer systems is illegal** in most jurisdictions. Violators face serious legal penalties including fines and imprisonment.

By using cSploit, you accept **full responsibility** for your actions. The developers assume **no liability** for misuse, damage, or legal consequences resulting from this tool.

---

**Last Updated**: December 5, 2025  
**Status**: Actively Maintained ✅
