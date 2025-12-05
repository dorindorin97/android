# Security Best Practices for cSploit

This document outlines security recommendations for cSploit development and deployment.

## Network Security

### HTTPS Enforcement
The app now includes a Network Security Configuration (`network_security_config.xml`) that:
- Enforces HTTPS by default for all network traffic
- Allows cleartext traffic only for localhost and local network addresses (required for penetration testing)
- Trusts system and user-installed certificates for flexibility in testing environments

### Certificate Pinning (Optional Enhancement)
For production deployments communicating with specific servers, consider implementing certificate pinning:

```xml
<domain-config>
    <domain includeSubdomains="true">api.example.com</domain>
    <pin-set>
        <pin digest="SHA-256">BASE64_ENCODED_PIN_HERE</pin>
        <pin digest="SHA-256">BACKUP_PIN_HERE</pin>
    </pin-set>
</domain-config>
```

## Data Storage

### Sensitive Data
- Never store passwords or API keys in SharedPreferences without encryption
- Use Android Keystore for cryptographic key storage
- Consider EncryptedSharedPreferences for sensitive settings:

```java
MasterKey masterKey = new MasterKey.Builder(context)
    .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
    .build();

SharedPreferences encryptedPrefs = EncryptedSharedPreferences.create(
    context,
    "secure_prefs",
    masterKey,
    EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
    EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
);
```

### External Storage
- Use scoped storage (Android 10+) for better privacy
- Request MANAGE_EXTERNAL_STORAGE only when absolutely necessary
- Store sensitive data in app-specific directories

## Permissions

### Runtime Permissions
Always request permissions at runtime with clear explanations:

```java
if (ContextCompat.checkSelfPermission(this, Manifest.permission.PERMISSION_NAME)
        != PackageManager.PERMISSION_GRANTED) {
    // Show explanation if needed
    if (ActivityCompat.shouldShowRequestPermissionRationale(this, 
            Manifest.permission.PERMISSION_NAME)) {
        // Show explanation dialog
    }
    // Request permission
    ActivityCompat.requestPermissions(this,
            new String[]{Manifest.permission.PERMISSION_NAME},
            REQUEST_CODE);
}
```

### Minimal Permissions
- Request only permissions that are absolutely necessary
- Remove READ_PHONE_STATE if not required
- Use NEARBY_WIFI_DEVICES instead of location permissions when possible

## Code Obfuscation

### R8/ProGuard
The app now uses R8 for release builds with:
- Code optimization enabled
- Resource shrinking enabled
- Comprehensive ProGuard rules in `proguard-rules.pro`
- Log removal in release builds

## Crash Reporting

### ACRA Configuration
Crash reporting is now opt-in and requires user consent:
- Users must explicitly enable crash reporting in settings
- Credentials are stored securely, not hardcoded
- Crash data should be sent over HTTPS only

## Root Access

### SuperSU/Magisk
- Always verify root access before attempting privileged operations
- Handle SecurityException gracefully
- Inform users about risks of running penetration testing tools

## Dependencies

### Regular Updates
- Keep all dependencies up to date for security patches
- Monitor for known vulnerabilities using:
  - GitHub Dependabot
  - OWASP Dependency-Check
  - Snyk or similar tools

### Current Security Considerations
- Apache Commons libraries updated to latest stable versions
- ACRA updated to 5.11.3 (includes security fixes)
- AndroidX libraries use modern, maintained versions

## Build Security

### Signing Configuration
- Never commit keystore files to version control
- Use environment variables for signing credentials
- Store keystores in secure, encrypted locations
- Implement proper key rotation policies

### CI/CD Security
- Use GitHub Actions secrets for sensitive data
- Scan builds for vulnerabilities before release
- Implement branch protection rules
- Require code review for all changes

## API Security

### Metasploit RPC
- Use SSL/TLS for Metasploit RPC connections
- Don't use default credentials (msf/msf)
- Implement proper authentication token management
- Rate limit RPC calls to prevent abuse

### Update Service
- Verify update signatures before installation
- Use HTTPS for all update checks and downloads
- Implement version pinning to prevent rollback attacks

## Logging

### Production Logs
- Remove verbose logging in release builds (handled by ProGuard)
- Never log sensitive data (passwords, tokens, personal info)
- Use appropriate log levels (ERROR for production)

### Debug Logs
- Keep debug logs for development only
- Use BuildConfig.DEBUG to conditionally enable logging

## Testing

### Security Testing
- Perform regular security audits
- Test with latest Android versions
- Verify permission handling on all API levels
- Check for common vulnerabilities (SQL injection, XSS, etc.)

### Penetration Testing
- The app itself should be penetration tested
- Follow OWASP Mobile Security Testing Guide
- Test on both rooted and non-rooted devices

## User Education

### Disclaimers
- Include clear disclaimers about legal usage
- Warn about risks of running on personal devices
- Provide guidance on responsible disclosure
- Include ethical hacking guidelines

## Incident Response

### Security Issues
- Have a clear process for reporting security vulnerabilities
- Respond to reports within 48 hours
- Provide security updates promptly
- Maintain a security advisory process

## Compliance

### Privacy
- Include privacy policy for any data collection
- Comply with GDPR/CCPA where applicable
- Implement data deletion capabilities
- Provide transparency in data handling

### Legal
- Ensure compliance with local laws regarding penetration testing
- Include appropriate disclaimers about authorized use only
- Document legitimate use cases
- Consider insurance for security research

## Recommended Reading

- [OWASP Mobile Security Testing Guide](https://owasp.org/www-project-mobile-security-testing-guide/)
- [Android Security Best Practices](https://developer.android.com/privacy-and-security/security-best-practices)
- [Android App Security Best Practices](https://developer.android.com/topic/security/best-practices)
- [CWE/SANS Top 25 Most Dangerous Software Errors](https://cwe.mitre.org/top25/)
