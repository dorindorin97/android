# Issue Report Template

Please fill out all relevant sections. Issues missing critical information may be closed.

---

## Issue Type

- [ ] Bug Report
- [ ] Feature Request
- [ ] Documentation
- [ ] Performance Issue
- [ ] Security Issue

---

## Bug Reports

### Environment

**Device Information:**
```
Manufacturer & Model: [e.g., Samsung Galaxy S21]
Android Version: [e.g., Android 13]
```

**cSploit Configuration:**
```
cSploit Version: [Check in Settings or About]
BusyBox Installed: [ ] Yes [ ] No
BusyBox Version: [if available]
Rooted: [yes/no]
SuperSU Installed: [ ] Yes [ ] No
```

### Issue Description

**Clear Title**: [One-sentence summary]

**Steps to Reproduce:**
1. [First step]
2. [Second step]
3. [Continue...]

**Expected Behavior:**
[What should happen]

**Actual Behavior:**
[What actually happens]

**Screenshots/Videos:**
[Attach visual evidence if applicable]

### Logs

**Logcat Output** (filtered for cSploit):
```
[Run: adb logcat | grep -i csploit]
[Paste filtered output here]
[Include at least 20 lines of context]
```

**cSploit Logs:**
[If available in app settings]

---

## Feature Requests

### Description
[Clear description of desired feature]

### Use Case
[Why this feature would be useful]

### Proposed Solution (Optional)
[Any suggestions for implementation]

### Alternative Solutions Considered
[Other approaches you've thought about]

---

## Security Issues

⚠️ **DO NOT SUBMIT SECURITY ISSUES PUBLICLY**

Instead:
1. Email security concerns privately to maintainers
2. Include detailed reproduction steps
3. Wait for acknowledgment before public disclosure
4. Follow 90-day responsible disclosure window

See [SECURITY.md](./SECURITY.md) for contact information.

---

## Checklist

Before submitting:

- [ ] Searched existing issues (no duplicates)
- [ ] Updated to latest cSploit version
- [ ] Tested on rooted device with BusyBox
- [ ] Included device info and Android version
- [ ] Provided clear, reproducible steps
- [ ] Attached relevant screenshots/logs
- [ ] Followed code of conduct
- [ ] Security issue handled privately (if applicable)

---

**Thank you for helping improve cSploit!**
