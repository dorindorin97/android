# TODO/FIXME Quick Reference Guide

Quick lookup table for all TODO/FIXME items with links to code and documentation.

## By Priority

### 🔴 High Priority (Address Soon)
| Item | File | Line | Issue | Notes |
|------|------|------|-------|-------|
| Target Index Bug | MultiAttackService.java | 271 | Array index out of bounds risk | Architecture refactor needed |

### 🟡 Medium Priority (Plan for Next Phase)
| Item | File | Line | Issue | Notes |
|------|------|------|-------|-------|
| MeterpreterSession | RPCClient.java | 220 | Missing meterpreter functionality | Requires new class implementation |
| msgpack MAP Issue | RPCClient.java | 290 | Silent data loss on deserialization | Library issue; logging added |
| msgpack ARRAY Issue | RPCClient.java | 345 | Silent data loss on deserialization | Library issue; logging added |
| Observable for Models | Search.java | 19 | Manual item update notifications | Architecture improvement |
| MsfModule Base Class | Payload.java | 13 | Code duplication across module types | Refactoring to DRY |
| Hardware Address | Network.java | 345 | Unreliable on some Android versions | Low risk; graceful fallback |

### 🟢 Low Priority (Nice to Have)
| Item | File | Line | Issue | Notes |
|------|------|------|-------|-------|
| Observer Pattern | ExploitFinder.java | 409 | Manual RPC change callbacks | Code quality improvement |
| Ettercap Events | Ettercap.java | 58 | Tool limitation; only onAccount() | Expected behavior |
| TcpDump Output | TcpDump.java | 56 | No live output with file save | Enhancement only |
| Non-String Enums | Option.java | 61 | Integer enums not supported | Partially resolved |
| Type-Safe setValue | Option.java | 107 | Only string-based setter | API improvement |
| Integer Enum Handling | Option.java | 133 | Integer enum validation | Partially resolved |
| Cloudflare Bypass | ExploitDb.java | 69 | OSVDB locked behind CF | Low impact enhancement |

---

## By Category

### Architecture (3 items)
- **MultiAttackService.java:271** - Index-based target reference
- **Search.java:19** - Observable pattern for models
- **Payload.java:13** - MsfModule base class extraction

### Bug/Issue (3 items)
- **Network.java:345** - Hardware address (#831)
- **RPCClient.java:290** - msgpack MAP deserialization
- **RPCClient.java:345** - msgpack ARRAY deserialization

### Feature Gap (1 item)
- **RPCClient.java:220** - MeterpreterSession missing

### Enhancement (4 items)
- **ExploitFinder.java:409** - Observer pattern
- **TcpDump.java:56** - Live output with file save
- **Option.java:61** - Non-string enum support
- **ExploitDb.java:69** - Cloudflare bypass

### Tool Limitation (1 item)
- **Ettercap.java:58** - Tool-specific event limitation

### Code Quality (2 items)
- **Option.java:107** - Type-specific setters
- **Option.java:133** - Integer enum validation

---

## By File

### MultiAttackService.java
- **Line 271:** TODO - Target index architecture issue

### Network.java
- **Line 345:** FIXME #831 - Hardware address unreliable

### ExploitDb.java
- **Line 69:** TODO - Cloudflare bypass for OSVDB

### ExploitFinder.java
- **Line 409:** TODO - Observer pattern refactoring

### Ettercap.java
- **Line 58:** TODO - Tool limitation; ettercap events

### TcpDump.java
- **Line 56:** TODO - Live output with file save

### Search.java
- **Line 19:** TODO - Observable pattern for models

### Payload.java
- **Line 13:** TODO - MsfModule base class extraction

### RPCClient.java
- **Line 220:** TODO - MeterpreterSession implementation
- **Line 290:** FIXME - msgpack-java-0.7 MAP issue
- **Line 345:** FIXME - msgpack-java-0.7 ARRAY issue

### Option.java
- **Line 61:** TODO - Non-string enum support (Partially resolved)
- **Line 107:** TODO - Type-specific setValue methods
- **Line 133:** TODO - Integer enum handling (Partially resolved)

---

## Resolution Status

### Fully Documented ✅
All 14 items have comprehensive documentation with:
- Problem statement
- Current workaround
- Proposed solution
- Impact assessment

### Partially Resolved ✅
- **Option.java:61** - Enhanced to support both String and Integer enums
- **Option.java:133** - Improved ENUM validation for mixed types
- **RPCClient.java:290,345** - Added warning logging for silent failures

### Enhanced with Logging ✅
- **RPCClient.java** - msgpack exceptions now logged (was silently ignored)

### Awaiting Implementation
- All others documented and ready for future work

---

## Related Documentation

- **Full Analysis:** See `TODO_FIXME_ANALYSIS_SUMMARY.md`
- **In-Code Comments:** Enhanced in all affected files
- **Session Summary:** Available in `SESSION_SUMMARY.txt` and `CODE_QUALITY_IMPROVEMENTS.md`

---

## Common Themes

### Architectural Improvements Needed (3 items)
1. Replace array indices with persistent IDs (MultiAttackService)
2. Implement Observer pattern (Search, ExploitFinder)
3. Extract base class (Payload - MsfModule)

### External Constraints (2 items)
1. Library issue in msgpack-java-0.7 (RPCClient)
2. Tool limitation in ettercap (Ettercap)

### API Enhancements (3 items)
1. Type-specific methods (Option)
2. Support for mixed types (Option enums)
3. Observable pattern (ExploitFinder)

### Feature Gaps (2 items)
1. MeterpreterSession missing (RPCClient)
2. Live output with file save (TcpDump)

---

## Next Steps

### Immediate (Current Sprint)
- Review enhanced comments in source code
- Assess feasibility of partial resolutions
- Plan msgpack library upgrade evaluation

### Short Term (1-2 Sprints)
- Implement MeterpreterSession class
- Add type-specific Option setters
- Extract MsfModule base class

### Medium Term (2-3 Sprints)
- Refactor MultiAttackService for ID-based references
- Implement Observable pattern for Search models
- Implement Observer pattern for RPC changes

### Long Term (Future)
- Evaluate external integrations (OSVDB, Cloudflare)
- TcpDump pipe-based approach
- Tool-specific event handling improvements

---

## Statistics

- **Total Items:** 14
- **High Priority:** 1 (7%)
- **Medium Priority:** 6 (43%)
- **Low Priority:** 7 (50%)
- **High Impact:** 3 (21%)
- **Medium Impact:** 5 (36%)
- **Low Impact:** 6 (43%)
- **Partially Resolved:** 2 (14%)
- **Enhanced:** 2 (14%)
- **Fully Documented:** 14 (100%)

---

## Search Commands

Find TODO/FIXME in source code:
```bash
# All TODOs and FIXMEs
grep -rn "TODO\|FIXME" cSploit/src/main/java --include="*.java"

# Only TODOs
grep -rn "TODO:" cSploit/src/main/java --include="*.java"

# Only FIXMEs
grep -rn "FIXME:" cSploit/src/main/java --include="*.java"

# By priority (look for HIGH, MEDIUM, LOW in comments)
grep -rn "TODO.*High\|FIXME.*High" cSploit/src/main/java --include="*.java"
```

---

Generated: December 5, 2025
Last Updated: TODO/FIXME Enhancement Phase
