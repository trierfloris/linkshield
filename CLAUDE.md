# LinkShield - Development Documentation

## Project Overview

**LinkShield** is a Chrome browser extension that protects users from phishing, malicious links, and various web-based attacks. It provides real-time security warnings for suspicious URLs, visual hijacking attempts, form hijacking, and more.

**Current Version:** 8.3.2
**Manifest Version:** 3

---

## Architecture

### Main Components

| File | Purpose |
|------|---------|
| `manifest.json` | Extension configuration and permissions |
| `content.js` | Main content script - runs on all pages (ISOLATED world) |
| `background.js` | Service worker for background tasks |
| `popup.js` | Extension popup UI logic |
| `dynamic.js` | Dynamic page handling |
| `config.js` | Configuration settings |
| `alert.js` | Alert page logic |
| `caution.js` | Caution page logic |

### Data Files

| File | Purpose |
|------|---------|
| `TrustedDomains.json` | Regex patterns for trusted domains |
| `trustedIframes.json` | Trusted iframe sources |
| `trustedScripts.json` | Trusted script sources |
| `rules.json` | DeclarativeNetRequest rules |

### Internationalization

24 locale files in `_locales/` directory supporting: ar, bn, de, en, es, fr, hi, id, it, ja, ko, nl, pl, pt, ru, th, tr, uk, vi, zh_CN, zh_TW, and more.

---

## Recent Implementations

### v8.3.2 - Smart Link Scanning Feature Tooltip (Marketing UX)

**Purpose:** Improve perceived value by showcasing all 10 security layers in Smart Link Scanning.

**Solution:** Added info icon (ⓘ) with hover tooltip showing all protection features.

**Files Modified:**
- `popup.html` - Added tooltip HTML structure and CSS
- `popup.js` - Added element references and i18n translations
- All 24 locale files - Added 13 new i18n keys with native translations

**Tooltip Features Displayed:**
1. Phishing URLs & suspicious TLDs
2. Unicode lookalike domains
3. Fake browser windows (BitB)
4. PowerShell/malware triggers
5. Invisible overlay attacks
6. Malicious QR codes
7. Dangerous link types
8. Form hijacking (with "NEW" badge)
9. Clipboard manipulation
10. Hidden code (Shadow DOM)

**i18n Keys Added:**
- `tooltipTitle`, `tooltipFeature1-10`, `tooltipFooter`, `tooltipNewBadge`
- All keys translated to native language (no English fallbacks)

**Marketing Rationale:**
- Progressive disclosure: clean UI for casual users, depth for power users
- "10 security layers active" emphasizes value
- "NEW" badge on Form Hijacking shows active development

---

### v8.3.1 - Visual Hijacking False Positive Fix

**Problem:** Visual Hijacking warnings appeared on legitimate ad banners (e.g., on BBC.com) because content scripts run inside ad iframes like `safeframe.googlesyndication.com`.

**Solution:** Added frame-level detection to only run visual hijacking scans in the top-level frame.

**Files Modified:**
- `content.js`

**Key Changes:**

```javascript
// In proactiveVisualHijackingScan():
if (window.self !== window.top) {
  return false; // Skip scanning inside iframes
}

// In showVisualHijackingWarning():
if (window.self !== window.top) {
  return; // Do NOT show warnings inside iframes
}
```

**Rationale:** Visual hijacking attacks target the main page, not embedded ad iframes. Running inside iframes caused false positives with legitimate ad overlays.

---

### v8.3.0 - Form Hijacking Protection (Fase 3)

**Problem:** Credential guard functionality was needed after removing unstable MAIN world script.

**Solution:** Implemented Form Hijacking Protection in ISOLATED world using MutationObserver.

**Files Modified:**
- `content.js` - Added form hijacking detection system
- `background.js` - Added message handler for `formHijackingDetected`
- All 24 locale files - Added i18n keys

**Features:**
| Feature | Detects |
|---------|---------|
| Form Action Monitoring | Static hijacking via MutationObserver |
| setAttribute Interceptie | Dynamic action changes |
| Focusin JIT Detection | Changes during password field focus |
| Cross-Origin Form Warning | Data exfiltration attempts |

**Key Functions:**
- `initFormHijackingProtection()` - Initialize protection
- `startFormMonitoring()` - Start monitoring forms
- `monitorForm(form)` - Monitor specific form element
- `checkFormActionChange(form)` - Check for external domain changes
- `handlePasswordFocus(e)` - JIT hijacking detection
- `showFormHijackingWarning(targetHost)` - Display warning

**i18n Keys Added:**
- `formHijackingTitle`
- `formHijackingMessage`
- `formHijackingTip`

---

### v8.2.1 - Code Quality Improvements (Fase 2)

**Problem:** Multiple inconsistent implementations of the same utilities across files.

**Solution:** Standardized implementations and added documentation.

**Changes:**

1. **Standardized i18n Wrappers** (4 files)
   - `content.js`: `getTranslatedMessage()`
   - `background.js`: `safeGetMessage()`
   - `alert.js`: `safeGetMessage()`
   - `caution.js`: `safeGetMessage()`
   - `popup.js`: `msg()`

   All now have consistent null checks and return key as fallback.

2. **Documented Domain Utilities**
   - `getDomainFromUrl()` - Extract hostname from URL
   - `extractMainDomain()` - Get registrable domain from hostname
   - `getRegistrableDomain()` - PSL-aware domain extraction
   - `normalizeDomain()` - Remove www. prefix and trailing dots

3. **Generic Cache Cleanup Utility**
   - Added `cleanupCache(cache, maxAge, maxSize, cacheName)`
   - Simplified `cleanupJsonCache()`, `cleanRdapCache()`, `cleanMxCache()`

4. **Enabled Error Logging in dynamic.js**
   - `handleError()` now logs errors for debugging

---

### v8.2.0 - Dead Code Removal

**Changes:**
- Removed unused/duplicate functions
- Cleaned up deprecated code

---

### v8.1.x - Security Hardening Series

| Version | Changes |
|---------|---------|
| 8.1.8 | UI consistency and close button fixes |
| 8.1.7 | Fix recursive safeGetMessage causing i18n to fail |
| 8.1.6 | Fix globalConfig null access errors |
| 8.1.5 | Suppress error messages in production mode |
| 8.1.4 | Production-ready - clean console output |
| 8.1.3 | Visual Hijacking hardening for warnImagelessQR |
| 8.1.2 | ImagelessQRScanner with SVG and CSS Grid detection |
| 8.1.0 | Security audit fixes - 92.6% pass rate |

---

## Security Features

### Visual Hijacking Detection
- Detects high z-index overlays with `pointer-events: none`
- Proactive scanning via MutationObserver
- Only runs in top-level frame (not ad iframes)

### Form Hijacking Protection
- Monitors form `action` attribute changes
- JIT detection on password field focus
- Blocks submit to external domains

### Link Analysis
- URL reputation checking
- Punycode/homograph detection
- RDAP/WHOIS domain age checking
- MX record validation

### QR Code Scanning
- Detects malicious QR codes on pages
- Imageless QR detection (CSS Grid, SVG)

---

## Development Commands

### Syntax Check
```bash
node --check content.js
node --check background.js
node --check popup.js
```

### Git Commit Pattern
```bash
git commit -m "v8.x.x: Brief description

- Detail 1
- Detail 2"
```

---

## Key Technical Concepts

### Frame Detection
```javascript
// Check if running inside iframe
if (window.self !== window.top) {
  // Inside iframe
}
```

### i18n Pattern
```javascript
function safeGetMessage(key, fallback) {
  try {
    if (typeof chrome !== 'undefined' && chrome.i18n && typeof chrome.i18n.getMessage === 'function') {
      const msg = chrome.i18n.getMessage(key);
      return msg || fallback || key;
    }
  } catch (e) {
    // Extension context might be invalidated
  }
  return fallback || key;
}
```

### Trusted Domain Check
```javascript
async function isTrustedDomain(hostname) {
  // Loads patterns from TrustedDomains.json
  // Returns true if hostname matches any pattern
}
```

---

## File Structure

```
LinkShield/
├── manifest.json
├── content.js          # Main content script (~7500 lines)
├── background.js       # Service worker
├── popup.js            # Popup UI
├── dynamic.js          # Dynamic page handler
├── config.js           # Configuration
├── alert.js            # Alert page
├── caution.js          # Caution page
├── TrustedDomains.json # Trusted domain patterns
├── trustedIframes.json
├── trustedScripts.json
├── rules.json
├── _locales/           # 24 language files
│   ├── en/messages.json
│   ├── nl/messages.json
│   └── ...
├── icons/              # Extension icons
└── tests/              # Jest + Puppeteer tests
```

---

## Testing

### Unit Tests (Jest)
```bash
cd tests
npm test
```

### E2E Tests (Puppeteer)
Located in `tests/e2e/`

---

## Known Issues / Future Work

1. **Not Detected (requires MAIN world):**
   - `fetch()` credential theft
   - `sendBeacon()` exfiltration
   - WebSocket data theft

2. **Potential False Positives:**
   - Some legitimate overlay patterns may trigger warnings
   - Handled by trusted domain checks

---

## Changelog Summary

| Version | Date | Changes |
|---------|------|---------|
| 8.3.2 | 2026-01 | Smart Link Scanning tooltip (marketing UX) |
| 8.3.1 | 2026-01 | Visual Hijacking iframe fix |
| 8.3.0 | 2026-01 | Form Hijacking Protection |
| 8.2.1 | 2026-01 | i18n wrappers standardization |
| 8.2.0 | 2026-01 | Dead code removal |
| 8.1.x | 2025-12 | Security hardening series |
