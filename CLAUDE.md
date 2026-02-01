# LinkShield - Development Documentation

## Project Overview

**LinkShield** is a Chrome browser extension that protects users from phishing, malicious links, and various web-based attacks. It provides real-time security warnings for suspicious URLs, visual hijacking attempts, form hijacking, and more.

**Current Version:** 8.7.3
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
| `hostileTrackers.json` | Tracking domains associated with phishing/malware |
| `rules.json` | DeclarativeNetRequest rules |

### Internationalization

24 locale files in `_locales/` directory supporting: ar, bn, de, en, es, fr, hi, id, it, ja, ko, nl, pl, pt, ru, th, tr, uk, vi, zh_CN, zh_TW, and more.

---

## Recent Implementations

### v8.7.3 - False Positive Reduction (2026-02)

**Purpose:** Reduce false positives for legitimate websites by optimizing TLD detection and disabling standalone checks that caused too many false positives.

**Changes:**

| Change | Before | After | Impact |
|--------|--------|-------|--------|
| Remove legitimate TLDs from suspicious list | .ai, .cloud, .tech, .digital, .link, .space, .es flagged | Not flagged | claude.ai, character.ai, etc. no FP |
| Reduce standalone TLD score | 7 points (almost CAUTION) | 4 points | TLD alone = minor indicator |
| Disable `freeHosting` standalone | 4-5 points per check | 0 (disabled) | github.io, vercel.app, netlify.app no FP |
| Disable `suspiciousKeywords` standalone | Variable points | 0 (disabled) | "login", "verify" alone no longer triggers |
| Add private network detection | Ports on localhost triggered | Excluded | Sysadmins: localhost:3000 no warning |

**Files Modified:**
- `config.js` - Removed TLDs from SUSPICIOUS_TLDS_SET and SUSPICIOUS_TLDS regex
- `content.js` - Reduced TLD scores (7→4), disabled freeHosting/suspiciousKeywords standalone, added `isPrivateNetwork()`
- `manifest.json` - Version bump to 8.7.3

**TLDs Removed from Suspicious List:**
```javascript
// These are now considered legitimate (too many real businesses use them)
'ai',      // claude.ai, character.ai, perplexity.ai
'cloud',   // jetbrains.cloud, adobe.cloud
'tech',    // legitimate tech companies
'digital', // digital agencies
'link',    // bio.link, link-in-bio services
'space',   // startups, space industry
'es'       // Spain's country TLD
```

**Detection Strategy Change:**
- **Before:** TLD alone = 7 points (near CAUTION threshold of 8)
- **After:** TLD alone = 4 points (needs additional indicators)
- **Combination checks preserved:** Brand + suspicious TLD = 15 points (DANGER)

**Test Results (50 URLs):**
- 47/50 passed (94%)
- All phishing URLs correctly detected
- All legitimate .ai/.cloud/.tech sites no longer flagged
- Edge Store Chrome reference issues resolved

---

### v8.7.2 - Security Audit Fixes (2026-01)

**Purpose:** Fix three critical vulnerabilities identified in security audit: ASCII I/l lookalike bypass, ClickFix split-tag bypass, and SVG race condition.

**Fixes:**

| Fix | Layer | Issue | Solution |
|-----|-------|-------|----------|
| ASCII I/l Lookalike | 2 | `paypaI.com` (capital I) not detected | Extended regex to `/paypa[1lI]/i` |
| ClickFix Split-Tag | 4 | `<span>Invoke-</span><span>Expression</span>` bypasses detection | Text normalization before pattern matching |
| SVG Race Condition | 14 | 1000ms delay allows malicious SVG onload to execute | Immediate scan + 50ms debounce MutationObserver |

**Files Modified:**
- `content.js` - All three security fixes
- `manifest.json` - Version bump to 8.7.2

**Fix 1: ASCII Lookalike Detection (Layer 2)**

Added comprehensive I/l/1 confusion patterns for major brands:

```javascript
// Before: /paypa1/ - only catches digit 1
// After: /paypa[1lI]/i - catches 1, l, and capital I (case-insensitive)

const asciiLookalikes = [
  { pattern: /paypa[1I]/i, brand: 'paypal' },      // paypa1, paypaI
  { pattern: /netf[1lI][1lI]x/i, brand: 'netflix' }, // netflix with l/1/I
  { pattern: /[1lI]inkedin/i, brand: 'linkedin' },  // 1inkedin, Iinkedin
  // ... expanded for all major brands
];
```

**Fix 2: ClickFix Split-Tag Bypass (Layer 4)**

Added text normalization function to detect split keywords:

```javascript
// Normalize text before pattern matching
const normalizeForScan = (text) => {
  return text
    // Remove zero-width characters
    .replace(/[\u200B-\u200D\uFEFF\u00AD]/g, '')
    // Normalize Unicode whitespace
    .replace(/[\u00A0\u2000-\u200A\u202F\u205F\u3000]/g, ' ')
    // Collapse multiple spaces
    .replace(/\s+/g, ' ');
};
```

**Fix 3: SVG Race Condition (Layer 14)**

Changed from delayed scan to immediate detection:

```javascript
// Before: setTimeout(() => detectSVGPayloads(), 1000);
// After: Immediate + MutationObserver with onload interception

queueMicrotask(async () => await detectSVGPayloads()); // Immediate

// MutationObserver with immediate onload check
if (node.tagName === 'svg') {
  const onload = node.getAttribute('onload');
  if (onload && /location|cookie|eval|fetch/.test(onload)) {
    node.removeAttribute('onload'); // Prevent execution
    detectSVGPayloads(); // Scan immediately
  }
}
```

**Key Architecture Decision:**

The SVG fix includes a **preemptive onload removal** mechanism. When a new SVG is added to the DOM with a dangerous `onload` attribute, the MutationObserver:
1. Detects the attribute synchronously (before script execution)
2. Removes the `onload` attribute to prevent execution
3. Triggers a full SVG payload scan

This is necessary because `queueMicrotask` runs after the current script but before browser-scheduled callbacks like `onload`.

---

### v8.7.1 - Landing Page Update + Price Change (2026-01)

**Purpose:** Detect tracking domains associated with phishing campaigns, malware C2 infrastructure, and data exfiltration. Strategically positioned as a security feature (not a privacy score) to extend the security moat.

**New Feature:**

| Feature | Description | Location |
|---------|-------------|----------|
| Tracking Infrastructure Risk | Detects hostile tracking domains via webRequest API | `background.js` |
| Risk Indicator | Non-intrusive floating indicator on elevated/high risk | `content.js` |
| Hostile Trackers Data | JSON database of known hostile tracking domains | `hostileTrackers.json` |

**Architecture:**

```
webRequest.onCompleted (background.js)
  → processThirdPartyRequest()
      → Skip first-party requests
      → Check against hostileTrackers.json
          ├─ trustedTrackers (whitelist) → score 0
          ├─ hostileDomains (known bad) → score 20
          ├─ hostilePatterns (regex match) → score 15
          ├─ suspiciousCharacteristics (random subdomain) → score 10
          ├─ dangerousTLDs + tracking prefix → score 8
          └─ unknown tracker → score 3
      → Update tab risk cache
      → Send trackingRiskUpdate to content.js
      → Update badge if elevated/high

webNavigation.onCommitted (background.js)
  → Clear tab risk cache on navigation

content.js
  → Listen for trackingRiskUpdate
  → Show/hide floating indicator
```

**Risk Levels:**

| Level | Score | Visual |
|-------|-------|--------|
| none | 0-4 | No indicator |
| low | 5-14 | No indicator |
| elevated | 15-24 | Orange indicator (auto-hide 10s) |
| high | 25+ | Red indicator (persistent) |

**Files Modified:**
- `hostileTrackers.json` - NEW: Hostile tracking domains database
- `config.js` - Added `trackingInfrastructureRisk` config section
- `background.js` - webRequest listener, tab cache, risk calculation
- `content.js` - trackingRiskUpdate listener, floating indicator
- `popup.html` - Added tooltipFeature15, updated footer to "15 layers"
- `popup.js` - Added tooltipFeature15 translation
- `manifest.json` - Added `webRequest`, `webNavigation` permissions, v8.7.0
- All 24 locale files - Added 5 new i18n keys

**New i18n Keys:**
- `tooltipFeature15` - "Hostile tracking infrastructure"
- `trackingRiskTitle` - "Hostile Tracking Detected"
- `trackingRiskHostile` - "hostile tracker(s)"
- `trackingRiskThirdParty` - "third-party domains"
- `trackingRiskDetected` - Alert reason text

**hostileTrackers.json Structure:**
```json
{
  "hostileDomains": {
    "phishingInfra": [...],
    "malwareC2": [...],
    "cryptoTheft": [...],
    "dataExfil": [...],
    "fingerprintAbuse": [...]
  },
  "hostilePatterns": ["^track[0-9]*\\.", ...],
  "suspiciousCharacteristics": {...},
  "trustedTrackers": ["google-analytics.com", ...],
  "dangerousTLDs": ["xyz", "top", ...]
}
```

**Key Functions:**
- `loadHostileTrackersData()` - Lazy-load hostile trackers JSON
- `checkHostileTracker(domain)` - Check if domain is hostile
- `processThirdPartyRequest(details)` - Process webRequest events
- `getTabTrackingRisk(tabId)` - Get/create tab risk cache
- `calculateTrackingRiskLevel(score)` - Calculate risk level from score
- `handleTrackingRiskUpdate(data)` - Content script handler
- `showTrackingRiskIndicator()` - Display floating indicator

**Strategic Positioning:**
- Framed as "hostile tracking infrastructure" (security), not "privacy score" (commodity)
- Extends existing 14-layer security moat to 15 layers
- Differentiates from Ghostery/Privacy Badger by focusing on phishing-associated trackers
- Uses same score-based architecture as other threat detections

---

### v8.7.1 - Landing Page Update + Price Change (2026-01)

**Purpose:** Add tracker detection feature to landing page and update premium pricing.

**Changes:**

| Change | Description | Location |
|--------|-------------|----------|
| Feature 8 added | "Verdachte Tracker Detectie" / "Suspicious Tracker Detection" | `index.html` |
| Security layers updated | 14 → 15 in all references | `index.html` |
| Premium price updated | €1,99 → €4,99 | `index.html`, `popup.html`, 24 locale files |

**Files Modified:**
- `index.html` - Added Feature 8 HTML block with "NIEUW" badge, updated "14" to "15" references, added feature8Title/feature8Text translations (NL + EN), updated price €1,99 → €4,99
- `popup.html` - Updated ctaPrice €1.99 → €4.99
- All 24 locale files - Updated `licenseUpgradeLink` and `ctaUpgradePrice` with new price

**New i18n Keys (index.html only):**
- `feature8Title` - "Verdachte Tracker Detectie" / "Suspicious Tracker Detection"
- `feature8Text` - Feature description text

---

### v8.6.1 - Detection Effectiveness Fixes + Performance (2026-01)

**Purpose:** Fix critical phishing URL detection gap (Layer 1: 13%→88%), eliminate data:image false positive, reduce SVG detection race condition, and fix STATUS_BREAKPOINT crash on heavy sites (bol.com).

**Detection Fixes:**

| Fix | Before | After | Location |
|-----|--------|-------|----------|
| Synchronous TLD + Brand check | 13% phishing URL detection | 88% detection | `content.js:classifyAndCheckLink()` |
| data:image/audio/video/font whitelist | False positive on legitimate data URIs | No FP | `content.js:immediateUriSecurityCheck()` + `detectDangerousScheme()` |
| SVG detection delay | 3000ms (race condition) | 1000ms | `content.js:initSVGPayloadDetection()` |

**Performance Fixes (STATUS_BREAKPOINT crash):**

| Fix | Description | Location |
|-----|-------------|----------|
| `all_frames: false` | Content script no longer runs in ad/tracking iframes | `manifest.json` |
| `_isTopFrame` guard | Early frame detection skips heavy operations in sub-frames | `content.js` (top) |
| `_isTrustedSiteCache` | Cached trusted domain check for performance-sensitive paths | `content.js` |
| Early observer top-frame only | MutationObserver buffering limited to main frame | `content.js` |
| NEVER_BLOCK_DOMAINS | Safety list prevents accidental blocking of major sites | `background.js` |
| BitB regex narrowing | Removed 'close' from controlClasses (false positive trigger) | `config.js` |

**Files Modified:**
- `content.js` - Synchronous TLD+Brand detection, data URI whitelist, SVG delay, frame guards
- `background.js` - NEVER_BLOCK_DOMAINS safety list, Dutch e-commerce trusted domains
- `config.js` - BitB `controlClasses` regex narrowed
- `manifest.json` - `all_frames: true` → `false`

**Synchronous TLD + Brand Detection (Key Architecture Decision):**

The async pipeline (`analyzeDomainAndUrl` → `performSuspiciousChecks` → `checkStaticConditions`) was hanging on the SSL Labs check (`chrome.runtime.sendMessage`) for unreachable domains, preventing the TLD check from ever firing. The fix adds a **synchronous** check directly in `classifyAndCheckLink()` that runs BEFORE the async routing:

```javascript
// In classifyAndCheckLink(), between ASCII lookalike and malicious keyword checks:
// 1. Extract TLD → check SUSPICIOUS_TLDS_SET (O(1) Set lookup)
// 2. Check 28 brand patterns against domain (not matching brand's own domain)
// 3. Check phishing keywords (login, secure, verify, account, etc.)
// 4. Score: brand+TLD=15(alert), brand+phishword=15(alert),
//    keyword stuffing=8(caution), TLD alone=5(caution), brand alone=8(caution)
```

**Link Scanning Pipeline (Updated):**
```
scanNodeForLinks()
  → immediateUriSecurityCheck()     [SYNC: data:, javascript:, vbscript:, blob:]
  → classifyAndCheckLink()
      ├─ Dangerous URI scheme        [SYNC]
      ├─ Trusted domain early exit   [SYNC]
      ├─ Unicode detection            [SYNC]
      ├─ ASCII lookalike detection    [SYNC]
      ├─ TLD + Brand keyword check   [SYNC] ← NEW (v8.6.1)
      ├─ Malicious domain keywords   [SYNC]
      ├─ Homoglyph/Punycode          [SYNC]
      └─ Route:
           ├─ Ad links → checkForPhishingAds()
           └─ Regular → analyzeDomainAndUrl()  [ASYNC]
                          → performSuspiciousChecks()
                              → checkStaticConditions()
                              → checkDynamicConditionsPhase2()
                              → checkDomainAgeDynamic()
```

**Detection Effectiveness (Tested):**

| Layer | Detection Rate | Notes |
|-------|---------------|-------|
| 1. Phishing URLs | 88% (7/8) | Only miss: internal IP (by design) |
| 2. Unicode lookalikes | 83% (5/6) | paypaI→paypai normalization |
| 3. BitB | 100% | |
| 4. ClickFix | 100% | |
| 5. Overlays | 100% | |
| 7. Dangerous links | 100%, 0 FP | data:image FP fixed |
| 10. Shadow DOM | 100% (open) | Closed inaccessible by design |
| 13. AiTM | 100% | |
| **False Positives** | **1** | münchen.de IDN only |

---

### v8.6.0 - AiTM Proxy Detection + SVG Payload Detection + Popup UX (2026-01)

**Purpose:** Detect reverse proxy phishing (Evilginx, Tycoon 2FA) and malicious SVG payloads. Improve popup UX by showing database freshness on badge hover.

**New Features:**

| Feature | Description | Location |
|---------|-------------|----------|
| AiTM Proxy Detection | Detects Microsoft/Google login elements on foreign domains | `content.js:detectAiTMProxy()` |
| SVG Payload Detection | Detects malicious JavaScript in inline/embedded SVGs | `content.js:detectSVGPayloads()` |
| Database Update Tooltip | Hover on "+X today" badge shows last database update time | `popup.html` / `popup.js` |

**Files Modified:**
- `config.js` - Added `aitmDetection` and `svgPayloadDetection` in `ADVANCED_THREAT_DETECTION`
- `content.js` - Added `detectAiTMProxy()`, `initAiTMDetection()`, `detectSVGPayloads()`, `initSVGPayloadDetection()`
- `background.js` - Added `aitmProxyDetected` and `svgPayloadDetected` message handlers
- `popup.html` - Added tooltip features 13+14, database tooltip on threats badge, removed broken liveBadge
- `popup.js` - Added tooltip translations, replaced liveBadge with dbUpdateText tooltip
- All 24 locale files - Added 11 new i18n keys
- `manifest.json` - Version bump to 8.6.0

**Detection Strategy:**
- Both features use score-based thresholds (>= 15) to minimize false positives
- AiTM: Identifies provider-specific DOM element IDs (`#i0116`, `#identifierId`, etc.) on non-legitimate domains
- SVG: Only flags high-confidence patterns (eval+atob, javascript: URIs, foreignObject redirects)
- Both: Staggered initialization (2500ms/3000ms), debounced MutationObservers

**AiTM Legitimate Provider Whitelist:**
- `login.microsoftonline.com`, `accounts.google.com`, `login.okta.com`, `auth0.com`, etc.

**SVG Scan Scope:**
- Inline `<svg>`: Yes (scripts execute)
- `<object>/<embed>` (same-origin): Yes
- `<img src="*.svg">`: No (browsers block scripts)

**Popup UX Changes:**
- Removed broken `liveBadge` element and CSS (was missing from HTML, causing silent errors)
- Threats badge ("+X today") now shows database update tooltip on hover
- Footer no longer used for update text (decluttered UI)
- Badge always visible as marketing trust signal

**New i18n Keys:**
- `aitmProxyTitle`, `aitmProxyMessage`, `aitmProxyTip`, `aitmProxyDetected`
- `svgPayloadTitle`, `svgPayloadMessage`, `svgPayloadTip`, `svgPayloadDetected`
- `tooltipFeature13`, `tooltipFeature14`, `tooltipFooter` (updated to "14")

**Key Functions:**
- `detectAiTMProxy()` - Score-based AiTM detection with provider identification
- `initAiTMDetection()` - 2500ms delay + MutationObserver for password fields
- `detectSVGPayloads()` - WeakSet-deduplicated SVG scanning with pattern matching
- `initSVGPayloadDetection()` - 3000ms delay + MutationObserver for svg/object/embed

**Tests:**
- `tests/unit/v860-detection.test.js` - 228 unit tests covering edge cases and false positive prevention

---

### v8.5.0 - Advanced Threat Detection (2026-01)

**Purpose:** Protect against new phishing techniques discovered in 2025-2026.

**New Features:**

| Feature | Description | Location |
|---------|-------------|----------|
| OAuth Paste Guard | Blocks pasting of localhost OAuth tokens (ConsentFix attack) | `content.js:initOAuthPasteGuard()` |
| Fake Turnstile Detection | Detects fake Cloudflare CAPTCHA/Turnstile UI | `content.js:detectFakeTurnstile()` |
| Split QR Detection | Detects QR codes split into multiple images | `content.js:SplitQRDetector` |

**Files Modified:**
- `config.js` - Added `ADVANCED_THREAT_DETECTION` configuration section
- `content.js` - Added 3 new detection modules
- `background.js` - Added message handlers and statistics tracking
- All 24 locale files - Added 8 new i18n keys

**New Config Section:**
```javascript
ADVANCED_THREAT_DETECTION: {
    enabled: true,
    scores: {
        FAKE_TURNSTILE_INDICATOR: 15,
        OAUTH_TOKEN_PASTE_ATTEMPT: 20,
        SPLIT_QR_DETECTED: 12,
        NESTED_QR_DETECTED: 14,
        CONSENTFIX_PATTERN: 18
    },
    splitQR: { ... },
    oauthProtection: { ... },
    fakeTurnstile: { ... }
}
```

**New i18n Keys:**
- `oauthTheftTitle`, `oauthTheftMessage`, `oauthTheftTip`
- `fakeTurnstileTitle`, `fakeTurnstileMessage`
- `splitQrTitle`, `splitQrMessage`
- `understoodButton`

**Test Pages:**
- `tests/scenarios/attack-vectors/consentfix-oauth.html`
- `tests/scenarios/attack-vectors/fake-turnstile.html`
- `tests/scenarios/attack-vectors/split-qr.html`

**References:**
- ConsentFix: https://pushsecurity.com/blog/consentfix
- Split QR: https://blog.barracuda.com/2025/08/20/threat-spotlight-split-nested-qr-codes-quishing-attacks

---

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
8. Form hijacking
9. Clipboard manipulation
10. Hidden code (Shadow DOM)
11. OAuth token theft
12. Fake security checks
13. Login proxy phishing (AiTM) (with "NEW" badge)
14. Malicious SVG scripts (with "NEW" badge)

**i18n Keys Added:**
- `tooltipTitle`, `tooltipFeature1-14`, `tooltipFooter`, `tooltipNewBadge`
- All keys translated to native language (no English fallbacks)

**Marketing Rationale:**
- Progressive disclosure: clean UI for casual users, depth for power users
- "14 security layers active" emphasizes value
- "NEW" badge on latest features shows active development
- Threats badge ("+X today") always visible as trust signal

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

## Development Guidelines

### New Security Detection Features

**CRITICAL:** Every new security detection feature MUST follow these rules:

1. **integratedProtection Check Required**
   - The function must check if `integratedProtection` (Smart Link Scanning) is enabled
   - Use `await isProtectionEnabled()` at the start of the function
   - Return early/skip detection if protection is disabled

2. **Trusted Domain Check Required**
   - The function must skip detection on domains listed in `TrustedDomains.json`
   - Use `await isTrustedDomain(hostname)` to check
   - This prevents false positives on major legitimate sites (e.g., facebook.com, google.com)

3. **Example Pattern:**
```javascript
async function detectNewThreat() {
    // 1. Check config enabled
    if (!globalConfig?.FEATURE?.enabled) {
        return { detected: false };
    }

    // 2. Check integratedProtection enabled
    if (!(await isProtectionEnabled())) {
        return { detected: false };
    }

    // 3. Skip trusted domains
    const hostname = window.location.hostname;
    if (await isTrustedDomain(hostname)) {
        return { detected: false };
    }

    // ... actual detection logic ...
}
```

### Internationalization (i18n) Requirements

**CRITICAL:** Every new i18n key MUST have translations in all 24 locales:

1. **Native Translations Only** - No English fallbacks
   - Each locale file must contain the actual native language translation
   - Do NOT use English text as a placeholder in non-English locales

2. **Supported Locales (24 total):**
   - ar, cs, de, el, en, es, fr, hi, hu, id, it, ja, ko, nl, pl, pt, pt_BR, ro, ru, th, tr, uk, vi, zh

3. **Key Naming Convention:**
   - Titles: `featureNameTitle` (e.g., `fakeTurnstileTitle`)
   - Messages: `featureNameMessage` (e.g., `fakeTurnstileMessage`)
   - Reason keys (for alert page): `featureNameDetected` (e.g., `fakeTurnstileDetected`)

4. **Reason Keys for Alert Page:**
   - When adding a new detection that appears in the alert reason list, you MUST add a corresponding reason key
   - The reason key is used in `alert.js` via `safeGetMessage(reasonKey)`
   - Format: Short description with risk level, e.g., "Fake security verification detected (high risk)."

### Popup Tooltip Requirements

**CRITICAL:** Every new Smart Link Scanning feature MUST be added to the popup tooltip:

1. **Add to popup.html:**
   - Add new `<li id="tooltipFeatureN">` in the tooltip list
   - For new features, add `<span class="new-badge">New</span>` after the text
   - Update the footer counter (e.g., "12 security layers active")

2. **Add to popup.js:**
   - Add element reference: `const tooltipFeatureN = document.getElementById('tooltipFeatureN');`
   - Add translation logic with badge handling

3. **Add translations to all 24 locales:**
   - Add `tooltipFeatureN` key with native translation
   - Update `tooltipFooter` with new count in native language

4. **Example (popup.html):**
```html
<li id="tooltipFeature12">Fake security checks <span class="new-badge">New</span></li>
```

5. **Example (popup.js):**
```javascript
const tooltipFeature12 = document.getElementById('tooltipFeature12');
// In translation section:
if (tooltipFeature12) {
    const newBadge = tooltipFeature12.querySelector('.new-badge');
    if (newBadge) {
        newBadge.textContent = msg('tooltipNewBadge');
        tooltipFeature12.firstChild.textContent = msg('tooltipFeature12') + ' ';
    } else {
        tooltipFeature12.textContent = msg('tooltipFeature12');
    }
}
```

### Promo Video Update Requirements (Remotion)

**Location:** `linkshield-promo/` (Remotion project, 1280x720, 30fps)

**CRITICAL:** Every new Smart Link Scanning feature MUST be added to the promo video:

1. **Add to `src/constants/features.ts`:**
   - Add new entry to `FEATURES` array with `isNew: true`
   - Set previous "new" features to `isNew: false`

2. **Add visual example to `src/components/FeatureExample.tsx`:**
   - Add new entry in the `examples` record keyed by feature ID
   - Create a mini visual showing the attack pattern being detected
   - Use existing helpers: `MiniBrowser`, `BlockBadge`, `DangerStrike`

3. **Update `src/constants/timing.ts`:**
   - `TOTAL_FRAMES` = `SCENES.CTA.start + SCENES.CTA.duration`
   - `SCENES.FEATURES.duration` = `N_features × FEATURE_FRAME_DURATION` (90 frames = 3s each)
   - Shift all subsequent scene start times accordingly

4. **Regenerate audio:**
   - Update `DURATION` in `generate-audio.js` to match new total seconds
   - Update `sceneChanges` array with new scene transition timestamps
   - Run `node generate-audio.js`

5. **Render:**
   ```bash
   cd linkshield-promo
   npm run render
   ```

6. **Key files:**
   - `src/constants/features.ts` - Feature list + batches
   - `src/constants/timing.ts` - Scene durations (auto-extends)
   - `src/components/FeatureExample.tsx` - Visual examples per feature
   - `src/scenes/Scene4_Features.tsx` - Features carousel scene
   - `src/compositions/LinkShieldPromo.tsx` - Master composition with audio
   - `generate-audio.js` - Synthesized background music generator
   - `public/background-music.wav` - Generated audio file

---

## Known Issues / Future Work

1. **Not Detected (requires MAIN world):**
   - `fetch()` credential theft
   - `sendBeacon()` exfiltration
   - WebSocket data theft

2. **Potential False Positives:**
   - IDN domains (e.g., `münchen.de`) trigger punycode detection (1 remaining FP)
   - Handled by trusted domain checks

3. **Async Pipeline Limitation:**
   - `performSuspiciousChecks()` SSL Labs check can hang for unreachable domains
   - Mitigated by synchronous TLD+Brand check in `classifyAndCheckLink()` (v8.6.1)
   - The async path still provides deeper analysis (domain age, MX, Levenshtein) when it completes

4. **SVG Detection Race Condition:**
   - Inline SVG scripts with `window.location` redirects execute before detection (1000ms delay)
   - Mitigation: reduced delay from 3000ms to 1000ms, but immediate redirects still bypass

5. **Headless Test Limitations:**
   - Clipboard/OAuth guards require real user interaction events (not testable in headless)
   - QR code scanning requires valid QR images (canvas patterns not decodable by jsQR)
   - Form hijacking detection requires precise timing (delayed scripts + MutationObserver)

---

## Changelog Summary

| Version | Date | Changes |
|---------|------|---------|
| 8.7.3 | 2026-02 | False positive reduction: TLD optimization, disable freeHosting/suspiciousKeywords standalone, private network detection |
| 8.7.2 | 2026-01 | Security audit fixes: ASCII I/l bypass, ClickFix split-tag, SVG race condition |
| 8.7.1 | 2026-01 | Landing page Feature 8 (tracker detection) + price €1,99 → €4,99 |
| 8.7.0 | 2026-01 | Tracking Infrastructure Risk Detection (Layer 15) |
| 8.6.1 | 2026-01 | Phishing URL detection fix (13%→88%) + data:image FP fix + performance |
| 8.6.0 | 2026-01 | AiTM Proxy Detection + SVG Payload Detection (14 layers) + Popup UX |
| 8.5.2 | 2026-01 | Add OAuth protection to tooltip (11 security layers) |
| 8.5.1 | 2026-01 | Fix false positive for email addresses in URL paths |
| 8.5.0 | 2026-01 | Advanced Threat Detection (OAuth Guard, Fake Turnstile, Split QR) |
| 8.3.2 | 2026-01 | Smart Link Scanning tooltip (marketing UX) |
| 8.3.1 | 2026-01 | Visual Hijacking iframe fix |
| 8.3.0 | 2026-01 | Form Hijacking Protection |
| 8.2.1 | 2026-01 | i18n wrappers standardization |
| 8.2.0 | 2026-01 | Dead code removal |
| 8.1.x | 2025-12 | Security hardening series |
