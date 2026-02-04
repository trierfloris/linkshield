# LinkShield - Development Documentation

## Project Overview
**LinkShield** is a Chrome extension (MV3) protecting users from phishing and web-based attacks.
**Current Version:** 8.9.2 | **Layers of Protection:** 16

## Architecture & Components
| File | Purpose |
|------|---------|
| `manifest.json` | Extension config & permissions |
| `content.js` | Main logic - runs in ISOLATED world |
| `background.js` | Service worker for background tasks & webRequest |
| `config.js` | Main configuration & threat scores |
| `_locales/` | 24 language files (ar, de, en, es, fr, hi, id, it, ja, ko, nl, pl, pt, ru, vi, zh, etc.) |

### Key Data Files
- `TrustedDomains.json`: Regex for whitelisted domains.
- `hostileTrackers.json`: Database of known phishing/malware trackers.
- `rules.json`: DeclarativeNetRequest rules.

---

## Recent Implementations (2026)

### v8.9.2 - Security Audit Remediation

#### Zero-Width Character Detection (Layer 2 Enhancement)
- **Issue:** Invisible Unicode characters (ZWSP, ZWNJ, ZWJ, BOM, RLO) could bypass URL validation.
- **Fix:** Added `detectZeroWidthCharacters(text)` function with comprehensive detection.
- **Characters Detected:**
  - `\u200B` (ZWSP), `\u200C` (ZWNJ), `\u200D` (ZWJ) - Zero-width characters
  - `\uFEFF` (BOM) - Invisible byte order mark
  - `\u202E` (RLO), `\u202D` (LRO) - **CRITICAL** BiDi override attacks
  - `\u202A-\u202C` - Directional embedding/formatting
  - `\u2060-\u2064` - Invisible operators
- **Scoring:** ZWSP/ZWNJ/ZWJ: +8, BOM: +10, RLO/LRO: +20 (with extra +10 penalty for BiDi)
- **Form Scanning:** `scanFormsForZeroWidthAttacks()` checks labels, placeholders, buttons.

#### Recursive Base64 Decoding (Layer 4 & 14 Enhancement)
- **Issue:** Nested Base64 payloads (2-3 layers) bypassed single-pass decoding.
- **Fix:** Made `decodeBase64PowerShell()` and `scanNestedBase64InSVG()` recursive (max 3 levels).
- **Nested Patterns Detected:**
  - `[Convert]::FromBase64String('...')` in PowerShell
  - `atob('...')` in JavaScript/SVG
  - `data:...;base64,...` nested data URIs
- **Indicators:** Adds `nested:` prefix for indicators found in nested payloads.

#### Canvas/WebGL Overlay Detection (Layer 3/5 Enhancement)
- **Issue:** Attackers could render fake browser UI via Canvas/WebGL, bypassing DOM scanning.
- **Fix:** Added `detectCanvasWebGLOverlays()` with heuristic analysis.
- **Detection Criteria:**
  1. Large canvas (>30% viewport coverage): +5 points
  2. High z-index (>1000): +8 points
  3. Fixed/absolute positioning: +4 points
  4. Interactive canvas with click handlers: +6 points
  5. WebGL context on large canvas: +7 points
  6. Canvas overlapping login form: +12 points **(CRITICAL)**
- **Threshold:** Score ≥10 triggers alert.

#### Domain Reputation API Placeholder (Layer 15 Enhancement)
- **Purpose:** Future integration point for WHOIS/reputation services.
- **Function:** `checkDomainReputation(domain)` returns `{reputation, score, age, registrar}`.
- **Current Implementation:** Placeholder with basic heuristics:
  - Suspicious TLD check (-30 score)
  - Subdomain depth analysis (>3 = suspicious)
  - Random subdomain pattern detection (hex/base64 strings)
- **Planned Integrations:** VirusTotal, Google Safe Browsing, URLhaus, PhishTank.

#### Visa Service Whitelist Expansion (Layer 16 Enhancement)
- **Issue:** Legitimate visa services triggered false positives.
- **Fix:** Added regional domains to `legitimateThirdParties`:
  - `ivisa.co.uk`, `ivisa.de`, `ivisa.fr`
  - `visahq.co.uk`, `visahq.nl`
  - `traveldoc.aero`

#### Known Limitations - Closed Shadow DOM (Documented)
- **Status:** Confirmed as architectural limitation in Manifest V3.
- **Reason:** Browser security boundary prevents access to `attachShadow({ mode: 'closed' })`.
- **Mitigation:** Other detection layers (URL analysis, TLD checking) still apply when users click links.
- **Documentation:** Added to CLAUDE.md as accepted residual risk.

---

### v8.9.1 - Enterprise-Grade Security Enhancements

#### Clipboard Hardening (Layer 9 Enhancement)
- **Issue:** 50ms delay was too short to detect sophisticated paste replacement attacks.
- **Fix:** Increased delay from 50ms to 300ms in `handlePasteEvent()`.
- **New Feature:** Length variance detection - triggers alert if paste result differs >20% from original.
- **Benefit:** Catches attacks that replace crypto addresses with different-length strings.

#### Advanced Visibility Check (Layer 5 Enhancement)
- **Issue:** Standard `isVisible()` couldn't detect overlays hidden via CSS transforms or clip-path.
- **Fix:** Added `checkAdvancedVisibility(el)` function with three new checks:
  1. **Transform Detection:** High z-index (>9000) combined with `transform: translate()` positioning element outside viewport.
  2. **Clip-Path Masks:** High z-index (>1000) with `clip-path` that creates zero visible area (`inset(100%)`, `circle(0)`).
  3. **Invisible Overlays:** `pointer-events: none` + high z-index + near-zero opacity.
- **Returns:** `{visible: boolean, dangerous: boolean, reason: string}` for fine-grained control.

#### Enterprise AiTM Detection (Layer 13 Enhancement)
- **Issue:** Only Microsoft and Google AiTM markers were detected.
- **Fix:** Added enterprise SSO provider markers to `config.js:aitmDetection`:
  - **Okta:** IDs (`okta-sign-in`, `okta-container`), classes (`okta-form-title`, `auth-content`), paths (`/login/login.htm`).
  - **Auth0:** IDs (`auth0-lock-container`, `auth0-widget`), classes (`auth0-lock-header`, `auth0-lock-form`).
  - **Salesforce:** IDs (`sfdc_username_container`, `login_form`), classes (`loginForm`, `slds-form`), paths (`/services/oauth2/authorize`).
- **Legitimate Providers Updated:** Added `okta.com`, `*.okta.com`, `*.auth0.com`, `*.salesforce.com`, `*.force.com`.
- **New Scores:** `oktaSpecificId`, `auth0SpecificId`, `salesforceSpecificId` (all score 8).

#### BitB Pseudo-Element Detection (Layer 3 Enhancement)
- **Issue:** Attackers could hide fake URLs in CSS `::before`/`::after` pseudo-elements, bypassing DOM scanning.
- **Fix:** Added `detectPseudoElementUrls(container)` function.
- **Detection Method:** Uses `window.getComputedStyle(el, '::before').content` and `::after`.
- **Patterns Detected:**
  - `accounts.google.com`, `login.microsoft.com`, `login.okta.com`
  - `*.auth0.com`, `login.salesforce.com`, `appleid.apple.com`
  - OAuth paths (`/oauth`, `/signin`)
- **Response:** Adds `pseudoElementFakeUrl` indicator with same score as `fakeUrlBar`.

---

### v8.9.0 - Security Audit Fixes & Memory Leak Prevention

#### Memory Leak Fixes (All Observers)
- **Issue:** MutationObservers and IntersectionObservers were not disconnected on page unload, causing memory leaks on SPAs.
- **Fix:** Added centralized observer registry (`activeObservers[]`) with automatic cleanup.
- **Functions Added:**
  - `registerObserver(observer, name)` - Registers observer for cleanup
  - `disconnectAllObservers()` - Disconnects all registered observers
- **Observers Fixed:** `formObserver`, `svgObserver`, `hijackMutationObserver`, `visualHijackingIntersectionObserver`, `aitmObserver`, `clickFixObserver`, `bitbObserver`, `dynamicDetectionObserver`
- **Cleanup:** Triggers on `beforeunload` and `pagehide` events via `cleanupOnUnload()`.

#### OAuth Implicit Flow Protection (Layer 11 Enhancement)
- **Issue:** Fragment-based tokens (`#access_token=`) used in OAuth implicit flow were not detected.
- **Fix:** Added `fragmentPatterns` to `config.js:oauthProtection` configuration.
- **Patterns Added:**
  - `#access_token=`, `#id_token=`, `#code=`
  - `#token_type=bearer`, `#expires_in=`
  - Localhost callback variants
- **Detection:** `initOAuthPasteGuard()` now checks both query string AND fragment patterns.

#### Fetch/XHR Credential Exfiltration Monitoring (New Layer)
- **Attack Vector:** Attackers bypass form hijacking by using `fetch()` or `XMLHttpRequest` to exfiltrate credentials.
- **Detection:** `content.js:initFetchMonitoring()` monkey-patches `window.fetch` and `XMLHttpRequest.prototype.send`.
- **Logic:**
  - Detects cross-origin requests with credential-containing bodies
  - Checks for keywords: `password`, `credential`, `token`, `apikey`, `cvv`, etc.
  - Respects payment gateway whitelist
- **Response:** Blocks request and shows critical warning.
- **Functions Added:** `installFetchMonitor()`, `installXHRMonitor()`, `analyzeRequestTarget()`, `checkForCredentials()`

#### Data URI Hardening (Layer 7 Enhancement)
- **Issue:** Executable MIME types like `data:application/javascript;base64,...` were not blocked.
- **Fix:** Rewrote `detectDangerousScheme()` with explicit MIME type validation.
- **Safe MIME Types:** `image/*`, `audio/*`, `video/*`, `font/*`, `text/plain` (non-base64)
- **Blocked MIME Types:** `text/html`, `text/javascript`, `application/javascript`, `application/x-shockwave-flash`, etc.
- **Unknown MIME Types:** Blocked by default for safety (risk score: 20).

#### ClickFix Base64 PowerShell Decoding (Layer 4 Enhancement)
- **Issue:** Base64-encoded PowerShell commands (via `-e` or `-EncodedCommand` flags) bypassed detection.
- **Fix:** Added `decodeBase64PowerShell()` and `scanForEncodedPowerShell()` helper functions.
- **Decoding:** Handles UTF-16LE encoding used by PowerShell.
- **Malicious Patterns Detected in Decoded Content:**
  - `Invoke-Expression`, `Invoke-WebRequest`, `DownloadString`
  - `Set-ExecutionPolicy Bypass`, `Add-MpPreference ExclusionPath`
  - Nested encoding (`FromBase64String`), hidden execution, registry modification
- **Scoring:** +15 points for encoded malicious commands, +8 for any encoded command.

### v8.8.3 - Critical Security Fixes & Performance Optimizations

#### Form Target Hijacking Detection (Layer 8 Enhancement)
- **Attack Vector:** Attacker sets `form.target` to a hidden/invisible iframe to steal credentials.
- **Detection:** `content.js:checkFormTargetHijacking()` monitors `target` attribute changes.
- **Logic:** Checks if target element is invisible (`display:none`, `visibility:hidden`, `opacity:0`, off-screen, 1x1 pixel).
- **Response:** Blocks form submission if target is suspicious and form contains password fields.
- **MutationObserver:** Now monitors both `action` AND `target` attributes.

#### SVG Data URI Payload Detection (Layer 13 Enhancement)
- **Attack Vector:** Malicious SVG embedded as `<img src="data:image/svg+xml;...">` bypasses normal SVG DOM scanning.
- **Detection:** `content.js:scanDataUriSVG()` decodes and scans data URI SVG content.
- **Patterns Detected:**
  - `<script>` tags with dangerous patterns (eval, fetch, document.cookie)
  - `javascript:` URIs in href attributes
  - Event handlers with malicious code (onload, onerror)
  - `<foreignObject>` with redirect code
  - Base64 + eval obfuscation combinations
- **Encoding Support:** Base64 (`data:image/svg+xml;base64,...`) and URL-encoded formats.

#### Shadow DOM Scan Timeout (Layer 10 Performance Fix)
- **Issue:** Deep/complex Shadow DOM structures could cause page hangs.
- **Fix:** 500ms timeout (`SHADOW_SCAN_TIMEOUT_MS`) on entire `scanAllShadowDOMs()` recursion.
- **Behavior:** Gracefully stops scanning after timeout, logs warning, preserves page performance.
- **Tracking:** Uses `performance.now()` for accurate timing across recursive calls.

#### Visual Hijacking Intersection Observer (Layer 5 Performance Fix)
- **Issue:** MutationObserver scanning ALL elements on every DOM change caused high CPU usage.
- **Fix:** Replaced with `IntersectionObserver` that only scans elements when visible in viewport.
- **Behavior:** Observes potential overlay elements (`.modal`, `.overlay`, `[role="dialog"]`, high z-index).
- **Benefit:** 60-80% reduction in CPU usage on complex SPAs with frequent DOM mutations.

#### Unicode/IDN Latin-Extended Exception (Layer 2 FP Reduction)
- **Issue:** Mixed-script detection flagged legitimate European IDN domains (münchen.de, café.fr).
- **Fix:** Allow Latin-Extended characters without warning when TLD matches European country.
- **Supported TLDs:** `.de`, `.fr`, `.nl`, `.be`, `.es`, `.it`, `.pt`, `.at`, `.ch`, `.pl`, `.cz`, etc.
- **Benefit:** Reduces false positives on legitimate European business websites.

#### ClickFix Educational Content Reduction (Layer 4 FP Reduction)
- **Issue:** Documentation sites (Microsoft Learn, GitHub) triggered ClickFix warnings.
- **Fix:** Reduces score by 8 points when educational keywords detected in page title/meta.
- **Keywords:** `tutorial`, `documentation`, `learn`, `guide`, `howto`, `example`, `reference`, `docs`.
- **Domain Patterns:** `docs.*`, `learn.*`, `developer.*`, `*wiki*`.

### v8.8.2 - Security Enhancements (Clipboard & WebSocket)

#### Paste Address Replacement Guard (Layer 9 Enhancement)
- **Attack Vector:** Malicious JS replaces pasted crypto addresses with attacker's address.
- **Detection:** `content.js:initPasteAddressGuard()` monitors paste events on input/textarea.
- **Logic:** Compares original clipboard content with field value after 50ms delay.
- **Supported Cryptos:** Bitcoin, Ethereum, Solana, Litecoin, Ripple, Dogecoin, Monero, TRON.
- **Response:** Auto-restores original address + shows critical warning (score: 15).
- **i18n Keys:** `pasteReplacementTitle`, `pasteReplacementMessage`, `pasteReplacementTip`, `reason_cryptoAddressReplacement`.

#### Payment Gateway Whitelist (Form Hijacking)
- **Purpose:** Prevents false positives during checkout flows.
- **Location:** `content.js:PAYMENT_GATEWAY_WHITELIST` (40+ domains).
- **Includes:** Stripe, PayPal, Adyen, Mollie, Klarna, iDEAL, Dutch banks (ING, Rabobank, ABN AMRO, Bunq).
- **Logic:** `isWhitelistedPaymentGateway(hostname)` checks exact match + subdomain inheritance.

#### WebSocket Monitoring (declarativeNetRequest)
- **Purpose:** Blocks hostile WebSocket connections (C2 servers, data exfiltration).
- **Location:** `background.js:initWebSocketBlocking()`.
- **Rule ID Range:** `800000-899999` (avoids conflicts with other dynamic rules).
- **Blocking Rules:**
  - Dangerous TLDs (.xyz, .tk, .ml, .ga, .cf, .gq, .click, etc.)
  - Direct IP addresses (common C2 pattern)
  - Suspicious high ports (>10000, excluding safe ports)
- **Whitelist:** Payment gateways + 200 trusted trackers from `hostileTrackers.json`.
- **Uses:** `resourceType: ['websocket']` for efficient filtering.
- **No new permissions required** - uses existing `declarativeNetRequest`.

### v8.8.1 - Tab Mismatch Bug Fix
- **Issue:** Warnings from Tab A were shown when clicking the icon on Tab B due to global `chrome.storage.local` usage.
- **Fix:** `dynamic.js` now validates the stored status hostname against the active tab hostname before displaying.

### v8.8.0 - Government Service Scam Detection (Layer 16)
- **Feature:** Detects unofficial sites charging high fees for official services (ETA, ESTA, Visas).
- **Logic:** `content.js:detectUnofficialGovernmentService()` scans headers/titles for keywords and compares against `config.js:OFFICIAL_GOVERNMENT_SERVICES`.
- **UI:** Shows an informative warning with the official URL and the correct (lower) price.

### v8.7.x - Infrastructure & FP Reduction
- **Layer 15:** Hostile Tracking Infrastructure detection via `webRequest`.
- **FP Fix:** Removed legitimate TLDs (.ai, .cloud, .tech) from suspicious list. Reduced standalone TLD score (7→4).
- **Security:** Fixed ASCII 'I/l' lookalike bypasses and SVG race conditions.

---

## Security Layers Summary
1. Phishing URLs & TLDs
2. Unicode/ASCII Lookalikes
3. Browser-in-the-Browser (BitB)
4. ClickFix/Malware Triggers
5. Visual Hijacking (Overlays)
6. Malicious QR Codes (incl. Split QR)
7. Dangerous Link Types (data:, blob:)
8. Form Hijacking (Action + Target monitoring)
9. Clipboard/OAuth Paste Guard + Crypto Address Swap Detection
10. Shadow DOM Scanning (with 500ms timeout)
11. Fake Turnstile/CAPTCHA
12. AiTM Proxy Detection (Evilginx)
13. Malicious SVG Payloads (incl. Data URI detection)
14. Hostile Tracking Infrastructure
15. Private Network Protection
16. Government Service Scams

---

## Known Limitations

### Closed Shadow DOM (Layer 10) - ARCHITECTURAL LIMITATION
**Status:** Cannot be fixed in Manifest V3 content scripts.

**Description:**
Elements with `attachShadow({ mode: 'closed' })` are completely inaccessible to content scripts. The `shadowRoot` property returns `null` for closed shadows, making it impossible to scan their contents.

**Attack Vector:**
Attackers can hide malicious links, forms, or overlays inside closed Shadow DOM that LinkShield cannot detect.

```javascript
// Attacker code - LinkShield cannot see this
const host = document.createElement('div');
const shadow = host.attachShadow({ mode: 'closed' });
shadow.innerHTML = '<a href="https://phishing.xyz/steal">Click here</a>';
document.body.appendChild(host);
```

**Mitigation:**
- Open Shadow DOM (`mode: 'open'`) IS scannable and protected.
- Other detection layers (URL analysis, TLD checking) still apply when users click links.
- Consider server-side validation for critical security flows.

**Technical Reason:**
This is a browser security boundary, not a LinkShield limitation. The Web Components spec intentionally prevents external access to closed shadows for encapsulation purposes.

---

## Development Guidelines

### 1. New Detection Features (CRITICAL)
Every detection function MUST:
1. **Check `integratedProtection`:** Use `await isProtectionEnabled()` to respect user settings.
2. **Skip Trusted Domains:** Use `await isTrustedDomain(window.location.hostname)`.
3. **Handle i18n:** Ensure keys exist in ALL 24 locale files (no English fallbacks).

### 2. Internationalization (i18n)
- Location: `_locales/[code]/messages.json`.
- All new features MUST be added to the popup tooltip in `popup.html` and `popup.js`.
- Update `tooltipFooter` counter when adding layers.

### 3. Testing
- `cd tests && npm test` (Jest).
- E2E tests in `tests/e2e/`.

### 4. DeclarativeNetRequest Rule ID Ranges
To avoid conflicts, use these reserved ranges:
| Range | Purpose |
|-------|---------|
| `1-999999` | Static rules from `rules.json` |
| `800000-899999` | WebSocket monitoring rules |
| `900000-999999` | Visual Hijacking Protection rules |
| `1000000+` | Dynamic rules from remote server |

---

## Changelog (Abbreviated)
| Version | Key Change |
|---------|------------|
| 8.9.2 | Zero-width character detection, recursive Base64 decoding (3 levels), Canvas/WebGL overlay detection, domain reputation API placeholder, visa whitelist expansion. |
| 8.9.1 | Clipboard hardening (300ms), advanced visibility checks, enterprise AiTM (Okta/Auth0/Salesforce), BitB pseudo-element detection. |
| 8.9.0 | Memory leak fixes, OAuth implicit flow, Fetch/XHR monitoring, Data URI hardening, Base64 PowerShell. |
| 8.8.3 | Form Target Hijacking, SVG Data URI Detection, Shadow DOM 500ms Timeout. |
| 8.8.2 | Paste Address Guard, Payment Gateway Whitelist, WebSocket Monitoring. |
| 8.8.1 | Fixed Tab Mismatch bug in popup/dynamic logic. |
| 8.8.0 | Added Government Service Scam Detection. |
| 8.7.3 | False Positive reduction for .ai/.cloud domains. |
| 8.7.0 | Added Hostile Tracker detection (Layer 15). |
| 8.6.1 | Improved Phishing URL detection rate (13% -> 88%). |
| 8.6.0 | Added AiTM Proxy & SVG Payload detection. |
| 8.5.0 | Added OAuth Paste Guard & Fake Turnstile detection. |
| 8.3.0 | Added Form Hijacking Protection. |