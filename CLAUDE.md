# LinkShield - Development Documentation

## Project Overview
**LinkShield** is a Chrome extension (MV3) protecting users from phishing and web-based attacks.
**Current Version:** 8.8.3 | **Layers of Protection:** 16

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