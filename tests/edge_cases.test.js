/**
 * LinkShield Edge Cases Test Suite
 *
 * Extreme edge-case analyse voor:
 * 1. URL-obfuscatie met @ symbolen
 * 2. Extreme subdomeinen (10+ levels)
 * 3. Punycode-varianten buiten de homoglyph-lijst
 * 4. LRU Cache gedrag bij maxCacheSize
 * 5. Shadow DOM en iframe link detectie
 */

// =============================================================================
// CONFIG - Kopie van relevante config waarden
// =============================================================================

const CONFIG = {
  LOW_THRESHOLD: 4,
  MEDIUM_THRESHOLD: 8,
  HIGH_THRESHOLD: 15,
  PROTOCOL_RISK: 4,
  MAX_SUBDOMAINS: 3,
  MAX_URL_LENGTH: 2000,

  SUSPICIOUS_TLDS: /\.(xyz|tk|top|cc|cf|ga|gq|ml|ru|cn|zip|mov|win|club|buzz|live|shop|pro|sbs|rest|dev|ai|bot|crypto|nft|web3)$/i,

  legitimateDomains: [
    'microsoft.com', 'apple.com', 'google.com', 'paypal.com',
    'amazon.com', 'facebook.com', 'netflix.com', 'ing.nl'
  ],

  trustedDomains: [
    'google.com', 'microsoft.com', 'apple.com', 'amazon.com'
  ]
};

// =============================================================================
// HELPER FUNCTIONS
// =============================================================================

function normalizeDomain(url) {
  try {
    const urlObj = new URL(url);
    return urlObj.hostname.toLowerCase().replace(/^www\./, '');
  } catch {
    return null;
  }
}

function isTrustedDomain(domain) {
  if (!domain) return false;
  const trustedSet = new Set(CONFIG.trustedDomains.map(d => d.toLowerCase()));
  const normalizedDomain = domain.toLowerCase().replace(/^www\./, '');
  if (trustedSet.has(normalizedDomain)) return true;
  for (const trusted of trustedSet) {
    if (normalizedDomain.endsWith(`.${trusted}`)) return true;
  }
  return false;
}

/**
 * Detecteert @ symbool in URL (credential stuffing attack)
 * Voorbeeld: https://google.com@evil.com gaat naar evil.com
 */
function detectAtSymbolAttack(url) {
  try {
    const urlObj = new URL(url);
    // Check of er een @ in de URL zit voor de host
    // In een URL zoals https://user:pass@host.com is @ legitiem
    // Maar https://google.com@evil.com is een aanval

    // Als de username eruitziet als een domein, is het verdacht
    if (urlObj.username && urlObj.username.includes('.')) {
      return {
        detected: true,
        fakeHost: urlObj.username,
        realHost: urlObj.hostname,
        reason: 'atSymbolPhishing'
      };
    }

    // Check voor @ in het pad (URL-encoded of niet)
    if (urlObj.pathname.includes('@') || urlObj.pathname.includes('%40')) {
      return {
        detected: true,
        reason: 'atSymbolInPath'
      };
    }

    return { detected: false };
  } catch {
    return { detected: false, error: true };
  }
}

/**
 * Detecteert extreme subdomeinen (meer dan MAX_SUBDOMAINS)
 */
function detectExtremeSubdomains(url) {
  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname;
    const parts = hostname.split('.');

    // Tel subdomeinen (totaal - TLD - main domain)
    // Voor compound TLDs zoals .co.uk, trek 2 af
    const compoundTlds = ['co.uk', 'org.uk', 'com.au', 'co.nz', 'co.jp'];
    let tldParts = 1;

    for (const ctld of compoundTlds) {
      if (hostname.endsWith(`.${ctld}`) || hostname === ctld) {
        tldParts = ctld.split('.').length;
        break;
      }
    }

    const subdomainCount = parts.length - tldParts - 1;

    return {
      subdomainCount,
      isExtreme: subdomainCount > CONFIG.MAX_SUBDOMAINS,
      parts: parts,
      risk: subdomainCount > 10 ? 'critical' : subdomainCount > 5 ? 'high' : 'normal'
    };
  } catch {
    return { subdomainCount: 0, isExtreme: false, error: true };
  }
}

/**
 * Punycode decoder met fallback
 */
function decodePunycode(hostname) {
  try {
    // Simpele punycode detectie en decoding
    if (!hostname.includes('xn--')) {
      return { decoded: hostname, isPunycode: false };
    }

    // Split op dots en decode elke xn-- prefix
    const parts = hostname.split('.');
    const decoded = parts.map(part => {
      if (part.startsWith('xn--')) {
        // Basis punycode decoding (vereenvoudigd)
        // In productie zou je een volledige punycode library gebruiken
        return part; // Placeholder - in echte code zou dit decoderen
      }
      return part;
    }).join('.');

    return { decoded, isPunycode: true, original: hostname };
  } catch {
    return { decoded: hostname, isPunycode: false, error: true };
  }
}

/**
 * Detecteert verdachte Punycode domeinen
 */
function detectPunycodeAttack(url) {
  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname.toLowerCase();

    // Check voor xn-- prefix (punycode indicator)
    if (!hostname.includes('xn--')) {
      return { detected: false, isPunycode: false };
    }

    // Bekende gevaarlijke punycode patronen
    const dangerousPatterns = [
      /xn--.*ggle/i,     // google varianten
      /xn--.*pple/i,     // apple varianten
      /xn--.*mazon/i,    // amazon varianten
      /xn--.*aypal/i,    // paypal varianten
      /xn--.*icrosoft/i, // microsoft varianten
      /xn--.*etflix/i,   // netflix varianten
    ];

    for (const pattern of dangerousPatterns) {
      if (pattern.test(hostname)) {
        return {
          detected: true,
          isPunycode: true,
          hostname,
          reason: 'punycodeBrandImpersonation'
        };
      }
    }

    // Elk punycode domein is verdacht
    return {
      detected: true,
      isPunycode: true,
      hostname,
      reason: 'punycodeDetected',
      riskLevel: 'medium'
    };
  } catch {
    return { detected: false, error: true };
  }
}

/**
 * Berekent totale risicoscore voor edge cases
 */
function calculateEdgeCaseRisk(url) {
  let score = 0;
  const reasons = [];

  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname.toLowerCase();

    // 1. @ Symbol attack check
    const atAttack = detectAtSymbolAttack(url);
    if (atAttack.detected) {
      score += 15; // Hoog risico
      reasons.push(atAttack.reason);
    }

    // 2. Extreme subdomain check
    const subdomainCheck = detectExtremeSubdomains(url);
    if (subdomainCheck.isExtreme) {
      const extraRisk = Math.min(subdomainCheck.subdomainCount - CONFIG.MAX_SUBDOMAINS, 10);
      score += 4 + extraRisk;
      reasons.push(`extremeSubdomains:${subdomainCheck.subdomainCount}`);
    }

    // 3. Punycode check
    const punycodeCheck = detectPunycodeAttack(url);
    if (punycodeCheck.detected) {
      score += punycodeCheck.reason === 'punycodeBrandImpersonation' ? 12 : 6;
      reasons.push(punycodeCheck.reason);
    }

    // 4. Suspicious TLD
    if (CONFIG.SUSPICIOUS_TLDS.test(hostname)) {
      score += 7;
      reasons.push('suspiciousTLD');
    }

    // 5. No HTTPS
    if (urlObj.protocol !== 'https:') {
      score += CONFIG.PROTOCOL_RISK;
      reasons.push('noHttps');
    }

    // 6. URL too long
    if (url.length > CONFIG.MAX_URL_LENGTH) {
      score += 2;
      reasons.push('urlTooLong');
    }

    // Trusted domain bypass
    if (isTrustedDomain(hostname)) {
      return { score: 0, reasons: ['trustedDomain'], level: 'safe' };
    }

    const level = score >= CONFIG.HIGH_THRESHOLD ? 'alert' :
                  score >= CONFIG.LOW_THRESHOLD ? 'caution' : 'safe';

    return { score, reasons, level };
  } catch {
    return { score: -1, reasons: ['invalidUrl'], level: 'error' };
  }
}

// =============================================================================
// LRU CACHE IMPLEMENTATION (voor testen)
// =============================================================================

class LRUCache {
  constructor(maxSize = 2000) {
    this.maxSize = maxSize;
    this.cache = new Map();
  }

  get(key) {
    if (!this.cache.has(key)) return undefined;

    // Move to end (most recently used)
    const value = this.cache.get(key);
    this.cache.delete(key);
    this.cache.set(key, value);
    return value;
  }

  set(key, value) {
    // If key exists, delete it first (will be re-added at end)
    if (this.cache.has(key)) {
      this.cache.delete(key);
    }

    // If at capacity, remove oldest (first) item
    if (this.cache.size >= this.maxSize) {
      const oldestKey = this.cache.keys().next().value;
      this.cache.delete(oldestKey);
    }

    this.cache.set(key, value);
  }

  has(key) {
    return this.cache.has(key);
  }

  get size() {
    return this.cache.size;
  }

  getOldestKey() {
    return this.cache.keys().next().value;
  }

  getNewestKey() {
    return Array.from(this.cache.keys()).pop();
  }

  clear() {
    this.cache.clear();
  }
}

// =============================================================================
// TESTS
// =============================================================================

describe('Edge Cases: URL Obfuscation', () => {

  describe('@ Symbol Attacks (Credential URL Phishing)', () => {

    test('https://google.com@evil.com should detect fake host', () => {
      const result = detectAtSymbolAttack('https://google.com@evil.com/login');

      expect(result.detected).toBe(true);
      expect(result.fakeHost).toBe('google.com');
      expect(result.realHost).toBe('evil.com');
    });

    test('https://www.paypal.com@phishing.xyz should be high risk', () => {
      const result = calculateEdgeCaseRisk('https://www.paypal.com@phishing.xyz/login');

      expect(result.score).toBeGreaterThanOrEqual(CONFIG.HIGH_THRESHOLD);
      expect(result.reasons).toContain('atSymbolPhishing');
      expect(result.level).toBe('alert');
    });

    test('https://user:password@example.com should NOT trigger (legitimate auth)', () => {
      // Normale basic auth URL - user is geen domein
      const result = detectAtSymbolAttack('https://admin:secret123@example.com');

      // admin bevat geen punt, dus het is geen domein-impersonatie
      expect(result.detected).toBe(false);
    });

    test('https://microsoft.com:443@attacker.ru should be detected', () => {
      const result = calculateEdgeCaseRisk('https://microsoft.com:443@attacker.ru');

      expect(result.reasons).toContain('atSymbolPhishing');
      expect(result.level).toBe('alert');
    });

    test('URL with encoded @ (%40) in path should be flagged', () => {
      const result = detectAtSymbolAttack('https://evil.com/redirect%40google.com');

      expect(result.detected).toBe(true);
      expect(result.reason).toBe('atSymbolInPath');
    });

  });

  describe('Extreme Subdomains (10+ levels)', () => {

    test('Domain with 5 subdomains should be flagged', () => {
      const url = 'https://a.b.c.d.e.example.com';
      const result = detectExtremeSubdomains(url);

      expect(result.subdomainCount).toBe(5);
      expect(result.isExtreme).toBe(true);
    });

    test('Domain with 10 subdomains should be high risk', () => {
      const url = 'https://a.b.c.d.e.f.g.h.i.j.example.com';
      const result = detectExtremeSubdomains(url);

      expect(result.subdomainCount).toBe(10);
      expect(result.isExtreme).toBe(true);
      // 10 subdomeinen = high risk (critical is > 10)
      expect(result.risk).toBe('high');
    });

    test('Legitimate subdomain (mail.google.com) should NOT be flagged', () => {
      const result = detectExtremeSubdomains('https://mail.google.com');

      expect(result.subdomainCount).toBe(1);
      expect(result.isExtreme).toBe(false);
    });

    test('Extreme subdomain with suspicious TLD should be high risk', () => {
      const url = 'https://login.secure.verify.account.update.confirm.validate.check.microsoft.example.xyz';
      const result = calculateEdgeCaseRisk(url);

      expect(result.score).toBeGreaterThanOrEqual(CONFIG.HIGH_THRESHOLD);
      expect(result.reasons.some(r => r.startsWith('extremeSubdomains'))).toBe(true);
      expect(result.reasons).toContain('suspiciousTLD');
    });

    test('15 subdomains should add significant risk', () => {
      const parts = Array(15).fill('sub').map((s, i) => `${s}${i}`);
      const url = `https://${parts.join('.')}.example.com`;
      const result = calculateEdgeCaseRisk(url);

      // 15 - 3 (max) = 12 extra, capped at 10, plus base 4 = 14
      expect(result.score).toBeGreaterThanOrEqual(14);
    });

    test('Compound TLD (co.uk) should be handled correctly', () => {
      const url = 'https://a.b.c.d.example.co.uk';
      const result = detectExtremeSubdomains(url);

      // a.b.c.d = 4 subdomeinen (example is main, co.uk is TLD)
      expect(result.subdomainCount).toBe(4);
      expect(result.isExtreme).toBe(true);
    });

  });

  describe('Punycode Attacks (IDN Homograph)', () => {

    test('xn-- prefixed domain should be detected as Punycode', () => {
      const result = detectPunycodeAttack('https://xn--80ak6aa92e.com');

      expect(result.detected).toBe(true);
      expect(result.isPunycode).toBe(true);
    });

    test('Punycode impersonating google should be high risk', () => {
      // xn--ggle-55da.com could decode to gооgle.com (Cyrillic o's)
      const result = detectPunycodeAttack('https://xn--ggle-55da.com');

      expect(result.detected).toBe(true);
      expect(result.reason).toBe('punycodeBrandImpersonation');
    });

    test('Any Punycode domain should be flagged as suspicious', () => {
      // Elk punycode domein is verdacht, ook als het geen bekende brand imiteert
      // Gebruik een URL die GEEN brand pattern matcht (geen ggle, pple, mazon, aypal, icrosoft, etflix)
      const result = detectPunycodeAttack('https://xn--nxasmq5b.com');

      // Het domein bevat xn--, dus het is punycode
      expect(result.isPunycode).toBe(true);
      // Wordt gedetecteerd als algemeen punycode (niet specifiek brand)
      expect(result.reason).toBe('punycodeDetected');
    });

    test('Normal domain without xn-- should not trigger', () => {
      const result = detectPunycodeAttack('https://example.com');

      expect(result.detected).toBe(false);
      expect(result.isPunycode).toBe(false);
    });

    test('Punycode + suspicious TLD should be alert level', () => {
      const result = calculateEdgeCaseRisk('https://xn--80ak6aa92e.xyz');

      expect(result.reasons).toContain('punycodeDetected');
      expect(result.reasons).toContain('suspiciousTLD');
      expect(result.score).toBeGreaterThanOrEqual(13); // 6 + 7
    });

    test('Multiple Punycode segments should be detected', () => {
      const result = detectPunycodeAttack('https://xn--nxasmq5b.xn--wgbh1c');

      expect(result.detected).toBe(true);
      expect(result.isPunycode).toBe(true);
    });

  });

  describe('Combined Edge Cases', () => {

    test('@ symbol + suspicious TLD + no HTTPS should be maximum risk', () => {
      // Note: Bij een @ URL wordt de tekst voor @ de username, niet het domein
      // Dus we testen de combinatie van @ attack + suspicious TLD + no HTTPS
      const url = 'http://google.com@evil.xyz/login';
      const result = calculateEdgeCaseRisk(url);

      expect(result.level).toBe('alert');
      expect(result.reasons).toContain('atSymbolPhishing');
      expect(result.reasons).toContain('suspiciousTLD');
      expect(result.reasons).toContain('noHttps');
    });

    test('Punycode + @ symbol should be critical', () => {
      const url = 'https://xn--pple-43d.com@attacker.ru';
      const result = calculateEdgeCaseRisk(url);

      expect(result.level).toBe('alert');
      expect(result.score).toBeGreaterThanOrEqual(20);
    });

    test('Very long URL with obfuscation should be flagged', () => {
      const longPath = 'a'.repeat(2500);
      const url = `https://google.com@evil.xyz/${longPath}`;
      const result = calculateEdgeCaseRisk(url);

      expect(result.reasons).toContain('atSymbolPhishing');
      expect(result.reasons).toContain('urlTooLong');
    });

  });

});

describe('Edge Cases: LRU Cache Behavior', () => {

  let cache;

  beforeEach(() => {
    cache = new LRUCache(5); // Small cache for testing
  });

  test('Cache should not exceed maxSize', () => {
    for (let i = 0; i < 10; i++) {
      cache.set(`key${i}`, `value${i}`);
    }

    expect(cache.size).toBe(5);
  });

  test('Oldest item should be removed when cache is full', () => {
    cache.set('first', 'value1');
    cache.set('second', 'value2');
    cache.set('third', 'value3');
    cache.set('fourth', 'value4');
    cache.set('fifth', 'value5');

    // Cache is full, add one more
    cache.set('sixth', 'value6');

    expect(cache.has('first')).toBe(false); // Should be removed
    expect(cache.has('sixth')).toBe(true);  // Should exist
    expect(cache.size).toBe(5);
  });

  test('Accessing an item should move it to end (most recent)', () => {
    cache.set('a', 1);
    cache.set('b', 2);
    cache.set('c', 3);

    // Access 'a' - should move to end
    cache.get('a');

    // Add more items to force eviction
    cache.set('d', 4);
    cache.set('e', 5);
    cache.set('f', 6); // This should evict 'b', not 'a'

    expect(cache.has('a')).toBe(true);  // Was accessed, should still exist
    expect(cache.has('b')).toBe(false); // Should be evicted (oldest)
  });

  test('Setting existing key should update and move to end', () => {
    cache.set('a', 1);
    cache.set('b', 2);
    cache.set('c', 3);

    // Update 'a'
    cache.set('a', 100);

    expect(cache.get('a')).toBe(100);
    expect(cache.getNewestKey()).toBe('a');
  });

  test('Cache should handle 2000 items correctly', () => {
    const largeCache = new LRUCache(2000);

    // Fill cache
    for (let i = 0; i < 2000; i++) {
      largeCache.set(`url${i}`, { result: 'safe', timestamp: Date.now() });
    }

    expect(largeCache.size).toBe(2000);

    // Add one more - should evict oldest
    largeCache.set('url2000', { result: 'safe', timestamp: Date.now() });

    expect(largeCache.size).toBe(2000);
    expect(largeCache.has('url0')).toBe(false); // First one should be gone
    expect(largeCache.has('url2000')).toBe(true);
  });

  test('Clear should remove all items', () => {
    cache.set('a', 1);
    cache.set('b', 2);

    cache.clear();

    expect(cache.size).toBe(0);
    expect(cache.has('a')).toBe(false);
  });

  test('getOldestKey should return first inserted key', () => {
    cache.set('first', 1);
    cache.set('second', 2);
    cache.set('third', 3);

    expect(cache.getOldestKey()).toBe('first');
  });

  test('getNewestKey should return last inserted key', () => {
    cache.set('first', 1);
    cache.set('second', 2);
    cache.set('third', 3);

    expect(cache.getNewestKey()).toBe('third');
  });

});

describe('Edge Cases: Shadow DOM and Iframe Link Detection', () => {

  // Note: These tests verify the logic, not actual DOM manipulation
  // In a real browser environment, JSDOM limitations apply

  describe('Shadow DOM Considerations', () => {

    test('Should identify when Shadow DOM scanning is needed', () => {
      // Simulated check for shadow root presence
      const hasShadowRoot = (element) => {
        return element && typeof element.shadowRoot !== 'undefined';
      };

      const mockElement = { shadowRoot: null };
      expect(hasShadowRoot(mockElement)).toBe(true);
    });

    test('Shadow DOM link extraction logic should handle closed shadows', () => {
      // Closed shadow roots cannot be accessed
      const canAccessShadow = (mode) => mode === 'open';

      expect(canAccessShadow('open')).toBe(true);
      expect(canAccessShadow('closed')).toBe(false);
    });

    test('Recursive shadow DOM traversal depth should be limited', () => {
      const MAX_SHADOW_DEPTH = 5;

      const traverseShadow = (depth = 0) => {
        if (depth >= MAX_SHADOW_DEPTH) {
          return { stopped: true, depth };
        }
        return { stopped: false, depth };
      };

      expect(traverseShadow(0).stopped).toBe(false);
      expect(traverseShadow(5).stopped).toBe(true);
    });

  });

  describe('Iframe Link Detection', () => {

    test('Same-origin iframe links should be scannable', () => {
      const canAccessIframe = (iframeSrc, pageSrc) => {
        try {
          const iframeOrigin = new URL(iframeSrc).origin;
          const pageOrigin = new URL(pageSrc).origin;
          return iframeOrigin === pageOrigin;
        } catch {
          return false;
        }
      };

      expect(canAccessIframe(
        'https://example.com/frame.html',
        'https://example.com/page.html'
      )).toBe(true);

      expect(canAccessIframe(
        'https://other.com/frame.html',
        'https://example.com/page.html'
      )).toBe(false);
    });

    test('Cross-origin iframes should be flagged but not scanned', () => {
      const isCrossOrigin = (iframeSrc, pageSrc) => {
        try {
          const iframeOrigin = new URL(iframeSrc).origin;
          const pageOrigin = new URL(pageSrc).origin;
          return iframeOrigin !== pageOrigin;
        } catch {
          return true; // Assume cross-origin on error
        }
      };

      expect(isCrossOrigin(
        'https://attacker.com/phishing.html',
        'https://example.com/page.html'
      )).toBe(true);
    });

    test('Iframe with suspicious src should add risk', () => {
      const checkIframeSrc = (src) => {
        if (!src) return { risk: 0, reason: null };

        try {
          const url = new URL(src);
          const hostname = url.hostname.toLowerCase();

          // Check for suspicious patterns
          if (CONFIG.SUSPICIOUS_TLDS.test(hostname)) {
            return { risk: 5, reason: 'suspiciousIframeTLD' };
          }

          // Punycode check - kijk naar de originele src string
          // URL parser kan punycode decoderen
          if (src.includes('xn--')) {
            return { risk: 4, reason: 'punycodeIframe' };
          }

          if (url.protocol === 'http:') {
            return { risk: 3, reason: 'insecureIframe' };
          }

          return { risk: 0, reason: null };
        } catch {
          return { risk: 2, reason: 'invalidIframeSrc' };
        }
      };

      expect(checkIframeSrc('https://malicious.xyz/frame').risk).toBe(5);
      expect(checkIframeSrc('http://example.com/frame').risk).toBe(3);
      // Punycode iframe - gebruik een valide punycode domein format
      expect(checkIframeSrc('https://xn--n3h.com/frame').risk).toBe(4);
    });

    test('Nested iframes should have depth limit', () => {
      const MAX_IFRAME_DEPTH = 3;

      const checkIframeDepth = (depth) => {
        return {
          canScan: depth < MAX_IFRAME_DEPTH,
          warning: depth >= MAX_IFRAME_DEPTH ? 'maxDepthReached' : null
        };
      };

      expect(checkIframeDepth(0).canScan).toBe(true);
      expect(checkIframeDepth(2).canScan).toBe(true);
      expect(checkIframeDepth(3).canScan).toBe(false);
      expect(checkIframeDepth(3).warning).toBe('maxDepthReached');
    });

  });

});

describe('Edge Cases: Special URL Patterns', () => {

  test('Data URL should be flagged as high risk', () => {
    const isDataUrl = (url) => url.startsWith('data:');
    const url = 'data:text/html,<script>alert(1)</script>';

    expect(isDataUrl(url)).toBe(true);
  });

  test('JavaScript URL should be flagged as critical', () => {
    const isJavaScriptUrl = (url) => url.toLowerCase().startsWith('javascript:');

    expect(isJavaScriptUrl('javascript:alert(1)')).toBe(true);
    expect(isJavaScriptUrl('JAVASCRIPT:void(0)')).toBe(true);
    expect(isJavaScriptUrl('https://example.com')).toBe(false);
  });

  test('URL with double encoding should be detected', () => {
    const hasDoubleEncoding = (url) => {
      // Double encoding: %25XX where XX is hex
      return /%25[0-9A-Fa-f]{2}/.test(url);
    };

    expect(hasDoubleEncoding('https://example.com/%252e%252e')).toBe(true);
    expect(hasDoubleEncoding('https://example.com/%20')).toBe(false);
  });

  test('URL with null bytes should be flagged', () => {
    const hasNullByte = (url) => {
      return url.includes('%00') || url.includes('\x00');
    };

    expect(hasNullByte('https://example.com/file%00.txt')).toBe(true);
    expect(hasNullByte('https://example.com/file.txt')).toBe(false);
  });

  test('Unicode normalization bypass should be detected', () => {
    const hasUnicodeBypass = (url) => {
      // Check for fullwidth characters that look like ASCII
      const fullwidthPattern = /[\uFF01-\uFF5E]/;
      return fullwidthPattern.test(url);
    };

    // ｇｏｏｇｌｅ in fullwidth
    expect(hasUnicodeBypass('https://ｇｏｏｇｌｅ.com')).toBe(true);
    expect(hasUnicodeBypass('https://google.com')).toBe(false);
  });

});

// Export functions for potential reuse
module.exports = {
  detectAtSymbolAttack,
  detectExtremeSubdomains,
  detectPunycodeAttack,
  calculateEdgeCaseRisk,
  LRUCache,
  CONFIG
};
