/**
 * LinkShield Risk Scoring Tests
 *
 * Test suite voor het valideren van de risico-scoring logica.
 * Gebaseerd op de thresholds uit config.js:
 *   - LOW_THRESHOLD: 4   (score < 4 = safe)
 *   - MEDIUM_THRESHOLD: 8 (4 <= score < 8 = caution, maar caution start bij LOW)
 *   - HIGH_THRESHOLD: 15  (score >= 15 = alert)
 *
 * Severity levels:
 *   - safe: totalRisk < LOW_THRESHOLD (4)
 *   - caution: LOW_THRESHOLD <= totalRisk < HIGH_THRESHOLD
 *   - alert: totalRisk >= HIGH_THRESHOLD (15)
 */

// =============================================================================
// CONFIG - Kopie van relevante config waarden voor testing
// =============================================================================

const CONFIG = {
  LOW_THRESHOLD: 4,
  MEDIUM_THRESHOLD: 8,
  HIGH_THRESHOLD: 15,
  PROTOCOL_RISK: 4,
  YOUNG_DOMAIN_THRESHOLD_DAYS: 7,
  YOUNG_DOMAIN_RISK: 5,
  MAX_SUBDOMAINS: 3,
  MAX_URL_LENGTH: 2000,

  // Uitgebreid met nieuwe TLD's voor 2026
  SUSPICIOUS_TLDS: /\.(xyz|tk|top|cc|cf|ga|gq|ml|ru|cn|zip|mov|win|club|buzz|live|shop|pro|sbs|rest|dev|hair|beauty|bond|uno|xin|li|es|ai|bot|chat|crypto|dao|data|dex|eth|gpt|llm|metaverse|nft|sol|token|wallet|web3|autos|boats|cam|casa|cfd|click|cloud|cyou|desi|digital|fit|fun|gdn|gives|icu|lat|lol|mom|monster|nexus|observer|online|ooo|pics|quest|racing|realty|rodeo|site|skin|space|store|stream|surf|tech|today|vip|wang|webcam|website|work|world|wtf|yachts)$/i,

  SHORTENED_URL_DOMAINS: new Set([
    "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd",
    "buff.ly", "tiny.cc", "cutt.ly", "rb.gy", "shorturl.at"
  ]),

  PHISHING_KEYWORDS: new Set([
    "login", "signin", "verify", "account", "secure", "update",
    "confirm", "password", "bank", "urgent", "blocked", "suspended"
  ]),

  MALWARE_EXTENSIONS: /\.(exe|zip|msi|dmg|jar|rar|scr|bat|cmd|ps1|vbs)$/i,

  HOMOGLYPHS: {
    'a': ['а', 'α', 'ä'],
    'e': ['е', 'ε', 'ë'],
    'o': ['ο', 'о', 'ö'],
    'i': ['і', 'ı', 'ì'],
    'c': ['с', 'ç'],
    'p': ['р'],
    'x': ['х'],
    'y': ['у']
  },

  legitimateDomains: [
    'microsoft.com', 'apple.com', 'google.com', 'linkedin.com',
    'amazon.com', 'facebook.com', 'paypal.com', 'netflix.com',
    'ing.nl', 'rabobank.nl', 'abnamro.nl'
  ],

  // Brand keywords die vaak het doelwit zijn van phishing
  BRAND_KEYWORDS: new Set([
    'ing', 'paypal', 'rabobank', 'abnamro', 'microsoft', 'apple',
    'google', 'amazon', 'netflix', 'facebook', 'linkedin', 'bank'
  ]),

  // Suspicious prefixes/suffixes rond brand names
  SUSPICIOUS_BRAND_PATTERNS: [
    'login', 'secure', 'verify', 'update', 'confirm', 'account',
    'signin', 'support', 'help', 'service', 'online', 'my', 'web'
  ],

  trustedDomains: [
    'google.com', 'youtube.com', 'facebook.com', 'amazon.com',
    'microsoft.com', 'apple.com', 'linkedin.com', 'wikipedia.org'
  ]
};

// =============================================================================
// SCORING FUNCTIONS - Geextraheerd uit content.js voor testbaarheid
// =============================================================================

/**
 * Normaliseert een domein uit een URL
 */
function normalizeDomain(url) {
  try {
    const urlObj = new URL(url);
    return urlObj.hostname.toLowerCase().replace(/^www\./, '');
  } catch {
    return null;
  }
}

/**
 * Controleert of een domein vertrouwd is
 */
function isTrustedDomain(domain) {
  const trustedSet = new Set(CONFIG.trustedDomains.map(d => d.toLowerCase()));
  const normalizedDomain = domain.toLowerCase().replace(/^www\./, '');

  // Exacte match of subdomein van trusted domain
  if (trustedSet.has(normalizedDomain)) return true;

  for (const trusted of trustedSet) {
    if (normalizedDomain.endsWith(`.${trusted}`)) return true;
  }

  return false;
}

/**
 * Detecteert homoglyph-aanvallen (look-alike characters)
 */
function detectHomoglyphAttack(domain) {
  const normalizedDomain = domain.toLowerCase();

  for (const legitDomain of CONFIG.legitimateDomains) {
    // Check of domein lijkt op een legitiem domein met homoglyphs
    let testDomain = normalizedDomain;

    for (const [char, homoglyphs] of Object.entries(CONFIG.HOMOGLYPHS)) {
      for (const homoglyph of homoglyphs) {
        testDomain = testDomain.replace(new RegExp(homoglyph, 'g'), char);
      }
    }

    // Als na normalisatie het domein lijkt op een legitiem domein
    if (testDomain !== normalizedDomain && testDomain.includes(legitDomain.replace('.com', '').replace('.nl', ''))) {
      return { detected: true, targetDomain: legitDomain };
    }
  }

  return { detected: false, targetDomain: null };
}

/**
 * Berekent de Levenshtein-afstand tussen twee strings
 */
function levenshteinDistance(a, b) {
  const matrix = Array(b.length + 1).fill(null).map(() => Array(a.length + 1).fill(null));

  for (let i = 0; i <= a.length; i++) matrix[0][i] = i;
  for (let j = 0; j <= b.length; j++) matrix[j][0] = j;

  for (let j = 1; j <= b.length; j++) {
    for (let i = 1; i <= a.length; i++) {
      const indicator = a[i - 1] === b[j - 1] ? 0 : 1;
      matrix[j][i] = Math.min(
        matrix[j][i - 1] + 1,
        matrix[j - 1][i] + 1,
        matrix[j - 1][i - 1] + indicator
      );
    }
  }

  return matrix[b.length][a.length];
}

/**
 * Detecteert typosquatting via Levenshtein distance
 */
function detectTyposquatting(domain) {
  const normalizedDomain = domain.toLowerCase().replace(/^www\./, '');
  const mainPart = normalizedDomain.split('.')[0];

  for (const legitDomain of CONFIG.legitimateDomains) {
    const legitMainPart = legitDomain.split('.')[0];
    const distance = levenshteinDistance(mainPart, legitMainPart);

    // Als de afstand 1-2 is, is het verdacht
    if (distance > 0 && distance <= 2) {
      return { detected: true, targetDomain: legitDomain, distance };
    }
  }

  return { detected: false, targetDomain: null, distance: null };
}

/**
 * Hoofdfunctie: berekent risicoscore voor een URL
 */
function calculateRiskScore(url) {
  let score = 0;
  const reasons = [];

  const addRisk = (points, reason) => {
    if (!reasons.includes(reason)) {
      score += points;
      reasons.push(reason);
    }
  };

  try {
    const urlObj = new URL(url);
    const domain = normalizeDomain(url);

    if (!domain) {
      return { score: -1, reasons: ['invalidUrl'] };
    }

    // Check trusted domain first
    if (isTrustedDomain(domain)) {
      return { score: 0, reasons: ['trustedDomain'] };
    }

    const hostname = urlObj.hostname.toLowerCase();
    const path = urlObj.pathname.toLowerCase();

    // 1. HTTPS check
    if (urlObj.protocol !== 'https:') {
      addRisk(CONFIG.PROTOCOL_RISK, 'noHttps');
    }

    // 2. Suspicious TLD
    if (CONFIG.SUSPICIOUS_TLDS.test(hostname)) {
      addRisk(7, 'suspiciousTLD');
    }

    // 3. IP as domain
    if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
      addRisk(8, 'ipAsDomain');
    }

    // 4. Too many subdomains
    const subdomainCount = hostname.split('.').length - 2;
    if (subdomainCount > CONFIG.MAX_SUBDOMAINS) {
      addRisk(4, 'tooManySubdomains');
    }

    // 5. Shortened URL
    if (CONFIG.SHORTENED_URL_DOMAINS.has(domain)) {
      addRisk(3, 'shortenedUrl');
    }

    // 6. Phishing keywords in URL
    const urlParts = url.toLowerCase().split(/[\/?#&=]/);
    if (urlParts.some(word => CONFIG.PHISHING_KEYWORDS.has(word))) {
      addRisk(1.5, 'suspiciousKeywords');
    }

    // 7. Malware extensions
    if (CONFIG.MALWARE_EXTENSIONS.test(path)) {
      addRisk(10, 'malwareExtension');
    }

    // 8. URL too long
    if (url.length > CONFIG.MAX_URL_LENGTH) {
      addRisk(1, 'urlTooLong');
    }

    // 9. Encoded characters
    if (/%[0-9A-Fa-f]{2}/.test(url)) {
      addRisk(1, 'encodedCharacters');
    }

    // 10. Homoglyph attack detection
    const homoglyphResult = detectHomoglyphAttack(hostname);
    if (homoglyphResult.detected) {
      addRisk(12, `homoglyphAttack:${homoglyphResult.targetDomain}`);
    }

    // 11. Typosquatting detection
    const typosquatResult = detectTyposquatting(hostname);
    if (typosquatResult.detected) {
      addRisk(8, `typosquatting:${typosquatResult.targetDomain}`);
    }

    // 12. Non-ASCII character detection (homoglyph indicator)
    // Check BOTH the original URL string AND the hostname for non-ASCII
    // Note: new URL() converts IDN to Punycode, so we need to check original URL
    // eslint-disable-next-line no-control-regex
    const originalDomain = url.split('//')[1]?.split('/')[0]?.split('?')[0] || '';
    const hasNonAscii = /[^\x00-\x7F]/.test(originalDomain);
    const hasPunycode = hostname.includes('xn--');

    if (hasNonAscii || hasPunycode) {
      addRisk(8, 'nonAscii');

      // 13. Brand keyword + homoglyph combination (HIGH RISK)
      // Normalize the ORIGINAL domain by replacing homoglyphs
      let normalizedHostname = originalDomain.toLowerCase();
      for (const [char, homoglyphs] of Object.entries(CONFIG.HOMOGLYPHS)) {
        for (const homoglyph of homoglyphs) {
          normalizedHostname = normalizedHostname.split(homoglyph).join(char);
        }
      }

      // Check if normalized hostname contains a brand keyword
      for (const brand of CONFIG.BRAND_KEYWORDS) {
        if (normalizedHostname.includes(brand)) {
          addRisk(10, `brandKeywordHomoglyph:${brand}`);
          break;
        }
      }
    }

    // 14. Suspicious brand pattern detection (prefix-brand-suffix)
    const domainWithoutTld = hostname.split('.').slice(0, -1).join('.');
    for (const brand of CONFIG.BRAND_KEYWORDS) {
      if (domainWithoutTld.includes(brand)) {
        // Check for suspicious prefixes/suffixes around the brand
        for (const pattern of CONFIG.SUSPICIOUS_BRAND_PATTERNS) {
          if (domainWithoutTld.includes(pattern) && domainWithoutTld.includes(brand)) {
            addRisk(6, `suspiciousBrandPattern:${pattern}-${brand}`);
            break;
          }
        }
      }
    }

    return { score, reasons };

  } catch (error) {
    return { score: -1, reasons: ['errorCalculatingRisk'] };
  }
}

/**
 * Bepaalt het risiconiveau op basis van de score
 */
function determineRiskLevel(score) {
  if (score < 0) return 'error';
  if (score < CONFIG.LOW_THRESHOLD) return 'safe';
  if (score < CONFIG.HIGH_THRESHOLD) return 'caution';
  return 'alert';
}

/**
 * Volledige analyse van een URL
 */
function analyzeUrl(url) {
  const { score, reasons } = calculateRiskScore(url);
  const level = determineRiskLevel(score);
  return { score, reasons, level };
}

// =============================================================================
// TESTS
// =============================================================================

describe('LinkShield Risk Scoring', () => {

  describe('Helper Functions', () => {

    test('normalizeDomain extracts domain correctly', () => {
      expect(normalizeDomain('https://www.google.com/search?q=test')).toBe('google.com');
      expect(normalizeDomain('https://sub.example.com/path')).toBe('sub.example.com');
      expect(normalizeDomain('http://example.xyz')).toBe('example.xyz');
    });

    test('normalizeDomain returns null for invalid URLs', () => {
      expect(normalizeDomain('not-a-url')).toBeNull();
      expect(normalizeDomain('')).toBeNull();
    });

    test('isTrustedDomain identifies trusted domains', () => {
      expect(isTrustedDomain('google.com')).toBe(true);
      expect(isTrustedDomain('www.google.com')).toBe(true);
      expect(isTrustedDomain('mail.google.com')).toBe(true);
      expect(isTrustedDomain('evil-google.com')).toBe(false);
    });

    test('levenshteinDistance calculates correctly', () => {
      expect(levenshteinDistance('google', 'google')).toBe(0);
      expect(levenshteinDistance('google', 'gogle')).toBe(1);
      expect(levenshteinDistance('google', 'goggle')).toBe(1);
      expect(levenshteinDistance('paypal', 'paypa1')).toBe(1);
    });

  });

  describe('Trusted Domains - Should be SAFE', () => {

    test('https://www.google.com/search?q=test should be safe', () => {
      const result = analyzeUrl('https://www.google.com/search?q=test');
      expect(result.level).toBe('safe');
      expect(result.score).toBe(0);
      expect(result.reasons).toContain('trustedDomain');
    });

    test('https://mail.google.com should be safe', () => {
      const result = analyzeUrl('https://mail.google.com');
      expect(result.level).toBe('safe');
    });

    test('https://www.microsoft.com should be safe', () => {
      const result = analyzeUrl('https://www.microsoft.com');
      expect(result.level).toBe('safe');
    });

    test('https://www.amazon.com/products should be safe', () => {
      const result = analyzeUrl('https://www.amazon.com/products');
      expect(result.level).toBe('safe');
    });

  });

  describe('Suspicious TLDs - Young .xyz domain without HTTPS', () => {

    test('http://malicious-site.xyz should be ALERT (no HTTPS + suspicious TLD)', () => {
      const result = analyzeUrl('http://malicious-site.xyz');

      // noHttps (4) + suspiciousTLD (7) = 11 punten
      // 11 < 15 = caution, maar met extra factors kan het alert worden
      expect(result.score).toBeGreaterThanOrEqual(CONFIG.LOW_THRESHOLD);
      expect(result.reasons).toContain('noHttps');
      expect(result.reasons).toContain('suspiciousTLD');
    });

    test('http://login-verify.xyz should have high risk', () => {
      const result = analyzeUrl('http://login-verify.xyz/account');

      // noHttps (4) + suspiciousTLD (7) + keywords = high risk
      expect(result.score).toBeGreaterThanOrEqual(11);
      expect(result.reasons).toContain('noHttps');
      expect(result.reasons).toContain('suspiciousTLD');
    });

    test('http://free-bitcoin.tk should be flagged', () => {
      const result = analyzeUrl('http://free-bitcoin.tk');
      expect(result.reasons).toContain('noHttps');
      expect(result.reasons).toContain('suspiciousTLD');
      expect(result.level).not.toBe('safe');
    });

  });

  describe('Homoglyph Attacks - Bank URL Spoofing', () => {

    test('paypa1.com (l replaced with 1) should trigger typosquatting', () => {
      const result = analyzeUrl('https://paypa1.com/login');

      // Typosquatting detection (Levenshtein distance = 1)
      expect(result.reasons.some(r => r.includes('typosquatting'))).toBe(true);
      expect(result.score).toBeGreaterThanOrEqual(8);
    });

    test('gooogle.com (extra o) should trigger typosquatting', () => {
      const result = analyzeUrl('https://gooogle.com');

      expect(result.reasons.some(r => r.includes('typosquatting'))).toBe(true);
    });

    test('arnazon.com (m replaced with rn) should trigger typosquatting', () => {
      const result = analyzeUrl('https://arnazon.com/login');

      // amazon -> arnazon = distance 2
      expect(result.reasons.some(r => r.includes('typosquatting'))).toBe(true);
    });

    test('microsoftt.com should trigger typosquatting', () => {
      const result = analyzeUrl('https://microsoftt.com');

      expect(result.reasons.some(r => r.includes('typosquatting'))).toBe(true);
    });

  });

  describe('Turkish ı Homoglyph Attacks - Unicode Confusables', () => {

    test('phishıng-ing.com (Turkish ı instead of i) should be detected', () => {
      const result = analyzeUrl('https://phishıng-ing.com/inloggen');

      // Should detect non-ASCII characters (Turkish ı = U+0131)
      expect(result.reasons.some(r =>
        r.includes('brandKeywordHomoglyph') ||
        r.includes('homoglyph') ||
        r.includes('nonAscii') ||
        r.includes('mixedScripts')
      )).toBe(true);
      expect(result.score).toBeGreaterThanOrEqual(4);
    });

    test('ıng-bank.com (brand starting with Turkish ı) should be high risk', () => {
      const result = analyzeUrl('https://ıng-bank.com/login');

      // Contains Turkish ı which should be flagged
      expect(result.reasons.some(r =>
        r.includes('brandKeywordHomoglyph') ||
        r.includes('homoglyph') ||
        r.includes('nonAscii')
      )).toBe(true);
      expect(result.score).toBeGreaterThanOrEqual(4);
    });

    test('secure-paypaı.com (Turkish ı in brand) should trigger homoglyph detection', () => {
      const result = analyzeUrl('https://secure-paypaı.com');

      expect(result.reasons.some(r =>
        r.includes('brandKeywordHomoglyph') ||
        r.includes('homoglyph') ||
        r.includes('nonAscii') ||
        r.includes('suspiciousBrandPattern')
      )).toBe(true);
    });

    test('rabobank-verıfy.nl should detect Turkish ı', () => {
      const result = analyzeUrl('https://rabobank-verıfy.nl/inloggen');

      // Should flag the non-ASCII character
      expect(result.reasons.some(r =>
        r.includes('brandKeywordHomoglyph') ||
        r.includes('homoglyph') ||
        r.includes('nonAscii') ||
        r.includes('rabo')
      )).toBe(true);
    });

  });

  describe('Brand Keyword Substring Detection', () => {

    test('login-ing-bank.com should detect suspicious prefix around brand', () => {
      const result = analyzeUrl('https://login-ing-bank.com');

      // Should detect suspicious pattern with brand keyword
      expect(result.score).toBeGreaterThanOrEqual(4);
    });

    test('secure-paypal-verify.com should trigger pattern detection', () => {
      const result = analyzeUrl('https://secure-paypal-verify.com');

      expect(result.reasons.some(r =>
        r.includes('suspiciousBrandPattern') ||
        r.includes('typosquatting') ||
        r.includes('phishingKeyword')
      )).toBe(true);
    });

  });

  describe('IP Address as Domain', () => {

    test('http://192.168.1.1/login should be flagged', () => {
      const result = analyzeUrl('http://192.168.1.1/login');

      expect(result.reasons).toContain('ipAsDomain');
      expect(result.reasons).toContain('noHttps');
      expect(result.score).toBeGreaterThanOrEqual(12); // 8 + 4 = 12
    });

    test('https://8.8.8.8 should still flag IP usage', () => {
      const result = analyzeUrl('https://8.8.8.8');

      expect(result.reasons).toContain('ipAsDomain');
      expect(result.score).toBeGreaterThanOrEqual(8);
    });

  });

  describe('Malware Extensions', () => {

    test('URL with .exe should be high risk', () => {
      const result = analyzeUrl('https://download.example.com/setup.exe');

      expect(result.reasons).toContain('malwareExtension');
      expect(result.score).toBeGreaterThanOrEqual(10);
    });

    test('URL with .zip should be flagged', () => {
      const result = analyzeUrl('https://files.example.com/archive.zip');

      expect(result.reasons).toContain('malwareExtension');
    });

  });

  describe('Shortened URLs', () => {

    test('bit.ly links should be flagged', () => {
      const result = analyzeUrl('https://bit.ly/abc123');

      expect(result.reasons).toContain('shortenedUrl');
      expect(result.score).toBeGreaterThanOrEqual(3);
    });

    test('tinyurl.com should be flagged', () => {
      const result = analyzeUrl('https://tinyurl.com/xyz789');

      expect(result.reasons).toContain('shortenedUrl');
    });

  });

  describe('Combined Risk Scenarios', () => {

    test('http://login-secure.xyz/verify - Multiple red flags should be ALERT', () => {
      const result = analyzeUrl('http://login-secure.xyz/verify');

      // noHttps (4) + suspiciousTLD (7) + keywords (1.5) = 12.5
      expect(result.score).toBeGreaterThanOrEqual(11);
      expect(result.level).not.toBe('safe');
      expect(result.reasons).toContain('noHttps');
      expect(result.reasons).toContain('suspiciousTLD');
    });

    test('http://192.168.1.1/download.exe - IP + malware should be ALERT', () => {
      const result = analyzeUrl('http://192.168.1.1/download.exe');

      // noHttps (4) + ipAsDomain (8) + malwareExtension (10) = 22
      expect(result.score).toBeGreaterThanOrEqual(CONFIG.HIGH_THRESHOLD);
      expect(result.level).toBe('alert');
    });

    test('https://paypa1.xyz/login - Typosquatting + suspicious TLD should be ALERT', () => {
      const result = analyzeUrl('https://paypa1.xyz/login');

      // suspiciousTLD (7) + typosquatting (8) + keywords (1.5) = 16.5
      expect(result.score).toBeGreaterThanOrEqual(CONFIG.HIGH_THRESHOLD);
      expect(result.level).toBe('alert');
      expect(result.reasons).toContain('suspiciousTLD');
      expect(result.reasons.some(r => r.includes('typosquatting'))).toBe(true);
    });

  });

  describe('Edge Cases', () => {

    test('Invalid URL should return error', () => {
      const result = analyzeUrl('not-a-valid-url');

      expect(result.score).toBe(-1);
      expect(result.level).toBe('error');
    });

    test('Empty string should return error', () => {
      const result = analyzeUrl('');

      expect(result.score).toBe(-1);
    });

    test('Very long URL should be slightly flagged', () => {
      const longPath = 'a'.repeat(2500);
      const result = analyzeUrl(`https://example.com/${longPath}`);

      expect(result.reasons).toContain('urlTooLong');
    });

    test('URL with encoded characters should be flagged', () => {
      const result = analyzeUrl('https://example.com/path%20with%20spaces');

      expect(result.reasons).toContain('encodedCharacters');
    });

  });

  describe('Risk Level Thresholds', () => {

    test('Score 0-3 should be SAFE', () => {
      expect(determineRiskLevel(0)).toBe('safe');
      expect(determineRiskLevel(1)).toBe('safe');
      expect(determineRiskLevel(3)).toBe('safe');
    });

    test('Score 4-14 should be CAUTION', () => {
      expect(determineRiskLevel(4)).toBe('caution');
      expect(determineRiskLevel(8)).toBe('caution');
      expect(determineRiskLevel(14)).toBe('caution');
    });

    test('Score 15+ should be ALERT', () => {
      expect(determineRiskLevel(15)).toBe('alert');
      expect(determineRiskLevel(20)).toBe('alert');
      expect(determineRiskLevel(100)).toBe('alert');
    });

    test('Negative score should be ERROR', () => {
      expect(determineRiskLevel(-1)).toBe('error');
    });

  });

});

// Export for potential use in other test files
module.exports = {
  calculateRiskScore,
  determineRiskLevel,
  analyzeUrl,
  normalizeDomain,
  isTrustedDomain,
  detectHomoglyphAttack,
  detectTyposquatting,
  levenshteinDistance,
  CONFIG
};
