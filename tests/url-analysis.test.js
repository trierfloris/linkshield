/**
 * LinkShield URL Analysis Unit Tests
 *
 * Tests for URL parsing, domain extraction, and security analysis functions
 */

const { mockStorage } = require('./setup');

// ============================================================================
// STANDALONE FUNCTION IMPLEMENTATIONS (extracted from content.js for testing)
// ============================================================================

/**
 * Extract domain from URL - from content.js line 189
 */
function getDomainFromUrl(url) {
  try {
    const urlObj = new URL(url);
    return urlObj.hostname.toLowerCase();
  } catch {
    return null;
  }
}

/**
 * Normalize domain - from content.js line 2238
 */
function normalizeDomain(url) {
  try {
    const urlObj = new URL(url);
    let hostname = urlObj.hostname.toLowerCase();
    // Remove www prefix
    if (hostname.startsWith('www.')) {
      hostname = hostname.substring(4);
    }
    return hostname;
  } catch {
    return null;
  }
}

/**
 * Get registrable domain (eTLD+1) - simplified version from content.js line 2074
 */
function getRegistrableDomain(url) {
  try {
    const hostname = getDomainFromUrl(url);
    if (!hostname) return null;

    const parts = hostname.split('.');
    if (parts.length < 2) return hostname;

    // Simple implementation: return last two parts
    // Real implementation uses public suffix list
    return parts.slice(-2).join('.');
  } catch {
    return null;
  }
}

/**
 * Check if URL uses HTTPS
 */
function isHttps(url) {
  try {
    const urlObj = new URL(url);
    return urlObj.protocol === 'https:';
  } catch {
    return false;
  }
}

/**
 * Check for suspicious TLD
 */
const SUSPICIOUS_TLDS = new Set([
  'xyz', 'top', 'club', 'online', 'site', 'tk', 'ml', 'ga', 'cf', 'gq',
  'zip', 'mov', 'work', 'click', 'link', 'info', 'biz', 'buzz', 'live',
  'icu', 'monster', 'quest', 'rest', 'sbs', 'cfd'
]);

function hasSuspiciousTLD(hostname) {
  if (!hostname) return false;
  const parts = hostname.toLowerCase().split('.');
  const tld = parts[parts.length - 1];
  return SUSPICIOUS_TLDS.has(tld);
}

/**
 * Check for URL shortener
 */
const URL_SHORTENERS = new Set([
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd',
  'buff.ly', 'j.mp', 'rb.gy', 'cutt.ly', 'shorturl.at', 'tiny.cc'
]);

function isUrlShortener(hostname) {
  if (!hostname) return false;
  return URL_SHORTENERS.has(hostname.toLowerCase());
}

/**
 * Check for free hosting platforms
 */
const FREE_HOSTING = new Set([
  'github.io', 'gitlab.io', 'netlify.app', 'vercel.app', 'herokuapp.com',
  'firebaseapp.com', 'web.app', 'pages.dev', 'workers.dev',
  'blogspot.com', 'wordpress.com', 'wixsite.com', 'weebly.com',
  '000webhostapp.com', 'infinityfreeapp.com'
]);

function isFreeHosting(hostname) {
  if (!hostname) return false;
  const lower = hostname.toLowerCase();
  for (const host of FREE_HOSTING) {
    if (lower === host || lower.endsWith('.' + host)) {
      return true;
    }
  }
  return false;
}

/**
 * Check for IP address as domain
 */
function isIPAddress(hostname) {
  if (!hostname) return false;
  // IPv4
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  if (ipv4Regex.test(hostname)) {
    // Validate each octet
    const parts = hostname.split('.').map(Number);
    return parts.every(p => p >= 0 && p <= 255);
  }
  // IPv6 (simplified)
  const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
  return ipv6Regex.test(hostname);
}

/**
 * Count subdomains
 */
function countSubdomains(hostname) {
  if (!hostname) return 0;
  const parts = hostname.split('.');
  // Subtract 2 for domain + TLD (simplified)
  return Math.max(0, parts.length - 2);
}

/**
 * Check for @ symbol attack (credential URL)
 */
function hasCredentialUrlAttack(url) {
  try {
    const urlObj = new URL(url);
    // Check for username in URL (before @)
    if (urlObj.username) {
      return true;
    }
    // Check for @ in the authority part that's not properly parsed
    if (url.includes('@') && !url.includes('mailto:')) {
      const match = url.match(/\/\/[^\/]*@/);
      if (match) {
        return true;
      }
    }
    return false;
  } catch {
    return false;
  }
}

/**
 * Check for unusual port
 */
function hasUnusualPort(url) {
  try {
    const urlObj = new URL(url);
    const port = urlObj.port;
    if (!port) return false;
    // Standard ports
    const standardPorts = ['80', '443', '8080', '8443'];
    return !standardPorts.includes(port);
  } catch {
    return false;
  }
}

/**
 * Check for encoded characters abuse
 */
function hasExcessiveEncoding(url) {
  // Count percent-encoded characters
  const encodedChars = (url.match(/%[0-9A-Fa-f]{2}/g) || []).length;
  // More than 10 encoded characters is suspicious
  return encodedChars > 10;
}

/**
 * Check for double encoding
 */
function hasDoubleEncoding(url) {
  // Pattern: %25XX where XX is a hex value
  return /%25[0-9A-Fa-f]{2}/i.test(url);
}

/**
 * Check URL length
 */
function isUrlTooLong(url, maxLength = 2000) {
  return url.length > maxLength;
}

/**
 * Check for javascript: scheme
 */
function hasJavascriptScheme(url) {
  const trimmed = url.trim().toLowerCase();
  return trimmed.startsWith('javascript:');
}

/**
 * Check for data: scheme
 */
function hasDataScheme(url) {
  const trimmed = url.trim().toLowerCase();
  return trimmed.startsWith('data:');
}

// ============================================================================
// TESTS
// ============================================================================

describe('Domain Extraction', () => {
  describe('getDomainFromUrl', () => {
    test('extracts domain from HTTPS URL', () => {
      expect(getDomainFromUrl('https://example.com/path')).toBe('example.com');
    });

    test('extracts domain from HTTP URL', () => {
      expect(getDomainFromUrl('http://example.com')).toBe('example.com');
    });

    test('extracts domain with subdomain', () => {
      expect(getDomainFromUrl('https://www.example.com')).toBe('www.example.com');
    });

    test('extracts domain with port', () => {
      expect(getDomainFromUrl('https://example.com:8080')).toBe('example.com');
    });

    test('converts to lowercase', () => {
      expect(getDomainFromUrl('https://EXAMPLE.COM')).toBe('example.com');
    });

    test('returns null for invalid URL', () => {
      expect(getDomainFromUrl('not a url')).toBeNull();
    });

    test('returns null for empty string', () => {
      expect(getDomainFromUrl('')).toBeNull();
    });
  });

  describe('normalizeDomain', () => {
    test('removes www prefix', () => {
      expect(normalizeDomain('https://www.example.com')).toBe('example.com');
    });

    test('preserves domain without www', () => {
      expect(normalizeDomain('https://example.com')).toBe('example.com');
    });

    test('converts to lowercase', () => {
      expect(normalizeDomain('https://WWW.EXAMPLE.COM')).toBe('example.com');
    });
  });

  describe('getRegistrableDomain', () => {
    test('returns eTLD+1 for simple domain', () => {
      expect(getRegistrableDomain('https://www.example.com')).toBe('example.com');
    });

    test('returns eTLD+1 for subdomain', () => {
      expect(getRegistrableDomain('https://sub.example.com')).toBe('example.com');
    });

    test('handles deep subdomains', () => {
      expect(getRegistrableDomain('https://a.b.c.example.com')).toBe('example.com');
    });
  });
});

describe('Protocol Checks', () => {
  describe('isHttps', () => {
    test('returns true for HTTPS', () => {
      expect(isHttps('https://example.com')).toBe(true);
    });

    test('returns false for HTTP', () => {
      expect(isHttps('http://example.com')).toBe(false);
    });

    test('returns false for invalid URL', () => {
      expect(isHttps('not a url')).toBe(false);
    });
  });

  describe('hasJavascriptScheme', () => {
    test('detects javascript: URL', () => {
      expect(hasJavascriptScheme('javascript:alert(1)')).toBe(true);
    });

    test('detects with whitespace', () => {
      expect(hasJavascriptScheme('  javascript:void(0)')).toBe(true);
    });

    test('ignores case', () => {
      expect(hasJavascriptScheme('JAVASCRIPT:alert(1)')).toBe(true);
    });

    test('returns false for normal URL', () => {
      expect(hasJavascriptScheme('https://example.com')).toBe(false);
    });
  });

  describe('hasDataScheme', () => {
    test('detects data: URL', () => {
      expect(hasDataScheme('data:text/html,<script>alert(1)</script>')).toBe(true);
    });

    test('returns false for normal URL', () => {
      expect(hasDataScheme('https://example.com')).toBe(false);
    });
  });
});

describe('Suspicious TLD Detection', () => {
  describe('hasSuspiciousTLD', () => {
    test.each([
      ['example.xyz', true],
      ['phishing.top', true],
      ['malware.zip', true],
      ['fake.tk', true],
      ['scam.ml', true],
      ['example.com', false],
      ['example.org', false],
      ['example.nl', false],
      ['example.gov', false]
    ])('hasSuspiciousTLD("%s") = %s', (hostname, expected) => {
      expect(hasSuspiciousTLD(hostname)).toBe(expected);
    });

    test('handles null', () => {
      expect(hasSuspiciousTLD(null)).toBe(false);
    });

    test('handles empty string', () => {
      expect(hasSuspiciousTLD('')).toBe(false);
    });
  });
});

describe('URL Shortener Detection', () => {
  describe('isUrlShortener', () => {
    test.each([
      ['bit.ly', true],
      ['tinyurl.com', true],
      ['t.co', true],
      ['goo.gl', true],
      ['example.com', false],
      ['google.com', false]
    ])('isUrlShortener("%s") = %s', (hostname, expected) => {
      expect(isUrlShortener(hostname)).toBe(expected);
    });
  });
});

describe('Free Hosting Detection', () => {
  describe('isFreeHosting', () => {
    test.each([
      ['mysite.github.io', true],
      ['app.netlify.app', true],
      ['project.herokuapp.com', true],
      ['blog.blogspot.com', true],
      ['site.wixsite.com', true],
      ['github.io', true],
      ['google.com', false],
      ['microsoft.com', false]
    ])('isFreeHosting("%s") = %s', (hostname, expected) => {
      expect(isFreeHosting(hostname)).toBe(expected);
    });
  });
});

describe('IP Address Detection', () => {
  describe('isIPAddress', () => {
    test('detects valid IPv4', () => {
      expect(isIPAddress('192.168.1.1')).toBe(true);
    });

    test('detects 8.8.8.8', () => {
      expect(isIPAddress('8.8.8.8')).toBe(true);
    });

    test('detects localhost IP', () => {
      expect(isIPAddress('127.0.0.1')).toBe(true);
    });

    test('rejects invalid IPv4 octets', () => {
      expect(isIPAddress('256.1.1.1')).toBe(false);
    });

    test('rejects partial IP', () => {
      expect(isIPAddress('192.168.1')).toBe(false);
    });

    test('rejects hostname', () => {
      expect(isIPAddress('example.com')).toBe(false);
    });

    test('handles null', () => {
      expect(isIPAddress(null)).toBe(false);
    });
  });
});

describe('Subdomain Analysis', () => {
  describe('countSubdomains', () => {
    test.each([
      ['example.com', 0],
      ['www.example.com', 1],
      ['sub.example.com', 1],
      ['a.b.example.com', 2],
      ['a.b.c.example.com', 3],
      ['a.b.c.d.example.com', 4]
    ])('countSubdomains("%s") = %d', (hostname, expected) => {
      expect(countSubdomains(hostname)).toBe(expected);
    });

    test('handles null', () => {
      expect(countSubdomains(null)).toBe(0);
    });
  });
});

describe('URL Attack Detection', () => {
  describe('hasCredentialUrlAttack', () => {
    test('detects @ symbol attack', () => {
      expect(hasCredentialUrlAttack('https://google.com@evil.com/path')).toBe(true);
    });

    test('detects username in URL', () => {
      expect(hasCredentialUrlAttack('https://user:pass@evil.com')).toBe(true);
    });

    test('allows mailto: with @', () => {
      expect(hasCredentialUrlAttack('mailto:user@example.com')).toBe(false);
    });

    test('allows normal URL', () => {
      expect(hasCredentialUrlAttack('https://example.com/path?email=user@test.com')).toBe(false);
    });
  });

  describe('hasUnusualPort', () => {
    test('detects unusual port', () => {
      expect(hasUnusualPort('https://example.com:4444')).toBe(true);
    });

    test('allows port 443', () => {
      expect(hasUnusualPort('https://example.com:443')).toBe(false);
    });

    test('allows port 80', () => {
      expect(hasUnusualPort('http://example.com:80')).toBe(false);
    });

    test('allows port 8080', () => {
      expect(hasUnusualPort('http://example.com:8080')).toBe(false);
    });

    test('allows no port', () => {
      expect(hasUnusualPort('https://example.com')).toBe(false);
    });
  });

  describe('hasDoubleEncoding', () => {
    test('detects double encoding', () => {
      expect(hasDoubleEncoding('https://example.com/%252e%252e')).toBe(true);
    });

    test('allows single encoding', () => {
      expect(hasDoubleEncoding('https://example.com/%2e%2e')).toBe(false);
    });

    test('allows normal URL', () => {
      expect(hasDoubleEncoding('https://example.com/path')).toBe(false);
    });
  });

  describe('hasExcessiveEncoding', () => {
    test('detects excessive encoding', () => {
      const encoded = 'https://example.com/' + '%20'.repeat(15);
      expect(hasExcessiveEncoding(encoded)).toBe(true);
    });

    test('allows moderate encoding', () => {
      const encoded = 'https://example.com/path%20with%20spaces';
      expect(hasExcessiveEncoding(encoded)).toBe(false);
    });
  });

  describe('isUrlTooLong', () => {
    test('detects very long URL', () => {
      const longUrl = 'https://example.com/' + 'a'.repeat(2000);
      expect(isUrlTooLong(longUrl)).toBe(true);
    });

    test('allows normal URL', () => {
      expect(isUrlTooLong('https://example.com/path')).toBe(false);
    });

    test('respects custom max length', () => {
      expect(isUrlTooLong('https://example.com/path', 10)).toBe(true);
    });
  });
});

describe('Combined URL Analysis', () => {
  function analyzeUrl(url) {
    const domain = getDomainFromUrl(url);
    const issues = [];
    let riskScore = 0;

    if (!isHttps(url) && !url.startsWith('http://localhost')) {
      issues.push('noHttps');
      riskScore += 2;
    }

    if (isIPAddress(domain)) {
      issues.push('ipAsDomain');
      riskScore += 8;
    }

    if (hasSuspiciousTLD(domain)) {
      issues.push('suspiciousTLD');
      riskScore += 3;
    }

    if (isUrlShortener(domain)) {
      issues.push('shortenedUrl');
      riskScore += 2;
    }

    if (isFreeHosting(domain)) {
      issues.push('freeHosting');
      riskScore += 2;
    }

    if (countSubdomains(domain) > 3) {
      issues.push('tooManySubdomains');
      riskScore += 3;
    }

    if (hasCredentialUrlAttack(url)) {
      issues.push('atSymbolPhishing');
      riskScore += 10;
    }

    if (hasUnusualPort(url)) {
      issues.push('unusualPort');
      riskScore += 2;
    }

    if (hasDoubleEncoding(url)) {
      issues.push('doubleEncoding');
      riskScore += 5;
    }

    if (isUrlTooLong(url)) {
      issues.push('urlTooLong');
      riskScore += 2;
    }

    if (hasJavascriptScheme(url)) {
      issues.push('javascriptScheme');
      riskScore += 10;
    }

    return { domain, issues, riskScore };
  }

  test('clean URL has no issues', () => {
    const result = analyzeUrl('https://google.com/search?q=test');
    expect(result.issues).toEqual([]);
    expect(result.riskScore).toBe(0);
  });

  test('HTTP URL has noHttps issue', () => {
    const result = analyzeUrl('http://example.com');
    expect(result.issues).toContain('noHttps');
    expect(result.riskScore).toBeGreaterThan(0);
  });

  test('IP address URL is flagged', () => {
    const result = analyzeUrl('http://192.168.1.1/admin');
    expect(result.issues).toContain('ipAsDomain');
    expect(result.riskScore).toBeGreaterThanOrEqual(8);
  });

  test('phishing URL with multiple issues', () => {
    const result = analyzeUrl('http://login.paypal.com.secure.verify.fake.tk:4444/signin');
    expect(result.issues).toContain('noHttps');
    expect(result.issues).toContain('suspiciousTLD');
    expect(result.issues).toContain('tooManySubdomains');
    expect(result.issues).toContain('unusualPort');
    expect(result.riskScore).toBeGreaterThanOrEqual(10);
  });

  test('credential URL attack is critical', () => {
    const result = analyzeUrl('https://google.com@evil.com/path');
    expect(result.issues).toContain('atSymbolPhishing');
    expect(result.riskScore).toBeGreaterThanOrEqual(10);
  });

  test('javascript: URL is critical', () => {
    const result = analyzeUrl('javascript:alert(document.cookie)');
    expect(result.issues).toContain('javascriptScheme');
    expect(result.riskScore).toBeGreaterThanOrEqual(10);
  });
});
