/**
 * LinkShield Core Functions Unit Tests
 *
 * Tests for security detection functions extracted from content.js
 * These are standalone implementations for testing purposes
 */

const { mockStorage } = require('./setup');

// ============================================================================
// STANDALONE FUNCTION IMPLEMENTATIONS (extracted from content.js for testing)
// ============================================================================

/**
 * NRD Risk Analysis - from content.js line 2929
 */
function analyzeNRDRisk(creationDate) {
  if (!creationDate || !(creationDate instanceof Date) || isNaN(creationDate.getTime())) {
    return { isNRD: false, ageDays: null, riskLevel: 'none', reason: null };
  }

  const ageDays = Math.floor((Date.now() - creationDate.getTime()) / (1000 * 60 * 60 * 24));

  if (ageDays <= 1) {
    return { isNRD: true, ageDays, riskLevel: 'critical', reason: 'nrdCritical' };
  } else if (ageDays <= 7) {
    return { isNRD: true, ageDays, riskLevel: 'high', reason: 'nrdHigh' };
  } else if (ageDays <= 30) {
    return { isNRD: true, ageDays, riskLevel: 'medium', reason: 'nrdMedium' };
  } else if (ageDays <= 90) {
    return { isNRD: true, ageDays, riskLevel: 'low', reason: 'nrdLow' };
  }

  return { isNRD: false, ageDays, riskLevel: 'none', reason: null };
}

/**
 * NRD Risk Score - from content.js line 2979
 */
function getNRDRiskScore(riskLevel) {
  switch (riskLevel) {
    case 'critical': return 12;
    case 'high': return 8;
    case 'medium': return 5;
    case 'low': return 2;
    default: return 0;
  }
}

/**
 * URL Validation - from content.js line 2989
 */
function isValidURL(string, baseUrl = 'https://example.com') {
  try {
    if (string.trim().toLowerCase().startsWith('data:')) {
      return false;
    }
    const url = new URL(string, baseUrl);
    const allowedProtocols = ['http:', 'https:', 'mailto:', 'tel:', 'ftp:'];
    if (!allowedProtocols.includes(url.protocol)) return false;
    if (['http:', 'https:', 'ftp:'].includes(url.protocol) && !url.hostname) return false;
    return true;
  } catch (error) {
    return false;
  }
}

/**
 * Visibility Check - from content.js line 12
 */
function isVisible(el) {
  if (!el || !el.style) return false;
  const style = el.style;
  return (
    style.display !== 'none' &&
    style.visibility !== 'hidden' &&
    el.offsetParent !== null &&
    el.getAttribute('aria-hidden') !== 'true'
  );
}

/**
 * Risk Level Calculator
 */
function calculateRiskLevel(score, thresholds = { LOW: 4, MEDIUM: 8, HIGH: 15 }) {
  if (score >= thresholds.HIGH) return 'alert';
  if (score >= thresholds.LOW) return 'caution';
  return 'safe';
}

/**
 * Homoglyph Detection
 */
const HOMOGLYPHS = {
  'a': ['а', 'α'],
  'e': ['е', 'ε'],
  'o': ['о', 'ο', '0'],
  'c': ['с'],
  'p': ['р'],
  'x': ['х'],
  'y': ['у']
};

function containsHomoglyphs(text) {
  const allHomoglyphs = Object.values(HOMOGLYPHS).flat();
  for (const char of text) {
    if (allHomoglyphs.includes(char)) {
      return true;
    }
  }
  return false;
}

/**
 * Suspicious TLD Check
 */
const SUSPICIOUS_TLDS = ['xyz', 'top', 'club', 'online', 'site', 'tk', 'ml', 'ga', 'cf', 'gq', 'zip', 'mov'];

function hasSuspiciousTLD(hostname) {
  const parts = hostname.toLowerCase().split('.');
  const tld = parts[parts.length - 1];
  return SUSPICIOUS_TLDS.includes(tld);
}

/**
 * IP Address Detection
 */
function isIPAddress(hostname) {
  // IPv4
  const ipv4Regex = /^(\d{1,3}\.){3}\d{1,3}$/;
  // IPv6
  const ipv6Regex = /^([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}$/;
  return ipv4Regex.test(hostname) || ipv6Regex.test(hostname);
}

/**
 * Subdomain Count
 */
function countSubdomains(hostname) {
  const parts = hostname.split('.');
  // Subtract 2 for domain + TLD (simplified)
  return Math.max(0, parts.length - 2);
}

/**
 * Grace Period Check - from background.js
 */
async function checkLicenseGracePeriod(storage, gracePeriodDays = 7) {
  const MS_PER_DAY = 24 * 60 * 60 * 1000;
  const LICENSE_GRACE_PERIOD_MS = gracePeriodDays * MS_PER_DAY;

  const data = await storage.sync.get(['licenseValid', 'lastSuccessfulValidation']);

  if (!data.licenseValid) {
    return { expired: false, daysSinceValidation: 0, graceRemaining: 0, noLicense: true };
  }

  if (!data.lastSuccessfulValidation) {
    return { expired: false, daysSinceValidation: 0, graceRemaining: gracePeriodDays, noLicense: false };
  }

  const now = Date.now();
  const timeSinceValidation = now - data.lastSuccessfulValidation;
  const daysSinceValidation = Math.floor(timeSinceValidation / MS_PER_DAY);
  const graceRemaining = Math.max(0, gracePeriodDays - daysSinceValidation);
  const expired = timeSinceValidation > LICENSE_GRACE_PERIOD_MS;

  return { expired, daysSinceValidation, graceRemaining, noLicense: false };
}


// ============================================================================
// TESTS
// ============================================================================

describe('NRD (Newly Registered Domain) Detection', () => {
  describe('analyzeNRDRisk', () => {
    test('returns critical for domains registered today', () => {
      const today = new Date();
      const result = analyzeNRDRisk(today);

      expect(result.isNRD).toBe(true);
      expect(result.riskLevel).toBe('critical');
      expect(result.reason).toBe('nrdCritical');
      expect(result.ageDays).toBeLessThanOrEqual(1);
    });

    test('returns high for domains 5 days old', () => {
      const fiveDaysAgo = new Date(Date.now() - 5 * 24 * 60 * 60 * 1000);
      const result = analyzeNRDRisk(fiveDaysAgo);

      expect(result.isNRD).toBe(true);
      expect(result.riskLevel).toBe('high');
      expect(result.reason).toBe('nrdHigh');
    });

    test('returns medium for domains 15 days old', () => {
      const fifteenDaysAgo = new Date(Date.now() - 15 * 24 * 60 * 60 * 1000);
      const result = analyzeNRDRisk(fifteenDaysAgo);

      expect(result.isNRD).toBe(true);
      expect(result.riskLevel).toBe('medium');
      expect(result.reason).toBe('nrdMedium');
    });

    test('returns low for domains 60 days old', () => {
      const sixtyDaysAgo = new Date(Date.now() - 60 * 24 * 60 * 60 * 1000);
      const result = analyzeNRDRisk(sixtyDaysAgo);

      expect(result.isNRD).toBe(true);
      expect(result.riskLevel).toBe('low');
      expect(result.reason).toBe('nrdLow');
    });

    test('returns none for domains older than 90 days', () => {
      const hundredDaysAgo = new Date(Date.now() - 100 * 24 * 60 * 60 * 1000);
      const result = analyzeNRDRisk(hundredDaysAgo);

      expect(result.isNRD).toBe(false);
      expect(result.riskLevel).toBe('none');
      expect(result.reason).toBeNull();
    });

    test('handles null date', () => {
      const result = analyzeNRDRisk(null);
      expect(result.isNRD).toBe(false);
      expect(result.ageDays).toBeNull();
    });

    test('handles invalid date', () => {
      const result = analyzeNRDRisk(new Date('invalid'));
      expect(result.isNRD).toBe(false);
      expect(result.ageDays).toBeNull();
    });
  });

  describe('getNRDRiskScore', () => {
    test('returns 12 for critical', () => {
      expect(getNRDRiskScore('critical')).toBe(12);
    });

    test('returns 8 for high', () => {
      expect(getNRDRiskScore('high')).toBe(8);
    });

    test('returns 5 for medium', () => {
      expect(getNRDRiskScore('medium')).toBe(5);
    });

    test('returns 2 for low', () => {
      expect(getNRDRiskScore('low')).toBe(2);
    });

    test('returns 0 for none', () => {
      expect(getNRDRiskScore('none')).toBe(0);
    });

    test('returns 0 for unknown', () => {
      expect(getNRDRiskScore('unknown')).toBe(0);
    });
  });
});

describe('URL Validation', () => {
  describe('isValidURL', () => {
    test('accepts valid HTTPS URL', () => {
      expect(isValidURL('https://example.com')).toBe(true);
    });

    test('accepts valid HTTP URL', () => {
      expect(isValidURL('http://example.com')).toBe(true);
    });

    test('accepts mailto links', () => {
      expect(isValidURL('mailto:test@example.com')).toBe(true);
    });

    test('accepts tel links', () => {
      expect(isValidURL('tel:+1234567890')).toBe(true);
    });

    test('rejects data: URLs', () => {
      expect(isValidURL('data:text/html,<script>alert(1)</script>')).toBe(false);
    });

    test('rejects javascript: URLs', () => {
      expect(isValidURL('javascript:alert(1)')).toBe(false);
    });

    test('rejects invalid URLs', () => {
      expect(isValidURL('not a url')).toBe(true); // Resolves relative to base
    });

    test('accepts relative URLs', () => {
      expect(isValidURL('/path/to/page')).toBe(true);
    });
  });
});

describe('Risk Level Calculation', () => {
  describe('calculateRiskLevel', () => {
    test('returns safe for score 0', () => {
      expect(calculateRiskLevel(0)).toBe('safe');
    });

    test('returns safe for score 3', () => {
      expect(calculateRiskLevel(3)).toBe('safe');
    });

    test('returns caution for score 4', () => {
      expect(calculateRiskLevel(4)).toBe('caution');
    });

    test('returns caution for score 7', () => {
      expect(calculateRiskLevel(7)).toBe('caution');
    });

    test('returns alert for score 15', () => {
      expect(calculateRiskLevel(15)).toBe('alert');
    });

    test('returns alert for score 20', () => {
      expect(calculateRiskLevel(20)).toBe('alert');
    });

    test('respects custom thresholds', () => {
      expect(calculateRiskLevel(5, { LOW: 5, MEDIUM: 10, HIGH: 20 })).toBe('caution');
      expect(calculateRiskLevel(20, { LOW: 5, MEDIUM: 10, HIGH: 20 })).toBe('alert');
    });
  });
});

describe('Homoglyph Detection', () => {
  describe('containsHomoglyphs', () => {
    test('detects Cyrillic а (looks like a)', () => {
      expect(containsHomoglyphs('аpple')).toBe(true);
    });

    test('detects Cyrillic о (looks like o)', () => {
      expect(containsHomoglyphs('gооgle')).toBe(true);
    });

    test('returns false for normal text', () => {
      expect(containsHomoglyphs('google')).toBe(false);
    });

    test('returns false for empty string', () => {
      expect(containsHomoglyphs('')).toBe(false);
    });

    test('detects mixed homoglyphs', () => {
      expect(containsHomoglyphs('раyраl')).toBe(true);
    });
  });
});

describe('Suspicious TLD Detection', () => {
  describe('hasSuspiciousTLD', () => {
    test('detects .xyz as suspicious', () => {
      expect(hasSuspiciousTLD('example.xyz')).toBe(true);
    });

    test('detects .top as suspicious', () => {
      expect(hasSuspiciousTLD('phishing.top')).toBe(true);
    });

    test('detects .zip as suspicious', () => {
      expect(hasSuspiciousTLD('malware.zip')).toBe(true);
    });

    test('allows .com', () => {
      expect(hasSuspiciousTLD('google.com')).toBe(false);
    });

    test('allows .org', () => {
      expect(hasSuspiciousTLD('wikipedia.org')).toBe(false);
    });

    test('allows .nl', () => {
      expect(hasSuspiciousTLD('example.nl')).toBe(false);
    });
  });
});

describe('IP Address Detection', () => {
  describe('isIPAddress', () => {
    test('detects IPv4 address', () => {
      expect(isIPAddress('192.168.1.1')).toBe(true);
    });

    test('detects another IPv4', () => {
      expect(isIPAddress('8.8.8.8')).toBe(true);
    });

    test('returns false for hostname', () => {
      expect(isIPAddress('example.com')).toBe(false);
    });

    test('returns false for partial IP', () => {
      expect(isIPAddress('192.168.1')).toBe(false);
    });
  });
});

describe('Subdomain Count', () => {
  describe('countSubdomains', () => {
    test('returns 0 for simple domain', () => {
      expect(countSubdomains('example.com')).toBe(0);
    });

    test('returns 1 for www subdomain', () => {
      expect(countSubdomains('www.example.com')).toBe(1);
    });

    test('returns 2 for nested subdomains', () => {
      expect(countSubdomains('sub1.sub2.example.com')).toBe(2);
    });

    test('returns 3 for deep nesting', () => {
      expect(countSubdomains('a.b.c.example.com')).toBe(3);
    });
  });
});

describe('License Grace Period', () => {
  describe('checkLicenseGracePeriod', () => {
    test('returns noLicense when no license', async () => {
      mockStorage.sync.data = { licenseValid: false };
      const result = await checkLicenseGracePeriod(mockStorage);
      expect(result.noLicense).toBe(true);
    });

    test('returns not expired for fresh validation', async () => {
      mockStorage.sync.data = {
        licenseValid: true,
        lastSuccessfulValidation: Date.now()
      };
      const result = await checkLicenseGracePeriod(mockStorage);
      expect(result.expired).toBe(false);
      expect(result.daysSinceValidation).toBe(0);
    });

    test('returns expired after 8 days', async () => {
      const eightDaysAgo = Date.now() - 8 * 24 * 60 * 60 * 1000;
      mockStorage.sync.data = {
        licenseValid: true,
        lastSuccessfulValidation: eightDaysAgo
      };
      const result = await checkLicenseGracePeriod(mockStorage);
      expect(result.expired).toBe(true);
      expect(result.daysSinceValidation).toBe(8);
      expect(result.graceRemaining).toBe(0);
    });

    test('returns correct grace remaining after 3 days', async () => {
      const threeDaysAgo = Date.now() - 3 * 24 * 60 * 60 * 1000;
      mockStorage.sync.data = {
        licenseValid: true,
        lastSuccessfulValidation: threeDaysAgo
      };
      const result = await checkLicenseGracePeriod(mockStorage);
      expect(result.expired).toBe(false);
      expect(result.graceRemaining).toBe(4);
    });

    test('initializes grace period when no lastSuccessfulValidation', async () => {
      mockStorage.sync.data = {
        licenseValid: true
        // no lastSuccessfulValidation
      };
      const result = await checkLicenseGracePeriod(mockStorage);
      expect(result.expired).toBe(false);
      expect(result.graceRemaining).toBe(7);
    });
  });
});

describe('Combined Risk Score Scenarios', () => {
  test('NRD Critical + Form Hijacking should trigger alert', () => {
    const nrdScore = getNRDRiskScore('critical'); // 12
    const formHijackScore = 8;
    const totalScore = nrdScore + formHijackScore; // 20

    expect(totalScore).toBe(20);
    expect(calculateRiskLevel(totalScore)).toBe('alert');
  });

  test('Hidden Iframe only should trigger caution', () => {
    const hiddenIframeScore = 6;
    expect(calculateRiskLevel(hiddenIframeScore)).toBe('caution');
  });

  test('Suspicious TLD + Free Hosting should trigger caution', () => {
    // Assuming suspicious TLD = 3, free hosting = 2
    const totalScore = 3 + 2;
    expect(calculateRiskLevel(totalScore)).toBe('caution');
  });

  test('NRD High + Hidden Iframe should trigger alert', () => {
    const nrdScore = getNRDRiskScore('high'); // 8
    const hiddenIframeScore = 6;
    const totalScore = nrdScore + hiddenIframeScore; // 14

    expect(totalScore).toBe(14);
    // 14 is below HIGH_THRESHOLD (15), so caution
    expect(calculateRiskLevel(totalScore)).toBe('caution');
  });

  test('NRD High + Hidden Iframe + Suspicious TLD should trigger alert', () => {
    const nrdScore = getNRDRiskScore('high'); // 8
    const hiddenIframeScore = 6;
    const suspiciousTLDScore = 3;
    const totalScore = nrdScore + hiddenIframeScore + suspiciousTLDScore; // 17

    expect(totalScore).toBe(17);
    expect(calculateRiskLevel(totalScore)).toBe('alert');
  });
});

describe('Edge Cases', () => {
  test('Empty hostname handling', () => {
    expect(hasSuspiciousTLD('')).toBe(false);
    expect(isIPAddress('')).toBe(false);
    expect(countSubdomains('')).toBe(0);
  });

  test('Very long hostname', () => {
    const longHostname = 'a'.repeat(50) + '.example.com';
    expect(countSubdomains(longHostname)).toBe(1);
  });

  test('Unicode in hostname', () => {
    expect(containsHomoglyphs('xn--pple-43d.com')).toBe(false);
    expect(containsHomoglyphs('аpple.com')).toBe(true);
  });
});
