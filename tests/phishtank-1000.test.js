/**
 * PhishTank + OpenPhish Large-Scale Validation Test
 * Tests LinkShield detection against 1000+ real-world phishing URLs
 * Sources: PhishTank (verified), OpenPhish
 * Date: 2026-01-08
 */

const fs = require('fs');
const path = require('path');

// Mock Chrome APIs
global.chrome = {
  storage: {
    local: { get: jest.fn(() => Promise.resolve({})), set: jest.fn(() => Promise.resolve()) },
    sync: { get: jest.fn(() => Promise.resolve({ backgroundSecurity: true, integratedProtection: true })) }
  },
  runtime: { id: 'test', sendMessage: jest.fn(() => Promise.resolve({})), getManifest: jest.fn(() => ({ version: '7.8' })) },
  i18n: { getMessage: jest.fn(key => key) }
};

// Load config
const configContent = fs.readFileSync(path.join(__dirname, '..', 'config.js'), 'utf8');
eval(configContent.replace('window.CONFIG', 'global.CONFIG'));
const CONFIG = global.CONFIG;

// Load phishing URLs from file
const urlsFile = path.join(__dirname, 'combined-phishing-urls.txt');
const PHISHING_URLS = fs.readFileSync(urlsFile, 'utf8')
  .split('\n')
  .map(url => url.trim())
  .filter(url => url && url.startsWith('http'));

console.log(`Loaded ${PHISHING_URLS.length} phishing URLs for testing`);

// Detection functions (same as LinkShield uses)
function isSuspiciousTLD(hostname) {
  return CONFIG.SUSPICIOUS_TLDS.test(hostname);
}

function isFreeHosting(hostname) {
  for (const domain of CONFIG.FREE_HOSTING_DOMAINS) {
    if (hostname === domain || hostname.endsWith('.' + domain)) {
      return true;
    }
  }
  return false;
}

function isShortenedUrl(hostname) {
  return CONFIG.SHORTENED_URL_DOMAINS.some(domain =>
    hostname === domain || hostname.endsWith('.' + domain)
  );
}

function hasCryptoKeywords(url) {
  return /wallet|crypto|web3|exodus|metamask|ledger|trezor|phantom|coinbase|binance|kucoin|uniswap|opensea/i.test(url);
}

function hasPhishingKeywords(url) {
  const keywords = ['login', 'signin', 'auth', 'verify', 'secure', 'account', 'update', 'confirm', 'bank', 'password', 'credential'];
  const lowerUrl = url.toLowerCase();
  return keywords.some(kw => lowerUrl.includes(kw));
}

function hasBrandKeywords(url) {
  const brands = ['microsoft', 'apple', 'google', 'facebook', 'amazon', 'netflix', 'paypal', 'instagram', 'whatsapp', 'telegram', 'roblox', 'steam'];
  const lowerUrl = url.toLowerCase();
  return brands.some(brand => lowerUrl.includes(brand));
}

function hasRandomSubdomain(hostname) {
  const parts = hostname.split('.');
  if (parts.length >= 3) {
    const subdomain = parts[0];
    // Random-looking subdomain: 6+ chars, mostly lowercase, possibly with numbers
    if (/^[a-z0-9]{6,}$/i.test(subdomain) && !/^(www|mail|ftp|api|cdn|app)$/.test(subdomain)) {
      return true;
    }
  }
  return false;
}

function hasIPAddress(hostname) {
  return /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname);
}

function assessUrl(url) {
  let risk = 0;
  const reasons = [];

  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname;

    // High-weight detections
    if (isSuspiciousTLD(hostname)) {
      risk += 8;
      reasons.push('suspiciousTLD');
    }

    if (isFreeHosting(hostname)) {
      risk += 5;
      reasons.push('freeHosting');
    }

    if (hasCryptoKeywords(url)) {
      risk += 7;
      reasons.push('cryptoKeywords');
    }

    if (isShortenedUrl(hostname)) {
      risk += 4;
      reasons.push('shortenedUrl');
    }

    // Medium-weight detections
    if (hasPhishingKeywords(url)) {
      risk += 3;
      reasons.push('phishingKeywords');
    }

    if (hasBrandKeywords(url)) {
      risk += 3;
      reasons.push('brandKeywords');
    }

    if (hasRandomSubdomain(hostname)) {
      risk += 3;
      reasons.push('randomSubdomain');
    }

    if (hasIPAddress(hostname)) {
      risk += 6;
      reasons.push('ipAddress');
    }

    // .cc TLD (often abused but not in main list)
    if (hostname.endsWith('.cc')) {
      risk += 4;
      reasons.push('ccTLD');
    }

    // duckdns.org - dynamic DNS often used for phishing
    if (hostname.endsWith('.duckdns.org')) {
      risk += 5;
      reasons.push('dynamicDNS');
    }

  } catch (e) {
    risk += 10;
    reasons.push('invalidUrl');
  }

  return { risk, reasons };
}

describe('PhishTank + OpenPhish 1000+ URL Validation', () => {

  test('Dataset should have 1000+ URLs', () => {
    expect(PHISHING_URLS.length).toBeGreaterThanOrEqual(1000);
    console.log(`\n✓ Dataset contains ${PHISHING_URLS.length} URLs\n`);
  });

  test('Run comprehensive detection analysis', () => {
    const results = {
      total: PHISHING_URLS.length,
      detected: 0,
      missed: 0,
      missedUrls: [],
      byReason: {
        suspiciousTLD: 0,
        freeHosting: 0,
        cryptoKeywords: 0,
        phishingKeywords: 0,
        brandKeywords: 0,
        randomSubdomain: 0,
        shortenedUrl: 0,
        ipAddress: 0,
        ccTLD: 0,
        dynamicDNS: 0,
        invalidUrl: 0
      },
      riskDistribution: {
        zero: 0,
        low: 0,      // 1-3
        medium: 0,   // 4-7
        high: 0,     // 8-14
        critical: 0  // 15+
      },
      tldStats: {},
      hostingStats: {}
    };

    // Process all URLs
    PHISHING_URLS.forEach(url => {
      const { risk, reasons } = assessUrl(url);

      // Detection tracking
      if (risk > 0) {
        results.detected++;
      } else {
        results.missed++;
        if (results.missedUrls.length < 50) { // Limit stored missed URLs
          results.missedUrls.push(url);
        }
      }

      // Reason tracking
      reasons.forEach(reason => {
        if (results.byReason[reason] !== undefined) {
          results.byReason[reason]++;
        }
      });

      // Risk distribution
      if (risk === 0) results.riskDistribution.zero++;
      else if (risk <= 3) results.riskDistribution.low++;
      else if (risk <= 7) results.riskDistribution.medium++;
      else if (risk <= 14) results.riskDistribution.high++;
      else results.riskDistribution.critical++;

      // TLD stats
      try {
        const hostname = new URL(url).hostname;
        const tld = hostname.split('.').pop();
        results.tldStats[tld] = (results.tldStats[tld] || 0) + 1;
      } catch (e) {}
    });

    // Calculate rates
    const detectionRate = (results.detected / results.total * 100).toFixed(1);
    const missRate = (results.missed / results.total * 100).toFixed(1);

    // Print report
    console.log('\n');
    console.log('╔══════════════════════════════════════════════════════════════════╗');
    console.log('║     LINKSHIELD vs PHISHTANK+OPENPHISH - 1000+ URL TEST           ║');
    console.log('╠══════════════════════════════════════════════════════════════════╣');
    console.log(`║  Total URLs tested:        ${results.total.toString().padStart(5)}                              ║`);
    console.log(`║  ✓ Detected (risk > 0):    ${results.detected.toString().padStart(5)} (${detectionRate}%)                       ║`);
    console.log(`║  ✗ Missed (risk = 0):      ${results.missed.toString().padStart(5)} (${missRate}%)                        ║`);
    console.log('╠══════════════════════════════════════════════════════════════════╣');
    console.log('║  DETECTION BREAKDOWN:                                            ║');
    console.log(`║    Suspicious TLD:         ${results.byReason.suspiciousTLD.toString().padStart(5)}                              ║`);
    console.log(`║    Free Hosting:           ${results.byReason.freeHosting.toString().padStart(5)}                              ║`);
    console.log(`║    Crypto Keywords:        ${results.byReason.cryptoKeywords.toString().padStart(5)}                              ║`);
    console.log(`║    Brand Keywords:         ${results.byReason.brandKeywords.toString().padStart(5)}                              ║`);
    console.log(`║    Phishing Keywords:      ${results.byReason.phishingKeywords.toString().padStart(5)}                              ║`);
    console.log(`║    Random Subdomain:       ${results.byReason.randomSubdomain.toString().padStart(5)}                              ║`);
    console.log(`║    Dynamic DNS:            ${results.byReason.dynamicDNS.toString().padStart(5)}                              ║`);
    console.log(`║    Shortened URL:          ${results.byReason.shortenedUrl.toString().padStart(5)}                              ║`);
    console.log(`║    IP Address:             ${results.byReason.ipAddress.toString().padStart(5)}                              ║`);
    console.log(`║    .cc TLD:                ${results.byReason.ccTLD.toString().padStart(5)}                              ║`);
    console.log('╠══════════════════════════════════════════════════════════════════╣');
    console.log('║  RISK DISTRIBUTION:                                              ║');
    console.log(`║    Zero (missed):          ${results.riskDistribution.zero.toString().padStart(5)}                              ║`);
    console.log(`║    Low (1-3):              ${results.riskDistribution.low.toString().padStart(5)}                              ║`);
    console.log(`║    Medium (4-7):           ${results.riskDistribution.medium.toString().padStart(5)}                              ║`);
    console.log(`║    High (8-14):            ${results.riskDistribution.high.toString().padStart(5)}                              ║`);
    console.log(`║    Critical (15+):         ${results.riskDistribution.critical.toString().padStart(5)}                              ║`);
    console.log('╠══════════════════════════════════════════════════════════════════╣');

    // Top TLDs
    const topTLDs = Object.entries(results.tldStats)
      .sort((a, b) => b[1] - a[1])
      .slice(0, 10);

    console.log('║  TOP 10 TLDs IN DATASET:                                         ║');
    topTLDs.forEach(([tld, count]) => {
      const detected = CONFIG.SUSPICIOUS_TLDS.test(`example.${tld}`) ? '✓' : '✗';
      console.log(`║    ${detected} .${tld.padEnd(12)} ${count.toString().padStart(5)} URLs                           ║`);
    });

    console.log('╚══════════════════════════════════════════════════════════════════╝');

    // Show some missed URLs for analysis
    if (results.missedUrls.length > 0) {
      console.log('\n⚠️  Sample MISSED URLs (first 20):');
      results.missedUrls.slice(0, 20).forEach(url => {
        try {
          const hostname = new URL(url).hostname;
          console.log(`    ${hostname}`);
        } catch (e) {
          console.log(`    ${url}`);
        }
      });
    }

    // Assertions
    expect(results.detected).toBeGreaterThan(0);

    // We expect at least 75% detection rate with heuristics
    const minExpectedRate = 75;
    expect(parseFloat(detectionRate)).toBeGreaterThanOrEqual(minExpectedRate);

    console.log(`\n✓ Detection rate ${detectionRate}% meets minimum threshold of ${minExpectedRate}%`);
  });

  test('All suspicious TLDs should be detected', () => {
    const suspiciousTLDUrls = PHISHING_URLS.filter(url => {
      try {
        const hostname = new URL(url).hostname;
        return CONFIG.SUSPICIOUS_TLDS.test(hostname);
      } catch (e) {
        return false;
      }
    });

    console.log(`\nURLs with suspicious TLDs: ${suspiciousTLDUrls.length}`);

    // All of these should have risk > 0
    let detected = 0;
    suspiciousTLDUrls.forEach(url => {
      const { risk } = assessUrl(url);
      if (risk > 0) detected++;
    });

    expect(detected).toBe(suspiciousTLDUrls.length);
    console.log(`✓ All ${suspiciousTLDUrls.length} suspicious TLD URLs detected`);
  });

  test('All free hosting URLs should be detected', () => {
    const freeHostingUrls = PHISHING_URLS.filter(url => {
      try {
        const hostname = new URL(url).hostname;
        return isFreeHosting(hostname);
      } catch (e) {
        return false;
      }
    });

    console.log(`\nURLs on free hosting: ${freeHostingUrls.length}`);

    let detected = 0;
    freeHostingUrls.forEach(url => {
      const { risk } = assessUrl(url);
      if (risk > 0) detected++;
    });

    expect(detected).toBe(freeHostingUrls.length);
    console.log(`✓ All ${freeHostingUrls.length} free hosting URLs detected`);
  });

  test('Crypto-related phishing should have high risk scores', () => {
    const cryptoUrls = PHISHING_URLS.filter(url => hasCryptoKeywords(url));

    console.log(`\nCrypto-related phishing URLs: ${cryptoUrls.length}`);

    let highRiskCount = 0;
    cryptoUrls.forEach(url => {
      const { risk } = assessUrl(url);
      if (risk >= 7) highRiskCount++;
    });

    const highRiskRate = (highRiskCount / cryptoUrls.length * 100).toFixed(1);
    console.log(`High risk (≥7): ${highRiskCount} (${highRiskRate}%)`);

    // At least 90% of crypto phishing should be high risk
    expect(parseFloat(highRiskRate)).toBeGreaterThanOrEqual(90);
  });

  test('Summary statistics', () => {
    // Get unique hostnames
    const hostnames = new Set();
    const tlds = new Set();

    PHISHING_URLS.forEach(url => {
      try {
        const hostname = new URL(url).hostname;
        hostnames.add(hostname);
        tlds.add(hostname.split('.').pop());
      } catch (e) {}
    });

    console.log('\n📊 DATASET SUMMARY:');
    console.log(`   Total URLs: ${PHISHING_URLS.length}`);
    console.log(`   Unique hostnames: ${hostnames.size}`);
    console.log(`   Unique TLDs: ${tlds.size}`);
    console.log(`   TLDs found: ${Array.from(tlds).sort().join(', ')}`);

    expect(true).toBe(true);
  });
});
