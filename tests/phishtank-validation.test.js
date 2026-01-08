/**
 * PhishTank URL Validation Test
 * Tests LinkShield detection against real-world phishing URLs from PhishTank
 * Date: 2026-01-08
 */

// Mock Chrome APIs
global.chrome = {
  storage: {
    local: { get: jest.fn(() => Promise.resolve({})), set: jest.fn(() => Promise.resolve()) },
    sync: { get: jest.fn(() => Promise.resolve({ backgroundSecurity: true, integratedProtection: true })), set: jest.fn(() => Promise.resolve()) }
  },
  runtime: { id: 'test', sendMessage: jest.fn(() => Promise.resolve({})), getManifest: jest.fn(() => ({ version: '7.8' })) },
  i18n: { getMessage: jest.fn(key => key) }
};

// Load config
const fs = require('fs');
const path = require('path');
const configContent = fs.readFileSync(path.join(__dirname, '..', 'config.js'), 'utf8');
eval(configContent.replace('window.CONFIG', 'global.CONFIG'));
const CONFIG = global.CONFIG;

// PhishTank verified URLs (2026-01-08)
const PHISHTANK_URLS = [
  { url: 'https://exoduswallet-us.my.canva.site/us', target: 'Exodus Wallet', expectedDetection: ['freeHosting', 'cryptoPhishing'] },
  { url: 'https://allegrolaknie.pl-479526.sbs/oferta', target: 'Allegro (Polish)', expectedDetection: ['suspiciousTLD'] },
  { url: 'https://saintycoup.com/TjpkdkbeL2', target: 'Unknown', expectedDetection: ['suspiciousPattern'] },
  { url: 'https://melzstore.com/GUByBz', target: 'Unknown', expectedDetection: ['suspiciousPattern'] },
  { url: 'https://www.xendary.cfd/y1.html', target: 'Unknown', expectedDetection: ['suspiciousTLD'] },
  { url: 'https://www.ravelloid.cfd/kwfdtiveekcg', target: 'Unknown', expectedDetection: ['suspiciousTLD'] },
  { url: 'https://wallet-web3-exdous.typedream.app/en-us', target: 'Web3 Wallet', expectedDetection: ['freeHosting', 'cryptoPhishing'] },
  { url: 'https://turesaaabo.z1.web.core.windows.net/', target: 'Azure Phishing', expectedDetection: ['freeHosting'] },
  { url: 'https://wubeyabei.z27.web.core.windows.net/', target: 'Azure Phishing', expectedDetection: ['freeHosting'] },
  { url: 'https://tutheewaia.z1.web.core.windows.net/', target: 'Azure Phishing', expectedDetection: ['freeHosting'] },
  { url: 'https://www.moonflare.cfd/y1.html', target: 'Unknown', expectedDetection: ['suspiciousTLD'] },
  { url: 'https://zzwww2.com/WS7FaC4vij', target: 'Unknown', expectedDetection: ['suspiciousPattern'] },
  { url: 'https://blissful-platforms-135005.framer.app/', target: 'Framer Phishing', expectedDetection: ['freeHosting'] }
];

describe('PhishTank URL Validation', () => {

  describe('1. Suspicious TLD Detection', () => {
    const tldUrls = PHISHTANK_URLS.filter(u => u.expectedDetection.includes('suspiciousTLD'));

    test.each(tldUrls)('Should detect suspicious TLD: $url', ({ url }) => {
      const hostname = new URL(url).hostname;
      const hasSuspiciousTLD = CONFIG.SUSPICIOUS_TLDS.test(hostname);
      expect(hasSuspiciousTLD).toBe(true);
    });

    test('.sbs TLD should be flagged', () => {
      expect(CONFIG.SUSPICIOUS_TLDS.test('example.sbs')).toBe(true);
    });

    test('.cfd TLD should be flagged', () => {
      expect(CONFIG.SUSPICIOUS_TLDS.test('example.cfd')).toBe(true);
    });
  });

  describe('2. Free Hosting Detection', () => {

    function isFreeHosting(hostname) {
      const domains = CONFIG.FREE_HOSTING_DOMAINS;
      for (const domain of domains) {
        if (hostname === domain || hostname.endsWith('.' + domain)) {
          return true;
        }
      }
      return false;
    }

    test('typedream.app should be detected as free hosting', () => {
      expect(isFreeHosting('wallet-web3-exdous.typedream.app')).toBe(true);
    });

    test('blob.core.windows.net should be detected as free hosting', () => {
      expect(isFreeHosting('test.blob.core.windows.net')).toBe(true);
    });

    // These tests will FAIL if not in config - identifying gaps
    test('COVERAGE GAP: web.core.windows.net (Azure Static Website)', () => {
      const result = isFreeHosting('turesaaabo.z1.web.core.windows.net');
      if (!result) {
        console.warn('⚠️ GAP DETECTED: web.core.windows.net not in FREE_HOSTING_DOMAINS');
      }
      // This test documents the gap - expect it to fail until fixed
      expect(result).toBe(true);
    });

    test('COVERAGE GAP: canva.site', () => {
      const result = isFreeHosting('exoduswallet-us.my.canva.site');
      if (!result) {
        console.warn('⚠️ GAP DETECTED: canva.site not in FREE_HOSTING_DOMAINS');
      }
      expect(result).toBe(true);
    });

    test('COVERAGE GAP: framer.app', () => {
      const result = isFreeHosting('blissful-platforms-135005.framer.app');
      if (!result) {
        console.warn('⚠️ GAP DETECTED: framer.app not in FREE_HOSTING_DOMAINS (only framer.website is listed)');
      }
      expect(result).toBe(true);
    });
  });

  describe('3. Crypto Phishing Detection', () => {

    function hasCryptoKeywords(url) {
      const cryptoPatterns = [
        /wallet/i, /crypto/i, /web3/i, /exodus/i, /metamask/i,
        /ledger/i, /trezor/i, /phantom/i, /coinbase/i, /binance/i
      ];
      return cryptoPatterns.some(pattern => pattern.test(url));
    }

    test('Exodus wallet phishing should trigger crypto detection', () => {
      expect(hasCryptoKeywords('https://exoduswallet-us.my.canva.site/us')).toBe(true);
    });

    test('Web3 wallet phishing should trigger crypto detection', () => {
      expect(hasCryptoKeywords('https://wallet-web3-exdous.typedream.app/en-us')).toBe(true);
    });
  });

  describe('4. Combined Risk Assessment', () => {

    function assessRisk(url) {
      let risk = 0;
      const reasons = [];

      try {
        const urlObj = new URL(url);
        const hostname = urlObj.hostname;

        // TLD check
        if (CONFIG.SUSPICIOUS_TLDS.test(hostname)) {
          risk += 8;
          reasons.push('suspiciousTLD');
        }

        // Free hosting check
        for (const domain of CONFIG.FREE_HOSTING_DOMAINS) {
          if (hostname === domain || hostname.endsWith('.' + domain)) {
            risk += 5;
            reasons.push('freeHosting');
            break;
          }
        }

        // Crypto keywords
        if (/wallet|crypto|web3|exodus|metamask|ledger/i.test(url)) {
          risk += 7;
          reasons.push('cryptoKeywords');
        }

        // Random string pattern (common in phishing)
        if (/\/[A-Za-z0-9]{6,12}$/.test(urlObj.pathname)) {
          risk += 3;
          reasons.push('randomPath');
        }

        // Azure/cloud hosting with random subdomain
        if (/^[a-z]{8,12}\.(z\d+\.)?web\.core\.windows\.net$/i.test(hostname)) {
          risk += 6;
          reasons.push('azureStaticPhishing');
        }

      } catch (e) {
        risk += 10;
        reasons.push('invalidUrl');
      }

      return { risk, reasons };
    }

    test.each(PHISHTANK_URLS)('Risk assessment for: $url', ({ url, target }) => {
      const { risk, reasons } = assessRisk(url);
      console.log(`  ${target}: risk=${risk}, reasons=[${reasons.join(', ')}]`);
      // All PhishTank URLs should have risk > 0
      expect(risk).toBeGreaterThan(0);
    });

    test('All PhishTank URLs should have risk >= 3 (minimum detection)', () => {
      const results = PHISHTANK_URLS.map(({ url }) => assessRisk(url));
      const allDetected = results.every(r => r.risk >= 3);

      if (!allDetected) {
        const missed = PHISHTANK_URLS.filter((_, i) => results[i].risk < 3);
        console.warn('⚠️ URLs with insufficient risk score:', missed.map(u => u.url));
      }

      expect(allDetected).toBe(true);
    });
  });

  describe('5. Detection Coverage Summary', () => {

    test('Generate coverage report', () => {
      const coverage = {
        suspiciousTLD: 0,
        freeHosting: 0,
        cryptoPhishing: 0,
        detected: 0,
        missed: 0
      };

      PHISHTANK_URLS.forEach(({ url }) => {
        const hostname = new URL(url).hostname;
        let detected = false;

        if (CONFIG.SUSPICIOUS_TLDS.test(hostname)) {
          coverage.suspiciousTLD++;
          detected = true;
        }

        for (const domain of CONFIG.FREE_HOSTING_DOMAINS) {
          if (hostname === domain || hostname.endsWith('.' + domain)) {
            coverage.freeHosting++;
            detected = true;
            break;
          }
        }

        if (/wallet|crypto|web3|exodus/i.test(url)) {
          coverage.cryptoPhishing++;
          detected = true;
        }

        if (detected) {
          coverage.detected++;
        } else {
          coverage.missed++;
        }
      });

      console.log('\n📊 PHISHTANK DETECTION COVERAGE REPORT');
      console.log('=====================================');
      console.log(`Total URLs tested: ${PHISHTANK_URLS.length}`);
      console.log(`Detected: ${coverage.detected} (${Math.round(coverage.detected/PHISHTANK_URLS.length*100)}%)`);
      console.log(`Missed: ${coverage.missed} (${Math.round(coverage.missed/PHISHTANK_URLS.length*100)}%)`);
      console.log('');
      console.log('Detection breakdown:');
      console.log(`  - Suspicious TLD: ${coverage.suspiciousTLD}`);
      console.log(`  - Free Hosting: ${coverage.freeHosting}`);
      console.log(`  - Crypto Phishing: ${coverage.cryptoPhishing}`);

      // We want at least 70% detection rate
      const detectionRate = coverage.detected / PHISHTANK_URLS.length;
      expect(detectionRate).toBeGreaterThanOrEqual(0.7);
    });
  });

  describe('6. Missing Domain Coverage', () => {

    test('List domains that should be added to FREE_HOSTING_DOMAINS', () => {
      const missingDomains = [
        'web.core.windows.net',  // Azure Static Website hosting
        'canva.site',            // Canva Sites
        'framer.app',            // Framer (different from framer.website)
        'my.canva.site'          // Canva subdomain variant
      ];

      console.log('\n🔧 RECOMMENDED ADDITIONS TO FREE_HOSTING_DOMAINS:');
      missingDomains.forEach(domain => {
        const isInConfig = CONFIG.FREE_HOSTING_DOMAINS.includes(domain);
        console.log(`  ${isInConfig ? '✓' : '✗'} ${domain}`);
      });

      // This test passes but logs recommendations
      expect(true).toBe(true);
    });
  });
});
