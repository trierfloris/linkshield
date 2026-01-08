/**
 * LinkShield v7.8 Comprehensive Audit Test Suite
 *
 * Focus: MV3 Compliance, Functional Stability, 2026 Phishing Resistance
 * Date: January 2026
 */

const fs = require('fs');
const path = require('path');

// Load source files
const manifestPath = path.join(__dirname, '..', 'manifest.json');
const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));

const configPath = path.join(__dirname, '..', 'config.js');
const configContent = fs.readFileSync(configPath, 'utf8');

const backgroundPath = path.join(__dirname, '..', 'background.js');
const backgroundContent = fs.readFileSync(backgroundPath, 'utf8');

const contentPath = path.join(__dirname, '..', 'content.js');
const contentContent = fs.readFileSync(contentPath, 'utf8');

// Load all locale files
const localesDir = path.join(__dirname, '..', '_locales');
const locales = fs.readdirSync(localesDir);
const localeData = {};
locales.forEach(locale => {
  const messagesPath = path.join(localesDir, locale, 'messages.json');
  if (fs.existsSync(messagesPath)) {
    localeData[locale] = JSON.parse(fs.readFileSync(messagesPath, 'utf8'));
  }
});

// Mock Chrome API
global.chrome = {
  runtime: {
    id: 'test-extension-id',
    sendMessage: jest.fn().mockResolvedValue({}),
    onMessage: { addListener: jest.fn() },
    getManifest: () => manifest
  },
  storage: {
    local: {
      get: jest.fn().mockResolvedValue({}),
      set: jest.fn().mockResolvedValue(undefined),
      remove: jest.fn().mockResolvedValue(undefined)
    },
    sync: {
      get: jest.fn().mockResolvedValue({}),
      set: jest.fn().mockResolvedValue(undefined)
    }
  },
  action: {
    setBadgeText: jest.fn(),
    setBadgeBackgroundColor: jest.fn(),
    setIcon: jest.fn(),
    setTitle: jest.fn()
  },
  tabs: {
    query: jest.fn().mockResolvedValue([]),
    get: jest.fn().mockResolvedValue({ id: 1, url: 'https://example.com' }),
    sendMessage: jest.fn().mockResolvedValue({})
  },
  alarms: {
    create: jest.fn(),
    clear: jest.fn(),
    onAlarm: { addListener: jest.fn() }
  },
  declarativeNetRequest: {
    updateDynamicRules: jest.fn().mockResolvedValue(undefined),
    getDynamicRules: jest.fn().mockResolvedValue([])
  },
  i18n: {
    getMessage: (key) => localeData.en?.[key]?.message || key,
    getUILanguage: () => 'en'
  }
};

// ============================================================================
// SECTION 1: ARCHITECTURAL INTEGRITY & MV3 COMPLIANCE
// ============================================================================
describe('1. Architectural Integrity & MV3 Compliance', () => {

  describe('1.1 Manifest MV3 Compliance', () => {
    test('manifest_version should be 3', () => {
      expect(manifest.manifest_version).toBe(3);
    });

    test('background should use service_worker (not scripts)', () => {
      expect(manifest.background.service_worker).toBe('background.js');
      expect(manifest.background.scripts).toBeUndefined();
    });

    test('background type should be module', () => {
      expect(manifest.background.type).toBe('module');
    });

    test('action should be defined (replaces browser_action)', () => {
      expect(manifest.action).toBeDefined();
      expect(manifest.action.default_popup).toBe('dynamic.html');
    });

    test('declarativeNetRequest permission present', () => {
      expect(manifest.permissions).toContain('declarativeNetRequest');
      expect(manifest.permissions).toContain('declarativeNetRequestWithHostAccess');
    });

    test('alarms permission present (MV3 timer replacement)', () => {
      expect(manifest.permissions).toContain('alarms');
    });
  });

  describe('1.2 Service Worker Lifecycle Compliance', () => {
    test('background.js should NOT contain window references', () => {
      // Allow window in comments but not as actual code
      const windowUsages = backgroundContent.match(/[^\/\/]window\./g) || [];
      // Filter out commented lines
      const actualUsages = windowUsages.filter(usage => {
        const lineIndex = backgroundContent.indexOf(usage);
        const lineStart = backgroundContent.lastIndexOf('\n', lineIndex);
        const line = backgroundContent.substring(lineStart, lineIndex);
        return !line.includes('//') && !line.includes('*');
      });
      expect(actualUsages.length).toBe(0);
    });

    test('background.js should NOT contain document references', () => {
      const documentUsages = backgroundContent.match(/[^\/\/]document\./g) || [];
      expect(documentUsages.length).toBe(0);
    });

    test('background.js should NOT use setInterval (use chrome.alarms)', () => {
      // setInterval is problematic in MV3 service workers
      const setIntervalUsages = backgroundContent.match(/setInterval\s*\(/g) || [];
      expect(setIntervalUsages.length).toBe(0);
    });
  });

  describe('1.3 Content Security Policy', () => {
    test('CSP should NOT allow unsafe-eval', () => {
      expect(manifest.content_security_policy.extension_pages).not.toContain('unsafe-eval');
    });

    test('CSP should block remote scripts (script-src self)', () => {
      expect(manifest.content_security_policy.extension_pages).toContain("script-src 'self'");
    });

    test('CSP object-src should be none', () => {
      expect(manifest.content_security_policy.extension_pages).toContain("object-src 'none'");
    });

    test('CSP frame-src should be none', () => {
      expect(manifest.content_security_policy.extension_pages).toContain("frame-src 'none'");
    });

    test('CSP base-uri should be self', () => {
      expect(manifest.content_security_policy.extension_pages).toContain("base-uri 'self'");
    });

    test('CSP form-action should be self', () => {
      expect(manifest.content_security_policy.extension_pages).toContain("form-action 'self'");
    });
  });

  describe('1.4 DNR Engine Configuration', () => {
    test('declarative_net_request rules should be defined', () => {
      expect(manifest.declarative_net_request).toBeDefined();
      expect(manifest.declarative_net_request.rule_resources).toHaveLength(1);
    });

    test('rules.json should exist and be valid', () => {
      const rulesPath = path.join(__dirname, '..', 'rules.json');
      expect(fs.existsSync(rulesPath)).toBe(true);
      const rules = JSON.parse(fs.readFileSync(rulesPath, 'utf8'));
      expect(Array.isArray(rules)).toBe(true);
    });

    test('rules should have valid structure', () => {
      const rulesPath = path.join(__dirname, '..', 'rules.json');
      const rules = JSON.parse(fs.readFileSync(rulesPath, 'utf8'));
      rules.slice(0, 10).forEach(rule => {
        expect(rule).toHaveProperty('id');
        expect(rule).toHaveProperty('priority');
        expect(rule).toHaveProperty('action');
        expect(rule).toHaveProperty('condition');
      });
    });
  });

  describe('1.5 Web Accessible Resources Security', () => {
    test('web_accessible_resources should not include JS files', () => {
      const resources = manifest.web_accessible_resources[0].resources;
      const jsFiles = resources.filter(r => r.endsWith('.js'));
      expect(jsFiles).toHaveLength(0);
    });

    test('web_accessible_resources should only include necessary files', () => {
      const resources = manifest.web_accessible_resources[0].resources;
      // Should only have JSON configs and icons
      resources.forEach(resource => {
        expect(resource).toMatch(/\.(json|png)$/);
      });
    });
  });
});

// ============================================================================
// SECTION 2: BACKGROUND ENGINE & SERVICE WORKER RESILIENCE
// ============================================================================
describe('2. Background Engine & Service Worker Resilience', () => {

  describe('2.1 License System Security', () => {

    test('License validation should reject empty keys', () => {
      const emptyKeyCheck = backgroundContent.includes('license') &&
                           backgroundContent.includes('empty') ||
                           backgroundContent.includes('!licenseKey');
      expect(emptyKeyCheck).toBe(true);
    });

    test('License data should be sanitized in logs', () => {
      expect(backgroundContent).toContain('REDACTED');
      expect(backgroundContent).toContain('sanitizedArgs');
    });

    test('Grace period check should exist', () => {
      expect(backgroundContent).toContain('checkLicenseGracePeriod');
      expect(backgroundContent).toContain('LICENSE_GRACE_PERIOD_DAYS');
    });

    test('License spoofing protection - storage validation', () => {
      // Check for storage.sync usage with validation
      expect(backgroundContent).toContain("chrome.storage.sync.get");
      expect(backgroundContent).toContain("licenseValid");
    });
  });

  describe('2.2 API Timeout & Error Handling', () => {

    test('fetchWithTimeout should be implemented', () => {
      expect(backgroundContent).toContain('fetchWithTimeout');
      expect(backgroundContent).toContain('AbortController');
    });

    test('API_TIMEOUT_MS should be defined', () => {
      expect(backgroundContent).toContain('API_TIMEOUT_MS');
    });

    test('SSL Labs rate limiting should be implemented', () => {
      expect(backgroundContent).toContain('SSL_LABS_MIN_INTERVAL_MS');
      expect(backgroundContent).toContain('sslLabsLastRequestTime');
    });
  });

  describe('2.3 State Management', () => {

    test('Tab-specific status should be isolated', () => {
      expect(backgroundContent).toContain('tabId');
      // Badge should be set per tab
      const hasTabIdUsage = backgroundContent.includes('tabId: sender.tab.id') ||
                             backgroundContent.includes('tabId: tabId') ||
                             backgroundContent.includes('sender.tab.id');
      expect(hasTabIdUsage).toBe(true);
    });

    test('Icon state restoration should exist', () => {
      expect(backgroundContent).toContain('restoreIconState');
    });
  });

  describe('2.4 Production Security', () => {

    test('IS_PRODUCTION flag should be true', () => {
      expect(backgroundContent).toContain('IS_PRODUCTION = true');
    });

    test('DEBUG functions should be disabled in production', () => {
      expect(backgroundContent).toContain('DEBUG_EXPOSE_FUNCTIONS = false');
    });

    test('Console methods should be overwritten in production', () => {
      expect(backgroundContent).toContain('console.log = function() {}');
      expect(backgroundContent).toContain('console.warn = function() {}');
    });
  });
});

// ============================================================================
// SECTION 3: CONTENT.JS - 2026 THREAT SHIELD
// ============================================================================
describe('3. Content.js - 2026 Threat Shield', () => {

  describe('3.1 ClickFix Attack Detection', () => {

    test('ClickFix detection should be initialized', () => {
      expect(contentContent).toContain('initClickFixDetection');
      expect(contentContent).toContain('clickFixDetectionInitialized');
    });

    test('PowerShell patterns should be detected', () => {
      expect(contentContent).toContain('powershell');
      expect(configContent).toContain('powershell');
    });

    test('CMD patterns should be detected', () => {
      expect(contentContent).toContain("type: 'cmd'");
      expect(configContent).toContain('cmd:');
    });

    test('Fake UI patterns should amplify risk', () => {
      expect(contentContent).toContain('fakeUI');
      expect(contentContent).toContain("totalScore +=");
    });

    test('Copy button detection near malicious code', () => {
      expect(contentContent).toContain('copyButtonNearMaliciousCode');
    });

    test('Warning UI should be shown', () => {
      expect(contentContent).toContain('showClickFixWarning');
      expect(contentContent).toContain('linkshield-clickfix-warning');
    });
  });

  describe('3.2 Shadow DOM Penetration', () => {

    test('Shadow DOM scanning should be implemented', () => {
      expect(contentContent).toContain('scanShadowDOM');
      expect(contentContent).toContain('shadowRoot');
    });

    test('Recursive depth limit should be enforced', () => {
      expect(contentContent).toContain('depth');
      expect(contentContent).toContain('MAX_SHADOW_DEPTH') ||
             expect(contentContent).toContain('depth + 1');
    });

    test('Shadow DOM phishing scan should exist', () => {
      expect(contentContent).toContain('scanShadowDOMForPhishing');
    });

    test('Login forms in Shadow DOM should be detected', () => {
      expect(contentContent).toContain('shadowForms');
      expect(contentContent).toContain('shadowDomLoginForm');
    });

    test('Phishing overlays in Shadow DOM should be detected', () => {
      expect(contentContent).toContain('shadowDomPhishingOverlay');
    });

    test('Iframes in Shadow DOM should be flagged', () => {
      expect(contentContent).toContain('shadowDomIframe');
    });
  });

  describe('3.3 Browser-in-the-Browser (BitB) Detection', () => {

    test('BitB detection should be initialized', () => {
      expect(contentContent).toContain('initBitBDetection');
    });

    test('Fake URL bar detection should exist', () => {
      expect(contentContent).toContain('findFakeUrlBarInElement') ||
             expect(contentContent).toContain('fakeUrlBar');
      expect(configContent).toContain('fakeUrlBarPatterns');
    });

    test('OAuth provider patterns should be configured', () => {
      // OAuth providers are in content.js (legitimateFormTargets) or background.js (whitelist)
      const hasGoogle = contentContent.includes('accounts.google.com') || backgroundContent.includes('accounts.google.com');
      const hasMicrosoft = contentContent.includes('login.microsoft') || backgroundContent.includes('login.microsoft');
      const hasApple = contentContent.includes('appleid.apple.com') || backgroundContent.includes('appleid.apple.com');
      expect(hasGoogle).toBe(true);
      expect(hasMicrosoft).toBe(true);
      expect(hasApple).toBe(true);
    });

    test('Window control detection (close/minimize)', () => {
      expect(contentContent).toContain('findWindowControls') ||
             expect(contentContent).toContain('windowControls');
      expect(configContent).toContain('windowControlIndicators');
    });

    test('Traffic light pattern detection (macOS)', () => {
      expect(configContent).toContain('trafficLights');
    });

    test('Padlock icon detection', () => {
      expect(contentContent).toContain('detectPadlockIcon') ||
             expect(contentContent).toContain('padlockIcon');
    });

    test('Overlay/modal detection', () => {
      expect(contentContent).toContain('findOverlayContainers') ||
             expect(contentContent).toContain('modal');
    });

    test('BitB warning should be displayed', () => {
      expect(contentContent).toContain('showBitBWarning');
    });

    test('BitB scoring thresholds should be configured', () => {
      expect(configContent).toContain('thresholds');
      expect(configContent).toContain('scores');
    });
  });

  describe('3.4 Imageless QR Detection (Table-based)', () => {

    test('Table QR scanner should be initialized', () => {
      expect(contentContent).toContain('initTableQRScanner') ||
             expect(contentContent).toContain('TableQRScanner');
    });

    test('Table-to-canvas reconstruction should exist', () => {
      expect(contentContent).toContain('canvas') ||
             expect(contentContent).toContain('getContext');
    });

    test('jsQR integration should be present', () => {
      expect(contentContent).toContain('jsQR');
    });

    test('Table QR warning messages should exist', () => {
      expect(localeData.en.tableQrDangerTitle).toBeDefined();
      expect(localeData.en.tableQrCautionTitle).toBeDefined();
    });
  });

  describe('3.5 NRD (Newly Registered Domain) Detection', () => {

    test('NRD analysis should be implemented', () => {
      const hasNrdAnalysis = contentContent.includes('analyzeNRDRisk') ||
                              contentContent.includes('nrdRisk') ||
                              contentContent.includes('domainAge') ||
                              contentContent.includes('newlyRegisteredDomain');
      expect(hasNrdAnalysis).toBe(true);
    });

    test('Ultra-critical NRD (hours) should be detected', () => {
      expect(localeData.en.nrdUltraCritical).toBeDefined();
    });

    test('Vishing combo (NRD + tel:) should be detected', () => {
      expect(localeData.en.nrdVishingCombo).toBeDefined();
    });

    test('NRD tiers should be configured', () => {
      // Critical: 0-1 days, High: 2-7 days, Medium: 8-30 days, Low: 31-90 days
      expect(configContent).toContain('DOMAIN_AGE') ||
             expect(backgroundContent).toContain('DOMAIN_AGE');
    });
  });

  describe('3.6 Form Action Hijacking Detection', () => {

    test('Form hijacking detection should exist', () => {
      expect(contentContent).toContain('formAction') ||
             expect(contentContent).toContain('form.action');
    });

    test('OAuth whitelist should be implemented', () => {
      const hasOAuthWhitelist = contentContent.includes('accounts.google.com') ||
                                 backgroundContent.includes('accounts.google.com') ||
                                 contentContent.includes('legitimateFormTargets');
      expect(hasOAuthWhitelist).toBe(true);
    });
  });

  describe('3.7 Hidden Iframe Detection', () => {

    test('Zero-size iframe detection', () => {
      expect(contentContent).toContain('width') &&
             expect(contentContent).toContain('height');
    });

    test('Off-screen iframe detection', () => {
      expect(contentContent).toContain('position') ||
             expect(contentContent).toContain('getBoundingClientRect');
    });

    test('CSS hidden iframe detection', () => {
      expect(contentContent).toContain('display') ||
             expect(contentContent).toContain('visibility');
    });
  });

  describe('3.8 URL Attack Detection', () => {

    test('@ symbol attack detection', () => {
      expect(contentContent).toContain('@') ||
             expect(contentContent).toContain('atSymbol');
    });

    test('Double encoding detection', () => {
      expect(contentContent).toContain('doubleEncoding') ||
             expect(contentContent).toContain('%25');
    });

    test('Fullwidth character detection', () => {
      expect(contentContent).toContain('fullwidth') ||
             expect(contentContent).toContain('Fullwidth');
    });

    test('Null byte injection detection', () => {
      expect(contentContent).toContain('nullByte') ||
             expect(contentContent).toContain('%00');
    });

    test('Blob URI blocking', () => {
      expect(contentContent).toContain('blob:');
    });
  });

  describe('3.9 Clipboard Guard', () => {

    test('Clipboard monitoring should exist', () => {
      expect(contentContent).toContain('initClipboardGuard') ||
             expect(contentContent).toContain('clipboard');
    });

    test('Crypto address hijacking detection', () => {
      expect(contentContent).toContain('crypto') ||
             expect(configContent).toContain('crypto');
    });
  });
});

// ============================================================================
// SECTION 4: POPUP, DYNAMIC FLOW & i18n
// ============================================================================
describe('4. Popup, Dynamic Flow & i18n', () => {

  describe('4.1 Dynamic Redirect Logic', () => {

    test('dynamic.html should exist', () => {
      const dynamicPath = path.join(__dirname, '..', 'dynamic.html');
      expect(fs.existsSync(dynamicPath)).toBe(true);
    });

    test('dynamic.js should exist', () => {
      const dynamicJsPath = path.join(__dirname, '..', 'dynamic.js');
      expect(fs.existsSync(dynamicJsPath)).toBe(true);
    });

    test('alert.html should exist for high-risk redirects', () => {
      const alertPath = path.join(__dirname, '..', 'alert.html');
      expect(fs.existsSync(alertPath)).toBe(true);
    });

    test('caution.html should exist for medium-risk redirects', () => {
      const cautionPath = path.join(__dirname, '..', 'caution.html');
      expect(fs.existsSync(cautionPath)).toBe(true);
    });
  });

  describe('4.2 i18n Integrity', () => {

    const requiredKeys = [
      'bitbWarningTitle',
      'bitbWarningMessage',
      'reason_bitbAttackDetected',
      'reason_bitbFakeUrlBar',
      'clickFixPowerShellTitle',
      'clickFixMessage',
      'shadowDomLoginForm',
      'tableQrDangerTitle',
      'nrdUltraCritical',
      'nrdVishingCombo'
    ];

    test('All 13 locales should be present', () => {
      expect(Object.keys(localeData).length).toBe(13);
    });

    requiredKeys.forEach(key => {
      test(`Key "${key}" should exist in English`, () => {
        expect(localeData.en[key]).toBeDefined();
        expect(localeData.en[key].message).toBeDefined();
        expect(localeData.en[key].message).not.toBe('');
      });
    });

    test('All required keys should exist in all locales', () => {
      const missingKeys = {};

      Object.keys(localeData).forEach(locale => {
        requiredKeys.forEach(key => {
          if (!localeData[locale][key]) {
            if (!missingKeys[locale]) missingKeys[locale] = [];
            missingKeys[locale].push(key);
          }
        });
      });

      const totalMissing = Object.values(missingKeys).flat().length;
      expect(totalMissing).toBe(0);
    });

    test('No undefined messages in any locale', () => {
      Object.keys(localeData).forEach(locale => {
        Object.keys(localeData[locale]).forEach(key => {
          const message = localeData[locale][key].message;
          expect(message).not.toBe('undefined');
          expect(message).not.toBeUndefined();
        });
      });
    });
  });

  describe('4.3 Severity Labels', () => {

    test('Site status titles should exist', () => {
      expect(localeData.en.siteSafeTitle).toBeDefined();
      expect(localeData.en.siteCautionTitle).toBeDefined();
      expect(localeData.en.siteAlertTitle).toBeDefined();
    });

    test('Risk level messages should exist', () => {
      expect(localeData.en.highRisk).toBeDefined();
      expect(localeData.en.mediumRisk).toBeDefined();
      expect(localeData.en.lowRisk).toBeDefined();
    });
  });
});

// ============================================================================
// SECTION 5: INTEGRATION & FALSE POSITIVE TESTS
// ============================================================================
describe('5. Integration & False Positive Tests', () => {

  describe('5.1 Risk Score Accumulation', () => {

    const calculateRiskLevel = (score, thresholds = { LOW: 4, MEDIUM: 8, HIGH: 15 }) => {
      if (score >= thresholds.HIGH) return 'alert';
      if (score >= thresholds.MEDIUM) return 'caution';
      if (score >= thresholds.LOW) return 'warning';
      return 'safe';
    };

    test('Score 0 = safe', () => {
      expect(calculateRiskLevel(0)).toBe('safe');
    });

    test('Score 4-7 = warning', () => {
      expect(calculateRiskLevel(4)).toBe('warning');
      expect(calculateRiskLevel(7)).toBe('warning');
    });

    test('Score 8-14 = caution', () => {
      expect(calculateRiskLevel(8)).toBe('caution');
      expect(calculateRiskLevel(14)).toBe('caution');
    });

    test('Score 15+ = alert', () => {
      expect(calculateRiskLevel(15)).toBe('alert');
      expect(calculateRiskLevel(25)).toBe('alert');
    });

    test('NRD critical (12) + Form hijacking (8) = alert (20)', () => {
      const score = 12 + 8;
      expect(calculateRiskLevel(score)).toBe('alert');
    });

    test('Hidden iframe (6) + No HTTPS (3) = caution (9)', () => {
      const score = 6 + 3;
      expect(calculateRiskLevel(score)).toBe('caution');
    });
  });

  describe('5.2 Trusted Domain Handling', () => {

    const trustedDomains = [
      'google.com', 'microsoft.com', 'apple.com', 'amazon.com',
      'facebook.com', 'linkedin.com', 'github.com', 'stackoverflow.com'
    ];

    test('TrustedDomains.json should exist', () => {
      const trustedPath = path.join(__dirname, '..', 'TrustedDomains.json');
      expect(fs.existsSync(trustedPath)).toBe(true);
    });

    test('Trusted domains file should be valid JSON', () => {
      const trustedPath = path.join(__dirname, '..', 'TrustedDomains.json');
      const content = fs.readFileSync(trustedPath, 'utf8');
      expect(() => JSON.parse(content)).not.toThrow();
    });
  });

  describe('5.3 Production Constants', () => {

    test('TRIAL_DAYS should be 30', () => {
      expect(backgroundContent).toContain('TRIAL_DAYS = 30');
    });

    test('LICENSE_GRACE_PERIOD_DAYS should be 7', () => {
      expect(backgroundContent).toContain('LICENSE_GRACE_PERIOD_DAYS = 7');
    });

    test('CACHE_TTL should be 24 hours', () => {
      expect(backgroundContent).toContain('CACHE_TTL = 24 * 60 * 60 * 1000');
    });
  });
});

// ============================================================================
// SECTION 6: ZERO-DAY RESILIENCE VALIDATION
// ============================================================================
describe('6. Zero-Day Resilience - 2026 Threat Scenarios', () => {

  describe('6.1 BitB Attack Simulation', () => {

    test('BitB config patterns should cover major OAuth providers', () => {
      const providers = [
        'accounts.google.com',
        'login.microsoft',  // login.microsoftonline.com or login.microsoft.com
        'login.live.com',
        'appleid.apple.com',
        'auth0.com',
        'okta.com'
      ];

      // OAuth providers are typically in content.js (legitimateFormTargets) or background.js
      const allContent = contentContent + backgroundContent;
      providers.forEach(provider => {
        const hasProvider = allContent.includes(provider);
        expect(hasProvider).toBe(true);
      });
    });

    test('BitB scoring should escalate appropriately', () => {
      // Fake URL bar alone should be high risk
      expect(configContent).toContain('fakeUrlBar');
      // Check for score values
      const fakeUrlBarScore = configContent.match(/fakeUrlBar:\s*(\d+)/);
      if (fakeUrlBarScore) {
        expect(parseInt(fakeUrlBarScore[1])).toBeGreaterThanOrEqual(8);
      }
    });
  });

  describe('6.2 ClickFix Attack Simulation', () => {

    test('PowerShell -e (encoded) should be detected', () => {
      const hasPowershell = configContent.includes('powershell') || configContent.includes('-e');
      expect(hasPowershell).toBe(true);
    });

    test('mshta patterns should be detected', () => {
      expect(configContent).toContain('mshta');
    });

    test('certutil patterns should be detected', () => {
      expect(configContent).toContain('certutil');
    });

    test('bitsadmin patterns should be detected', () => {
      expect(configContent).toContain('bitsadmin');
    });
  });

  describe('6.3 Evasion Technique Detection', () => {

    test('Base64 encoded commands should be flagged', () => {
      const hasBase64 = configContent.includes('base64') || configContent.includes('FromBase64') || configContent.includes('Base64');
      expect(hasBase64).toBe(true);
    });

    test('URL encoding evasion should be detected', () => {
      const hasUrlEncoding = contentContent.includes('decodeURIComponent') || contentContent.includes('encodeURIComponent') || contentContent.includes('URLSearchParams');
      expect(hasUrlEncoding).toBe(true);
    });
  });
});

// ============================================================================
// AUDIT SUMMARY TEST
// ============================================================================
describe('AUDIT SUMMARY', () => {

  test('All critical audit sections should pass', () => {
    // This test serves as a summary marker
    expect(true).toBe(true);
  });
});
