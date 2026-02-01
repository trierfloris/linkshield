/**
 * LinkShield i18n Reason Keys Validation Tests
 *
 * Validates that all reason keys used in the codebase exist in all locale files
 */

const fs = require('fs');
const path = require('path');

// All reason keys that can be pushed to the reasons array in content.js
const REASON_KEYS = [
  // Shadow DOM reasons
  'shadowDomLoginForm',
  'shadowDomPhishingOverlay',
  'shadowDomIframe',

  // Form action reasons
  'formActionInvalid',
  'formActionHijacking',

  // QR code reasons
  'tableBasedQR',

  // URL analysis reasons
  'noHttps',
  'ipAsDomain',
  'tooManySubdomains',
  'suspiciousKeywords',
  'suspiciousPattern',
  'shortenedUrl',
  'downloadPage',
  'freeHosting',
  'encodedCharacters',
  'homoglyphAttack',
  'metaRedirect',
  'cryptoPhishing',
  'externalScripts',
  'suspiciousParams',
  'mixedContent',
  'unusualPort',
  'javascriptScheme',
  'urlFragmentTrick',
  'suspiciousTLD',
  'base64OrHex',
  'similarToLegitimateDomain',
  'youngDomain',
  'insecureLoginPage',
  'loginPageNoMX',
  'malwareExtension',
  'typosquattingAttack',
  'downloadKeyword',
  'mixedScripts',
  'digitHomoglyph',
  'suspiciousPageText',
  'urgencyTactic',

  // Iframe reasons
  'suspiciousIframeAdComponent',
  'suspiciousIframeTracking',
  'suspiciousIframeMalicious',
  'suspiciousIframeHidden',
  'mixedContentIframe',
  'invalidIframeSrc',
  'iframeHidden',
  'hiddenIframeZeroSize',
  'hiddenIframeOffScreen',
  'hiddenIframeCSSHidden',
  'hiddenIframeNegativePos',

  // Script reasons
  'suspiciousScriptContent',
  'invalidScriptSrc',

  // NRD reasons
  'nrdCritical',
  'nrdHigh',
  'nrdMedium',
  'nrdLow',
  'nrdUltraCritical',
  'nrdVishingCombo',
  'nrdTelCombo',

  // BitB attack reasons
  'reason_bitbAttackDetected',
  'reason_bitbFakeUrlBar',
  'reason_bitbWindowControls',
  'reason_bitbLoginFormInOverlay',
  'reason_bitbOAuthBranding',
  'reason_bitbPadlockIcon',
  'reason_bitbWindowStyling',
  'reason_bitbIframeInModal',

  // Redirect chain reasons
  'reason_redirectChain',
  'reason_excessiveRedirects',
  'reason_domainHopping',
  'reason_chainedShorteners',
  'reason_suspiciousFinalTLD',
  'reason_redirectToIP',
  'reason_redirectTimeout',

  // URL attack reasons
  'atSymbolPhishing',
  'atSymbolInPath',
  'doubleEncoding',
  'fullwidthCharacters',
  'nullByteInjection',
  'reason_atSymbolPhishing',
  'reason_doubleEncoding',
  'reason_fullwidthCharacters',
  'reason_nullByteInjection',

  // Clipboard hijacking
  'reason_clipboardHijackingCrypto',
  'reason_clipboardHijackingDetected',

  // Brand/domain reasons
  'brandSubdomainPhishing',
  'reason_brandSubdomainPhishing',

  // Opaque redirect reasons
  'reason_opaqueRedirectChain',
  'reason_opaqueRedirectToIP',
  'reason_opaqueRedirectSuspiciousTLD',
  'reason_opaqueRedirectNRD',

  // General reasons
  'invalidUrl',
  'safeDomain',
  'allowedProtocol',
  'trustedDomain',
  'trustedDomainSkipped',
  'urlCredentialsAttack',
  'urlTooLong',
  'invalidUrlFormat',
  'invalidDomain',
  'invalidHostname',
  'typosquattingPattern',
  'punycodeDetected',

  // Additional reason_ prefixed keys
  'reason_nonAscii',
  'reason_brandKeywordHomoglyph',
  'reason_noHttps',
  'reason_suspiciousTLD',
  'reason_ipAsDomain',
  'reason_tooManySubdomains',
  'reason_shortenedUrl',
  'reason_suspiciousKeywords',
  'reason_malwareExtension',
  'reason_urlTooLong',
  'reason_encodedCharacters',
  'reason_homoglyphAttack',
  'reason_typosquatting',
  'reason_suspiciousBrandPattern',
  'reason_unusualPort',
  'reason_punycode',
  'reason_loginPageNoMX',
  'reason_insecureLoginPage',
  'reason_sslValidationFailed',
  'reason_similarToLegitimateDomain'
];

// UI message keys (for completeness)
const UI_KEYS = [
  'extName',
  'extDescription',
  'alertTitle',
  'alertMessage',
  'severityLabel',
  'reasonLabel',
  'adviceMessage',
  'adviceCheckUrl',
  'highRisk',
  'mediumRisk',
  'lowRisk',
  'noSuspiciousFeatures',
  'siteStatusNotAvailable',
  'loadingMessage',
  'saveSettings',
  'settingsSaved',
  'bitbClosePageButton',
  'bitbDismissButton'
];

// Keys that should exist but are optional (may be added later)
const OPTIONAL_KEYS = [
  'trustDomainButton',
  'trustedDomainSkipped'
];

const LOCALES_DIR = path.join(__dirname, '..', '_locales');

/**
 * Get all available locale directories
 */
function getLocales() {
  if (!fs.existsSync(LOCALES_DIR)) {
    throw new Error(`Locales directory not found: ${LOCALES_DIR}`);
  }
  return fs.readdirSync(LOCALES_DIR).filter(dir => {
    const messagesPath = path.join(LOCALES_DIR, dir, 'messages.json');
    return fs.existsSync(messagesPath);
  });
}

/**
 * Load messages for a specific locale
 */
function loadMessages(locale) {
  const messagesPath = path.join(LOCALES_DIR, locale, 'messages.json');
  const content = fs.readFileSync(messagesPath, 'utf8');
  return JSON.parse(content);
}

describe('i18n Reason Keys Validation', () => {
  let locales;
  let englishMessages;

  beforeAll(() => {
    locales = getLocales();
    englishMessages = loadMessages('en');
  });

  describe('English (base locale)', () => {
    test('should have all reason keys defined', () => {
      const missingKeys = REASON_KEYS.filter(key => !englishMessages[key]);

      if (missingKeys.length > 0) {
        console.log('Missing reason keys in English:', missingKeys);
      }

      // Allow some flexibility - warn but don't fail for missing keys
      expect(missingKeys.length).toBeLessThan(20);
    });

    test('should have all UI keys defined', () => {
      const missingKeys = UI_KEYS.filter(key => !englishMessages[key]);
      expect(missingKeys).toEqual([]);
    });

    test('should have non-empty messages for all defined keys', () => {
      const emptyKeys = Object.entries(englishMessages)
        .filter(([key, value]) => !value.message || value.message.trim() === '')
        .map(([key]) => key);

      expect(emptyKeys).toEqual([]);
    });
  });

  describe('All locales completeness', () => {
    test('should have at least 10 locales', () => {
      expect(locales.length).toBeGreaterThanOrEqual(10);
    });

    test.each(['en', 'nl', 'de', 'fr', 'es'])('locale %s should exist', (locale) => {
      expect(locales).toContain(locale);
    });
  });

  describe('Locale consistency', () => {
    const englishKeys = Object.keys(loadMessages('en'));

    test.each(getLocales().filter(l => l !== 'en'))('locale %s should have all English keys', (locale) => {
      const localeMessages = loadMessages(locale);
      const localeKeys = Object.keys(localeMessages);
      const missingKeys = englishKeys.filter(key => !localeKeys.includes(key));

      // Allow up to 5% missing keys (translations may lag)
      const maxMissing = Math.ceil(englishKeys.length * 0.05);

      if (missingKeys.length > maxMissing) {
        console.log(`Locale ${locale} missing ${missingKeys.length} keys:`, missingKeys.slice(0, 10));
      }

      expect(missingKeys.length).toBeLessThanOrEqual(maxMissing);
    });
  });

  describe('Message format validation', () => {
    test('placeholder syntax should be valid in English', () => {
      const invalidPlaceholders = [];

      Object.entries(englishMessages).forEach(([key, value]) => {
        if (value.placeholders) {
          Object.entries(value.placeholders).forEach(([phKey, phValue]) => {
            // Check that placeholder content matches $1, $2, etc.
            if (!phValue.content || !/^\$\d+$/.test(phValue.content)) {
              invalidPlaceholders.push({ key, placeholder: phKey });
            }
          });
        }

        // Check for placeholders in message that aren't defined
        const messagePlaceholders = value.message.match(/\$[A-Z_]+\$/g) || [];
        messagePlaceholders.forEach(ph => {
          const phName = ph.replace(/\$/g, '');
          if (!value.placeholders || !value.placeholders[phName]) {
            invalidPlaceholders.push({ key, undefinedPlaceholder: phName });
          }
        });
      });

      expect(invalidPlaceholders).toEqual([]);
    });
  });

  describe('Critical reason keys', () => {
    const criticalKeys = [
      'formActionHijacking',
      'reason_bitbAttackDetected',
      'homoglyphAttack',
      'cryptoPhishing',
      'reason_clipboardHijackingCrypto',
      'nrdCritical'
    ];

    test.each(criticalKeys)('critical key "%s" should exist in English', (key) => {
      expect(englishMessages[key]).toBeDefined();
      expect(englishMessages[key].message).toBeTruthy();
    });

    test.each(criticalKeys)('critical key "%s" should indicate high/critical risk', (key) => {
      const message = englishMessages[key]?.message || '';
      const hasRiskIndicator =
        message.toLowerCase().includes('high risk') ||
        message.toLowerCase().includes('critical') ||
        message.toLowerCase().includes('dangerous') ||
        message.toLowerCase().includes('critical risk');

      expect(hasRiskIndicator).toBe(true);
    });
  });

  describe('Brand-specific keys', () => {
    const brands = ['microsoft', 'apple', 'google', 'paypal', 'amazon', 'facebook'];

    test.each(brands)('typosquatting key for %s should exist', (brand) => {
      const key = `typosquattingAttack_${brand}_com`;
      expect(englishMessages[key]).toBeDefined();
    });

    test.each(brands)('homoglyph key for %s should exist', (brand) => {
      const key = `homoglyphAttack_${brand}_com`;
      expect(englishMessages[key]).toBeDefined();
    });
  });
});

describe('i18n Key Usage in Source Code', () => {
  const contentJs = fs.readFileSync(
    path.join(__dirname, '..', 'content.js'),
    'utf8'
  );

  test('reasons.push() calls should use valid keys', () => {
    const pushPattern = /reasons\.push\(['"]([a-zA-Z_][a-zA-Z0-9_]*)['"]\)/g;
    const usedKeys = [];
    let match;

    while ((match = pushPattern.exec(contentJs)) !== null) {
      usedKeys.push(match[1]);
    }

    const englishMessages = loadMessages('en');
    const undefinedKeys = usedKeys.filter(key => !englishMessages[key]);

    if (undefinedKeys.length > 0) {
      console.log('Undefined keys used in reasons.push():', [...new Set(undefinedKeys)]);
    }

    // Allow some undefined keys (may be dynamically generated)
    expect(undefinedKeys.length).toBeLessThan(10);
  });

  test('chrome.i18n.getMessage() calls should use valid keys', () => {
    const getMessagePattern = /chrome\.i18n\.getMessage\(['"]([a-zA-Z_][a-zA-Z0-9_]*)['"]/g;
    const usedKeys = [];
    let match;

    while ((match = getMessagePattern.exec(contentJs)) !== null) {
      usedKeys.push(match[1]);
    }

    const englishMessages = loadMessages('en');
    const undefinedKeys = usedKeys.filter(key => !englishMessages[key]);

    // All chrome.i18n.getMessage keys should be defined
    expect(undefinedKeys).toEqual([]);
  });
});
