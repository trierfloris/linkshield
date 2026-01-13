const fs = require('fs');
const path = require('path');

const localesDir = path.join(__dirname, '..', '_locales');
const enKeys = Object.keys(require(path.join(localesDir, 'en', 'messages.json')));
const locales = fs.readdirSync(localesDir).filter(f => {
  const stat = fs.statSync(path.join(localesDir, f));
  return stat.isDirectory() && f !== 'en';
});

const securityKeys = [
  'visualHijackingDetected', 'visualHijackingMessage', 'detectionReason', 'closeWarning',
  'transparentHighZIndexOverlay', 'invisibleClickjackOverlay', 'fullscreenTransparentOverlay', 'hiddenLinkOverlay',
  'failSafeNetworkTitle', 'failSafeNetworkMessage', 'failSafeGraceTitle', 'failSafeGraceMessage',
  'failSafePreservedTitle', 'failSafePreservedMessage', 'failSafeDefaultTitle', 'failSafeDefaultMessage',
  'webTransportWarningTitle', 'webTransportWarningMessage', 'webTransportDirectIP', 'webTransportHighPort',
  'webTransportRandomSubdomain', 'webTransportFreeTLD', 'webTransportHighConnectionRate',
  'webTransportHighDatagramRate', 'webTransportObfuscatedUrl', 'webTransportInvalidUrl'
];

console.log('=== LOCALE GAP ANALYSIS ===');
console.log('EN keys total:', enKeys.length);
console.log('Security keys to check:', securityKeys.length);
console.log('');

const results = [];
for (const locale of locales) {
  try {
    const localeData = require(path.join(localesDir, locale, 'messages.json'));
    const localeKeys = Object.keys(localeData);
    const missing = enKeys.filter(k => !localeKeys.includes(k));
    const missingSecurityKeys = securityKeys.filter(k => !localeKeys.includes(k));
    results.push({
      locale,
      total: localeKeys.length,
      missing: missing.length,
      missingSecurityKeys: missingSecurityKeys.length,
      securityKeysMissing: missingSecurityKeys,
      allMissing: missing
    });
  } catch (e) {
    results.push({ locale, error: e.message });
  }
}

// Sort by missing count
results.sort((a, b) => (b.missing || 0) - (a.missing || 0));

console.log('| Locale | Keys | Missing | Security Missing |');
console.log('|--------|------|---------|------------------|');
for (const r of results) {
  if (r.error) {
    console.log(`| ${r.locale} | ERROR | ${r.error} |`);
  } else {
    console.log(`| ${r.locale} | ${r.total} | ${r.missing} | ${r.missingSecurityKeys} |`);
  }
}

// List missing security keys per locale
console.log('');
console.log('=== MISSING SECURITY KEYS PER LOCALE ===');
for (const r of results) {
  if (r.securityKeysMissing && r.securityKeysMissing.length > 0) {
    console.log(`${r.locale}: ${r.securityKeysMissing.join(', ')}`);
  }
}

// Export for automation
module.exports = { results, securityKeys, enKeys };
