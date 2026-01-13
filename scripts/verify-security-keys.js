/**
 * Verify that all 21 security keys are present in all locale files
 */
const fs = require('fs');
const path = require('path');

const localesDir = path.join(__dirname, '..', '_locales');
const requiredKeys = [
  'visualHijackingDetected', 'visualHijackingMessage', 'transparentHighZIndexOverlay',
  'invisibleClickjackOverlay', 'fullscreenTransparentOverlay', 'hiddenLinkOverlay',
  'detectionReason', 'closeWarning', 'failSafeNetworkTitle', 'failSafeNetworkMessage',
  'failSafeGraceTitle', 'failSafeGraceMessage', 'failSafePreservedTitle', 'failSafePreservedMessage',
  'failSafeDefaultTitle', 'failSafeDefaultMessage', 'dismissTooltip', 'dontShowAgain',
  'confirmYes', 'confirmNo', 'reportPhishingSuccess'
];

console.log('=== SECURITY KEYS SYNC VERIFICATION ===');
console.log(`Required keys: ${requiredKeys.length}`);
console.log('');

const locales = fs.readdirSync(localesDir).filter(f =>
  fs.statSync(path.join(localesDir, f)).isDirectory()
);

let allComplete = true;
let syncedCount = 0;
let missingCount = 0;

console.log('| Locale | Total Keys | Security Keys | Status |');
console.log('|--------|------------|---------------|--------|');

for (const locale of locales.sort()) {
  const data = require(path.join(localesDir, locale, 'messages.json'));
  const totalKeys = Object.keys(data).length;
  const presentKeys = requiredKeys.filter(k => data[k] !== undefined);
  const missingKeys = requiredKeys.filter(k => data[k] === undefined);

  let status = '✅ Complete';
  if (missingKeys.length > 0) {
    status = `❌ Missing ${missingKeys.length}`;
    allComplete = false;
    missingCount++;
  } else {
    syncedCount++;
  }

  console.log(`| ${locale.padEnd(6)} | ${String(totalKeys).padEnd(10)} | ${presentKeys.length}/21         | ${status} |`);

  if (missingKeys.length > 0) {
    console.log(`         Missing: ${missingKeys.join(', ')}`);
  }
}

console.log('');
console.log('=== SUMMARY ===');
console.log(`Total locales: ${locales.length}`);
console.log(`Fully synced: ${syncedCount}`);
console.log(`Missing keys: ${missingCount}`);
console.log(`Status: ${allComplete ? '✅ ALL LOCALES SYNCHRONIZED' : '❌ SYNC REQUIRED'}`);
