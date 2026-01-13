/**
 * Automatic i18n Fallback Injector for LinkShield
 * Adds missing keys from EN to all other locales with English values as placeholders
 */
const fs = require('fs');
const path = require('path');

const localesDir = path.join(__dirname, '..', '_locales');
const enData = require(path.join(localesDir, 'en', 'messages.json'));
const enKeys = Object.keys(enData);

// Get all locales except EN
const locales = fs.readdirSync(localesDir).filter(f => {
  const stat = fs.statSync(path.join(localesDir, f));
  return stat.isDirectory() && f !== 'en';
});

console.log('=== ADDING MISSING i18n KEYS ===\n');

let totalAdded = 0;

for (const locale of locales) {
  const localePath = path.join(localesDir, locale, 'messages.json');

  try {
    const localeData = require(localePath);
    const localeKeys = Object.keys(localeData);
    const missingKeys = enKeys.filter(k => !localeKeys.includes(k));

    if (missingKeys.length === 0) {
      console.log(`${locale}: Already complete (${localeKeys.length} keys)`);
      continue;
    }

    // Add missing keys with English values as fallback
    for (const key of missingKeys) {
      localeData[key] = {
        message: enData[key].message,
        description: enData[key].description || `[EN fallback] ${enData[key].message}`
      };
    }

    // Write back to file with proper formatting
    fs.writeFileSync(localePath, JSON.stringify(localeData, null, 2) + '\n');

    console.log(`${locale}: Added ${missingKeys.length} keys (now ${Object.keys(localeData).length} total)`);
    totalAdded += missingKeys.length;

  } catch (e) {
    console.error(`${locale}: ERROR - ${e.message}`);
  }
}

console.log(`\n=== COMPLETE ===`);
console.log(`Total keys added across all locales: ${totalAdded}`);
