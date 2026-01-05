/**
 * LinkShield i18n Validation Script
 * Validates that all reason keys used in source code exist in all locale files
 *
 * Usage: node scripts/validate-i18n.js
 */

const fs = require('fs');
const path = require('path');

// Configuration
const SOURCE_FILES = ['content.js', 'background.js', 'popup.js', 'alert.js', 'caution.js', 'dynamic.js'];
const LOCALES_DIR = '_locales';
const BASE_LOCALE = 'en';

// Colors for console output
const colors = {
  reset: '\x1b[0m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m'
};

/**
 * Extract all i18n keys used in source files
 */
function extractKeysFromSource(rootDir) {
  const keys = new Set();
  const keyLocations = new Map(); // key -> [{file, line}]

  // Patterns to match i18n key usage
  const patterns = [
    // Direct reason keys in objects
    /reason:\s*['"]([a-zA-Z_][a-zA-Z0-9_]*)['"]/g,
    // Reasons array
    /reasons:\s*\[['"]([a-zA-Z_][a-zA-Z0-9_]*)['"]/g,
    // reasons.push/add
    /reasons\.(push|add)\(['"]([a-zA-Z_][a-zA-Z0-9_]*)['"]\)/g,
    // chrome.i18n.getMessage
    /chrome\.i18n\.getMessage\(['"]([a-zA-Z_][a-zA-Z0-9_]*)['"]/g,
    // getMessage helper
    /getMessage\(['"]([a-zA-Z_][a-zA-Z0-9_]*)['"]/g,
    // getTranslatedMessage
    /getTranslatedMessage\(['"]([a-zA-Z_][a-zA-Z0-9_]*)['"]/g,
    // data-i18n attributes
    /data-i18n=['"]([a-zA-Z_][a-zA-Z0-9_]*)['"]/g,
    // messageKey in check objects
    /messageKey:\s*['"]([a-zA-Z_][a-zA-Z0-9_]*)['"]/g,
  ];

  for (const file of SOURCE_FILES) {
    const filePath = path.join(rootDir, file);
    if (!fs.existsSync(filePath)) {
      console.log(`${colors.yellow}Warning: ${file} not found${colors.reset}`);
      continue;
    }

    const content = fs.readFileSync(filePath, 'utf8');
    const lines = content.split('\n');

    lines.forEach((line, lineNum) => {
      for (const pattern of patterns) {
        // Reset regex lastIndex
        pattern.lastIndex = 0;
        let match;
        while ((match = pattern.exec(line)) !== null) {
          // Get the captured key (may be in group 1 or 2 depending on pattern)
          const key = match[2] || match[1];
          if (key && !key.startsWith('$') && key.length > 1) {
            keys.add(key);

            if (!keyLocations.has(key)) {
              keyLocations.set(key, []);
            }
            keyLocations.get(key).push({ file, line: lineNum + 1 });
          }
        }
      }
    });
  }

  // Also scan HTML files for data-i18n
  const htmlFiles = ['popup.html', 'alert.html', 'caution.html', 'dynamic.html'];
  for (const file of htmlFiles) {
    const filePath = path.join(rootDir, file);
    if (!fs.existsSync(filePath)) continue;

    const content = fs.readFileSync(filePath, 'utf8');
    const dataI18nPattern = /data-i18n=['"]([a-zA-Z_][a-zA-Z0-9_]*)['"]/g;
    let match;
    while ((match = dataI18nPattern.exec(content)) !== null) {
      keys.add(match[1]);
      if (!keyLocations.has(match[1])) {
        keyLocations.set(match[1], []);
      }
      keyLocations.get(match[1]).push({ file, line: 0 });
    }
  }

  return { keys, keyLocations };
}

/**
 * Get all available locales
 */
function getLocales(rootDir) {
  const localesPath = path.join(rootDir, LOCALES_DIR);
  if (!fs.existsSync(localesPath)) {
    throw new Error(`Locales directory not found: ${localesPath}`);
  }

  return fs.readdirSync(localesPath).filter(dir => {
    const messagesPath = path.join(localesPath, dir, 'messages.json');
    return fs.existsSync(messagesPath);
  });
}

/**
 * Load messages for a locale
 */
function loadMessages(rootDir, locale) {
  const messagesPath = path.join(rootDir, LOCALES_DIR, locale, 'messages.json');
  const content = fs.readFileSync(messagesPath, 'utf8');
  return JSON.parse(content);
}

/**
 * Main validation function
 */
function validate(rootDir) {
  console.log(`\n${colors.cyan}═══════════════════════════════════════════════════════════${colors.reset}`);
  console.log(`${colors.cyan}  LinkShield i18n Validation Report${colors.reset}`);
  console.log(`${colors.cyan}═══════════════════════════════════════════════════════════${colors.reset}\n`);

  // Extract keys from source
  console.log(`${colors.blue}Scanning source files...${colors.reset}`);
  const { keys: usedKeys, keyLocations } = extractKeysFromSource(rootDir);
  console.log(`Found ${usedKeys.size} unique i18n keys in source code\n`);

  // Get all locales
  const locales = getLocales(rootDir);
  console.log(`${colors.blue}Found ${locales.length} locales:${colors.reset} ${locales.join(', ')}\n`);

  // Load base locale (English) for reference
  const baseMessages = loadMessages(rootDir, BASE_LOCALE);
  const baseKeys = new Set(Object.keys(baseMessages));

  // Track issues
  const missingInBase = [];
  const missingInLocales = new Map(); // locale -> [keys]
  const unusedKeys = [];

  // Check 1: Keys used in code but missing in base locale
  console.log(`${colors.blue}Checking for missing keys in base locale (${BASE_LOCALE})...${colors.reset}`);
  for (const key of usedKeys) {
    if (!baseKeys.has(key)) {
      missingInBase.push(key);
    }
  }

  if (missingInBase.length > 0) {
    console.log(`${colors.red}✗ ${missingInBase.length} keys missing in ${BASE_LOCALE}:${colors.reset}`);
    for (const key of missingInBase) {
      const locations = keyLocations.get(key) || [];
      const locStr = locations.map(l => `${l.file}:${l.line}`).join(', ');
      console.log(`  - ${key} (used in: ${locStr})`);
    }
  } else {
    console.log(`${colors.green}✓ All used keys exist in ${BASE_LOCALE}${colors.reset}`);
  }
  console.log();

  // Check 2: Keys missing in other locales (compared to base)
  console.log(`${colors.blue}Checking for missing keys in other locales...${colors.reset}`);
  for (const locale of locales) {
    if (locale === BASE_LOCALE) continue;

    const messages = loadMessages(rootDir, locale);
    const localeKeys = new Set(Object.keys(messages));
    const missing = [];

    for (const key of baseKeys) {
      if (!localeKeys.has(key)) {
        missing.push(key);
      }
    }

    if (missing.length > 0) {
      missingInLocales.set(locale, missing);
      console.log(`${colors.yellow}⚠ ${locale}: ${missing.length} keys missing${colors.reset}`);
    } else {
      console.log(`${colors.green}✓ ${locale}: All keys present${colors.reset}`);
    }
  }
  console.log();

  // Check 3: Unused keys in base locale
  console.log(`${colors.blue}Checking for unused keys in ${BASE_LOCALE}...${colors.reset}`);
  for (const key of baseKeys) {
    if (!usedKeys.has(key)) {
      // Skip known meta keys
      if (!['extName', 'extDescription'].includes(key)) {
        unusedKeys.push(key);
      }
    }
  }

  if (unusedKeys.length > 0) {
    console.log(`${colors.yellow}⚠ ${unusedKeys.length} potentially unused keys (may be dynamically generated):${colors.reset}`);
    // Only show first 20
    const showKeys = unusedKeys.slice(0, 20);
    for (const key of showKeys) {
      console.log(`  - ${key}`);
    }
    if (unusedKeys.length > 20) {
      console.log(`  ... and ${unusedKeys.length - 20} more`);
    }
  } else {
    console.log(`${colors.green}✓ No obviously unused keys found${colors.reset}`);
  }
  console.log();

  // Summary
  console.log(`${colors.cyan}═══════════════════════════════════════════════════════════${colors.reset}`);
  console.log(`${colors.cyan}  Summary${colors.reset}`);
  console.log(`${colors.cyan}═══════════════════════════════════════════════════════════${colors.reset}`);

  const hasErrors = missingInBase.length > 0;
  const hasWarnings = missingInLocales.size > 0 || unusedKeys.length > 0;

  console.log(`Total keys in source: ${usedKeys.size}`);
  console.log(`Total keys in ${BASE_LOCALE}: ${baseKeys.size}`);
  console.log(`Missing in ${BASE_LOCALE}: ${colors.red}${missingInBase.length}${colors.reset}`);
  console.log(`Locales with missing keys: ${colors.yellow}${missingInLocales.size}${colors.reset}`);
  console.log(`Potentially unused keys: ${colors.yellow}${unusedKeys.length}${colors.reset}`);
  console.log();

  if (hasErrors) {
    console.log(`${colors.red}✗ VALIDATION FAILED - Missing keys must be added${colors.reset}`);
    return 1;
  } else if (hasWarnings) {
    console.log(`${colors.yellow}⚠ VALIDATION PASSED WITH WARNINGS${colors.reset}`);
    return 0;
  } else {
    console.log(`${colors.green}✓ VALIDATION PASSED${colors.reset}`);
    return 0;
  }
}

// Run validation
const rootDir = path.resolve(__dirname, '..');
try {
  const exitCode = validate(rootDir);
  process.exit(exitCode);
} catch (error) {
  console.error(`${colors.red}Error: ${error.message}${colors.reset}`);
  process.exit(1);
}
