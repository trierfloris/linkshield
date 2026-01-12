/**
 * LinkShield Comprehensive i18n Validation Script
 *
 * Validates that the extension is fully language-agnostic:
 * - All i18n keys used in source code exist in all locale files
 * - Detects hardcoded fallback strings that should be removed
 * - Validates __MSG_key__ patterns in manifest.json
 *
 * Usage: node scripts/validate-i18n.js
 */

const fs = require('fs');
const path = require('path');

// Configuration
const SOURCE_FILES = ['content.js', 'background.js', 'popup.js', 'alert.js', 'caution.js', 'dynamic.js', 'config.js'];
const LOCALES_DIR = '_locales';
const BASE_LOCALE = 'en';

// Colors for console output
const colors = {
  reset: '\x1b[0m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
  dim: '\x1b[2m',
  magenta: '\x1b[35m'
};

/**
 * Extract hardcoded fallback strings from source files
 * These are patterns like: chrome.i18n.getMessage('key') || 'Fallback text'
 */
function extractFallbackStrings(rootDir) {
  const fallbacks = []; // [{file, line, key, fallbackText}]

  // Pattern to match getMessage with fallback
  const fallbackPattern = /chrome\.i18n\.getMessage\s*\(\s*['"]([^'"]+)['"]\s*(?:,\s*[^)]+)?\s*\)\s*\|\|\s*['"]([^'"]+)['"]/g;
  const msgHelperPattern = /\bmsg\s*\(\s*['"]([^'"]+)['"]\s*\)\s*\|\|\s*['"]([^'"]+)['"]/g;

  for (const file of SOURCE_FILES) {
    const filePath = path.join(rootDir, file);
    if (!fs.existsSync(filePath)) continue;

    const content = fs.readFileSync(filePath, 'utf8');
    const lines = content.split('\n');

    lines.forEach((line, lineNum) => {
      // Skip comment lines
      if (line.trim().startsWith('//') || line.trim().startsWith('*')) return;

      for (const pattern of [fallbackPattern, msgHelperPattern]) {
        pattern.lastIndex = 0;
        let match;
        while ((match = pattern.exec(line)) !== null) {
          fallbacks.push({
            file,
            line: lineNum + 1,
            key: match[1],
            fallbackText: match[2]
          });
        }
      }
    });
  }

  return fallbacks;
}

/**
 * Extract __MSG_key__ patterns from manifest.json
 */
function extractManifestKeys(rootDir) {
  const keys = new Set();
  const manifestPath = path.join(rootDir, 'manifest.json');

  if (!fs.existsSync(manifestPath)) return keys;

  const content = fs.readFileSync(manifestPath, 'utf8');
  const pattern = /__MSG_([a-zA-Z_][a-zA-Z0-9_]*)__/g;

  let match;
  while ((match = pattern.exec(content)) !== null) {
    keys.add(match[1]);
  }

  return keys;
}

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
    // getMessage helper (msg function in popup.js)
    /\bmsg\s*\(['"]([a-zA-Z_][a-zA-Z0-9_]*)['"]/g,
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
  console.log(`\n${colors.cyan}═══════════════════════════════════════════════════════════════${colors.reset}`);
  console.log(`${colors.cyan}  LinkShield Comprehensive i18n Validation Report${colors.reset}`);
  console.log(`${colors.cyan}═══════════════════════════════════════════════════════════════${colors.reset}\n`);

  // Extract keys from source
  console.log(`${colors.blue}Scanning source files...${colors.reset}`);
  const { keys: usedKeys, keyLocations } = extractKeysFromSource(rootDir);
  console.log(`Found ${colors.magenta}${usedKeys.size}${colors.reset} unique i18n keys in source code`);

  // Extract manifest keys
  const manifestKeys = extractManifestKeys(rootDir);
  console.log(`Found ${colors.magenta}${manifestKeys.size}${colors.reset} keys in manifest.json`);

  // Merge all used keys
  for (const key of manifestKeys) {
    usedKeys.add(key);
  }
  console.log(`Total unique keys: ${colors.magenta}${usedKeys.size}${colors.reset}\n`);

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
  const fallbackStrings = extractFallbackStrings(rootDir);

  // ═══════════════════════════════════════════════════════════════
  // Check 1: Keys used in code but missing in base locale
  // ═══════════════════════════════════════════════════════════════
  console.log(`${colors.cyan}─── Check 1: Keys missing in ${BASE_LOCALE} ───${colors.reset}\n`);
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
      console.log(`  ${colors.red}•${colors.reset} ${key}${locStr ? ` ${colors.dim}(${locStr})${colors.reset}` : ''}`);
    }
  } else {
    console.log(`${colors.green}✓ All used keys exist in ${BASE_LOCALE}${colors.reset}`);
  }
  console.log();

  // ═══════════════════════════════════════════════════════════════
  // Check 2: Keys missing in other locales
  // ═══════════════════════════════════════════════════════════════
  console.log(`${colors.cyan}─── Check 2: Keys missing in other locales ───${colors.reset}\n`);
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
      console.log(`${colors.green}✓ ${locale}: Complete${colors.reset}`);
    }
  }
  console.log();

  // ═══════════════════════════════════════════════════════════════
  // Check 3: Hardcoded fallback strings (language-agnostic violation)
  // ═══════════════════════════════════════════════════════════════
  console.log(`${colors.cyan}─── Check 3: Hardcoded fallback strings ───${colors.reset}\n`);

  // Filter fallbacks where key exists in base (these are unnecessary)
  const unnecessaryFallbacks = fallbackStrings.filter(f => baseKeys.has(f.key));
  // Filter fallbacks where key is missing (these are required but key should be added)
  const requiredFallbacks = fallbackStrings.filter(f => !baseKeys.has(f.key));

  if (unnecessaryFallbacks.length > 0) {
    console.log(`${colors.yellow}⚠ ${unnecessaryFallbacks.length} unnecessary fallback strings found:${colors.reset}`);
    console.log(`${colors.dim}  (Key exists in ${BASE_LOCALE}, fallback can be removed for full i18n compliance)${colors.reset}\n`);

    // Group by file
    const byFile = new Map();
    for (const item of unnecessaryFallbacks) {
      if (!byFile.has(item.file)) byFile.set(item.file, []);
      byFile.get(item.file).push(item);
    }

    for (const [file, items] of byFile) {
      console.log(`  ${colors.blue}${file}:${colors.reset}`);
      for (const item of items.slice(0, 5)) {
        const preview = item.fallbackText.length > 35 ? item.fallbackText.substring(0, 35) + '...' : item.fallbackText;
        console.log(`    ${colors.yellow}Line ${item.line}:${colors.reset} ${item.key} ${colors.dim}|| "${preview}"${colors.reset}`);
      }
      if (items.length > 5) {
        console.log(`    ${colors.dim}... and ${items.length - 5} more${colors.reset}`);
      }
    }
  } else {
    console.log(`${colors.green}✓ No unnecessary fallback strings found${colors.reset}`);
  }
  console.log();

  // ═══════════════════════════════════════════════════════════════
  // Check 4: Unused keys in base locale
  // ═══════════════════════════════════════════════════════════════
  console.log(`${colors.cyan}─── Check 4: Potentially unused keys ───${colors.reset}\n`);
  for (const key of baseKeys) {
    if (!usedKeys.has(key)) {
      // Skip known meta keys
      if (!['extName', 'extDescription'].includes(key)) {
        unusedKeys.push(key);
      }
    }
  }

  if (unusedKeys.length > 0) {
    console.log(`${colors.yellow}⚠ ${unusedKeys.length} potentially unused keys:${colors.reset}`);
    console.log(`${colors.dim}  (May be dynamically generated or can be removed)${colors.reset}\n`);
    const showKeys = unusedKeys.slice(0, 20);
    for (const key of showKeys) {
      console.log(`  ${colors.dim}• ${key}${colors.reset}`);
    }
    if (unusedKeys.length > 20) {
      console.log(`  ${colors.dim}... and ${unusedKeys.length - 20} more${colors.reset}`);
    }
  } else {
    console.log(`${colors.green}✓ No obviously unused keys found${colors.reset}`);
  }
  console.log();

  // ═══════════════════════════════════════════════════════════════
  // Summary
  // ═══════════════════════════════════════════════════════════════
  console.log(`${colors.cyan}═══════════════════════════════════════════════════════════════${colors.reset}`);
  console.log(`${colors.cyan}  Summary${colors.reset}`);
  console.log(`${colors.cyan}═══════════════════════════════════════════════════════════════${colors.reset}\n`);

  const hasErrors = missingInBase.length > 0;
  const hasWarnings = missingInLocales.size > 0 || unusedKeys.length > 0 || unnecessaryFallbacks.length > 0;
  const isFullyAgnostic = !hasErrors && unnecessaryFallbacks.length === 0;

  console.log(`Total keys in source:           ${colors.magenta}${usedKeys.size}${colors.reset}`);
  console.log(`Total keys in ${BASE_LOCALE}:              ${colors.magenta}${baseKeys.size}${colors.reset}`);
  console.log(`Missing in ${BASE_LOCALE}:                ${missingInBase.length > 0 ? colors.red : colors.green}${missingInBase.length}${colors.reset}`);
  console.log(`Locales with missing keys:      ${missingInLocales.size > 0 ? colors.yellow : colors.green}${missingInLocales.size}${colors.reset}`);
  console.log(`Unnecessary fallback strings:   ${unnecessaryFallbacks.length > 0 ? colors.yellow : colors.green}${unnecessaryFallbacks.length}${colors.reset}`);
  console.log(`Potentially unused keys:        ${unusedKeys.length > 0 ? colors.yellow : colors.green}${unusedKeys.length}${colors.reset}`);
  console.log();

  // Language-agnostic status
  console.log(`${colors.cyan}Language-Agnostic Status:${colors.reset}`);
  if (isFullyAgnostic && missingInLocales.size === 0) {
    console.log(`${colors.green}✓ Extension is FULLY language-agnostic${colors.reset}`);
    console.log(`${colors.dim}  All text comes from _locales, no hardcoded strings${colors.reset}`);
  } else if (isFullyAgnostic) {
    console.log(`${colors.green}✓ Code is language-agnostic (no hardcoded strings)${colors.reset}`);
    console.log(`${colors.yellow}⚠ Some locales have incomplete translations${colors.reset}`);
  } else {
    console.log(`${colors.yellow}⚠ NOT fully language-agnostic${colors.reset}`);
    if (unnecessaryFallbacks.length > 0) {
      console.log(`${colors.dim}  Remove ${unnecessaryFallbacks.length} fallback strings for full compliance${colors.reset}`);
    }
  }
  console.log();

  // Final verdict
  if (hasErrors) {
    console.log(`${colors.red}✗ VALIDATION FAILED - ${missingInBase.length} keys missing in ${BASE_LOCALE}${colors.reset}`);
    return 1;
  } else if (unnecessaryFallbacks.length > 0) {
    console.log(`${colors.yellow}⚠ VALIDATION PASSED WITH WARNINGS - Remove fallback strings for full i18n compliance${colors.reset}`);
    return 0;
  } else if (hasWarnings) {
    console.log(`${colors.yellow}⚠ VALIDATION PASSED WITH WARNINGS${colors.reset}`);
    return 0;
  } else {
    console.log(`${colors.green}✓ VALIDATION PASSED - Extension is fully i18n compliant${colors.reset}`);
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
