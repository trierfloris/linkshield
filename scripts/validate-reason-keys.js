/**
 * LinkShield i18n Reason Keys Validation Script
 *
 * Automatically extracts all reason keys used in source files and validates
 * that they exist in all locale files.
 *
 * Usage: node scripts/validate-reason-keys.js
 */

const fs = require('fs');
const path = require('path');

// Configuration
const SOURCE_FILES = ['content.js', 'background.js', 'dynamic.js', 'config.js'];
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
  magenta: '\x1b[35m'
};

/**
 * Extract all reason keys from source files
 */
function extractReasonKeys(rootDir) {
  const reasonKeys = new Set();
  const keyLocations = new Map(); // key -> [{file, line, context}]

  // Patterns to match reason key usage
  const patterns = [
    // reasons.push('key')
    { regex: /reasons\.push\(['"]([a-zA-Z_][a-zA-Z0-9_]*)['"]\)/g, group: 1 },
    // result.reasons.push('key')
    { regex: /\.reasons\.push\(['"]([a-zA-Z_][a-zA-Z0-9_]*)['"]\)/g, group: 1 },
    // results.reasons.push('key')
    { regex: /results\.reasons\.push\(['"]([a-zA-Z_][a-zA-Z0-9_]*)['"]\)/g, group: 1 },
    // reason: 'key' in objects (for NRD, URL checks, etc.)
    { regex: /reason:\s*['"]([a-zA-Z_][a-zA-Z0-9_]*)['"]/g, group: 1 },
    // reasons: ['key'] or reasons: ["key", ...]
    { regex: /reasons:\s*\[['"]([a-zA-Z_][a-zA-Z0-9_]*)['"]/g, group: 1 },
    // reasons: [..., 'key']
    { regex: /reasons:\s*\[[^\]]*,\s*['"]([a-zA-Z_][a-zA-Z0-9_]*)['"][^\]]*\]/g, group: 1 },
    // messageKey: 'key'
    { regex: /messageKey:\s*['"]([a-zA-Z_][a-zA-Z0-9_]*)['"]/g, group: 1 },
  ];

  // Known non-reason keys to exclude (API responses, internal reasons)
  const excludeKeys = new Set([
    'trial_expired',
    'not_eligible',
    'No valid license to revalidate',
    'Network error',
    'Storage error'
  ]);

  for (const file of SOURCE_FILES) {
    const filePath = path.join(rootDir, file);
    if (!fs.existsSync(filePath)) {
      console.log(`${colors.yellow}Warning: ${file} not found${colors.reset}`);
      continue;
    }

    const content = fs.readFileSync(filePath, 'utf8');
    const lines = content.split('\n');

    lines.forEach((line, lineNum) => {
      for (const { regex, group } of patterns) {
        regex.lastIndex = 0;
        let match;
        while ((match = regex.exec(line)) !== null) {
          const key = match[group];

          // Filter out non-translation keys
          if (key &&
              !key.startsWith('$') &&
              key.length > 2 &&
              !excludeKeys.has(key) &&
              !key.includes(' ') &&
              // Only include keys that look like reason keys
              (key.startsWith('reason') ||
               key.startsWith('nrd') ||
               key.startsWith('form') ||
               key.startsWith('shadow') ||
               key.startsWith('suspicious') ||
               key.startsWith('invalid') ||
               key.startsWith('hidden') ||
               key.startsWith('mixed') ||
               key.startsWith('url') ||
               key.startsWith('typosquatting') ||
               key.startsWith('homoglyph') ||
               key.startsWith('crypto') ||
               key.startsWith('trust') ||
               key.startsWith('safe') ||
               key.startsWith('allow') ||
               key.startsWith('no') ||
               key.startsWith('ip') ||
               key.startsWith('table') ||
               key.startsWith('young') ||
               key.startsWith('download') ||
               key.startsWith('free') ||
               key.startsWith('encoded') ||
               key.startsWith('meta') ||
               key.startsWith('external') ||
               key.startsWith('unusual') ||
               key.startsWith('javascript') ||
               key.startsWith('base64') ||
               key.startsWith('similar') ||
               key.startsWith('insecure') ||
               key.startsWith('login') ||
               key.startsWith('malware') ||
               key.startsWith('digit') ||
               key.startsWith('urgency') ||
               key.startsWith('punycode') ||
               key.startsWith('brand') ||
               key.startsWith('at') ||
               key.startsWith('double') ||
               key.startsWith('full') ||
               key.startsWith('null') ||
               key.startsWith('error') ||
               key.startsWith('file') ||
               key.startsWith('short') ||
               key.startsWith('too')
              )) {
            reasonKeys.add(key);

            if (!keyLocations.has(key)) {
              keyLocations.set(key, []);
            }
            // Get context (trimmed line)
            const context = line.trim().substring(0, 80);
            keyLocations.get(key).push({
              file,
              line: lineNum + 1,
              context: context.length < line.trim().length ? context + '...' : context
            });
          }
        }
      }
    });
  }

  return { reasonKeys, keyLocations };
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
  console.log(`${colors.cyan}  LinkShield Reason Keys Validation Report${colors.reset}`);
  console.log(`${colors.cyan}═══════════════════════════════════════════════════════════${colors.reset}\n`);

  // Extract reason keys from source
  console.log(`${colors.blue}Scanning source files for reason keys...${colors.reset}`);
  const { reasonKeys, keyLocations } = extractReasonKeys(rootDir);
  console.log(`Found ${colors.magenta}${reasonKeys.size}${colors.reset} unique reason keys in source code\n`);

  // Get all locales
  const locales = getLocales(rootDir);
  console.log(`${colors.blue}Found ${locales.length} locales:${colors.reset} ${locales.join(', ')}\n`);

  // Load base locale (English)
  const baseMessages = loadMessages(rootDir, BASE_LOCALE);

  // Track issues
  const missingInBase = [];
  const missingInLocales = new Map(); // locale -> [keys]
  let totalMissing = 0;

  // Check: Reason keys missing in base locale
  console.log(`${colors.blue}Checking reason keys in ${BASE_LOCALE} locale...${colors.reset}\n`);

  for (const key of reasonKeys) {
    if (!baseMessages[key]) {
      missingInBase.push(key);
    }
  }

  if (missingInBase.length > 0) {
    console.log(`${colors.red}✗ ${missingInBase.length} reason keys missing in ${BASE_LOCALE}:${colors.reset}\n`);
    for (const key of missingInBase) {
      const locations = keyLocations.get(key) || [];
      console.log(`  ${colors.red}• ${key}${colors.reset}`);
      for (const loc of locations.slice(0, 2)) {
        console.log(`    ${colors.yellow}└ ${loc.file}:${loc.line}${colors.reset} - ${loc.context}`);
      }
      if (locations.length > 2) {
        console.log(`    ${colors.yellow}└ ... and ${locations.length - 2} more locations${colors.reset}`);
      }
    }
    console.log();
    totalMissing += missingInBase.length;
  } else {
    console.log(`${colors.green}✓ All ${reasonKeys.size} reason keys exist in ${BASE_LOCALE}${colors.reset}\n`);
  }

  // Check: Reason keys missing in other locales
  console.log(`${colors.blue}Checking reason keys in other locales...${colors.reset}\n`);

  for (const locale of locales) {
    if (locale === BASE_LOCALE) continue;

    const messages = loadMessages(rootDir, locale);
    const missing = [];

    for (const key of reasonKeys) {
      if (!messages[key] && baseMessages[key]) {
        missing.push(key);
      }
    }

    if (missing.length > 0) {
      missingInLocales.set(locale, missing);
      console.log(`${colors.yellow}⚠ ${locale}: ${missing.length} reason keys missing${colors.reset}`);
      if (missing.length <= 5) {
        console.log(`  ${missing.join(', ')}`);
      }
    } else {
      console.log(`${colors.green}✓ ${locale}: All reason keys present${colors.reset}`);
    }
  }
  console.log();

  // List all found reason keys (for reference)
  console.log(`${colors.cyan}═══════════════════════════════════════════════════════════${colors.reset}`);
  console.log(`${colors.cyan}  All Extracted Reason Keys (${reasonKeys.size})${colors.reset}`);
  console.log(`${colors.cyan}═══════════════════════════════════════════════════════════${colors.reset}`);

  const sortedKeys = [...reasonKeys].sort();
  const columns = 3;
  const columnWidth = 35;

  for (let i = 0; i < sortedKeys.length; i += columns) {
    let row = '';
    for (let j = 0; j < columns && i + j < sortedKeys.length; j++) {
      const key = sortedKeys[i + j];
      const inBase = baseMessages[key] ? colors.green + '✓' : colors.red + '✗';
      row += `${inBase} ${key.padEnd(columnWidth - 2)}${colors.reset}`;
    }
    console.log(row);
  }
  console.log();

  // Summary
  console.log(`${colors.cyan}═══════════════════════════════════════════════════════════${colors.reset}`);
  console.log(`${colors.cyan}  Summary${colors.reset}`);
  console.log(`${colors.cyan}═══════════════════════════════════════════════════════════${colors.reset}`);

  console.log(`Total reason keys found: ${reasonKeys.size}`);
  console.log(`Missing in ${BASE_LOCALE}: ${colors.red}${missingInBase.length}${colors.reset}`);
  console.log(`Locales with missing keys: ${colors.yellow}${missingInLocales.size}${colors.reset}`);
  console.log();

  if (missingInBase.length > 0) {
    console.log(`${colors.red}✗ VALIDATION FAILED - ${missingInBase.length} reason keys must be added to ${BASE_LOCALE}${colors.reset}`);

    // Generate stub entries for missing keys
    console.log(`\n${colors.cyan}Suggested entries for ${BASE_LOCALE}/messages.json:${colors.reset}\n`);
    for (const key of missingInBase) {
      console.log(`  "${key}": {`);
      console.log(`    "message": "TODO: Add translation for ${key}"`);
      console.log(`  },`);
    }

    return 1;
  } else if (missingInLocales.size > 0) {
    console.log(`${colors.yellow}⚠ VALIDATION PASSED WITH WARNINGS - Some locales have missing translations${colors.reset}`);
    return 0;
  } else {
    console.log(`${colors.green}✓ VALIDATION PASSED - All reason keys are properly translated${colors.reset}`);
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
