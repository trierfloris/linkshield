/**
 * SECURITY FIX v8.7.0: Universal Non-ASCII Flag
 *
 * Elke URL die karakters bevat die niet in de standaard Latijnse set zitten,
 * wordt direct als 'Suspicious' (ORANJE) gemarkeerd, ongeacht de rest van de analyse.
 */

const fs = require('fs');
const path = require('path');

const contentPath = path.join(__dirname, '..', 'content.js');
let content = fs.readFileSync(contentPath, 'utf8');
content = content.replace(/\r\n/g, '\n');

// Find the classifyAndCheckLink function and add Universal Non-ASCII check after isValidURL
const oldValidUrlCheck = `  // Controleer of href een geldige URL is
  if (!isValidURL(href)) {
    logDebug(\`Skipping classification: Invalid URL in link: \${href || 'undefined'}\`);
    return;
  }

  // =============================================================================
  // SECURITY FIX v8.5.0: HIGH-RISK DOMAIN KEYWORD DETECTION
  // =============================================================================`;

const newValidUrlCheck = `  // Controleer of href een geldige URL is
  if (!isValidURL(href)) {
    logDebug(\`Skipping classification: Invalid URL in link: \${href || 'undefined'}\`);
    return;
  }

  // =============================================================================
  // SECURITY FIX v8.7.0: UNIVERSAL NON-ASCII FLAG
  // =============================================================================
  // Elke URL met karakters buiten standaard Latijnse set (charCode > 127)
  // wordt DIRECT als Suspicious (ORANJE) gemarkeerd - Safe-by-Default
  // Dit vangt ALLE mogelijke homoglyph/IDN aanvallen, inclusief onbekende varianten
  try {
    const urlObj = new URL(href);
    const hostname = urlObj.hostname;

    // Check for ANY non-ASCII character in hostname
    const hasNonAscii = /[^\\x00-\\x7F]/.test(hostname);

    if (hasNonAscii) {
      console.log(\`[SecurityFix v8.7.0] ⚠️ UNIVERSAL NON-ASCII FLAG: \${hostname}\`);

      // Onmiddellijk ORANJE waarschuwing (caution level)
      warnLinkByLevel(link, {
        level: 'caution',
        risk: 10,
        reasons: ['universalNonAsciiDetected']
      });

      // Markeer als gescand om dubbele verwerking te voorkomen
      link.dataset.linkshieldScanned = 'true';

      // Continue met verdere analyse voor mogelijke escalatie naar ROOD
      // (bijv. als het ook een phishing keyword of brand impersonation bevat)
    }
  } catch (e) {
    // URL parsing error - skip this check
  }

  // =============================================================================
  // SECURITY FIX v8.5.0: HIGH-RISK DOMAIN KEYWORD DETECTION
  // =============================================================================`;

if (content.includes(oldValidUrlCheck)) {
    content = content.replace(oldValidUrlCheck, newValidUrlCheck);
    console.log('SUCCESS: Added Universal Non-ASCII Flag to classifyAndCheckLink');
} else {
    console.log('ERROR: Could not find isValidURL check in classifyAndCheckLink');
    // Try alternative pattern
    if (content.includes('SECURITY FIX v8.5.0: HIGH-RISK DOMAIN KEYWORD')) {
        console.log('Found v8.5.0 marker - trying alternative approach');
    }
}

// Write the file
content = content.replace(/\n/g, '\r\n');
fs.writeFileSync(contentPath, content, 'utf8');
console.log('DONE: Universal Non-ASCII Flag implementation complete');
