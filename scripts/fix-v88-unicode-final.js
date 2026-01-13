/**
 * SECURITY FIX v8.8.2: Final Unicode detection fix
 *
 * Issue: new URL() converts IDN to punycode, losing the original non-ASCII chars
 * Solution: Check href BEFORE URL parsing, AND use the link text for display check
 */

const fs = require('fs');
const path = require('path');

const contentPath = path.join(__dirname, '..', 'content.js');
let content = fs.readFileSync(contentPath, 'utf8');
content = content.replace(/\r\n/g, '\n');

// Find the existing Unicode check and replace it with an improved version
const oldUnicodeCheck = `  // =============================================================================
  // SECURITY FIX v8.8.0: ENHANCED UNIVERSAL NON-ASCII FLAG
  // =============================================================================
  // Comprehensive Unicode detection for ALL homoglyph/IDN attacks
  // Targets: 80%+ detection rate in security audits
  try {
    const urlObj = new URL(href);
    const hostname = urlObj.hostname;
    const normalizedHost = hostname.normalize('NFC'); // Unicode normalization

    let unicodeReasons = [];
    let unicodeRisk = 0;

    // 1. Universal Non-ASCII check (charCode > 127)
    if (/[^\\x00-\\x7F]/.test(normalizedHost)) {
      unicodeReasons.push('universalNonAsciiDetected');
      unicodeRisk += 8;
    }

    // 2. Mathematical Alphanumeric Symbols (U+1D400-U+1D7FF) - bold/italic lookalikes
    // These include 𝐚𝐛𝐜 (bold), 𝑎𝑏𝑐 (italic), 𝒂𝒃𝒄 (bold italic), etc.
    if (/[\\u{1D400}-\\u{1D7FF}]/u.test(normalizedHost)) {
      unicodeReasons.push('mathematicalAlphanumericsDetected');
      unicodeRisk += 10;
    }

    // 3. Fullwidth Latin characters (U+FF00-U+FFEF) - ａｂｃ
    if (/[\\uFF00-\\uFFEF]/.test(normalizedHost)) {
      unicodeReasons.push('fullwidthCharactersDetected');
      unicodeRisk += 10;
    }

    // 4. Greek letters commonly used as lookalikes (α, ο, ρ, etc.)
    // Greek: U+0370-U+03FF (αβγδ...)
    if (/[\\u0370-\\u03FF]/.test(normalizedHost)) {
      unicodeReasons.push('greekLettersDetected');
      unicodeRisk += 10;
    }

    // 5. Cyrillic characters (U+0400-U+04FF) - already detected but add specific reason
    if (/[\\u0400-\\u04FF]/.test(normalizedHost)) {
      unicodeReasons.push('cyrillicCharactersDetected');
      unicodeRisk += 10;
    }

    // 6. Cherokee characters (U+13A0-U+13FF) - ꮓ looks like z
    if (/[\\u13A0-\\u13FF]/.test(normalizedHost)) {
      unicodeReasons.push('cherokeeCharactersDetected');
      unicodeRisk += 10;
    }

    // 7. Script/Letterlike Symbols (U+2100-U+214F) - ℊ looks like g
    if (/[\\u2100-\\u214F]/.test(normalizedHost)) {
      unicodeReasons.push('scriptSymbolsDetected');
      unicodeRisk += 10;
    }

    // 8. Enclosed Alphanumerics (U+2460-U+24FF)
    if (/[\\u2460-\\u24FF]/.test(normalizedHost)) {
      unicodeReasons.push('enclosedAlphanumericsDetected');
      unicodeRisk += 8;
    }

    // 9. Superscripts/Subscripts (U+2070-U+209F)
    if (/[\\u2070-\\u209F]/.test(normalizedHost)) {
      unicodeReasons.push('superscriptSubscriptDetected');
      unicodeRisk += 8;
    }

    // Apply warning if any Unicode issues detected
    if (unicodeReasons.length > 0) {
      console.log(\`[SecurityFix v8.8.0] ⚠️ UNICODE DETECTED: \${hostname} → \${unicodeReasons.join(', ')}\`);

      // Determine level based on risk (>=10 = alert, otherwise caution)
      const level = unicodeRisk >= 15 ? 'alert' : 'caution';

      warnLinkByLevel(link, {
        level: level,
        risk: unicodeRisk,
        reasons: unicodeReasons
      });

      // Mark as scanned
      link.dataset.linkshieldScanned = 'true';
      link.dataset.linkshieldUnicodeRisk = unicodeRisk.toString();
    }
  } catch (e) {
    // URL parsing error - skip this check
  }`;

const newUnicodeCheck = `  // =============================================================================
  // SECURITY FIX v8.8.2: PRE-PARSE UNICODE DETECTION
  // =============================================================================
  // CRITICAL: Check href BEFORE URL parsing, because new URL() converts IDN to punycode
  // This ensures we catch Unicode characters that would be lost in the conversion
  {
    let unicodeReasons = [];
    let unicodeRisk = 0;

    // Extract domain-like part from href before URL parsing
    const hrefLower = href.toLowerCase();
    const linkText = (link.textContent || '').toLowerCase();
    const checkTarget = hrefLower + ' ' + linkText; // Check both href and display text

    // 1. Universal Non-ASCII check (charCode > 127)
    if (/[^\\x00-\\x7F]/.test(checkTarget)) {
      unicodeReasons.push('universalNonAsciiDetected');
      unicodeRisk += 8;
    }

    // 2. Mathematical Alphanumeric Symbols (U+1D400-U+1D7FF) - bold/italic lookalikes
    if (/[\\u{1D400}-\\u{1D7FF}]/u.test(checkTarget)) {
      unicodeReasons.push('mathematicalAlphanumericsDetected');
      unicodeRisk += 10;
    }

    // 3. Fullwidth Latin characters (U+FF00-U+FFEF) - ａｂｃ
    if (/[\\uFF00-\\uFFEF]/.test(checkTarget)) {
      unicodeReasons.push('fullwidthCharactersDetected');
      unicodeRisk += 10;
    }

    // 4. Greek letters (U+0370-U+03FF)
    if (/[\\u0370-\\u03FF]/.test(checkTarget)) {
      unicodeReasons.push('greekLettersDetected');
      unicodeRisk += 10;
    }

    // 5. Cyrillic characters (U+0400-U+04FF)
    if (/[\\u0400-\\u04FF]/.test(checkTarget)) {
      unicodeReasons.push('cyrillicCharactersDetected');
      unicodeRisk += 10;
    }

    // 6. Cherokee characters (U+13A0-U+13FF) - ꮓ looks like z
    if (/[\\u13A0-\\u13FF]/.test(checkTarget)) {
      unicodeReasons.push('cherokeeCharactersDetected');
      unicodeRisk += 10;
    }

    // 7. Script/Letterlike Symbols (U+2100-U+214F) - ℊ looks like g
    if (/[\\u2100-\\u214F]/.test(checkTarget)) {
      unicodeReasons.push('scriptSymbolsDetected');
      unicodeRisk += 10;
    }

    // 8. Enclosed Alphanumerics (U+2460-U+24FF)
    if (/[\\u2460-\\u24FF]/.test(checkTarget)) {
      unicodeReasons.push('enclosedAlphanumericsDetected');
      unicodeRisk += 8;
    }

    // 9. Superscripts/Subscripts (U+2070-U+209F)
    if (/[\\u2070-\\u209F]/.test(checkTarget)) {
      unicodeReasons.push('superscriptSubscriptDetected');
      unicodeRisk += 8;
    }

    // Apply warning if any Unicode issues detected
    if (unicodeReasons.length > 0) {
      console.log(\`[SecurityFix v8.8.2] ⚠️ UNICODE DETECTED (pre-parse): \${href.substring(0, 50)} → \${unicodeReasons.join(', ')}\`);

      // Set warned attribute IMMEDIATELY
      link.dataset.linkshieldWarned = 'true';
      link.dataset.linkshieldLevel = unicodeRisk >= 15 ? 'alert' : 'caution';
      link.dataset.linkshieldUnicodeRisk = unicodeRisk.toString();

      warnLinkByLevel(link, {
        level: unicodeRisk >= 15 ? 'alert' : 'caution',
        risk: unicodeRisk,
        reasons: unicodeReasons
      });
    }
  }`;

if (content.includes(oldUnicodeCheck)) {
    content = content.replace(oldUnicodeCheck, newUnicodeCheck);
    console.log('SUCCESS [1/1]: Replaced Unicode check with pre-parse version');
} else {
    console.log('WARNING [1/1]: Could not find Unicode check block');
    // Try to find a key part
    if (content.includes('SECURITY FIX v8.8.0: ENHANCED UNIVERSAL NON-ASCII FLAG')) {
        console.log('Found v8.8.0 marker - may need manual fix');
    }
}

// Write the updated content
content = content.replace(/\n/g, '\r\n');
fs.writeFileSync(contentPath, content, 'utf8');

console.log('\n============================================');
console.log('SECURITY FIX v8.8.2 COMPLETE');
console.log('============================================');
console.log('Changes:');
console.log('- Unicode detection now runs BEFORE URL parsing');
console.log('- Checks both href AND link text content');
console.log('- Sets data-linkshield-warned immediately');
console.log('');
console.log('Expected: Test 4.3 should now detect 80%+ Unicode lookalikes');
