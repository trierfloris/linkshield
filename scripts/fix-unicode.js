const fs = require('fs');
const path = require('path');

const contentPath = path.join(__dirname, '..', 'content.js');
let content = fs.readFileSync(contentPath, 'utf8');
content = content.replace(/\r\n/g, '\n');

// Find and replace the non-ASCII catch-all section
const oldSection = `  // 6. General catch-all for non-ASCII characters in suspicious positions
  // Any character with code > 127 in a domain that resembles a brand is suspicious
  if (/[^\\x00-\\x7F]/.test(normalizedHost)) {
    // Has non-ASCII characters - check if it's in a brand-like context
    const brandPatterns = ['google', 'apple', 'amazon', 'paypal', 'microsoft', 'facebook',
                          'twitter', 'netflix', 'bank', 'login', 'account', 'secure'];
    const normalizedLower = normalizedHost.toLowerCase();
    for (const brand of brandPatterns) {
      // Check if normalized version contains brand-like patterns
      if (normalizedLower.includes(brand) ||
          normalizedHost.normalize('NFKD').toLowerCase().includes(brand)) {
        if (!result.reasons.includes('nonAsciiInBrandDomain')) {
          result.hasConfusables = true;
          result.reasons.push('nonAsciiInBrandDomain');
          result.risk += 8;
          console.log(\`[SecurityFix v8.5.0] 🚨 Non-ASCII in brand-like domain: \${hostname}\`);
        }
        break;
      }
    }
  }`;

const newSection = `  // 6. Enclosed Alphanumerics (U+2460-U+24FF) - ①②③ and ⓐⓑⓒ
  // These can be used to create lookalike domains
  if (/[\\u2460-\\u24FF]/.test(normalizedHost)) {
    result.hasConfusables = true;
    if (!result.reasons.includes('enclosedAlphanumericsDetected')) {
      result.reasons.push('enclosedAlphanumericsDetected');
      result.risk += 10;
      console.log(\`[SecurityFix v8.6.0] 🚨 Enclosed Alphanumerics detected in: \${hostname}\`);
    }
  }

  // 7. Superscripts and Subscripts (U+2070-U+209F)
  if (/[\\u2070-\\u209F]/.test(normalizedHost)) {
    result.hasConfusables = true;
    if (!result.reasons.includes('superscriptSubscriptDetected')) {
      result.reasons.push('superscriptSubscriptDetected');
      result.risk += 10;
      console.log(\`[SecurityFix v8.6.0] 🚨 Superscript/Subscript characters detected in: \${hostname}\`);
    }
  }

  // 8. Number Forms (U+2150-U+218F) - ⅓, ⅔, Roman numerals, etc.
  if (/[\\u2150-\\u218F]/.test(normalizedHost)) {
    result.hasConfusables = true;
    if (!result.reasons.includes('numberFormsDetected')) {
      result.reasons.push('numberFormsDetected');
      result.risk += 8;
      console.log(\`[SecurityFix v8.6.0] 🚨 Number Forms detected in: \${hostname}\`);
    }
  }

  // 9. UNIVERSAL NON-ASCII CATCH-ALL (CRITICAL for 100% detection)
  // ANY character with charCode > 127 in a domain is suspicious
  // Flag as MEDIUM RISK minimum, escalate to HIGH if brand-like
  if (/[^\\x00-\\x7F]/.test(normalizedHost)) {
    // Has non-ASCII characters - always flag as at least medium risk
    if (!result.reasons.includes('nonAsciiCharactersDetected') &&
        !result.reasons.includes('nonAsciiInBrandDomain')) {
      result.hasConfusables = true;
      result.reasons.push('nonAsciiCharactersDetected');
      result.risk += 6; // Medium risk for any non-ASCII
      console.log(\`[SecurityFix v8.6.0] 🚨 Non-ASCII characters detected: \${hostname}\`);
    }

    // Escalate to HIGH if brand-like context
    const brandPatterns = ['google', 'apple', 'amazon', 'paypal', 'microsoft', 'facebook',
                          'twitter', 'netflix', 'bank', 'login', 'account', 'secure',
                          'verify', 'signin', 'support', 'update', 'confirm', 'wallet'];
    const normalizedLower = normalizedHost.toLowerCase();
    const nfkdNormalized = normalizedHost.normalize('NFKD').toLowerCase();
    for (const brand of brandPatterns) {
      if (normalizedLower.includes(brand) || nfkdNormalized.includes(brand)) {
        if (!result.reasons.includes('nonAsciiInBrandDomain')) {
          result.reasons.push('nonAsciiInBrandDomain');
          result.risk += 8; // Additional 8 points for brand context
          console.log(\`[SecurityFix v8.6.0] 🚨 Non-ASCII in brand-like domain: \${hostname}\`);
        }
        break;
      }
    }
  }`;

if (content.includes(oldSection)) {
    content = content.replace(oldSection, newSection);
    content = content.replace(/\n/g, '\r\n');
    fs.writeFileSync(contentPath, content, 'utf8');
    console.log('SUCCESS: Updated Unicode detection in content.js');
} else {
    console.log('ERROR: Pattern not found');
    // Try to find partial match
    if (content.includes('// 6. General catch-all for non-ASCII')) {
        console.log('Found partial match - section header exists');
    }
}
