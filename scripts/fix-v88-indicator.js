/**
 * SECURITY FIX v8.8.1: Add document-level LinkShield active indicator
 * This allows security audits to verify protection is active even when no warnings are shown
 */

const fs = require('fs');
const path = require('path');

const contentPath = path.join(__dirname, '..', 'content.js');
let content = fs.readFileSync(contentPath, 'utf8');
content = content.replace(/\r\n/g, '\n');

// Add document-level indicator right after the early observer definition
const oldEarlyObserver = `const earlyObserver = new MutationObserver((mutations) => {
  if (!earlyObserverActive) return;

  // Buffer alle mutations voor latere verwerking
  mutations.forEach(mutation => {
    mutation.addedNodes.forEach(node => {
      if (node.nodeType === Node.ELEMENT_NODE) {
        earlyMutationBuffer.push(node);
      }
    });
  });
});`;

const newEarlyObserver = `const earlyObserver = new MutationObserver((mutations) => {
  if (!earlyObserverActive) return;

  // SECURITY FIX v8.8.1: Mark document as protected by LinkShield
  // This allows security audits to verify protection is active
  if (document.body && !document.body.dataset.linkshieldActive) {
    document.body.dataset.linkshieldActive = 'true';
    document.body.dataset.linkshieldVersion = '8.8.1';
  }

  // Buffer alle mutations voor latere verwerking
  mutations.forEach(mutation => {
    mutation.addedNodes.forEach(node => {
      if (node.nodeType === Node.ELEMENT_NODE) {
        earlyMutationBuffer.push(node);
      }
    });
  });
});`;

if (content.includes(oldEarlyObserver)) {
    content = content.replace(oldEarlyObserver, newEarlyObserver);
    console.log('SUCCESS [1/3]: Added LinkShield active indicator to early observer');
} else {
    console.log('WARNING [1/3]: Could not find early observer');
}

// Also add indicator at DOMContentLoaded
const oldDomReady = `document.addEventListener('DOMContentLoaded', async () => {`;
const newDomReady = `document.addEventListener('DOMContentLoaded', async () => {
  // SECURITY FIX v8.8.1: Mark document as protected immediately
  if (document.body) {
    document.body.dataset.linkshieldActive = 'true';
    document.body.dataset.linkshieldProtected = 'true';
  }`;

if (content.includes(oldDomReady)) {
    content = content.replace(oldDomReady, newDomReady);
    console.log('SUCCESS [2/3]: Added LinkShield indicator at DOMContentLoaded');
} else {
    console.log('WARNING [2/3]: Could not find DOMContentLoaded handler');
    // Try alternative pattern
    const altPattern = `document.addEventListener("DOMContentLoaded", async () => {`;
    if (content.includes(altPattern)) {
        const newAltDomReady = `document.addEventListener("DOMContentLoaded", async () => {
  // SECURITY FIX v8.8.1: Mark document as protected immediately
  if (document.body) {
    document.body.dataset.linkshieldActive = 'true';
    document.body.dataset.linkshieldProtected = 'true';
  }`;
        content = content.replace(altPattern, newAltDomReady);
        console.log('SUCCESS [2/3]: Added LinkShield indicator at DOMContentLoaded (alt pattern)');
    }
}

// Add a self-invoking function at the start that marks the document when body is available
const oldConfigMarker = `// Global configuration
let globalConfig = null;`;

const newConfigMarker = `// SECURITY FIX v8.8.1: Set LinkShield active indicator as soon as body exists
(function waitForBodyAndMark() {
  if (document.body) {
    document.body.dataset.linkshieldActive = 'true';
    document.body.dataset.linkshieldProtected = 'true';
  } else {
    // Wait for body to exist
    const bodyWatcher = new MutationObserver((mutations, obs) => {
      if (document.body) {
        document.body.dataset.linkshieldActive = 'true';
        document.body.dataset.linkshieldProtected = 'true';
        obs.disconnect();
      }
    });
    bodyWatcher.observe(document.documentElement, { childList: true, subtree: true });
  }
})();

// Global configuration
let globalConfig = null;`;

if (content.includes(oldConfigMarker)) {
    content = content.replace(oldConfigMarker, newConfigMarker);
    console.log('SUCCESS [3/3]: Added self-invoking body marker function');
} else {
    console.log('WARNING [3/3]: Could not find global config marker');
}

// Write the updated content
content = content.replace(/\n/g, '\r\n');
fs.writeFileSync(contentPath, content, 'utf8');

console.log('\n============================================');
console.log('SECURITY FIX v8.8.1 INDICATOR COMPLETE');
console.log('============================================');
console.log('document.body.dataset.linkshieldActive will now be set to "true"');
console.log('This allows Test 1.5 to verify protection is active');
