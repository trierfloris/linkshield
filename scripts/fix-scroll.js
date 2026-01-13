const fs = require('fs');
const path = require('path');

const contentPath = path.join(__dirname, '..', 'content.js');
let content = fs.readFileSync(contentPath, 'utf8');
content = content.replace(/\r\n/g, '\n');

// Replace the scroll scan function with improved version
const oldScrollSection = `let lastScrollScanTime = 0;
const SCROLL_SCAN_THROTTLE_MS = 1000; // Max 1 scan per second

/**
 * Scans viewport for new links after scroll
 * Throttled to prevent performance issues
 */
function scanViewportAfterScroll() {
  const now = Date.now();
  if (now - lastScrollScanTime < SCROLL_SCAN_THROTTLE_MS) {
    return; // Throttled
  }
  lastScrollScanTime = now;

  // Get all links in viewport
  const viewportHeight = window.innerHeight;
  const viewportWidth = window.innerWidth;

  const allLinks = document.querySelectorAll('a[href]');
  let scannedCount = 0;

  allLinks.forEach(link => {
    // Skip already scanned
    if (link.dataset.linkshieldScanned) return;

    // Check if in viewport
    const rect = link.getBoundingClientRect();
    const isInViewport = (
      rect.top < viewportHeight &&
      rect.bottom > 0 &&
      rect.left < viewportWidth &&
      rect.right > 0
    );

    if (isInViewport) {
      classifyAndCheckLink(link);
      scannedCount++;
    }
  });

  if (scannedCount > 0) {
    console.log(\`[SecurityFix v8.3.0] 📜 Scroll scan: \${scannedCount} new links in viewport\`);
  }
}

// Add throttled scroll listener
document.addEventListener('scroll', debounce(scanViewportAfterScroll, 500), { passive: true });

// Also scan on resize (viewport changes)
window.addEventListener('resize', debounce(scanViewportAfterScroll, 500), { passive: true });`;

const newScrollSection = `let lastScrollScanTime = 0;
const SCROLL_SCAN_THROTTLE_MS = 300; // SECURITY FIX v8.6.0: Reduced from 1000ms for faster detection

/**
 * SECURITY FIX v8.6.0: Enhanced scroll-triggered link scanner
 * - Reduced throttle for faster detection
 * - Extended viewport buffer to catch near-edge injections
 * - Also scans Shadow DOM roots
 * - Handles scroll-triggered evasion attempts
 */
function scanViewportAfterScroll() {
  const now = Date.now();
  if (now - lastScrollScanTime < SCROLL_SCAN_THROTTLE_MS) {
    return; // Throttled
  }
  lastScrollScanTime = now;

  // Get viewport dimensions with buffer for near-edge detection
  const viewportHeight = window.innerHeight;
  const viewportWidth = window.innerWidth;
  const VIEWPORT_BUFFER = 200; // Extra pixels to catch links near viewport edge

  const allLinks = document.querySelectorAll('a[href]');
  let scannedCount = 0;

  allLinks.forEach(link => {
    // Skip already scanned
    if (link.dataset.linkshieldScanned) return;

    // Check if in or near viewport (extended bounds)
    const rect = link.getBoundingClientRect();
    const isInViewport = (
      rect.top < (viewportHeight + VIEWPORT_BUFFER) &&
      rect.bottom > -VIEWPORT_BUFFER &&
      rect.left < (viewportWidth + VIEWPORT_BUFFER) &&
      rect.right > -VIEWPORT_BUFFER
    );

    if (isInViewport) {
      // SECURITY FIX: Check dangerous URI first
      if (typeof immediateUriSecurityCheck === 'function') {
        if (immediateUriSecurityCheck(link)) {
          link.dataset.linkshieldScanned = 'true';
          scannedCount++;
          return;
        }
      }
      classifyAndCheckLink(link);
      link.dataset.linkshieldScanned = 'true';
      scannedCount++;
    }
  });

  // SECURITY FIX v8.6.0: Also scan Shadow DOM for scroll-injected links
  const elementsWithShadow = document.querySelectorAll('*');
  elementsWithShadow.forEach(el => {
    if (el.shadowRoot) {
      const shadowLinks = el.shadowRoot.querySelectorAll('a[href]');
      shadowLinks.forEach(link => {
        if (link.dataset.linkshieldScanned) return;
        const rect = link.getBoundingClientRect();
        const isInViewport = (
          rect.top < (viewportHeight + VIEWPORT_BUFFER) &&
          rect.bottom > -VIEWPORT_BUFFER
        );
        if (isInViewport) {
          if (typeof immediateUriSecurityCheck === 'function') {
            if (immediateUriSecurityCheck(link)) {
              link.dataset.linkshieldScanned = 'true';
              scannedCount++;
              return;
            }
          }
          classifyAndCheckLink(link);
          link.dataset.linkshieldScanned = 'true';
          scannedCount++;
        }
      });
    }
  });

  if (scannedCount > 0) {
    console.log(\`[SecurityFix v8.6.0] 📜 Scroll scan: \${scannedCount} new links in/near viewport\`);
  }
}

/**
 * SECURITY FIX v8.6.0: Intersection Observer for lazy-loaded content
 * Catches elements that become visible without explicit scroll events
 */
let scrollScanObserver = null;

function initScrollScanObserver() {
  if (typeof IntersectionObserver === 'undefined') return;

  scrollScanObserver = new IntersectionObserver((entries) => {
    entries.forEach(entry => {
      if (entry.isIntersecting && entry.target.tagName === 'A') {
        const link = entry.target;
        if (!link.dataset.linkshieldScanned && link.href) {
          if (typeof immediateUriSecurityCheck === 'function') {
            if (immediateUriSecurityCheck(link)) {
              link.dataset.linkshieldScanned = 'true';
              return;
            }
          }
          classifyAndCheckLink(link);
          link.dataset.linkshieldScanned = 'true';
          console.log('[SecurityFix v8.6.0] 👁️ IntersectionObserver caught link:', link.href.substring(0, 50));
        }
      }
    });
  }, {
    rootMargin: '200px', // Start scanning before element is visible
    threshold: 0
  });

  // Observe all unscanned links
  document.querySelectorAll('a[href]:not([data-linkshield-scanned])').forEach(link => {
    scrollScanObserver.observe(link);
  });
}

// Initialize observer after DOM ready
if (document.readyState === 'complete') {
  initScrollScanObserver();
} else {
  window.addEventListener('load', initScrollScanObserver);
}

// Add throttled scroll listener with shorter debounce
document.addEventListener('scroll', debounce(scanViewportAfterScroll, 300), { passive: true });

// Also scan on resize (viewport changes)
window.addEventListener('resize', debounce(scanViewportAfterScroll, 300), { passive: true });

// SECURITY FIX v8.6.0: Also listen for scrollend event (modern browsers)
if ('onscrollend' in window) {
  document.addEventListener('scrollend', scanViewportAfterScroll, { passive: true });
}`;

if (content.includes(oldScrollSection)) {
    content = content.replace(oldScrollSection, newScrollSection);
    content = content.replace(/\n/g, '\r\n');
    fs.writeFileSync(contentPath, content, 'utf8');
    console.log('SUCCESS: Updated scroll scan handler in content.js');
} else {
    console.log('ERROR: Pattern not found');
    // Debug
    if (content.includes('SCROLL_SCAN_THROTTLE_MS = 1000')) {
        console.log('Found throttle constant');
    }
    if (content.includes('scanViewportAfterScroll')) {
        console.log('Found function name');
    }
}
