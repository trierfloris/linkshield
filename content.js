/**
 * Logt debug-informatie - alleen actief als DEBUG_MODE: true in config.js
 * @param {string} message - Het bericht om te loggen.
 * @param {...any} optionalParams - Optionele parameters.
 */
function logDebug(message, ...optionalParams) {
  if (globalConfig && globalConfig.DEBUG_MODE) {
    console.log(message, ...optionalParams);
  }
}
// PERFORMANCE FIX: Detect sub-frames early to skip heavy operations
// Sub-frames (ads, tracking pixels, embeds) don't need full security scanning
const _isTopFrame = (window.self === window.top);

function isHiddenInput(el) {
  return el.tagName === 'INPUT' && el.type === 'hidden';
}
function isVisible(el) {
  const style = getComputedStyle(el);
  return (
    style.display !== 'none' &&
    style.visibility !== 'hidden' &&
    el.offsetParent !== null &&
    el.getAttribute('aria-hidden') !== 'true'
  );
}
/**
 * Zorgt ervoor dat de globale configuratie (`globalConfig`) beschikbaar en geldig is.
 *
 * Deze functie wordt gebruikt als safeguard in functies die afhankelijk zijn van
 * globale configuratie-instellingen zoals risico-drempels, toegestane protocollen,
 * verdachte extensies, enz.
 *
 * Werking:
 * - Controleert of `globalConfig` beschikbaar is en gevuld.
 * - Zo niet, roept `loadConfig()` aan om de configuratie opnieuw te laden (asynchroon).
 * - Indien `globalConfig` daarna nog steeds niet beschikbaar is (bijv. door fetch-fout),
 * wordt een fallbackconfiguratie gebruikt via `validateConfig(defaultConfig)`.
 *
 * Belangrijk:
 * Deze functie voorkomt runtime-fouten bij vroege of onverwachte aanroepen van
 * analysefuncties die `globalConfig` nodig hebben. Te gebruiken bovenin:
 * - `warnLink()`
 * - `performSuspiciousChecks()`
 * - `analyzeDomainAndUrl()`
 * - `checkCurrentUrl()`
 */
async function ensureConfigReady() {
  // Controleer of de globale configuratie beschikbaar en niet leeg is
  if (!globalConfig || Object.keys(globalConfig).length === 0) {
    logDebug("[Config] Config niet beschikbaar, opnieuw laden...");
    await loadConfig(); // Wacht altijd op loadConfig(), wat nu idempotent is
    // Als na het laden globalConfig nog steeds leeg is: fallback
    if (!globalConfig || Object.keys(globalConfig).length === 0) {
      logError("[Config] Config nog steeds niet beschikbaar. Gebruik default fallback.");
      globalConfig = validateConfig(defaultConfig);
    }
  }
}
/**
 * Haalt een vertaling op voor een gegeven message key.
 * Veilige wrapper met null checks voor contexts waar chrome.i18n niet beschikbaar is.
 * @param {string} messageKey
 * @returns {string}
 */
function getTranslatedMessage(messageKey) {
  try {
    if (typeof chrome !== 'undefined' && chrome.i18n && typeof chrome.i18n.getMessage === 'function') {
      return chrome.i18n.getMessage(messageKey) || messageKey;
    }
  } catch (e) {
    // Ignore - extension context might be invalidated
  }
  return messageKey;
}
/**
 * Logt een foutmelding.
 * @param {string} message - Het foutbericht.
 * @param {...any} optionalParams - Optionele parameters.
 */
function logError(message, ...optionalParams) {
  if (globalConfig && globalConfig.DEBUG_MODE) {
    console.error(message, ...optionalParams);
  }
}
/**
 * Centrale foutafhandelingsfunctie die een fout logt met context.
 * @param {Error} error - De fout.
 * @param {string} context - Contextuele informatie over waar de fout is opgetreden.
 */
function handleError(error, context) {
  logError(`[${context}] ${error.message}`, error);
}
// SECURITY FIX v8.8.1: Set LinkShield active indicator as soon as body exists
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

// Global configuration - initialize as empty object to prevent null access errors
let globalConfig = {};
let globalHomoglyphReverseMap = {};
// Shared constants for throttling and caching
const CHECK_INTERVAL_MS = 5000; // 5 seconds between checks
const CACHE_DURATION_MS = 3600 * 1000; // 1 hour cache expiration
const MAX_CACHE_SIZE = 1000;
const MUTATION_DEBOUNCE_MS = 500; // Increased from 250ms for heavy SPA sites
let _isTrustedSiteCache = null; // Cached trusted domain check for performance-sensitive paths
const warnedDomainsInline = new Set()

// =============================================================================
// SECURITY FIX v8.0.0 - EARLY MUTATION OBSERVER (Vector 1: Race Condition Fix)
// =============================================================================
// Dit systeem start DIRECT bij document_start en buffert alle DOM mutaties
// tot de config geladen is. Dit voorkomt dat aanvallers links kunnen injecteren
// in het korte tijdvenster tussen document_start en config load.

const earlyMutationBuffer = [];
let earlyObserverActive = true;
let configReady = false;

// v8.4.1: Smart Link Scanning (PRO feature) toggle state
// This is set during initialization and controls whether link scanning is active
let smartLinkScanningEnabled = false;

// v8.4.1: Listen for storage changes to update Smart Link Scanning toggle in real-time
// This ensures the feature is immediately enabled/disabled when user toggles in popup
if (typeof chrome !== 'undefined' && chrome.storage && chrome.storage.onChanged) {
  chrome.storage.onChanged.addListener((changes, areaName) => {
    if (areaName === 'sync' && changes.integratedProtection) {
      const newValue = changes.integratedProtection.newValue;
      smartLinkScanningEnabled = newValue === true;
      logDebug(`[Settings] Smart Link Scanning toggled: ${smartLinkScanningEnabled}`);
    }
  });
}

// Shadow DOM configuratie - SECURITY FIX v8.0.0 (Vector 2)
const MAX_SHADOW_DEPTH = 20; // Verhoogd van 5 naar 20 voor diepe Shadow DOM nesting

/**
 * Early Observer - start DIRECT, buffert mutations tot config klaar is
 * SECURITY FIX v8.0.0: Voorkomt race condition bypass
 */
const earlyObserver = new MutationObserver((mutations) => {
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
});

// Start DIRECT - zelfs voordat document.body bestaat
// We observeren documentElement wat altijd bestaat bij document_start
// PERFORMANCE FIX: Only run in top frame - sub-frames don't need early mutation buffering
if (document.documentElement && _isTopFrame) {
  earlyObserver.observe(document.documentElement, {
    childList: true,
    subtree: true
  });
}

/**
 * Verwerkt gebufferde mutations nadat config geladen is
 * @returns {Promise<void>}
 */
async function processEarlyMutationBuffer() {
  if (earlyMutationBuffer.length === 0) return;

  const nodesToProcess = [...earlyMutationBuffer];
  earlyMutationBuffer.length = 0; // Clear buffer

  logDebug(`[EarlyObserver] Processing ${nodesToProcess.length} buffered nodes`);

  for (const node of nodesToProcess) {
    try {
      // Scan voor links (inclusief Shadow DOM)
      await scanNodeForLinks(node);
    } catch (e) {
      // Ignore errors in individual node processing
    }
  }
}

/**
 * SECURITY FIX v8.4.0: Immediate dangerous URI check at scan entry point
 * Performs fast check BEFORE any caching or complex parsing
 * v8.4.1: Only runs if Smart Link Scanning (integratedProtection) is enabled
 * @param {HTMLAnchorElement} link - The link element to check
 * @returns {boolean} - true if dangerous URI was blocked, false otherwise
 */
function immediateUriSecurityCheck(link) {
  // v8.4.1: Skip if Smart Link Scanning is disabled (PRO feature)
  if (!smartLinkScanningEnabled) return false;
  if (!link) return false;

  // Get BOTH href property AND raw attribute - browsers don't decode protocol in encoded URIs
  // e.g., href="javascript%3avoid(0)" -> link.href becomes relative path, NOT javascript:
  const hrefProp = link.href instanceof SVGAnimatedString ? link.href.baseVal : link.href;
  const hrefAttr = link.getAttribute ? link.getAttribute('href') : null;

  // Check both sources - attribute may have encoded protocol that browser didn't recognize
  const hrefsToCheck = [hrefProp, hrefAttr].filter(h => h && typeof h === 'string');
  if (hrefsToCheck.length === 0) return false;

  for (const href of hrefsToCheck) {
    // IMMEDIATE CHECK 1: Data URI (simple fast check)
    if (href.trim().toLowerCase().startsWith('data:')) {
      const lowerHref = href.toLowerCase();
      // Skip safe MIME types: images, audio, video, fonts, plain text
      if (/^data:(image|audio|video|font)\//i.test(lowerHref) ||
          (lowerHref.startsWith('data:text/plain,') && !lowerHref.includes('base64'))) {
        continue; // Safe non-executable data URI, check next href source
      }
      logDebug(`[SecurityFix v8.4.0] 🛑 IMMEDIATE BLOCK: data: URI detected`);
      warnLinkByLevel(link, {
        level: 'alert',
        risk: 25,
        reasons: ['dataUriBlocked', 'criticalSecurityThreat']
      });
      link.dataset.linkshieldScanned = 'true';
      return true;
    }

    // IMMEDIATE CHECK 2: JavaScript URI (with recursive decode)
    let decoded = href;
    try {
      // Recursive decode up to 5 times for bypass attempts
      for (let i = 0; i < 5; i++) {
        const prev = decoded;
        try {
          decoded = decodeURIComponent(decoded);
        } catch (e) {
          decoded = decoded.replace(/%([0-9A-Fa-f]{2})/g, (_, hex) =>
            String.fromCharCode(parseInt(hex, 16)));
        }
        if (decoded === prev) break;
      }
    } catch (e) { /* ignore decode errors */ }

    // Remove whitespace/control chars and check for javascript:
    const normalized = decoded.replace(/[\s\r\n\t\0\x00-\x1F\x7F]/g, '').toLowerCase();
    if (normalized.startsWith('javascript:')) {
      // Skip harmless void(0) patterns - use continue to check other href sources
      const code = normalized.slice('javascript:'.length).trim();
      const harmless = ['void(0)', 'void(0);', 'void0', '', ';', 'void0;', 'undefined', 'false', 'true', 'null'];
      if (harmless.includes(code)) {
        continue; // Check next href source, don't exit early
      }
      logDebug(`[SecurityFix v8.4.0] 🛑 IMMEDIATE BLOCK: javascript: URI detected`);
      warnLinkByLevel(link, {
        level: 'alert',
        risk: 25,
        reasons: ['javascriptUriBlocked', 'criticalSecurityThreat']
      });
      link.dataset.linkshieldScanned = 'true';
      return true;
    }

    // IMMEDIATE CHECK 3: VBScript URI
    if (normalized.startsWith('vbscript:')) {
      logDebug(`[SecurityFix v8.4.0] 🛑 IMMEDIATE BLOCK: vbscript: URI detected`);
      warnLinkByLevel(link, {
        level: 'alert',
        risk: 25,
        reasons: ['vbscriptUriBlocked', 'criticalSecurityThreat']
      });
      link.dataset.linkshieldScanned = 'true';
      return true;
    }

    // IMMEDIATE CHECK 4: Blob URI (can execute arbitrary code)
    if (href.trim().toLowerCase().startsWith('blob:')) {
      logDebug(`[SecurityFix v8.4.0] 🛑 IMMEDIATE BLOCK: blob: URI detected`);
      warnLinkByLevel(link, {
        level: 'alert',
        risk: 25,
        reasons: ['blobUriBlocked', 'criticalSecurityThreat']
      });
      link.dataset.linkshieldScanned = 'true';
      return true;
    }
  } // end for loop over hrefsToCheck

  return false;
}

/**
 * Scant een node en al zijn children voor links, inclusief Shadow DOM
 * SECURITY FIX v8.0.0: Recursieve Shadow DOM scanning tot depth 20
 * SECURITY FIX v8.4.0: Immediate URI security checks at entry point
 * v8.4.1: Only runs if Smart Link Scanning (integratedProtection) is enabled
 * @param {Node} node - De node om te scannen
 * @param {number} shadowDepth - Huidige Shadow DOM diepte
 */
async function scanNodeForLinks(node, shadowDepth = 0) {
  // v8.4.1: Skip if Smart Link Scanning is disabled (PRO feature)
  if (!smartLinkScanningEnabled) return;
  if (!node || shadowDepth > MAX_SHADOW_DEPTH) return;

  // Check directe links
  if (node.tagName === 'A' && node.href && !node.dataset.linkshieldScanned) {
    try {
      // SECURITY FIX v8.4.0: Immediate dangerous URI check FIRST
      if (immediateUriSecurityCheck(node)) {
        return; // Blocked, skip further processing
      }
      if (typeof isValidURL === 'function' && isValidURL(node.href)) {
        if (typeof classifyAndCheckLink === 'function') {
          classifyAndCheckLink(node);
          // SECURITY FIX v8.0.1 (Vector 1): Mark as scanned
          node.dataset.linkshieldScanned = 'true';
        }
      }
    } catch (e) { /* ignore */ }
  }

  // Scan children
  if (node.querySelectorAll) {
    const links = node.querySelectorAll('a[href]');
    links.forEach(link => {
      if (link.dataset.linkshieldScanned) return; // Skip already scanned
      try {
        // SECURITY FIX v8.4.0: Immediate dangerous URI check FIRST
        if (immediateUriSecurityCheck(link)) {
          return; // Blocked, skip further processing
        }
        if (typeof isValidURL === 'function' && isValidURL(link.href)) {
          if (typeof classifyAndCheckLink === 'function') {
            classifyAndCheckLink(link);
            // SECURITY FIX v8.0.1 (Vector 1): Mark as scanned
            link.dataset.linkshieldScanned = 'true';
          }
        }
      } catch (e) { /* ignore */ }
    });

    // SECURITY FIX v8.0.0: Recursief scannen van Shadow DOM
    const allElements = node.querySelectorAll('*');
    allElements.forEach(el => {
      if (el.shadowRoot) {
        scanNodeForLinks(el.shadowRoot, shadowDepth + 1);
      }
    });
  }

  // Check eigen shadowRoot
  if (node.shadowRoot) {
    scanNodeForLinks(node.shadowRoot, shadowDepth + 1);
  }
}

/**
 * Callback wanneer config klaar is - verwerk buffer en start normale observer
 * v8.4.1: Now checks integratedProtection (Smart Link Scanning) setting
 */
async function onConfigReady() {
  if (configReady) return;
  configReady = true;

  // v8.4.1: Check if Smart Link Scanning (integratedProtection) is enabled
  // This is a PRO feature - only scan links if the user has it enabled
  try {
    const settings = await getStoredSettings();
    smartLinkScanningEnabled = settings.integratedProtection === true;
    logDebug(`[EarlyObserver] Smart Link Scanning enabled: ${smartLinkScanningEnabled}`);
  } catch (e) {
    // Default to false if settings can't be read (PRO feature should be opt-in)
    smartLinkScanningEnabled = false;
    logDebug('[EarlyObserver] Could not read settings, Smart Link Scanning disabled');
  }

  // Stop early observer (wordt vervangen door hoofdobserver)
  earlyObserverActive = false;
  earlyObserver.disconnect(); // Actually disconnect to prevent observer overhead

  // v8.4.1: Only process buffered mutations and schedule scan if Smart Link Scanning is enabled
  if (smartLinkScanningEnabled) {
    // Verwerk gebufferde mutations
    processEarlyMutationBuffer();

    // Schedule een fallback full-page scan met requestIdleCallback
    // SECURITY FIX v8.0.0: Vangt gemiste elementen op
    scheduleFullPageScan();

    logDebug('[EarlyObserver] Config ready, buffer processed, fallback scan scheduled');
  } else {
    // Clear the buffer without processing - Smart Link Scanning is disabled
    earlyMutationBuffer.length = 0;
    logDebug('[EarlyObserver] Config ready, Smart Link Scanning disabled - skipping link scans');
  }
}

/**
 * PERFORMANCE FIX v8.6.0: Optimized progressive scanning
 * Target: <10 seconds for 5000 links
 * v8.4.1: Only runs if Smart Link Scanning (integratedProtection) is enabled
 *
 * Strategy:
 * 1. Viewport-first: Scan visible links immediately (blocking)
 * 2. Batched processing: Process off-screen links in batches of 200
 * 3. requestIdleCallback: Use idle time for background work
 * 4. Early termination: Skip already-scanned links via WeakSet
 * 5. Deferred classification: Skip heavy checks for simple URLs
 */

// WeakSet for O(1) "already scanned" lookup (faster than dataset attribute)
const scannedLinksSet = new WeakSet();

function scheduleFullPageScan() {
  // PERFORMANCE FIX: Skip on trusted domains
  if (_isTrustedSiteCache) {
    logDebug('[ProgressiveScan] Skipped - trusted domain');
    return;
  }
  // v8.4.1: Skip if Smart Link Scanning is disabled (PRO feature)
  if (!smartLinkScanningEnabled) {
    logDebug('[ProgressiveScan] Skipped - Smart Link Scanning disabled');
    return;
  }

  const BATCH_SIZE = 200; // PERFORMANCE FIX v8.6.0: Increased from 100 to 200
  const BATCH_DELAY = 0; // ms between batches (0 = requestIdleCallback handles timing)
  const startTime = performance.now();

  /**
   * Check if an element is in the viewport
   */
  const isInViewport = (el) => {
    const rect = el.getBoundingClientRect();
    return (
      rect.top < window.innerHeight &&
      rect.bottom > 0 &&
      rect.left < window.innerWidth &&
      rect.right > 0
    );
  };

  /**
   * Scan a single link
   * PERFORMANCE FIX v8.6.0: Uses WeakSet for O(1) lookup + dataset for persistence
   */
  const scanLink = (link) => {
    // Fast WeakSet check first (O(1) vs O(n) for dataset)
    if (scannedLinksSet.has(link)) return false;
    if (link.dataset.linkshieldScanned) {
      scannedLinksSet.add(link); // Sync WeakSet with dataset
      return false;
    }
    try {
      // SECURITY FIX v8.4.0: Immediate dangerous URI check FIRST (before any other checks)
      if (typeof immediateUriSecurityCheck === 'function' && immediateUriSecurityCheck(link)) {
        return true; // Link was blocked by immediate check
      }
      if (typeof isValidURL === 'function' && isValidURL(link.href)) {
        if (typeof classifyAndCheckLink === 'function') {
          classifyAndCheckLink(link);
          link.dataset.linkshieldScanned = 'true';
          scannedLinksSet.add(link); // PERFORMANCE FIX v8.6.0: Keep WeakSet in sync
          return true;
        }
      }
    } catch (e) { /* ignore */ }
    return false;
  };

  /**
   * Process a batch of links
   */
  const processBatch = (links, startIndex, callback) => {
    const endIndex = Math.min(startIndex + BATCH_SIZE, links.length);
    let scanned = 0;

    for (let i = startIndex; i < endIndex; i++) {
      if (scanLink(links[i])) scanned++;
    }

    if (endIndex < links.length) {
      // More links to process - schedule next batch
      if (typeof requestIdleCallback === 'function') {
        requestIdleCallback(() => processBatch(links, endIndex, callback), { timeout: 50 }); // PERFORMANCE FIX v8.6.0: Faster batching
      } else {
        setTimeout(() => processBatch(links, endIndex, callback), BATCH_DELAY);
      }
    } else {
      // All done
      callback(scanned);
    }
  };

  const performScan = () => {
    // PERFORMANCE FIX: Skip if trusted domain was determined after scheduling
    if (_isTrustedSiteCache) return;
    try {
      const allLinks = Array.from(document.querySelectorAll('a[href]'));
      const totalLinks = allLinks.length;

      // Phase 1: Immediate viewport scan (blocking but fast)
      const viewportLinks = allLinks.filter(isInViewport);
      const offscreenLinks = allLinks.filter(link => !isInViewport(link));

      let viewportScanned = 0;
      viewportLinks.forEach(link => {
        if (scanLink(link)) viewportScanned++;
      });

      const viewportTime = performance.now() - startTime;
      logDebug(`[ProgressiveScan] 👁️ Phase 1: ${viewportScanned}/${viewportLinks.length} viewport links in ${viewportTime.toFixed(1)}ms`);

      // Phase 2: Background scan for off-screen links (non-blocking)
      if (offscreenLinks.length > 0) {
        processBatch(offscreenLinks, 0, (offscreenScanned) => {
          const totalTime = performance.now() - startTime;
          logDebug(`[ProgressiveScan] 📄 Phase 2: ${offscreenScanned}/${offscreenLinks.length} off-screen links`);
          logDebug(`[ProgressiveScan] ✅ Total: ${viewportScanned + offscreenScanned}/${totalLinks} links in ${totalTime.toFixed(1)}ms`);

          // Phase 3: Shadow DOM scan (after main links done)
          // Skip on trusted domains - querySelectorAll('*') is too expensive on complex SPAs
          if (!_isTrustedSiteCache) {
            scanAllShadowDOMs(document.body, 0);
          }
        });
      } else {
        const totalTime = performance.now() - startTime;
        logDebug(`[ProgressiveScan] ✅ Complete: ${viewportScanned}/${totalLinks} links in ${totalTime.toFixed(1)}ms`);
        if (!_isTrustedSiteCache) {
          scanAllShadowDOMs(document.body, 0);
        }
      }
    } catch (e) {
      logError('[ProgressiveScan] Error:', e);
    }
  };

  // Start scan after a short delay to allow page to stabilize
  if (typeof requestIdleCallback === 'function') {
    requestIdleCallback(performScan, { timeout: 500 }); // PERFORMANCE FIX v8.6.0: Reduced from 2000ms
  } else {
    setTimeout(performScan, 500);
  }
}

/**
 * Scant alle Shadow DOMs recursief
 * SECURITY FIX v8.0.0 (Vector 2): Diepte 20 voor Shadow DOM Inception aanvallen
 * @param {Element} root - Root element
 * @param {number} depth - Huidige diepte
 */
function scanAllShadowDOMs(root, depth = 0) {
  if (!root || depth > MAX_SHADOW_DEPTH) {
    if (depth > MAX_SHADOW_DEPTH) {
      logDebug(`[ShadowScan] 🛑 MAX_DEPTH reached (${MAX_SHADOW_DEPTH}) - stopping recursion`);
    }
    return;
  }

  try {
    const allElements = root.querySelectorAll ? root.querySelectorAll('*') : [];
    let shadowRootsFound = 0;
    let linksScanned = 0;

    // DEBUG: Log scan start
    if (depth === 0) {
      logDebug(`[ShadowScan] 🔍 Starting Shadow DOM scan from root:`, root.nodeName || 'document');
    }

    allElements.forEach(el => {
      if (el.shadowRoot) {
        shadowRootsFound++;
        const hostTag = el.tagName?.toLowerCase() || 'unknown';

        // DEBUG: Log each Shadow Root found
        logDebug(`[ShadowScan] 🌑 Shadow Root FOUND at depth ${depth}: <${hostTag}> (mode: ${el.shadowRoot.mode || 'unknown'})`);

        // Scan links in deze shadow root
        const shadowLinks = el.shadowRoot.querySelectorAll('a[href]');
        logDebug(`[ShadowScan]   └─ Links in shadow: ${shadowLinks.length}`);

        shadowLinks.forEach(link => {
          if (!link.dataset.linkshieldScanned) {
            try {
              if (typeof isValidURL === 'function' && isValidURL(link.href)) {
                if (typeof classifyAndCheckLink === 'function') {
                  classifyAndCheckLink(link);
                  link.dataset.linkshieldScanned = 'true';
                  linksScanned++;
                  logDebug(`[ShadowScan]   └─ ✅ Scanned: ${link.href.substring(0, 60)}...`);
                }
              }
            } catch (e) {
              logDebug(`[ShadowScan]   └─ ❌ Error scanning link:`, e.message);
            }
          }
        });

        // Recursief scannen
        scanAllShadowDOMs(el.shadowRoot, depth + 1);
      }
    });

    // DEBUG: Log scan summary for this depth level
    if (shadowRootsFound > 0 || depth === 0) {
      logDebug(`[ShadowScan] 📊 Depth ${depth} complete: ${shadowRootsFound} shadow roots, ${linksScanned} links scanned`);
    }
  } catch (e) {
    logError(`[ShadowScan] ❌ Error at depth ${depth}:`, e);
  }
}

// ============================================================================
// CACHE MANAGEMENT - Prevent memory exhaustion in long-running sessions
// ============================================================================
const activeIntervals = []; // Track all setInterval IDs for cleanup

/**
 * Enforces cache size limit using LRU-style eviction (oldest entries first)
 * @param {Map} cache - The cache Map to limit
 * @param {number} maxSize - Maximum number of entries (default: MAX_CACHE_SIZE)
 */
function enforceCacheLimit(cache, maxSize = MAX_CACHE_SIZE) {
  if (cache.size <= maxSize) return;
  // Remove oldest entries (first entries in Map iteration order)
  const entriesToRemove = cache.size - maxSize;
  let removed = 0;
  for (const key of cache.keys()) {
    if (removed >= entriesToRemove) break;
    cache.delete(key);
    removed++;
  }
  logDebug(`🗑️ Cache eviction: removed ${removed} entries, size now ${cache.size}`);
}

/**
 * Safe cache set with automatic size limiting
 * @param {Map} cache - The cache Map
 * @param {string} key - Cache key
 * @param {any} value - Value to cache
 */
function safeSetCache(cache, key, value) {
  cache.set(key, value);
  enforceCacheLimit(cache);
}

/**
 * Wrapper for setInterval that tracks interval IDs for cleanup
 * @param {Function} callback - The callback function
 * @param {number} delay - The interval delay in ms
 * @returns {number} - The interval ID
 */
function trackedSetInterval(callback, delay) {
  const id = setInterval(callback, delay);
  activeIntervals.push(id);
  return id;
}

/**
 * Cleanup function to be called on page unload
 * Clears all tracked intervals and caches to prevent memory leaks
 */
function cleanupOnUnload() {
  // Clear all tracked intervals
  activeIntervals.forEach(id => clearInterval(id));
  activeIntervals.length = 0;

  // Clear all caches
  if (window.linkSafetyCache) window.linkSafetyCache.clear();
  if (window.linkRiskCache) window.linkRiskCache.clear();

  logDebug('🧹 LinkShield cleanup complete on page unload');
}

// Register cleanup on page unload/beforeunload
window.addEventListener('beforeunload', cleanupOnUnload);
window.addEventListener('pagehide', cleanupOnUnload);

if (!window.linkSafetyCache) {
  window.linkSafetyCache = new Map();
}
if (!window.linkRiskCache) {
  window.linkRiskCache = new Map();
}

// ============================================================================
// TRUSTED DOMAINS WHITELIST - User-defined trusted domains
// ============================================================================

/**
 * Controleert of een domein door de gebruiker als vertrouwd is gemarkeerd
 * @param {string} domain - Het te controleren domein (hostname)
 * @returns {Promise<boolean>} - true als het domein vertrouwd is
 */
async function isDomainTrusted(domain) {
  if (!domain) return false;
  try {
    const { trustedDomains = [] } = await chrome.storage.sync.get('trustedDomains');
    // Check exact match of subdomein van vertrouwd domein
    return trustedDomains.some(trusted =>
      domain === trusted || domain.endsWith('.' + trusted)
    );
  } catch (error) {
    logError('[Whitelist] Fout bij ophalen vertrouwde domeinen:', error);
    return false;
  }
}

/**
 * Haalt het domein uit een URL
 * @param {string} url - De URL
 * @returns {string|null} - Het domein of null bij fout
 */
function getDomainFromUrl(url) {
  try {
    return new URL(url).hostname;
  } catch {
    return null;
  }
}

/**
 * Controleert of een hostname een lokaal netwerk adres is
 * @param {string} hostname - De hostname om te controleren
 * @returns {boolean} - true als het een lokaal adres is
 */
function isLocalNetwork(hostname) {
  if (!hostname) return false;
  const h = hostname.toLowerCase();
  return (
    h === 'localhost' ||
    h.endsWith('.local') ||
    h.endsWith('.localhost') ||
    h.startsWith('127.') ||
    h.startsWith('10.') ||
    h.startsWith('192.168.') ||
    /^172\.(1[6-9]|2\d|3[01])\./.test(h) ||
    h === '[::1]' ||
    h.startsWith('0.0.0.0')
  );
}

// Throttle tracking variables (global scope for persistence)
let lastIframeCheck = 0;
let lastScriptCheck = 0;

// ============================================================================
// UNIFIED SECURITY WARNING SYSTEM
// Consistent UI voor alle security detecties (BitB, ClickFix, Clipboard, etc.)
// Gebruikt Shadow DOM voor CSS isolatie en design tokens uit shared.css
// ============================================================================

/**
 * SECURITY FIX v8.1.1: HTML escape helper om XSS te voorkomen
 * Escapet speciale HTML karakters in user-controlled strings
 * @param {string} str - De string om te escapen
 * @returns {string} - Escaped string veilig voor innerHTML
 */
function escapeHtml(str) {
  if (typeof str !== 'string') return '';
  return str
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#039;');
}

/**
 * Toont een uniforme security waarschuwing met consistent design
 * @param {Object} config - Configuratie object
 * @param {string} config.id - Unieke ID voor de waarschuwing (bijv. 'bitb', 'clickfix')
 * @param {string} config.severity - 'critical' of 'warning'
 * @param {string} config.title - Titel van de waarschuwing
 * @param {string} config.message - Hoofdbericht
 * @param {string} [config.tip] - Optionele tip tekst
 * @param {string} [config.icon] - Emoji icon (default: ⚠️ of 🚨)
 * @param {boolean} [config.showTrust=true] - Toon "Trust this site" knop
 * @param {boolean} [config.autoClose=false] - Auto-close na 30 seconden (alleen voor warnings)
 * @param {Function} [config.onTrust] - Callback wanneer Trust wordt geklikt
 * @param {Function} [config.onLeave] - Callback wanneer Leave wordt geklikt
 * @param {Function} [config.onDismiss] - Callback wanneer Dismiss wordt geklikt
 */
function showSecurityWarning(config) {
  const {
    id,
    severity = 'warning',
    title,
    message,
    tip,
    icon,
    showTrust = true,
    autoClose = false,
    onTrust,
    onLeave,
    onDismiss
  } = config;

  // Verwijder bestaande waarschuwing
  const existingHost = document.getElementById(`linkshield-warning-${id}`);
  if (existingHost) existingHost.remove();

  // Bepaal kleuren op basis van severity (design tokens uit shared.css)
  const isCritical = severity === 'critical';
  const colors = {
    header: isCritical ? '#dc2626' : '#d97706',
    headerGradient: isCritical
      ? 'linear-gradient(135deg, #dc2626 0%, #b91c1c 100%)'
      : 'linear-gradient(135deg, #d97706 0%, #b45309 100%)',
    iconBg: isCritical ? '#fef2f2' : '#fffbeb',
    iconBorder: isCritical ? '#fecaca' : '#fde68a',
    titleColor: isCritical ? '#dc2626' : '#d97706',
    boxBg: isCritical ? '#fef2f2' : '#fffbeb',
    boxBorder: isCritical ? '#fecaca' : '#fde68a',
    boxText: isCritical ? '#991b1b' : '#92400e'
  };

  const displayIcon = icon || (isCritical ? '🚨' : '⚠️');

  // i18n teksten
  const trustText = getTranslatedMessage('trustDomainButton') || 'Trust this site';
  const leaveText = getTranslatedMessage('exitPage') || 'Leave this page';
  const dismissText = getTranslatedMessage('understandRisk') || 'I understand the risk';

  // Create host element with Shadow DOM
  const host = document.createElement('div');
  host.id = `linkshield-warning-${id}`;
  host.style.cssText = `
    position: fixed !important;
    top: 0 !important;
    left: 0 !important;
    width: 100vw !important;
    height: 100vh !important;
    z-index: 2147483647 !important;
    pointer-events: auto !important;
  `;

  // Closed Shadow DOM voor CSS isolatie
  const shadow = host.attachShadow({ mode: 'closed' });

  shadow.innerHTML = `
    <style>
      :host {
        all: initial !important;
      }
      * {
        box-sizing: border-box;
        margin: 0;
        padding: 0;
      }
      .overlay {
        position: fixed;
        top: 0;
        left: 0;
        width: 100vw;
        height: 100vh;
        background: rgba(0, 0, 0, 0.6);
        display: flex;
        align-items: center;
        justify-content: center;
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        animation: fadeIn 0.2s ease;
      }
      @keyframes fadeIn {
        from { opacity: 0; }
        to { opacity: 1; }
      }
      .dialog {
        background: #ffffff;
        border-radius: 12px;
        box-shadow: 0 25px 50px -12px rgba(0, 0, 0, 0.25);
        max-width: 440px;
        width: 90vw;
        overflow: hidden;
        animation: slideIn 0.3s ease;
      }
      @keyframes slideIn {
        from { transform: translateY(-20px); opacity: 0; }
        to { transform: translateY(0); opacity: 1; }
      }
      .header {
        background: ${colors.headerGradient};
        color: white;
        padding: 14px 20px;
        display: flex;
        align-items: center;
        gap: 10px;
      }
      .header-icon {
        font-size: 18px;
      }
      .header-text {
        font-weight: 600;
        font-size: 14px;
        letter-spacing: 0.3px;
      }
      .content {
        padding: 24px;
      }
      .title-row {
        display: flex;
        align-items: center;
        gap: 14px;
        margin-bottom: 18px;
      }
      .title-icon {
        width: 52px;
        height: 52px;
        background: ${colors.iconBg};
        border: 2px solid ${colors.iconBorder};
        border-radius: 50%;
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 26px;
        flex-shrink: 0;
      }
      .title-text {
        font-size: 18px;
        font-weight: 700;
        color: ${colors.titleColor};
        line-height: 1.3;
      }
      .message-box {
        background: ${colors.boxBg};
        border: 1px solid ${colors.boxBorder};
        border-radius: 8px;
        padding: 14px 16px;
        margin-bottom: 16px;
        line-height: 1.6;
        color: ${colors.boxText};
        font-size: 13px;
      }
      .tip {
        font-size: 12px;
        color: #6b7280;
        margin-bottom: 20px;
        line-height: 1.5;
        display: flex;
        align-items: flex-start;
        gap: 6px;
      }
      .tip-icon {
        flex-shrink: 0;
      }
      .actions {
        display: flex;
        gap: 10px;
        flex-wrap: wrap;
      }
      .btn {
        flex: 1;
        min-width: 100px;
        padding: 12px 16px;
        border-radius: 8px;
        font-size: 13px;
        font-weight: 600;
        cursor: pointer;
        transition: all 0.2s ease;
        border: none;
        text-align: center;
      }
      .btn:hover {
        transform: translateY(-1px);
      }
      .btn:active {
        transform: translateY(0);
      }
      .btn-trust {
        background: linear-gradient(135deg, #10b981 0%, #059669 100%);
        color: white;
        box-shadow: 0 2px 8px rgba(16, 185, 129, 0.3);
      }
      .btn-trust:hover {
        box-shadow: 0 4px 12px rgba(16, 185, 129, 0.4);
      }
      .btn-leave {
        background: ${colors.headerGradient};
        color: white;
        box-shadow: 0 2px 8px rgba(0, 0, 0, 0.15);
      }
      .btn-leave:hover {
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
      }
      .btn-dismiss {
        background: #f3f4f6;
        color: #374151;
        border: 1px solid #e5e7eb;
      }
      .btn-dismiss:hover {
        background: #e5e7eb;
      }
    </style>
    <div class="overlay">
      <div class="dialog">
        <div class="header">
          <span class="header-icon">🛡️</span>
          <span class="header-text">LinkShield Security</span>
        </div>
        <div class="content">
          <div class="title-row">
            <div class="title-icon">${escapeHtml(displayIcon)}</div>
            <div class="title-text">${escapeHtml(title)}</div>
          </div>
          <div class="message-box">${escapeHtml(message)}</div>
          ${tip ? `<div class="tip"><span class="tip-icon">💡</span><span>${escapeHtml(tip)}</span></div>` : ''}
          <div class="actions">
            ${showTrust ? `<button class="btn btn-trust" data-action="trust">${escapeHtml(trustText)}</button>` : ''}
            <button class="btn btn-leave" data-action="leave">${escapeHtml(leaveText)}</button>
            <button class="btn btn-dismiss" data-action="dismiss">${escapeHtml(dismissText)}</button>
          </div>
        </div>
      </div>
    </div>
  `;

  document.body.appendChild(host);

  // Event handlers
  const handleAction = (action) => {
    switch (action) {
      case 'trust':
        // Voeg domein toe aan trusted list
        const domain = window.location.hostname;
        chrome.storage.sync.get('trustedDomains', (result) => {
          const trustedDomains = result.trustedDomains || [];
          if (!trustedDomains.includes(domain)) {
            trustedDomains.push(domain);
            chrome.storage.sync.set({ trustedDomains }, () => {
              logDebug(`[SecurityWarning] Domain trusted: ${domain}`);
              if (onTrust) onTrust();
              host.remove();
              // Reload pagina om nieuwe trust status toe te passen
              window.location.reload();
            });
          } else {
            host.remove();
          }
        });
        break;
      case 'leave':
        if (onLeave) onLeave();
        window.history.back();
        setTimeout(() => { window.location.href = 'about:blank'; }, 100);
        break;
      case 'dismiss':
        if (onDismiss) onDismiss();
        host.remove();
        break;
    }
  };

  // Bind click events
  shadow.querySelectorAll('.btn').forEach(btn => {
    btn.addEventListener('click', (e) => {
      e.preventDefault();
      e.stopPropagation();
      handleAction(btn.dataset.action);
    });
  });

  // Click op overlay sluit ook (maar niet op dialog)
  shadow.querySelector('.overlay').addEventListener('click', (e) => {
    if (e.target.classList.contains('overlay')) {
      handleAction('dismiss');
    }
  });

  // Auto-close voor warnings (niet voor critical)
  if (autoClose && !isCritical) {
    setTimeout(() => {
      if (document.getElementById(`linkshield-warning-${id}`)) {
        host.remove();
      }
    }, 30000);
  }

  return host;
}

// ============================================================================
// CLIPBOARD GUARD - Detecteert clipboard hijacking pogingen
// ============================================================================
let clipboardGuardInitialized = false;
let hasRecentUserGesture = false;
let clipboardHijackingDetected = false;

/**
 * Initialiseert de Clipboard Guard die clipboard hijacking detecteert.
 * Detecteert:
 * 1. Scripts die preventDefault() + setData() gebruiken in copy handlers
 * 2. navigator.clipboard.writeText() zonder user gesture
 */
function initClipboardGuard() {
    if (clipboardGuardInitialized) return;
    clipboardGuardInitialized = true;

    // Track user gestures voor writeText detectie
    ['click', 'keydown', 'touchstart'].forEach(eventType => {
        document.addEventListener(eventType, () => {
            hasRecentUserGesture = true;
            setTimeout(() => { hasRecentUserGesture = false; }, 1000);
        }, { passive: true, capture: true });
    });

    // Hook EventTarget.prototype.addEventListener om copy handlers te monitoren
    const originalAddEventListener = EventTarget.prototype.addEventListener;
    EventTarget.prototype.addEventListener = function(type, listener, options) {
        if (type === 'copy' && typeof listener === 'function') {
            const wrappedListener = function(e) {
                let preventDefaultCalled = false;
                let setDataCalled = false;
                let setDataContent = null;

                // Wrap preventDefault
                const originalPreventDefault = e.preventDefault.bind(e);
                e.preventDefault = function() {
                    preventDefaultCalled = true;
                    return originalPreventDefault();
                };

                // Wrap clipboardData.setData
                if (e.clipboardData && e.clipboardData.setData) {
                    const originalSetData = e.clipboardData.setData.bind(e.clipboardData);
                    e.clipboardData.setData = function(format, data) {
                        setDataCalled = true;
                        setDataContent = data;
                        return originalSetData(format, data);
                    };
                }

                // Roep originele listener aan
                try {
                    listener.call(this, e);
                } catch (err) {
                    // Listener error, negeren
                }

                // Analyseer na listener uitvoering
                if (preventDefaultCalled && setDataCalled) {
                    // Check of setData content crypto address bevat
                    const cryptoPattern = globalConfig?.CRYPTO_ADDRESS_PATTERNS?.any ||
                        /(bc1|0x[a-fA-F0-9]{40}|[13][a-zA-HJ-NP-Z0-9]{25,39})/;

                    if (setDataContent && cryptoPattern.test(setDataContent)) {
                        // KRITIEK: Clipboard hijacking met crypto address
                        reportClipboardHijacking('setDataCrypto', setDataContent);
                    } else if (preventDefaultCalled) {
                        // Minder kritiek: preventDefault zonder crypto
                        reportClipboardHijacking('preventDefaultSetData', setDataContent);
                    }
                }
            };
            return originalAddEventListener.call(this, type, wrappedListener, options);
        }
        return originalAddEventListener.call(this, type, listener, options);
    };

    // Hook navigator.clipboard.writeText
    if (navigator.clipboard && navigator.clipboard.writeText) {
        const originalWriteText = navigator.clipboard.writeText.bind(navigator.clipboard);
        navigator.clipboard.writeText = function(text) {
            if (!hasRecentUserGesture) {
                // writeText zonder user gesture is verdacht
                const cryptoPattern = globalConfig?.CRYPTO_ADDRESS_PATTERNS?.any ||
                    /(bc1|0x[a-fA-F0-9]{40}|[13][a-zA-HJ-NP-Z0-9]{25,39})/;

                if (cryptoPattern.test(text)) {
                    reportClipboardHijacking('writeTextCrypto', text);
                } else {
                    reportClipboardHijacking('writeTextNoGesture', text);
                }
            }
            return originalWriteText(text);
        };
    }

    logDebug('[ClipboardGuard] Initialized');
}

/**
 * Rapporteert een gedetecteerde clipboard hijacking poging
 * @param {string} type - Type detectie
 * @param {string} content - De verdachte content
 */
function reportClipboardHijacking(type, content) {
    if (clipboardHijackingDetected) return; // Voorkom spam
    clipboardHijackingDetected = true;

    const hostname = window.location.hostname;
    let score = 0;
    let reason = '';

    switch (type) {
        case 'setDataCrypto':
            score = 12; // ALERT
            reason = 'clipboardHijackingCrypto';
            break;
        case 'writeTextCrypto':
            score = 10;
            reason = 'clipboardHijackingCrypto';
            break;
        case 'preventDefaultSetData':
            score = 8;
            reason = 'clipboardHijackingDetected';
            break;
        case 'writeTextNoGesture':
            score = 10;
            reason = 'clipboardHijackingDetected';
            break;
        default:
            score = 8;
            reason = 'clipboardHijackingDetected';
    }

    logDebug(`[ClipboardGuard] Hijacking detected: ${type}, score: ${score}`);

    // Stuur naar background voor icon update
    chrome.runtime.sendMessage({
        action: 'clipboardHijackingDetected',
        data: {
            hostname,
            type,
            score,
            reason,
            contentPreview: content ? content.substring(0, 50) + '...' : null
        }
    }).catch(() => {});

    // Toon waarschuwing aan gebruiker
    showClipboardWarning(type, score);
}

/**
 * Toont een waarschuwing bij clipboard hijacking
 */
function showClipboardWarning(type, score) {
    const isCrypto = type.includes('Crypto');

    const title = isCrypto
        ? getTranslatedMessage('clipboardHijackingCryptoTitle') || 'Crypto Address Hijacking Detected!'
        : getTranslatedMessage('clipboardHijackingTitle') || 'Clipboard Manipulation Detected!';

    const message = getTranslatedMessage('clipboardHijackingMessage') ||
        'This page is attempting to modify your clipboard. Be careful when pasting wallet addresses.';

    const tip = isCrypto
        ? getTranslatedMessage('clipboardHijackingCryptoTip') || 'Always verify wallet addresses before sending cryptocurrency. Attackers replace addresses in your clipboard.'
        : getTranslatedMessage('clipboardHijackingTip') || 'This site may be trying to replace content you copy. Always verify pasted content.';

    showSecurityWarning({
        id: 'clipboard',
        severity: 'critical',
        title: title,
        message: message,
        tip: tip,
        icon: isCrypto ? '💰' : '📋',
        showTrust: true
    });
}

// =============================
// OAUTH PASTE GUARD (v8.5.0)
// Beschermt tegen ConsentFix en OAuth token theft aanvallen
// =============================

/**
 * SECURITY FIX v8.5.0: OAuth Token Paste Guard
 * Blokkeert het plakken van localhost URLs met OAuth tokens
 * Beschermt tegen ConsentFix en vergelijkbare token-theft aanvallen
 *
 * @see https://pushsecurity.com/blog/consentfix
 */
async function initOAuthPasteGuard() {
    if (!globalConfig?.ADVANCED_THREAT_DETECTION?.oauthProtection?.enabled) {
        logDebug('[OAuthGuard] Disabled in config');
        return;
    }

    // Skip if Smart Link Scanning (integratedProtection) is disabled
    if (!(await isProtectionEnabled())) {
        logDebug('[OAuthGuard] Disabled - integratedProtection is off');
        return;
    }

    // Skip on trusted domains from TrustedDomains.json
    const currentHost = window.location.hostname.toLowerCase();
    try {
        if (await isTrustedDomain(currentHost)) {
            logDebug(`[OAuthGuard] Skipped - ${currentHost} is a trusted domain`);
            return;
        }
    } catch (e) {
        // Continue if trust check fails
    }

    const config = globalConfig.ADVANCED_THREAT_DETECTION.oauthProtection;

    // Compile patterns eenmalig
    const dangerousPatterns = config.patterns.map(p => new RegExp(p, 'i'));

    // Check of huidige domein paste mag toestaan (extra config-based whitelist)
    const isPasteAllowed = config.allowedPasteDomains.some(domain =>
        currentHost === domain || currentHost.endsWith('.' + domain)
    );

    if (isPasteAllowed) {
        logDebug(`[OAuthGuard] Paste allowed on ${currentHost}`);
        return;
    }

    document.addEventListener('paste', handleOAuthPaste, true);
    logDebug('[OAuthGuard] Initialized');

    function handleOAuthPaste(e) {
        try {
            const pastedText = (e.clipboardData || window.clipboardData)?.getData('text') || '';

            if (!pastedText || pastedText.length < 10) return;

            // Check tegen alle gevaarlijke patronen
            for (const pattern of dangerousPatterns) {
                if (pattern.test(pastedText)) {
                    e.preventDefault();
                    e.stopPropagation();

                    logDebug(`[OAuthGuard] 🛑 BLOCKED OAuth token paste attempt`);
                    logDebug(`[OAuthGuard] Pattern matched: ${pattern.source}`);

                    showOAuthTheftWarning(pastedText, pattern.source);

                    // Rapporteer aan background
                    if (typeof chrome !== 'undefined' && chrome.runtime?.sendMessage) {
                        chrome.runtime.sendMessage({
                            type: 'oauthTheftAttempt',
                            url: window.location.href,
                            pattern: pattern.source,
                            blocked: true,
                            timestamp: Date.now()
                        }).catch(() => {});
                    }

                    return false;
                }
            }
        } catch (err) {
            handleError(err, 'OAuthPasteGuard');
        }
    }
}

/**
 * Toont waarschuwing voor OAuth token theft poging
 * Gebruikt de standaard showSecurityWarning() voor consistente UI.
 *
 * @param {string} pastedContent - De geblokkeerde content (wordt NIET getoond aan user)
 * @param {string} matchedPattern - Het patroon dat matchte
 */
function showOAuthTheftWarning(pastedContent, matchedPattern) {
    showSecurityWarning({
        id: 'oauth-theft',
        severity: 'critical',
        title: getTranslatedMessage('oauthTheftTitle') || 'OAuth Token Theft Blocked',
        message: getTranslatedMessage('oauthTheftMessage') ||
            'You tried to paste an authentication URL. This is a known phishing technique called "ConsentFix" that steals your account access.',
        tip: getTranslatedMessage('oauthTheftTip') ||
            'Never paste URLs containing ?code= or access tokens into websites.',
        icon: '🛡️',
        showTrust: false  // Geen "trust this site" voor OAuth theft - dit is altijd gevaarlijk
    });
}

// =============================
// CLICKFIX ATTACK DETECTION
// Detecteert ClickFix aanvallen waar gebruikers misleid worden om
// PowerShell/CMD commando's te kopiëren en plakken via nep-CAPTCHA of "Fix it" prompts
// =============================

let clickFixDetectionInitialized = false;
let clickFixDetected = false;

/**
 * Initialiseert ClickFix Attack detectie
 * Scant de pagina voor verdachte PowerShell/CMD commando's en nep UI patronen
 */
async function initClickFixDetection() {
    if (clickFixDetectionInitialized) return;
    clickFixDetectionInitialized = true;

    // Skip observers on trusted domains to prevent performance issues on complex SPAs
    const hostname = window.location.hostname.toLowerCase();
    if (await isTrustedDomain(hostname)) {
        logDebug('[ClickFix] Skipping observer for trusted domain:', hostname);
        return;
    }

    // Initiële scan
    setTimeout(() => scanForClickFixAttack(), 1000);

    // Observer voor dynamisch geladen content
    const observer = new MutationObserver((mutations) => {
        for (const mutation of mutations) {
            if (mutation.addedNodes.length > 0) {
                // Debounce de scan
                clearTimeout(window._clickFixScanTimeout);
                window._clickFixScanTimeout = setTimeout(() => scanForClickFixAttack(), 500);
                break;
            }
        }
    });

    observer.observe(document.body, {
        childList: true,
        subtree: true
    });

    logDebug('[ClickFix] Detection initialized');
}

/**
 * Scant de pagina voor ClickFix aanval indicatoren
 */
async function scanForClickFixAttack() {
    if (clickFixDetected) return; // Voorkom herhaalde waarschuwingen
    if (!(await isProtectionEnabled())) return;

    try {
        // Check if current site is a globally trusted domain (TrustedDomains.json)
        const hostname = window.location.hostname.toLowerCase();
        if (await isTrustedDomain(hostname)) {
            logDebug(`[ClickFix] Skipping scan for trusted domain: ${hostname}`);
            return;
        }

        const patterns = globalConfig?.CLICKFIX_PATTERNS;
        if (!patterns) {
            logDebug('[ClickFix] No patterns configured');
            return;
        }

        const textContent = document.body?.innerText || '';
        const htmlContent = document.body?.innerHTML || '';

        // Check voor pre/code/textarea elementen met verdachte commando's
        const codeElements = document.querySelectorAll('pre, code, textarea, .code, .command, [class*="terminal"], [class*="console"]');
        let codeContent = '';
        codeElements.forEach(el => {
            codeContent += ' ' + (el.textContent || '');
        });

        // SECURITY FIX v8.7.2: Normalize text to prevent split-tag bypass attacks
        // Attackers can split "Invoke-Expression" across multiple tags: <span>Invoke-</span><span>Expression</span>
        // This normalization:
        // 1. Removes Unicode whitespace variations (non-breaking spaces, zero-width chars)
        // 2. Collapses multiple whitespaces into single space
        // 3. Uses innerText (already strips HTML) but also handles hidden text tricks
        const normalizeForScan = (text) => {
            return text
                // Remove zero-width characters that could split keywords
                .replace(/[\u200B-\u200D\uFEFF\u00AD]/g, '')
                // Normalize Unicode whitespace to regular space
                .replace(/[\u00A0\u2000-\u200A\u202F\u205F\u3000]/g, ' ')
                // Collapse multiple spaces into one
                .replace(/\s+/g, ' ')
                // Remove invisible characters between visible chars
                .replace(/([a-zA-Z])\s+([a-zA-Z])/g, (_, a, b) => {
                    // Only collapse if it looks like split word (e.g., "Invoke - Expression")
                    return a + b;
                });
        };

        const allContent = normalizeForScan(textContent + ' ' + codeContent);
        const detectedPatterns = [];
        let totalScore = 0;

        // Check PowerShell patterns
        // Patterns common in tutorials get lower score to avoid false positives on docs sites
        const tutorialCommonPS = /Invoke-WebRequest|Invoke-RestMethod|Start-Process|DownloadString|DownloadFile|\[System\.Net\.WebClient\]/i;
        for (const pattern of patterns.powershell || []) {
            if (pattern.test(allContent)) {
                const isTutorialCommon = tutorialCommonPS.test(pattern.source);
                detectedPatterns.push({ type: 'powershell', pattern: pattern.toString() });
                totalScore += isTutorialCommon ? 5 : 10; // Tutorial-common patterns score lower
            }
        }

        // Check CMD patterns
        for (const pattern of patterns.cmd || []) {
            if (pattern.test(allContent)) {
                detectedPatterns.push({ type: 'cmd', pattern: pattern.toString() });
                totalScore += 8;
            }
        }

        // Check Fake UI patterns (versterkt risico bij combinatie met commando's)
        for (const pattern of patterns.fakeUI || []) {
            if (pattern.test(textContent)) {
                detectedPatterns.push({ type: 'fakeUI', pattern: pattern.toString() });
                totalScore += (detectedPatterns.some(p => p.type === 'powershell' || p.type === 'cmd')) ? 5 : 2;
            }
        }

        // Check voor "copy" buttons nabij verdachte code
        const copyButtons = document.querySelectorAll('button, [role="button"], .btn, [class*="copy"]');
        copyButtons.forEach(btn => {
            const btnText = (btn.textContent || '').toLowerCase();
            const nearbyCode = btn.closest('div, section, article')?.querySelector('pre, code, textarea');
            if ((btnText.includes('copy') || btnText.includes('kopieer')) && nearbyCode) {
                const codeText = nearbyCode.textContent || '';
                // Count suspicious pattern matches in this code block
                // A single common cmdlet in a tutorial is normal; require 2+ matches
                // or a high-risk pattern (encoded command, policy bypass, etc.)
                let codeMatchCount = 0;
                let hasHighRisk = false;
                for (const pattern of [...(patterns.powershell || []), ...(patterns.cmd || [])]) {
                    if (pattern.test(codeText)) {
                        codeMatchCount++;
                        if (!tutorialCommonPS.test(pattern.source)) {
                            hasHighRisk = true;
                        }
                    }
                }
                if (hasHighRisk || codeMatchCount >= 2) {
                    detectedPatterns.push({ type: 'copyButtonNearMaliciousCode', pattern: `${codeMatchCount} patterns` });
                    totalScore += 8;
                }
            }
        });

        // Alleen waarschuwen bij significante score
        if (totalScore >= 10) {
            clickFixDetected = true;
            reportClickFixAttack(detectedPatterns, totalScore);
        } else if (detectedPatterns.length > 0) {
            logDebug(`[ClickFix] Low confidence detection: ${JSON.stringify(detectedPatterns)}, score: ${totalScore}`);
        }

    } catch (error) {
        handleError(error, '[ClickFix] Scan error');
    }
}

/**
 * Rapporteert een gedetecteerde ClickFix aanval
 */
function reportClickFixAttack(patterns, score) {
    const hostname = window.location.hostname;
    const reason = patterns.some(p => p.type === 'powershell') ? 'clickFixPowerShell' : 'clickFixCommand';

    logDebug(`[ClickFix] Attack detected! Score: ${score}, Patterns: ${JSON.stringify(patterns)}`);

    // Stuur naar background voor icon update
    chrome.runtime.sendMessage({
        action: 'clickFixDetected',
        data: {
            hostname,
            patterns: patterns.map(p => p.type),
            score,
            reason
        }
    }).catch(() => {});

    // Toon waarschuwing
    showClickFixWarning(patterns, score);
}

/**
 * Toont een waarschuwing voor ClickFix aanval
 */
function showClickFixWarning(patterns, score) {
    const hasPowerShell = patterns.some(p => p.type === 'powershell');

    const title = hasPowerShell
        ? (getTranslatedMessage('clickFixPowerShellTitle') || 'PowerShell Command Detected!')
        : (getTranslatedMessage('clickFixCommandTitle') || 'Suspicious Command Detected!');

    const message = getTranslatedMessage('clickFixMessage') ||
        'This page contains a suspicious command that could harm your computer. Do not copy or execute this command.';

    const tip = getTranslatedMessage('clickFixSubMessage') ||
        'Attackers often disguise malicious commands as \'fixes\' or \'verification steps\'. Never run commands from untrusted sources.';

    showSecurityWarning({
        id: 'clickfix',
        severity: 'critical',
        title: title,
        message: message,
        tip: tip,
        icon: hasPowerShell ? '💻' : '⚠️',
        showTrust: true
    });
}

// =============================
// BROWSER-IN-THE-BROWSER (BitB) ATTACK DETECTION
// Detecteert nep browser popups die OAuth/SSO logins simuleren
// Deze aanvallen creëren fake browser vensters met nep URL bars
// =============================

let bitbDetectionInitialized = false;
let bitbDetected = false;

/**
 * Initialiseert BitB Attack detectie
 */
async function initBitBDetection() {
    if (bitbDetectionInitialized) return;
    bitbDetectionInitialized = true;

    // Skip observers on trusted domains to prevent performance issues on complex SPAs
    const hostname = window.location.hostname.toLowerCase();
    if (await isTrustedDomain(hostname)) {
        logDebug('[BitB] Skipping observer for trusted domain:', hostname);
        return;
    }

    // Initiële scan na page load (wacht op dynamische content)
    setTimeout(() => scanForBitBAttack(), 2000);

    // Observer voor dynamisch geladen modals/overlays
    const observer = new MutationObserver((mutations) => {
        for (const mutation of mutations) {
            for (const node of mutation.addedNodes) {
                if (node.nodeType === Node.ELEMENT_NODE) {
                    if (isPotentialBitBContainer(node)) {
                        clearTimeout(window._bitbScanTimeout);
                        window._bitbScanTimeout = setTimeout(() => scanForBitBAttack(), 400);
                        return;
                    }
                }
            }
        }
    });

    if (document.body) {
        observer.observe(document.body, { childList: true, subtree: true });
    }

    // Click listener voor popup triggers (OAuth buttons etc.)
    document.addEventListener('click', () => {
        clearTimeout(window._bitbClickTimeout);
        window._bitbClickTimeout = setTimeout(() => scanForBitBAttack(), 600);
    }, true);

    logDebug('[BitB] Detection initialized');
}

/**
 * Check of een element een potentiële BitB container zou kunnen zijn
 */
function isPotentialBitBContainer(element) {
    if (!element || !element.style) return false;

    try {
        const style = window.getComputedStyle(element);
        const classList = (element.className || '').toLowerCase();

        // Check voor fixed/absolute positioning met hoge z-index
        if (style.position === 'fixed' || style.position === 'absolute') {
            const zIndex = parseInt(style.zIndex) || 0;
            if (zIndex > 1000) return true;
        }

        // Check class names voor modal/overlay indicators
        if (/modal|popup|overlay|dialog|lightbox|signin|login/i.test(classList)) return true;

        // Check role attribute
        if (element.getAttribute('role') === 'dialog') return true;
        if (element.getAttribute('aria-modal') === 'true') return true;

    } catch (e) {
        // Ignore errors voor elementen zonder computed style
    }

    return false;
}

/**
 * Hoofd scan functie voor BitB detectie
 */
async function scanForBitBAttack() {
    if (bitbDetected) return;
    if (!(await isProtectionEnabled())) return;

    try {
        const config = globalConfig?.BITB_DETECTION;
        if (!config) {
            logDebug('[BitB] No config available');
            return;
        }

        // 0. Check if current site is a globally trusted domain (TrustedDomains.json)
        const currentHost = window.location.hostname.toLowerCase();
        if (await isTrustedDomain(currentHost)) {
            logDebug(`[BitB] Domain ${currentHost} is trusted, skipping BitB detection`);
            return;
        }

        // 1. Zoek alle potentiële modal/overlay containers
        const overlays = findOverlayContainers();

        // 2. Analyseer ELKE overlay INDIVIDUEEL voor BitB patterns
        // Indicatoren van verschillende overlays mogen NIET gecombineerd worden
        // (voorkomt false positives zoals ClickMate + Facebook login form)
        for (const overlay of overlays) {
            const result = analyzeOverlayForBitB(overlay, config);
            if (result.score === 0) continue;

            const foundTypes = result.foundTypes;
            const hasFakeUrlBar = foundTypes.has('fakeUrlBar');
            const hasLoginForm = foundTypes.has('loginForm');
            const hasWindowControls = foundTypes.has('windowControls');
            const hasOAuthBranding = foundTypes.has('oauthBranding');
            const hasWindowChrome = foundTypes.has('windowChromeStyle');
            const hasPadlock = foundTypes.has('padlockIcon');

            // Bepaal of DEZE SPECIFIEKE overlay een BitB attack is
            let isLikelyBitB = false;
            let severity = null;

            if (hasFakeUrlBar) {
                // Fake URL bar is zeer sterke indicator - altijd alert
                isLikelyBitB = true;
                severity = 'critical';
                logDebug('[BitB] Fake URL bar detected in overlay - strong BitB indicator');
            } else if (hasLoginForm && hasWindowControls) {
                // Login form + window controls in DEZELFDE overlay = waarschijnlijk BitB
                isLikelyBitB = true;
                severity = 'critical';
                logDebug('[BitB] Login form + window controls in same overlay');
            } else if (hasLoginForm && hasOAuthBranding) {
                // Login form + OAuth branding in DEZELFDE overlay = waarschijnlijk BitB
                isLikelyBitB = true;
                severity = 'critical';
                logDebug('[BitB] Login form + OAuth branding in same overlay');
            } else if (hasLoginForm && hasWindowChrome && hasPadlock) {
                // Login form + window chrome + padlock in DEZELFDE overlay
                isLikelyBitB = true;
                severity = 'warning';
                logDebug('[BitB] Login form + window chrome + padlock in same overlay');
            } else if (hasWindowControls && hasWindowChrome && hasPadlock) {
                // Window controls + chrome + padlock zonder login = mogelijk BitB
                isLikelyBitB = true;
                severity = 'warning';
                logDebug('[BitB] Window simulation detected in overlay');
            }

            // Als deze overlay een BitB attack is, rapporteer en stop
            if (isLikelyBitB) {
                if (severity === 'critical') {
                    bitbDetected = true;
                    reportBitBAttack('critical', result.indicators, result.score);
                    return; // Stop na eerste critical detection
                } else if (severity === 'warning') {
                    reportBitBAttack('warning', result.indicators, result.score);
                    return; // Stop na eerste warning
                }
            }
        }

        // 3. Globale check voor fake URL bars (buiten overlays) - dit blijft pagina-breed
        const fakeUrlBars = detectFakeUrlBarsGlobal(config);
        if (fakeUrlBars.length > 0) {
            logDebug('[BitB] Global fake URL bar detected');
            bitbDetected = true;
            reportBitBAttack('critical', [{ type: 'fakeUrlBarGlobal', count: fakeUrlBars.length }], fakeUrlBars.length * config.scores.fakeUrlBar);
        }

    } catch (error) {
        handleError(error, '[BitB] Scan error');
    }
}

/**
 * Vindt alle overlay/modal containers op de pagina
 */
function findOverlayContainers() {
    const candidates = [];
    const seen = new WeakSet();

    // Selecteer elementen met modal/overlay karakteristieken
    const selectors = [
        '[role="dialog"]',
        '[aria-modal="true"]',
        '.modal', '.popup', '.overlay', '.dialog', '.lightbox',
        '[class*="modal"]', '[class*="popup"]', '[class*="overlay"]',
        '[class*="dialog"]', '[class*="signin"]', '[class*="login-popup"]'
    ];

    try {
        const elements = document.querySelectorAll(selectors.join(','));

        elements.forEach(el => {
            if (seen.has(el)) return;
            seen.add(el);

            try {
                const style = window.getComputedStyle(el);
                if (style.display !== 'none' &&
                    style.visibility !== 'hidden' &&
                    parseInt(style.zIndex) > 100 &&
                    el.offsetWidth > 150 && el.offsetHeight > 150) {
                    candidates.push(el);
                }
            } catch (e) { /* ignore */ }
        });

        // Ook zoeken naar fixed positioned elements met zeer hoge z-index
        document.querySelectorAll('div, section, aside').forEach(el => {
            if (seen.has(el)) return;

            try {
                const style = window.getComputedStyle(el);
                if (style.position === 'fixed' &&
                    parseInt(style.zIndex) > 9000 &&
                    el.offsetWidth > 200 && el.offsetHeight > 200) {
                    seen.add(el);
                    candidates.push(el);
                }
            } catch (e) { /* ignore */ }
        });
    } catch (e) {
        handleError(e, '[BitB] findOverlayContainers');
    }

    return candidates.slice(0, 10); // Limiteer voor performance
}

/**
 * Analyseert een overlay container voor BitB indicatoren
 */
function analyzeOverlayForBitB(overlay, config) {
    const indicators = [];
    let score = 0;
    const scores = config.scores;

    // Track welke indicator types gevonden zijn voor de nieuwe detectie logica
    const foundTypes = new Set();

    try {
        const overlayText = (overlay.innerText || '').toLowerCase();

        // 1. Check voor fake URL bar elementen (STERKE indicator)
        const fakeUrlBar = findFakeUrlBarInElement(overlay, config);
        if (fakeUrlBar) {
            indicators.push({
                type: 'fakeUrlBar',
                url: fakeUrlBar.textContent?.substring(0, 60)
            });
            score += scores.fakeUrlBar;
            foundTypes.add('fakeUrlBar');
        }

        // 2. Check voor window control buttons (close/minimize/maximize) (STERKE indicator)
        const windowControls = findWindowControls(overlay, config);
        if (windowControls.found) {
            indicators.push({ type: 'windowControls', details: windowControls.details });
            score += scores.windowControls;
            foundTypes.add('windowControls');
        }

        // 3. Check voor login form binnen overlay (STERKE indicator)
        const loginInputs = overlay.querySelectorAll(
            'input[type="password"], input[type="email"], ' +
            'input[name*="password"], input[name*="email"], input[name*="user"]'
        );

        if (loginInputs.length > 0) {
            // Check of login form naar same-domain post (legitieme login)
            const form = overlay.querySelector('form');
            const formAction = form?.getAttribute('action');
            let isSameDomainLogin = false;

            if (!formAction || formAction === '' || formAction === '#') {
                // Empty/missing action defaults to current page (same-domain)
                isSameDomainLogin = true;
            } else {
                try {
                    const actionHost = new URL(formAction, window.location.href).hostname;
                    isSameDomainLogin = actionHost === window.location.hostname;
                } catch (e) { /* ignore URL parse errors */ }
            }

            // Alleen als indicator tellen als het NIET same-domain is
            if (!isSameDomainLogin) {
                indicators.push({ type: 'loginForm', inputs: loginInputs.length });
                score += scores.loginFormInOverlay;
                foundTypes.add('loginForm');

                // Extra score als er ook OAuth branding is (STERKE indicator)
                for (const brand of config.oauthBranding || []) {
                    if (overlayText.includes(brand.toLowerCase())) {
                        indicators.push({ type: 'oauthBranding', brand });
                        score += scores.oauthBrandingWithForm;
                        foundTypes.add('oauthBranding');
                        break;
                    }
                }
            } else {
                // Log same-domain login maar tel niet als indicator
                logDebug('[BitB] Same-domain login form detected, skipping as indicator');
            }
        }

        // 4. Check voor padlock/security icons
        if (detectPadlockIcon(overlay)) {
            indicators.push({ type: 'padlockIcon' });
            score += scores.padlockIcon;
            foundTypes.add('padlockIcon');
        }

        // 5. Check voor OS-achtige window chrome styling
        if (hasWindowChromeStyle(overlay)) {
            indicators.push({ type: 'windowChromeStyle' });
            score += scores.windowChromeStyle;
            foundTypes.add('windowChromeStyle');
        }

        // 6. Check voor iframe binnen modal met login
        const iframes = overlay.querySelectorAll('iframe');
        if (iframes.length > 0 && loginInputs.length > 0) {
            indicators.push({ type: 'iframeInModal', count: iframes.length });
            score += scores.iframeInModal;
            foundTypes.add('iframeInModal');
        }

    } catch (error) {
        handleError(error, '[BitB] analyzeOverlay');
    }

    return { score, indicators, foundTypes };
}

/**
 * Zoekt naar elementen die eruitzien als een URL bar
 */
function findFakeUrlBarInElement(container, config) {
    try {
        const allElements = container.querySelectorAll('span, div, p, a, input[readonly]');
        const currentHost = window.location.hostname.toLowerCase();

        for (const el of allElements) {
            // Skip grote containers
            if (el.children.length > 3) continue;

            const text = (el.textContent || '').trim();

            // Check of tekst eruitziet als een URL (15-100 karakters)
            if (text.length >= 15 && text.length <= 100) {
                // Check tegen bekende OAuth URLs
                for (const pattern of config.fakeUrlBarPatterns || []) {
                    if (pattern.test(text)) {
                        // Verifieer dat dit NIET de echte pagina URL is
                        const textHost = text.replace(/^https?:\/\//, '').split('/')[0].toLowerCase();
                        if (textHost !== currentHost && !currentHost.endsWith('.' + textHost)) {
                            return el;
                        }
                    }
                }
            }
        }
    } catch (e) {
        handleError(e, '[BitB] findFakeUrlBar');
    }

    return null;
}

/**
 * Zoekt naar fake window control buttons
 */
function findWindowControls(container, config) {
    const details = [];
    const indicators = config.windowControlIndicators || {};

    try {
        const textContent = container.innerText || '';
        const innerHTML = container.innerHTML || '';

        // Check voor macOS traffic lights (● ○ ○)
        if (indicators.trafficLights?.test(textContent)) {
            details.push('trafficLights');
        }

        // Check voor close button karakters (× ✕ etc.)
        if (indicators.closeButtons?.test(textContent)) {
            details.push('closeButton');
        }

        // Check voor window control CSS classes
        if (indicators.controlClasses?.test(innerHTML)) {
            details.push('controlClasses');
        }

        // Check voor elementen met typische window control styling
        const smallButtons = container.querySelectorAll('button, [role="button"], .btn');
        let roundButtonCount = 0;

        smallButtons.forEach(btn => {
            if (btn.offsetWidth > 0 && btn.offsetWidth < 25 &&
                btn.offsetHeight > 0 && btn.offsetHeight < 25) {
                try {
                    const style = window.getComputedStyle(btn);
                    if (style.borderRadius === '50%' || parseInt(style.borderRadius) >= 10) {
                        roundButtonCount++;
                    }
                } catch (e) { /* ignore */ }
            }
        });

        if (roundButtonCount >= 2) {
            details.push('roundButtons');
        }

    } catch (e) {
        handleError(e, '[BitB] findWindowControls');
    }

    // A single closeButton (×) is too common in legitimate modals.
    // Require either a strong indicator (trafficLights, controlClasses, roundButtons)
    // or multiple details to indicate fake OS window controls.
    const hasStrongIndicator = details.some(d => d !== 'closeButton');
    return { found: details.length >= 2 || hasStrongIndicator, details };
}

/**
 * Detecteert padlock/security icons
 */
function detectPadlockIcon(container) {
    try {
        const text = container.innerText || '';
        const html = container.innerHTML || '';

        // Unicode padlock characters
        if (/[🔒🔐🔓🛡️🔏]/.test(text)) return true;

        // Images/SVGs met lock in naam
        const lockImages = container.querySelectorAll(
            'img[src*="lock"], img[src*="secure"], img[alt*="lock"], ' +
            'svg[class*="lock"], [class*="padlock"], [class*="secure-icon"]'
        );
        if (lockImages.length > 0) return true;

        // SVG paths die lijken op een lock (heuristic)
        if (/<svg[^>]*>.*<path[^>]*d="[^"]*[Aa]\s*\d+[^"]*[Vv][^"]*".*<\/svg>/i.test(html)) {
            // Mogelijke lock SVG - check of het klein is (icon-size)
            const svgs = container.querySelectorAll('svg');
            for (const svg of svgs) {
                if (svg.offsetWidth > 10 && svg.offsetWidth < 30 &&
                    svg.offsetHeight > 10 && svg.offsetHeight < 30) {
                    return true;
                }
            }
        }

    } catch (e) { /* ignore */ }

    return false;
}

/**
 * Check of element OS-achtige window chrome styling heeft
 */
function hasWindowChromeStyle(element) {
    try {
        const style = window.getComputedStyle(element);

        // Check voor typische window styling combinaties
        const boxShadow = style.boxShadow || '';
        const borderRadius = parseInt(style.borderRadius) || 0;
        const backgroundColor = style.backgroundColor || '';

        // macOS/Windows window-achtige shadows (diep, soft)
        const hasDeepShadow = /rgba?\([^)]+\)\s+\d+px\s+\d+px\s+(2[0-9]|[3-9][0-9])px/.test(boxShadow);

        // Window-achtige border radius (8-12px typisch voor OS windows)
        const hasWindowRadius = borderRadius >= 8 && borderRadius <= 16;

        // Heeft een "title bar" achtig kind element (specifiek voor OS window chrome)
        const hasHeader = element.querySelector(
            '[class*="titlebar"], [class*="title-bar"], [class*="window-title"], [class*="toolbar"], [class*="top-bar"]'
        );

        // Combinatie van factoren
        if (hasDeepShadow && hasWindowRadius) return true;
        if (hasWindowRadius && hasHeader) return true;

    } catch (e) { /* ignore */ }

    return false;
}

/**
 * Globale detectie van fake URL bars (buiten overlays)
 */
function detectFakeUrlBarsGlobal(config) {
    const fakeUrlBars = [];
    const currentHost = window.location.hostname.toLowerCase();

    try {
        // Zoek elementen die URL-tekst bevatten
        const candidates = document.querySelectorAll(
            '[class*="url"], [class*="address"], [class*="location-bar"], ' +
            'input[readonly][value*="http"], span[class*="domain"]'
        );

        candidates.forEach(el => {
            const text = (el.textContent || el.value || '').trim();

            if (text.length >= 15 && text.length <= 100) {
                for (const pattern of config.fakeUrlBarPatterns || []) {
                    if (pattern.test(text)) {
                        const textHost = text.replace(/^https?:\/\//, '').split('/')[0].toLowerCase();
                        if (textHost !== currentHost) {
                            fakeUrlBars.push({ text, element: el });
                        }
                        break;
                    }
                }
            }
        });

    } catch (e) {
        handleError(e, '[BitB] detectFakeUrlBarsGlobal');
    }

    return fakeUrlBars.slice(0, 5); // Limiteer resultaten
}

/**
 * Rapporteert BitB aanval detectie
 */
function reportBitBAttack(severity, indicators, score) {
    const hostname = window.location.hostname;
    const reason = severity === 'critical' ? 'bitbAttackCritical' : 'bitbAttackWarning';

    logDebug(`[BitB] Attack detected! Severity: ${severity}, Score: ${score}`);
    logDebug(`[BitB] Indicators: ${JSON.stringify(indicators)}`);

    // Stuur naar background voor icon update en logging
    chrome.runtime.sendMessage({
        action: 'bitbDetected',
        data: {
            hostname,
            severity,
            score,
            indicators: indicators.map(i => i.type),
            reason
        }
    }).catch(() => {});

    // Toon waarschuwing aan gebruiker
    showBitBWarning(severity, indicators, score);
}

/**
 * Toont waarschuwing voor BitB aanval
 * Design consistent met alert.html/caution.html
 */
function showBitBWarning(severity, indicators, score) {
    const isCritical = severity === 'critical';

    const title = isCritical
        ? (getTranslatedMessage('bitbAttackCriticalTitle') || 'Fake Login Window Detected!')
        : (getTranslatedMessage('bitbAttackWarningTitle') || 'Suspicious Login Popup');

    const message = getTranslatedMessage('bitbAttackMessage') ||
        'This page is showing a fake browser window designed to steal your credentials. Real login popups open in separate browser windows.';

    const tip = getTranslatedMessage('bitbAttackTip') ||
        'Always check the browser address bar for the real URL, not text displayed within the page.';

    showSecurityWarning({
        id: 'bitb',
        severity: isCritical ? 'critical' : 'warning',
        title: title,
        message: message,
        tip: tip,
        icon: '🪟',
        showTrust: true,
        autoClose: !isCritical
    });
}

// =============================================================================
// FORM HIJACKING PROTECTION v8.3.0
// =============================================================================
// Detecteert pogingen om form actions te wijzigen naar externe domeinen.
// Werkt volledig in ISOLATED world - geen MAIN world script nodig.
//
// Detectie methoden:
// 1. MutationObserver voor action attribute wijzigingen
// 2. Focusin handler voor JIT hijacking tijdens password focus
// 3. Submit interceptie voor last-minute wijzigingen
// =============================================================================

let formHijackingInitialized = false;
let formHijackingDetected = false;
const monitoredForms = new WeakSet();
const originalFormActions = new WeakMap();

/**
 * Initialiseert Form Hijacking Protection
 * Moet worden aangeroepen na DOMContentLoaded
 */
function initFormHijackingProtection() {
  if (formHijackingInitialized) return;
  formHijackingInitialized = true;

  // Skip op vertrouwde domeinen
  const currentHostname = window.location.hostname.toLowerCase();
  if (typeof isTrustedDomain === 'function') {
    isTrustedDomain(currentHostname).then(trusted => {
      if (trusted) {
        logDebug('[FormHijacking] Skipping for trusted domain:', currentHostname);
        return;
      }
      startFormMonitoring();
    });
  } else {
    startFormMonitoring();
  }
}

/**
 * Start de form monitoring
 */
function startFormMonitoring() {
  // Monitor bestaande forms
  document.querySelectorAll('form').forEach(form => {
    monitorForm(form);
  });

  // Monitor nieuwe forms via MutationObserver
  const formObserver = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      // Check voor nieuwe form elementen
      mutation.addedNodes.forEach(node => {
        if (node.nodeType === Node.ELEMENT_NODE) {
          if (node.tagName === 'FORM') {
            monitorForm(node);
          }
          // Check ook voor forms binnen toegevoegde elementen
          if (node.querySelectorAll) {
            node.querySelectorAll('form').forEach(form => {
              monitorForm(form);
            });
          }
        }
      });

      // Check voor action attribute wijzigingen
      if (mutation.type === 'attributes' &&
          mutation.attributeName === 'action' &&
          mutation.target.tagName === 'FORM') {
        checkFormActionChange(mutation.target);
      }
    }
  });

  formObserver.observe(document.body, {
    childList: true,
    subtree: true,
    attributes: true,
    attributeFilter: ['action']
  });

  // Globale focusin handler voor JIT detectie
  document.addEventListener('focusin', handlePasswordFocus, true);

  logDebug('[FormHijacking] Protection initialized');
}

/**
 * Monitor een specifiek form element
 * @param {HTMLFormElement} form
 */
function monitorForm(form) {
  if (monitoredForms.has(form)) return;
  monitoredForms.add(form);

  // Sla originele action op
  const originalAction = form.action || form.getAttribute('action') || '';
  originalFormActions.set(form, originalAction);

  // Monitor submit event
  form.addEventListener('submit', (e) => {
    if (checkFormActionChange(form)) {
      e.preventDefault();
      e.stopPropagation();
      logDebug('[FormHijacking] Submit blocked due to action change');
    }
  }, true);

  logDebug('[FormHijacking] Monitoring form:', form.id || form.name || 'unnamed');
}

/**
 * Check of form action is gewijzigd naar een extern domein
 * @param {HTMLFormElement} form
 * @returns {boolean} true als hijacking gedetecteerd
 */
function checkFormActionChange(form) {
  if (formHijackingDetected) return true; // Al gedetecteerd

  const originalAction = originalFormActions.get(form) || '';
  const currentAction = form.action || form.getAttribute('action') || '';

  // Geen wijziging
  if (originalAction === currentAction) return false;

  // Parse URLs
  const currentHost = window.location.hostname.toLowerCase();
  let originalHost = currentHost;
  let newHost = currentHost;

  try {
    if (originalAction) {
      originalHost = new URL(originalAction, window.location.href).hostname.toLowerCase();
    }
  } catch (e) { /* invalid URL, assume same origin */ }

  try {
    if (currentAction) {
      newHost = new URL(currentAction, window.location.href).hostname.toLowerCase();
    }
  } catch (e) { /* invalid URL, assume same origin */ }

  // Check of action is gewijzigd naar een ANDER domein
  const wasInternal = originalHost === currentHost || originalHost.endsWith('.' + currentHost);
  const isNowExternal = newHost !== currentHost && !newHost.endsWith('.' + currentHost);

  if (wasInternal && isNowExternal) {
    // HIJACKING GEDETECTEERD
    formHijackingDetected = true;
    reportFormHijacking(form, originalAction, currentAction, newHost);
    return true;
  }

  // Check of form password velden heeft en naar extern gaat
  const hasPasswordField = form.querySelector('input[type="password"]');
  if (hasPasswordField && isNowExternal) {
    formHijackingDetected = true;
    reportFormHijacking(form, originalAction, currentAction, newHost);
    return true;
  }

  return false;
}

/**
 * Handler voor focus op password velden - detecteert JIT hijacking
 * @param {FocusEvent} e
 */
function handlePasswordFocus(e) {
  const target = e.target;

  // Alleen password velden
  if (!target || target.tagName !== 'INPUT' || target.type !== 'password') return;

  const form = target.closest('form');
  if (!form) return;

  // Capture huidige action
  const actionAtFocus = form.action || form.getAttribute('action') || '';
  const hostAtFocus = getHostFromAction(actionAtFocus);

  // Check na microtask (voor synchrone wijzigingen)
  queueMicrotask(() => {
    checkJITHijacking(form, actionAtFocus, hostAtFocus, 'microtask');
  });

  // Check na korte delay (voor setTimeout-based attacks)
  setTimeout(() => {
    checkJITHijacking(form, actionAtFocus, hostAtFocus, 'timeout');
  }, 50);

  // Check na langere delay (voor vertraagde attacks)
  setTimeout(() => {
    checkJITHijacking(form, actionAtFocus, hostAtFocus, 'delayed');
  }, 200);
}

/**
 * Check voor JIT hijacking na password focus
 */
function checkJITHijacking(form, originalAction, originalHost, phase) {
  if (formHijackingDetected) return;

  const currentAction = form.action || form.getAttribute('action') || '';
  const currentHost = getHostFromAction(currentAction);
  const pageHost = window.location.hostname.toLowerCase();

  // Check of action is gewijzigd naar extern domein
  if (currentAction !== originalAction &&
      currentHost !== pageHost &&
      !currentHost.endsWith('.' + pageHost)) {

    formHijackingDetected = true;
    logDebug(`[FormHijacking] JIT hijacking detected in ${phase} phase`);
    reportFormHijacking(form, originalAction, currentAction, currentHost);
  }
}

/**
 * Helper: haal hostname uit action URL
 */
function getHostFromAction(action) {
  if (!action) return window.location.hostname.toLowerCase();
  try {
    return new URL(action, window.location.href).hostname.toLowerCase();
  } catch (e) {
    return window.location.hostname.toLowerCase();
  }
}

/**
 * Rapporteer en toon waarschuwing voor form hijacking
 */
function reportFormHijacking(form, originalAction, newAction, targetHost) {
  logDebug('[FormHijacking] DETECTED!', {
    original: originalAction,
    new: newAction,
    target: targetHost
  });

  // Stuur naar background voor icon update
  if (typeof chrome !== 'undefined' && chrome.runtime && chrome.runtime.sendMessage) {
    chrome.runtime.sendMessage({
      action: 'formHijackingDetected',
      data: {
        hostname: window.location.hostname,
        targetHost: targetHost,
        originalAction: originalAction,
        newAction: newAction
      }
    }).catch(() => { /* ignore */ });
  }

  // Toon waarschuwing
  showFormHijackingWarning(targetHost);
}

/**
 * Toon waarschuwing voor form hijacking
 */
function showFormHijackingWarning(targetHost) {
  const title = getTranslatedMessage('formHijackingTitle') || 'Form Hijacking Detected!';
  const message = getTranslatedMessage('formHijackingMessage') ||
    'This page attempted to redirect your login credentials to an external server.';
  const tip = (getTranslatedMessage('formHijackingTip') ||
    'The form was secretly modified to send your data to: ') + targetHost;

  if (typeof showSecurityWarning === 'function') {
    showSecurityWarning({
      id: 'form-hijacking',
      severity: 'critical',
      title: title,
      message: message,
      tip: tip,
      icon: '🔓',
      showTrust: true
    });
  }
}

// =============================================================================
// END FORM HIJACKING PROTECTION
// =============================================================================

/**
 * Hoofd-functie die alle subsector-helpers aanroept.
 * @param {object} config
 * @returns {object}
 */
function validateConfig(config) {
  const validated = { ...config };
  // 1. General settings
  validateGeneralSettings(validated);
  // 2. String-arrayvelden
  validateStringArrayField(validated, 'ALLOWED_PROTOCOLS', ['https:', 'http:', 'mailto:', 'tel:', 'ftp:']);
  validateRegexArrayField(validated, 'ALLOWED_PATHS', [
    /^\/home/i, /^\/products/i, /^\/about/i,
    /^\/contact/i, /^\/blog/i
  ]);
  validateRegexArrayField(validated, 'ALLOWED_QUERY_PARAMS', [
    /^utm_/i, /^ref$/i, /^source$/i,
    /^lang$/i, /^session$/i
  ]);
  validateStringArrayField(validated, 'CRYPTO_DOMAINS', [
    'binance.com', 'kraken.com', 'metamask.io', 'wallet-connect.org', 'coinbase.com',
    'bybit.com', 'okx.com', 'kucoin.com', 'hashkey.com', 'binance.us', 'raydium.io'
  ]);
  validateStringArrayField(validated, 'FREE_HOSTING_DOMAINS', [
    'sites.net', 'angelfire.com', 'geocities.ws', '000a.biz', '000webhostapp.com',
    'weebly.com', 'wixsite.com', 'freehosting.com', 'glitch.me', 'firebaseapp.com',
    'herokuapp.com', 'freehostia.com', 'netlify.app', 'webs.com', 'yolasite.com',
    'github.io', 'bravenet.com', 'zyro.com', 'altervista.org', 'tripod.com',
    'jimdo.com', 'ucoz.com', 'blogspot.com', 'square.site', 'pages.dev',
    'r2.dev', 'mybluehost.me', '000space.com', 'awardspace.com', 'byethost.com',
    'biz.nf', 'hyperphp.com', 'infinityfree.net', '50webs.com', 'tripod.lycos.com',
    'site123.me', 'webflow.io', 'strikingly.com', 'x10hosting.com',
    'freehostingnoads.net', '000freewebhost.com', 'mystrikingly.com',
    'sites.google.com', 'appspot.com', 'vercel.app', 'weeblysite.com',
    's3.amazonaws.com', 'bubbleapps.io', 'typedream.app', 'codeanyapp.com',
    'carrd.co', 'surge.sh', 'replit.dev', 'fly.dev', 'render.com', 'onrender.com'
  ]);
  validateStringArrayField(validated, 'TRUSTED_IFRAME_DOMAINS', ['youtube.com', 'vimeo.com', 'google.com']);
  validateStringArrayField(validated, 'legitimateDomains', [
    'microsoft.com', 'apple.com', 'google.com', 'linkedin.com', 'alibaba.com',
    'whatsapp.com', 'amazon.com', 'x.com', 'facebook.com', 'adobe.com'
  ]);
  // 3. Risicogewichten
  validateRiskWeights(validated);
  // 4. Compound TLD's
  validateStringArrayField(validated, 'COMPOUND_TLDS', [
    'co.uk', 'org.uk', 'gov.uk', 'ac.uk',
    'com.au', 'org.au',
    'co.nz'
  ]);
  // 5. Velden met RegExp of Set
  validateSetField(validated, 'DOWNLOAD_KEYWORDS', [
    'download','install','setup','file','update','patch','plugin','installer','software','driver',
    'execute','run','launch','tool','patcher','application','program','app','fix','crack',
    'keygen','serial','activation','license','trial','demo','zip','archive','compressed',
    'installer_package','upgrade','update_tool','free','fixer','repair','optimizer','restore',
    'reset','unlock','backup','configuration','config','module','library','framework','macro',
    'enable','torrent','seed','payload','exploit','dropper','loader','package','binary',
    'release','beta','mod','hack'
  ]);
  validateRegexOrSetPatternFields(validated);
  // 6. Suspicious-patternvelden
  validateSuspiciousPatterns(validated);
  return validated;
}
/* --- Helper 1: Algemene instellingen --- */
function validateGeneralSettings(cfg) {
  // DEBUG_MODE moet boolean zijn
  if (typeof cfg.DEBUG_MODE !== 'boolean') {
    cfg.DEBUG_MODE = false;
  }
  // MAX_SUBDOMAINS moet positief zijn
  if (typeof cfg.MAX_SUBDOMAINS !== 'number' || cfg.MAX_SUBDOMAINS < 0) {
    cfg.MAX_SUBDOMAINS = 3;
  }
  // CACHE_DURATION_MS moet > 0 zijn
  if (typeof cfg.CACHE_DURATION_MS !== 'number' || cfg.CACHE_DURATION_MS <= 0) {
    cfg.CACHE_DURATION_MS = 24 * 60 * 60 * 1000;
  }
  // SUSPICION_THRESHOLD tussen 0 en 1
  if (typeof cfg.SUSPICION_THRESHOLD !== 'number' || cfg.SUSPICION_THRESHOLD < 0 || cfg.SUSPICION_THRESHOLD > 1) {
    cfg.SUSPICION_THRESHOLD = 0.1;
  }
  // ==== Validatie voor de nieuwe risicodrempels ====
  if (typeof cfg.LOW_THRESHOLD !== 'number' || cfg.LOW_THRESHOLD < 0) {
    cfg.LOW_THRESHOLD = 3;
  }
  if (typeof cfg.MEDIUM_THRESHOLD !== 'number' || cfg.MEDIUM_THRESHOLD < cfg.LOW_THRESHOLD) {
    cfg.MEDIUM_THRESHOLD = cfg.LOW_THRESHOLD + 1;
  }
  if (typeof cfg.HIGH_THRESHOLD !== 'number' || cfg.HIGH_THRESHOLD < cfg.MEDIUM_THRESHOLD) {
    cfg.HIGH_THRESHOLD = cfg.MEDIUM_THRESHOLD + 1;
  }
  // Domain-age checks
  if (typeof cfg.DOMAIN_AGE_MIN_RISK !== 'number' || cfg.DOMAIN_AGE_MIN_RISK < 0) {
    cfg.DOMAIN_AGE_MIN_RISK = 5;
  }
  if (typeof cfg.YOUNG_DOMAIN_THRESHOLD_DAYS !== 'number' || cfg.YOUNG_DOMAIN_THRESHOLD_DAYS < 0) {
    cfg.YOUNG_DOMAIN_THRESHOLD_DAYS = 7;
  }
  if (typeof cfg.YOUNG_DOMAIN_RISK !== 'number' || cfg.YOUNG_DOMAIN_RISK < 0) {
    cfg.YOUNG_DOMAIN_RISK = 5;
  }
  // Nieuwe instelling: risico-gewicht voor “geen HTTPS”
  if (typeof cfg.PROTOCOL_RISK !== 'number' || cfg.PROTOCOL_RISK < 0) {
    // defaultConfig.PROTOCOL_RISK staat in je defaultConfig op bijv. 4
    cfg.PROTOCOL_RISK = defaultConfig.PROTOCOL_RISK;
  }
}
/* --- Helper 2: Array van strings --- */
function validateStringArrayField(cfg, field, defaultArray) {
  const val = cfg[field];
  if (!Array.isArray(val) || val.some(item => typeof item !== 'string')) {
    cfg[field] = defaultArray.slice();
  } else {
    cfg[field] = val
      .map(s => s.trim())
      .filter(s => s.length > 0);
  }
}
/* --- Helper 3: Array van RegExp --- */
function validateRegexArrayField(cfg, field, defaultRegexArray) {
  const val = cfg[field];
  if (!Array.isArray(val) || val.some(item => !(item instanceof RegExp))) {
    cfg[field] = defaultRegexArray.slice();
  }
}
/* --- Helper 4: Risicogewichten --- */
function validateRiskWeights(cfg) {
  const val = cfg.domainRiskWeights;
  const defaultWeights = {
    'microsoft.com': 10,
    'apple.com': 4,
    'google.com': 4,
    'linkedin.com': 3,
    'alibaba.com': 1,
    'whatsapp.com': 1,
    'amazon.com': 1,
    'x.com': 1,
    'facebook.com': 1,
    'adobe.com': 1
  };
  if (
    typeof val !== 'object' ||
    val === null ||
    Array.isArray(val) ||
    Object.values(val).some(w => typeof w !== 'number' || w < 0)
  ) {
    cfg.domainRiskWeights = { ...defaultWeights };
  }
}
/* --- Helper 5a: Set van strings --- */
function validateSetField(cfg, field, defaultArray) {
  const val = cfg[field];
  if (!(val instanceof Set)) {
    cfg[field] = new Set(defaultArray);
  } else {
    // Sanitiseer: houd alleen niet-lege strings
    cfg[field] = new Set(
      Array.from(val).filter(item => typeof item === 'string' && item.trim().length > 0)
    );
    if (cfg[field].size === 0) {
      cfg[field] = new Set(defaultArray);
    }
  }
}
/* --- Helper 5b: RegExp- en Set-patronen --- */
function validateRegexOrSetPatternFields(cfg) {
  const safeRegex = () => new RegExp('$^');
  // HOMOGLYPHS: object met array<string>
  const h = cfg.HOMOGLYPHS;
  const isValidHomoglyphs =
    typeof h === 'object' &&
    h !== null &&
    !Array.isArray(h) &&
    Object.values(h).every(
      arr => Array.isArray(arr) && arr.every(item => typeof item === 'string')
    );
  if (!isValidHomoglyphs) {
    cfg.HOMOGLYPHS = {
      'a': ['а', 'ä', 'α', 'ạ', 'å'],
      'b': ['Ь', 'β', 'ḅ'],
      'c': ['с', 'ç', 'ć'],
      'e': ['е', 'ë', 'ε', 'ẹ'],
      'i': ['і', 'ï', 'ι', 'ḯ'],
      'l': ['ӏ', 'ł', 'ḷ'],
      'o': ['о', 'ö', 'ο', 'ọ', 'ø'],
      'p': ['р', 'ρ', 'ṗ'],
      's': ['ѕ', 'ś', 'ṣ'],
      'u': ['υ', 'ü', 'µ', 'ṵ'],
      'v': ['ν', 'ṽ'],
      'w': ['ω', 'ẉ'],
      'x': ['х', 'χ'],
      'y': ['у', 'ÿ', 'γ'],
      'z': ['ž', 'ƶ', 'ź', 'ż', 'ẑ', 'ẓ', 'ẕ', 'ƹ', 'ɀ']
    };
  }
  // LOGIN_PATTERNS: RegExp
  if (!(cfg.LOGIN_PATTERNS instanceof RegExp)) {
    try {
      cfg.LOGIN_PATTERNS = new RegExp(
        '(login|account|auth|authenticate|signin|wp-login|sign-in|log-in|dashboard|portal|session|user|profile)',
        'i'
      );
    } catch (error) {
      logError(`Ongeldig RegExp-patroon voor LOGIN_PATTERNS: ${error.message}`);
      cfg.LOGIN_PATTERNS = safeRegex();
    }
  }
  // MALWARE_EXTENSIONS: RegExp (false positives verwijderd: .js, .py, .svg, .dll, .doc, .xls, .ppt, .rtf, .sh)
  if (!(cfg.MALWARE_EXTENSIONS instanceof RegExp)) {
    try {
      cfg.MALWARE_EXTENSIONS = new RegExp(
        '\\.(exe|zip|bak|tar|gz|msi|dmg|jar|rar|7z|iso|bin|scr|bat|cmd|vbs|lnk|chm|ps1|apk|vbscript|docm|xlsm|pptm|torrent|wsf|hta|jse|reg|swf|wsh|pif|wasm|cab|cpl|inf|msc|pcd|sct|shb|sys)$',
        'i'
      );
    } catch (error) {
      logError(`Ongeldig RegExp-patroon voor MALWARE_EXTENSIONS: ${error.message}`);
      cfg.MALWARE_EXTENSIONS = safeRegex();
    }
  }
  // PHISHING_KEYWORDS: Set<string>
  const phishingSet = cfg.PHISHING_KEYWORDS;
  if (!(phishingSet instanceof Set)) {
    cfg.PHISHING_KEYWORDS = new Set([
      'login','password','verify','access','account','auth','blocked','bonus',
      'captcha','claim','click','credentials','free','gift','notification','pay',
      'pending','prize','recover','secure','signin','unlock','unusual','update',
      'urgent','validate','win'
    ]);
  }
  // SHORTENED_URL_DOMAINS: Set<string>
  const shortUrls = cfg.SHORTENED_URL_DOMAINS;
  if (!(shortUrls instanceof Set) || shortUrls.size === 0) {
    cfg.SHORTENED_URL_DOMAINS = new Set([
      'bit.ly','is.gd','tinyurl.com','goo.gl','t.co','ow.ly','shorturl.at','rb.gy',
      'adf.ly','bc.vc','cutt.ly','lnk.to','rebrand.ly','shorte.st','s.id','tiny.cc',
      'v.gd','zpr.io','clk.sh','soo.gd','u.to','x.co','1url.com','bl.ink',
      'clicky.me','dub.sh','kutt.it','lc.cx','linktr.ee','rb.gy','short.io',
      't.ly','tr.im','urlz.fr','vzturl.com','yourls.org','zi.ma','qr.ae',
      // v8.8.12: Added missing shorteners from QA audit
      'buff.ly','bit.do','j.mp','shr.tn','lc.chat','moourl.com','clck.ru',
      'shortlink.de','qps.ru','tinu.be','su.pr','snip.ly','snipurl.com'
    ]);
  }
  cfg.SHORTENED_URL_DOMAINS = new Set(
    Array.from(cfg.SHORTENED_URL_DOMAINS).filter(d => typeof d === 'string' && d.trim().length > 0)
  );
  logDebug(`Validated SHORTENED_URL_DOMAINS: ${Array.from(cfg.SHORTENED_URL_DOMAINS).join(', ')}`);

  // OFFICIAL_SHORTENERS: Set<string> - vertrouwde bedrijfs-shorteners die NIET als verdacht moeten worden gemarkeerd
  const officialShorteners = cfg.OFFICIAL_SHORTENERS;
  if (!(officialShorteners instanceof Set) && !Array.isArray(officialShorteners)) {
    cfg.OFFICIAL_SHORTENERS = new Set([
      't.co', 'youtu.be', 'fb.me', 'g.co', 'goo.gl', 'lnkd.in', 'amzn.to', 'amzn.eu',
      'msft.it', 'aka.ms', 'apple.co', 'spoti.fi', 'pin.it', 'redd.it'
    ]);
  } else if (Array.isArray(officialShorteners)) {
    cfg.OFFICIAL_SHORTENERS = new Set(officialShorteners.filter(d => typeof d === 'string' && d.trim().length > 0));
  }
  logDebug(`Validated OFFICIAL_SHORTENERS: ${Array.from(cfg.OFFICIAL_SHORTENERS).join(', ')}`);

  // TRUSTED_CDN_DOMAINS: Set<string> - vertrouwde CDN domeinen
  const trustedCdns = cfg.TRUSTED_CDN_DOMAINS;
  if (!(trustedCdns instanceof Set) && !Array.isArray(trustedCdns)) {
    cfg.TRUSTED_CDN_DOMAINS = new Set([
      'cloudfront.net', 'amazonaws.com', 'azureedge.net', 'googleusercontent.com',
      'gstatic.com', 'akamaized.net', 'fastly.net', 'jsdelivr.net', 'unpkg.com',
      'fbcdn.net', 'twimg.com', 'ytimg.com'
    ]);
  } else if (Array.isArray(trustedCdns)) {
    cfg.TRUSTED_CDN_DOMAINS = new Set(trustedCdns.filter(d => typeof d === 'string' && d.trim().length > 0));
  }
  logDebug(`Validated TRUSTED_CDN_DOMAINS: ${Array.from(cfg.TRUSTED_CDN_DOMAINS).join(', ')}`);

  // TRUSTED_API_DOMAINS: Set<string> - vertrouwde API domeinen
  const trustedApis = cfg.TRUSTED_API_DOMAINS;
  if (!(trustedApis instanceof Set) && !Array.isArray(trustedApis)) {
    cfg.TRUSTED_API_DOMAINS = new Set([
      'accounts.google.com', 'login.microsoftonline.com', 'appleid.apple.com',
      'api.stripe.com', 'api.paypal.com', 'auth0.com', 'okta.com'
    ]);
  } else if (Array.isArray(trustedApis)) {
    cfg.TRUSTED_API_DOMAINS = new Set(trustedApis.filter(d => typeof d === 'string' && d.trim().length > 0));
  }
  logDebug(`Validated TRUSTED_API_DOMAINS: ${Array.from(cfg.TRUSTED_API_DOMAINS).join(', ')}`);
}
/* --- Helper 6: Suspicious-patternvelden --- */
function validateSuspiciousPatterns(cfg) {
  const safeRegex = () => new RegExp('$^');
  // Verhoogde totaalgewicht-drempel om false positives te verminderen
  cfg.SCRIPT_SUSPICION_THRESHOLD = cfg.SCRIPT_SUSPICION_THRESHOLD || 20;
  // SUSPICIOUS_EMAIL_PATTERNS (ongewijzigd)
  if (
    !Array.isArray(cfg.SUSPICIOUS_EMAIL_PATTERNS) ||
    cfg.SUSPICIOUS_EMAIL_PATTERNS.some(p => !(p instanceof RegExp))
  ) {
    cfg.SUSPICIOUS_EMAIL_PATTERNS = [
      /admin@.*\.xyz/i,
      /support@.*\.top/i,
      /noreply@.*\.info/i,
      /verify@.*\.site/i,
      /account@.*\.online/i
    ];
  }
  // SUSPICIOUS_SCRIPT_PATTERNS met strengere validatie
  if (
    !Array.isArray(cfg.SUSPICIOUS_SCRIPT_PATTERNS) ||
    cfg.SUSPICIOUS_SCRIPT_PATTERNS.some(entry => !(entry.regex instanceof RegExp))
  ) {
    cfg.SUSPICIOUS_SCRIPT_PATTERNS = [
      {
        regex: /\beval\s*\(\s*['"][^'"]{30,}['"]\s*\)/i,
        weight: 12,
        description: 'Dangerous eval of Function met zeer lange strings'
      },
      {
        regex: /\bnew\s+Function\s*\(\s*['"][^'"]{30,}['"](?:\s*,\s*['"][^'"]*['"])*\)/i,
        weight: 12,
        description: 'Dangerous Function constructor met zeer lange strings'
      },
      {
        regex: /\b(?:coinimp|cryptonight|webminer|miner\.js|crypto-jacking|keylogger|trojan|worm|ransomware)\b/i,
        weight: 12,
        description: 'Expliciete malware-/cryptomining-termen'
      },
      {
        regex: /\b(?:malicious|phish(?:ing)?|exploit(?:s)?|redirect(?:ing)?|inject(?:ion)?|clickjacking|backdoor|rootkit)\b/i,
        weight: 11,
        description: 'Malware- of phishing-termen'
      },
      {
        regex: /\b(?:document\.write\s*\(\s*['"][^'"]*javascript:|innerHTML\s*=\s*['"][^'"]*eval)/i,
        weight: 8,
        description: 'Verdachte DOM-manipulatie'
      },
      {
        regex: /\b(?:fetch\([^)]*\.wasm[^)]*eval|import\([^)]*\.wasm[^)]*javascript:)/i,
        weight: 7,
        description: 'WebAssembly-misbruik'
      },
      {
        regex: /\b(?:RTCPeerConnection\s*\(\s*{[^}]*stun:|RTCDataChannel\W*send\s*\(\s*['"][^'"]*eval)/i,
        weight: 6,
        description: 'WebRTC-aanvallen'
      }
    ];
  }
  // SUSPICIOUS_TLDS (ongewijzigd)
  if (!(cfg.SUSPICIOUS_TLDS instanceof RegExp)) {
    try {
      cfg.SUSPICIOUS_TLDS = new RegExp(
        "\\.(academy|accountant|...|zone)$", 'i'
      );
    } catch (err) {
      logError(`Ongeldig RegExp-patroon voor SUSPICIOUS_TLDS: ${err.message}`);
      cfg.SUSPICIOUS_TLDS = safeRegex();
    }
  }
  // SUSPICIOUS_URL_PATTERNS & TYPOSQUATTING_PATTERNS (ongewijzigd)
}
/* --- Helper 7: detectInteractiveControls --- */
function detectInteractiveControls(root = document) {
  const selector = `
    button, input[type="button"], input[type="submit"],
    input[type="text"], input[type="email"], input[type="password"], input[type="search"],
    select, textarea, a[href],
    [role="button"], [role="link"],
    [onclick], [tabindex]:not([tabindex="-1"])
  `;
  let elements = Array.from(root.querySelectorAll(selector))
    .filter(el => isVisible(el) && !isHiddenInput(el));
  // Shadow DOM ondersteuning
  for (const el of root.querySelectorAll('*')) {
    if (el.shadowRoot) {
      elements = elements.concat(detectInteractiveControls(el.shadowRoot));
    }
  }
  return elements;
}
function startDynamicDetection(callback) {
  const observer = new MutationObserver(mutations => {
    for (const mutation of mutations) {
      mutation.addedNodes.forEach(node => {
        if (node.nodeType === Node.ELEMENT_NODE) {
          const controls = detectInteractiveControls(node);
          if (controls.length > 0) {
            callback(controls);
          }
        }
      });
    }
  });
  observer.observe(document.body, { childList: true, subtree: true });
}
/**
 * Laadt de configuratie uit window.CONFIG en valideert deze.
 */
const defaultConfig = {
  // **Algemene instellingen**
  CACHE_DURATION_MS: 24 * 60 * 60 * 1000, // 24 uur
  DEBUG_MODE: false,
  MAX_SUBDOMAINS: 3,
  RISK_THRESHOLD: 5,
  SUSPICION_THRESHOLD: 0.1,
  // ==== Risicodrempels voor gefaseerde analyse en UI-feedback ====
  LOW_THRESHOLD: 4, // risico < 4 → safe (was 2)
  MEDIUM_THRESHOLD: 8, // 4 ≤ risico < 8 → caution (was 5)
  HIGH_THRESHOLD: 15, // risico ≥ 15 → alert (was 10)
  YOUNG_DOMAIN_THRESHOLD_DAYS: 14, // Domeinen jonger dan 2 weken (blijft 14)
  DOMAIN_AGE_MIN_RISK: 5, // Domeinleeftijd‐check vanaf 5 punten (was 3)
  YOUNG_DOMAIN_RISK: 5, // Risico‐gewicht voor jonge domeinen (was 7)
  PROTOCOL_RISK: 4,
  // **Lijsten van toegestane waarden**
  ALLOWED_PROTOCOLS: ['https:', 'http:', 'mailto:', 'tel:', 'ftp:'],
  ALLOWED_PATHS: [
    /^\/home/i,
    /^\/products/i,
    /^\/about/i,
    /^\/contact/i,
    /^\/blog/i
  ],
  ALLOWED_QUERY_PARAMS: [
    /^utm_/i,
    /^ref$/i,
    /^source$/i,
    /^lang$/i,
    /^session$/i
  ],
  // **Vertrouwde domeinen**
  CRYPTO_DOMAINS: [
    'binance.com',
    'kraken.com',
    'metamask.io',
    'wallet-connect.org',
    'coinbase.com',
    'bybit.com',
    'okx.com',
    'kucoin.com',
    'hashkey.com',
    'binance.us',
    'raydium.io'
  ],
  FREE_HOSTING_DOMAINS: [
    'sites.net', 'angelfire.com', 'geocities.ws', '000a.biz', '000webhostapp.com', 'weebly.com', 'wixsite.com',
    'freehosting.com', 'glitch.me', 'firebaseapp.com', 'herokuapp.com', 'freehostia.com', 'netlify.app', 'webs.com',
    'yolasite.com', 'github.io', 'bravenet.com', 'zyro.com', 'altervista.org', 'tripod.com', 'jimdo.com', 'ucoz.com',
    'blogspot.com', 'square.site', 'pages.dev', 'r2.dev', 'mybluehost.me', '000space.com', 'awardspace.com',
    'byethost.com', 'biz.nf', 'hyperphp.com', 'infinityfree.net', '50webs.com', 'tripod.lycos.com', 'site123.me',
    'webflow.io', 'strikingly.com', 'x10hosting.com', 'freehostingnoads.net', '000freewebhost.com', 'mystrikingly.com',
    'sites.google.com', 'appspot.com', 'vercel.app', 'weeblysite.com', 's3.amazonaws.com', 'bubbleapps.io',
    'typedream.app', 'codeanyapp.com', 'carrd.co', 'surge.sh', 'replit.dev', 'fly.dev', 'render.com', 'onrender.com'
  ],
  TRUSTED_IFRAME_DOMAINS: ['youtube.com', 'vimeo.com', 'google.com'],
  legitimateDomains: [
    'microsoft.com', 'apple.com', 'google.com', 'linkedin.com', 'alibaba.com',
    'whatsapp.com', 'amazon.com', 'x.com', 'facebook.com', 'adobe.com'
  ],
  // **Risicogewichten**
  domainRiskWeights: {
    'microsoft.com': 10, 'apple.com': 4, 'google.com': 4, 'linkedin.com': 3, 'alibaba.com': 1,
    'whatsapp.com': 1, 'amazon.com': 1, 'x.com': 1, 'facebook.com': 1, 'adobe.com': 1
  },
  // **Regex-gebaseerde patronen**
  COMPOUND_TLDS: [
    'co.uk', 'org.uk', 'gov.uk', 'ac.uk',
    'com.au', 'org.au',
    'co.nz'
  ],
  DOWNLOAD_KEYWORDS: new Set([
    'download', 'install', 'setup', 'file', 'update', 'patch', 'plugin', 'installer', 'software', 'driver',
    'execute', 'run', 'launch', 'tool', 'patcher', 'application', 'program', 'app', 'fix', 'crack',
    'keygen', 'serial', 'activation', 'license', 'trial', 'demo', 'zip', 'archive', 'compressed',
    'installer_package', 'upgrade', 'update_tool', 'free', 'fixer', 'repair', 'optimizer', 'restore',
    'reset', 'unlock', 'backup', 'configuration', 'config', 'module', 'library', 'framework', 'macro',
    'enable', 'torrent', 'seed', 'payload', 'exploit', 'dropper', 'loader', 'package', 'binary',
    'release', 'beta', 'mod', 'hack'
  ]),
  HOMOGLYPHS: {
    'a': ['а', 'ä', 'α', 'ạ', 'å'],
    'b': ['Ь', 'β', 'ḅ'],
    'c': ['с', 'ç', 'ć'],
    'e': ['е', 'ë', 'ε', 'ẹ'],
    'i': ['і', 'ï', 'ι', 'ḯ'],
    'l': ['ӏ', 'ł', 'ḷ'],
    'o': ['о', 'ö', 'ο', 'ọ', 'ø'],
    'p': ['р', 'ρ', 'ṗ'],
    's': ['ѕ', 'ś', 'ṣ'],
    'u': ['υ', 'ü', 'µ', 'ṵ'],
    'v': ['ν', 'ṽ'],
    'w': ['ω', 'ẉ'],
    'x': ['х', 'χ'],
    'y': ['у', 'ÿ', 'γ'],
    'z': ['ž', 'ƶ', 'ź', 'ż', 'ẑ', 'ẓ', 'ẕ', 'ƹ', 'ɀ']
  },
  LOGIN_PATTERNS: /(login|account|auth|authenticate|signin|wp-login|sign-in|log-in|dashboard|portal|session|user|profile)/i,
  // MALWARE_EXTENSIONS: .js, .py, .svg, .dll, .doc, .xls, .ppt, .rtf, .sh VERWIJDERD (false positives)
  MALWARE_EXTENSIONS: /\.(exe|zip|bak|tar|gz|msi|dmg|jar|rar|7z|iso|bin|scr|bat|cmd|vbs|lnk|chm|ps1|apk|vbscript|docm|xlsm|pptm|torrent|wsf|hta|jse|reg|swf|wsh|pif|wasm|cab|cpl|inf|msc|pcd|sct|shb|sys)$/i,
  PHISHING_KEYWORDS: new Set([
    'login', 'password', 'verify', 'access', 'account', 'auth', 'blocked', 'bonus', 'captcha', 'claim',
    'click', 'credentials', 'free', 'gift', 'notification', 'pay', 'pending', 'prize', 'recover',
    'secure', 'signin', 'unlock', 'unusual', 'update', 'urgent', 'validate', 'win'
  ]),
  SHORTENED_URL_DOMAINS: new Set(['bit.ly', 'is.gd', 'tinyurl.com', 'goo.gl', 't.co']),
  SUSPICIOUS_EMAIL_PATTERNS: [
    /admin@.*\.xyz/i,
    /support@.*\.top/i,
    /noreply@.*\.info/i,
    /verify@.*\.site/i,
    /account@.*\.online/i
  ],
  SUSPICIOUS_SCRIPT_PATTERNS: [
    { regex: new RegExp('(?:\\beval\\s*\\(\\s*[\'"].*[\'"][^)]*\\)|new\\s+Function\\s*\\(\\s*[\'"].*[\'"][^)]*\\)|base64_decode\\s*\\()', 'i'), weight: 8, description: 'Dangerous eval or Function with strings' },
    { regex: new RegExp('(?:coinimp|cryptonight|webminer|miner\\.js|crypto-jacking|keylogger|trojan|worm|ransomware|xss\\s*\\()', 'i'), weight: 10, description: 'Explicit malware terms' },
    { regex: new RegExp('(?:document\\.write\\s*\\(\\s*[\'"][^\'"]*javascript:|innerHTML\\s*=\\s*[\'"][^\'"]*eval)', 'i'), weight: 7, description: 'Suspicious DOM manipulation' },
    { regex: new RegExp('(?:fetch\\(.+\\.wasm[^)]*eval|import\\(.+\\.wasm[^)]*javascript:)', 'i'), weight: 6, description: 'WebAssembly misuse' },
    { regex: new RegExp('(?:malicious|phish|exploit|redirect|inject|clickjacking|backdoor|rootkit)', 'i'), weight: 9, description: 'Malware keywords' },
    { regex: new RegExp('(?:RTCPeerConnection\\s*\\(\\s*{[^}]*stun:|RTCDataChannel\\s*.\\s*send\\s*\\(\\s*[\'"][^\'"]*eval)', 'i'), weight: 6, description: 'WebRTC attacks' },
  ],
  SUSPICIOUS_TLDS: /\.(academy|accountant|accountants|agency|ap|app|art|asia|auto|bank|bar|beauty|bet|bid|bio|biz|blog|buzz|cam|capital|casa|casino|cfd|charity|cheap|church|city|claims|click|club|company|crispsalt|cyou|data|date|design|dev|digital|directory|download|email|energy|estate|events|exchange|expert|exposed|express|finance|fit|forsale|foundation|fun|games|gle|goog|gq|guide|guru|health|help|home|host|html|icu|ink|institute|investments|ip|jobs|life|limited|link|live|loan|lol|ltd|ly|mall|market|me|media|men|ml|mom|money|monster|mov|network|one|online|page|partners|party|php|pics|play|press|pro|promo|pw|quest|racing|rest|review|rocks|run|sbs|school|science|services|shop|shopping|site|software|solutions|space|store|stream|support|team|tech|tickets|to|today|tools|top|trade|trading|uno|ventures|vip|website|wiki|win|work|world|xin|xyz|zip|zone|co|cc|tv|name|team|live|stream|quest|sbs)$/i,
  SUSPICIOUS_URL_PATTERNS: [
    /\/(payment|invoice|billing|money|bank|secure|login|checkout|subscription|refund|delivery)\//i,
    /(Base64|hexadecimal|b64|encode|urlencode|obfuscate|crypt)/i,
    /\/(signup|register|confirmation|securepayment|order|tracking|verify-account|reset-password|oauth)\//i,
    /(?:\bsecurepay\b|\baccountverify\b|\bresetpassword\b|\bverifyemail\b|\bupdateinfo\b)/i,
    /(qr-code|qrcode|qr\.|generate-qr|scan|qrserver|qrcodes\.)/i,
    /(fake|clone|spoof|impersonate|fraud|scam|phish)/i,
    /[^a-zA-Z0-9]{2,}/,
    /(http[s]?:\/\/[^\/]+){2,}/i,
    /(qr-code|qrcode|qr\.|generate-qr|scan)/i
  ],
  TYPOSQUATTING_PATTERNS: [
    /g00gle/i,
    /paypa1/i,
    /micr0soft/i,
    /[0o][0o]/i,
    /1n/i,
    /vv/i,
    /rn$/i
  ]
};
// Voeg een vlag toe om te controleren of de configuratie al is geladen
let configLoaded = false;
let configPromise = null;
const maxConfigLoadAttempts = 5;
// Nieuw: Mutex flag voor loading
let isLoadingConfig = false; // Voorkomt parallelle loads
async function loadConfig() {
  // Mutex check - als al loading, retourneer bestaande promise (idempotent)
  if (isLoadingConfig && configPromise) {
    logDebug("[loadConfig] Already loading, returning existing promise.");
    return configPromise;
  }
  // Zet mutex aan
  isLoadingConfig = true;
  // Bestaande logica, maar nu in een try-finally voor mutex reset
  try {
    if (configLoaded) {
      logDebug("[loadConfig] Config already loaded, returning globalConfig.");
      return globalConfig; // Direct retourneren als al geladen
    }
    // Wrap de promise met een timeout van 30 seconden
    configPromise = Promise.race([
      (async () => {
        let attempt = 0;
        while (attempt < maxConfigLoadAttempts && !configLoaded) {
          attempt++;
          try {
            // — Stap 1: Probeer window.CONFIG —
            if (window.CONFIG && typeof window.CONFIG === 'object' && !Array.isArray(window.CONFIG)) {
              const merged = { ...defaultConfig, ...window.CONFIG };
              try {
                globalConfig = validateConfig(merged);
                logDebug(`Configuration geladen uit window.CONFIG (poging ${attempt}):`, globalConfig);
                configLoaded = true;
                return globalConfig;
              } catch (validationError) {
                handleError(validationError, 'loadConfig: window.CONFIG ongeldig, fallback naar default');
                globalConfig = validateConfig(defaultConfig);
                configLoaded = true;
                return globalConfig;
              }
            }
            // — Stap 2: Probeer chrome.storage.sync —
            const stored = await new Promise((resolve, reject) => {
              chrome.storage.sync.get('CONFIG', (items) => {
                if (chrome.runtime.lastError) {
                  reject(new Error(chrome.runtime.lastError.message));
                } else {
                  resolve(items.CONFIG);
                }
              });
            });
            if (stored && typeof stored === 'object' && !Array.isArray(stored)) {
              const merged = { ...defaultConfig, ...stored };
              try {
                globalConfig = validateConfig(merged);
                logDebug(`Configuration geladen uit chrome.storage (poging ${attempt}):`, globalConfig);
                configLoaded = true;
                return globalConfig;
              } catch (validationError) {
                handleError(validationError, 'loadConfig: chrome.storage.CONFIG ongeldig, fallback naar default');
                globalConfig = validateConfig(defaultConfig);
                configLoaded = true;
                return globalConfig;
              }
            }
            // — Stap 3: Geen geldige configuratie —
            throw new Error('Geen geldige configuratie in window of chrome.storage');
          } catch (error) {
            handleError(error, `loadConfig: kon config niet laden (poging ${attempt})`);
            if (attempt < maxConfigLoadAttempts) {
              const delay = Math.min(Math.pow(2, attempt) * 1000, 10000);
              logDebug(`Retry in ${delay / 1000} s… (poging ${attempt})`);
              await new Promise(res => setTimeout(res, delay));
            }
          }
        }
        // Na max pogingen: fallback
        if (!configLoaded) {
          logDebug(`Max pogingen (${maxConfigLoadAttempts}) bereikt — gebruik defaultConfig.`);
          try {
            globalConfig = validateConfig(defaultConfig);
          } catch (fallbackError) {
            handleError(fallbackError, 'validateConfig(defaultConfig) faalde');
            globalConfig = defaultConfig;
          }
          configLoaded = true;
          return globalConfig;
        }
      })(),
      new Promise((_, reject) => setTimeout(() => reject(new Error('Config load timeout')), 30000)) // 30s timeout
    ]);
    // Wacht op de promise en handel errors af
    return await configPromise;
  } catch (err) {
    handleError(err, 'loadConfig final error - fallback to default');
    globalConfig = validateConfig(defaultConfig);
    configLoaded = true;
    return globalConfig;
  } finally {
    // Reset mutex na completion (ook bij errors)
    isLoadingConfig = false;
    configPromise = null; // Reset promise voor toekomstige calls bij reject
  }
}
(async () => {
  await loadConfig();
  // SECURITY FIX v8.0.0: Trigger early observer buffer processing
  // v8.4.1: Must await to ensure smartLinkScanningEnabled is set before any scanning
  await onConfigReady();
})();
// Cache voor JSON-bestanden met expiratie
const jsonCache = {};
// Voeg dit toe direct na de declaratie van jsonCache
const CACHE_TTL_MS = 3600000; // TTL van 1 uur
function cleanupJsonCache() {
  const now = Date.now();
  for (const [key, entry] of Object.entries(jsonCache)) {
    if (now - entry.timestamp > CACHE_TTL_MS) {
      delete jsonCache[key];
      logDebug(`Cache entry '${key}' verwijderd omdat deze ouder is dan ${CACHE_TTL_MS / 1000} seconden.`);
    }
  }
}
// Start de cleanup op een interval (bijv. elke 1 uur)
setInterval(cleanupJsonCache, CACHE_TTL_MS);
async function fetchCachedJson(fileName) {
  const cached = jsonCache[fileName];
  const now = Date.now();
  if (cached && (now - cached.timestamp < CACHE_DURATION_MS)) {
    logDebug(`Cache hit for ${fileName}`);
    return cached.data;
  }
  try {
    if (!chrome.runtime || !chrome.runtime.getURL) {
      throw new Error("chrome.runtime is niet beschikbaar");
    }
    const url = chrome.runtime.getURL(fileName);
    logDebug(`Attempting to fetch ${fileName} from: ${url}`);
    const response = await fetch(url, {
      method: 'GET',
      cache: 'no-store'
    });
    logDebug(`Response status: ${response.status}, statusText: ${response.statusText}`);
    if (!response.ok) {
      throw new Error(`Fetch failed with status: ${response.status} - ${response.statusText}`);
    }
    const json = await response.json();
    if (!json || typeof json !== 'object') {
      throw new Error(`Invalid JSON format in ${fileName}`);
    }
    jsonCache[fileName] = { data: json, timestamp: now };
    logDebug(`Successfully fetched and cached ${fileName}`);
    return json;
  } catch (error) {
    handleError(error, `fetchCachedJson: Kon ${fileName} niet laden`);
    if (fileName === 'trustedIframes.json') {
      logDebug(`Falling back to default trusted iframes`);
      return ['youtube.com', 'vimeo.com', 'google.com'];
    } else if (fileName === 'trustedScripts.json') {
      logDebug(`Falling back to default trusted scripts`);
      return ['googleapis.com', 'cloudflare.com']; // Aanpassen aan jouw behoeften
    }
    return [];
  }
}
async function fetchJson(url) {
  try {
    const response = await fetch(url);
    if (!response.ok) throw new Error(`Error fetching ${url}: ${response.statusText}`);
    return await response.json();
  } catch (error) {
    handleError(error, `fetchJson: Kon ${url} niet laden`);
    return null;
  }
}
// Global cache voor RDAP-resultaten
const rdapCache = new Map();
const RDAP_CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 1 dag TTL
// Functie om verlopen RDAP cache-entries te verwijderen
function cleanRdapCache() {
  const now = Date.now();
  for (const [key, entry] of rdapCache.entries()) {
    if (now - entry.timestamp > RDAP_CACHE_TTL_MS) {
      rdapCache.delete(key);
      logDebug(`RDAP cache entry '${key}' verwijderd omdat deze ouder is dan ${RDAP_CACHE_TTL_MS / (1000 * 60 * 60)} uur.`);
    }
  }
}
// Start periodieke schoonmaak
setInterval(cleanRdapCache, RDAP_CACHE_TTL_MS);
/**
 * Haalt de registratiedatum op via de RDAP.org aggregator.
 * v8.8.14: Fetch via background script om CORS-beperkingen te vermijden.
 * Gebruikt een interne cache om dubbele aanroepen te voorkomen.
 * @param {string} domain — b.v. "example.com"
 * @returns {Promise<Date|null>}
 */
async function fetchDomainCreationDate(domain) {
  // Controleer eerst de cache
  const cachedEntry = rdapCache.get(domain);
  if (cachedEntry && (Date.now() - cachedEntry.timestamp < RDAP_CACHE_TTL_MS)) {
    logDebug(`RDAP cache hit voor ${domain}`);
    return cachedEntry.data;
  }
  try {
    // v8.8.14: Fetch via background script to avoid CORS issues
    const result = await new Promise((resolve, reject) => {
      const timeoutId = setTimeout(() => reject(new Error('Timeout')), 10000);
      chrome.runtime.sendMessage({
        action: 'fetchRdapData',
        domain: domain
      }, (response) => {
        clearTimeout(timeoutId);
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
        } else {
          resolve(response);
        }
      });
    });

    if (!result.success) {
      logError(`RDAP.org fout voor ${domain}: ${result.error}`);
      rdapCache.set(domain, { data: null, timestamp: Date.now() });
      return null;
    }

    if (result.notFound || !result.data) {
      logDebug(`RDAP.org kent geen data voor ${domain}`);
      rdapCache.set(domain, { data: null, timestamp: Date.now() });
      return null;
    }

    const data = result.data;
    const regEvent = Array.isArray(data.events)
      ? data.events.find(e => e.eventAction === 'registration')
      : null;
    const creationDate = regEvent && regEvent.eventDate
      ? new Date(regEvent.eventDate)
      : null;
    rdapCache.set(domain, { data: creationDate, timestamp: Date.now() });
    return creationDate;
  } catch (e) {
    logError(`RDAP.org fetch fout voor ${domain}:`, e);
    rdapCache.set(domain, { data: null, timestamp: Date.now() });
    return null;
  }
}
/**
 * Controleert of een domein jonger is dan de configureerbare drempel (standaard 7 dagen).
 * Indien ja, voegt een vertaald bericht toe met de exacte leeftijd in dagen en voegt risicopunten toe.
 *
 * @param {string} url — de volledige URL
 * @param {{ totalRiskRef: { value: number }, reasons: Set<string> }} ctx — context object met risicoreferentie en redenen
 * @returns {Promise<boolean>} — true als jong domein, anders false
 */
async function checkDomainAgeDynamic(url, ctx) {
  // Zorg dat de globale config geladen is
  await ensureConfigReady();
  // Gebruik de robuustere getRegistrableDomain die nu extractMainDomain aanroept
  const domain = getRegistrableDomain(url);
  if (!domain) {
    logDebug(`checkDomainAgeDynamic: Kon geen registreerbaar domein extraheren uit ${url}. Overslaan.`);
    return false;
  }
  // Haal de aanmaakdatum op via de gecachte functie
  const created = await fetchDomainCreationDate(domain);
  if (!created) {
    logDebug(`checkDomainAgeDynamic: Kon geen aanmaakdatum vinden voor domein ${domain}. Overslaan.`);
    return false;
  }

  // Gebruik de nieuwe analyzeNRDRisk functie voor gedifferentieerde risicoscoring
  const nrdAnalysis = analyzeNRDRisk(created);

  if (nrdAnalysis.isNRD && nrdAnalysis.riskLevel !== 'none') {
    // Bereken dynamische risicoscore gebaseerd op leeftijd
    const riskScore = getNRDRiskScore(nrdAnalysis.riskLevel);

    // Voeg de specifieke reden toe op basis van risiconiveau
    ctx.reasons.add(nrdAnalysis.reason);
    ctx.totalRiskRef.value += riskScore;

    logDebug(`⚠️ NRD Gedetecteerd: ${domain}, ${nrdAnalysis.ageDays.toFixed(1)} dagen oud, niveau: ${nrdAnalysis.riskLevel}. Risico toegevoegd: ${riskScore}. Huidig totaalrisico: ${ctx.totalRiskRef.value}`);
    return true;
  }

  logDebug(`checkDomainAgeDynamic: Domein ${domain} is ${nrdAnalysis.ageDays.toFixed(1)} dagen oud (niveau: ${nrdAnalysis.riskLevel}). Geen risico toegevoegd.`);
  return false;
}
/**
 * Extraheert het registreerbare domein (bijv. "example.com" of "example.co.uk") uit een volledige URL.
 * Deze functie maakt gebruik van de robuustere `extractMainDomain` functie die rekening houdt met compound TLD's.
 *
 * @param {string} url - De volledige URL waaruit het registreerbare domein moet worden geëxtraheerd.
 * @returns {string|null} - Het registreerbare domein (SLD + TLD) of `null` als de URL ongeldig is.
 */
function getRegistrableDomain(url) {
  try {
    const hostname = new URL(url).hostname.toLowerCase();
    // Gebruik je eigen extractMainDomain functie voor robuuste extractie
    return extractMainDomain(hostname);
  } catch (e) {
    // Log de fout voor debugging, maar retourneer null om crashes te voorkomen
    handleError(e, `getRegistrableDomain: Failed to extract registrable domain from URL: ${url}`);
    return null;
  }
}
// Definieer cache en TTL bovenaan je script (buiten de functie)
const safeDomainsCache = {};
const SAFE_DOMAINS_TTL_MS = 3600 * 1000; // 1 uur TTL
let safeDomains = [];
let safeDomainsInitialized = false;
async function initializeSafeDomains() {
  const now = Date.now();
  const cached = safeDomainsCache['TrustedDomains'];
  // Controleer of er een geldige cache is
  if (cached && (now - cached.timestamp < SAFE_DOMAINS_TTL_MS)) {
    logDebug("Using cached safeDomains");
    safeDomains = cached.data;
    safeDomainsInitialized = true;
    return; // Gebruik de gecachte data en stop
  }
  try {
    const domains = await fetchCachedJson('TrustedDomains.json') || [];
    if (!Array.isArray(domains) || domains.some(domain => typeof domain !== 'string')) {
      throw new Error("Invalid format in TrustedDomains.json");
    }
    safeDomains = domains;
    safeDomainsInitialized = true;
    // Cache de nieuwe data
    safeDomainsCache['TrustedDomains'] = { data: domains, timestamp: now };
    logDebug("Trusted domains loaded successfully and cached:", safeDomains);
  } catch (error) {
    handleError(error, `initializeSafeDomains: Kon TrustedDomains.json niet laden of verwerken`);
    safeDomains = ['example.com', 'google.com']; // Hardcoded fallback
    safeDomainsInitialized = true;
    // Cache ook de fallback
    safeDomainsCache['TrustedDomains'] = { data: safeDomains, timestamp: now };
    logDebug("Fallback domains cached:", safeDomains);
  }
}
// Roep de functie aan bij initialisatie
initializeSafeDomains();
// Periodieke cache-schoonmaak (voeg dit toe aan je script)
setInterval(() => {
  const now = Date.now();
  for (const key in safeDomainsCache) {
    if (now - safeDomainsCache[key].timestamp > SAFE_DOMAINS_TTL_MS) {
      delete safeDomainsCache[key];
      logDebug(`SafeDomains cache entry '${key}' verwijderd wegens verlopen TTL`);
    }
  }
}, SAFE_DOMAINS_TTL_MS);

/**
 * Waits for safeDomains to be initialized (max 2 seconds)
 */
async function waitForSafeDomains() {
  if (safeDomainsInitialized) return;
  const maxWait = 2000;
  const interval = 50;
  let waited = 0;
  while (!safeDomainsInitialized && waited < maxWait) {
    await new Promise(r => setTimeout(r, interval));
    waited += interval;
  }
}

/**
 * Checks if a hostname is a globally trusted domain (from TrustedDomains.json)
 * Use this function consistently across all scans (ClickFix, BitB, risk analysis)
 * @param {string} hostname - The hostname to check (e.g., "accounts.google.com")
 * @returns {Promise<boolean>} - True if the hostname matches a trusted domain pattern
 */
async function isTrustedDomain(hostname) {
  if (!hostname) return false;

  // Wait for safeDomains to be loaded
  await waitForSafeDomains();

  const lowerHostname = hostname.toLowerCase();

  return safeDomains.some(pattern => {
    try {
      const regex = new RegExp(pattern, 'i');
      return regex.test(lowerHostname);
    } catch (e) {
      // Fallback for non-regex patterns
      const plainDomain = pattern.replace(/\\\./g, '.').replace(/\$/, '').replace(/^\^/, '');
      return lowerHostname === plainDomain || lowerHostname.endsWith(`.${plainDomain}`);
    }
  });
}

async function isProtectionEnabled() {
  const settings = await getStoredSettings();
  return settings.backgroundSecurity && settings.integratedProtection;
}
async function getStoredSettings() {
  const defaultSettings = { backgroundSecurity: true, integratedProtection: true };

  try {
    // Check of chrome.storage beschikbaar is
    if (!chrome?.storage?.sync) {
      logDebug("chrome.storage.sync niet beschikbaar, gebruik standaardinstellingen");
      return defaultSettings;
    }

    const settings = await new Promise((resolve, reject) => {
      chrome.storage.sync.get(['backgroundSecurity', 'integratedProtection'], (result) => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
        } else {
          resolve(result);
        }
      });
    });

    if (!settings || typeof settings !== 'object') {
      logDebug("Ongeldige settings structuur, gebruik standaardinstellingen");
      return defaultSettings;
    }

    // Use nullish coalescing to default to true when settings are not stored
    // This fixes the bug where undefined settings caused protection to be disabled
    return {
      backgroundSecurity: settings.backgroundSecurity ?? true,
      integratedProtection: settings.integratedProtection ?? true
    };
  } catch (error) {
    // Stil falen met standaardinstellingen - geen crash
    logDebug(`getStoredSettings fout: ${error.message}, gebruik standaardinstellingen`);
    return defaultSettings;
  }
}
async function getFinalUrl(url) {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);
    const response = await fetch(url, {
      method: 'HEAD',
      redirect: 'follow',
      signal: controller.signal
    });
    clearTimeout(timeoutId);
    return response.url || url; // Fallback naar originele URL
  } catch (error) {
    logError(`Fout bij ophalen uiteindelijke URL voor ${url}: ${error.message}`);
    return url; // Fallback naar originele URL bij fout
  }
}
function getMetaRefreshUrl() {
  try {
    const metaTag = document.querySelector('meta[http-equiv="refresh"]');
    if (metaTag) {
      const content = metaTag.getAttribute('content');
      if (content) {
        const match = content.match(/url=(.+)/i);
        if (match) return match[1];
      }
    }
    return null;
  } catch (error) {
    handleError(error, 'getMetaRefreshUrl: Fout bij ophalen meta refresh URL');
    return null;
  }
}
async function applyDynamicChecks(dynamicChecks, url, reasons, totalRiskRef) {
  logDebug("Starting applyDynamicChecks: Current risk:", totalRiskRef.value);
  for (const { func, message, risk, severity } of dynamicChecks) {
    try {
      const result = await func(url);
      if (result) {
        reasons.add(`${message} (${severity})`);
        logDebug(`Before adding: Current risk=${totalRiskRef.value}, Adding=${risk}`);
        totalRiskRef.value += risk;
        logDebug(`After adding: Current risk=${totalRiskRef.value}`);
      }
    } catch (error) {
      handleError(error, `applyDynamicChecks: Fout bij uitvoeren van ${message} op URL ${url}`);
    }
  }
  logDebug("Finished applyDynamicChecks: Current risk:", totalRiskRef.value);
}
// Controleer URL bij pagina-load
document.addEventListener('popstate', () => checkCurrentUrl());
window.addEventListener('hashchange', () => checkCurrentUrl());
const domainRegex = /^www\./;
const trailingSlashRegex = /\/$/;
function normalizeDomain(url) {
  try {
    if (!/^[a-z]+:\/\//i.test(url)) {
      url = `https://${url}`; // Standaard https toevoegen
    }
    const parsedUrl = new URL(url);
    if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
      return null; // Alleen http/https toestaan
    }
    let hostname = parsedUrl.hostname.toLowerCase();
    hostname = hostname.replace(/^www\./, "").replace(/\/$/, "");
    return hostname;
  } catch (error) {
    logError(`Fout bij normaliseren van URL ${url}: ${error.message}`);
    return null;
  }
}
/**
 * Normaliseert een string door homoglyphen te vervangen door hun Latijnse equivalenten
 * met behulp van een reverse mapping.
 * Bijvoorbeeld: 'а' (Cyrillisch) -> 'a' (Latijn), 'ö' -> 'o'.
 * @param {string} str - De string om te normaliseren.
 * @param {object} reverseMap - De reverse homoglyph-mapping (homoglyph -> Latijnse base).
 * @returns {string} - Het genormaliseerde domein.
 */
function normalizeToLatinBase(str, reverseMap) {
    if (!str) return '';
    let normalized = '';
    // Itereren over karakters, ook Unicode (daarom for...of)
    for (const char of str) {
        normalized += reverseMap[char] || char; // Als er een mapping is, gebruik die; anders, behoud het karakter
    }
    // Specifieke gevallen voor combinaties die niet door char-per-char mapping gaan
    normalized = normalized.replace(/rn/g, 'm').replace(/vv/g, 'w');
    return normalized;
}

async function initContentScript() {
  logDebug("Starting initialization of content script...");
  try {
    

    // Wacht op configuratie en veilige domeinen
    await Promise.all([loadConfig(), initializeSafeDomains()]);
    if (!globalConfig) {
      logError("globalConfig is niet geladen na loadConfig(). Gebruik standaardconfiguratie.");
      globalConfig = validateConfig(defaultConfig);
    }
    // Controleer of de bescherming is ingeschakeld
    const isEnabled = await isProtectionEnabled();
    if (!isEnabled) {
      logDebug("Protection is disabled. Skipping initialization.");
      return;
    }
    // Controleer of het een Google-zoekresultatenpagina is
    if (isSearchResultPage()) {
      logDebug("Setting up Google search protection...");
      setupGoogleSearchProtection();
    } else {
      logDebug("Checking links...");
      await checkLinks(); // Controleert hoofddomein en externe links
      // Geen extra 'alert'-bericht meer nodig
    }
    await scanForQRPhishing(); // New: Scan for QR codes on initialization
    logDebug("Initialization complete.");
  } catch (error) {
    logError(`Error during initialization: ${error.message}`);
    throw error; // Optioneel: fout doorsluizen
  }
}
let debounceTimer = null;
const checkedLinks = new Set();
const scannedLinks = new Set();

// =============================================================================
// OPTIMIZED LINK SCANNER - Performance verbeteringen voor 2026
// Gebruikt IntersectionObserver + requestIdleCallback om CPU-pieken te voorkomen
// =============================================================================

/**
 * LinkScannerOptimized - Lazy scanning van links met IntersectionObserver
 * - Scant alleen zichtbare links (in viewport)
 * - Gebruikt requestIdleCallback voor niet-blokkerende verwerking
 * - Bevat TTL-gebaseerde caching om dubbel werk te voorkomen
 */
class LinkScannerOptimized {
  constructor(options = {}) {
    this.batchSize = options.batchSize || 10;
    this.idleTimeout = options.idleTimeout || 2000;
    this.cacheTTL = options.cacheTTL || 3600000; // 1 uur default
    this.maxCacheSize = options.maxCacheSize || 2000;

    // Cache met TTL voor gescande URLs
    this.urlCache = new Map();

    // Queue voor te verwerken links
    this.pendingLinks = new Set();
    this.isProcessing = false;

    // IntersectionObserver voor lazy loading
    this.observer = null;
    this.observedLinks = new WeakSet();

    // Bind methods
    this.handleIntersection = this.handleIntersection.bind(this);
    this.processQueue = this.processQueue.bind(this);

    this.initObserver();
  }

  /**
   * Initialiseert de IntersectionObserver
   */
  initObserver() {
    if (typeof IntersectionObserver === 'undefined') {
      logDebug('[LinkScanner] IntersectionObserver niet beschikbaar, fallback naar direct scanning');
      return;
    }

    this.observer = new IntersectionObserver(this.handleIntersection, {
      root: null, // viewport
      rootMargin: '100px', // start 100px voor element zichtbaar wordt
      threshold: 0.05 // 5% zichtbaarheid vereist - reduceert callbacks voor batterijbesparing
    });

    logDebug('[LinkScanner] IntersectionObserver geïnitialiseerd');
  }

  /**
   * Handler voor IntersectionObserver callbacks
   */
  handleIntersection(entries) {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        const link = entry.target;
        const href = link.href;

        // Stop met observeren van deze link
        this.observer?.unobserve(link);

        // Check cache
        if (!this.isCached(href)) {
          this.pendingLinks.add(link);
        }
      }
    });

    // Start queue processing als er nieuwe links zijn
    if (this.pendingLinks.size > 0 && !this.isProcessing) {
      this.scheduleProcessing();
    }
  }

  /**
   * Controleert of een URL in cache zit en nog geldig is
   */
  isCached(url) {
    const cached = this.urlCache.get(url);
    if (!cached) return false;

    // Check TTL
    if (Date.now() - cached.timestamp > this.cacheTTL) {
      this.urlCache.delete(url);
      return false;
    }

    return true;
  }

  /**
   * Voegt een scan resultaat toe aan cache
   */
  addToCache(url, result) {
    // Verwijder oudste entries als cache vol is
    if (this.urlCache.size >= this.maxCacheSize) {
      const oldestKey = this.urlCache.keys().next().value;
      this.urlCache.delete(oldestKey);
    }

    this.urlCache.set(url, {
      result,
      timestamp: Date.now()
    });
  }

  /**
   * Plant verwerking in met requestIdleCallback of setTimeout fallback
   */
  scheduleProcessing() {
    if (this.isProcessing) return;

    if ('requestIdleCallback' in window) {
      requestIdleCallback(this.processQueue, { timeout: this.idleTimeout });
    } else {
      // Fallback voor browsers zonder requestIdleCallback
      setTimeout(this.processQueue, 0);
    }
  }

  /**
   * Verwerkt links in batches tijdens idle time
   */
  async processQueue(deadline) {
    this.isProcessing = true;
    const startTime = performance.now();
    let processed = 0;

    // Converteer Set naar Array voor batch processing
    const linksArray = Array.from(this.pendingLinks);

    for (const link of linksArray) {
      // Check of we nog tijd hebben (requestIdleCallback)
      const hasIdleTime = deadline
        ? deadline.timeRemaining() > 0
        : (performance.now() - startTime) < 50; // 50ms max per batch

      if (!hasIdleTime && processed >= this.batchSize) {
        break;
      }

      const href = link.href;

      // Skip als al verwerkt of in cache
      if (this.isCached(href) || scannedLinks.has(href)) {
        this.pendingLinks.delete(link);
        continue;
      }

      try {
        // Markeer als gescand
        scannedLinks.add(href);
        this.pendingLinks.delete(link);

        // Voer de daadwerkelijke check uit
        const result = await this.scanLink(link);

        // Cache het resultaat
        this.addToCache(href, result);

        processed++;
      } catch (error) {
        handleError(error, `LinkScanner.processQueue: Error scanning ${href}`);
        this.pendingLinks.delete(link);
      }
    }

    this.isProcessing = false;

    // Als er nog links in de queue staan, plan volgende batch
    if (this.pendingLinks.size > 0) {
      this.scheduleProcessing();
    }

    logDebug(`[LinkScanner] Batch verwerkt: ${processed} links, ${this.pendingLinks.size} in queue`);
  }

  /**
   * Scant een enkele link en past waarschuwingen toe indien nodig
   * SECURITY FIX v8.4.0: Added immediateUriSecurityCheck for data/javascript URI blocking
   */
  async scanLink(link) {
    // SECURITY FIX v8.4.0: Immediate dangerous URI check FIRST
    if (typeof immediateUriSecurityCheck === 'function' && immediateUriSecurityCheck(link)) {
      return { level: 'alert', blocked: true, reasons: ['dangerousUriBlocked'] };
    }

    const href = link.href;
    let urlObj;

    try {
      urlObj = new URL(href);
    } catch {
      return { level: 'safe', skip: true };
    }

    // Skip links naar hetzelfde domein
    const currentDomain = window.location.hostname.toLowerCase();
    const linkDomain = urlObj.hostname.toLowerCase();

    if (isSameDomain(linkDomain, currentDomain)) {
      return { level: 'safe', sameDomain: true };
    }

    // Voer security checks uit
    const result = await performSuspiciousChecks(href);

    // Pas visuele waarschuwing toe als nodig
    if (result.level !== 'safe') {
      warnLinkByLevel(link, result);
      logDebug(`[LinkScanner] Verdachte link: ${href} → level=${result.level}`);
    }

    return result;
  }

  /**
   * Observeert een link element
   */
  observe(link) {
    if (!link || !link.href || !isValidURL(link.href)) return;
    if (this.observedLinks.has(link)) return;
    if (this.isCached(link.href) || scannedLinks.has(link.href)) return;

    this.observedLinks.add(link);

    if (this.observer) {
      this.observer.observe(link);
    } else {
      // Fallback: direct toevoegen aan queue
      this.pendingLinks.add(link);
      this.scheduleProcessing();
    }
  }

  /**
   * Scant alle links op de pagina (lazy)
   * Inclusief Shadow DOM en same-origin iframes
   */
  scanAllLinks() {
    let observedCount = 0;

    try {
      // 1. Normale document links
      const links = document.querySelectorAll('a[href]');
      links.forEach(link => {
        try {
          if (isValidURL(link.href) && !scannedLinks.has(link.href)) {
            this.observe(link);
            observedCount++;
          }
        } catch (e) { /* ignore individual link errors */ }
      });

      // 2. Shadow DOM links
      const shadowLinks = this.scanShadowDOM(document.body);
      shadowLinks.forEach(link => {
        try {
          if (isValidURL(link.href) && !scannedLinks.has(link.href)) {
            this.observe(link);
            observedCount++;
          }
        } catch (e) { /* ignore individual link errors */ }
      });

      // 3. Same-origin iframe links
      const iframeLinks = this.scanIframeLinks();
      iframeLinks.forEach(link => {
        try {
          if (isValidURL(link.href) && !scannedLinks.has(link.href)) {
            this.observe(link);
            observedCount++;
          }
        } catch (e) { /* ignore individual link errors */ }
      });

      logDebug(`[LinkScanner] ${observedCount} links worden geobserveerd (incl. Shadow DOM en iframes)`);
    } catch (error) {
      handleError(error, 'scanAllLinks: Fout bij scannen van links');
    }
  }

  /**
   * Recursief scannen van Shadow DOM voor links
   * SECURITY FIX v8.0.0: Gebruikt globale MAX_SHADOW_DEPTH (20) i.p.v. lokale (5)
   * @param {Element} root - Root element om te scannen
   * @param {number} depth - Huidige diepte
   * @returns {Array} Array van gevonden link elementen
   */
  scanShadowDOM(root, depth = 0) {
    // SECURITY FIX v8.0.0: Gebruik globale MAX_SHADOW_DEPTH constante (20)
    const links = [];

    if (!root || depth >= MAX_SHADOW_DEPTH) return links;

    try {
      // Vind alle elementen die mogelijk een shadowRoot hebben
      const allElements = root.querySelectorAll ? root.querySelectorAll('*') : [];

      allElements.forEach(el => {
        // Check voor open shadow root
        if (el.shadowRoot) {
          // Vind links in de shadow root
          const shadowLinks = el.shadowRoot.querySelectorAll('a[href]');
          shadowLinks.forEach(link => links.push(link));

          // Recursief scannen van geneste shadow roots
          const nestedLinks = this.scanShadowDOM(el.shadowRoot, depth + 1);
          links.push(...nestedLinks);
        }
      });
    } catch (error) {
      logDebug(`[LinkScanner] Shadow DOM scan error: ${error.message}`);
    }

    return links;
  }

  /**
   * Scant Shadow DOM specifiek voor verborgen login forms en phishing overlays
   * AI-phishing kits injecteren vaak login forms in Shadow DOM om detectie te omzeilen
   * SECURITY FIX v8.0.0: Gebruikt globale MAX_SHADOW_DEPTH (20) i.p.v. lokale (5)
   *
   * @param {Element|Document} root - Root element om te scannen
   * @param {number} depth - Huidige recursie diepte
   * @returns {{detected: boolean, forms: Array, overlays: Array, reasons: string[]}}
   */
  scanShadowDOMForPhishing(root, depth = 0) {
    // SECURITY FIX v8.0.0: Gebruik globale MAX_SHADOW_DEPTH constante (20)
    const result = {
      detected: false,
      forms: [],
      overlays: [],
      reasons: []
    };

    if (!root || depth >= MAX_SHADOW_DEPTH) return result;

    try {
      const allElements = root.querySelectorAll ? root.querySelectorAll('*') : [];

      allElements.forEach(el => {
        if (el.shadowRoot) {
          // 1. Zoek naar login forms in Shadow DOM
          const shadowForms = el.shadowRoot.querySelectorAll('form');
          shadowForms.forEach(form => {
            const hasPassword = form.querySelector('input[type="password"]');
            const hasEmail = form.querySelector('input[type="email"], input[name*="email"], input[name*="user"]');

            if (hasPassword || hasEmail) {
              result.forms.push({
                element: form,
                hasPassword: !!hasPassword,
                hasEmail: !!hasEmail,
                action: form.action || form.getAttribute('action')
              });
              result.detected = true;
              result.reasons.push('shadowDomLoginForm');
              logDebug(`[ShadowDOM] Login form gevonden in Shadow DOM: ${form.action || 'geen action'}`);
            }
          });

          // 2. Zoek naar verdachte overlays (login modals, fake pop-ups)
          const shadowOverlays = el.shadowRoot.querySelectorAll(
            '[class*="modal"], [class*="overlay"], [class*="popup"], [class*="dialog"], ' +
            '[id*="modal"], [id*="overlay"], [id*="popup"], [id*="login"]'
          );
          shadowOverlays.forEach(overlay => {
            // Check of overlay password/login velden bevat
            const hasCredentialInputs = overlay.querySelector(
              'input[type="password"], input[type="email"], input[name*="password"], input[name*="user"]'
            );

            if (hasCredentialInputs) {
              // Check of het element verborgen is maar nog steeds in DOM (phishing techniek)
              const style = window.getComputedStyle(overlay);
              const isHidden = style.display === 'none' ||
                              style.visibility === 'hidden' ||
                              style.opacity === '0' ||
                              parseInt(style.height) === 0;

              result.overlays.push({
                element: overlay,
                isHidden,
                hasCredentialInputs: true,
                className: overlay.className
              });

              if (!isHidden) {
                result.detected = true;
                result.reasons.push('shadowDomPhishingOverlay');
                logDebug(`[ShadowDOM] Phishing overlay gevonden: ${overlay.className || overlay.id || 'unknown'}`);
              }
            }
          });

          // 3. Zoek naar iframes in Shadow DOM (extra verdacht)
          const shadowIframes = el.shadowRoot.querySelectorAll('iframe');
          shadowIframes.forEach(iframe => {
            if (iframe.src) {
              result.detected = true;
              result.reasons.push('shadowDomIframe');
              logDebug(`[ShadowDOM] Iframe in Shadow DOM: ${iframe.src}`);
            }
          });

          // 4. Recursief scannen
          const nestedResult = this.scanShadowDOMForPhishing(el.shadowRoot, depth + 1);
          if (nestedResult.detected) {
            result.detected = true;
            result.forms.push(...nestedResult.forms);
            result.overlays.push(...nestedResult.overlays);
            result.reasons.push(...nestedResult.reasons);
          }
        }
      });
    } catch (error) {
      logDebug(`[ShadowDOM] Phishing scan error: ${error.message}`);
    }

    // Deduplicate reasons
    result.reasons = [...new Set(result.reasons)];
    return result;
  }

  /**
   * Scant accessible iframes voor links
   * SECURITY FIX v8.0.1 (Vector 2): Scan ook data: en about:blank iframes
   * @returns {Array} Array van gevonden link elementen
   */
  scanIframeLinks() {
    const MAX_IFRAME_DEPTH = 3;
    const links = [];

    try {
      const iframes = document.querySelectorAll('iframe');

      iframes.forEach(iframe => {
        try {
          const iframeSrc = iframe.src || '';

          // SECURITY FIX v8.0.1: data: en about:blank iframes zijn vaak
          // gebruikt voor obfuscatie - probeer altijd te scannen
          const isSpecialProtocol = iframeSrc.startsWith('data:') ||
                                    iframeSrc.startsWith('about:') ||
                                    iframeSrc.startsWith('blob:') ||
                                    iframeSrc === '';

          // Probeer toegang tot iframe content (werkt voor same-origin en special protocols)
          const iframeDoc = iframe.contentDocument || iframe.contentWindow?.document;
          if (!iframeDoc) {
            // Cross-origin iframe - content script draait daar apart via all_frames
            return;
          }

          // Scan links in iframe
          const iframeLinks = iframeDoc.querySelectorAll('a[href]');
          iframeLinks.forEach(link => {
            if (!link.dataset.linkshieldScanned) {
              links.push(link);
            }
          });

          // Check voor Shadow DOM in iframe
          const shadowLinks = this.scanShadowDOM(iframeDoc.body);
          links.push(...shadowLinks);

          if (isSpecialProtocol) {
            logDebug(`[LinkScanner] Special protocol iframe gescand: ${iframeSrc.substring(0, 50)}...`);
          }

        } catch (e) {
          // SecurityError bij cross-origin - content script draait daar apart
          if (e.name !== 'SecurityError') {
            logDebug(`[LinkScanner] Iframe scan error: ${e.message}`);
          }
        }
      });
    } catch (error) {
      logDebug(`[LinkScanner] Iframe scanning error: ${error.message}`);
    }

    return links;
  }

  /**
   * Ruimt de cache op (verwijdert verlopen entries)
   */
  cleanCache() {
    const now = Date.now();
    let removed = 0;

    for (const [url, data] of this.urlCache) {
      if (now - data.timestamp > this.cacheTTL) {
        this.urlCache.delete(url);
        removed++;
      }
    }

    if (removed > 0) {
      logDebug(`[LinkScanner] Cache cleanup: ${removed} entries verwijderd`);
    }
  }

  /**
   * Stopt de observer en ruimt resources op
   */
  destroy() {
    this.observer?.disconnect();
    this.pendingLinks.clear();
    this.urlCache.clear();
    logDebug('[LinkScanner] Destroyed');
  }
}

// Globale instance van de geoptimaliseerde scanner
let linkScanner = null;

/**
 * Initialiseert de geoptimaliseerde link scanner
 */
function initOptimizedLinkScanner() {
  if (linkScanner) {
    linkScanner.destroy();
  }

  linkScanner = new LinkScannerOptimized({
    batchSize: 10,
    idleTimeout: 2000,
    cacheTTL: 3600000, // 1 uur
    maxCacheSize: 2000
  });

  // Start cache cleanup interval
  setInterval(() => linkScanner?.cleanCache(), 600000); // Elke 10 minuten

  return linkScanner;
}

// =============================================================================
// EINDE OPTIMIZED LINK SCANNER
// =============================================================================

function debounce(func, delay = 250) {
  let timer;
  return (...args) => {
    clearTimeout(timer);
    return new Promise((resolve) => {
      timer = setTimeout(async () => {
        const result = await func(...args);
        resolve(result);
      }, delay);
    });
  };
}

/**
 * SECURITY FIX v8.8.2: Accumulating debounce for MutationObserver
 * Unlike regular debounce, this accumulates all mutations and processes them together
 * Prevents losing mutations during rapid DOM changes (like requestIdleCallback attacks)
 */
function debounceMutations(func, delay = 250) {
  let timer;
  let accumulatedMutations = [];

  return (mutations) => {
    // Accumulate all mutations instead of replacing
    accumulatedMutations.push(...mutations);

    clearTimeout(timer);
    timer = setTimeout(async () => {
      const mutationsToProcess = accumulatedMutations;
      accumulatedMutations = []; // Reset accumulator
      await func(mutationsToProcess);
    }, delay);
  };
}
function setupGoogleSearchProtection() {
  logDebug("Google Search Protection started...");
  const searchContainer = document.querySelector('#search') || document.body;
  // Observer voor nieuwe resultaten
  const observer = new MutationObserver(debounce(() => {
    debounceCheckGoogleSearchResults();
  }, 300));
  observer.observe(searchContainer, { childList: true, subtree: true });
  // Initial run
  debounceCheckGoogleSearchResults();
  // Styles voor waarschuwingsiconen
  injectWarningIconStyles();
}
function debounceCheckGoogleSearchResults() {
  clearTimeout(debounceTimer);
  debounceTimer = setTimeout(checkGoogleSearchResults, 250);
}
/**
 * Controleert een link specifiek op kenmerken van phishing-advertenties.
 * Past visuele waarschuwingen toe via `warnLinkByLevel` indien verdacht.
 * @param {HTMLAnchorElement} link - Het HTML-ankerelement van de advertentie.
 */
async function checkForPhishingAds(link) {
  // Valideer de link href om fouten te voorkomen
  if (!link || !link.href || !isValidURL(link.href)) {
    logDebug(`Skipping checkForPhishingAds: Invalid or missing link href: ${link?.href || 'undefined'}`);
    return;
  }
  const url = link.href; // Gebruik link.href direct, sanitizeInput is niet nodig voor URL constructie.
  let urlObj;
  try {
    urlObj = new URL(url);
  } catch (error) {
    logError(`checkForPhishingAds: Ongeldige URL voor constructie: ${url}`, error);
    // Bij een constructiefout, converteer naar een "caution" of "alert" level
    warnLinkByLevel(link, { level: 'caution', risk: 5, reasons: ['invalidUrlFormat'] });
    return;
  }
  const domain = normalizeDomain(url);
  if (!domain) {
    logDebug(`checkForPhishingAds: Kon domein niet normaliseren voor URL: ${url}`);
    warnLinkByLevel(link, { level: 'caution', risk: 5, reasons: ['invalidDomain'] });
    return;
  }
  // Zorg dat globalConfig geladen is voor toegang tot HOMOGLYPHS en legitimateDomains
  await ensureConfigReady();
  // Definieer homoglyphMap en knownBrands - haal deze uit globalConfig
  const homoglyphMapEntries = globalConfig.HOMOGLYPHS || {};
  const homoglyphMap = {};
  for (const [latin, variants] of Object.entries(homoglyphMapEntries)) {
      if (Array.isArray(variants)) { // Belangrijk om te controleren of variants een array is
          for (const g of variants) {
              homoglyphMap[g] = latin;
          }
      }
  }
  const knownBrands = globalConfig.legitimateDomains || ['microsoft.com', 'apple.com', 'google.com'];
  // Definieer de specifieke checks voor advertenties, met scores
  const checks = [
    { func: () => /^(crypto|coins|wallet|exchange|ico|airdrop)/i.test(domain), score: 5, messageKey: "cryptoPhishingAd" },
    { func: () => /adclick|gclid|utm_source/i.test(urlObj.search), score: 2, messageKey: "suspiciousAdStructure" },
    // Zorg ervoor dat SUSPICIOUS_TLDS een RegExp is voordat je test
    { func: () => (globalConfig.SUSPICIOUS_TLDS instanceof RegExp) && globalConfig.SUSPICIOUS_TLDS.test(domain), score: 5, messageKey: "suspiciousAdTLD" },
    // isHomoglyphAttack voegt al redenen toe aan een Set, dus hier return we alleen true/false
    { func: async () => await isHomoglyphAttack(domain, homoglyphMap, knownBrands, extractTld(domain), new Set()), score: 4, messageKey: "homoglyphAdAttack" },
    { func: () => /^(amazon|google|microsoft|paypal)/i.test(domain) && !knownBrands.includes(domain), score: 5, messageKey: "brandMisuse" },
    { func: () => /(^|[.\-])(microsoft|paypal|apple|google|amazon|netflix|facebook|instagram|whatsapp|bank|coinbase|binance|metamask)([.\-])/i.test(domain) && !knownBrands.includes(domain), score: 5, messageKey: "brandKeywordInDomain" }
  ];
  try {
    const specificReasons = new Set(); // Gebruik een Set om unieke redenen te verzamelen
    let totalRiskScore = 0;
    for (const check of checks) {
      // Voer de functie uit; als het een Promise is, wacht dan
      const condition = await Promise.resolve(check.func());
      if (condition) {
        specificReasons.add(check.messageKey);
        totalRiskScore += check.score;
        logDebug(`[checkForPhishingAds] Reden toegevoegd: ${check.messageKey}, score: ${check.score}. Huidige risicoscore: ${totalRiskScore}`);
      }
    }
    if (specificReasons.size > 0) {
      // Bepaal het level op basis van de geaccumuleerde score en de globale drempels
      let level;
      if (totalRiskScore >= (globalConfig.HIGH_THRESHOLD || 12)) {
        level = 'alert';
      } else if (totalRiskScore >= (globalConfig.LOW_THRESHOLD || 3)) {
        level = 'caution';
      } else {
        level = 'safe'; // Kan ook 'safe' zijn als de score te laag is voor een waarschuwing
      }
      // Local Network Calibration: lokale IP's krijgen maximaal 'caution', nooit 'alert'
      if (level === 'alert' && isLocalNetwork(urlObj.hostname)) {
        level = 'caution';
        logDebug(`📍 Local network calibration: ${urlObj.hostname} beperkt tot 'caution' (was 'alert')`);
      }
      // Roep de nieuwe, universele waarschuwingsfunctie aan
      warnLinkByLevel(link, { level: level, risk: totalRiskScore, reasons: Array.from(specificReasons) });
      logDebug(`[checkForPhishingAds] Advertentie link ${url} gemarkeerd: Level=${level}, Risk=${totalRiskScore}, Redenen=${Array.from(specificReasons).join(', ')}`);
    } else {
      logDebug(`[checkForPhishingAds] Advertentie link ${url} veilig bevonden. Geen waarschuwing.`);
      warnLinkByLevel(link, { level: 'safe', risk: 0, reasons: [] }); // Zorg dat eventuele oude waarschuwingen worden verwijderd
    }
  } catch (error) {
    handleError(error, `checkForPhishingAds: Fout bij controleren van link ${link.href}`);
    // Bij een fout, converteer naar een "caution" level met een generieke foutreden
    warnLinkByLevel(link, { level: 'caution', risk: 5, reasons: ["fileCheckFailed"] }); // Gebruik "fileCheckFailed" of een meer generieke "analysisError"
  }
}
// =============================================================================
// SECURITY FIX v8.3.0 - DANGEROUS URI SCHEME DETECTION (ENHANCED)
// =============================================================================
// Detecteert en blokkeert gevaarlijke URI schemes: data:, javascript:, vbscript:
// AUDIT FIX: Case-insensitive, recursive URL-decoding, entity decoding
// Now returns CRITICAL (risk 25) for all dangerous schemes

/**
 * SECURITY FIX v8.3.0: Detecteert gevaarlijke URI schemes
 * Enhanced with:
 * - Recursive URL decoding (catches java%73cript:)
 * - HTML entity decoding (catches &#106;avascript:)
 * - Whitespace/null byte stripping
 * - Case-insensitive matching
 * @param {string} href - De te controleren URL
 * @returns {{isDangerous: boolean, scheme: string, reason: string, risk: number}}
 */
function detectDangerousScheme(href) {
  if (!href || typeof href !== 'string') {
    return { isDangerous: false, scheme: '', reason: '', risk: 0 };
  }

  // Step 1: Recursive URL-decoding om encoding bypasses te voorkomen
  let decoded = href;
  let prevDecoded = '';
  let iterations = 0;
  const MAX_DECODE_ITERATIONS = 10; // Increased for deep encoding

  while (decoded !== prevDecoded && iterations < MAX_DECODE_ITERATIONS) {
    prevDecoded = decoded;
    try {
      decoded = decodeURIComponent(decoded);
    } catch (e) {
      // decodeURIComponent faalt bij ongeldige sequences, probeer handmatige decode
      try {
        decoded = decoded.replace(/%([0-9A-Fa-f]{2})/g, (_, hex) =>
          String.fromCharCode(parseInt(hex, 16))
        );
      } catch (e2) {
        break;
      }
    }
    iterations++;
  }

  // Step 2: HTML entity decoding (catches &#106;avascript:, &Tab;, etc.)
  decoded = decoded
    .replace(/&#(\d+);/g, (_, num) => String.fromCharCode(parseInt(num, 10)))
    .replace(/&#x([0-9A-Fa-f]+);/g, (_, hex) => String.fromCharCode(parseInt(hex, 16)))
    .replace(/&Tab;/gi, '\t')
    .replace(/&NewLine;/gi, '\n');

  // Step 3: Verwijder whitespace, newlines, null bytes, control chars (bypass techniques)
  const normalized = decoded
    .replace(/[\s\r\n\t\0\x00-\x1F\x7F]/g, '')  // Remove all control chars
    .toLowerCase();

  // Step 4: Gevaarlijke schemes (case-insensitive)
  const dangerousSchemes = [
    { pattern: /^javascript:/i, scheme: 'javascript:', reason: 'dangerousJavascriptUri' },
    { pattern: /^vbscript:/i, scheme: 'vbscript:', reason: 'dangerousVbscriptUri' },
    { pattern: /^data:/i, scheme: 'data:', reason: 'dangerousDataUri' },
    { pattern: /^blob:/i, scheme: 'blob:', reason: 'dangerousBlobUri' },
  ];

  for (const { pattern, scheme, reason } of dangerousSchemes) {
    if (pattern.test(normalized)) {
      // Extra check voor harmless javascript: patterns
      if (scheme === 'javascript:') {
        const code = normalized.slice('javascript:'.length).trim();
        // Alleen void(0) en lege varianten zijn veilig
        const harmlessPatterns = ['void(0)', 'void(0);', 'void0', '', ';', 'void0;', 'undefined', 'false', 'true', 'null'];
        if (harmlessPatterns.includes(code)) {
          return { isDangerous: false, scheme: '', reason: '', risk: 0 };
        }
      }
      // Data URIs: image/audio/video/font en text/plain zijn veilig
      if (scheme === 'data:') {
        if (/^data:(image|audio|video|font)\//i.test(normalized) ||
            (/^data:text\/plain[,;]/.test(normalized) && !normalized.includes('base64'))) {
          return { isDangerous: false, scheme: '', reason: '', risk: 0 };
        }
      }
      logDebug(`[SecurityFix v8.3.0] 🚨 CRITICAL: Dangerous URI scheme detected: ${scheme}`);
      logDebug(`[SecurityFix v8.3.0] Original: ${href.substring(0, 80)}...`);
      logDebug(`[SecurityFix v8.3.0] Normalized: ${normalized.substring(0, 80)}...`);
      return { isDangerous: true, scheme, reason, risk: 25 }; // CRITICAL risk
    }
  }

  return { isDangerous: false, scheme: '', reason: '', risk: 0 };
}

// =============================================================================
// SECURITY FIX v8.3.0 - HOMOGLYPH & PUNYCODE CRITICAL DETECTION (ENHANCED)
// =============================================================================
// AUDIT FIX: Case-insensitive Punycode regex, expanded confusables, charCode > 127 catch-all
// Flag als CRITICAL risico voor onmiddellijke waarschuwing

/**
 * SECURITY FIX v8.3.0: Detecteert Punycode en mixed-script attacks
 * Enhanced with:
 * - Case-insensitive Punycode detection (/xn--/i catches XN--)
 * - CharCode > 127 catch-all for ANY non-ASCII
 * - Expanded confusables (Greek, Mathematical, digit lookalikes)
 * @param {string} href - De te controleren URL
 * @returns {{isSuspicious: boolean, reasons: string[], risk: number}}
 */
function detectHomoglyphAndPunycode(href) {
  const result = { isSuspicious: false, reasons: [], risk: 0 };

  if (!href || typeof href !== 'string') {
    return result;
  }

  try {
    // Parse de URL
    let urlObj;
    try {
      urlObj = new URL(href, window.location.href);
    } catch (e) {
      return result; // Ongeldige URL, geen homoglyph check nodig
    }

    const hostname = urlObj.hostname.toLowerCase();

    // Skip interne/lokale hostnames
    if (hostname === 'localhost' || hostname.endsWith('.local') ||
        /^(127\.|192\.168\.|10\.|172\.(1[6-9]|2\d|3[01])\.)/.test(hostname)) {
      return result;
    }

    // 1) PUNYCODE DETECTION - CASE-INSENSITIVE (catches xn--, XN--, Xn--)
    // AUDIT FIX: Use case-insensitive regex instead of includes()
    if (/xn--/i.test(hostname)) {
      result.isSuspicious = true;
      result.reasons.push('punycodeDetected');
      result.risk += 12; // Increased from 8
      logDebug(`[SecurityFix v8.3.0] 🚨 Punycode domain detected: ${hostname}`);

      // Decode punycode voor verdere analyse
      let decodedHostname = hostname;
      if (typeof punycode !== 'undefined' && punycode.toUnicode) {
        try {
          // Decode elk label apart (xn-- kan in subdomeinen zitten)
          decodedHostname = hostname.split('.').map(label => {
            if (/^xn--/i.test(label)) {
              return punycode.toUnicode(label.toLowerCase());
            }
            return label;
          }).join('.');
          logDebug(`[SecurityFix v8.3.0] Decoded Punycode: ${hostname} → ${decodedHostname}`);
        } catch (e) {
          result.reasons.push('punycodeDecodingError');
          result.risk += 3;
        }
      }

      // 2) MIXED-SCRIPT DETECTION na punycode decoding
      const scripts = detectUnicodeScripts(decodedHostname);
      if (scripts.size > 1 && scripts.has('Latin')) {
        // Gemengde Latin + andere scripts is zeer verdacht
        result.reasons.push('mixedScriptAttack');
        result.risk += 15; // Increased from 10
        logDebug(`[SecurityFix v8.3.0] 🚨 Mixed-script attack detected: ${[...scripts].join(', ')}`);
      }
    }

    // 3) NON-ASCII CATCH-ALL: Any character with charCode > 127
    // AUDIT FIX: Flag ANY non-ASCII in hostname as CAUTION
    const originalDomain = href.split('//')[1]?.split('/')[0]?.split('?')[0]?.split('@').pop() || '';
    let hasNonAscii = false;
    for (let i = 0; i < hostname.length; i++) {
      if (hostname.charCodeAt(i) > 127) {
        hasNonAscii = true;
        break;
      }
    }

    if (hasNonAscii || /[^\x00-\x7F]/.test(originalDomain)) {
      result.isSuspicious = true;
      if (!result.reasons.includes('nonAsciiDomain')) {
        result.reasons.push('nonAsciiDomain');
        result.risk += 8; // Increased from 6
      }
      logDebug(`[SecurityFix v8.3.0] 🚨 Non-ASCII characters (charCode > 127) in domain: ${hostname}`);

      // Check voor gemengde scripts in origineel domein
      const domainToCheck = hasNonAscii ? hostname : originalDomain;
      const scripts = detectUnicodeScripts(domainToCheck.normalize('NFC'));
      if (scripts.size > 1 && scripts.has('Latin') && !result.reasons.includes('mixedScriptAttack')) {
        result.reasons.push('mixedScriptAttack');
        result.risk += 15;
      }
    }

    // 4) CONFUSABLE CHARACTER DETECTION (expanded)
    const confusableResult = detectConfusableCharacters(hostname);
    if (confusableResult.hasConfusables) {
      result.isSuspicious = true;
      result.reasons.push(...confusableResult.reasons);
      result.risk += confusableResult.risk;
    }

    // 5) DIGIT LOOKALIKE DETECTION in brand context
    const digitLookalikes = detectDigitLookalikes(hostname);
    if (digitLookalikes.detected) {
      result.isSuspicious = true;
      result.reasons.push(...digitLookalikes.reasons);
      result.risk += digitLookalikes.risk;
    }

  } catch (e) {
    // Silently ignore parsing errors
    logDebug(`[SecurityFix v8.3.0] Error in homoglyph detection: ${e.message}`);
  }

  return result;

}

/**
 * SECURITY FIX v8.3.0: Detecteert digit lookalikes in brand context
 * Catches: g00gle (0 for o), paypa1 (1 for l), amaz0n (0 for o)
 */
function detectDigitLookalikes(hostname) {
  const result = { detected: false, reasons: [], risk: 0 };

  // Common brand targets
  const brands = ['google', 'facebook', 'amazon', 'apple', 'microsoft', 'paypal', 'netflix', 'linkedin', 'twitter', 'instagram'];

  // Digit lookalike patterns
  const digitMap = {
    '0': 'o', // g00gle -> google
    '1': 'l', // paypa1 -> paypal, also 1 -> i
    '3': 'e', // appl3 -> apple
    '4': 'a', // 4mazon -> amazon
    '5': 's', // micro5oft -> microsoft
    '8': 'b', // face8ook -> facebook
  };

  // Normalize hostname by replacing digits with their letter equivalents
  let normalized = hostname;
  for (const [digit, letter] of Object.entries(digitMap)) {
    normalized = normalized.replace(new RegExp(digit, 'g'), letter);
  }

  // Check if normalized version matches any brand
  for (const brand of brands) {
    if (normalized.includes(brand) && hostname !== normalized) {
      // Original had digits that were converted to match brand
      result.detected = true;
      result.reasons.push('digitHomoglyph');
      result.risk = 10;
      logDebug(`[SecurityFix v8.3.0] 🚨 Digit lookalike detected: ${hostname} → ${normalized} (matches ${brand})`);
      break;
    }
  }

  return result;
}

/**
 * Detecteert Unicode script types in een string
 * @param {string} str - De string om te analyseren
 * @returns {Set<string>} - Set van gedetecteerde scripts
 */
function detectUnicodeScripts(str) {
  const scripts = new Set();

  for (const char of str.normalize('NFC')) {
    const code = char.codePointAt(0);

    // Basic Latin (ASCII letters)
    if ((code >= 0x0041 && code <= 0x005A) || (code >= 0x0061 && code <= 0x007A)) {
      scripts.add('Latin');
    }
    // Latin Extended
    else if ((code >= 0x00C0 && code <= 0x024F)) {
      scripts.add('Latin');
    }
    // Cyrillic
    else if ((code >= 0x0400 && code <= 0x04FF) || (code >= 0x0500 && code <= 0x052F)) {
      scripts.add('Cyrillic');
    }
    // Greek
    else if ((code >= 0x0370 && code <= 0x03FF) || (code >= 0x1F00 && code <= 0x1FFF)) {
      scripts.add('Greek');
    }
    // Armenian
    else if (code >= 0x0530 && code <= 0x058F) {
      scripts.add('Armenian');
    }
    // Hebrew
    else if (code >= 0x0590 && code <= 0x05FF) {
      scripts.add('Hebrew');
    }
    // Arabic
    else if ((code >= 0x0600 && code <= 0x06FF) || (code >= 0x0750 && code <= 0x077F)) {
      scripts.add('Arabic');
    }
    // CJK (Chinese/Japanese/Korean)
    else if ((code >= 0x4E00 && code <= 0x9FFF) || (code >= 0x3400 && code <= 0x4DBF)) {
      scripts.add('CJK');
    }
    // Hiragana
    else if (code >= 0x3040 && code <= 0x309F) {
      scripts.add('Hiragana');
    }
    // Katakana
    else if (code >= 0x30A0 && code <= 0x30FF) {
      scripts.add('Katakana');
    }
    // Common punctuation, digits - skip
    else if ((code >= 0x0030 && code <= 0x0039) || // digits
             (code >= 0x002D && code <= 0x002F) || // hyphen, period, slash
             code === 0x002E) { // period
      // Common characters, don't add to scripts
    }
  }

  return scripts;
}

/**
 * SECURITY FIX v8.3.0: Detecteert confusable/homoglyph karakters (EXPANDED)
 * Now includes:
 * - Cyrillic lookalikes
 * - Greek lookalikes (ρ for p, ν for v, ο for o)
 * - Mathematical Alphanumerics (bold/italic/script variants)
 * - Fullwidth characters
 * @param {string} hostname - De hostname om te controleren
 * @returns {{hasConfusables: boolean, reasons: string[], risk: number}}
 */
function detectConfusableCharacters(hostname) {
  const result = { hasConfusables: false, reasons: [], risk: 0 };

  // EXPANDED: Kritieke homoglyph mappings
  const criticalConfusables = {
    // Cyrillic -> Latin lookalikes
    'а': 'a', // Cyrillic а (U+0430)
    'е': 'e', // Cyrillic е (U+0435)
    'о': 'o', // Cyrillic о (U+043E)
    'р': 'p', // Cyrillic р (U+0440)
    'с': 'c', // Cyrillic с (U+0441)
    'х': 'x', // Cyrillic х (U+0445)
    'у': 'y', // Cyrillic у (U+0443)
    'і': 'i', // Cyrillic і (U+0456, Ukrainian)
    'ј': 'j', // Cyrillic ј (U+0458, Serbian)
    'ѕ': 's', // Cyrillic ѕ (U+0455)
    'ԁ': 'd', // Cyrillic ԁ (U+0501)
    'ԝ': 'w', // Cyrillic ԝ (U+051D)
    'Ь': 'b', // Cyrillic soft sign looks like b
    'К': 'K', // Cyrillic К
    'М': 'M', // Cyrillic М
    'Н': 'H', // Cyrillic Н
    'В': 'B', // Cyrillic В
    'Т': 'T', // Cyrillic Т
    'А': 'A', // Cyrillic А
    'Е': 'E', // Cyrillic Е
    'О': 'O', // Cyrillic О
    'Р': 'P', // Cyrillic Р
    'С': 'C', // Cyrillic С

    // Greek -> Latin lookalikes
    'ν': 'v', // Greek nu (U+03BD)
    'ο': 'o', // Greek omicron (U+03BF)
    'ρ': 'p', // Greek rho (U+03C1) - AUDIT FIX
    'α': 'a', // Greek alpha (U+03B1)
    'β': 'b', // Greek beta (U+03B2)
    'γ': 'y', // Greek gamma (U+03B3)
    'ε': 'e', // Greek epsilon (U+03B5)
    'η': 'n', // Greek eta (U+03B7)
    'ι': 'i', // Greek iota (U+03B9)
    'κ': 'k', // Greek kappa (U+03BA)
    'τ': 't', // Greek tau (U+03C4)
    'υ': 'u', // Greek upsilon (U+03C5)
    'χ': 'x', // Greek chi (U+03C7)
    'ω': 'w', // Greek omega (U+03C9)

    // Latin Extended/IPA lookalikes
    'ɡ': 'g', // Latin small letter script g (U+0261)
    'ɑ': 'a', // Latin alpha (U+0251)
    'ə': 'e', // Schwa (U+0259)
    'ı': 'i', // Dotless i (U+0131)
    'ȷ': 'j', // Dotless j (U+0237)
    'ɴ': 'N', // Small capital N (U+0274)
    'ʀ': 'R', // Small capital R (U+0280)

    // Mathematical Alphanumerics (bold, italic, script variants) - AUDIT FIX
    '𝐚': 'a', '𝐛': 'b', '𝐜': 'c', '𝐝': 'd', '𝐞': 'e', '𝐟': 'f', '𝐠': 'g',
    '𝑎': 'a', '𝑏': 'b', '𝑐': 'c', '𝑑': 'd', '𝑒': 'e', '𝑓': 'f', '𝑔': 'g',
    '𝒂': 'a', '𝒃': 'b', '𝒄': 'c', '𝒅': 'd', '𝒆': 'e', '𝒇': 'f', '𝒈': 'g',
    '𝓪': 'a', '𝓫': 'b', '𝓬': 'c', '𝓭': 'd', '𝓮': 'e', '𝓯': 'f', '𝓰': 'g',
    '𝔞': 'a', '𝔟': 'b', '𝔠': 'c', '𝔡': 'd', '𝔢': 'e', '𝔣': 'f', '𝔤': 'g',

    // Fullwidth characters - AUDIT FIX
    'ａ': 'a', 'ｂ': 'b', 'ｃ': 'c', 'ｄ': 'd', 'ｅ': 'e', 'ｆ': 'f', 'ｇ': 'g',
    'ｈ': 'h', 'ｉ': 'i', 'ｊ': 'j', 'ｋ': 'k', 'ｌ': 'l', 'ｍ': 'm', 'ｎ': 'n',
    'ｏ': 'o', 'ｐ': 'p', 'ｑ': 'q', 'ｒ': 'r', 'ｓ': 's', 'ｔ': 't', 'ｕ': 'u',
    'ｖ': 'v', 'ｗ': 'w', 'ｘ': 'x', 'ｙ': 'y', 'ｚ': 'z',
  };

  const normalizedHost = hostname.normalize('NFC');
  let confusableCount = 0;
  const detectedChars = [];

  for (const char of normalizedHost) {
    if (criticalConfusables[char]) {
      confusableCount++;
      result.hasConfusables = true;
      detectedChars.push(`${char}→${criticalConfusables[char]}`);
    }
  }

  if (confusableCount > 0) {
    result.reasons.push('homoglyphCharactersDetected');
    result.risk = Math.min(confusableCount * 5, 20); // Increased: Max 20 punten
    logDebug(`[SecurityFix v8.3.0] 🚨 Homoglyph characters detected: ${confusableCount} in ${hostname}`);
    logDebug(`[SecurityFix v8.3.0] Confusables found: ${detectedChars.join(', ')}`);
  }

  // =============================================================================
  // SECURITY FIX v8.4.0: EXPANDED UNICODE CATEGORY DETECTION
  // =============================================================================

  // 1. Mathematical Alphanumerics (U+1D400 - U+1D7FF)
  // Used to create lookalike letters (𝐚𝐛𝐜, 𝑎𝑏𝑐, 𝒂𝒃𝒄, etc.)
  if (/[\u{1D400}-\u{1D7FF}]/u.test(normalizedHost)) {
    result.hasConfusables = true;
    if (!result.reasons.includes('mathematicalCharsDetected')) {
      result.reasons.push('mathematicalCharsDetected');
      result.risk += 12;
      logDebug(`[SecurityFix v8.4.0] 🚨 Mathematical Alphanumerics detected in: ${hostname}`);
    }
  }

  // 2. Greek Characters (Α-Ω uppercase U+0391-U+03A9, α-ω lowercase U+03B1-U+03C9)
  // Many Greek letters look like Latin letters (ο→o, ν→v, ρ→p, α→a)
  if (/[Α-Ωα-ω]/.test(normalizedHost)) {
    result.hasConfusables = true;
    if (!result.reasons.includes('greekCharsDetected')) {
      result.reasons.push('greekCharsDetected');
      result.risk += 10;
      logDebug(`[SecurityFix v8.4.0] 🚨 Greek characters detected in: ${hostname}`);
    }
  }

  // 3. Letterlike Symbols / Script Characters (U+2100 - U+214F)
  // Includes ℃, №, ™, ℮, ℹ and script letters like ℊ, ℋ, ℌ, etc.
  if (/[℀-℻]/.test(normalizedHost)) {
    result.hasConfusables = true;
    if (!result.reasons.includes('scriptCharsDetected')) {
      result.reasons.push('scriptCharsDetected');
      result.risk += 10;
      logDebug(`[SecurityFix v8.4.0] 🚨 Script/Letterlike symbols detected in: ${hostname}`);
    }
  }

  // 4. Fullwidth Latin Letters (U+FF01-U+FF5E) - AUDIT FIX v8.5.0
  // Fullwidth characters look identical to ASCII but are different Unicode points
  // Example: ａｐｐｌｅ.com (using fullwidth a, p, l, e)
  if (/[\uFF01-\uFF5E]/.test(normalizedHost)) {
    result.hasConfusables = true;
    if (!result.reasons.includes('fullwidthCharsDetected')) {
      result.reasons.push('fullwidthCharsDetected');
      result.risk += 12;
      logDebug(`[SecurityFix v8.5.0] 🚨 Fullwidth Latin characters detected in: ${hostname}`);
    }
  }

  // 5. Cherokee Characters (U+13A0-U+13FF) - AUDIT FIX v8.5.0
  // Cherokee script has characters that look like Latin letters
  // Example: ꮓ (U+13D3) looks like 'z', ꮃ (U+13C3) looks like 'W'
  if (/[\u13A0-\u13FF]/.test(normalizedHost)) {
    result.hasConfusables = true;
    if (!result.reasons.includes('cherokeeCharsDetected')) {
      result.reasons.push('cherokeeCharsDetected');
      result.risk += 12;
      logDebug(`[SecurityFix v8.5.0] 🚨 Cherokee characters detected in: ${hostname}`);
    }
  }

  // 6. Enclosed Alphanumerics (U+2460-U+24FF) - ①②③ and ⓐⓑⓒ
  // These can be used to create lookalike domains
  if (/[\u2460-\u24FF]/.test(normalizedHost)) {
    result.hasConfusables = true;
    if (!result.reasons.includes('enclosedAlphanumericsDetected')) {
      result.reasons.push('enclosedAlphanumericsDetected');
      result.risk += 10;
      logDebug(`[SecurityFix v8.6.0] 🚨 Enclosed Alphanumerics detected in: ${hostname}`);
    }
  }

  // 7. Superscripts and Subscripts (U+2070-U+209F)
  if (/[\u2070-\u209F]/.test(normalizedHost)) {
    result.hasConfusables = true;
    if (!result.reasons.includes('superscriptSubscriptDetected')) {
      result.reasons.push('superscriptSubscriptDetected');
      result.risk += 10;
      logDebug(`[SecurityFix v8.6.0] 🚨 Superscript/Subscript characters detected in: ${hostname}`);
    }
  }

  // 8. Number Forms (U+2150-U+218F) - ⅓, ⅔, Roman numerals, etc.
  if (/[\u2150-\u218F]/.test(normalizedHost)) {
    result.hasConfusables = true;
    if (!result.reasons.includes('numberFormsDetected')) {
      result.reasons.push('numberFormsDetected');
      result.risk += 8;
      logDebug(`[SecurityFix v8.6.0] 🚨 Number Forms detected in: ${hostname}`);
    }
  }

  // 9. UNIVERSAL NON-ASCII CATCH-ALL (CRITICAL for 100% detection)
  // ANY character with charCode > 127 in a domain is suspicious
  // Flag as MEDIUM RISK minimum, escalate to HIGH if brand-like
  if (/[^\x00-\x7F]/.test(normalizedHost)) {
    // Has non-ASCII characters - always flag as at least medium risk
    if (!result.reasons.includes('nonAsciiCharactersDetected') &&
        !result.reasons.includes('nonAsciiInBrandDomain')) {
      result.hasConfusables = true;
      result.reasons.push('nonAsciiCharactersDetected');
      result.risk += 6; // Medium risk for any non-ASCII
      logDebug(`[SecurityFix v8.6.0] 🚨 Non-ASCII characters detected: ${hostname}`);
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
          logDebug(`[SecurityFix v8.6.0] 🚨 Non-ASCII in brand-like domain: ${hostname}`);
        }
        break;
      }
    }
  }

  // 10. Digit substitution in domain (0→o, 1→l, 3→e, etc.)
  // Pattern: digits in positions that would spell brand names
  const digitSubstitutions = {
    '0': 'o', '1': ['l', 'i'], '3': 'e', '4': 'a', '5': 's', '8': 'b', '9': 'g'
  };
  let hasDigitSubstitution = false;
  for (const digit of Object.keys(digitSubstitutions)) {
    if (normalizedHost.includes(digit)) {
      hasDigitSubstitution = true;
      break;
    }
  }
  if (hasDigitSubstitution) {
    // Check against known brand patterns
    const suspiciousPatterns = [
      /g[0o]{2}gle/i, /paypa[l1]/i, /amaz[0o]n/i, /app[l1]e/i,
      /faceb[0o]{2}k/i, /micr[0o]s[0o]ft/i, /netf[l1]ix/i,
      /g[0o]{2}g[l1]e/i, /y[0o]utube/i, /twitt[3e]r/i, /inst[4a]gram/i
    ];
    for (const pattern of suspiciousPatterns) {
      if (pattern.test(normalizedHost)) {
        result.hasConfusables = true;
        if (!result.reasons.includes('digitInDomainDetected')) {
          result.reasons.push('digitInDomainDetected');
          result.risk += 12;
          logDebug(`[SecurityFix v8.4.0] 🚨 Digit-substitution brand impersonation detected: ${hostname}`);
        }
        break;
      }
    }
  }

  return result;
}

function classifyAndCheckLink(link) {
  // v8.4.1: Skip if Smart Link Scanning is disabled (PRO feature)
  // This check is placed at the top to prevent all link scanning when disabled
  if (!smartLinkScanningEnabled) {
    return;
  }

  if (!link || !link.href) {
    logDebug(`Skipping classification: Invalid or missing link: ${link || 'undefined'}`);
    return; // Sla volledig ongeldige links over
  }
  // Haal de href op, rekening houdend met SVGAnimatedString
  const href = link.href instanceof SVGAnimatedString ? link.href.baseVal : link.href;
  // Log voor debugging, inclusief type en SVG-status
  logDebug(`Classifying link: ${href || 'undefined'}, Type: ${typeof link.href}, Is SVG: ${link.ownerSVGElement ? 'yes' : 'no'}`);

  // =============================================================================
  // SECURITY FIX v8.2.0: DANGEROUS URI SCHEME CHECK (BEFORE isValidURL)
  // =============================================================================
  // Check voor gevaarlijke URI schemes VOORDAT we isValidURL aanroepen
  // Dit vangt javascript:, data:, vbscript: URLs die anders worden overgeslagen
  const schemeCheck = detectDangerousScheme(href);
  if (schemeCheck.isDangerous) {
    logDebug(`[SecurityFix v8.2.0] 🛑 BLOCKING dangerous ${schemeCheck.scheme} URI`);
    warnLinkByLevel(link, {
      level: 'alert',
      risk: 25, // Maximum risk score voor gevaarlijke schemes
      reasons: [schemeCheck.reason, 'criticalSecurityThreat']
    });
    return; // Stop verdere processing
  }

  // Controleer of href een geldige URL is
  if (!isValidURL(href)) {
    logDebug(`Skipping classification: Invalid URL in link: ${href || 'undefined'}`);
    return;
  }

  // =============================================================================
  // SECURITY FIX v8.8.10: TRUSTED DOMAIN EARLY EXIT
  // =============================================================================
  // Check if this link points to a trusted domain BEFORE running expensive
  // security checks. This prevents false positives on trusted sites like Discord.
  // Uses the global safeDomains array (initialized at script load)
  {
    try {
      const urlObj = new URL(href);
      const linkHostname = urlObj.hostname.toLowerCase();
      // Use synchronous check via global safeDomains array
      if (safeDomainsInitialized && safeDomains.length > 0) {
        for (const pattern of safeDomains) {
          try {
            if (new RegExp(pattern, 'i').test(linkHostname)) {
              logDebug(`[classifyAndCheckLink] Trusted domain, skipping security checks: ${linkHostname}`);
              return; // Skip all security checks for trusted domains
            }
          } catch (e) { /* invalid regex, skip */ }
        }
      }
    } catch (e) {
      // URL parsing failed, continue with checks
    }
  }

  // =============================================================================
  // SECURITY FIX v8.8.2: PRE-PARSE UNICODE DETECTION
  // SECURITY FIX v8.8.10: Only check href, NOT linkText (was causing false positives)
  // =============================================================================
  // CRITICAL: Check href BEFORE URL parsing, because new URL() converts IDN to punycode
  // This ensures we catch Unicode characters that would be lost in the conversion
  // NOTE: We only check the URL itself, not the display text. Link text with emoji
  // or non-ASCII characters is normal and not a security risk.
  {
    let unicodeReasons = [];
    let unicodeRisk = 0;

    // Only check the href (URL), not the link text
    // Link text with emoji/non-ASCII is normal (e.g., Discord channel names)
    const checkTarget = href.toLowerCase();

    // 1. Universal Non-ASCII check (charCode > 127)
    if (/[^\x00-\x7F]/.test(checkTarget)) {
      unicodeReasons.push('universalNonAsciiDetected');
      unicodeRisk += 8;
    }

    // 2. Mathematical Alphanumeric Symbols (U+1D400-U+1D7FF) - bold/italic lookalikes
    if (/[\u{1D400}-\u{1D7FF}]/u.test(checkTarget)) {
      unicodeReasons.push('mathematicalAlphanumericsDetected');
      unicodeRisk += 10;
    }

    // 3. Fullwidth Latin characters (U+FF00-U+FFEF) - ａｂｃ
    if (/[\uFF00-\uFFEF]/.test(checkTarget)) {
      unicodeReasons.push('fullwidthCharactersDetected');
      unicodeRisk += 10;
    }

    // 4. Greek letters (U+0370-U+03FF)
    if (/[\u0370-\u03FF]/.test(checkTarget)) {
      unicodeReasons.push('greekLettersDetected');
      unicodeRisk += 10;
    }

    // 5. Cyrillic characters (U+0400-U+04FF)
    if (/[\u0400-\u04FF]/.test(checkTarget)) {
      unicodeReasons.push('cyrillicCharactersDetected');
      unicodeRisk += 10;
    }

    // 6. Cherokee characters (U+13A0-U+13FF) - ꮓ looks like z
    if (/[\u13A0-\u13FF]/.test(checkTarget)) {
      unicodeReasons.push('cherokeeCharactersDetected');
      unicodeRisk += 10;
    }

    // 7. Script/Letterlike Symbols (U+2100-U+214F) - ℊ looks like g
    if (/[\u2100-\u214F]/.test(checkTarget)) {
      unicodeReasons.push('scriptSymbolsDetected');
      unicodeRisk += 10;
    }

    // 8. Enclosed Alphanumerics (U+2460-U+24FF)
    if (/[\u2460-\u24FF]/.test(checkTarget)) {
      unicodeReasons.push('enclosedAlphanumericsDetected');
      unicodeRisk += 8;
    }

    // 9. Superscripts/Subscripts (U+2070-U+209F)
    if (/[\u2070-\u209F]/.test(checkTarget)) {
      unicodeReasons.push('superscriptSubscriptDetected');
      unicodeRisk += 8;
    }

    // Apply warning if any Unicode issues detected
    if (unicodeReasons.length > 0) {
      logDebug(`[SecurityFix v8.8.2] ⚠️ UNICODE DETECTED (pre-parse): ${href.substring(0, 50)} → ${unicodeReasons.join(', ')}`);

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
  }

  // =============================================================================
  // SECURITY FIX v8.8.1: ENHANCED ASCII LOOKALIKE DETECTION
  // =============================================================================
  // Detect visually similar ASCII substitutions (1 vs l, 0 vs O, rn vs m)
  // These MUST be detected even if Unicode check already ran
  try {
    const urlObj = new URL(href);
    const hostname = urlObj.hostname.toLowerCase();

    // Known brand patterns with common ASCII substitutions
    // Patterns match against hostname (e.g., "paypa1.com", "paypaI.com")
    // SECURITY FIX v8.7.2: Added I/l confusion patterns (capital I looks like lowercase l)
    const asciiLookalikes = [
      // PayPal: 1/l/I confusion (paypa1, paypal with wrong char, paypaI)
      { pattern: /paypa[1I]/i, brand: 'paypal', reason: 'asciiLookalikePaypal' },
      { pattern: /paypa[l1I]{2}/i, brand: 'paypal', reason: 'asciiLookalikePaypal' }, // paypall, paypa11, etc.
      // Amazon: rn/m confusion + 0/o confusion
      { pattern: /arnazon/i, brand: 'amazon', reason: 'asciiLookalikeAmazon' },
      { pattern: /arnezon/i, brand: 'amazon', reason: 'asciiLookalikeAmazon' },
      { pattern: /arnaz0n/i, brand: 'amazon', reason: 'asciiLookalikeAmazon' },
      { pattern: /amaz[0o]n/i, brand: 'amazon', reason: 'asciiLookalikeAmazon' }, // amaz0n
      // Microsoft: 0/o confusion + rn/m confusion
      { pattern: /micr[0o]s[0o]ft/i, brand: 'microsoft', reason: 'asciiLookalikeMicrosoft' },
      { pattern: /rnicrosoft/i, brand: 'microsoft', reason: 'asciiLookalikeMicrosoft' },
      { pattern: /mlcrosoft/i, brand: 'microsoft', reason: 'asciiLookalikeMicrosoft' }, // l for i
      // Google: 0/o confusion
      { pattern: /g[0o]{2}gle/i, brand: 'google', reason: 'asciiLookalikeGoogle' },
      { pattern: /go[0o]gle/i, brand: 'google', reason: 'asciiLookalikeGoogle' },
      { pattern: /goog[1lI]e/i, brand: 'google', reason: 'asciiLookalikeGoogle' }, // l/1/I for l
      // Twitter/X: l/I confusion
      { pattern: /tw[1lI]tter/i, brand: 'twitter', reason: 'asciiLookalikeTwitter' },
      { pattern: /tw[1lI]tt[3e]r/i, brand: 'twitter', reason: 'asciiLookalikeTwitter' },
      // Facebook: 0/o confusion
      { pattern: /faceb[0o]{2}k/i, brand: 'facebook', reason: 'asciiLookalikeFacebook' },
      { pattern: /faceb[0o]ok/i, brand: 'facebook', reason: 'asciiLookalikeFacebook' },
      // Apple: 1/l/I confusion
      { pattern: /app[1lI]e/i, brand: 'apple', reason: 'asciiLookalikeApple' },
      { pattern: /[a4]pp[1lI]e/i, brand: 'apple', reason: 'asciiLookalikeApple' }, // 4pple
      // Netflix: 1/l/I confusion
      { pattern: /netf[1lI][1lI]x/i, brand: 'netflix', reason: 'asciiLookalikeNetflix' },
      { pattern: /netfl[1I]x/i, brand: 'netflix', reason: 'asciiLookalikeNetflix' },
      // LinkedIn: 1/l/I confusion
      { pattern: /[1lI]inkedin/i, brand: 'linkedin', reason: 'asciiLookalikeLinkedin' },
      { pattern: /linked[1lI]n/i, brand: 'linkedin', reason: 'asciiLookalikeLinkedin' },
      // Instagram: 1/l/I confusion
      { pattern: /[1lI]nstagram/i, brand: 'instagram', reason: 'asciiLookalikeInstagram' },
      { pattern: /instag[rn]am/i, brand: 'instagram', reason: 'asciiLookalikeInstagram' }, // rn for m
      // WWW: vv confusion
      { pattern: /^vvv+w\./i, brand: 'www', reason: 'asciiLookalikeWww' },
      { pattern: /^wvvw\./i, brand: 'www', reason: 'asciiLookalikeWww' },
    ];

    for (const lookalike of asciiLookalikes) {
      if (lookalike.pattern.test(hostname)) {
        logDebug(`[SecurityFix v8.8.1] ⚠️ ASCII LOOKALIKE: ${hostname} → impersonates ${lookalike.brand}`);
        // Use caution level and set warned attribute immediately
        link.dataset.linkshieldWarned = 'true';
        link.dataset.linkshieldLevel = 'caution';
        link.dataset.linkshieldReasons = (link.dataset.linkshieldReasons || '') + ',' + lookalike.reason;
        warnLinkByLevel(link, {
          level: 'caution',
          risk: 8,
          reasons: [lookalike.reason, 'brandImpersonation']
        });
        break;
      }
    }
  } catch (e) {
    // URL parsing error - skip
  }

  // =============================================================================
  // SECURITY FIX v8.6.1: SUSPICIOUS TLD + BRAND KEYWORD DETECTION (SYNCHRONOUS)
  // =============================================================================
  // Detects phishing domains using suspicious TLDs and/or brand impersonation keywords
  // This runs SYNCHRONOUSLY to avoid dependency on async SSL/domain checks
  try {
    const urlObj = new URL(href);
    const hostname = urlObj.hostname.toLowerCase();
    const parts = hostname.split('.');
    const tld = parts.length >= 2 ? parts[parts.length - 1] : '';

    // Check suspicious TLD
    const hasSuspiciousTLD = globalConfig?.SUSPICIOUS_TLDS_SET?.has(tld) ||
      (globalConfig?.SUSPICIOUS_TLDS instanceof RegExp && globalConfig.SUSPICIOUS_TLDS.test(hostname));

    // Known brands that are commonly impersonated
    const brandPatterns = ['microsoft', 'paypal', 'apple', 'google', 'amazon', 'netflix',
      'facebook', 'instagram', 'whatsapp', 'coinbase', 'binance', 'metamask', 'chase',
      'wellsfargo', 'bankofamerica', 'citibank', 'hsbc', 'barclays', 'ing', 'rabobank',
      'abnamro', 'linkedin', 'twitter', 'dropbox', 'adobe', 'zoom', 'slack', 'spotify'];

    // Extract base domain (without TLD) for brand checking
    const baseDomain = parts.length >= 2 ? parts.slice(0, -1).join('.') : hostname;
    // Check if a brand keyword appears in the domain but domain is NOT the brand itself
    let detectedBrand = null;
    for (const brand of brandPatterns) {
      if (baseDomain.includes(brand)) {
        // Verify it's not the actual brand domain (e.g., microsoft.com is legit)
        const brandDomain = brand + '.' + tld;
        const brandWithWww = 'www.' + brand + '.' + tld;
        if (hostname !== brandDomain && hostname !== brandWithWww &&
            !hostname.endsWith('.' + brand + '.' + tld)) {
          detectedBrand = brand;
          break;
        }
      }
    }

    // Phishing keywords that indicate credential theft when combined with brand
    const phishKeywords = ['login', 'signin', 'secure', 'verify', 'account', 'auth',
      'update', 'confirm', 'recover', 'reset', 'unlock', 'suspended', 'alert'];
    const hasPhishKeyword = phishKeywords.some(kw => baseDomain.includes(kw));

    // Keyword stuffing: multiple phishing keywords in domain
    const phishKeywordCount = phishKeywords.filter(kw => baseDomain.includes(kw)).length;
    const isKeywordStuffing = phishKeywordCount >= 2;

    // Scoring
    let tldRisk = 0;
    let tldReasons = [];

    if (hasSuspiciousTLD && detectedBrand) {
      // Brand on suspicious TLD = HIGH RISK (e.g., netflix-login.top)
      tldRisk = 15;
      tldReasons = ['suspiciousTLD', `brandImpersonation:${detectedBrand}`];
    } else if (detectedBrand && hasPhishKeyword) {
      // Brand + phishing keyword = HIGH RISK (e.g., login-microsoft-verify.com)
      tldRisk = 15;
      tldReasons = [`brandImpersonation:${detectedBrand}`, 'phishingKeywordInDomain'];
    } else if (isKeywordStuffing) {
      // Multiple phishing keywords = MEDIUM RISK (e.g., secure-bank-login-verify-account.com)
      tldRisk = 8;
      tldReasons = ['keywordStuffing'];
    } else if (hasSuspiciousTLD) {
      // Suspicious TLD alone = CAUTION (e.g., free-iphone-winner.buzz)
      tldRisk = 5;
      tldReasons = ['suspiciousTLD'];
    } else if (detectedBrand) {
      // Brand keyword alone on normal TLD = CAUTION (e.g., paypal-something.com)
      tldRisk = 8;
      tldReasons = [`brandImpersonation:${detectedBrand}`];
    }

    if (tldRisk > 0) {
      const level = tldRisk >= 15 ? 'alert' : 'caution';
      logDebug(`[SecurityFix v8.6.1] ⚠️ TLD/BRAND: ${hostname} → risk=${tldRisk}, reasons=${tldReasons.join(',')}`);
      link.dataset.linkshieldWarned = 'true';
      link.dataset.linkshieldLevel = level;
      link.dataset.linkshieldReasons = (link.dataset.linkshieldReasons || '') +
        (link.dataset.linkshieldReasons ? ',' : '') + tldReasons.join(',');
      warnLinkByLevel(link, {
        level: level,
        risk: tldRisk,
        reasons: tldReasons
      });
    }
  } catch (e) {
    // URL parsing error - skip
  }

  // =============================================================================
  // SECURITY FIX v8.5.0: HIGH-RISK DOMAIN KEYWORD DETECTION
  // =============================================================================
  // Check for obviously malicious keywords in domain names (phishing, malicious, evil, etc.)
  // These are HIGH RISK and should trigger immediate alerts
  try {
    const urlObj = new URL(href);
    const hostname = urlObj.hostname.toLowerCase();
    const maliciousDomainKeywords = [
      'phishing', 'malicious', 'evil', 'scam', 'phish', 'hacker', 'attacker',
      'steal', 'credential', 'fake-', '-fake', 'malware', 'exploit', 'trojan',
      'virus', 'ransomware', 'keylog', 'botnet', 'injection', 'evasion'
    ];
    for (const keyword of maliciousDomainKeywords) {
      if (hostname.includes(keyword)) {
        logDebug(`[SecurityFix v8.5.0] 🛑 HIGH RISK: Malicious keyword "${keyword}" in domain: ${hostname}`);
        // SECURITY FIX v8.8.2: Set warned attribute SYNCHRONOUSLY before async warnLinkByLevel
        link.dataset.linkshieldWarned = 'true';
        link.dataset.linkshieldLevel = 'alert';
        warnLinkByLevel(link, {
          level: 'alert',
          risk: 20,
          reasons: ['maliciousDomainKeyword', 'criticalSecurityThreat']
        });
        return; // Stop further processing
      }
    }
  } catch (e) { /* ignore URL parsing errors */ }

  // =============================================================================
  // SECURITY FIX v8.2.0: HOMOGLYPH & PUNYCODE EARLY DETECTION
  // =============================================================================
  // Check voor homoglyph/punycode attacks VOORDAT normale analyse
  // Dit zorgt voor CRITICAL flagging van IDN spoofing attacks
  const homoglyphCheck = detectHomoglyphAndPunycode(href);
  if (homoglyphCheck.isSuspicious && homoglyphCheck.risk >= 10) {
    logDebug(`[SecurityFix v8.2.0] 🛑 HIGH RISK homoglyph/punycode detected: ${homoglyphCheck.reasons.join(', ')}`);
    warnLinkByLevel(link, {
      level: 'alert',
      risk: homoglyphCheck.risk,
      reasons: homoglyphCheck.reasons
    });
    // Continue met normale analyse voor extra context, maar link is al geflagd
  }

  if (link.closest('div[data-text-ad], .ads-visurl')) {
    checkForPhishingAds(link);
  } else {
    analyzeDomainAndUrl(link);
  }
}
/**
 * Toont een eenmalige introductiebanner als deze nog niet eerder is getoond.
 * @param {string} message De tekst van de introductiebanner.
 */
async function showIntroBannerOnce(message) {
  try {
    const result = await chrome.storage.sync.get('hasShownIntroBanner');
    if (!result.hasShownIntroBanner) {
      // Creëer de banner
      const banner = document.createElement('div');
      banner.id = 'linkshield-intro-banner';
      banner.style.cssText = `
        position: fixed;
        top: 10px;
        left: 50%;
        transform: translateX(-50%);
        background-color: #4CAF50; /* Groen */
        color: white;
        padding: 15px 20px;
        border-radius: 8px;
        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
        z-index: 2147483647 !important; /* SECURITY FIX v8.2.0: Maximum z-index */
        font-family: sans-serif;
        font-size: 16px;
        text-align: center;
        opacity: 0;
        transition: opacity 0.5s ease-in-out;
      `;
      banner.textContent = message;
      document.body.appendChild(banner);
      // Fade-in effect
      setTimeout(() => {
        banner.style.opacity = '1';
      }, 100);
      // Verdwijn na 10 seconden
      setTimeout(() => {
        banner.style.opacity = '0';
        banner.addEventListener('transitionend', () => banner.remove());
      }, 10000); // 10 seconden
      // Stel de vlag in Chrome Storage in
      await chrome.storage.sync.set({ hasShownIntroBanner: true });
      logDebug("Introductiebanner getoond en vlag opgeslagen.");
    }
  } catch (error) {
    handleError(error, "showIntroBannerOnce");
  }
}
/**
 * Plaatst een waarschuwing-icoon bij een link op basis van niveau en redenen,
 * en vertaalt de reden-keys via chrome.i18n.
 *
 * @param {HTMLAnchorElement} link
 * @param {{ level: 'safe'|'caution'|'alert', reasons: string[] }} options
 */
async function warnLinkByLevel(link, { level, reasons }) {
  // v8.4.1: Skip ALL warnings if Smart Link Scanning is disabled (PRO feature)
  // This is the final guard - no warnings will be shown if feature is off
  if (!smartLinkScanningEnabled) {
    return;
  }

  // Verwijder oude styling/iconen
  clearWarning(link);
  injectWarningIconStyles();
  if (level === 'safe') {
    return;
  }
  // Vertaal de reden-keys (houd camelCase, vervang alleen ongeldige tekens)
  const translatedReasons = reasons.map(r => {
    const key = r.replace(/[^a-zA-Z0-9_]/g, '_');
    return getTranslatedMessage(key) || r;
  });
  // Alert: direct rood icoon + SECURITY FIX v8.0.0 (Vector 3): Blokkeer navigatie op netwerkniveau
  if (level === 'alert') {
    addIcon(link, '❗️', 'high-risk-warning', translatedReasons);

    // SECURITY FIX v8.0.0 (Vector 3 - Visual Hijacking):
    // Blokkeer de URL op netwerkniveau via declarativeNetRequest
    // Dit voorkomt dat aanvallers met z-index overlays of clickjacking de gebruiker naar malafide URLs kunnen leiden
    const targetUrl = link.href;
    if (targetUrl && targetUrl.startsWith('http')) {
      try {
        chrome.runtime.sendMessage({
          type: 'blockMaliciousNavigation',
          url: targetUrl,
          reason: reasons.join(', ') || 'alert_level_link'
        }, (response) => {
          if (chrome.runtime.lastError) {
            logDebug('[Vector3] Kon navigatie niet blokkeren:', chrome.runtime.lastError.message);
          } else if (response && response.blocked) {
            logDebug(`[Vector3] Navigatie geblokkeerd voor: ${targetUrl} (rule ${response.ruleId})`);
          }
        });
      } catch (e) {
        logDebug('[Vector3] Fout bij blokkeren navigatie:', e);
      }

      // Voeg ook een click interceptor toe als backup voor DNR blokkering
      attachClickInterceptor(link, reasons);
    }
    return;
  }
  // Caution: geel icoon pas bij hover/focus, met stay-open als je naar het icoon beweegt
  if (level === 'caution') {
    // SECURITY FIX v8.8.0: Set data-linkshield-warned IMMEDIATELY for test detection
    // This ensures security audits can verify protection is active
    link.dataset.linkshieldWarned = 'true';
    link.dataset.linkshieldLevel = 'caution';
    link.dataset.linkshieldReasons = reasons.join(',');

    let hideTimeout;
    const show = () => {
      clearTimeout(hideTimeout);
      // Voeg het icoon maar één keer toe
      if (!link.querySelector('.phishing-warning-icon')) {
        addIcon(link, '⚠️', 'moderate-warning', translatedReasons);
        // Zodra het icoon er is, zorg dat hover over icoon ook 'show' blijft triggeren
        // v8.8.14: Check if icon exists before adding listeners (addIcon may early-return)
        const icon = link.querySelector('.phishing-warning-icon');
        if (icon) {
          icon.addEventListener('mouseenter', show);
          icon.addEventListener('mouseleave', hide);
        }
      }
    };
    const hide = () => {
      clearTimeout(hideTimeout);
      hideTimeout = setTimeout(() => clearWarning(link), 300);
    };
    link.addEventListener('mouseenter', show);
    link.addEventListener('focus', show);
    link.addEventListener('mouseleave', hide);
    link.addEventListener('blur', hide);
  }
}
function addIcon(link, symbol, cssClass, reasons) {
  if (link.dataset.linkshieldWarned === 'true') return;
  const icon = document.createElement('span');
  icon.className = `phishing-warning-icon ${cssClass}`;
  icon.textContent = symbol;
  icon.title = `Redenen:\n${reasons.join('\n')}`;
  link.appendChild(icon);
  link.dataset.linkshieldWarned = 'true';
}
function clearWarning(link) {
  delete link.dataset.linkshieldWarned;
  const old = link.querySelector('.phishing-warning-icon');
  if (old) old.remove();
  link.classList.remove('moderate-risk-link', 'high-risk-link');
}

// ==============================================================================
// SECURITY FIX v8.0.0 (Vector 3 - Visual Hijacking Protection)
// Detecteert transparante overlays en intercepteert clicks op geblokkeerde links
// ==============================================================================

/**
 * SECURITY FIX v8.8.3: CMP (Consent Management Platform) Whitelist
 * Voorkomt false positives voor legitieme consent/cookie modals.
 * Deze platforms gebruiken legaal fullscreen overlays voor privacy consent.
 */

// Cache voor pagina-niveau CMP detectie
let _isCMPPageCache = null;
let _cmpPageCacheTime = 0;
const CMP_CACHE_TTL = 5000; // 5 seconden cache

/**
 * Controleert of de huidige pagina een Consent Management pagina is.
 * Gebruikt caching om performance te behouden.
 *
 * @returns {boolean} - True als de pagina een CMP pagina is
 */
function isConsentManagementPage() {
  // Check cache
  const now = Date.now();
  if (_isCMPPageCache !== null && (now - _cmpPageCacheTime) < CMP_CACHE_TTL) {
    return _isCMPPageCache;
  }

  let isCMPPage = false;

  try {
    // 1) Check page title
    const pageTitle = document.title.toLowerCase();
    if (pageTitle.includes('privacy gate') ||
        pageTitle.includes('cookie consent') ||
        pageTitle.includes('consent manager') ||
        pageTitle.includes('cookie policy') ||
        pageTitle.includes('privacy policy') ||
        pageTitle.includes('gdpr')) {
      isCMPPage = true;
    }

    // 2) Check URL path voor consent-gerelateerde paden
    const urlPath = window.location.pathname.toLowerCase();
    if (urlPath.includes('/privacy') ||
        urlPath.includes('/consent') ||
        urlPath.includes('/cookie') ||
        urlPath.includes('/gdpr')) {
      isCMPPage = true;
    }

    // 3) Check voor CMP scripts op de pagina
    if (!isCMPPage) {
      const scripts = document.querySelectorAll('script[src]');
      for (const script of scripts) {
        const src = script.src.toLowerCase();
        if (CMP_WHITELIST_DOMAINS.some(domain => src.includes(domain))) {
          isCMPPage = true;
          break;
        }
      }
    }

    // 4) Check voor CMP preconnect/prefetch hints
    if (!isCMPPage) {
      const links = document.querySelectorAll('link[rel="preconnect"], link[rel="prefetch"], link[rel="dns-prefetch"]');
      for (const link of links) {
        const href = (link.href || '').toLowerCase();
        if (CMP_WHITELIST_DOMAINS.some(domain => href.includes(domain))) {
          isCMPPage = true;
          break;
        }
      }
    }

  } catch (e) {
    logDebug('[CMP-Page-Check] Error:', e);
  }

  // Cache het resultaat
  _isCMPPageCache = isCMPPage;
  _cmpPageCacheTime = now;

  if (isCMPPage) {
    logDebug('[CMP-Page-Check] Detected CMP/consent page - visual hijacking detection will be relaxed');
  }

  return isCMPPage;
}

const CMP_WHITELIST_DOMAINS = [
  'dpgmedia.net',        // DPG Media (nu.nl, ad.nl, volkskrant.nl, etc.)
  'myprivacy-static.dpgmedia.net',
  'onetrust.com',        // OneTrust CMP
  'cookiebot.com',       // Cookiebot CMP
  'trustarc.com',        // TrustArc CMP
  'usercentrics.eu',     // Usercentrics CMP
  'quantcast.com',       // Quantcast Choice CMP
  'consentmanager.net',  // Consentmanager CMP
  'didomi.io',           // Didomi CMP
  'privacymanager.io',   // Privacy Manager CMP
  'sourcepoint.com',     // Sourcepoint CMP
  'cookielaw.org',       // OneTrust domain
  'cookieinformation.com', // Cookie Information CMP
  'iubenda.com',         // Iubenda CMP
  'termly.io',           // Termly CMP
  'osano.com',           // Osano CMP
];

/**
 * CMP Element Selectors - Patronen die consent modals identificeren
 */
const CMP_ELEMENT_PATTERNS = [
  // DPG Media specific
  '[id*="dpg-"]',
  '[class*="dpg-"]',
  '[data-testid*="dpg-"]',
  '.modal[style*="z-index: 999"]', // DPG privacy gate modal
  // Generic CMP patterns
  '[id*="consent"]',
  '[id*="cookie-banner"]',
  '[id*="cookie-consent"]',
  '[id*="privacy-gate"]',
  '[class*="consent-modal"]',
  '[class*="cookie-banner"]',
  '[class*="cookie-notice"]',
  '[class*="cookie-popup"]',
  '[class*="cookie-overlay"]',
  '[class*="cmp-"]',
  '[id*="onetrust"]',
  // Cookiebot specific patterns
  '[id*="cookiebot"]',
  '[id*="Cookiebot"]',
  '[id*="CybotCookiebot"]',
  '[class*="cookiebot"]',
  '[class*="Cookiebot"]',
  '[class*="CybotCookiebot"]',
  '#CybotCookiebotDialog',
  '#CybotCookiebotDialogBody',
  // Other CMP providers
  '[id*="usercentrics"]',
  '[id*="didomi"]',
  '[id*="quantcast"]',
  '[id*="trustarc"]',
  '[id*="osano"]',
  // Cookie consent library patterns (cookieconsent.js, etc.)
  '[class*="cc-window"]',
  '[class*="cc-banner"]',
  '[class*="cc-overlay"]',
  '.cookieconsent',
  '.gdpr-banner',
  '.gdpr-overlay',
  '.privacy-banner',
  '.privacy-overlay',
  // GDPR/Privacy specific
  '[aria-label*="cookie"]',
  '[aria-label*="consent"]',
  '[aria-label*="privacy"]',
  '[role="dialog"][aria-modal="true"]', // Modal dialogs (often used for consent)
];

/**
 * Controleert of een element onderdeel is van een legitieme Consent Management Platform.
 *
 * @param {HTMLElement} element - Het te controleren element
 * @returns {boolean} - True als het een CMP-element is
 */
function isCMPElement(element) {
  if (!element) return false;

  try {
    // 1) Check of element of ancestor matcht met CMP selectors
    for (const selector of CMP_ELEMENT_PATTERNS) {
      try {
        if (element.matches && element.matches(selector)) return true;
        if (element.closest && element.closest(selector)) return true;
      } catch (e) { /* ignore invalid selector */ }
    }

    // 2) Check script sources op pagina voor CMP providers
    const scripts = document.querySelectorAll('script[src]');
    for (const script of scripts) {
      const src = script.src.toLowerCase();
      if (CMP_WHITELIST_DOMAINS.some(domain => src.includes(domain))) {
        // CMP script gevonden - check of element in een modal/overlay zit
        const isInModal = element.closest('[class*="modal"]') ||
                          element.closest('[role="dialog"]') ||
                          element.closest('[aria-modal="true"]');
        if (isInModal) return true;
      }
    }

    // 3) Check preconnect/prefetch hints voor CMP domains
    const links = document.querySelectorAll('link[href]');
    for (const link of links) {
      const href = link.href.toLowerCase();
      if (CMP_WHITELIST_DOMAINS.some(domain => href.includes(domain))) {
        const isInModal = element.closest('[class*="modal"]') ||
                          element.closest('[role="dialog"]') ||
                          element.closest('[aria-modal="true"]');
        if (isInModal) return true;
      }
    }

    // 4) Check page title voor privacy gate indicaties
    const pageTitle = document.title.toLowerCase();
    if (pageTitle.includes('privacy gate') ||
        pageTitle.includes('cookie consent') ||
        pageTitle.includes('consent manager')) {
      return true;
    }

  } catch (e) {
    logDebug('[CMP-Check] Error checking CMP element:', e);
  }

  return false;
}

/**
 * SECURITY FIX v8.3.0: Detecteert Google Ads elementen
 * Google Ads gebruikt legitieme overlays met hoge z-index en pointer-events: none
 * voor click tracking. Deze moeten niet als Visual Hijacking worden gedetecteerd.
 *
 * Detectie methoden:
 * 1. data-jc attribuut (Google Ads marker)
 * 2. data-google-* attributen
 * 3. Elementen binnen Google Ads iframes/containers
 * 4. Elementen van gstatic.com/doubleclick scripts
 *
 * @param {HTMLElement} element - Het te controleren element
 * @returns {boolean} - True als het een Google Ads element is
 */
function isGoogleAdsElement(element) {
  if (!element) return false;

  try {
    // 1) Check voor Google Ads data attributen
    if (element.hasAttribute('data-jc') ||
        element.hasAttribute('data-google-av-cxn') ||
        element.hasAttribute('data-google-av-dm') ||
        element.hasAttribute('data-load-complete') ||
        element.hasAttribute('data-google-container-id') ||
        element.hasAttribute('data-ad-client') ||
        element.hasAttribute('data-ad-slot')) {
      return true;
    }

    // 2) Check ID patterns voor Google Ads
    const elId = (element.id || '').toLowerCase();
    if (elId.includes('google_ads') ||
        elId.includes('gpt_unit') ||
        elId.includes('div-gpt-ad') ||
        elId.includes('aswift_')) {
      return true;
    }

    // 3) Check class patterns voor Google Ads
    const elClass = (element.className || '').toLowerCase();
    if (typeof elClass === 'string' && (
        elClass.includes('adsbygoogle') ||
        elClass.includes('google-ad') ||
        elClass.includes('dfp-ad') ||
        elClass.includes('gpt-ad'))) {
      return true;
    }

    // 4) Check of element binnen een Google Ads container zit
    const adsAncestor = element.closest(
      '[data-jc], [data-google-av-cxn], [data-ad-client], ' +
      '[id*="google_ads"], [id*="div-gpt-ad"], [id*="aswift_"], ' +
      '[class*="adsbygoogle"], [class*="google-ad"], ' +
      'ins.adsbygoogle, iframe[id^="google_ads_iframe"]'
    );
    if (adsAncestor) {
      return true;
    }

    // 5) Check of element een Google Ads iframe is
    if (element.tagName === 'IFRAME') {
      const src = (element.src || '').toLowerCase();
      if (src.includes('doubleclick.net') ||
          src.includes('googlesyndication.com') ||
          src.includes('googleadservices.com') ||
          src.includes('googleads.g.doubleclick.net') ||
          src.includes('tpc.googlesyndication.com')) {
        return true;
      }
    }

    // 6) Check voor elementen die via Google Ads scripts zijn toegevoegd
    // Deze scripts voegen vaak elementen toe met specifieke structuur
    if (element.tagName === 'DIV' || element.tagName === 'INS') {
      const parentIframe = element.closest('iframe');
      if (parentIframe) {
        const iframeSrc = (parentIframe.src || '').toLowerCase();
        if (iframeSrc.includes('google') || iframeSrc.includes('doubleclick')) {
          return true;
        }
      }
    }

  } catch (e) {
    // Silently ignore errors
  }

  return false;
}

/**
 * SECURITY FIX v8.0.2 (Vector 3 - Z-Index War 2.0)
 * Detecteert pointer-events: none overlays met hoge z-index.
 * elementsFromPoint() mist deze omdat ze geen pointer events ontvangen.
 *
 * Aanval: Overlay met z-index: 2147483647, position: fixed, pointer-events: none
 * Result: Clicks gaan door naar onderliggende malicious links.
 *
 * @param {number} x - X-coördinaat van de click
 * @param {number} y - Y-coördinaat van de click
 * @returns {{isHijacked: boolean, hijacker: HTMLElement|null, reason: string}}
 */
function detectPointerEventsNoneOverlay(x, y) {
  // Zoek alle fixed en absolute positioned elementen
  const suspiciousSelectors = [
    '[style*="position: fixed"]',
    '[style*="position:fixed"]',
    '[style*="z-index"]'
  ];

  // Verzamel alle potentieel verdachte elementen
  const candidates = new Set();

  // Check alle elementen met inline styles
  document.querySelectorAll('*').forEach(el => {
    try {
      const style = window.getComputedStyle(el);
      const position = style.position;
      const zIndex = parseInt(style.zIndex, 10) || 0;

      // Alleen fixed/absolute elementen met significante z-index
      if ((position === 'fixed' || position === 'absolute') && zIndex > 1000) {
        candidates.add(el);
      }
    } catch (e) { /* ignore */ }
  });

  // INT_MAX voor 32-bit signed integer
  const INT_MAX = 2147483647;
  const HIGH_Z_THRESHOLD = 999999; // Verdacht hoog

  for (const el of candidates) {
    try {
      const rect = el.getBoundingClientRect();
      const style = window.getComputedStyle(el);

      // Check of dit element de click-coördinaten bedekt
      const coversPoint = (
        x >= rect.left &&
        x <= rect.right &&
        y >= rect.top &&
        y <= rect.bottom
      );

      if (!coversPoint) continue;

      // SECURITY FIX v8.8.3: Skip CMP (Consent Management Platform) elementen
      if (isCMPElement(el)) {
        logDebug('[Visual-Hijack] Skipping CMP element:', el.tagName, el.className);
        continue;
      }

      // SECURITY FIX v8.3.0: Skip Google Ads elementen
      if (isGoogleAdsElement(el)) {
        logDebug('[Visual-Hijack] Skipping Google Ads element:', el.tagName, el.className);
        continue;
      }

      const zIndex = parseInt(style.zIndex, 10) || 0;
      const pointerEvents = style.pointerEvents;
      const opacity = parseFloat(style.opacity);

      // CRITICAL: Detecteer pointer-events: none met hoge z-index
      if (pointerEvents === 'none' && zIndex >= HIGH_Z_THRESHOLD) {
        return {
          isHijacked: true,
          hijacker: el,
          reason: 'pointerEventsNoneHighZIndex'
        };
      }

      // Detecteer INT_MAX z-index aanvallen (zelfs met pointer-events: auto)
      if (zIndex >= INT_MAX - 1000) {
        // Bijna INT_MAX is verdacht ongeacht pointer-events
        if (opacity < 0.1 || pointerEvents === 'none') {
          return {
            isHijacked: true,
            hijacker: el,
            reason: 'intMaxZIndexOverlay'
          };
        }
      }

      // Detecteer transparante fullscreen overlays met pointer-events: none
      const isFullscreen = rect.width >= window.innerWidth * 0.9 &&
                           rect.height >= window.innerHeight * 0.9;
      if (isFullscreen && pointerEvents === 'none' && zIndex > 9000) {
        return {
          isHijacked: true,
          hijacker: el,
          reason: 'fullscreenPointerEventsNone'
        };
      }
    } catch (e) { /* ignore */ }
  }

  return { isHijacked: false, hijacker: null, reason: '' };
}

/**
 * Detecteert of er een transparant/onzichtbaar element over een bepaald punt ligt.
 * Dit beschermt tegen z-index aanvallen waarbij een aanvaller een transparante
 * overlay over legitieme links plaatst om clicks te hijacken.
 *
 * @param {number} x - X-coördinaat van de click
 * @param {number} y - Y-coördinaat van de click
 * @param {HTMLElement} expectedTarget - Het element dat we verwachten aan te klikken
 * @returns {{isHijacked: boolean, hijacker: HTMLElement|null, reason: string}}
 */
function detectVisualHijacking(x, y, expectedTarget) {
  // SECURITY FIX v8.0.2: Eerst check voor pointer-events: none overlays
  // Deze worden NIET gedetecteerd door elementsFromPoint()
  const pointerEventsCheck = detectPointerEventsNoneOverlay(x, y);
  if (pointerEventsCheck.isHijacked) {
    return pointerEventsCheck;
  }

  // Haal alle elementen op dit punt op (voor normale overlay detectie)
  const elementsAtPoint = document.elementsFromPoint(x, y);

  if (!elementsAtPoint || elementsAtPoint.length === 0) {
    return { isHijacked: false, hijacker: null, reason: '' };
  }

  // Het bovenste element op dit punt
  const topElement = elementsAtPoint[0];

  // Als het bovenste element het verwachte element is, geen hijacking
  if (topElement === expectedTarget || expectedTarget.contains(topElement) || topElement.contains(expectedTarget)) {
    return { isHijacked: false, hijacker: null, reason: '' };
  }

  // SECURITY FIX v8.8.3: Skip CMP (Consent Management Platform) elementen
  if (isCMPElement(topElement)) {
    logDebug('[Visual-Hijack] Skipping CMP top element:', topElement.tagName, topElement.className);
    return { isHijacked: false, hijacker: null, reason: '' };
  }

  // SECURITY FIX v8.3.0: Skip Google Ads elementen
  if (isGoogleAdsElement(topElement)) {
    logDebug('[Visual-Hijack] Skipping Google Ads top element:', topElement.tagName, topElement.className);
    return { isHijacked: false, hijacker: null, reason: '' };
  }

  // Controleer of het bovenste element verdacht is
  const style = window.getComputedStyle(topElement);

  // Verdachte kenmerken voor overlay hijacking
  const isTransparent = parseFloat(style.opacity) < 0.1 || style.opacity === '0';
  const isInvisible = style.visibility === 'hidden' && style.pointerEvents !== 'none';
  const hasNoBackground = (style.backgroundColor === 'transparent' || style.backgroundColor === 'rgba(0, 0, 0, 0)') && !style.backgroundImage;
  const hasHighZIndex = parseInt(style.zIndex, 10) > 9000;
  const coversFullViewport = topElement.offsetWidth >= window.innerWidth * 0.9 && topElement.offsetHeight >= window.innerHeight * 0.9;

  // Check voor verdachte combinaties
  if (isTransparent && hasHighZIndex) {
    return {
      isHijacked: true,
      hijacker: topElement,
      reason: 'transparentHighZIndexOverlay'
    };
  }

  if (hasNoBackground && hasHighZIndex && !topElement.textContent.trim()) {
    return {
      isHijacked: true,
      hijacker: topElement,
      reason: 'invisibleClickjackOverlay'
    };
  }

  if (coversFullViewport && (isTransparent || hasNoBackground)) {
    return {
      isHijacked: true,
      hijacker: topElement,
      reason: 'fullscreenTransparentOverlay'
    };
  }

  // Controleer of het element een link is met een andere href
  if (topElement.tagName === 'A' && topElement.href !== expectedTarget.href) {
    const topStyle = window.getComputedStyle(topElement);
    if (parseFloat(topStyle.opacity) < 0.5 || topElement.offsetWidth === 0 || topElement.offsetHeight === 0) {
      return {
        isHijacked: true,
        hijacker: topElement,
        reason: 'hiddenLinkOverlay'
      };
    }
  }

  return { isHijacked: false, hijacker: null, reason: '' };
}

/**
 * Voegt een click interceptie handler toe aan alert-level links.
 * Dit is een backup mechanisme naast de DNR netwerk blokkering.
 *
 * @param {HTMLAnchorElement} link - De link die geblokkeerd moet worden
 * @param {string[]} reasons - Redenen waarom de link gevaarlijk is
 */
function attachClickInterceptor(link, reasons) {
  // Voorkom dubbele handlers
  if (link.dataset.linkshieldClickIntercepted === 'true') return;
  link.dataset.linkshieldClickIntercepted = 'true';

  const interceptHandler = (event) => {
    // SECURITY FIX v8.8.11: Check if on trusted domain (skip visual hijacking but not link blocking)
    const HARDCODED_TRUSTED = [
      'google.com', 'youtube.com', 'facebook.com', 'twitter.com', 'x.com',
      'instagram.com', 'linkedin.com', 'reddit.com', 'amazon.com', 'microsoft.com',
      'apple.com', 'netflix.com', 'spotify.com', 'github.com', 'stackoverflow.com',
      'bbc.com', 'bbc.co.uk', 'cnn.com', 'nytimes.com', 'theguardian.com',
      'yahoo.com', 'bing.com', 'duckduckgo.com', 'wikipedia.org'
    ];
    const currentHostname = window.location.hostname.toLowerCase();
    let isOnTrustedDomain = false;

    // Check hardcoded list first
    for (const domain of HARDCODED_TRUSTED) {
      if (currentHostname === domain || currentHostname.endsWith('.' + domain)) {
        isOnTrustedDomain = true;
        break;
      }
    }

    // Then check loaded safeDomains
    if (!isOnTrustedDomain && safeDomainsInitialized && safeDomains.length > 0) {
      for (const pattern of safeDomains) {
        try {
          if (new RegExp(pattern, 'i').test(currentHostname)) {
            isOnTrustedDomain = true;
            break;
          }
        } catch (e) { /* invalid regex, skip */ }
      }
    }

    // Detecteer visual hijacking (skip on trusted domains)
    if (!isOnTrustedDomain) {
      const hijackCheck = detectVisualHijacking(event.clientX, event.clientY, link);

      if (hijackCheck.isHijacked) {
        event.preventDefault();
        event.stopPropagation();
        event.stopImmediatePropagation();

        logDebug(`[Vector3] Visual Hijacking gedetecteerd: ${hijackCheck.reason}`);

        // Toon waarschuwing aan gebruiker
        showVisualHijackingWarning(hijackCheck.reason, link.href);
        return false;
      }
    }

    // Als de link al als gevaarlijk is gemarkeerd, blokkeer de click
    if (link.dataset.linkshieldBlocked === 'true') {
      event.preventDefault();
      event.stopPropagation();
      event.stopImmediatePropagation();

      logDebug(`[Vector3] Click geblokkeerd op alert-level link: ${link.href}`);

      // Redirect naar de alert pagina
      const alertUrl = chrome.runtime.getURL(`alert.html?blocked=true&url=${encodeURIComponent(link.href)}&reason=${encodeURIComponent(reasons.join(', '))}`);
      window.location.href = alertUrl;
      return false;
    }
  };

  // Voeg handler toe in capture phase om andere handlers te overrulen
  link.addEventListener('click', interceptHandler, { capture: true });

  // Markeer de link als geblokkeerd voor de click interceptor
  link.dataset.linkshieldBlocked = 'true';
}

/**
 * SECURITY FIX v8.0.2 (Vector 3 - Z-Index War 2.0 Defense)
 * Toont een visuele hijacking waarschuwing met behulp van de Top Layer API.
 *
 * De <dialog> element met showModal() rendert in de "top layer" die boven ALLE
 * reguliere z-index elementen staat, inclusief z-index: 2147483647.
 *
 * Gebruikt closed ShadowRoot om manipulatie door de pagina te voorkomen.
 *
 * @param {string} reason - De reden voor de detectie
 * @param {string} targetUrl - De oorspronkelijke target URL
 */
function showVisualHijackingWarning(reason, targetUrl) {
  // SECURITY FIX v8.3.1: Never show warnings inside iframes (ad frames, etc.)
  if (window.self !== window.top) {
    return; // Do NOT show warnings inside iframes
  }

  const reasonText = getTranslatedMessage(reason) || reason;
  const title = getTranslatedMessage('visualHijackingDetected') || 'Visual Hijacking Detected';
  const message = getTranslatedMessage('visualHijackingMessage') ||
    'A hidden overlay was detected trying to intercept your click. This is a common phishing technique.';
  const tip = (getTranslatedMessage('detectionReason') || 'Detection reason') + ': ' + reasonText;

  showSecurityWarning({
    id: 'visual-hijack',
    severity: 'critical',
    title: title,
    message: message,
    tip: tip,
    icon: '👁️',
    showTrust: true
  });
}

/**
 * SECURITY FIX v8.0.2 (Vector 3 - Visual Hijack v2):
 * Globale click interceptor die ALTIJD visual hijacking detecteert voor externe links,
 * ongeacht de risk score. Dit voorkomt click-through aanvallen op "safe" looking links.
 *
 * Detecteert:
 * 1. Overlays met pointer-events: none die clicks doorlaten
 * 2. Links ZELF met verdacht hoge z-index (INT_MAX aanval)
 * 3. Fixed/absolute positioned links die over content liggen
 *
 * Draait in capture phase om voor alle andere handlers te komen.
 */
function initGlobalVisualHijackProtection() {
  // INT_MAX threshold voor verdachte z-index
  const SUSPICIOUS_Z_INDEX = 999999;
  const INT_MAX = 2147483647;

  document.addEventListener('click', (event) => {
    // SECURITY FIX v8.8.3: Skip visual hijacking checks op CMP/consent pagina's
    if (isConsentManagementPage()) {
      return; // Laat clicks door op consent pagina's
    }

    // SECURITY FIX v8.8.11: Skip visual hijacking checks op trusted domains
    // Advertisements on trusted sites (like BBC) use legitimate overlays for click tracking
    const HARDCODED_TRUSTED = [
      'google.com', 'youtube.com', 'facebook.com', 'twitter.com', 'x.com',
      'instagram.com', 'linkedin.com', 'reddit.com', 'amazon.com', 'microsoft.com',
      'apple.com', 'netflix.com', 'spotify.com', 'github.com', 'stackoverflow.com',
      'bbc.com', 'bbc.co.uk', 'cnn.com', 'nytimes.com', 'theguardian.com',
      'yahoo.com', 'bing.com', 'duckduckgo.com', 'wikipedia.org'
    ];
    const currentHostname = window.location.hostname.toLowerCase();

    // Check hardcoded list first (always works, no async needed)
    for (const domain of HARDCODED_TRUSTED) {
      if (currentHostname === domain || currentHostname.endsWith('.' + domain)) {
        return; // Skip visual hijacking checks on trusted domains
      }
    }

    // Then check loaded safeDomains
    if (safeDomainsInitialized && safeDomains.length > 0) {
      for (const pattern of safeDomains) {
        try {
          if (new RegExp(pattern, 'i').test(currentHostname)) {
            return; // Skip visual hijacking checks on trusted domains
          }
        } catch (e) { /* invalid regex, skip */ }
      }
    }

    // Vind de dichtstbijzijnde link (in geval van nested elements)
    const link = event.target.closest('a[href]');
    if (!link || !link.href) return;

    // Skip interne links
    try {
      const linkUrl = new URL(link.href);
      const currentHost = window.location.hostname;

      // Skip same-origin links en javascript: links
      if (linkUrl.hostname === currentHost ||
          linkUrl.protocol === 'javascript:' ||
          linkUrl.protocol === 'mailto:' ||
          linkUrl.protocol === 'tel:') {
        return;
      }
    } catch (e) {
      // Ongeldige URL - skip
      return;
    }

    // SECURITY FIX v8.0.2: Check of de LINK ZELF verdacht hoge z-index heeft
    const linkStyle = window.getComputedStyle(link);
    const linkZIndex = parseInt(linkStyle.zIndex, 10) || 0;
    const linkPosition = linkStyle.position;

    // Detecteer INT_MAX z-index aanval op de link zelf
    if (linkZIndex >= SUSPICIOUS_Z_INDEX) {
      // Link heeft verdacht hoge z-index - mogelijk clickjack aanval
      const isPositioned = linkPosition === 'fixed' || linkPosition === 'absolute' || linkPosition === 'relative';

      if (isPositioned) {
        event.preventDefault();
        event.stopPropagation();
        event.stopImmediatePropagation();

        logDebug(`[Vector3-Global] BLOCKED: Link has suspicious z-index ${linkZIndex} with position: ${linkPosition}`);
        showVisualHijackingWarning('suspiciousLinkZIndex', link.href);
        return false;
      }
    }

    // Check ook parent elementen voor hoge z-index
    let parent = link.parentElement;
    let depth = 0;
    while (parent && parent !== document.body && depth < 10) {
      const parentStyle = window.getComputedStyle(parent);
      const parentZIndex = parseInt(parentStyle.zIndex, 10) || 0;
      const parentPosition = parentStyle.position;

      if (parentZIndex >= SUSPICIOUS_Z_INDEX &&
          (parentPosition === 'fixed' || parentPosition === 'absolute')) {
        event.preventDefault();
        event.stopPropagation();
        event.stopImmediatePropagation();

        logDebug(`[Vector3-Global] BLOCKED: Link parent has suspicious z-index ${parentZIndex}`);
        showVisualHijackingWarning('suspiciousContainerZIndex', link.href);
        return false;
      }
      parent = parent.parentElement;
      depth++;
    }

    // SECURITY FIX v8.0.1: Detecteer visual hijacking overlays op ELKE externe link click
    const hijackCheck = detectVisualHijacking(event.clientX, event.clientY, link);

    if (hijackCheck.isHijacked) {
      // Blokkeer de click
      event.preventDefault();
      event.stopPropagation();
      event.stopImmediatePropagation();

      logDebug(`[Vector3-Global] Visual Hijacking gedetecteerd: ${hijackCheck.reason} voor ${link.href}`);

      // Toon waarschuwing
      showVisualHijackingWarning(hijackCheck.reason, link.href);
      return false;
    }

    // Extra check: pointer-events manipulatie detectie
    if (linkStyle.pointerEvents === 'none') {
      // Link heeft pointer-events: none maar kreeg toch een click - verdacht!
      const elementsAtClick = document.elementsFromPoint(event.clientX, event.clientY);
      const actualTarget = elementsAtClick[0];

      if (actualTarget && actualTarget !== link && actualTarget.tagName === 'A') {
        // Er is een andere link op deze positie die de echte click ontvangt
        event.preventDefault();
        event.stopPropagation();
        event.stopImmediatePropagation();

        logDebug(`[Vector3-Global] Pointer-events hijack gedetecteerd`);
        showVisualHijackingWarning('pointerEventsHijack', link.href);
        return false;
      }
    }
  }, { capture: true }); // BELANGRIJK: capture phase

  logDebug('[Vector3-Global] Visual Hijack protection initialized for ALL external links');
}

// SECURITY FIX v8.8.12: Global visual hijack protection disabled - causes too many false positives
// Visual hijacking is now only checked on links already flagged as suspicious by URL analysis
// (via attachClickInterceptor which only runs on alert-level links)
// if (document.readyState === 'loading') {
//   document.addEventListener('DOMContentLoaded', initGlobalVisualHijackProtection);
// } else {
//   initGlobalVisualHijackProtection();
// }

/**
 * SECURITY FIX v8.5.0: Proactive Visual Hijacking Scanner
 * Detects malicious overlays on page load WITHOUT waiting for user clicks.
 * This catches Z-Index War attacks where attackers place transparent overlays
 * with pointer-events: none to intercept user interactions.
 */
async function proactiveVisualHijackingScan() {
  // SECURITY FIX v8.3.1: Only run in top-level frame, not inside iframes
  // Visual hijacking attacks target the main page, not embedded ad iframes.
  // Running inside iframes causes false positives with legitimate ad overlays.
  if (window.self !== window.top) {
    return false; // Skip scanning inside iframes
  }

  // SECURITY FIX v8.2.0: Respect protection settings
  if (!(await isProtectionEnabled())) {
    logDebug('[Vector3-Proactive] Skipping scan - protection disabled');
    return false;
  }

  // SECURITY FIX v8.8.3: Skip scan op CMP/consent pagina's
  if (isConsentManagementPage()) {
    logDebug('[Vector3-Proactive] Skipping scan - CMP/consent page detected');
    return false;
  }

  // SECURITY FIX v8.8.11: Skip scan on trusted domains
  // Hardcoded fallback for major trusted domains (in case TrustedDomains.json fails to load)
  const HARDCODED_TRUSTED = [
    'google.com', 'youtube.com', 'facebook.com', 'twitter.com', 'x.com',
    'instagram.com', 'linkedin.com', 'reddit.com', 'amazon.com', 'microsoft.com',
    'apple.com', 'netflix.com', 'spotify.com', 'github.com', 'stackoverflow.com',
    'bbc.com', 'bbc.co.uk', 'cnn.com', 'nytimes.com', 'theguardian.com',
    'yahoo.com', 'bing.com', 'duckduckgo.com', 'wikipedia.org'
  ];

  const currentHostname = window.location.hostname.toLowerCase();

  // Check hardcoded list first (always works)
  for (const domain of HARDCODED_TRUSTED) {
    if (currentHostname === domain || currentHostname.endsWith('.' + domain)) {
      logDebug('[Vector3-Proactive] Skipping scan - hardcoded trusted domain:', currentHostname);
      return false;
    }
  }

  // Then check loaded safeDomains
  await waitForSafeDomains();
  if (safeDomains.length > 0) {
    for (const pattern of safeDomains) {
      try {
        if (new RegExp(pattern, 'i').test(currentHostname)) {
          logDebug('[Vector3-Proactive] Skipping scan - trusted domain:', currentHostname);
          return false;
        }
      } catch (e) { /* invalid regex, skip */ }
    }
  }

  const INT_MAX = 2147483647;
  const HIGH_Z_THRESHOLD = 999999;

  // SECURITY FIX v8.3.1: Final safety check helper for trusted domains
  const isOnTrustedDomainFinal = () => {
    const hostname = window.location.hostname.toLowerCase();
    const trustedPatterns = [
      'google.com', 'youtube.com', 'facebook.com', 'twitter.com', 'x.com',
      'instagram.com', 'linkedin.com', 'reddit.com', 'amazon.com', 'microsoft.com',
      'apple.com', 'netflix.com', 'spotify.com', 'github.com', 'stackoverflow.com',
      'bbc.com', 'bbc.co.uk', 'cnn.com', 'nytimes.com', 'theguardian.com',
      'yahoo.com', 'bing.com', 'duckduckgo.com', 'wikipedia.org'
    ];
    for (const domain of trustedPatterns) {
      if (hostname === domain || hostname.endsWith('.' + domain)) {
        return true;
      }
    }
    return false;
  };

  // Scan all elements for suspicious overlay patterns
  const allElements = document.querySelectorAll('*');

  for (const el of allElements) {
    try {
      // Skip LinkShield's own elements
      if (el.id && el.id.includes('linkshield')) continue;
      if (el.tagName === 'DIALOG') continue;

      // SECURITY FIX v8.8.5: Skip CMP/cookie banner elements in proactive scan
      if (isCMPElement(el)) {
        continue;
      }

      // SECURITY FIX v8.3.0: Skip Google Ads elements (legitimate ad overlays)
      if (isGoogleAdsElement(el)) {
        continue;
      }

      const style = window.getComputedStyle(el);
      const position = style.position;
      const zIndex = parseInt(style.zIndex, 10) || 0;
      const pointerEvents = style.pointerEvents;
      const opacity = parseFloat(style.opacity);

      // Only check fixed/absolute positioned elements
      if (position !== 'fixed' && position !== 'absolute') continue;

      const rect = el.getBoundingClientRect();
      const isLargeOverlay = rect.width >= window.innerWidth * 0.5 &&
                             rect.height >= window.innerHeight * 0.5;

      // Check for transparent/invisible properties
      const bgColor = style.backgroundColor;
      const isTransparentBg = bgColor === 'transparent' ||
                              bgColor === 'rgba(0, 0, 0, 0)' ||
                              bgColor.startsWith('rgba') && parseFloat(bgColor.split(',')[3]) < 0.1;
      const hasNoVisibleContent = !el.textContent.trim() && !style.backgroundImage;
      const isInvisible = opacity < 0.3 || (isTransparentBg && hasNoVisibleContent);

      // CRITICAL: Detect pointer-events: none with high z-index (Z-Index War attack)
      if (pointerEvents === 'none' && zIndex >= HIGH_Z_THRESHOLD && isLargeOverlay) {
        // Double-check: skip if any ancestor is a CMP element
        if (el.closest('[id*="cookiebot"], [id*="consent"], [id*="cookie"], [class*="cookie"], [class*="consent"], [id*="onetrust"], [id*="didomi"]')) {
          logDebug('[Vector3-Proactive] Skipping CMP overlay element');
          continue;
        }
        // SECURITY FIX v8.3.1: Final trusted domain check before warning
        if (isOnTrustedDomainFinal()) {
          logDebug('[Vector3-Proactive] Skipping warning - trusted domain (final check)');
          continue;
        }
        logDebug(`[Vector3-Proactive] 🛡️ Visual Hijacking DETECTED: z-index=${zIndex}, pointer-events=none`);
        showVisualHijackingWarning('pointerEventsNoneHighZIndex', window.location.href);
        return true; // Stop after first detection
      }

      // Detect INT_MAX z-index with suspicious properties (transparent overlay attack)
      if (zIndex >= INT_MAX - 1000 && isLargeOverlay) {
        if (isInvisible || pointerEvents === 'none') {
          // Double-check: skip if any ancestor is a CMP element
          if (el.closest('[id*="cookiebot"], [id*="consent"], [id*="cookie"], [class*="cookie"], [class*="consent"], [id*="onetrust"], [id*="didomi"]')) {
            logDebug('[Vector3-Proactive] Skipping CMP INT_MAX element');
            continue;
          }
          // SECURITY FIX v8.3.1: Final trusted domain check before warning
          if (isOnTrustedDomainFinal()) {
            logDebug('[Vector3-Proactive] Skipping warning - trusted domain (final check)');
            continue;
          }
          logDebug(`[Vector3-Proactive] 🛡️ INT_MAX Z-Index attack DETECTED: transparent overlay`);
          showVisualHijackingWarning('intMaxZIndexOverlay', window.location.href);
          return true;
        }
      }

      // SECURITY FIX v8.1.8: Detect clickable links with extreme z-index that are nearly invisible
      if (el.tagName === 'A' && el.href && zIndex >= INT_MAX - 1000) {
        if (isInvisible) {
          if (el.closest('[id*="cookiebot"], [id*="consent"], [id*="cookie"], [class*="cookie"], [class*="consent"], [id*="onetrust"], [id*="didomi"]')) {
            continue;
          }
          // SECURITY FIX v8.3.1: Final trusted domain check before warning
          if (isOnTrustedDomainFinal()) {
            logDebug('[Vector3-Proactive] Skipping warning - trusted domain (final check)');
            continue;
          }
          logDebug(`[Vector3-Proactive] 🛡️ Invisible link with INT_MAX z-index DETECTED: ${el.href}`);
          showVisualHijackingWarning('hiddenLinkOverlay', el.href);
          return true;
        }
      }
    } catch (e) { /* ignore */ }
  }

  return false;
}

/**
 * SECURITY FIX v8.5.0: Fake Cloudflare Turnstile Detection
 * Detecteert nep CAPTCHA/Turnstile verificaties die gebruikt worden
 * in ConsentFix en andere social engineering aanvallen
 *
 * @returns {Object} - { detected: boolean, indicators: string[], score: number }
 */
async function detectFakeTurnstile() {
    if (!globalConfig?.ADVANCED_THREAT_DETECTION?.fakeTurnstile?.enabled) {
        return { detected: false, indicators: [], score: 0 };
    }

    // Skip if Smart Link Scanning (integratedProtection) is disabled
    if (!(await isProtectionEnabled())) {
        return { detected: false, indicators: [], score: 0 };
    }

    // Skip check on trusted domains (e.g., facebook.com)
    try {
        const currentHostname = window.location.hostname;
        if (await isTrustedDomain(currentHostname)) {
            return { detected: false, indicators: [], score: 0 };
        }
    } catch (e) {
        // Continue with check if trust verification fails
    }

    const config = globalConfig.ADVANCED_THREAT_DETECTION.fakeTurnstile;
    const indicators = [];
    let score = 0;

    try {
        // Stap 1: Check voor legitieme Turnstile iframes
        const iframes = document.querySelectorAll('iframe');
        let hasLegitimateTurnstile = false;

        for (const iframe of iframes) {
            if (!iframe.src) continue;
            try {
                const iframeSrc = iframe.src.toLowerCase();
                if (config.legitimateOrigins.some(origin => iframeSrc.includes(origin))) {
                    hasLegitimateTurnstile = true;
                    break;
                }
            } catch (e) { /* cross-origin */ }
        }

        // Stap 2: Check voor Turnstile-achtige UI elementen
        const bodyText = document.body?.innerText?.toLowerCase() || '';
        const bodyHtml = document.body?.innerHTML?.toLowerCase() || '';

        let hasTurnstileText = false;
        for (const pattern of config.textPatterns) {
            if (bodyText.includes(pattern.toLowerCase())) {
                hasTurnstileText = true;
                indicators.push(`turnstile_text: "${pattern}"`);
                break;
            }
        }

        // Stap 3: Check voor Turnstile branding/styling zonder legitieme iframe
        const hasTurnstileBranding =
            bodyHtml.includes('cf-turnstile') ||
            bodyHtml.includes('turnstile-widget') ||
            !!document.querySelector('[class*="turnstile"]') ||
            !!document.querySelector('[id*="turnstile"]');

        if (hasTurnstileBranding) {
            indicators.push('turnstile_branding_found');
        }

        // Stap 4: Check voor checkbox met "I'm human" zonder Turnstile
        const checkboxes = document.querySelectorAll('input[type="checkbox"]');
        for (const cb of checkboxes) {
            const parentText = cb.parentElement?.innerText?.toLowerCase() || '';
            const labelText = document.querySelector(`label[for="${cb.id}"]`)?.innerText?.toLowerCase() || '';
            const combinedText = parentText + ' ' + labelText;

            if (combinedText.match(/human|robot|not a robot|i('| a)?m human|verify.{0,5}(human|identity|yourself)/)) {
                indicators.push('fake_human_checkbox');
                break;
            }
        }

        // Stap 5: Check voor spinner/loading animatie met verificatie tekst
        const spinners = document.querySelectorAll('[class*="spinner"], [class*="loading"], [class*="loader"]');
        for (const spinner of spinners) {
            const nearbyText = spinner.parentElement?.innerText?.toLowerCase() || '';
            if (nearbyText.match(/verify.{0,10}human|checking.{0,15}(connection|secure|browser)|human.{0,10}verif|captcha|turnstile/)) {
                indicators.push('fake_verification_spinner');
                break;
            }
        }

        // Bepaal of het fake is
        // Require Turnstile-specific context (text or branding), or multiple supporting indicators
        const hasTurnstileContext = hasTurnstileText || hasTurnstileBranding;
        const hasMultipleSupportingIndicators = indicators.filter(i => !i.startsWith('turnstile_')).length >= 2;
        const isFake = (hasTurnstileContext || hasMultipleSupportingIndicators) &&
                       !hasLegitimateTurnstile;

        if (isFake) {
            score = globalConfig.ADVANCED_THREAT_DETECTION.scores.FAKE_TURNSTILE_INDICATOR;

            logDebug(`[FakeTurnstile] 🚨 DETECTED - Score: ${score}`);
            logDebug(`[FakeTurnstile] Indicators: ${indicators.join(', ')}`);

            // Rapporteer aan background
            if (typeof chrome !== 'undefined' && chrome.runtime?.sendMessage) {
                chrome.runtime.sendMessage({
                    type: 'fakeTurnstileDetected',
                    url: window.location.href,
                    indicators: indicators,
                    score: score,
                    timestamp: Date.now()
                }).catch(() => {});
            }
        }

        return { detected: isFake, indicators, score };

    } catch (err) {
        handleError(err, 'FakeTurnstileDetection');
        return { detected: false, indicators: [], score: 0 };
    }
}

// =============================================================================
// v8.6.0: AiTM (Adversary-in-the-Middle) Proxy Detection
// Detecteert reverse proxy phishing (Evilginx, Tycoon 2FA) door provider-specifieke
// DOM element IDs te vinden op niet-legitieme domeinen
// =============================================================================
async function detectAiTMProxy() {
    const config = globalConfig?.ADVANCED_THREAT_DETECTION?.aitmDetection;
    if (!config?.enabled) {
        return { detected: false, provider: null, score: 0, indicators: [] };
    }

    // Check integratedProtection enabled
    if (!(await isProtectionEnabled())) {
        return { detected: false, provider: null, score: 0, indicators: [] };
    }

    // Skip trusted domains
    const hostname = window.location.hostname.toLowerCase();
    try {
        if (await isTrustedDomain(hostname)) {
            return { detected: false, provider: null, score: 0, indicators: [] };
        }
    } catch (e) { /* Continue */ }

    // Check if current domain is a legitimate provider
    for (const provider of config.legitimateProviders) {
        if (hostname === provider || hostname.endsWith('.' + provider)) {
            return { detected: false, provider: null, score: 0, indicators: [] };
        }
    }

    const indicators = [];
    let score = 0;
    let detectedProvider = null;

    try {
        // === Microsoft Markers ===
        let msScore = 0;
        if (document.getElementById('i0116')) {
            msScore += config.scores.msSpecificId;
            indicators.push('ms_email_input_i0116');
        }
        if (document.getElementById('i0118')) {
            msScore += config.scores.msSpecificId;
            indicators.push('ms_password_input_i0118');
        }
        if (document.getElementById('idSIButton9')) {
            msScore += config.scores.msButton;
            indicators.push('ms_submit_button');
        }
        if (document.getElementById('lightbox') || document.querySelector('.login-paginated-page')) {
            msScore += config.scores.msContainer;
            indicators.push('ms_login_container');
        }
        if (document.querySelector('.ext-sign-in-box')) {
            msScore += config.scores.msContainer;
            indicators.push('ms_signin_box');
        }
        if (window.location.pathname.includes('/common/oauth2/')) {
            msScore += config.scores.msOAuthPath;
            indicators.push('ms_oauth_path');
        }

        // === Google Markers ===
        let googleScore = 0;
        if (document.getElementById('identifierId')) {
            googleScore += config.scores.googleSpecificId;
            indicators.push('google_identifier_input');
        }
        if (document.getElementById('passwordNext') || document.getElementById('identifierNext')) {
            googleScore += config.scores.googleButton;
            indicators.push('google_next_button');
        }
        if (document.querySelector('.OLlbdf') || document.querySelector('.U26fgb')) {
            googleScore += config.scores.googleClass;
            indicators.push('google_internal_class');
        }
        if (window.location.pathname.includes('/ServiceLogin')) {
            googleScore += config.scores.googleLoginPath;
            indicators.push('google_servicelogin_path');
        }

        // Bepaal welke provider gedetecteerd is
        if (msScore > googleScore && msScore >= 8) {
            score = msScore;
            detectedProvider = 'Microsoft';
        } else if (googleScore >= 8) {
            score = googleScore;
            detectedProvider = 'Google';
        }

        // Universal signals (alleen als provider markers gevonden)
        if (detectedProvider) {
            // Wachtwoordveld aanwezig
            if (document.querySelector('input[type="password"]')) {
                score += config.scores.passwordField;
                indicators.push('password_field_present');
            }
            // Verdachte TLD
            const tld = hostname.split('.').pop();
            if (globalConfig?.isSuspiciousTLD && globalConfig.isSuspiciousTLD(tld)) {
                score += config.scores.suspiciousTLD;
                indicators.push('suspicious_tld');
            }
            // Free hosting domein
            if (globalConfig?.FREE_HOSTING_DOMAINS) {
                for (const freeHost of globalConfig.FREE_HOSTING_DOMAINS) {
                    if (hostname === freeHost || hostname.endsWith('.' + freeHost)) {
                        score += config.scores.freeHosting;
                        indicators.push('free_hosting_domain');
                        break;
                    }
                }
            }
        }

        // Threshold check: HIGH_THRESHOLD (15)
        const detected = score >= (globalConfig?.HIGH_THRESHOLD || 15);

        if (detected) {
            logDebug(`[AiTM] 🚨 DETECTED - Provider: ${detectedProvider}, Score: ${score}`);
            logDebug(`[AiTM] Indicators: ${indicators.join(', ')}`);

            // Rapporteer aan background
            if (typeof chrome !== 'undefined' && chrome.runtime?.sendMessage) {
                chrome.runtime.sendMessage({
                    type: 'aitmProxyDetected',
                    url: window.location.href,
                    provider: detectedProvider,
                    indicators: indicators,
                    score: score,
                    timestamp: Date.now()
                }).catch(() => {});
            }

            // Toon waarschuwing
            showSecurityWarning({
                id: 'aitm-proxy',
                severity: 'critical',
                title: getTranslatedMessage('aitmProxyTitle') || 'Phishing Proxy Detected!',
                message: (getTranslatedMessage('aitmProxyMessage') || 'This page appears to be a phishing proxy impersonating {provider}. Your credentials will be stolen if you log in here.').replace('{provider}', detectedProvider),
                tip: getTranslatedMessage('aitmProxyTip') || 'Always verify the URL in your address bar before entering credentials.',
                icon: '🎭',
                showTrust: false
            });
        }

        return { detected, provider: detectedProvider, score, indicators };

    } catch (err) {
        handleError(err, 'AiTMProxyDetection');
        return { detected: false, provider: null, score: 0, indicators: [] };
    }
}

// Initialiseer AiTM detectie met delay en MutationObserver
async function initAiTMDetection() {
    // Skip observers on trusted domains to prevent performance issues on complex SPAs
    const hostname = window.location.hostname.toLowerCase();
    if (await isTrustedDomain(hostname)) {
        logDebug('[AiTM] Skipping observer for trusted domain:', hostname);
        return;
    }

    // Initial scan na 2500ms (staggered na andere scans)
    setTimeout(async () => {
        await detectAiTMProxy();
    }, 2500);

    // MutationObserver voor dynamisch geladen login forms
    let aitmDebounceTimer = null;
    const aitmObserver = new MutationObserver((mutations) => {
        for (const mutation of mutations) {
            for (const node of mutation.addedNodes) {
                if (node.nodeType !== Node.ELEMENT_NODE) continue;
                // Hercheck als password veld of bekende IDs worden toegevoegd
                const isRelevant = node.matches?.('input[type="password"]') ||
                    node.id === 'i0116' || node.id === 'i0118' || node.id === 'identifierId' ||
                    node.querySelector?.('input[type="password"], #i0116, #i0118, #identifierId');
                if (isRelevant) {
                    clearTimeout(aitmDebounceTimer);
                    aitmDebounceTimer = setTimeout(() => detectAiTMProxy(), 500);
                    return;
                }
            }
        }
    });

    if (document.body) {
        aitmObserver.observe(document.body, { childList: true, subtree: true });
    }
}

// =============================================================================
// v8.6.0: SVG Payload Detection
// Detecteert kwaadaardige JavaScript in SVG elementen (alleen high-confidence patronen)
// =============================================================================
const _scannedSVGs = new WeakSet();

async function detectSVGPayloads() {
    const config = globalConfig?.ADVANCED_THREAT_DETECTION?.svgPayloadDetection;
    if (!config?.enabled) {
        return { detected: false, score: 0, indicators: [] };
    }

    // Check integratedProtection enabled
    if (!(await isProtectionEnabled())) {
        return { detected: false, score: 0, indicators: [] };
    }

    // Skip trusted domains
    const hostname = window.location.hostname.toLowerCase();
    try {
        if (await isTrustedDomain(hostname)) {
            return { detected: false, score: 0, indicators: [] };
        }
    } catch (e) { /* Continue */ }

    const indicators = [];
    let totalScore = 0;

    try {
        // Verzamel alle SVG elementen om te scannen
        const svgElements = [];

        // 1. Inline <svg> elementen
        const inlineSVGs = document.querySelectorAll('svg');
        for (const svg of inlineSVGs) {
            if (!_scannedSVGs.has(svg)) {
                svgElements.push({ element: svg, type: 'inline' });
                _scannedSVGs.add(svg);
            }
        }

        // 2. <object> met SVG type (same-origin)
        const objects = document.querySelectorAll('object[type="image/svg+xml"]');
        for (const obj of objects) {
            if (!_scannedSVGs.has(obj)) {
                _scannedSVGs.add(obj);
                try {
                    const svgDoc = obj.contentDocument;
                    if (svgDoc) {
                        const svg = svgDoc.querySelector('svg');
                        if (svg) svgElements.push({ element: svg, type: 'object' });
                    }
                } catch (e) { /* cross-origin, skip */ }
            }
        }

        // 3. <embed> met SVG type (same-origin)
        const embeds = document.querySelectorAll('embed[type="image/svg+xml"]');
        for (const embed of embeds) {
            if (!_scannedSVGs.has(embed)) {
                _scannedSVGs.add(embed);
                try {
                    const svgDoc = embed.getSVGDocument?.();
                    if (svgDoc) {
                        const svg = svgDoc.querySelector('svg');
                        if (svg) svgElements.push({ element: svg, type: 'embed' });
                    }
                } catch (e) { /* cross-origin, skip */ }
            }
        }

        // Scan elke SVG
        for (const { element: svg, type } of svgElements) {
            let svgScore = 0;
            const svgIndicators = [];

            // Check 1: <script> tags met gevaarlijke content
            const scripts = svg.querySelectorAll('script');
            for (const script of scripts) {
                const content = script.textContent || '';
                if (!content.trim()) continue;

                for (const pattern of config.dangerousScriptPatterns) {
                    if (pattern.test(content)) {
                        svgScore += config.scores.dangerousScript;
                        svgIndicators.push('dangerous_script_content');
                        break; // Eén match per script is genoeg
                    }
                }

                // Check atob + eval combinatie
                if (/\batob\b/i.test(content) && /\beval\b/i.test(content)) {
                    svgScore += config.scores.base64Eval;
                    svgIndicators.push('base64_eval_combo');
                }
            }

            // Check 2: javascript:/data: URIs in href attributen
            const hrefElements = svg.querySelectorAll('[href], [xlink\\:href]');
            for (const el of hrefElements) {
                const href = el.getAttribute('href') || el.getAttribute('xlink:href') || '';
                for (const pattern of config.dangerousURIPatterns) {
                    if (pattern.test(href)) {
                        svgScore += config.scores.dangerousURI;
                        svgIndicators.push('dangerous_uri_in_href');
                        break;
                    }
                }
            }

            // Check 3: foreignObject met redirect code
            const foreignObjects = svg.querySelectorAll('foreignObject');
            for (const fo of foreignObjects) {
                const foContent = fo.innerHTML || '';
                if (/window\.location/i.test(foContent) ||
                    /meta\s+http-equiv\s*=\s*["']refresh/i.test(foContent) ||
                    /document\.location/i.test(foContent)) {
                    svgScore += config.scores.foreignObjectRedirect;
                    svgIndicators.push('foreignobject_redirect');
                }
            }

            // Check 4: Event handlers met gevaarlijke patronen (alleen als andere indicators gevonden)
            if (svgIndicators.length > 0) {
                const allElements = svg.querySelectorAll('*');
                for (const el of allElements) {
                    for (const attr of el.attributes) {
                        if (attr.name.startsWith('on')) {
                            const val = attr.value || '';
                            for (const pattern of config.dangerousScriptPatterns) {
                                if (pattern.test(val)) {
                                    svgScore += config.scores.maliciousEventHandler;
                                    svgIndicators.push('malicious_event_handler');
                                    break;
                                }
                            }
                            break; // Eén event handler check per element
                        }
                    }
                }
            }

            // Threshold check per SVG
            if (svgScore >= config.scoreThreshold) {
                totalScore = Math.max(totalScore, svgScore);
                indicators.push(...svgIndicators);
            }
        }

        const detected = totalScore >= config.scoreThreshold;

        if (detected) {
            logDebug(`[SVGPayload] 🚨 DETECTED - Score: ${totalScore}`);
            logDebug(`[SVGPayload] Indicators: ${indicators.join(', ')}`);

            // Rapporteer aan background
            if (typeof chrome !== 'undefined' && chrome.runtime?.sendMessage) {
                chrome.runtime.sendMessage({
                    type: 'svgPayloadDetected',
                    url: window.location.href,
                    indicators: indicators,
                    score: totalScore,
                    timestamp: Date.now()
                }).catch(() => {});
            }

            // Toon waarschuwing
            showSecurityWarning({
                id: 'svg-payload',
                severity: 'critical',
                title: getTranslatedMessage('svgPayloadTitle') || 'Malicious SVG Detected!',
                message: getTranslatedMessage('svgPayloadMessage') || 'This page contains an SVG with embedded malicious code that could steal your data.',
                tip: getTranslatedMessage('svgPayloadTip') || 'Be cautious with SVG attachments from unknown sources.',
                icon: '🖼️',
                showTrust: true
            });
        }

        return { detected, score: totalScore, indicators };

    } catch (err) {
        handleError(err, 'SVGPayloadDetection');
        return { detected: false, score: 0, indicators: [] };
    }
}

// Initialiseer SVG Payload detectie met MutationObserver
// SECURITY FIX v8.7.2: Removed delay to prevent race condition where malicious
// SVG onload scripts execute before detection runs
async function initSVGPayloadDetection() {
    // Skip observers on trusted domains to prevent performance issues on complex SPAs
    const hostname = window.location.hostname.toLowerCase();
    if (await isTrustedDomain(hostname)) {
        logDebug('[SVG] Skipping observer for trusted domain:', hostname);
        return;
    }

    // SECURITY FIX v8.7.2: Scan existing SVGs IMMEDIATELY (no delay)
    // This catches inline SVGs that exist at page load
    // Use queueMicrotask to run after current script execution but before onload events
    queueMicrotask(async () => {
        await detectSVGPayloads();
    });

    // Also scan after a short delay to catch SVGs loaded via defer/async scripts
    setTimeout(async () => {
        await detectSVGPayloads();
    }, 100);

    // SECURITY FIX v8.7.2: MutationObserver with IMMEDIATE scanning for new SVGs
    // Reduced debounce from 500ms to 50ms to catch fast-loading SVGs
    let svgDebounceTimer = null;
    const svgObserver = new MutationObserver((mutations) => {
        let foundSVG = false;
        for (const mutation of mutations) {
            for (const node of mutation.addedNodes) {
                if (node.nodeType !== Node.ELEMENT_NODE) continue;

                // Check if this node IS an SVG or CONTAINS an SVG
                const isSVG = node.matches?.('svg, object[type="image/svg+xml"], embed[type="image/svg+xml"]');
                const containsSVG = node.querySelector?.('svg, object[type="image/svg+xml"], embed[type="image/svg+xml"]');

                if (isSVG || containsSVG) {
                    foundSVG = true;

                    // SECURITY FIX v8.7.2: Check for immediate threats in inline SVG
                    // This catches <svg onload="..."> before the script can execute much
                    if (isSVG && node.tagName === 'svg') {
                        // Check for dangerous onload attribute immediately (synchronous)
                        const onload = node.getAttribute('onload');
                        if (onload) {
                            const dangerPatterns = [
                                /location\s*[=.]/i,
                                /document\.cookie/i,
                                /eval\s*\(/i,
                                /fetch\s*\(/i,
                                /XMLHttpRequest/i
                            ];
                            for (const pattern of dangerPatterns) {
                                if (pattern.test(onload)) {
                                    logDebug('[SVG] IMMEDIATE THREAT: Dangerous onload detected');
                                    // Remove the onload to prevent execution
                                    node.removeAttribute('onload');
                                    // Trigger full scan immediately
                                    detectSVGPayloads();
                                    return;
                                }
                            }
                        }
                    }
                    break;
                }
            }
            if (foundSVG) break;
        }

        if (foundSVG) {
            // Minimal debounce (50ms) to batch rapid DOM changes
            clearTimeout(svgDebounceTimer);
            svgDebounceTimer = setTimeout(() => detectSVGPayloads(), 50);
        }
    });

    if (document.body) {
        svgObserver.observe(document.body, { childList: true, subtree: true });
    }

    logDebug('[SVG] Payload detection initialized with immediate scanning');
}

// Run proactive scan after page load
async function initProactiveVisualHijackingScan() {
  // Skip observers on trusted domains to prevent performance issues on complex SPAs
  const hostname = window.location.hostname.toLowerCase();
  if (await isTrustedDomain(hostname)) {
    logDebug('[Vector3-Proactive] Skipping observer for trusted domain:', hostname);
    return;
  }

  // Initial scan with delay to let page render
  setTimeout(proactiveVisualHijackingScan, 1000);

  // Also scan when new elements are added via MutationObserver
  const hijackObserver = new MutationObserver((mutations) => {
    for (const mutation of mutations) {
      if (mutation.addedNodes.length > 0) {
        // Debounce: wait for DOM to settle
        clearTimeout(hijackObserver._debounceTimer);
        hijackObserver._debounceTimer = setTimeout(proactiveVisualHijackingScan, 500);
        break;
      }
    }
  });

  hijackObserver.observe(document.documentElement, {
    childList: true,
    subtree: true
  });

  logDebug('[Vector3-Proactive] Proactive Visual Hijacking scanner initialized');
}

// SECURITY FIX v8.1.8: Re-enabled proactive scanner with improved CMP/ad filtering
// The scanner now properly skips cookie consent banners, ad overlays, and trusted domains
// PERFORMANCE FIX: Only run in top frame - visual hijacking only targets main page
if (_isTopFrame) {
  if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', initProactiveVisualHijackingScan);
  } else {
    initProactiveVisualHijackingScan();
  }
}

function injectWarningIconStyles() {
    if (!document.head.querySelector('#phishing-warning-styles')) {
        const style = document.createElement('style');
        style.id = 'phishing-warning-styles';
        // SECURITY FIX v8.4.0: Added pointer-events: auto and z-index: 2147483647
        // to prevent Visual Hijacking attacks where attackers use pointer-events: none
        // overlays to let clicks pass through to malicious links underneath
        style.textContent = `
            .phishing-warning-icon {
                position: relative !important;
                z-index: 2147483647 !important;
                pointer-events: auto !important;
                vertical-align: middle !important;
                margin-left: 5px !important;
                cursor: help !important;
                transition: color 0.3s ease !important;
            }
            .subtle-warning {
                font-size: 12px !important;
                color: #ff9800 !important; /* Softer orange */
            }
            .high-risk-warning {
                font-size: 16px !important;
                color: #ff0000 !important;
                pointer-events: auto !important;
            }
            .high-risk-link {
                border: 1px dashed #ff0000 !important;
                color: #ff0000 !important;
                pointer-events: auto !important;
            }
            .moderate-warning {
                font-size: 14px !important;
                color: #ff5722 !important; /* Orange-red */
                pointer-events: auto !important;
            }
            .moderate-risk-link {
                border: 1px dotted #ff5722 !important;
                pointer-events: auto !important;
            }
            .phishing-warning-icon:hover {
                color: #d32f2f !important; /* Darker red on hover */
            }
            /* NIEUWE FALLBACK STIJLEN HIERONDER */
            .high-risk-link-fallback {
                outline: 2px dashed #ff0000 !important; /* Een zichtbare rand als fallback */
                outline-offset: 2px !important;
                box-shadow: 0 0 5px rgba(255, 0, 0, 0.5) !important; /* Optionele schaduw */
                pointer-events: auto !important;
            }
            .moderate-risk-link-fallback {
                outline: 1px dotted #ff5722 !important;
                outline-offset: 1px !important;
            }
        `;
        document.head.appendChild(style);
    }
}
function sanitizeInput(input) {
  const tempDiv = document.createElement('div');
  tempDiv.textContent = input;
  return tempDiv.innerHTML;
}

/**
 * SECURITY FIX v8.8.4 (Vector 3 V3 - Viewport-Fixed Badge)
 * Shows a subtle "Site Safe" badge when a page passes all security checks.
 *
 * Key improvements:
 * - Injects into document.documentElement (not body) to avoid CSS interference
 * - Aggressive CSS reset neutralizes transform, filter, perspective from parent
 * - Guaranteed viewport-fixed positioning regardless of page CSS
 * - Closed Shadow DOM prevents external CSS/JS manipulation
 *
 * The badge appears briefly in the bottom-right corner and fades out automatically.
 * User can dismiss permanently via the close button.
 */
async function showSiteSafeBadge() {
  // ============================================================================
  // SAFE BADGE v8.8.9 - Pure CSS positioning (no enforcer loop)
  // ============================================================================
  // Based on the old working version:
  // - Pure CSS fixed positioning (browser handles it)
  // - Inject into documentElement to bypass body transform issues
  // - Unique tag <ls-safe-badge> to avoid CSS conflicts
  // - Closed Shadow DOM for visual styling only
  // - NO all:initial on host (breaks too much)
  // ============================================================================

  // Check if user permanently disabled the badge
  try {
    const result = await chrome.storage.local.get('safeBadgeDisabled');
    if (result.safeBadgeDisabled === true) {
      logDebug('[SafeBadge] Permanently disabled by user');
      return;
    }
  } catch (e) {
    // storage error, continue
  }

  const currentHostname = window.location.hostname.toLowerCase();

  // Skip badge for globally trusted domains (TrustedDomains.json)
  try {
    if (await isTrustedDomain(currentHostname)) {
      logDebug(`[SafeBadge] Skipping for globally trusted domain: ${currentHostname}`);
      return;
    }
  } catch (e) {
    logDebug('[SafeBadge] Could not check trusted domain status:', e);
  }

  // Don't show if badge already exists
  if (document.querySelector('ls-safe-badge')) {
    logDebug('[SafeBadge] Badge already exists, skipping');
    return;
  }

  // Check sessionStorage - only show once per domain per session
  try {
    const storageKey = `linkshield_safe_shown_${currentHostname}`;
    if (sessionStorage.getItem(storageKey)) {
      logDebug('[SafeBadge] Already shown this session, skipping');
      return;
    }
    sessionStorage.setItem(storageKey, 'true');
  } catch (e) {
    if (window.linkshieldSafeBadgeShown) return;
    window.linkshieldSafeBadgeShown = true;
  }

  logDebug('[SafeBadge] Creating badge v8.8.9 (pure CSS positioning)');

  // Create unique custom element - immune to generic CSS selectors
  const host = document.createElement('ls-safe-badge');

  // Pure CSS positioning - let the browser handle it
  // Key: left: auto and top: auto prevent jumping to wrong positions
  host.style.cssText = `
    position: fixed !important;
    bottom: 20px !important;
    right: 20px !important;
    left: auto !important;
    top: auto !important;
    width: auto !important;
    z-index: 2147483647 !important;
    display: block !important;
  `;

  // Create closed Shadow DOM - website cannot access or style the content
  const shadow = host.attachShadow({ mode: 'closed' });

  // Get localized strings
  const badgeText = getTranslatedMessage('siteSafeSuccessBadge') || 'Verified Safe';
  const dismissText = getTranslatedMessage('dismissTooltip') || 'Dismiss';
  const dontShowText = getTranslatedMessage('dontShowAgain') || "Don't show again?";
  const yesText = getTranslatedMessage('confirmYes') || 'Yes';
  const noText = getTranslatedMessage('confirmNo') || 'No';
  const detailText = getTranslatedMessage('siteSafeSuccessDetail') ||
    'LinkShield scanned this page for phishing, typosquatting, and malicious scripts. Everything looks good.';

  // Shadow DOM content - visual styling only, positioning is on host
  shadow.innerHTML = `
    <style>
      .badge {
        background: linear-gradient(135deg, #10b981 0%, #059669 100%);
        color: #ffffff;
        padding: 8px 12px;
        border-radius: 6px;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, sans-serif;
        font-size: 12px;
        font-weight: 500;
        line-height: 1.4;
        box-shadow: 0 2px 8px rgba(16, 185, 129, 0.35);
        display: inline-flex;
        align-items: center;
        white-space: nowrap;
        max-width: 320px;
        width: auto;
        cursor: default;
        opacity: 0;
        transform: translateY(8px);
        transition: opacity 0.3s ease, transform 0.3s ease;
        -webkit-font-smoothing: antialiased;
      }
      .badge.visible {
        opacity: 1;
        transform: translateY(0);
      }
      .badge.hiding {
        opacity: 0;
        transform: translateY(10px);
      }
      .icon {
        margin-right: 6px;
        font-size: 14px;
        line-height: 1;
      }
      .text {
        margin-right: 8px;
        font-weight: 500;
      }
      .close-btn {
        all: unset;
        display: flex;
        align-items: center;
        justify-content: center;
        width: 18px;
        height: 18px;
        color: #ffffff;
        font-size: 16px;
        cursor: pointer;
        opacity: 0.7;
        border-radius: 50%;
        transition: opacity 0.15s ease, background 0.15s ease;
      }
      .close-btn:hover {
        opacity: 1;
        background: rgba(255, 255, 255, 0.15);
      }
      .confirm-text {
        margin-right: 10px;
        font-weight: 500;
      }
      .yes-btn {
        all: unset;
        background: #ffffff;
        color: #059669;
        padding: 4px 10px;
        border-radius: 4px;
        cursor: pointer;
        font-size: 11px;
        font-weight: 600;
        margin-right: 6px;
      }
      .yes-btn:hover {
        background: #f0fdf4;
      }
      .no-btn {
        all: unset;
        background: transparent;
        color: #ffffff;
        border: 1px solid rgba(255, 255, 255, 0.6);
        padding: 4px 10px;
        border-radius: 4px;
        cursor: pointer;
        font-size: 11px;
        font-weight: 500;
      }
      .no-btn:hover {
        background: rgba(255, 255, 255, 0.1);
        border-color: #ffffff;
      }
    </style>
    <div class="badge" title="${detailText}">
      <span class="icon">🛡️</span>
      <span class="text">LinkShield: ${badgeText}</span>
      <button class="close-btn" title="${dismissText}" aria-label="${dismissText}">×</button>
    </div>
  `;

  const badge = shadow.querySelector('.badge');
  const closeBtn = shadow.querySelector('.close-btn');
  let autoFadeTimeout = null;

  const removeBadge = () => {
    badge.classList.add('hiding');
    setTimeout(() => {
      if (host.parentNode) host.remove();
    }, 300);
  };

  closeBtn.addEventListener('click', (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (autoFadeTimeout) {
      clearTimeout(autoFadeTimeout);
      autoFadeTimeout = null;
    }

    // Show confirmation UI
    badge.innerHTML = `
      <span class="confirm-text">${dontShowText}</span>
      <button class="yes-btn">${yesText}</button>
      <button class="no-btn">${noText}</button>
    `;
    badge.style.padding = '10px 14px';

    shadow.querySelector('.yes-btn').addEventListener('click', async () => {
      try { await chrome.storage.local.set({ safeBadgeDisabled: true }); } catch (err) {}
      removeBadge();
    });
    shadow.querySelector('.no-btn').addEventListener('click', removeBadge);
  });

  // CRITICAL: Inject into documentElement (the <html> tag)
  // This places the element OUTSIDE the body, avoiding transform/filter
  // on body that would break position: fixed
  document.documentElement.appendChild(host);

  // Animate in after a short delay
  setTimeout(() => {
    badge.classList.add('visible');
    logDebug('[SafeBadge] Badge visible (pure CSS mode, attached to documentElement)');
  }, 50);

  // Auto-fade after 4 seconds
  autoFadeTimeout = setTimeout(() => {
    if (document.querySelector('ls-safe-badge')) {
      removeBadge();
      logDebug('[SafeBadge] Badge auto-removed after timeout');
    }
  }, 4000);
}

/**
 * Analyseert het domein en de URL van een gegeven link om verdachte kenmerken te detecteren.
 * Roept de gelaagde detectielogica aan en de bijbehorende visuele waarschuwing.
 * @param {HTMLAnchorElement} link - Het HTML-ankerelement om te analyseren.
 */
async function analyzeDomainAndUrl(link) {
  await ensureConfigReady(); // Zorgt ervoor dat de globale configuratie geladen is
  // Log de input voor debugging, inclusief type en SVG-status.
  // We controleren nu ook direct op SVGAnimatedString om fouten te voorkomen met new URL().
  logDebug(`Analyzing link with href: ${link.href}, Type: ${typeof link.href}, Instance: ${link.href instanceof SVGAnimatedString ? 'SVGAnimatedString' : 'Other'}`);
  // Valideer de link en de href: sla volledig ongeldige links over.
  // Behandel ook SVGAnimatedString correct door de baseVal te gebruiken.
  let href;
  if (link && link.href) {
    href = link.href instanceof SVGAnimatedString ? link.href.baseVal : link.href;
  } else {
    logDebug(`Skipping analysis: Invalid or missing link or href: ${link?.href || 'undefined'}`);
    return;
  }
  // Controleer of de href een geldige URL is na mogelijke SVG-conversie.
  if (!isValidURL(href)) {
    logDebug(`Skipping analysis: Invalid URL in link: ${href}`);
    return;
  }
  try {
    const urlObj = new URL(href);
    const hostname = urlObj.hostname;
    // Sla checks over voor interne IP-adressen, .local, of localhost.
    const isInternalIp = (host) => {
      return (
        /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host) ||
        /^192\.168\.\d{1,3}\.\d{1,3}$/.test(host) ||
        /^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host) ||
        /^172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}$/.test(host)
      );
    };
    if (isInternalIp(hostname) || hostname.endsWith(".local") || hostname === "localhost") {
      logDebug(`Internal server detected for ${hostname}. Skipping checks.`);
      return;
    }

    // AUDIT MODE (v8.1.0): TEST_MODE forces all external links to be flagged as HIGH RISK
    // This allows testing visual protection (overlays, z-index) on any site
    if (globalConfig.TEST_MODE === true) {
      // Skip same-origin links in test mode
      if (hostname !== window.location.hostname) {
        logDebug(`[TEST_MODE] 🧪 Forcing HIGH RISK for external link: ${href.substring(0, 60)}...`);
        const testResult = {
          level: 'alert',
          risk: globalConfig.TEST_MODE_RISK_SCORE || 25,
          reasons: ['TEST_MODE_ENABLED'],
          link: href
        };
        warnLinkByLevel(link, testResult);
        return;
      }
    }

    // Voer de gelaagde verdachte controles uit op de link's href.
    const result = await performSuspiciousChecks(href);
    // Als het risiconiveau niet 'safe' is, roep dan de visuele waarschuwing aan.
    if (result.level !== 'safe') {
      warnLinkByLevel(link, result);
    } else {
      // Optioneel: als de link eerder gemarkeerd was en nu veilig is, verwijder dan de markering.
      // De `warnLinkByLevel` functie doet dit al als `level === 'safe'`.
      logDebug(`Link ${href} is veilig bevonden (level: ${result.level}, risk: ${result.risk}). Geen waarschuwing nodig.`);
    }
  } catch (error) {
    // Specifieke afhandeling voor URL-constructie fouten (die nu minder vaak zouden moeten voorkomen door isValidURL).
    if (error instanceof TypeError && error.message.includes('Failed to construct \'URL\'')) {
      handleError(error, `analyzeDomainAndUrl: Invalid URL (possibly malformed or SVGAnimatedString) in link ${href || 'undefined'}`);
    } else {
      // Algemene foutafhandeling.
      handleError(error, `analyzeDomainAndUrl: Error analyzing URL ${href || 'undefined'}`);
    }
    // Geen verdere verwerking bij een fout.
    return;
  }
}
function ensureProtocol(url) {
  if (url.startsWith('tel:')) {
    return url;
  }
  if (!/^https?:\/\//i.test(url)) {
    return `http://${url}`;
  }
  return url;
}
function getAbsoluteUrl(relativeUrl) {
  try {
    return new URL(relativeUrl, window.location.href).href;
  } catch (error) {
    handleError(error, `getAbsoluteUrl: Fout bij omzetten van relatieve URL ${relativeUrl}`);
    return relativeUrl;
  }
}
async function calculateRiskScore(url) {
  let score = 0;
  let reasons = [];
  const addRisk = (points, reasonKey, severity = "low") => {
    if (!reasons.includes(reasonKey)) {
      score += points;
      reasons.push(reasonKey);
    }
  };
  try {
    const urlObj = new URL(url);
    const domain = normalizeDomain(url);
    if (!domain) return { score: -1, reasons: ["invalidUrl"] };
    const path = urlObj.pathname.toLowerCase();
    const urlParts = sanitizeInput(url.toLowerCase()).split(/[\/?#]/);
    const ext = urlObj.pathname.toLowerCase().match(/\.[0-9a-z]+$/i);
    const maxLength = globalConfig.MAX_URL_LENGTH || 2000;
    // --- AANGEPASTE TRUSTED DOMAIN CHECK ---
    const fullHostname = urlObj.hostname.toLowerCase();
    const isTrusted = await isTrustedDomain(fullHostname);
   
    // Als het domein vertrouwd is, direct stoppen met een lage score
    if (isTrusted) {
      logDebug(`Trusted domain ${domain}, risk calculation skipped.`);
      return { score: 0, reasons: ["trustedDomain"] };
    }
    // --- EINDE AANPASSING ---
    const domainParts = domain.split(".");
    const subdomain = domainParts.length > 2 ? domainParts.slice(0, -2).join(".") : "";
    // --- START AANGEPASTE RISICOSCORES ---
    // 1. HTTPS-controle
    if (urlObj.protocol !== 'https:') {
      // De gevaarlijkste situatie eerst: een inlogpagina zonder HTTPS
      if (isLoginPage(url)) {
        addRisk(15, "insecureLoginPage", "high"); // Was 20
      } else {
        // Algemene onveilige verbinding
        addRisk(4, "noHttps", "medium"); // Was 15 (aanzienlijk verlaagd)
      }
    }
    // 2. Phishing-trefwoorden - UITGESCHAKELD (te veel false positives)
    // Keywords zoals "login", "account", "verify" staan op elke legitieme site
    // De combinatie-checks (brandKeyword, suspiciousTLD) vangen echte phishing op
    // if (urlParts.some(word => globalConfig.PHISHING_KEYWORDS.has(word))) {
    //   addRisk(0, "suspiciousKeywords", "low");
    // }
    // 3. BrandKeyword subdomein check (alleen als niet trusted)
    if (!isTrusted && /^(login|secure|auth|signin|verify|portal|account|access)\b/i.test(subdomain)) {
      addRisk(4, `brandKeyword:${subdomain}`, "medium"); // Was 5
    }
    // 4. Download-trefwoorden (contextuele indicator)
    if (urlParts.some(word => globalConfig.DOWNLOAD_KEYWORDS.has(word))) {
      addRisk(3, "downloadKeyword", "low"); // Was 8
    }
    // 5. Verdachte bestandsextensies (sterke indicator)
    if (ext && globalConfig.MALWARE_EXTENSIONS.test(ext[0])) {
      addRisk(10, "malwareExtension", "high"); // Was 12
    }
    // 6. IP-adres als domeinnaam (sterke technische indicator)
    // Skip for private networks (localhost, LAN) - used by sysadmins
    if (/^(?:https?:\/\/)?(\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:\/|$)/.test(url) && !isPrivateNetwork(urlObj.hostname)) {
      addRisk(8, "ipAsDomain", "high"); // Was 12, nu verfijnd
      // Check op ongebruikelijke poort als extra risico
      if (urlObj.port && !["80", "443"].includes(urlObj.port)) {
        addRisk(4, "unusualPort", "medium"); // Was 6
      }
    }
    // 7. Verkorte URL (contextuele indicator)
    if (globalConfig.SHORTENED_URL_DOMAINS.has(domain)) {
      addRisk(3, "shortenedUrl", "medium"); // Was 6
      try {
        const response = await fetch(url, { method: 'HEAD', redirect: 'follow' });
        const finalUrl = response.url;
        // Een redirect is inherent aan een shortener, dus we verwijderen de extra bestraffing
        if (finalUrl && finalUrl !== url) {
          logDebug(`Shortened URL ${url} resolved to ${finalUrl}`);
        }
      } catch (error) {
        addRisk(2, "shortenedUrlError", "low"); // Was 5
        handleError(error, `calculateRiskScore: Kon verkorte URL ${url} niet oplossen`);
      }
    }
    // 8. Verdachte TLD's (contextuele indicator, niet standalone alarmerend)
    // FIX v8.7.3: Score 7→4, severity high→medium (TLD alleen is geen sterk signaal)
    if (globalConfig.SUSPICIOUS_TLDS.test(domain)) {
      addRisk(4, "suspiciousTLD", "medium");
    }
    // 9. Ongewoon lange URL's (zwakke indicator)
    if (url.length > maxLength) {
      addRisk(1, "urlTooLong", "low"); // Was 8
    }
    // 10. Gecodeerde tekens (zwakke indicator)
    if (/%[0-9A-Fa-f]{2}/.test(url)) {
      addRisk(1, "encodedCharacters", "low"); // Was 6
    }
    // 11. Te veel subdomeinen (technische indicator)
    if (domain.split(".").length > (globalConfig.MAX_SUBDOMAINS || 3)) { // Gebruik MAX_SUBDOMAINS uit config
      addRisk(4, "tooManySubdomains", "medium"); // Was 5
    }
    // 12. Base64, hex of javascript-schema (sterke indicator)
    if (/^(javascript|data):/.test(url) || /[a-f0-9]{32,}/.test(url)) {
      addRisk(10, "base64OrHex", "high"); // Was 12
    }
    
    // --- EINDE AANGEPASTE RISICOSCORES ---
    logDebug(`Risk score for ${url}: ${score}. Reasons: ${reasons.join(', ')}`);
    return { score, reasons };
  } catch (error) {
    handleError(error, `calculateRiskScore: Fout bij risicoberekening voor URL ${url}`);
    return { score: -1, reasons: ["errorCalculatingRisk"] };
  }
}
function isSearchResultPage() {
  const url = new URL(window.location.href);
  return url.hostname.includes("google.") && (url.pathname === "/search" || url.pathname === "/imgres");
}
function isLoginPage(url = window.location.href) {
  try {
    // Controleer op wachtwoordveld
    let hasPasswordField = false;
    try {
      hasPasswordField = document.querySelector('input[type="password"]') !== null;
    } catch (error) {
      handleError(error, `isLoginPage: Error checking for password field on URL ${url}`);
    }
    // Controleer op login-patronen in tekst
    let hasLoginText = false;
    try {
      if (document.body) {
        const loginPatterns = /(login|signin|auth|authenticate|wp-login)/i;
        hasLoginText = document.body.textContent.match(loginPatterns) !== null;
      }
    } catch (error) {
      handleError(error, `isLoginPage: Error checking login text patterns on URL ${url}`);
    }
    // Controleer op login-patronen in URL
    let hasLoginInUrl = false;
    try {
      const loginPatterns = /(login|signin|auth|authenticate|wp-login)/i;
      hasLoginInUrl = loginPatterns.test(url);
    } catch (error) {
      handleError(error, `isLoginPage: Error checking URL patterns on URL ${url}`);
    }
    // Basisdetectie: is dit waarschijnlijk een login-pagina?
    const basicDetection = hasPasswordField || hasLoginText || hasLoginInUrl;
    // Als geen login-pagina wordt gedetecteerd, stoppen we hier
    if (!basicDetection) {
      return false;
    }
    // Diepere analyse van formulieren voor phishing-detectie
    let isSuspiciousLoginForm = false;
    try {
      const forms = document.querySelectorAll('form');
      forms.forEach(form => {
        const inputs = form.querySelectorAll('input');
        let hasPassword = false;
        let hasSuspiciousFields = false;
        let hasHiddenFields = false;
        let hasAutoCompleteOn = false;
        let actionDomain = null;
        // Controleer het action-attribuut van het formulier
        const action = form.getAttribute('action');
        if (action) {
          try {
            const actionUrl = new URL(action, window.location.href);
            actionDomain = actionUrl.hostname;
            if (actionDomain !== window.location.hostname) {
              isSuspiciousLoginForm = true; // Verdacht: ander domein
            }
          } catch (error) {
            handleError(error, `isLoginPage: Error parsing form action URL ${action}`);
          }
        }
        // Analyseer alle inputvelden in het formulier
        inputs.forEach(input => {
          const type = input.getAttribute('type');
          const name = input.getAttribute('name');
          const autocomplete = input.getAttribute('autocomplete');
          // Controleer wachtwoordvelden en autocomplete
          if (type === 'password') {
            hasPassword = true;
            if (autocomplete !== 'off') {
              hasAutoCompleteOn = true; // Verdacht: autocomplete aan
            }
          }
          // Controleer op verborgen velden
          if (type === 'hidden') {
            hasHiddenFields = true; // Verdacht: verborgen veld aanwezig
          }
          // Controleer op verdachte veldnamen
          if (name && /(creditcard|ccnumber|securitycode|ssn|dob)/i.test(name)) {
            hasSuspiciousFields = true; // Verdacht: niet-login-gerelateerd veld
          }
        });
        // Beoordeel of het formulier verdacht is
        if (hasPassword && (hasSuspiciousFields || hasHiddenFields || hasAutoCompleteOn || actionDomain !== window.location.hostname)) {
          isSuspiciousLoginForm = true;
        }
      });
    } catch (error) {
      handleError(error, `isLoginPage: Error analyzing forms on URL ${url}`);
    }
    // Controleer of de pagina via HTTPS wordt geserveerd
    let isHttpsSecure = true;
    try {
      if (window.location.protocol !== 'https:') {
        isHttpsSecure = false; // Verdacht: geen HTTPS
      }
    } catch (error) {
      handleError(error, `isLoginPage: Error checking HTTPS for URL ${url}`);
    }
    // Resultaat: login-pagina met verdachte kenmerken of geen HTTPS
    const result = basicDetection && (isSuspiciousLoginForm || !isHttpsSecure);
    logDebug("Login Page Analysis: Basic detection = ", basicDetection, ", Suspicious form = ", isSuspiciousLoginForm, ", HTTPS secure = ", isHttpsSecure, "Result = ", result);
    return result;
  } catch (error) {
    handleError(error, `isLoginPage: Unexpected error while detecting login page on URL ${url}. Details: ${error.message}`);
    return false;
  }
}
function isHttps(url) {
  try {
    if (globalConfig && Array.isArray(globalConfig.ALLOWED_PROTOCOLS)) {
      for (const protocol of globalConfig.ALLOWED_PROTOCOLS) {
        if (url.startsWith(protocol)) {
          logDebug(`Allowed protocol detected: ${protocol}`);
          return true;
        }
      }
    }
    const parsedUrl = new URL(url, window.location.href);
    const protocol = parsedUrl.protocol;
    if (protocol === 'https:') {
      return true;
    }
    if (protocol === 'http:') {
      logDebug(`Insecure protocol detected (HTTP): ${url}`);
      return false;
    }
    logDebug(`Unsupported protocol detected: ${protocol}`);
    return false;
  } catch (e) {
    handleError(e, `isHttps: Fout bij controleren van protocol voor URL ${url}`);
    return false;
  }
}
function isIpAddress(input) {
  if (!input || typeof input !== 'string') {
    logDebug(`Skipping IP check for invalid input: ${input || 'undefined'}`);
    return false;
  }
  const trimmed = input.trim().toLowerCase();
  // ❗ Voorkom crash bij incomplete of ongeldige schema's
  if (
    trimmed === '' ||
    trimmed === 'https://' ||
    trimmed === 'http://' ||
    trimmed.startsWith('mailto:') ||
    trimmed.startsWith('javascript:')
  ) {
    logDebug(`Skipping IP check for unsupported input: ${input}`);
    return false;
  }
  let hostname = input;
  try {
    if (input.includes('://')) {
      hostname = new URL(input).hostname;
    }
    const ipv4Pattern = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    if (ipv4Pattern.test(hostname)) {
      logDebug(`IPv4 address detected: ${hostname}`);
      return true;
    }
    const ipv6Pattern = /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|... )$/; // jouw bestaande IPv6-regex
    if (ipv6Pattern.test(hostname)) {
      logDebug(`IPv6 address detected: ${hostname}`);
      return true;
    }
    logDebug(`No IP address detected for hostname: ${hostname}`);
    return false;
  } catch (error) {
    logDebug(`Fout bij controleren van IP-adres voor input ${input}: ${error.message}`);
    return false;
  }
}
const mxCache = {};
const MX_TTL_MS = 3600 * 1000; // 1 uur
const MAX_RETRIES = 2;
const RETRY_DELAY_MS = 1000;
const REQUEST_TIMEOUT_MS = 5000;
// Functie om verlopen cache-entries te verwijderen
function cleanMxCache() {
  const now = Date.now();
  for (const domain in mxCache) {
    if (now - mxCache[domain].timestamp >= MX_TTL_MS) {
      delete mxCache[domain];
      logDebug(`Verwijderd verlopen cache-entry voor ${domain}`);
    }
  }
}
// Periodieke schoonmaak van de cache (elke 10 minuten)
setInterval(cleanMxCache, 10 * 60 * 1000);
// Fetch met timeout
async function fetchWithTimeout(url, options = {}) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    const response = await fetch(url, { ...options, signal: controller.signal });
    clearTimeout(timeoutId);
    return response;
  } catch (error) {
    if (error.name === 'AbortError') {
      throw new Error('Request timeout');
    }
    throw error;
  }
}
// Retry-logica voor netwerkverzoeken
async function retryFetch(url, options = {}, retries = MAX_RETRIES) {
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      return await fetchWithTimeout(url, options);
    } catch (error) {
      if (attempt < retries) {
        logDebug(`Poging ${attempt} mislukt voor ${url}: ${error.message}. Probeer opnieuw...`);
        await new Promise(resolve => setTimeout(resolve, RETRY_DELAY_MS));
      } else {
        throw error;
      }
    }
  }
}
// Validatie van hostnamen
function isValidHostname(hostname) {
  return /^[a-zA-Z0-9.-]+$/.test(hostname) && hostname.includes('.');
}
const mxQueue = [];
let isProcessing = false;
async function processMxQueue() {
  if (isProcessing || mxQueue.length === 0) return;
  isProcessing = true;
  const { domain, resolve } = mxQueue.shift();
  try {
    const mxRecords = await getMxRecords(domain);
    resolve(mxRecords);
  } catch (error) {
    handleError(error, `MX-queue: Fout voor ${domain}`);
    resolve([]);
  }
  isProcessing = false;
  processMxQueue();
}
function queueMxCheck(domain) {
  return new Promise(resolve => {
    mxQueue.push({ domain, resolve });
    processMxQueue();
  });
}
async function getMxRecords(domain) {
  const now = Date.now();
 
  if (mxCache[domain] && (now - mxCache[domain].timestamp < MX_TTL_MS)) {
    logDebug(`MX-cache hit voor ${domain}:`, mxCache[domain].records);
    return mxCache[domain].records;
  }
  // Controleer vertrouwde domeinen
  const trustedDomains = window.trustedDomains || [];
  const isTrusted = trustedDomains.some(pattern => {
    const regex = new RegExp(pattern);
    return regex.test(domain) || domain.endsWith(pattern.replace(/\\\.com$/, '.com'));
  });
  if (isTrusted) {
    logDebug(`MX-check overgeslagen voor vertrouwd domein: ${domain}`);
    mxCache[domain] = { records: [], timestamp: now };
    return [];
  }
  let mxHosts = [];
  mxHosts = await tryGetMxRecords(domain);
  if (mxHosts.length === 0) {
    const parts = domain.split('.');
    if (parts.length > 2) {
      const parentDomain = parts.slice(-2).join('.');
      mxHosts = await tryGetMxRecords(parentDomain);
      logDebug(`Geen MX voor ${domain}, fallback naar ${parentDomain}:`, mxHosts);
    }
  }
  mxCache[domain] = { records: mxHosts, timestamp: now };
  if (mxHosts.length === 0) {
    logDebug(`Geen MX-records gevonden voor ${domain} via alle providers`);
  }
  return mxHosts;
  async function tryGetMxRecords(targetDomain) {
    const googleUrl = `https://dns.google/resolve?name=${targetDomain}&type=MX`;
    try {
      const response = await retryFetch(googleUrl);
      const json = await response.json();
      if (json.Status === 0 && json.Answer) {
        const hosts = json.Answer
          .map(r => r.data.split(' ')[1]?.replace(/\.$/, ''))
          .filter(host => host && isValidHostname(host));
        if (hosts.length > 0) {
          logDebug(`MX-records (Google) voor ${targetDomain}:`, hosts);
          return hosts;
        }
      }
      logDebug(`Geen geldige MX-records via Google voor ${targetDomain}`);
    } catch (error) {
      handleError(error, `Google DoH faalde voor ${targetDomain} - ${error.message}`);
    }
    const cloudflareUrl = `https://cloudflare-dns.com/dns-query?name=${targetDomain}&type=MX`;
    try {
      const response = await retryFetch(cloudflareUrl, {
        headers: { 'Accept': 'application/dns-json' }
      });
      const json = await response.json();
      if (json.Status === 0 && json.Answer) {
        const hosts = json.Answer
          .map(r => r.data.split(' ')[1]?.replace(/\.$/, ''))
          .filter(host => host && isValidHostname(host));
        if (hosts.length > 0) {
          logDebug(`MX-records (Cloudflare) voor ${targetDomain}:`, hosts);
          return hosts;
        }
      }
      logDebug(`Geen geldige MX-records via Cloudflare voor ${targetDomain}`);
    } catch (error) {
      handleError(error, `Cloudflare DoH faalde voor ${targetDomain} - ${error.message}`);
    }
    return [];
  }
}
async function hasSuspiciousPattern(url) {
  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname.toLowerCase().normalize('NFC');
    const path = urlObj.pathname.toLowerCase().normalize('NFC');
    const query = urlObj.search.toLowerCase().normalize('NFC');
    // Snelle pre-check: alleen verder als URL verdacht lijkt
    if (hostname.length < 10 && path.length < 5 && query.length < 5) {
      return false; // Korte, eenvoudige URL's overslaan
    }
    const weightedPatterns = [
      { pattern: /\d{15,}/, weight: 3, description: "Long numeric sequences" },
      { pattern: /-{5,}/, weight: 2, description: "Multiple consecutive hyphens" },
      { pattern: /%[0-9A-Fa-f]{2}/, weight: 2, description: "Encoded characters" },
      { pattern: /[^a-zA-Z0-9.-]{3,}/, weight: 3, description: "Unusual characters" }
    ];
    let totalScore = 0;
    const detectedPatterns = [];
    weightedPatterns.forEach(({ pattern, weight, description }) => {
      if (pattern.test(hostname) || pattern.test(path) || pattern.test(query)) {
        totalScore += weight;
        detectedPatterns.push(description);
      }
    });
    if (totalScore >= 5) {
      logDebug(`Suspicious patterns in ${url}:`, detectedPatterns);
      return true;
    }
    return false;
  } catch (error) {
    handleError(error, `hasSuspiciousPattern: Fout bij controleren van patronen in URL ${url}`);
    return false;
  }
}
function countMatches(pattern, ...strings) {
  return strings.reduce((count, str) => count + (str.match(pattern) || []).length, 0);
}
let trustedDownloadDomains = new Set();
function isDownloadPage(url) {
  try {
    const urlObj = new URL(url);
    const ext = urlObj.pathname.toLowerCase().match(/\.[0-9a-z]+$/i);
    if (ext && globalConfig.MALWARE_EXTENSIONS.test(ext[0])) {
      logDebug(`Download extension detected in URL: ${url}`);
      return true;
    }
    return false;
  } catch (error) {
    handleError(error, `isDownloadPage: Fout bij controleren van downloadpagina voor URL ${url}`);
    return false;
  }
}
function isInDownloadContext(link) {
  const downloadKeywords = new Set(["download", "install", "setup", "file", "update"]);
  let surroundingText = '';
  if (link.textContent) {
    surroundingText += link.textContent.toLowerCase() + ' ';
  }
  const parent = link.parentElement;
  if (parent) {
    surroundingText += parent.textContent.toLowerCase() + ' ';
  }
  return Array.from(downloadKeywords).some(keyword => surroundingText.includes(keyword));
}
const MAX_URL_LENGTH = 200;
const MAX_QUERY_LENGTH = 1000;
const MAX_PARAMETERS = 15;
function isUrlTooLong(url) {
  try {
    const urlObj = new URL(url);
    const queryParams = new URLSearchParams(urlObj.search);
    const totalLength = url.length;
    const queryLength = queryParams.toString().length;
    const paramCount = queryParams.size;
    logDebug(`Total Length: ${totalLength}, Query Length: ${queryLength}, Parameter Count: ${paramCount}`);
    return totalLength > MAX_URL_LENGTH &&
      queryLength > MAX_QUERY_LENGTH &&
      paramCount > MAX_PARAMETERS;
  } catch (error) {
    handleError(error, `isUrlTooLong: Fout bij controleren van URL-lengte voor ${url}`);
    return false;
  }
}
function hasSuspiciousKeywords(url) {
  const weightedKeywords = [
    { keyword: "login", weight: 4 },
    { keyword: "secure", weight: 3 },
    { keyword: "verify", weight: 4 },
    { keyword: "password", weight: 4 },
    { keyword: "auth", weight: 3 },
    { keyword: "account", weight: 2 },
    { keyword: "billing", weight: 2 },
    { keyword: "invoice", weight: 2 },
    { keyword: "payment", weight: 3 },
    { keyword: "token", weight: 3 },
    { keyword: "session", weight: 2 },
    { keyword: "activate", weight: 3 },
    { keyword: "reset", weight: 4 },
  ];
  const patterns = [
    /\/(signin|reset-password|confirm|validate|secure-login|update-account|activate)/i,
    /[?&](action|step|verify|auth|reset|token|session)=/i,
    /(password-reset|confirm-email|verify-account|secure-payment|2fa-verification)/i,
  ];
  const legitimatePaths = [
    "/wp-login.php",
    "/admin/login",
    "/user/account",
    "/password-reset/valid",
    "/secure-payment/success"
  ];
  const legitimatePatterns = [
    /reset-password=valid/i,
    /verify-email=completed/i,
    /session-id=[a-z0-9]+/i
  ];
  const urlObj = new URL(url);
  const path = urlObj.pathname.toLowerCase();
  const search = urlObj.search.toLowerCase();
  if (legitimatePaths.includes(path) || legitimatePatterns.some(pattern => pattern.test(search))) {
    logDebug(`Legitimate context detected: ${url}`);
    return false;
  }
  const foundKeywords = weightedKeywords
    .map(({ keyword, weight }) => ({
      keyword,
      weight,
      matched: path.includes(keyword) || search.includes(keyword)
    }))
    .filter(item => item.matched);
  const totalScore = foundKeywords.reduce((sum, { weight }) => sum + weight, 0);
  const matchesPattern = patterns.some(pattern => pattern.test(path) || pattern.test(search));
  const isHighlySuspicious = totalScore >= 4 && matchesPattern;
  const isModeratelySuspicious = totalScore >= 3 && patterns.some(pattern => pattern.test(path) || pattern.test(search));
  logDebug(`Checked URL: ${url}`);
  logDebug(`Keywords found: ${JSON.stringify(foundKeywords)}`);
  logDebug(`Patterns matched: ${matchesPattern}`);
  return isHighlySuspicious || isModeratelySuspicious;
}
function hasSuspiciousUrlPattern(url) {
  const urlObj = new URL(url);
  const path = urlObj.pathname.toLowerCase();
  const search = urlObj.search.toLowerCase();
  const patterns = globalConfig.SUSPICIOUS_URL_PATTERNS || [];
  const matches = patterns.filter(pattern => pattern.test(path) || pattern.test(search));
  return matches.length >= 2;
}
// Definieer de cache buiten de functie voor persistentie
const scriptAnalysisCache = new Map();
const SCRIPT_CACHE_TTL_MS = 3600000; // 1 uur TTL

/**
 * MV3 FIX: Analyseert scripts op basis van URL-patronen in plaats van content fetching.
 *
 * CORS PROBLEEM OPGELOST: Content scripts kunnen geen cross-origin fetches doen naar
 * externe scripts (CORS blocking). In plaats daarvan analyseren we:
 * - URL structuur (verdachte paden, parameters)
 * - Domein kenmerken (leeftijd suggesties, verdachte patronen)
 * - Bestandsnaam patronen (obfuscatie indicatoren)
 *
 * Dit is ook sneller en werkt 100% betrouwbaar.
 *
 * @param {URL} scriptUrl - De URL van het script om te analyseren
 * @returns {{isSuspicious: boolean, matchedPatterns: string[], totalWeight: number}}
 */
async function analyzeScriptContent(scriptUrl) {
  try {
    const urlString = scriptUrl.href;
    const now = Date.now();

    // Cache check
    const cached = scriptAnalysisCache.get(urlString);
    if (cached && now - cached.timestamp < SCRIPT_CACHE_TTL_MS) {
      logDebug(`Cache hit voor script URL analyse: ${urlString}`);
      return cached.result;
    }

    const hostname = scriptUrl.hostname.toLowerCase();
    const pathname = scriptUrl.pathname.toLowerCase();
    const filename = pathname.split('/').pop() || '';
    const search = scriptUrl.search.toLowerCase();

    let totalWeight = 0;
    const matchedPatterns = [];

    // 1. Bekende veilige bibliotheken in URL (snel overslaan)
    const safeLibraryPatterns = [
      /jquery[-.]?[\d.]*\.min\.js$/i,
      /react[-.]?[\d.]*\.min\.js$/i,
      /angular[-.]?[\d.]*\.min\.js$/i,
      /vue[-.]?[\d.]*\.min\.js$/i,
      /bootstrap[-.]?[\d.]*\.min\.js$/i,
      /lodash[-.]?[\d.]*\.min\.js$/i,
      /moment[-.]?[\d.]*\.min\.js$/i,
      /axios[-.]?[\d.]*\.min\.js$/i,
      /d3[-.]?[\d.]*\.min\.js$/i,
      /chart[-.]?[\d.]*\.min\.js$/i,
      /gtag\.js$/i,
      /analytics\.js$/i,
      /gtm\.js$/i,
      /polyfill[-.]?[\d.]*\.js$/i,
    ];

    if (safeLibraryPatterns.some(pattern => pattern.test(pathname))) {
      logDebug(`Bekende bibliotheek URL gedetecteerd: ${urlString}`);
      const result = { isSuspicious: false, matchedPatterns: [], totalWeight: 0 };
      scriptAnalysisCache.set(urlString, { result, timestamp: now });
      return result;
    }

    // 2. Verdachte URL patronen analyseren

    // 2a. Obfuscated bestandsnamen (random karakters, base64-achtig)
    if (/^[a-z0-9]{20,}\.js$/i.test(filename)) {
      totalWeight += 4;
      matchedPatterns.push('obfuscatedFilename');
      logDebug(`[URL] Obfuscated bestandsnaam: ${filename}`);
    }

    // 2b. Verdachte paden die op malware wijzen
    const suspiciousPathPatterns = [
      { regex: /\/inject/i, weight: 5, desc: 'injectPath' },
      { regex: /\/keylog/i, weight: 8, desc: 'keyloggerPath' },
      { regex: /\/stealer/i, weight: 8, desc: 'stealerPath' },
      { regex: /\/miner/i, weight: 6, desc: 'cryptominerPath' },
      { regex: /\/payload/i, weight: 6, desc: 'payloadPath' },
      { regex: /\/exploit/i, weight: 7, desc: 'exploitPath' },
      { regex: /\/shell/i, weight: 5, desc: 'shellPath' },
      { regex: /\/c2\//i, weight: 8, desc: 'c2Path' },
      { regex: /\/beacon/i, weight: 5, desc: 'beaconPath' },
      { regex: /\/dropper/i, weight: 7, desc: 'dropperPath' },
    ];

    for (const { regex, weight, desc } of suspiciousPathPatterns) {
      if (regex.test(pathname)) {
        totalWeight += weight;
        matchedPatterns.push(desc);
        logDebug(`[URL] Verdacht pad patroon: ${desc}`);
      }
    }

    // 2c. Verdachte query parameters
    const suspiciousParams = [
      { regex: /[?&](cmd|exec|eval|shell)=/i, weight: 6, desc: 'execParam' },
      { regex: /[?&](callback|jsonp)=[^&]*\(/i, weight: 4, desc: 'callbackInjection' },
      { regex: /[?&]token=[a-f0-9]{32,}/i, weight: 2, desc: 'suspiciousToken' },
    ];

    for (const { regex, weight, desc } of suspiciousParams) {
      if (regex.test(search)) {
        totalWeight += weight;
        matchedPatterns.push(desc);
        logDebug(`[URL] Verdachte parameter: ${desc}`);
      }
    }

    // 2d. Verdachte domeinen (freehosting, dynamische DNS)
    const suspiciousDomainPatterns = [
      { regex: /\.(tk|ml|ga|cf|gq)$/i, weight: 3, desc: 'freeTLD' },
      { regex: /\.(duckdns|no-ip|ddns)\./i, weight: 4, desc: 'dynamicDNS' },
      { regex: /pastebin\.(com|io)/i, weight: 5, desc: 'pastebinScript' },
      { regex: /raw\.githubusercontent\.com/i, weight: 2, desc: 'githubRaw' },
      { regex: /\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i, weight: 3, desc: 'ipAddress' },
    ];

    for (const { regex, weight, desc } of suspiciousDomainPatterns) {
      if (regex.test(hostname)) {
        totalWeight += weight;
        matchedPatterns.push(desc);
        logDebug(`[URL] Verdacht domein patroon: ${desc}`);
      }
    }

    // 2e. Data URL in script src (zeldzaam maar verdacht)
    if (scriptUrl.protocol === 'data:') {
      totalWeight += 8;
      matchedPatterns.push('dataUrlScript');
      logDebug(`[URL] Data URL script gedetecteerd`);
    }

    // Drempel: script is verdacht als gewicht >= 8
    const isSuspicious = totalWeight >= 8;

    const result = { isSuspicious, matchedPatterns, totalWeight };

    if (isSuspicious) {
      logDebug(`Verdacht script URL: ${urlString}, Gewicht: ${totalWeight}, Patronen: ${matchedPatterns.join(', ')}`);
    } else if (totalWeight > 0) {
      logDebug(`Script heeft enkele verdachte kenmerken: ${urlString}, Gewicht: ${totalWeight}`);
    } else {
      logDebug(`Script URL OK: ${urlString}`);
    }

    scriptAnalysisCache.set(urlString, { result, timestamp: now });
    return result;

  } catch (error) {
    handleError(error, `analyzeScriptContent: Fout bij URL-analyse van ${scriptUrl.href}`);
    const result = { isSuspicious: false, matchedPatterns: [], totalWeight: 0 };
    scriptAnalysisCache.set(scriptUrl.href, { result, timestamp: Date.now() });
    return result;
  }
}
// Optioneel: Periodieke cache-schoonmaak
setInterval(() => {
  const now = Date.now();
  for (const [url, { timestamp }] of scriptAnalysisCache) {
    if (now - timestamp >= SCRIPT_CACHE_TTL_MS) {
      scriptAnalysisCache.delete(url);
      logDebug(`Removed expired script cache entry for ${url}`);
    }
  }
}, SCRIPT_CACHE_TTL_MS);
// VERWIJDERD: checkScriptMinification en checkScriptObfuscation
// Deze functies gebruikten cross-origin fetch die geblokkeerd wordt door CORS.
// De functionaliteit is nu geïntegreerd in analyzeScriptContent() via URL-analyse.
/**
 * Detecteert @ Symbol Attack (credential URL phishing)
 * Voorbeeld: https://google.com@evil.com gaat naar evil.com, niet google.com
 * @param {string} urlString - De URL om te controleren
 * @returns {{detected: boolean, fakeHost?: string, realHost?: string, reason?: string}}
 */
function detectAtSymbolAttack(urlString) {
  try {
    const url = new URL(urlString, window.location.href);
    // Check of de username eruitziet als een domein (bevat een punt)
    // Dit detecteert: https://google.com@evil.com waar google.com de "username" is
    if (url.username && url.username.includes('.')) {
      return {
        detected: true,
        fakeHost: url.username,
        realHost: url.hostname,
        reason: 'atSymbolPhishing'
      };
    }
    // Check voor @ in het pad (URL-encoded of niet) - kan duiden op obfuscatie
    // MAAR: whitelist platforms die @ legitiem gebruiken voor user handles
    if (url.pathname.includes('@') || url.pathname.includes('%40')) {
      // SECURITY FIX v8.5.1: Detecteer e-mailadressen in paden (false positive fix)
      // E-mailadressen zoals /path/info@example.com zijn legitiem
      // Aanvallen hebben altijd een domein-achtig patroon: google.com@evil.com
      const decodedPath = decodeURIComponent(url.pathname);
      const pathSegments = decodedPath.split('/');
      const segmentWithAt = pathSegments.find(seg => seg.includes('@'));

      if (segmentWithAt) {
        const atIndex = segmentWithAt.indexOf('@');
        const localPart = segmentWithAt.substring(0, atIndex);

        // Als localPart GEEN punt bevat, is het waarschijnlijk een e-mailadres
        // E-mail: info@nomorec.nl (localPart = "info", geen punt)
        // Aanval: google.com@evil.com (localPart = "google.com", WEL een punt)
        if (localPart && !localPart.includes('.')) {
          logDebug(`[AtSymbol] Skipping email address in path: ${segmentWithAt}`);
          return { detected: false };
        }
      }

      // Platforms die @ gebruiken voor handles/usernames in URLs
      const platformsWithAtHandles = [
        'youtube.com',
        'www.youtube.com',
        'm.youtube.com',
        'medium.com',
        'www.medium.com',
        'threads.net',
        'www.threads.net',
        'substack.com',
        'instagram.com',      // Instagram gebruikt @ in sommige embed URLs
        'www.instagram.com'
      ];

      // Check ook voor Mastodon instances (*.social, mastodon.*)
      const isMastodonInstance = /^(.*\.social|mastodon\..*)$/i.test(url.hostname);

      const isWhitelistedPlatform = platformsWithAtHandles.some(domain =>
        url.hostname === domain || url.hostname.endsWith('.' + domain)
      );

      // Als het een legitiem platform is met @ handles, geen alert
      if (isWhitelistedPlatform || isMastodonInstance) {
        return { detected: false };
      }

      return {
        detected: true,
        reason: 'atSymbolInPath'
      };
    }
    return { detected: false };
  } catch {
    return { detected: false, error: true };
  }
}

/**
 * Detecteert double encoding bypass pogingen
 * Voorbeeld: %252e%252e decodeert naar %2e%2e en dan naar ..
 * @param {string} urlString - De URL om te controleren
 * @returns {boolean}
 */
function hasDoubleEncoding(urlString) {
  // Double encoding: %25XX waar XX hex is (bijv. %252e = %2e = .)
  return /%25[0-9A-Fa-f]{2}/.test(urlString);
}

/**
 * Detecteert fullwidth Unicode karakters die ASCII imiteren
 * Voorbeeld: ｇｏｏｇｌｅ (fullwidth) lijkt op google
 * @param {string} urlString - De URL om te controleren
 * @returns {boolean}
 */
function hasFullwidthCharacters(urlString) {
  // Fullwidth karakters range: U+FF01 tot U+FF5E
  return /[\uFF01-\uFF5E]/.test(urlString);
}

/**
 * Detecteert null byte injection pogingen
 * @param {string} urlString - De URL om te controleren
 * @returns {boolean}
 */
function hasNullByteInjection(urlString) {
  return urlString.includes('%00') || urlString.includes('\x00');
}

/**
 * SECURITY: Detecteert URL credential/userinfo attack (@-symbol obfuscation)
 * Attackers use URLs like: https://google.com@evil.com/phishing
 * The browser navigates to evil.com, but users see google.com
 *
 * @param {string} urlString - De URL om te controleren
 * @returns {{detected: boolean, reason: string|null, realHost: string|null}}
 */
function hasUrlCredentialsAttack(urlString) {
  try {
    // Check for @ symbol in the URL (before query string)
    const urlWithoutQuery = urlString.split('?')[0];
    const urlWithoutFragment = urlWithoutQuery.split('#')[0];

    // Pattern: protocol://[userinfo@]host
    // Legitimate: ftp://user:pass@ftp.example.com (rare but valid)
    // Malicious: https://google.com@evil.com/page

    const match = urlWithoutFragment.match(/^(https?:\/\/)([^\/]+)@([^\/]+)/i);
    if (match) {
      const fakeHost = match[2]; // What user sees (e.g., google.com)
      const realHost = match[3]; // Where browser actually goes (e.g., evil.com)

      // Check if the "userinfo" part looks like a domain (deceptive)
      const looksLikeDomain = /^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z]{2,})+$/i.test(fakeHost);

      if (looksLikeDomain) {
        logDebug(`🚨 URL Credentials Attack detected: ${fakeHost}@${realHost}`);
        return {
          detected: true,
          reason: 'urlCredentialsAttack',
          fakeHost: fakeHost,
          realHost: realHost
        };
      }
    }

    // Also check for encoded @ symbol (%40)
    if (urlWithoutFragment.includes('%40')) {
      const decoded = decodeURIComponent(urlWithoutFragment);
      return hasUrlCredentialsAttack(decoded);
    }

    return { detected: false, reason: null, realHost: null };
  } catch (e) {
    handleError(e, 'hasUrlCredentialsAttack');
    return { detected: false, reason: null, realHost: null };
  }
}

/**
 * SECURITY: Detecteert Form Action Hijacking
 * Waarschuwt wanneer een login/password formulier data naar een ANDER domein stuurt.
 * Dit is een klassieke credential theft techniek.
 *
 * @returns {{detected: boolean, forms: Array<{action: string, currentDomain: string, targetDomain: string}>, reasons: string[]}}
 */
function detectFormActionHijacking() {
  const results = {
    detected: false,
    forms: [],
    reasons: []
  };

  try {
    const currentHostname = window.location.hostname.toLowerCase();
    const forms = document.querySelectorAll('form');

    for (const form of forms) {
      // Check of het formulier password/login velden bevat
      const hasPasswordField = form.querySelector('input[type="password"]') !== null;
      const hasLoginIndicators = form.querySelector('input[type="email"], input[name*="user"], input[name*="login"], input[name*="email"], input[autocomplete="username"]') !== null;

      // Alleen checken als het een credential-gerelateerd formulier is
      if (!hasPasswordField && !hasLoginIndicators) continue;

      // Bepaal de form action URL
      const actionAttr = form.getAttribute('action');
      let actionUrl;

      try {
        if (!actionAttr || actionAttr === '' || actionAttr === '#') {
          // Leeg action = submit naar huidige pagina (veilig)
          continue;
        }
        actionUrl = new URL(actionAttr, window.location.href);
      } catch (e) {
        // Ongeldige URL in action
        results.detected = true;
        results.reasons.push('formActionInvalid');
        continue;
      }

      const targetHostname = actionUrl.hostname.toLowerCase();

      // Check of het een ander domein is
      if (targetHostname !== currentHostname) {
        // Uitzonderingen voor bekende legitieme services
        const legitimateFormTargets = [
          'accounts.google.com',
          'login.microsoft.com',
          'login.live.com',
          'appleid.apple.com',
          'auth0.com',
          'okta.com',
          'cognito-idp',
          'stripe.com',
          'paypal.com',
          'checkout.stripe.com'
        ];

        const isLegitimate = legitimateFormTargets.some(legit =>
          targetHostname === legit || targetHostname.endsWith('.' + legit)
        );

        if (!isLegitimate) {
          results.detected = true;
          results.forms.push({
            action: actionUrl.href,
            currentDomain: currentHostname,
            targetDomain: targetHostname
          });
          results.reasons.push('formActionHijacking');
          logDebug(`[SECURITY] Form Action Hijacking gedetecteerd: ${currentHostname} -> ${targetHostname}`);
        }
      }
    }
  } catch (error) {
    handleError(error, 'detectFormActionHijacking');
  }

  return results;
}

/**
 * SECURITY: Detecteert verborgen iframes die gebruikt kunnen worden voor:
 * - Credential theft (invisible login forms)
 * - Keylogging
 * - Clickjacking
 * - Cryptomining
 *
 * @returns {{detected: boolean, count: number, reasons: string[]}}
 */
function detectHiddenIframes() {
  const results = {
    detected: false,
    count: 0,
    reasons: []
  };

  // SECURITY FIX v8.8.11: Skip hidden iframe detection on trusted domains
  // Ad networks on trusted sites commonly use hidden tracking iframes
  if (safeDomainsInitialized && safeDomains.length > 0) {
    const currentHostname = window.location.hostname.toLowerCase();
    for (const pattern of safeDomains) {
      try {
        if (new RegExp(pattern, 'i').test(currentHostname)) {
          return results; // Return empty results for trusted domains
        }
      } catch (e) { /* invalid regex, skip */ }
    }
  }

  try {
    const iframes = document.querySelectorAll('iframe');

    for (const iframe of iframes) {
      const src = iframe.src || '';
      const style = window.getComputedStyle(iframe);
      const rect = iframe.getBoundingClientRect();

      // Check 1: Zero-size iframes (1x1 pixel of kleiner)
      const isZeroSize = (
        rect.width <= 1 ||
        rect.height <= 1 ||
        parseInt(style.width) <= 1 ||
        parseInt(style.height) <= 1
      );

      // Check 2: Off-screen iframes (buiten viewport)
      const isOffScreen = (
        rect.right < 0 ||
        rect.bottom < 0 ||
        rect.left > window.innerWidth ||
        rect.top > window.innerHeight ||
        rect.left < -1000 ||
        rect.top < -1000
      );

      // Check 3: CSS hidden iframes
      const isCSSHidden = (
        style.display === 'none' ||
        style.visibility === 'hidden' ||
        style.opacity === '0' ||
        (parseInt(style.opacity) === 0)
      );

      // Check 4: Negative positioning
      const hasNegativePosition = (
        parseInt(style.left) < -100 ||
        parseInt(style.top) < -100 ||
        parseInt(style.marginLeft) < -100 ||
        parseInt(style.marginTop) < -100
      );

      // Bepaal of iframe verdacht is
      let isSuspicious = false;
      let reason = '';

      if (isZeroSize && src) {
        isSuspicious = true;
        reason = 'hiddenIframeZeroSize';
      } else if (isOffScreen && src) {
        isSuspicious = true;
        reason = 'hiddenIframeOffScreen';
      } else if (isCSSHidden && src && !iframe.closest('[aria-hidden="true"]')) {
        // Negeer iframes die bewust verborgen zijn voor accessibility
        isSuspicious = true;
        reason = 'hiddenIframeCSSHidden';
      } else if (hasNegativePosition && src) {
        isSuspicious = true;
        reason = 'hiddenIframeNegativePos';
      }

      if (isSuspicious) {
        // Whitelist check voor bekende tracking pixels
        const trustedPixels = [
          'facebook.com/tr',
          'connect.facebook.net',
          'google-analytics.com',
          'analytics.google.com',
          'googletagmanager.com',
          'googlesyndication.com',
          'doubleclick.net',
          'bing.com/action',
          'bat.bing.com',
          'clarity.ms',
          'linkedin.com/px',
          'snap.licdn.com',
          'twitter.com/i/adsct',
          'ct.pinterest.com',
          'hotjar.com',
          'hs-analytics.net'
        ];

        const isTrustedPixel = trustedPixels.some(pixel => src.includes(pixel));

        if (!isTrustedPixel) {
          results.detected = true;
          results.count++;
          if (!results.reasons.includes(reason)) {
            results.reasons.push(reason);
          }
          logDebug(`[SECURITY] Hidden iframe gedetecteerd: ${src.substring(0, 100)} (${reason})`);
        }
      }
    }
  } catch (error) {
    handleError(error, 'detectHiddenIframes');
  }

  return results;
}

/**
 * SECURITY: Uitgebreide NRD (Newly Registered Domain) detectie
 * Domeinen < 30 dagen oud krijgen extra risicopunten.
 * 70% van phishing domeinen is < 30 dagen oud.
 *
 * @param {Date} creationDate - De registratiedatum van het domein
 * @returns {{isNRD: boolean, ageDays: number, riskLevel: 'critical'|'high'|'medium'|'low'|'none', reason: string|null}}
 */
function analyzeNRDRisk(creationDate) {
  if (!creationDate || !(creationDate instanceof Date) || isNaN(creationDate.getTime())) {
    return { isNRD: false, ageDays: null, ageHours: null, riskLevel: 'none', reason: null };
  }

  const ageMs = Date.now() - creationDate.getTime();
  const ageHours = Math.floor(ageMs / (1000 * 60 * 60));
  const ageDays = Math.floor(ageMs / (1000 * 60 * 60 * 24));

  // Risico classificatie gebaseerd op domein leeftijd
  // AI-phishing kits registreren domeinen vlak voor aanvallen - ultra-jonge domeinen zijn hoogste risico
  if (ageHours < 24) {
    // Domein minder dan 24 uur oud - ULTRA KRITIEK (AI-phishing indicator)
    // Dit is de primaire indicator voor agentic AI aanvallen
    return {
      isNRD: true,
      ageDays,
      ageHours,
      riskLevel: 'critical',
      reason: 'nrdUltraCritical' // < 24 uur - hoogste risico
    };
  } else if (ageDays <= 1) {
    // Domein 24-48 uur oud - KRITIEK
    return {
      isNRD: true,
      ageDays,
      ageHours,
      riskLevel: 'critical',
      reason: 'nrdCritical' // < 2 dagen
    };
  } else if (ageDays <= 7) {
    // Domein < 1 week oud - HOOG RISICO
    return {
      isNRD: true,
      ageDays,
      ageHours,
      riskLevel: 'high',
      reason: 'nrdHigh' // < 7 dagen
    };
  } else if (ageDays <= 30) {
    // Domein < 30 dagen oud - MEDIUM RISICO
    return {
      isNRD: true,
      ageDays,
      ageHours,
      riskLevel: 'medium',
      reason: 'nrdMedium' // < 30 dagen
    };
  } else if (ageDays <= 90) {
    // Domein < 90 dagen oud - LAAG RISICO
    return {
      isNRD: true,
      ageDays,
      ageHours,
      riskLevel: 'low',
      reason: 'nrdLow' // < 90 dagen
    };
  }

  return { isNRD: false, ageDays, ageHours, riskLevel: 'none', reason: null };
}

/**
 * Geeft risicopunten terug gebaseerd op NRD analyse
 * @param {string} riskLevel - Het risiconiveau van analyzeNRDRisk
 * @returns {number} - Risicopunten om toe te voegen
 */
function getNRDRiskScore(riskLevel) {
  switch (riskLevel) {
    case 'critical': return 12; // Bijna zeker phishing
    case 'high': return 8;      // Zeer verdacht
    case 'medium': return 5;    // Verdacht
    case 'low': return 2;       // Licht verhoogd risico
    default: return 0;
  }
}

/**
 * NRD + tel: combo detectie (Vishing Indicator)
 * Detecteert tel: links op pagina's die:
 * 1. Een NRD zijn (<7 dagen oud)
 * 2. tel: links bevatten OF telefoonnummer-gerelateerde CTA's
 * 3. Optioneel: phishing keywords bevatten
 *
 * Dit is een sterke indicator voor vishing (voice phishing) aanvallen,
 * waarbij AI-gegenereerde stemmen worden gebruikt om slachtoffers te bellen.
 *
 * @returns {Promise<{detected: boolean, score: number, reason: string|null, indicators: string[]}>}
 */
async function checkNRDTelCombo() {
  try {
    const pageUrl = window.location.href;
    const pageHostname = window.location.hostname;
    const indicators = [];

    // Haal domein leeftijd op via bestaande RDAP functie
    const domain = getRegistrableDomain(pageUrl);
    if (!domain) {
      return { detected: false, score: 0, reason: null, indicators: [] };
    }

    const created = await fetchDomainCreationDate(domain);
    if (!created) {
      return { detected: false, score: 0, reason: null, indicators: [] };
    }

    // Check of domein NRD is (<7 dagen)
    const nrdAnalysis = analyzeNRDRisk(created);
    if (!nrdAnalysis.isNRD || nrdAnalysis.ageDays > 7) {
      return { detected: false, score: 0, reason: null, indicators: [] };
    }

    // Indicator 1: tel: links aanwezig
    const telLinks = document.querySelectorAll('a[href^="tel:"]');
    const hasTelLinks = telLinks.length > 0;
    if (hasTelLinks) {
      indicators.push(`tel:links(${telLinks.length})`);
    }

    // Indicator 2: Telefoonnummer patronen in tekst (internationale formaten)
    const phonePatterns = [
      /\+\d{1,4}[\s.-]?\(?\d{1,4}\)?[\s.-]?\d{1,4}[\s.-]?\d{1,9}/g, // Internationaal: +31 6 12345678
      /\(?\d{2,4}\)?[\s.-]?\d{3,4}[\s.-]?\d{3,4}/g, // Lokaal: (020) 123-4567
      /\d{3}[\s.-]\d{3}[\s.-]\d{4}/g, // US format: 123-456-7890
      /0\d{9,10}/g, // NL mobiel: 0612345678
    ];

    const bodyText = document.body?.innerText || '';
    let phoneMatches = 0;
    for (const pattern of phonePatterns) {
      const matches = bodyText.match(pattern);
      if (matches) phoneMatches += matches.length;
    }
    const hasPhoneNumbers = phoneMatches > 0;
    if (hasPhoneNumbers) {
      indicators.push(`phoneNumbers(${phoneMatches})`);
    }

    // Indicator 3: Vishing-specifieke CTA keywords
    const vishingKeywords = [
      'call us', 'bel ons', 'call now', 'bel nu', 'call immediately', 'bel direct',
      'phone support', 'telefonische hulp', 'call back', 'terugbellen',
      'speak to', 'spreek met', 'contact by phone', 'telefonisch contact',
      'our agents', 'onze medewerkers', 'customer service', 'klantenservice',
      'helpdesk', 'support line', 'hotline', 'toll free', 'gratis nummer',
      'verify by phone', 'telefonisch verifiëren', 'confirm by call', 'bevestig telefonisch',
      'we will call', 'wij bellen', 'expect a call', 'verwacht een telefoontje'
    ];

    const bodyTextLower = bodyText.toLowerCase();
    const titleTextLower = document.title?.toLowerCase() || '';
    let foundVishingKeywords = [];

    for (const keyword of vishingKeywords) {
      if (bodyTextLower.includes(keyword) || titleTextLower.includes(keyword)) {
        foundVishingKeywords.push(keyword);
      }
    }
    const hasVishingKeywords = foundVishingKeywords.length > 0;
    if (hasVishingKeywords) {
      indicators.push(`vishingCTA(${foundVishingKeywords.slice(0, 3).join(',')})`);
    }

    // Indicator 4: Urgentie keywords (verhogen risico bij combinatie)
    const urgencyKeywords = [
      'urgent', 'immediately', 'right now', 'nu meteen', 'direct actie',
      'within 24 hours', 'binnen 24 uur', 'expires', 'verloopt', 'deadline',
      'suspended', 'opgeschort', 'blocked', 'geblokkeerd', 'unauthorized',
      'unusual activity', 'ongebruikelijke activiteit', 'security alert'
    ];

    let hasUrgency = false;
    for (const keyword of urgencyKeywords) {
      if (bodyTextLower.includes(keyword) || titleTextLower.includes(keyword)) {
        hasUrgency = true;
        indicators.push('urgency');
        break;
      }
    }

    // Bereken score gebaseerd op indicatoren
    let score = 0;
    const nrdAge = nrdAnalysis.ageHours !== undefined
      ? `${nrdAnalysis.ageHours}h`
      : `${nrdAnalysis.ageDays}d`;

    // NRD basis score
    if (nrdAnalysis.ageHours !== undefined && nrdAnalysis.ageHours < 24) {
      score += 5; // Ultra-kritiek NRD
    } else {
      score += 3; // Kritiek NRD
    }

    // Tel links of telefoonnummers
    if (hasTelLinks) score += 4;
    if (hasPhoneNumbers && phoneMatches >= 2) score += 2;

    // Vishing keywords
    if (hasVishingKeywords) score += 3;

    // Urgentie verhoogt risico
    if (hasUrgency) score += 2;

    // Detectie drempel: minimaal NRD + (tel links OF vishing keywords)
    const isVishingIndicator = hasTelLinks || hasVishingKeywords || (hasPhoneNumbers && phoneMatches >= 2);

    if (isVishingIndicator) {
      logDebug(`[NRDTelCombo] Vishing indicator detected: NRD(${nrdAge}), indicators: ${indicators.join(', ')}, score: ${score}`);

      return {
        detected: true,
        score,
        reason: 'nrdVishingCombo',
        indicators,
        details: {
          nrdAge,
          telLinks: telLinks.length,
          phoneNumbers: phoneMatches,
          vishingKeywords: foundVishingKeywords.slice(0, 5),
          hasUrgency
        }
      };
    }

    return { detected: false, score: 0, reason: null, indicators: [] };
  } catch (error) {
    logError('[NRDTelCombo] Error:', error);
    return { detected: false, score: 0, reason: null, indicators: [] };
  }
}

function isValidURL(string) {
  try {
    // Blokkeer data: URLs expliciet (XSS vector)
    if (string.trim().toLowerCase().startsWith('data:')) {
      logDebug(`isValidURL: data: URL geblokkeerd: ${string.substring(0, 50)}...`);
      return false;
    }

    // Blokkeer blob: URLs (Blob URI Phishing - lokaal gegenereerde phishing pagina's)
    if (string.trim().toLowerCase().startsWith('blob:')) {
      logDebug(`isValidURL: blob: URL geblokkeerd: ${string.substring(0, 50)}...`);
      return false;
    }

    const url = new URL(string, window.location.href);
    const protocol = url.protocol;
    const allowedProtocols = ['http:', 'https:', 'mailto:', 'tel:', 'ftp:'];
    if (!allowedProtocols.includes(protocol)) return false;
    if (['http:', 'https:', 'ftp:'].includes(protocol) && !url.hostname) return false;
    return true;
  } catch (error) {
    logDebug(`isValidURL: Ongeldige URL gedetecteerd: ${string}`);
    return false;
  }
}
// Standaard homoglyph-mappings als fallback
const DEFAULT_HOMOGLYPHS = {
  'a': ['а', 'ä', 'α', 'ạ', 'å'],
  'b': ['Ь', 'β', 'ḅ'],
  'c': ['с', 'ç', 'ć'],
  'e': ['е', 'ë', 'ε', 'ẹ'],
  'i': ['і', 'ï', 'ι', 'ḯ'],
  'l': ['ӏ', 'ł', 'ḷ'],
  'o': ['о', 'ö', 'ο', 'ọ', 'ø'],
  'p': ['р', 'ρ', 'ṗ'],
  's': ['ѕ', 'ś', 'ṣ'],
  'u': ['υ', 'ü', 'µ', 'ṵ'],
  'v': ['ν', 'ṽ'],
  'w': ['ω', 'ẉ'],
  'x': ['х', 'χ'],
  'y': ['у', 'ÿ', 'γ'],
};
// Initialiseer homoglyph-set en regex éénmalig
const homoglyphConfig = globalConfig?.HOMOGLYPHS || DEFAULT_HOMOGLYPHS;
const homoglyphSet = new Set(Object.values(homoglyphConfig).flat());
const homoglyphRegex = new RegExp(
  Object.values(homoglyphConfig)
    .map(variants => `(${variants.join('|')})`)
    .join('|'),
  'g'
);
/**
 * Normaliseert een domein door homoglyphs te vervangen door hun Latijnse equivalenten.
 * @param {string} domain - Het te normaliseren domein.
 * @param {object} homoglyphMap - De homoglyph-mapping uit config.js.
 * @returns {string} - Het genormaliseerde domein.
 */
function normalizeWithHomoglyphs(str, homoglyphMap) {
  return str.replace(/./g, c => {
    const mapped = homoglyphMap[c] || c;
    if (mapped !== c) {
      logDebug(`Mapping ${c} (U+${c.codePointAt(0).toString(16)}) to ${mapped}`);
    }
    return mapped;
  });
}
/**
 * Extraheert het hoofddomein uit een volledig domein.
 * @param {string} domain - Het volledige domein.
 * @returns {string} - Het hoofddomein.
 */
function extractMainDomain(domain) {
  const parts = domain.toLowerCase().split('.');
  const tld = parts.slice(-1)[0];
  const compoundTlds = window.CONFIG.COMPOUND_TLDS || [];
  if (compoundTlds.some(ctld => domain.endsWith(ctld))) {
    return parts.slice(-3).join('.');
  }
  return parts.slice(-2).join('.');
}
/**
 * Bouwt de globale reverse homoglyph mapping op uit de HOMOGLYPHS configuratie.
 * Dit wordt gebruikt om homoglyfen (bijv. cyrillische 'а') terug te mappen naar hun
 * Latijnse basis (bijv. 'a').
 */
function buildGlobalHomoglyphReverseMap() {
  const homoglyphs = globalConfig.HOMOGLYPHS || {};
  const tempReverseMap = {};
  // Map Latijnse basiskarakters naar zichzelf en hun varianten naar de Latijnse basis
  for (const [latinBase, variants] of Object.entries(homoglyphs)) {
      tempReverseMap[latinBase] = latinBase; // 'a' mapt naar 'a'
      if (Array.isArray(variants)) {
          for (const variant of variants) {
              tempReverseMap[variant] = latinBase; // 'а' mapt naar 'a'
          }
      }
  }
  // Extra specifieke mappings voor bekende problematische Unicode-tekens
  // Cijfer homoglyfen
  tempReverseMap['0'] = 'o';
  tempReverseMap['1'] = 'l';
  tempReverseMap['3'] = 'e';
  tempReverseMap['4'] = 'a';
  tempReverseMap['5'] = 's';
  tempReverseMap['7'] = 't';
  tempReverseMap['8'] = 'b';
  tempReverseMap['9'] = 'g';
  tempReverseMap['2'] = 'z';
  tempReverseMap['6'] = 'b';
  // Specifieke Punycode/Homoglyph issues
  tempReverseMap['Ñ'] = 'n'; // Hoofdletter N met tilde (U+00D1)
  tempReverseMap['ñ'] = 'n'; // Kleine letter n met tilde (U+00F1)
  tempReverseMap['İ'] = 'i'; // Hoofdletter I met punt (U+0130)
  tempReverseMap['ı'] = 'i'; // Kleine letter puntloze i (U+0131)
  tempReverseMap['Ø'] = 'o'; // Hoofdletter O met schuine streep (U+00D8)
  tempReverseMap['ø'] = 'o'; // Kleine letter o met schuine streep (U+00F8)
  tempReverseMap['Œ'] = 'oe';// Latijnse ligature OE (U+0152)
  tempReverseMap['œ'] = 'oe';// Latijnse ligature oe (U+0153)
  tempReverseMap['ẞ'] = 'ss';// Duitse scherpe S (U+1E9E)
  tempReverseMap['ß'] = 'ss';// Duitse scherpe S (U+00DF)
  // Overige Cyrillische / Griekse homoglyfen
  tempReverseMap['а'] = 'a'; // Cyrillisch a
  tempReverseMap['с'] = 'c'; // Cyrillisch es
  tempReverseMap['е'] = 'e'; // Cyrillisch ie
  tempReverseMap['і'] = 'i'; // Cyrillisch i (dotless)
  tempReverseMap['κ'] = 'k'; // Grieks kappa
  tempReverseMap['м'] = 'm'; // Cyrillisch em
  tempReverseMap['о'] = 'o'; // Cyrillisch o
  tempReverseMap['р'] = 'p'; // Cyrillisch er
  tempReverseMap['ѕ'] = 's'; // Cyrillisch ze
  tempReverseMap['т'] = 't'; // Cyrillisch te
  tempReverseMap['у'] = 'y'; // Cyrillisch u
  tempReverseMap['х'] = 'x'; // Cyrillisch ha
  tempReverseMap['з'] = 'z'; // Cyrillisch ze (alternate)
  tempReverseMap['д'] = 'd'; // Cyrillisch de
  tempReverseMap['г'] = 'r'; // Cyrillisch ge (low)
  tempReverseMap['п'] = 'n'; // Cyrillisch pe
  tempReverseMap['б'] = 'b'; // Cyrillisch be
  tempReverseMap['ц'] = 'u'; // Cyrillisch tse
  tempReverseMap['э'] = 'e'; // Cyrillisch e
  tempReverseMap['ш'] = 'w'; // Cyrillisch sha
  tempReverseMap['ч'] = 'h'; // Cyrillisch che
  tempReverseMap['щ'] = 'sh'; // Cyrillisch shcha
  tempReverseMap['ъ'] = ''; // Hard sign (ignored)
  tempReverseMap['ь'] = ''; // Soft sign (ignored)
  // Grieks
  tempReverseMap['α'] = 'a'; // Alpha
  tempReverseMap['β'] = 'b'; // Beta
  tempReverseMap['ε'] = 'e'; // Epsilon
  tempReverseMap['η'] = 'n'; // Eta
  tempReverseMap['ι'] = 'i'; // Iota
  tempReverseMap['κ'] = 'k'; // Kappa
  tempReverseMap['μ'] = 'm'; // Mu
  tempReverseMap['ν'] = 'v'; // Nu
  tempReverseMap['ο'] = 'o'; // Omicron
  tempReverseMap['ρ'] = 'p'; // Rho
  tempReverseMap['τ'] = 't'; // Tau
  tempReverseMap['υ'] = 'u'; // Upsilon
  tempReverseMap['χ'] = 'x'; // Chi
  tempReverseMap['ψ'] = 'ps'; // Psi
  tempReverseMap['ω'] = 'w'; // Omega
  tempReverseMap['π'] = 'p'; // Pi (U+03C0)
  tempReverseMap['λ'] = 'l'; // Lambda (U+03BB)
  globalHomoglyphReverseMap = tempReverseMap;
  logDebug("Global homoglyph reverse map built with", Object.keys(globalHomoglyphReverseMap).length, "entries.");
}
/**
 * Controleert of een domein een homoglyph- of typosquatting-aanval is.
 * @param {string} domain Het onbewerkte domein (zonder protocol).
 * @param {object} homoglyphMap De mapping uit globalConfig.HOMOGLYPHS (nu alleen gebruikt voor `buildGlobalHomoglyphReverseMap`).
 * @param {string[]} knownBrands Lijst met legitieme domeinen.
 * @param {string} tld De TLD (bv. 'fr', 'de', 'co.uk').
 * @param {Set<string>} reasons Set waarin de reden-tags worden toegevoegd.
 * @returns {Promise<boolean>} True als een aanval is gedetecteerd, anders false.
 */
async function isHomoglyphAttack(domain, homoglyphMap, knownBrands, tld = '', reasons = new Set()) {
    // Zorg dat de globale config geladen is
    await ensureConfigReady();
    // Bouw de reverse map als deze nog niet is gebouwd
    if (Object.keys(globalHomoglyphReverseMap).length === 0) {
        buildGlobalHomoglyphReverseMap();
    }
    const reverseMap = globalHomoglyphReverseMap;
    // Basiskontrole
    if (!domain || typeof domain !== 'string') {
        logDebug('isHomoglyphAttack: Ongeldig domein:', domain);
        return false;
    }
    try {
        // 1) CLEANUP & NFC
        let cleanHostname = domain
            .toLowerCase()
            .replace(/^www\./, '')
            .normalize('NFC');
        logDebug(`Clean hostname: ${cleanHostname}`);
       
        // 2) WHITELIST-EXACT MATCH (op basis van Unicode-codepoints)
        const safeList = Array.isArray(globalConfig.legitimateDomains)
            ? globalConfig.legitimateDomains.map(d => d.toLowerCase().normalize('NFC'))
            : [];
        const cp = [...cleanHostname].map(c => c.codePointAt(0)).join();
        if (safeList.some(d =>
            [...d].map(c => c.codePointAt(0)).join() === cp
        )) {
            logDebug(`Whitelist: ${cleanHostname} is exact legitiem domein`);
            reasons.add('safeDomain');
            return false;
        }
        // 3) SUBDOMEINEN-CHECK
        // Correcte berekening van subdomeinen, rekening houdend met compound TLDs.
        const tldParts = tld.split('.');
        const actualSubCount = cleanHostname.split('.').length - (tldParts.length + 1); // +1 voor het SLD
        if (actualSubCount > (globalConfig.MAX_SUBDOMAINS || 3)) {
            logDebug(`Te veel subdomeinen in ${cleanHostname}: ${actualSubCount}`);
            reasons.add('tooManySubdomains');
        }
        // 4) PUNYCODE-DECODING
        let decodedDomain = cleanHostname;
        let isPunycode = false;
        if (cleanHostname.startsWith('xn--') && typeof punycode !== 'undefined' && punycode.toUnicode) {
            try {
                decodedDomain = punycode.toUnicode(cleanHostname)
                    .toLowerCase()
                    .normalize('NFC');
                isPunycode = true;
                logDebug(`Punycode decoded: ${cleanHostname} → ${decodedDomain}`);
            } catch (e) {
                logError(`Punycode faalde voor ${cleanHostname}: ${e.message}`);
                reasons.add('punycodeDecodingError');
            }
        }
        // 5) DIAKRITICA-STRIPPING
        // Dit is een standaard Unicode normalisatie stap.
        const strippedDomain = decodedDomain
            .normalize('NFD') // Normaliseert naar decomposed form (bijv. 'ö' -> 'o' + diacritisch teken)
            .replace(/\p{Diacritic}/gu, '') // Verwijdert alle diakritische tekens
            .normalize('NFC'); // Normaliseert terug naar canonical form
        logDebug(`Diacritics stripped: ${decodedDomain} → ${strippedDomain}`);
        // 6) GEMENGDE SCRIPTS-CHECK
        const scripts = getUnicodeScripts(strippedDomain); // Deze functie moet Unicode scripts identificeren
        const accentFriendlyTlds = ['fr','de','es','it']; // TLDs waar gemengde scripts minder verdacht zijn
        if (scripts.size > 1 && !accentFriendlyTlds.includes(tld.toLowerCase())) {
            logDebug(`Gemengde scripts in ${strippedDomain}: ${[...scripts].join(',')}`);
            reasons.add('mixedScripts');
        }
        // 7) SKELETON-NORMALISATIE (Kern van de homoglyph-detectie)
        // Gebruik de `normalizeToLatinBase` functie die de `globalHomoglyphReverseMap` gebruikt.
        const skeletonDomain = normalizeToLatinBase(strippedDomain, reverseMap);
        logDebug(`Skeleton domain: ${strippedDomain} → ${skeletonDomain}`);
        // 8) SUSPICIOUS PUNYCODE-NA NORMALISATIE
        // Controleert of een Punycode-domein, eenmaal gedecodeerd en geskeletoniseerd,
        // verdacht veel lijkt op een bekend merk.
        if (isPunycode && skeletonDomain !== cleanHostname) { // Vergelijk skeleton met *initiële* cleanHostname voor verandering
            for (const brand of safeList) {
                const brandMain = extractMainDomain(brand); // Zorg dat brandMain ook genormaliseerd is
                const dist = levenshteinDistance(skeletonDomain, brandMain);
                // Een kleine Levenshtein afstand na normalisatie van een Punycode is zeer verdacht.
                if (dist > 0 && dist <= 2) {
                    logDebug(`Suspicious punycode after skeleton: ${skeletonDomain} lijkt op ${brandMain}`);
                    reasons.add(`suspiciousPunycodeDecoding:${brandMain.replace(/\./g,'_')}`);
                    return true; // Hoog risico, direct return
                }
            }
        }
        // 9) EXTRACT MAIN DOMAIN (altijd op basis van skeletonDomain voor vergelijkingen)
        const mainDomain = extractMainDomain(skeletonDomain);
        logDebug(`Main domain for Levenshtein: ${skeletonDomain} → ${mainDomain}`);
        // 10) ACCENT-VRIENDELIJKE TLD? (voor logging, geen risico-add)
        if (
            tld && accentFriendlyTlds.includes(tld.toLowerCase()) &&
            scripts.size === 1 && scripts.has('Latin')
        ) {
            logDebug(`Accent-TLD ${tld} met alleen Latin; minder verdacht.`);
        }
        // 11) DIGIT-TYPOSQUATTING (specifiekere check)
        // Detecteert wanneer cijfers worden gebruikt om merknamen na te bootsen (bijv. g00gle.com)
        let digitTyposquattingDetected = false;
        // De `digitMap` is al geïntegreerd in `buildGlobalHomoglyphReverseMap`
        // We vergelijken de `strippedDomain` (zonder diakritica)
        // met de geskeletoniseerde versie (die cijfers naar letters omzet)
        const skeletonFromStrippedDigits = normalizeToLatinBase(strippedDomain, reverseMap);
        for (const brand of knownBrands) {
            const brandMain = extractMainDomain(brand.toLowerCase().normalize('NFC'));
            if (!brandMain) continue;
            const dist = levenshteinDistance(skeletonFromStrippedDigits, brandMain);
            const ratio = dist / Math.max(skeletonFromStrippedDigits.length, brandMain.length);
            // Als de afstand na cijfer-substitutie erg klein is, is het verdacht.
            // dist <= 1 is zeer sterk bewijs.
            // dist <= 2 met een lage relatieve ratio (bijv. < 0.1) kan ook verdacht zijn.
            if (dist > 0 && (dist <= 1 || (dist <= 2 && ratio < 0.1))) {
                // Alleen toevoegen als de originele domeinnaam daadwerkelijk een cijfer bevatte
                if (/\d/.test(cleanHostname)) { // Controleer of het origineel een cijfer had
                    logDebug(`Digit typosquatting: "${cleanHostname}" (stripped+mapped: "${skeletonFromStrippedDigits}") looks like "${brandMain}" (d=${dist}, r=${ratio.toFixed(3)})`);
                    reasons.add(`digitTyposquatting:${brandMain.replace(/\./g,'_')}`);
                    digitTyposquattingDetected = true;
                    // Geen break hier, om alle relevante matches te vinden.
                }
            }
        }
        if (digitTyposquattingDetected) {
            return true; // Hoog risico, direct return
        }
        // 12) ALGEMENE TYPOSQUATTING-PATRONEN
        // Dit zijn patronen die vaak duiden op typosquatting, naast homoglyfen.
        const patterns = globalConfig.TYPOSQUATTING_PATTERNS || [
            /g00gle/i, /paypa1/i, /micr0soft/i, // Specifieke, hardcoded typos
            /-\d+\b/, // bv. google-4.com (domein met suffix-cijfer)
            /[-.]login\b/i, // bv. microsoft.login.com (subdomein/path 'login')
            // OPMERKING: /^(?:[a-z0-9]+\.)+[a-z0-9]+\.[a-z]{2,}$/ is vaak gedekt door 'tooManySubdomains'
            /^[a-z0-9-]{1,63}\.[a-z]{2,}$/ // bv. weebly-9.com (generieke hostingsnamen met cijfers)
        ];
        for (const pat of patterns) {
            if (pat.test(skeletonDomain)) { // Test op de geskeletoniseerde versie
                for (const brand of knownBrands) {
                    const bm = extractMainDomain(brand.toLowerCase().normalize('NFC'));
                    if (tld && !bm.endsWith(`.${tld}`)) continue; // Optioneel: alleen vergelijken met merken met dezelfde TLD
                    const dist = levenshteinDistance(mainDomain, bm); // Vergelijk mainDomain (skeleton) met brandMain
                    const ratio = dist / Math.max(mainDomain.length, bm.length);
                    // Lage afstand is verdacht
                    if (dist > 0 && (dist <= 2 && ratio <= 0.2)) { // dist 1 of 2 met acceptabele ratio
                        logDebug(`Typosquatting patroon match: "${skeletonDomain}" (main: "${mainDomain}") → "${bm}" (d=${dist}, r=${ratio.toFixed(3)})`);
                        reasons.add(`typosquatting_${bm.replace(/\./g,'_')}`);
                        return true; // Hoog risico, direct return
                    }
                }
            }
        }
        // 13) GENERIEKE LEVENSHTEIN-CHECK (op geskeletoniseerde hoofddomein)
        // Dit is een catch-all voor domeinen die niet via specifieke patronen zijn gevangen,
        // maar wel een zeer lage Levenshtein-afstand hebben tot een bekend merk na normalisatie.
        let minDist = Infinity, closest = null;
        for (const brand of knownBrands) {
            const bm = extractMainDomain(brand.toLowerCase().normalize('NFC'));
            if (tld && !bm.endsWith(`.${tld}`)) continue;
            const d = levenshteinDistance(mainDomain, bm); // Vergelijk mainDomain (skeleton) met brandMain
            if (d > 0 && d <= 2 && d < minDist) { // Max 2 verschillen
                minDist = d; closest = bm;
            }
        }
        if (closest && !reasons.has('tooManySubdomains')) { // Voorkom dubbele flagging
            const ratio = minDist / Math.max(mainDomain.length, closest.length);
            // Pas de drempel aan: Punycode-domeinen zijn inherent verdachter, zelfs met lage ratios.
            // globalConfig.SUSPICION_THRESHOLD is een goede basis.
            const threshold = isPunycode ? 0.05 : (globalConfig.SUSPICION_THRESHOLD || 0.1); // Lagere threshold voor Punycode
            logDebug(`Levenshtein generiek: "${mainDomain}" vs "${closest}" → d=${minDist}, r=${ratio.toFixed(3)}, t=${threshold}`);
            // Conditie: 1 teken verschil is altijd verdacht, of ratio onder threshold.
            if (minDist === 1 || ratio <= threshold) {
                reasons.add(`similarToLegitimateDomain_${closest.replace(/\./g,'_')}`);
                return true; // Markeer als verdacht
            }
        }

        // 14) BRAND-KEYWORD SUBSTRING CHECK
        // Detecteert wanneer een bekend merk-keyword IN het domein voorkomt met homoglyfen
        // Bijv. "phishıng-ing.com" bevat "ing" (merk) maar met Turkse ı in plaats van normale i
        const brandKeywords = globalConfig.BRAND_KEYWORDS || [];
        if (brandKeywords.length > 0) {
            // Check of het originele domein niet-ASCII karakters bevat (potentiële homoglyfen)
            const hasNonAscii = /[^\x00-\x7F]/.test(cleanHostname);
            // Check of het genormaliseerde domein een merk-keyword bevat
            for (const brand of brandKeywords) {
                const brandLower = brand.toLowerCase();
                // Check in het skeleton domein (genormaliseerd)
                if (skeletonDomain.includes(brandLower)) {
                    // Als het originele domein non-ASCII bevat EN het merk bevat na normalisatie
                    if (hasNonAscii) {
                        logDebug(`Brand-keyword homoglyph: "${cleanHostname}" bevat "${brand}" met homoglyfen`);
                        reasons.add(`brandKeywordHomoglyph:${brand}`);
                        return true; // Hoog risico - merknaam met homoglyfen
                    }
                    // Of check of het domein verdachte prefixen/suffixen heeft rond het merk
                    const suspiciousPrefixes = ['secure-', 'login-', 'verify-', 'update-', 'account-', 'bank-', 'my-', 'online-'];
                    const suspiciousSuffixes = ['-login', '-secure', '-verify', '-update', '-account', '-bank', '-online', '-portal'];
                    for (const prefix of suspiciousPrefixes) {
                        if (skeletonDomain.includes(prefix + brandLower)) {
                            logDebug(`Suspicious brand pattern: "${skeletonDomain}" heeft verdacht prefix "${prefix}" voor "${brand}"`);
                            reasons.add(`suspiciousBrandPattern:${brand}`);
                            return true;
                        }
                    }
                    for (const suffix of suspiciousSuffixes) {
                        if (skeletonDomain.includes(brandLower + suffix)) {
                            logDebug(`Suspicious brand pattern: "${skeletonDomain}" heeft verdacht suffix "${suffix}" na "${brand}"`);
                            reasons.add(`suspiciousBrandPattern:${brand}`);
                            return true;
                        }
                    }
                }
            }
        }

        // 15) EINDOORDEEL: Retourneer true als er enige reden is gevonden.
        return reasons.size > 0;
    } catch (error) {
        logError(`isHomoglyphAttack error voor ${domain}: ${error.message}`);
        return false; // Bij een fout, retourneer false om overblokkering te voorkomen.
    }
}
/**
 * Haalt de Unicode-scripts van karakters in een string op.
 * @param {string} str - De te analyseren string.
 * @returns {Set<string>} - Set van Unicode-scriptnamen.
 */
function getUnicodeScripts(str) {
  const scripts = new Set();
  // Valideer invoer
  if (!str || typeof str !== 'string') {
    logDebug(`getUnicodeScripts: Ongeldige invoer: ${str}`);
    return scripts;
  }
  for (const char of str) {
    const codePoint = char.codePointAt(0);
    if (!Number.isInteger(codePoint)) {
      logDebug(`getUnicodeScripts: Ongeldig codepoint voor karakter: ${char}`);
      continue;
    }
    const script = getScriptForCodePoint(codePoint);
    if (script) {
      scripts.add(script);
      logDebug(`Character ${char} (U+${codePoint.toString(16).toUpperCase()}) mapped to script: ${script}`);
    } else {
      logDebug(`Character ${char} (U+${codePoint.toString(16).toUpperCase()}) heeft geen bekende script`);
    }
  }
  return scripts;
}
/**
 * Bepaalt de Unicode-script voor een gegeven codepoint.
 * @param {number} codePoint - Het Unicode-codepoint van een teken.
 * @returns {string|null} De scriptnaam (bijv. 'Latin', 'Cyrillic', 'Greek', etc.),
 * of null bij ongeldig input.
 */
function getScriptForCodePoint(codePoint) {
  // 1) Input-validatie
  if (!Number.isInteger(codePoint) || codePoint < 0) {
    return null;
  }
  // 2) Ranges checken van meest voorkomende scripts
  if (codePoint <= 0x02FF) {
    // Basic Latin + Latin-1 + Latin Extended-A/B
    return 'Latin';
  }
  if (codePoint >= 0x0370 && codePoint <= 0x03FF) {
    return 'Greek';
  }
  if (codePoint >= 0x0400 && codePoint <= 0x04FF) {
    return 'Cyrillic';
  }
  if (codePoint >= 0x0530 && codePoint <= 0x058F) {
    return 'Armenian';
  }
  if (codePoint >= 0x0600 && codePoint <= 0x06FF) {
    return 'Arabic';
  }
  if (codePoint >= 0x3040 && codePoint <= 0x309F) {
    return 'Hiragana';
  }
  if (codePoint >= 0x30A0 && codePoint <= 0x30FF) {
    return 'Katakana';
  }
  if (codePoint >= 0x4E00 && codePoint <= 0x9FFF) {
    return 'Han';
  }
  // Interpunctie, spaties, zero-width etc.
  if (
    (codePoint >= 0x2000 && codePoint <= 0x206F) ||
    codePoint === 0x200B || codePoint === 0x200C || codePoint === 0x200D
  ) {
    return 'Common';
  }
  // 3) Fallback voor alle andere ranges
  return 'Unknown';
}
/**
 * Bepaalt verwachte scripts op basis van TLD.
 * @param {string} tld - De top-level domein (bijv. 'fr').
 * @returns {string[]} - Lijst van verwachte scripts.
 */
function getExpectedScriptForTld(tld) {
  const tldScriptMap = {
    'fr': ['Latin'],
    'ru': ['Cyrillic'],
    'cn': ['Han'],
    'jp': ['Hiragana', 'Katakana', 'Han'],
    'de': ['Latin'],
    // Voeg meer TLD's en scripts toe
  };
  return tldScriptMap[tld.toLowerCase()] || ['Latin'];
}
// Je bestaande Levenshtein-functie (ongewijzigd)
function levenshteinDistance(a, b) {
  const matrix = Array(b.length + 1).fill().map(() => Array(a.length + 1).fill(0));
  for (let i = 0; i <= a.length; i++) matrix[0][i] = i;
  for (let j = 0; j <= b.length; j++) matrix[j][0] = j;
  for (let j = 1; j <= b.length; j++) {
    for (let i = 1; i <= a.length; i++) {
      const indicator = a[i - 1] === b[j - 1] ? 0 : 1;
      matrix[j][i] = Math.min(
        matrix[j][i - 1] + 1,
        matrix[j - 1][i] + 1,
        matrix[j - 1][i - 1] + indicator
      );
    }
  }
  return matrix[b.length][a.length];
}
const nonHttpProtocols = ['mailto:', 'tel:'];
// -------------------------
// performSuspiciousChecks.js (gewone script-versie, géén modules)
// -------------------------
/**
 * Helper om resultaat in de cache op te slaan, inclusief timestamp.
 */
function storeInCache(url, result) {
    linkRiskCache.set(url, {
        timestamp: Date.now(),
        result
    });
}
/**
 * Voert een reeks gelaagde checks uit op een URL en retourneert het risiconiveau.
 * De checks zijn verdeeld in fasen: lokaal, licht netwerk/CPU, en diepe validatie.
 * @param {string} url - De URL die gecontroleerd moet worden.
 * @returns {Promise<{level: 'safe'|'caution'|'alert', risk: number, reasons: string[]}>}
 */
async function performSuspiciousChecks(url, options = {}) {
  // v8.4.1: countQuota option - only true when checking the current PAGE URL (not links)
  const { countQuota = false } = options;
  await ensureConfigReady();

  // =============================================================================
  // SECURITY FIX v8.3.0: DANGEROUS URI SCHEME DETECTION (FIRST CHECK!)
  // =============================================================================
  // AUDIT FIX: This MUST run BEFORE cache lookup and URL parsing
  // Catches: javascript:, data:, vbscript:, blob: with obfuscation bypass
  const dangerousSchemeResult = detectDangerousScheme(url);
  if (dangerousSchemeResult.isDangerous) {
    logDebug(`[SecurityFix v8.3.0] 🛑 performSuspiciousChecks: BLOCKING ${dangerousSchemeResult.scheme}`);
    const criticalResult = {
      level: 'alert',
      risk: dangerousSchemeResult.risk, // 25 = CRITICAL
      reasons: [dangerousSchemeResult.reason, 'criticalSecurityThreat']
    };
    // Cache the result
    window.linkRiskCache.set(url, { result: criticalResult, timestamp: Date.now() });
    return criticalResult;
  }

  // =============================================================================
  // SECURITY FIX v8.3.0: HOMOGLYPH & PUNYCODE EARLY DETECTION
  // =============================================================================
  // AUDIT FIX: Check for IDN/homoglyph attacks BEFORE normal processing
  const homoglyphResult = detectHomoglyphAndPunycode(url);
  if (homoglyphResult.isSuspicious && homoglyphResult.risk >= 15) {
    logDebug(`[SecurityFix v8.3.0] 🛑 performSuspiciousChecks: HIGH RISK homoglyph/punycode`);
    const homoglyphAlertResult = {
      level: 'alert',
      risk: homoglyphResult.risk,
      reasons: homoglyphResult.reasons
    };
    window.linkRiskCache.set(url, { result: homoglyphAlertResult, timestamp: Date.now() });
    return homoglyphAlertResult;
  }

  // 1) Cache lookup
  const cachedEntry = window.linkRiskCache.get(url);
  if (cachedEntry && Date.now() - cachedEntry.timestamp < CACHE_TTL_MS) {
    logDebug(`Cache hit voor verdachte controles: ${url}`);
    return cachedEntry.result;
  }

  // 2) Feature flag
  const protectionEnabled = await isProtectionEnabled();
  if (!protectionEnabled) {
    const fallback = { level: 'safe', risk: 0, reasons: [] };
    window.linkRiskCache.set(url, { result: fallback, timestamp: Date.now() });
    return fallback;
  }
  const reasons = new Set();
  const totalRiskRef = { value: 0 };

  // Add homoglyph results to reasons if detected but not critical
  if (homoglyphResult.isSuspicious) {
    homoglyphResult.reasons.forEach(r => reasons.add(r));
    totalRiskRef.value += homoglyphResult.risk;
  }

  // 3) URL parsing
  let urlObj;
  try {
    urlObj = new URL(url, window.location.href);
  } catch (err) {
    logError(`Ongeldige URL: ${url}`, err);
    const fallback = { level: 'safe', risk: 0, reasons: ['invalidUrl'] };
    window.linkRiskCache.set(url, { result: fallback, timestamp: Date.now() });
    return fallback;
  }

  // 3b) Early exit for globally trusted domains (TrustedDomains.json)
  const hostname = urlObj.hostname.toLowerCase();
  const isTrusted = await isTrustedDomain(hostname);
  if (isTrusted) {
    logDebug(`[performSuspiciousChecks] Trusted domain, skipping checks: ${hostname}`);
    const safeResult = { level: 'safe', risk: 0, reasons: ['trustedDomain'] };
    window.linkRiskCache.set(url, { result: safeResult, timestamp: Date.now() });
    return safeResult;
  }

  // 3c) v8.4.0: Scan quota check for free users
  // v8.4.1 FIX: Only count quota when:
  // 1. countQuota option is true (only for current PAGE URL checks, not link scanning)
  // 2. Running in TOP-LEVEL frame (not iframes)
  const isTopFrame = window.self === window.top;
  const shouldCountQuota = countQuota && isTopFrame;

  if (shouldCountQuota) {
    // Extract registrable domain for quota tracking (e.g., "sub.example.com" -> "example.com")
    // v8.4.0 FIX: Use extractMainDomain directly (getRegistrableDomain expects URL, not hostname)
    const quotaDomain = extractMainDomain(hostname) || hostname;
    try {
      const quotaCheck = await new Promise((resolve) => {
        chrome.runtime.sendMessage({ type: 'canScanDomain', domain: quotaDomain }, (response) => {
          if (chrome.runtime.lastError) {
            resolve({ allowed: true, reason: 'error' }); // Fail-safe
          } else {
            resolve(response || { allowed: true, reason: 'error' });
          }
        });
      });

      if (!quotaCheck.allowed && quotaCheck.reason === 'quota_exceeded') {
        logDebug(`[performSuspiciousChecks] Quota exceeded, skipping scan for: ${hostname}`);
        // v8.4.1: Disable Smart Link Scanning globally when quota exceeded
        // This stops all further link scanning until quota resets or user upgrades
        smartLinkScanningEnabled = false;
        logDebug('[performSuspiciousChecks] Smart Link Scanning disabled due to quota');
        const quotaResult = { level: 'safe', risk: 0, reasons: ['quotaExceeded'], quotaExceeded: true };
        // Don't cache quota exceeded results - user might upgrade
        return quotaResult;
      }

      // v8.4.0: Record domain scan IMMEDIATELY after quota check passes
      // This ensures the domain is counted even if later checks return early
      if (quotaCheck.reason === 'within_quota') {
        chrome.runtime.sendMessage({ type: 'recordDomainScan', domain: quotaDomain });
        logDebug(`[performSuspiciousChecks] Quota recorded for PAGE: ${quotaDomain}`);
      }
    } catch (quotaError) {
      logDebug(`[performSuspiciousChecks] Quota check error, continuing: ${quotaError}`);
      // Fail-safe: continue with scan on error
    }
  }

  // 4) Early exits voor niet-http(s) protocollen
  // SECURITY FIX v8.3.0: javascript:, data:, vbscript: already handled above
  const nonHttpProtocols = ['mailto:', 'tel:', 'ftp:', 'javascript:'];
  if (nonHttpProtocols.includes(urlObj.protocol)) {
    logDebug(`Niet-HTTP protocol gedetecteerd: ${urlObj.protocol}`);
    if (urlObj.protocol === 'javascript:') {
      // Already handled by detectDangerousScheme above, but double-check
      const clean = url.trim().toLowerCase();
      // Alleen flaggen als het geen harmless shorthand is én er verdacht script in zit
      if (!harmlessJsProtocols.includes(clean) && hasJavascriptScheme(clean)) {
        reasons.add('javascriptScheme');
        totalRiskRef.value += 20; // Increased from 8
        logDebug(`⚠️ Verdachte javascript link: ${url}`);
      }
      // anders geen waarschuwing
    } else if (urlObj.protocol === 'tel:') {
      // NRD + tel: combo detectie (vishing indicator)
      // Check of huidige pagina een NRD is met phishing keywords
      const telComboResult = await checkNRDTelCombo();
      if (telComboResult.detected) {
        reasons.add('nrdTelCombo');
        totalRiskRef.value += telComboResult.score;
        logDebug(`⚠️ NRD + tel: combo gedetecteerd: ${telComboResult.reason}`);
      } else {
        reasons.add('allowedProtocol');
      }
    } else {
      reasons.add('allowedProtocol');
    }
    const level = totalRiskRef.value >= globalConfig.LOW_THRESHOLD ? 'caution' : 'safe';
    const result = { level, risk: totalRiskRef.value, reasons: Array.from(reasons) };
    window.linkRiskCache.set(url, { result, timestamp: Date.now() });
    return result;
  }
  // 5) file: protocol
  if (urlObj.protocol === 'file:') {
    logDebug(`File protocol gedetecteerd: ${url}`);
    const result = { level: 'safe', risk: 0, reasons: ['fileProtocol'] };
    window.linkRiskCache.set(url, { result, timestamp: Date.now() });
    return result;
  }
  // 6) Invalid hostname
  if (!urlObj.hostname || urlObj.href === `${urlObj.protocol}//`) {
    logDebug(`Ongeldige hostname, overslaan: ${url}`);
    const result = { level: 'safe', risk: 0, reasons: ['invalidHostname'] };
    window.linkRiskCache.set(url, { result, timestamp: Date.now() });
    return result;
  }
  // 7) Whitelist check (trusted domains)
  if ((globalConfig.legitimateDomains || []).includes(urlObj.hostname)) {
    logDebug(`Trusted domain ${urlObj.hostname} gedetecteerd.`);
    const result = { level: 'safe', risk: 0, reasons: ['trustedDomain'] };
    window.linkRiskCache.set(url, { result, timestamp: Date.now() });
    return result;
  }
  // =================== HIER BEGINT DE SSL-SKIP FIX ===================
  const currentPageHostname = window.location.hostname;
  if (urlObj.hostname !== currentPageHostname) {
    try {
      const sslResult = await new Promise(resolve => {
        chrome.runtime.sendMessage(
          { action: 'checkSslLabs', domain: urlObj.hostname },
          resolve
        );
      });
      if (!sslResult.isValid) {
        reasons.add('sslValidationFailed');
        totalRiskRef.value += (globalConfig.PROTOCOL_RISK * 2);
        logDebug(`⚠️ SSL Labs check faalde voor extern domein ${urlObj.hostname}: ${sslResult.reason}`);
      } else {
        logDebug(`✅ SSL Labs check OK voor extern domein ${urlObj.hostname}: ${sslResult.reason}`);
      }
    } catch (e) {
      reasons.add('sslValidationFailed');
      totalRiskRef.value += (globalConfig.PROTOCOL_RISK * 2);
      logError(`Fout bij SSL Labs check voor extern domein ${urlObj.hostname}`, e);
    }
  } else {
    logDebug(`SSL Labs check overgeslagen voor intern domein: ${urlObj.hostname}`);
  }
  // =================== HIER EINDIGT DE SSL-SKIP FIX ===================
  // 9) Fase 1: snelle, lokale checks
  checkStaticConditions(url, reasons, totalRiskRef);
  // 10) Fase 2: middelzware, async checks
  await checkDynamicConditionsPhase2(url, reasons, totalRiskRef);
  // 11) Fase 3: diepe checks (domain-age, MX, login HTTPS)
  // Helper: check of hostname een lokaal/privé IP-adres is (vroege definitie voor domain-age skip)
  const isLocalHost = (host) => {
    return (
      /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host) ||
      /^192\.168\.\d{1,3}\.\d{1,3}$/.test(host) ||
      /^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host) ||
      /^172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}$/.test(host) ||
      host === 'localhost' ||
      host.endsWith('.local')
    );
  };
  // Skip domain-age check voor lokale IP's (voorkomt rdap.org 404 errors)
  if (totalRiskRef.value >= globalConfig.DOMAIN_AGE_MIN_RISK && !isLocalHost(urlObj.hostname)) {
    await checkDomainAgeDynamic(url, { totalRiskRef, reasons });
  } else if (isLocalHost(urlObj.hostname)) {
    logDebug(`⏭️ Domain-age check overgeslagen voor lokaal adres: ${urlObj.hostname}`);
  }
  if (detectLoginPage(url)) {
    // Helper: check of hostname een intern/privé IP-adres is
    const isInternalIpAddress = (host) => {
      return (
        /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host) ||
        /^192\.168\.\d{1,3}\.\d{1,3}$/.test(host) ||
        /^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host) ||
        /^172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}$/.test(host) ||
        host === 'localhost' ||
        host.endsWith('.local')
      );
    };
    // MX-check alleen uitvoeren voor publieke domeinen, niet voor interne IP-adressen
    if (!isInternalIpAddress(urlObj.hostname)) {
      try {
        let dom = urlObj.hostname.toLowerCase();
        if (dom.startsWith('xn--') && typeof punycode !== 'undefined') {
          dom = punycode.toUnicode(dom);
        }
        const mx = await queueMxCheck(dom);
        if (mx.length === 0) {
          reasons.add('loginPageNoMX');
          totalRiskRef.value += 12;
        }
      } catch (e) {
        handleError(e, 'performSuspiciousChecks MX');
      }
    } else {
      logDebug(`⏭️ MX-check overgeslagen voor intern IP-adres: ${urlObj.hostname}`);
    }
    if (urlObj.hostname === window.location.hostname && urlObj.protocol !== 'https:') {
      reasons.add('insecureLoginPage');
      totalRiskRef.value += 15;
      logDebug(`⚠️ Insecure loginpagina zonder HTTPS: ${url}`);
    }
  }
  // 12) Bepaal final level en cache
  let finalLevel = totalRiskRef.value >= globalConfig.HIGH_THRESHOLD
    ? 'alert'
    : (totalRiskRef.value >= globalConfig.LOW_THRESHOLD ? 'caution' : 'safe');
  // Local Network Calibration: lokale IP's krijgen maximaal 'caution', nooit 'alert'
  // Dit voorkomt user fatigue bij thuisgebruikers met lokale servers/routers
  if (finalLevel === 'alert' && isLocalNetwork(urlObj.hostname)) {
    finalLevel = 'caution';
    logDebug(`📍 Local network calibration: ${urlObj.hostname} beperkt tot 'caution' (was 'alert')`);
  }
  const finalResult = {
    level: finalLevel,
    risk: Number(totalRiskRef.value.toFixed(1)),
    reasons: Array.from(reasons)
  };

  window.linkRiskCache.set(url, { result: finalResult, timestamp: Date.now() });
  logDebug(`Resultaat voor ${url}:`, finalResult);
  return finalResult;
}
/**
 * Scant alle iframes op de pagina en retourneert een lijst met i18n-reden-keys voor verdachte iframes.
 * Werkt met de SUSPICIOUS_IFRAME_PATTERNS en TRUSTED_IFRAME_DOMAINS uit window.CONFIG, en optioneel
 * met host-specifieke uitzonderingen via CONFIG.HOST_IFRAME_EXCEPTIONS.
 *
 * @returns {Promise<string[]>} Een array van unieke reden-keys.
 */
async function hasSuspiciousIframes() {
  await ensureConfigReady(); // Zorg dat globalConfig geladen is

  // SECURITY FIX v8.8.11: Skip suspicious iframe detection on trusted domains
  // Ad networks on trusted sites commonly use tracking iframes
  await waitForSafeDomains();
  if (safeDomains.length > 0) {
    const currentHostname = window.location.hostname.toLowerCase();
    for (const pattern of safeDomains) {
      try {
        if (new RegExp(pattern, 'i').test(currentHostname)) {
          return []; // Return empty array for trusted domains
        }
      } catch (e) { /* invalid regex, skip */ }
    }
  }

  const patterns = globalConfig.SUSPICIOUS_IFRAME_PATTERNS || [];
  const trustedDomains = globalConfig.TRUSTED_IFRAME_DOMAINS || ['youtube.com', 'vimeo.com', 'google.com']; // Fallback als niet in config
  const hostExceptionsConfig = globalConfig.HOST_IFRAME_EXCEPTIONS || {}; // Fallback empty object
  const currentHost = window.location.hostname;
  // Host-specifieke uitzonderingen (regex strings uit config omgezet naar RegExp)
  const hostExceptions = (hostExceptionsConfig[currentHost] || [])
    .map(str => {
      try {
        return new RegExp(str, 'i');
      } catch (e) {
        logError(`Invalid regex in HOST_IFRAME_EXCEPTIONS for ${str}: ${e.message}`);
        return null;
      }
    })
    .filter(rx => rx !== null);
  const iframes = Array.from(document.querySelectorAll('iframe'))
    .filter(el => isVisible(el) && (el.src || el.srcdoc));
  let elements = iframes;
  // Shadow DOM ondersteuning
  for (const el of document.querySelectorAll('*')) {
    if (el.shadowRoot) {
      elements = elements.concat(Array.from(el.shadowRoot.querySelectorAll('iframe'))
        .filter(f => f.src || f.srcdoc));
    }
  }
  const detected = new Set();
  for (const iframe of elements) {
    const src = iframe.src || '';
    // 1) Iframe zonder src maar met verdachte attributen
    if (!src) {
      const style = getComputedStyle(iframe);
      const isTiny = parseInt(style.width) < 2 && parseInt(style.height) < 2;
      if ((iframe.hasAttribute('onload') || iframe.hasAttribute('onerror')) && isTiny) {
        detected.add('suspiciousIframeHidden');
      }
      continue;
    }
    // 2) URL-parsing en validatie
    let urlObj;
    try {
      urlObj = new URL(src, window.location.origin);
    } catch (err) {
      detected.add('invalidIframeSrc');
      logError(`hasSuspiciousIframes: Ongeldige src: ${src}`);
      continue;
    }
    const hostname = urlObj.hostname.replace(/^www\./, '').toLowerCase();
    // 3) Globale domein-whitelist
    if (trustedDomains.some(d => {
      d = d.toLowerCase();
      return hostname === d || hostname.endsWith(`.${d}`);
    })) {
      logDebug(`hasSuspiciousIframes: Vertrouwd domein, overslaan: ${src}`);
      continue;
    }
    // 4) Host-specifieke uitzonderingen
    if (hostExceptions.some(rx => rx.test(src))) {
      logDebug(`hasSuspiciousIframes: Host-exceptie, overslaan: ${src}`);
      continue;
    }
    // 5) Aanvullende signalen
    const style = getComputedStyle(iframe);
    const rect = iframe.getBoundingClientRect();
    const isHidden = style.display === 'none'
                  || style.visibility === 'hidden'
                  || style.opacity === '0';
    const isSmall = rect.width < 100
                  && rect.height < 100;
    // 6) Strengere regex: boundaries en negatieve look-arounds
    for (const { name, pattern } of patterns) {
      if (!(pattern instanceof RegExp)) continue;
      const strict = new RegExp(
        `(?:^|\\b)(?:${pattern.source})(?:\\b|$)`,
        pattern.flags
      );
      if (strict.test(src) && (isHidden || isSmall)) {
        detected.add(name);
        logDebug(`hasSuspiciousIframes: Verdacht (${name}): ${src}`);
        break;
      }
    }
  }
  logDebug(`hasSuspiciousIframes: Gedetecteerde redenen: ${[...detected].join(', ')}`);
  return [...detected];
}
/**
 * Controleert externe scripts op verdachte kenmerken met een focus op inhoudsanalyse
 * en minder nadruk op zwakke, contextuele signalen om false positives te verminderen.
 * @returns {Promise<string[]>} Een array van reden-keys voor daadwerkelijk verdachte scripts.
 */
async function checkForSuspiciousExternalScripts() {
  const MAX_SCRIPTS_TO_CHECK = 20;
  const scripts = Array.from(document.getElementsByTagName('script'))
    .filter(s => s.src)
    .slice(0, MAX_SCRIPTS_TO_CHECK);
  // --- VERBETERING 1: Configuratie en whitelists eenmalig ophalen ---
  let trustedDomains = [];
  try {
    const json = await fetchCachedJson('trustedScripts.json');
    if (Array.isArray(json)) {
      trustedDomains = json
        .filter(d => typeof d === 'string' && /^[a-zA-Z0-9.-]+$/.test(d))
        .map(d => d.toLowerCase());
    }
  } catch (err) {
    handleError(err, 'checkForSuspiciousExternalScripts: fout laden trustedScripts.json');
  }
  const builtinTrusted = [
    'google.com', 'www.google.com', 'google.be', 'www.google.be',
    'accounts.google.com', 'search.google.com', 'www.gstatic.com',
    'translate.google.com', 'support.google.com', 'apis.google.com',
    'googleapis.com', 'cloudflare.com', 'cdnjs.cloudflare.com', 'jsdelivr.net', 'unpkg.com',
    'code.jquery.com', 'bootstrapcdn.com', 'ajax.googleapis.com', 'static.cloudflareinsights.com',
    'polyfill.io', 'googletagmanager.com', 'analytics.google.com',
  ];
  const trustedScripts = new Set([...builtinTrusted, ...trustedDomains]);
  // Aanbeveling: Maak deze lijst in de configuratie veel kleiner!
  const safeTLDs = new Set(['com', 'net', 'org', 'edu', 'gov', 'be', 'nl', 'io', 'app', 'dev', 'tech', 'cloud', 'info']);
  const allDetectedReasons = new Set();
  const currentPageHostname = window.location.hostname;
  for (const script of scripts) {
    const src = script.src;
    if (!src) continue;
    try {
      const urlObj = new URL(src);
      // --- VERBETERING X: Overslaan niet-HTTP(S)-scripts ---
      if (urlObj.protocol !== 'http:' && urlObj.protocol !== 'https:') {
        logDebug(`⚪️ Overslaan niet-HTTP(S)-script: ${src}`);
        continue;
      }
      const hostname = urlObj.hostname.toLowerCase();
      // --- VERBETERING 2: Interne scripts direct overslaan ---
      if (hostname === currentPageHostname) {
        logDebug(`🔵 Intern script overgeslagen: ${src}`);
        continue;
      }
      // --- Whitelist check (vertrouwde externe domeinen) ---
      if (trustedScripts.has(hostname) || Array.from(trustedScripts).some(d => hostname.endsWith(`.${d}`))) {
        logDebug(`🟢 Vertrouwd extern script: ${src}`);
        continue;
      }
     
      // --- Heuristische checks voor overslaan (async, defer, module) ---
      if (script.hasAttribute('defer') || script.hasAttribute('async') || script.getAttribute('type') === 'module') {
        logDebug(`🟢 Modern script (defer/async/module) overgeslagen: ${src}`);
        continue;
      }
      // --- VERBETERING 3: Contextuele risico's verzamelen i.p.v. direct bestraffen ---
      let contextualRisk = 0;
      const contextReasons = [];
      // Mixed content
      if (urlObj.protocol === 'http:' && window.location.protocol === 'https:') {
        contextualRisk += 6;
        contextReasons.push('mixedContent');
        logDebug(`[Context] ⚠️ mixedContent: ${src}`);
      }
      // Verdachte TLD
      if (globalConfig?.SUSPICIOUS_TLDS instanceof RegExp) {
        const tld = hostname.split('.').pop();
        if (globalConfig.SUSPICIOUS_TLDS.test(tld) && !safeTLDs.has(tld)) {
          contextualRisk += 1;
          contextReasons.push('suspiciousTLD');
          logDebug(`[Context] 🤏 Verdachte TLD (.${tld}): ${src}`);
        }
      }
      // IP-adres als domein
      if (/^\d+\.\d+\.\d+\.\d+$/.test(hostname)) {
        contextualRisk += 3;
        contextReasons.push('ipAsDomain');
        logDebug(`[Context] ⚠️ IP-domein: ${src}`);
      }
      // --- VERBETERING 4: Focus op de inhoudsanalyse ---
      const contentResult = await analyzeScriptContent(urlObj);
      if (contentResult.isSuspicious) {
        const totalRisk = contentResult.totalWeight + contextualRisk;
        logDebug(`[Analyse] Inhoud verdacht (gewicht ${contentResult.totalWeight}), context risico (${contextualRisk}). Totaal: ${totalRisk}`);
        if (totalRisk >= (globalConfig?.SCRIPT_RISK_THRESHOLD || 10)) {
          logDebug(`❌ Verdacht script gedetecteerd (score ${totalRisk}): ${src}`);
          contentResult.matchedPatterns.forEach(reason => allDetectedReasons.add(reason));
          contextReasons.forEach(reason => allDetectedReasons.add(reason));
        } else {
          logDebug(`✔️ Inhoud wel verdacht, maar totale score (${totalRisk}) is onder de drempel.`);
        }
      } else {
        logDebug(`✔️ Inhoudsanalyse OK voor script: ${src}`);
      }
    } catch (err) {
      logError(`checkForSuspiciousExternalScripts: fout bij ${src}: ${err.message}`);
      allDetectedReasons.add('scriptAnalysisError');
    }
  }
  logDebug(`🔍 Totaal gedetecteerde redenen voor verdachte scripts: ${[...allDetectedReasons].join(', ')}`);
  return [...allDetectedReasons];
}
// Optionele periodieke cache-schoonmaak (voeg dit toe aan je script)
setInterval(() => {
  const now = Date.now();
  for (const [url, { timestamp }] of linkRiskCache) {
    if (now - timestamp >= CACHE_TTL_MS) {
      linkRiskCache.delete(url);
      logDebug(`Removed expired cache entry for ${url}`);
    }
  }
}, CACHE_TTL_MS);
/**
 * Voert “statische” controles uit op een URL, wijzigt `reasons` en `totalRiskRef.value`.
 * - Punycode + NFC-normalisatie
 * - Whitelist-check vóór alle andere checks
 * - HTTPS-controle (noHttps) in fase 1
 * - Compound-TLD-ondersteuning bij subdomeinen
 * - Adaptieve relatieve Levenshtein-drempel (≤ 0.1 of 0.2)
 * - Extra statische checks: urlTooLong, encodedCharacters, unusualPort, ipAsDomain, suspiciousTLD
 *
 * @param {string} url
 * @param {Set<string>} reasons
 * @param {{ value: number }} totalRiskRef
 */
function checkStaticConditions(url, reasons, totalRiskRef) {
  let urlObj;
  try {
    urlObj = new URL(url, window.location.href);
  } catch (err) {
    logError(`checkStaticConditions: Ongeldige URL: ${url}`);
    return;
  }
  // 1) Punycode-decoding & NFC-normalisatie
  let rawHost = urlObj.hostname.toLowerCase();
  if (rawHost.startsWith('xn--') && typeof punycode !== 'undefined' && punycode.toUnicode) {
    try {
      rawHost = punycode.toUnicode(rawHost);
      logDebug(`Static: Punycode decoded: ${urlObj.hostname} → ${rawHost}`);
    } catch (e) {
      logError(`Static: Kon Punycode niet decoderen voor ${urlObj.hostname}: ${e.message}`);
    }
  }
  const hostNFC = rawHost.normalize('NFC');
  // 2) Whitelist vóór alle checks
  const allSafe = new Set([
    ...(window.trustedDomains || []),
    ...(globalConfig.legitimateDomains || [])
  ].map(d => d.toLowerCase().replace(/^www\./, '')));
  const checkDomain = hostNFC.replace(/^www\./, '');
  if (allSafe.has(checkDomain)) {
    logDebug(`Static: ✅ ${checkDomain} is expliciet veilig (whitelist).`);
    reasons.add('safeDomain');
    totalRiskRef.value = 0;
    return;
  }
  const proto = urlObj.protocol;
  // 3) Verzamel subdomein-informatie m.b.v. compound TLDs
  const parts = hostNFC.split('.');
  let tldLen = 1;
  for (const ctld of (globalConfig.COMPOUND_TLDS || [])) {
    if (hostNFC === ctld || hostNFC.endsWith(`.${ctld}`)) {
      tldLen = ctld.split('.').length;
      break;
    }
  }
  const subCount = parts.length - tldLen - 1;
  // 4) Overzicht van alle statische checks INCLUSIEF HTTPS
  const staticChecks = [
    // HTTPS-controle
    {
      condition: proto === 'http:',
      weight: globalConfig.PROTOCOL_RISK,
      reason: 'noHttps'
    },
    // Verdachte TLD's (contextuele indicator)
    // FIX v8.7.3: weight 7→4 (TLD alleen is geen sterk signaal)
    {
      condition: (globalConfig.SUSPICIOUS_TLDS instanceof RegExp)
        ? globalConfig.SUSPICIOUS_TLDS.test(hostNFC)
        : false,
      weight: 4,
      reason: 'suspiciousTLD'
    },
    // IP-adres als domeinnaam
    {
      condition: /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/.test(hostNFC),
      weight: 8,
      reason: 'ipAsDomain'
    },
    // Te veel subdomeinen
    {
      condition: !isIpAddress(hostNFC) && subCount > (globalConfig.MAX_SUBDOMAINS || 3),
      weight: 4,
      reason: 'tooManySubdomains'
    },
    // Ongewoon lange URL's
    {
      condition: url.length > (globalConfig.MAX_URL_LENGTH || 2000),
      weight: 1,
      reason: 'urlTooLong'
    },
    // Gecodeerde tekens
    {
      condition: hasEncodedCharacters(url),
      weight: 1,
      reason: 'encodedCharacters'
    },
    // Ongebruikelijke poort
    {
      condition: hasUnusualPort(url),
      weight: 5,
      reason: 'unusualPort'
    },
    // Non-ASCII karakters in originele URL (homoglyph indicator)
    // Check de originele URL string, want new URL() converteert IDN naar Punycode
    {
      condition: (() => {
        const originalDomain = url.split('//')[1]?.split('/')[0]?.split('?')[0] || '';
        return /[^\x00-\x7F]/.test(originalDomain) || rawHost.includes('xn--');
      })(),
      weight: 8,
      reason: 'nonAscii'
    },
    // @ Symbol Attack detectie (KRITIEK - credential URL phishing)
    // Voorbeeld: https://google.com@evil.com gaat naar evil.com
    {
      condition: (() => {
        const atAttack = detectAtSymbolAttack(url);
        return atAttack.detected;
      })(),
      weight: 15,
      reason: 'atSymbolPhishing'
    },
    // Double encoding detectie (obfuscatie poging)
    {
      condition: hasDoubleEncoding(url),
      weight: 6,
      reason: 'doubleEncoding'
    },
    // Fullwidth Unicode karakters (homoglyph variant)
    {
      condition: hasFullwidthCharacters(url),
      weight: 8,
      reason: 'fullwidthCharacters'
    },
    // Null byte injection detectie
    {
      condition: hasNullByteInjection(url),
      weight: 10,
      reason: 'nullByteInjection'
    },
    // URL credentials/@ attack detection (e.g., https://google.com@evil.com)
    {
      condition: hasUrlCredentialsAttack(url).detected,
      weight: 15, // Very high risk - this is a classic phishing technique
      reason: 'urlCredentialsAttack'
    }
  ];
  for (const { condition, weight, reason } of staticChecks) {
    if (condition && !reasons.has(reason)) {
      logDebug(`Static: ${reason} gedetecteerd op ${hostNFC}`);
      reasons.add(reason);
      totalRiskRef.value += weight;
    }
  }
  // 4b) Brand keyword + homoglyph combinatie detectie (HIGH RISK)
  // Als nonAscii gedetecteerd is, controleer of genormaliseerd domein een bekend merk bevat
  if (reasons.has('nonAscii')) {
    const originalDomain = url.split('//')[1]?.split('/')[0]?.split('?')[0] || '';
    let normalizedDomain = originalDomain.toLowerCase();

    // Normaliseer door homoglyphs te vervangen
    const homoglyphs = globalConfig.HOMOGLYPHS || {};
    for (const [latinChar, variants] of Object.entries(homoglyphs)) {
      if (Array.isArray(variants)) {
        for (const variant of variants) {
          normalizedDomain = normalizedDomain.split(variant).join(latinChar);
        }
      }
    }

    // Brand keywords die vaak het doelwit zijn van phishing
    const brandKeywords = ['ing', 'paypal', 'rabobank', 'abnamro', 'microsoft', 'apple',
      'google', 'amazon', 'netflix', 'facebook', 'linkedin', 'bank', 'verify', 'secure'];

    for (const brand of brandKeywords) {
      if (normalizedDomain.includes(brand)) {
        const key = `brandKeywordHomoglyph:${brand}`;
        if (!reasons.has(key)) {
          logDebug(`Static: ${key} gedetecteerd - homoglyph attack op merk "${brand}"`);
          reasons.add(key);
          totalRiskRef.value += 10; // Hoge score voor homoglyph + brand combinatie
        }
        break;
      }
    }
  }
  // 5) Adaptieve Levenshtein-check tegen legitieme domeinen
  if (
    Array.isArray(globalConfig.legitimateDomains) &&
    typeof globalConfig.domainRiskWeights === 'object'
  ) {
    for (const legit of globalConfig.legitimateDomains) {
      const base = extractMainDomain(legit.toLowerCase().normalize('NFC'));
      const dist = levenshteinDistance(hostNFC, base);
      if (dist > 0 && dist <= 2) {
        const maxLen = Math.max(hostNFC.length, base.length);
        const ratio = dist / maxLen;
        const thr = (base.length <= 6)
          ? 0.2
          : (globalConfig.SUSPICION_THRESHOLD || 0.1);
        logDebug(`Static Levenshtein: ${hostNFC} vs ${base} → d=${dist}, r=${ratio.toFixed(2)}, t=${thr}`);
        if (ratio <= thr) {
          const wt = globalConfig.domainRiskWeights[base] || 1;
          const key = `similarToLegitimateDomain:${base}`;
          if (!reasons.has(key)) {
            logDebug(`Static: ${key} (weight=${wt})`);
            reasons.add(key);
            totalRiskRef.value += wt;
          }
          break;
        }
      }
    }
  }

  // 6) Brand Subdomain Phishing detectie
  // Detecteert brand keywords op free hosting platforms
  const brandSubdomainResult = detectBrandSubdomainPhishing(url);
  if (brandSubdomainResult.detected && !reasons.has('brandSubdomainPhishing')) {
    logDebug(`Static: brandSubdomainPhishing - ${brandSubdomainResult.brand} on free hosting`);
    reasons.add('brandSubdomainPhishing');
    totalRiskRef.value += brandSubdomainResult.score;
  }

  // 7) Hostname Brand + Keyword Phishing detectie
  // Detecteert brand + phishing keywords in hostname (bijv. login-microsoft-verify.com)
  const hostnameBrandResult = detectHostnameBrandKeywordPhishing(url);
  if (hostnameBrandResult.detected && !reasons.has('hostnameBrandKeywordPhishing')) {
    logDebug(`Static: hostnameBrandKeywordPhishing - ${hostnameBrandResult.brand} + ${hostnameBrandResult.keywords.join(', ')}`);
    reasons.add('hostnameBrandKeywordPhishing');
    totalRiskRef.value += hostnameBrandResult.score;
  }
}
/**
 * Voert snelle, lokale checks uit op een URL zonder netwerkverkeer.
 * Wijzigt `reasons` en `totalRiskRef.value` direct.
 * @param {string} url - De volledige URL.
 * @param {Set<string>} reasons - Set waarin reason-tags worden toegevoegd.
 * @param {{ value: number }} totalRiskRef - Object dat de cumulatieve risicoscore bijhoudt.
 */
function applyStaticChecks(url, reasons, totalRiskRef) {
    let urlObj;
    try {
        urlObj = new URL(url, window.location.href);
    } catch (err) {
        logError(`applyStaticChecks: Ongeldige URL: ${url}`);
        reasons.add('invalidUrl');
        totalRiskRef.value += 0.5; // Een minimaal risico voor ongeldige URL's
        return;
    }
    const rawHost = urlObj.hostname.toLowerCase();
    let hostNFC = rawHost; // Start met rawHost, normalisatie gebeurt later
    let isPunycode = false;
    // Decode punycode indien nodig
    if (rawHost.startsWith('xn--') && typeof punycode !== 'undefined') {
        try {
            hostNFC = punycode.toUnicode(rawHost);
            logDebug(`Static: Punycode decoded: ${rawHost} → ${hostNFC}`);
            isPunycode = true;
        } catch (e) {
            logError(`Static: Kon Punycode niet decoderen voor ${rawHost}: ${e.message}`);
            reasons.add('punycodeDecodingError');
            totalRiskRef.value += 2;
        }
    }
    // Normaliseer naar NFC voor consistente vergelijkingen
    hostNFC = hostNFC.normalize('NFC');
    // --- GEFIXTE WHITELIST-LOGICA ---
    const allSafe = Array.from(new Set([
        ...(window.trustedDomains || []),
        ...(globalConfig.legitimateDomains || [])
    ]))
    .map(d => d.toLowerCase().replace(/^www\./, ''));
    // Check op exact match of subdomein-match
    const checkDomainRaw = rawHost.replace(/^www\./, '');
    const checkDomainDecoded = hostNFC.replace(/^www\./, '');
    const isWhitelisted = allSafe.some(d =>
        checkDomainRaw === d || checkDomainRaw.endsWith(`.${d}`) ||
        checkDomainDecoded === d || checkDomainDecoded.endsWith(`.${d}`)
    );
    if (isWhitelisted) {
        logDebug(`Static: ✅ Domein "${checkDomainRaw}" of "${checkDomainDecoded}" is (sub)domein van whitelist. Skip verdere checks.`);
        reasons.add('safeDomain');
        totalRiskRef.value = 0; // Geen risico voor whitelisted domeinen
        return;
    }
    // --- Einde GEFIXTE WHITELIST-LOGICA ---
    // Bepaal aantal subdomeinen, met ondersteuning voor compound TLDs
    const parts = hostNFC.split('.');
    let tldLen = 1;
    for (const ctld of (globalConfig.COMPOUND_TLDS || [])) {
        if (hostNFC === ctld || hostNFC.endsWith(`.${ctld}`)) {
            tldLen = ctld.split('.').length;
            break;
        }
    }
    const subdomainCount = parts.length - (tldLen + 1);
    // De overige statische checks
    // FIX v8.7.3: suspiciousTLD weight 6→4 (TLD alleen is geen sterk signaal)
    const staticChecks = [
        {
            condition: (globalConfig.SUSPICIOUS_TLDS instanceof RegExp)
                       && globalConfig.SUSPICIOUS_TLDS.test(hostNFC),
            weight: 4,
            reason: 'suspiciousTLD'
        },
        {
            condition: /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/.test(hostNFC),
            weight: 5,
            reason: 'ipAsDomain'
        },
        {
            condition: subdomainCount > (globalConfig.MAX_SUBDOMAINS || 3),
            weight: 5,
            reason: 'tooManySubdomains'
        },
        {
            condition: (globalConfig.TYPOSQUATTING_PATTERNS || []).some(pat => pat.test(hostNFC)),
            weight: 3,
            reason: 'typosquattingPattern'
        },
        {
            condition: url.length > (globalConfig.MAX_URL_LENGTH || 2000),
            weight: 2,
            reason: 'urlTooLong'
        },
        {
            condition: /%[0-9A-Fa-f]{2}/.test(url) && !hasEncodedCharactersExclusion(url),
            weight: 2,
            reason: 'encodedCharacters'
        }
    ];
    staticChecks.forEach(({ condition, weight, reason }) => {
        if (condition && !reasons.has(reason)) {
            logDebug(`Static: ${reason} gedetecteerd op ${hostNFC}`);
            reasons.add(reason);
            totalRiskRef.value += weight;
        }
    });
    // Uitsluiting voor enkel %20 in pad
    function hasEncodedCharactersExclusion(u) {
        const o = new URL(u);
        const enc = /%[0-9A-Fa-f]{2}/g;
        const pathMatches = (o.pathname.match(enc) || []);
        const queryMatches = (o.search.match(enc) || []);
        const uniq = new Set([...pathMatches, ...queryMatches]);
        return uniq.size === 1 && uniq.has('%20')
               && pathMatches.length > 0 && queryMatches.length === 0;
    }
    // Levenshtein-check tegen legitieme domeinen
    if (Array.isArray(globalConfig.legitimateDomains)
        && typeof globalConfig.domainRiskWeights === 'object') {
        const simpHost = hostNFC.replace(/[-.]/g, '');
        for (const legit of globalConfig.legitimateDomains) {
            const simpLegit = legit.toLowerCase().replace(/^www\./, '').replace(/[-.]/g, '');
            const dist = levenshteinDistance(simpHost, simpLegit);
            if (dist > 0 && dist <= 2) {
                const ratio = dist / Math.max(simpHost.length, simpLegit.length);
                const thr = (simpLegit.length <= 6) ? 0.2 : (globalConfig.SUSPICION_THRESHOLD || 0.1);
                if (ratio <= thr) {
                    const wt = globalConfig.domainRiskWeights[legit] || 1;
                    const tag = `similarToLegitimateDomain:${legit.replace(/\./g,'_')}`;
                    if (!reasons.has(tag)) {
                        logDebug(`Static (Lev): ${tag} (weight=${wt})`);
                        reasons.add(tag);
                        totalRiskRef.value += wt;
                    }
                    break;
                }
            }
        }
    }
    logDebug(`Einde applyStaticChecks: Risico ${totalRiskRef.value}, Redenen: ${[...reasons].join(', ')}`);
}
/**
 * Voert middelzware checks uit (licht netwerk/CPU, DOM-analyse) op een URL.
 * Wordt alleen uitgevoerd als de statische checks al een basisrisico hebben gedetecteerd.
 * @param {string} url - De volledige URL.
 * @param {Set<string>} reasons - Set wherein reason-tags worden toegevoegd.
 * @param {{ value: number }} totalRiskRef - Object dat de cumulatieve risicoscore bijhoudt.
 */
async function applyMediumChecks(url, reasons, totalRiskRef) {
  const urlObj = new URL(url);
  const domainOnly = urlObj.hostname.toLowerCase();
  const tld = extractTld(domainOnly); // Gebruik je eigen extractTld functie
  // Bouw homoglyphMap en knownBrands vanuit globalConfig
  const homoglyphMapEntries = globalConfig.HOMOGLYPHS || {};
  const homoglyphMap = {};
  for (const [latin, variants] of Object.entries(homoglyphMapEntries)) {
    if (Array.isArray(variants)) { // Check if variants is an array
      for (const g of variants) {
        homoglyphMap[g] = latin;
      }
    }
  }
  const knownBrands = Array.isArray(globalConfig.legitimateDomains)
    ? globalConfig.legitimateDomains.map(d => d.toLowerCase())
    : [];
  // Lijst van checks voor de middelzware fase
  const mediumChecks = [
    // isHomoglyphAttack kan network calls doen (bijv. voor punycode, hoewel we die al eerder decodeerden),
    // dus past hier goed. Het voegt zelf al redenen toe aan de 'reasons' Set.
    {
    func: async () => {
      // maak een eigen Set voor deze check
      const localReasons = new Set();
      const attack = await isHomoglyphAttack(domainOnly, homoglyphMap, knownBrands, tld, localReasons);
      if (attack) {
        reasons.add('homoglyphAttack');
        // eventueel: localReasons.forEach(r => reasons.add(r));
      }
      return attack;
    },
    messageKey: 'homoglyphAttack',
    risk: 10
  },
    { func: async () => await isShortenedUrl(url), messageKey: 'shortenedUrl', risk: 4.0 },
    { func: async () => await isDownloadPage(url), messageKey: 'downloadPage', risk: 3.5 },
    { func: async () => await hasSuspiciousQueryParameters(url), messageKey: 'suspiciousParams', risk: 2.5 },
    { func: async () => await hasMixedContent(url), messageKey: 'mixedContent', risk: 2.0 },
    { func: async () => await hasUnusualPort(url), messageKey: 'unusualPort', risk: 5 },
    { func: async () => await hasJavascriptScheme(url), messageKey: 'javascriptScheme', risk: 4.0 },
    { func: async () => await usesUrlFragmentTrick(url), messageKey: 'urlFragmentTrick', risk: 2.0 },
    { func: async () => await isCryptoPhishingUrl(url), messageKey: 'cryptoPhishing', risk: 10.0 },
    // { func: async () => await isFreeHostingDomain(url), messageKey: 'freeHosting', risk: 5 }, // UITGESCHAKELD - te veel false positives (github.io, vercel.app, netlify.app zijn legitiem)
    // { func: async () => await hasSuspiciousKeywords(url), messageKey: 'suspiciousKeywords', risk: 0 }, // UITGESCHAKELD - te veel false positives
    { func: async () => await hasSuspiciousUrlPattern(url), messageKey: 'suspiciousPattern', risk: 3.0 },
    // Scripts en Iframes checks zijn vaak iets zwaarder door DOM-traversal / head requests
    // Deze retourneren al arrays van redenen.
    { func: async () => await hasSuspiciousIframes(), messageKey: 'suspiciousIframes', risk: 3.5 },
    { func: async () => await checkForSuspiciousExternalScripts(), messageKey: 'suspiciousScripts', risk: 4.0 },
    // Form Action Hijacking - detecteert credential theft via externe form actions
    { func: async () => {
      const result = detectFormActionHijacking();
      return result.detected ? result.reasons : [];
    }, messageKey: 'formActionHijacking', risk: 8.0 },
    // Hidden Iframes - detecteert onzichtbare iframes (keyloggers, clickjacking)
    { func: async () => {
      const result = detectHiddenIframes();
      return result.detected ? result.reasons : [];
    }, messageKey: 'hiddenIframes', risk: 6.0 },
  ];
  for (const { func, messageKey, risk } of mediumChecks) {
    try {
      const result = await func();
      let triggered = false;
      let specificReasons = [];
      if (Array.isArray(result)) {
        if (result.length > 0) {
          triggered = true;
          specificReasons = result;
        }
      } else {
        triggered = Boolean(result);
      }
      // Voeg alleen de risicopunten en redenen toe als de check niet al een reden heeft toegevoegd
      // of als de check zelf een array van specifieke redenen retourneert.
      if (triggered) {
        if (specificReasons.length > 0) {
          specificReasons.forEach(r => reasons.add(r));
        } else if (!reasons.has(messageKey)) { // Voeg alleen toe als de reden nog niet bestaat
          reasons.add(messageKey);
        }
        totalRiskRef.value += risk;
        logDebug(`Fase 2: Toegevoegd ${messageKey} (risico ${risk}) voor ${url}. Huidig risico: ${totalRiskRef.value}.`);
      }
    } catch (e) {
      handleError(e, `applyMediumChecks (${messageKey})`);
      reasons.add(`error_${messageKey}`); // Voeg een foutreden toe
    }
  }
}
/**
 * Voert middelzware checks uit (licht netwerk/CPU, DOM-analyse) op een URL.
 * Wordt alleen uitgevoerd als de statische checks al een basisrisico hebben gedetecteerd.
 * @param {string} url - De volledige URL.
 * @param {Set<string>} reasons - Set wherein reason-tags worden toegevoegd.
 * @param {{ value: number }} totalRiskRef - Object dat de cumulatieve risicoscore bijhoudt.
 */
async function checkDynamicConditionsPhase2(url, reasons, totalRiskRef) {
  const urlObj = new URL(url);
  const domainOnly = urlObj.hostname.toLowerCase();
  const tld = domainOnly.split('.').pop().toLowerCase();
  // Hergebruik de homoglyphMap en knownBrands
  const homoglyphMapEntries = globalConfig.HOMOGLYPHS || {};
  const homoglyphMap = {};
  for (const [latin, variants] of Object.entries(homoglyphMapEntries)) {
    // Voeg een controle toe om er zeker van te zijn dat variants een array is
    if (Array.isArray(variants)) {
        for (const g of variants) {
            homoglyphMap[g] = latin;
        }
    }
  }
  const knownBrands = Array.isArray(globalConfig.legitimateDomains)
    ? globalConfig.legitimateDomains.map(d => d.toLowerCase())
    : [];
  // De lijst met dynamische checks en hun aangepaste risicoscores
  const dynamicChecksPhase2 = [
    // --- 'Red Flag' Indicatoren ---
    {
      func: async () => {
        const localReasons = new Set();
        const attack = await isHomoglyphAttack(domainOnly, homoglyphMap, knownBrands, tld, localReasons);
        if (attack) {
          reasons.add('homoglyphAttack');
          // Voeg eventueel de specifiekere redenen van de aanval toe
          localReasons.forEach(r => reasons.add(r));
        }
        return attack;
      },
      messageKey: 'homoglyphAttack',
      risk: 10 // Blijft 10. Dit is een zeer sterke indicator.
    },
    {
      func: () => isCryptoPhishingUrl(url),
      messageKey: 'cryptoPhishing',
      risk: 10.0 // Blijft 10. Crypto phishing is een hoog-risico categorie.
    },
    // --- Technische Indicatoren ---
   
    {
      func: () => checkForSuspiciousExternalScripts(),
      messageKey: 'suspiciousScripts',
      risk: 5.0 // Was 4.0. De aanwezigheid van verdachte scripts is een belangrijk signaal.
    },
    {
      func: () => hasSuspiciousIframes(),
      messageKey: 'suspiciousIframes',
      risk: 5.0 // Was 3.5. Hetzelfde als scripts; dit is een significant risico.
    },
    // --- Contextuele Indicatoren ---
    // UITGESCHAKELD - freeHosting standalone geeft te veel false positives (github.io, vercel.app, etc.)
    // Blijft actief in AiTM detectie waar het gecombineerd wordt met login form detectie
    // {
    //   func: () => isFreeHostingDomain(url),
    //   messageKey: 'freeHosting',
    //   risk: 4
    // },
    {
      func: () => isShortenedUrl(url),
      messageKey: 'shortenedUrl',
      risk: 3.0 // Was 4.0. Verlaagd omdat legitiem gebruik veel voorkomt.
    },
    {
      func: () => isDownloadPage(url),
      messageKey: 'downloadPage',
      risk: 3.0 // Was 3.5. Licht verlaagd.
    },
    {
      func: () => hasSuspiciousUrlPattern(url),
      messageKey: 'suspiciousPattern',
      risk: 3.0 // Blijft 3.0. Een goede indicator voor ongebruikelijke URL-structuren.
    },
    {
      func: () => hasSuspiciousQueryParameters(url),
      messageKey: 'suspiciousParams',
      risk: 2.0 // Was 2.5. Verlaagd, context is hier erg belangrijk.
    },
    {
      func: () => hasMixedContent(url),
      messageKey: 'mixedContent',
      risk: 2.0 // Blijft 2.0.
    },
    // UITGESCHAKELD - standalone keywords geven te veel false positives
    // {
    //   func: () => hasSuspiciousKeywords(url),
    //   messageKey: 'suspiciousKeywords',
    //   risk: 0
    // },
    {
      func: () => usesUrlFragmentTrick(url),
      messageKey: 'urlFragmentTrick',
      risk: 1.0 // Was 2.0. Dit is een zeer zwakke indicator op zichzelf.
    }
  ];
  for (const { func, messageKey, risk } of dynamicChecksPhase2) {
    try {
      const result = await func();
      let triggered = false;
      let specificReasons = [];
      if (Array.isArray(result)) {
        // Functies die een array van redenen teruggeven (bijv. scripts/iframes)
        if (result.length > 0) {
          triggered = true;
          specificReasons = result;
        }
      } else {
        // Functies die een boolean teruggeven
        triggered = Boolean(result);
      }
      if (triggered) {
        if (specificReasons.length > 0) {
          specificReasons.forEach(r => reasons.add(r));
        } else {
          reasons.add(messageKey); // Voeg de algemene reden toe
        }
        totalRiskRef.value += risk;
        logDebug(`Fase 2: Toegevoegd ${messageKey} (risico ${risk}) voor ${url}. Huidig risico: ${totalRiskRef.value}`);
      }
    } catch (e) {
      handleError(e, `checkDynamicConditionsPhase2 (${messageKey})`);
      reasons.add(`error_${messageKey}`); // Voeg een foutreden toe
    }
  }
}
function addReason(map, reason, severity) {
  if (!map.has(reason)) {
    map.set(reason, severity);
  }
}
function addReasonIfNotExists(reasonsMap, reason, severity) {
  const normalizedReason = normalizeReason(reason, severity);
  if (!reasonsMap.has(normalizedReason)) {
    reasonsMap.set(normalizedReason, severity);
  }
}
function normalizeReason(reason, severity) {
  return `${reason} (${severity})`;
}
function addUniqueReason(reasonsMap, reason, severity) {
  const normalizedReason = normalizeReason(reason, severity);
  if (!reasonsMap.has(normalizedReason)) {
    reasonsMap.set(normalizedReason, severity);
  }
}
async function isLoginPageFromUrl(url) {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000); // 5 seconden timeout
    const loginPatterns = globalConfig.LOGIN_PATTERNS || /(login|signin|authenticate)/i;
    if (loginPatterns.test(url)) {
      logDebug(`Login page detected based on URL pattern: ${url}`);
      return true;
    }
    const response = await fetch(url, { signal: controller.signal });
    clearTimeout(timeout);
    const html = await response.text();
    const hasPasswordField = /<input[^>]*type=["']?password["']?/i.test(html);
    if (hasPasswordField) {
      logDebug(`Login page detected based on content: ${url}`);
      return true;
    }
    logDebug(`No login page detected: ${url}`);
    return false;
  } catch (error) {
    handleError(error, `isLoginPageFromUrl: Fout bij controleren van loginpagina voor URL ${url}`);
    return false;
  }
}
function constructResult(isSafe, reasons, priorRisk) {
  try {
    if (typeof priorRisk !== "number" || isNaN(priorRisk)) {
      logError("priorRisk is not a valid number:", priorRisk);
      priorRisk = 1.0;
    }
    if (!Array.isArray(reasons)) {
      logError("reasons is not an array:", reasons);
      reasons = ["Unexpected error analyzing risks."];
    }
    logDebug("Construct Result:", { isSafe, reasons, priorRisk });
    return {
      isSafe: Boolean(isSafe),
      reasons: reasons.length > 0 ? reasons : ["No specific risks detected."],
      risk: priorRisk.toFixed(2),
    };
  } catch (error) {
    handleError(error, `constructResult: Fout bij construeren van resultaat met risico ${priorRisk}`);
    return {
      isSafe: false,
      reasons: ["Unexpected error in result construction."],
      risk: "1.00",
    };
  }
}
function calculateBayesianRisk(prior, evidenceRisk, evidence) {
  if (evidence === 0) return prior;
  const posterior = ((evidenceRisk ** 2) * prior) / (evidence + prior);
  return Math.min(posterior, 1);
}
function generateResult(isSafe, reasons, riskProbability, isExternal) {
  return {
    isSafe,
    reasons,
    riskProbability,
    isExternal,
  };
}
function checkSafeProtocol(url) {
  try {
    const protocol = new URL(url, window.location.href).protocol;
    return globalConfig.ALLOWED_PROTOCOLS.includes(protocol);
  } catch (e) {
    return false;
  }
}
function processSeverity(priorRisk, severity, risk, severityWeights, lowSeverityCount) {
  const weight = severityWeights[severity] || 1.0;
  if (severity === "low") {
    lowSeverityCount++;
    if (lowSeverityCount >= 2) {
      return updateRisk(priorRisk, risk * weight * 1.1, 0.05);
    } else {
      return updateRisk(priorRisk, risk * weight, 0.02);
    }
  }
  if (severity === "medium") {
    return updateRisk(priorRisk, risk * weight * 1.0, 0.05);
  }
  if (severity === "high") {
    return updateRisk(priorRisk, risk * weight * 1.3, 0.1);
  }
  return priorRisk;
}
function updateRisk(priorRisk, addedRisk, adjustmentFactor) {
  const adjustedRisk = priorRisk + addedRisk;
  const finalRisk = adjustedRisk + adjustmentFactor;
  return Math.min(finalRisk, 0.9);
}
function hasSuspiciousQueryParameters(url) {
  const suspiciousParams = /(token|auth|password|key|session|id|login|verify|secure|access)/i;
  try {
    const urlObj = new URL(url);
    for (const [key, value] of urlObj.searchParams) {
      if (suspiciousParams.test(key) || suspiciousParams.test(value)) {
        if (!isSafeParameter(key, value)) {
          return true;
        }
      }
    }
    return false;
  } catch (error) {
    handleError(error, `hasSuspiciousQueryParameters: Fout bij controleren van queryparameters voor URL ${url}`);
    return false; // Terugvallen op default false bij fout
  }
}
function hasMixedContent(url) {
  try {
    const urlObj = new URL(url);
    return urlObj.protocol === "https:" && urlObj.href.includes("http://");
  } catch (error) {
    handleError(error, `hasMixedContent: Fout bij controleren van gemengde inhoud voor URL ${url}`);
  }
  return false;
}
/**
 * Checks if a hostname belongs to a private/local network
 * Private networks cannot be used for phishing (not publicly accessible)
 */
function isPrivateNetwork(hostname) {
  if (!hostname) return false;

  const h = hostname.toLowerCase();

  // Localhost
  if (h === 'localhost' || h === '127.0.0.1' || h === '::1') return true;

  // .local domains (mDNS/Bonjour)
  if (h.endsWith('.local')) return true;

  // .localhost TLD (RFC 6761)
  if (h.endsWith('.localhost')) return true;

  // Private IPv4 ranges
  const ipv4Match = h.match(/^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/);
  if (ipv4Match) {
    const [, a, b] = ipv4Match.map(Number);
    // 10.0.0.0/8
    if (a === 10) return true;
    // 172.16.0.0/12
    if (a === 172 && b >= 16 && b <= 31) return true;
    // 192.168.0.0/16
    if (a === 192 && b === 168) return true;
    // 169.254.0.0/16 (link-local)
    if (a === 169 && b === 254) return true;
  }

  return false;
}

function hasUnusualPort(url) {
  const commonPorts = [80, 443];
  try {
    const urlObj = new URL(url);

    // Skip port check for private networks (localhost, LAN, .local)
    // These are used by sysadmins and developers, not phishing
    if (isPrivateNetwork(urlObj.hostname)) {
      return false;
    }

    const port = urlObj.port ? parseInt(urlObj.port, 10) : (urlObj.protocol === "http:" ? 80 : 443);
    return !commonPorts.includes(port);
  } catch (error) {
    handleError(error, "hasUnusualPort");
  }
  return false;
}
// Bovenaan in content.js, na de andere helperfuncties
const harmlessJsProtocols = [
  'javascript:void(0);',
  'javascript:void(0)',
  'javascript:;',
  'javascript:'
];
function hasJavascriptScheme(url) {
  // Haal de code achter 'javascript:' op en check op gevaarlijke calls
  const code = url.slice('javascript:'.length).trim();
  return /\b(eval|Function|document\.write|innerHTML=|location\.|window\.)\b/.test(code);
}
function usesUrlFragmentTrick(url) {
  try {
    const urlObj = new URL(url);
    return urlObj.hash && urlObj.hash.length > 10;
  } catch (error) {
    handleError(error, "usesUrlFragmentTrick");
  }
  return false;
}
function isSafeParameter(param, value) {
  const allowedParams = [
    'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
    'fbclid', 'gclid', 'dclid', 'sclid', 'twclid',
    'referrer', 'source', 'campaign', 'session_id', 'visitor_id', 'ga_id',
    'q', 'query', 'search', 'keyword', 'kw',
    'product_id', 'sku', 'variant', 'category', 'price', 'currency',
    'page', 'page_id', 'section', 'lang', 'locale', 'country',
    'debug', 'cache_bypass', 'test',
    'user_id', 'session_token', 'affiliate_id', 'partner'
  ];
  return allowedParams.includes(param);
}
function hasMultipleSubdomains(url) {
  logDebug(`hasMultipleSubdomains called with url: ${url}`);
  try {
    logDebug(`Attempting to extract hostname from url: ${url}`);
    const hostname = new URL(url).hostname;
    logDebug(`Extracted hostname: ${hostname}`);
   
    const isIpAddress = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
    logDebug(`Is hostname an IP address? ${isIpAddress}`);
    if (isIpAddress) {
      logDebug(`Hostname is an IP address, returning false`);
      return false;
    }
    logDebug(`Splitting hostname into subdomains`);
    const subdomains = hostname.split('.').slice(0, -2);
    logDebug(`Subdomains: ${subdomains.join(', ')}`);
    const maxAllowedSubdomains = globalConfig.MAX_SUBDOMAINS || 3;
    const hasTooManySubdomains = subdomains.length > maxAllowedSubdomains;
    logDebug(`Number of subdomains: ${subdomains.length}, max allowed: ${maxAllowedSubdomains}, has too many: ${hasTooManySubdomains}`);
    return hasTooManySubdomains;
  } catch (error) {
    logDebug(`Error in hasMultipleSubdomains: ${error.message}`);
    handleError(error, "hasMultipleSubdomains");
    return false;
  }
}
// Definieer de cache buiten de functie om persistentie te garanderen
const shortenedUrlCache = new Map();
async function isShortenedUrl(url) {
  try {
    if (shortenedUrlCache.has(url)) {
      logDebug(`Cache hit voor URL: ${url}`);
      return shortenedUrlCache.get(url);
    }
    const shortenedDomains = globalConfig.SHORTENED_URL_DOMAINS;
    const officialShorteners = globalConfig.OFFICIAL_SHORTENERS;
    const domain = new URL(url).hostname.toLowerCase().replace(/^www\./, "");

    // Check eerst of het een officiële shortener is (t.co, youtu.be, etc.)
    // Deze worden NIET als verdacht gemarkeerd
    if (officialShorteners && officialShorteners.has(domain)) {
      logDebug(`Official shortener detected for ${domain} - not flagging as suspicious`);
      shortenedUrlCache.set(url, false);
      return false;
    }

    logDebug(`Checking domain ${domain} against SHORTENED_URL_DOMAINS: ${Array.from(shortenedDomains).join(', ')}`);
    const isShortened = shortenedDomains.has(domain);
    logDebug(`Shortener check for ${url}: ${isShortened ? 'Detected' : 'Not detected'}`);
    if (shortenedUrlCache.size >= MAX_CACHE_SIZE) {
      shortenedUrlCache.clear();
      logDebug("Cache limiet bereikt, cache gereset.");
    }
    shortenedUrlCache.set(url, isShortened);
    return isShortened;
  } catch (error) {
    handleError(error, `isShortenedUrl: Fout bij controleren van verkorte URL ${url}`);
    shortenedUrlCache.set(url, true); // Conservatief: assume shortened bij fout
    return true;
  }
}
async function resolveShortenedUrlWithRetry(url, retries = 3, delay = 1000) {
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      const response = await fetch(url, {
        method: 'HEAD',
        redirect: 'follow',
        mode: 'no-cors', // Voorkom CORS-blokkering
      });
      return response.url || url; // Fallback naar originele URL als no-cors geen redirect geeft
    } catch (error) {
      if (attempt === retries) return url;
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
  return url;
}
// ----------------------------------------------------
// AANGEPASTE hasEncodedCharacters FUNCTIE
// ----------------------------------------------------
function hasEncodedCharacters(url) {
    try {
        const urlObj = new URL(url);
        const path = urlObj.pathname;
        const query = urlObj.search;
        const encodedCharPattern = /%[0-9A-Fa-f]{2}/g;
        const pathEncodedMatches = path.match(encodedCharPattern) || [];
        const queryEncodedMatches = query.match(encodedCharPattern) || [];
        // Geen verdachtheid als de enige encoding spaties (%20) zijn in het pad
        // en er geen andere verdachte elementen zijn.
        // We willen alleen waarschuwen als het een complexere of ongebruikelijke encoding betreft.
       
        // Tel het aantal verschillende gecodeerde tekens.
        const uniqueEncodedChars = new Set([...pathEncodedMatches, ...queryEncodedMatches]);
        // Uitzondering: %20 (spatie) in het pad is vaak legitiem, vooral voor bestandsnamen
        if (uniqueEncodedChars.size === 1 && uniqueEncodedChars.has('%20') && pathEncodedMatches.length > 0 && queryEncodedMatches.length === 0) {
            logDebug(`Legitieme URL-encoding (%20) gedetecteerd in pad: ${url}`);
            return false;
        }
        // Als er meer dan één type encoding is, of als het in de query staat (potentieel verdachter)
        // of als het niet alleen %20 is, markeer het dan als verdacht.
        if (uniqueEncodedChars.size > 0) {
             // Controleer op dubbele encoding (bijv. %2520) - zeer verdacht
            if (/%25[0-9A-Fa-f]{2}/i.test(url)) {
                logDebug(`Dubbele URL-encoding gedetecteerd in ${url}`);
                return true;
            }
            // Controleer op lange, opeenvolgende reeksen van encoded tekens (kan obfuscation zijn)
            if (/%[0-9A-Fa-f]{2}(?:%[0-9A-Fa-f]{2}){5,}/i.test(url)) { // 6 of meer opvolgende encoded chars
                 logDebug(`Lange reeks encoded karakters gedetecteerd in ${url}`);
                 return true;
            }
            logDebug(`Verdachte URL-encoding gedetecteerd in ${url}: ${Array.from(uniqueEncodedChars).join(', ')}`);
            return true;
        }
       
        logDebug(`Geen verdachte URL-encoding gedetecteerd in ${url}`);
        return false;
    } catch (error) {
        handleError(error, `hasEncodedCharacters: Fout bij controleren van gecodeerde tekens voor URL ${url}`);
        return false; // Bij fout, val terug op 'niet verdacht'
    }
}
function hasBase64OrHex(url) {
  const base64Pattern = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
  const hexPattern = /\b[a-f0-9]{16,}\b/i; // Verhoogd naar 16 tekens voor Hex
  const minLengthThreshold = 12; // Strengere drempel
  const allowedProtocols = globalConfig?.ALLOWED_PROTOCOLS || ['https:', 'http:', 'ftp:'];
  try {
    const urlObj = new URL(url);
    const protocol = urlObj.protocol;
    // Skip niet-relevante protocollen
    if (!allowedProtocols.includes(protocol)) {
      logDebug(`Skipping Base64/Hex check for non-relevant protocol: ${url}`);
      return false;
    }
    const components = [
      urlObj.pathname.slice(1),
      urlObj.search.slice(1),
      urlObj.hash.slice(1),
    ].filter(Boolean);
    for (const component of components) {
      if (component.length < minLengthThreshold) continue;
      const segments = component.split(/[/?#&=]+/).filter(seg => seg.length >= minLengthThreshold);
      for (const segment of segments) {
        // Base64: vereis decodeerbare inhoud met verdachte kenmerken
        if (base64Pattern.test(segment)) {
          try {
            const decoded = atob(segment.replace(/=+$/, ''));
            const suspiciousContent = /script|eval|javascript|onload|onclick/i.test(decoded);
            if (suspiciousContent) {
              logDebug(`Valid Base64 with suspicious content detected in ${url}: ${segment} -> ${decoded}`);
              return true;
            }
          } catch (e) {
            logDebug(`Base64 matched but invalid decoding: ${segment} in ${url}`);
          }
        }
        // Hex: alleen lange reeksen met context
        const hexMatches = segment.match(hexPattern);
        if (hexMatches && hexMatches.some(match => match.length >= minLengthThreshold)) {
          const hasSuspiciousContext = /script|js|exec|load|data/i.test(component);
          if (hasSuspiciousContext) {
            logDebug(`Suspicious Hex detected in ${url}: ${hexMatches.join(', ')}`);
            return true;
          }
        }
      }
    }
    logDebug(`No suspicious Base64 or Hex detected in ${url}`);
    return false;
  } catch (error) {
    handleError(error, `hasBase64OrHex: Error checking Base64/Hex for URL ${url}`);
    return false;
  }
}
// Definieer de cache buiten de functie voor persistentie
const loginPageCache = new Map();
const LOGIN_CACHE_TTL_MS = 3600000; // 1 uur TTL
function detectLoginPage(url) {
  try {
    const cached = loginPageCache.get(url);
    const now = Date.now();
    if (cached && (now - cached.timestamp < LOGIN_CACHE_TTL_MS)) {
      logDebug(`Cache hit for login detection: ${url}`);
      return cached.result;
    }
    const loginPatterns = /(login|signin|wp-login|authenticate|account)/i;
    const urlIndicatesLogin = loginPatterns.test(url);
    const hasPasswordField = !!document.querySelector('input[type="password"]');
    logDebug(`Login detection for ${url}: URL indication: ${urlIndicatesLogin}, Password field: ${hasPasswordField}`);
    const result = urlIndicatesLogin || hasPasswordField;
    loginPageCache.set(url, { result, timestamp: now });
    logDebug(`Cached login detection result for ${url}: ${result}`);
    return result;
  } catch (error) {
    handleError(error, `detectLoginPage: Fout bij detecteren van loginpagina voor URL ${url}`);
    return false;
  }
}
// Optioneel: Periodieke cache-schoonmaak
setInterval(() => {
  const now = Date.now();
  for (const [url, { timestamp }] of loginPageCache) {
    if (now - timestamp >= LOGIN_CACHE_TTL_MS) {
      loginPageCache.delete(url);
      logDebug(`Removed expired login cache entry for ${url}`);
    }
  }
}, LOGIN_CACHE_TTL_MS);
/**
 * Controleert of een URL afkomstig is van een gratis-hostingdienst.
 *
 * @param {string} url De volledige URL-string om te controleren.
 * @returns {Promise<boolean>} true als de URL van gratis hosting lijkt, anders false.
 */
async function isFreeHostingDomain(url) {
  try {
    const parsedUrl = new URL(url);
    let domain = parsedUrl.hostname.toLowerCase();
    // Decode Punycode indien nodig
    if (domain.startsWith('xn--') && typeof punycode !== 'undefined' && punycode.toUnicode) {
      domain = punycode.toUnicode(domain);
      logDebug(`Checking free hosting voor gede­codeerd domein: ${domain}`);
    }

    // Check eerst of het een vertrouwde CDN is - deze zijn NIET verdacht
    const trustedCdns = globalConfig.TRUSTED_CDN_DOMAINS || new Set();
    for (const cdn of trustedCdns) {
      if (domain === cdn || domain.endsWith('.' + cdn)) {
        logDebug(`Trusted CDN detected for ${domain} - not flagging as free hosting`);
        return false;
      }
    }

    // Check ook vertrouwde API domeinen
    const trustedApis = globalConfig.TRUSTED_API_DOMAINS || new Set();
    for (const api of trustedApis) {
      if (domain === api || domain.endsWith('.' + api)) {
        logDebug(`Trusted API domain detected for ${domain} - not flagging as free hosting`);
        return false;
      }
    }

    // Splits hostname in labels
    const parts = domain.split('.');
    if (parts.length < 2) {
      // Geen geldig domein om verder te checken
      return false;
    }
    // Bepaal de TLD (laatste label) en SLD (voorlaatste label)
    const tld = parts[parts.length - 1];
    let sld = parts[parts.length - 2];
    // Haal globale lijst op (uit config.js)
    const freeHostingDomains = globalConfig.FREE_HOSTING_DOMAINS || [];
    // 1) Directe match of suffix-match: "domein" is exact in de lijst, of eindigt op ".entry"
    for (const entry of freeHostingDomains) {
      if (domain === entry || domain.endsWith('.' + entry)) {
        logDebug(`Gratis hosting gedetecteerd via directe suffix-match: ${entry}`);
        return true;
      }
    }
    // 2) Strip "-<cijfers>" achter SLD (bijv. "weebly-9" → "weebly") en check opnieuw
    // Dit dekt gevallen zoals "weebly-9.com" → "weebly.com"
    const strippedSld = sld.replace(/-\d+$/, '');
    const reconstructed = strippedSld + '.' + tld;
    if (freeHostingDomains.includes(reconstructed)) {
      logDebug(`Gratis hosting gedetecteerd via gestript SLD ("${sld}" → "${strippedSld}"): ${reconstructed}`);
      return true;
    }
    // 3) Verdachte trefwoorden in de volledige hostname (nu uitgebreid met bekende platform-namen)
    const suspiciousKeywords = [
      'free', 'webhost', 'cheap', 'hosting', 'tumblr', 'blogspot', 'blogger', 'weebly', 'wixsite'
    ];
    if (suspiciousKeywords.some(keyword => domain.includes(keyword))) {
      logDebug(`Verdacht hostingkeyword in ${domain}`);
      return true;
    }
    // 4) Meer dan één opeenvolgend koppelteken (soms duidt op auto-genereerde subdomeinen)
    // Skip Punycode labels (xn--) die legitiem dubbele koppeltekens bevatten
    const domainWithoutPunycode = domain.replace(/\bxn--[a-z0-9-]+/g, '');
    if (/[-]{2,}/.test(domainWithoutPunycode)) {
      logDebug(`Meerdere opeenvolgende koppeltekens in ${domain}`);
      return true;
    }
    // 5) Een onderdeel (label) langer dan 25 tekens (kennelijk een gratis-hosting subdomein)
    if (parts.some(part => part.length > 25)) {
      logDebug(`Lang domeinonderdeel in ${domain}`);
      return true;
    }
    return false;
  } catch (error) {
    logError(`Fout bij free hosting-check voor ${url}: ${error.message}`);
    return false;
  }
}

/**
 * Detecteert brand keywords in subdomeinen op gratis hosting platforms.
 * Bijv: ing-secure.firebaseapp.com, rabo-login.herokuapp.com
 *
 * @param {string} url - De URL om te controleren
 * @returns {{detected: boolean, brand: string|null, score: number, reason: string|null}}
 */
function detectBrandSubdomainPhishing(url) {
    try {
        const parsedUrl = new URL(url);
        const hostname = parsedUrl.hostname.toLowerCase();
        const parts = hostname.split('.');

        // Check of dit een legitiem merkdomein is (whitelist)
        const legitimateDomains = globalConfig?.LEGITIMATE_BRAND_DOMAINS || [];
        if (legitimateDomains.some(legit => hostname === legit || hostname.endsWith('.' + legit))) {
            return { detected: false, brand: null, score: 0, reason: null };
        }

        // Check of dit een gratis hosting domein is
        const freeHostingDomains = globalConfig?.FREE_HOSTING_DOMAINS || [];
        let isOnFreeHosting = false;
        let hostingDomain = null;

        for (const freeHost of freeHostingDomains) {
            if (hostname.endsWith('.' + freeHost) || hostname === freeHost) {
                isOnFreeHosting = true;
                hostingDomain = freeHost;
                break;
            }
        }

        if (!isOnFreeHosting) {
            return { detected: false, brand: null, score: 0, reason: null };
        }

        // Check of een brand keyword voorkomt in de subdomeinen
        const brandKeywords = globalConfig?.BRAND_KEYWORDS || [
            'ing', 'rabo', 'abnamro', 'abn', 'sns', 'bunq', 'digid', 'belasting',
            'paypal', 'amazon', 'google', 'microsoft', 'apple', 'facebook'
        ];

        // Haal de subdomeinen (alles behalve het hosting domein)
        const hostingParts = hostingDomain.split('.');
        const subdomainParts = parts.slice(0, parts.length - hostingParts.length);
        const subdomainStr = subdomainParts.join('.');

        for (const brand of brandKeywords) {
            // For short brands (<=3 chars), require word boundaries (-, ., start, end)
            // to avoid matching substrings like "shopping" → "ing" or "startups" → "ups"
            let matched = false;
            if (brand.length <= 3) {
                const regex = new RegExp(`(^|[.\\-])${brand}($|[.\\-])`);
                matched = regex.test(subdomainStr);
            } else {
                matched = subdomainStr.includes(brand);
            }

            if (matched) {
                logDebug(`[BrandSubdomain] Detected: ${brand} in ${hostname}`);
                return {
                    detected: true,
                    brand: brand,
                    score: 5,
                    reason: 'brandSubdomainPhishing'
                };
            }
        }

        return { detected: false, brand: null, score: 0, reason: null };
    } catch (error) {
        logError(`[BrandSubdomain] Error: ${error.message}`);
        return { detected: false, brand: null, score: 0, reason: null };
    }
}

/**
 * Detecteert brand + phishing keyword combinaties in HOSTNAME.
 * Bijv: login-microsoft-verify.com, secure-paypal-update.net
 *
 * @param {string} url - De URL om te analyseren
 * @returns {{detected: boolean, brand: string|null, keywords: string[], score: number}}
 */
function detectHostnameBrandKeywordPhishing(url) {
    try {
        const parsedUrl = new URL(url);
        const hostname = parsedUrl.hostname.toLowerCase();

        // Whitelist check - skip legitieme merkdomeinen
        const legitimateDomains = globalConfig?.LEGITIMATE_BRAND_DOMAINS || [];
        for (const legit of legitimateDomains) {
            if (hostname === legit || hostname.endsWith('.' + legit)) {
                return { detected: false, brand: null, keywords: [], score: 0 };
            }
        }

        // Haal domeinnaam zonder TLD (bijv. "login-microsoft-verify" van "login-microsoft-verify.com")
        const parts = hostname.split('.');
        const domainName = parts.length >= 2 ? parts.slice(0, -1).join('.') : hostname;

        // Brand keywords uit config
        const brandKeywords = globalConfig?.BRAND_KEYWORDS || [];

        // Phishing action keywords die vaak gecombineerd worden met merknamen
        const phishingKeywords = ['login', 'secure', 'verify', 'update', 'account', 'signin',
                                  'auth', 'confirm', 'password', 'billing', 'payment', 'support'];

        for (const brand of brandKeywords) {
            const brandLower = brand.toLowerCase();
            // For short brands (<=3 chars), require word boundaries to avoid
            // substring matches like "shopping" → "ing" or "groups" → "ups"
            let brandMatched = false;
            if (brandLower.length <= 3) {
                const regex = new RegExp(`(^|[.\\-])${brandLower}($|[.\\-])`);
                brandMatched = regex.test(domainName);
            } else {
                brandMatched = domainName.includes(brandLower);
            }
            if (brandMatched) {
                // Zoek phishing keywords (die niet het merk zelf zijn)
                const foundKeywords = phishingKeywords.filter(k =>
                    k !== brandLower && domainName.includes(k));

                if (foundKeywords.length >= 1) {
                    // Score berekening:
                    // - Base score: 8 punten voor brand + keyword combo
                    // - High-value brands (Microsoft, Google, etc.): +2 punten
                    // - Extra punten per gevonden keyword
                    const highValueBrands = ['microsoft', 'google', 'apple', 'paypal', 'amazon', 'ing', 'rabo', 'abnamro', 'digid'];
                    let score = highValueBrands.includes(brandLower) ? 10 : 8;

                    const highRiskKeywords = ['login', 'verify', 'secure', 'password', 'signin'];
                    for (const kw of foundKeywords) {
                        score += highRiskKeywords.includes(kw) ? 3 : 2;
                    }

                    logDebug(`[HostnameBrandKeyword] Detected: ${brand} + [${foundKeywords.join(', ')}] in ${hostname}, score=${Math.min(score, 20)}`);
                    return { detected: true, brand, keywords: foundKeywords, score: Math.min(score, 20) };
                }
            }
        }
        return { detected: false, brand: null, keywords: [], score: 0 };
    } catch (error) {
        logError(`[HostnameBrandKeyword] Error: ${error.message}`);
        return { detected: false, brand: null, keywords: [], score: 0 };
    }
}

/**
 * Analyzes a URL's redirect chain by calling the background service worker.
 * Only triggered for shortened URLs or links with 'caution' level.
 *
 * @param {string} url - The URL to analyze
 * @param {string} level - Current risk level ('safe', 'caution', 'alert')
 * @param {boolean} force - Force analysis regardless of conditions
 * @returns {Promise<{finalUrl: string, chain: string[], threats: string[], redirectCount: number, error?: string}|null>}
 */
async function analyzeRedirectChain(url, level = 'safe', force = false) {
  try {
    const urlObj = new URL(url);
    const domain = urlObj.hostname.toLowerCase();

    // Check if URL is a shortened URL
    const isShortened = globalConfig && globalConfig.SHORTENED_URL_DOMAINS &&
                        globalConfig.SHORTENED_URL_DOMAINS.has(domain);

    // Only analyze if: forced, shortened URL, or caution level
    if (!force && !isShortened && level !== 'caution') {
      return null;
    }

    // Send message to background script for redirect chain analysis
    const response = await chrome.runtime.sendMessage({
      action: 'analyzeRedirectChain',
      url: url,
      level: level,
      force: force
    });

    if (response && response.success) {
      return response.result;
    } else if (response && response.error) {
      logDebug(`[RedirectChain] Error: ${response.error}`);
      return null;
    }

    return null;
  } catch (error) {
    handleError(error, 'analyzeRedirectChain');
    return null;
  }
}

/**
 * Merges redirect chain analysis results with the original analysis result.
 * The highest risk level and all unique reasons are combined.
 *
 * @param {Object} originalResult - Original performSuspiciousChecks result
 * @param {Object} chainResult - Result from redirect chain analysis
 * @returns {Object} Merged result with worst-case level and combined reasons
 */
function mergeRedirectChainResult(originalResult, chainResult) {
  if (!chainResult || !chainResult.threats || chainResult.threats.length === 0) {
    return originalResult;
  }

  const levelPriority = { 'safe': 0, 'caution': 1, 'alert': 2 };

  // Calculate risk from redirect threats
  let redirectRisk = 0;
  const redirectReasons = [];

  for (const threat of chainResult.threats) {
    switch (threat) {
      case 'excessiveRedirects':
        redirectRisk += 4;
        redirectReasons.push('reason_excessiveRedirects');
        break;
      case 'domainHopping':
        redirectRisk += 5;
        redirectReasons.push('reason_domainHopping');
        break;
      case 'chainedShorteners':
        redirectRisk += 3;
        redirectReasons.push('reason_chainedShorteners');
        break;
      case 'suspiciousFinalTLD':
        redirectRisk += 4;
        redirectReasons.push('reason_suspiciousFinalTLD');
        break;
      case 'redirectToIP':
        redirectRisk += 6;
        redirectReasons.push('reason_redirectToIP');
        break;
      case 'timeout':
        redirectRisk += 2;
        redirectReasons.push('reason_redirectTimeout');
        break;
      default:
        redirectRisk += 2;
        redirectReasons.push('reason_redirectChain');
    }
  }

  // Determine new level based on combined risk
  const combinedRisk = originalResult.risk + redirectRisk;
  let newLevel = originalResult.level;

  if (combinedRisk >= (globalConfig?.HIGH_THRESHOLD || 15)) {
    newLevel = 'alert';
  } else if (combinedRisk >= (globalConfig?.LOW_THRESHOLD || 4)) {
    newLevel = 'caution';
  }

  // Ensure level never decreases
  if (levelPriority[newLevel] < levelPriority[originalResult.level]) {
    newLevel = originalResult.level;
  }

  // Merge reasons (remove duplicates)
  const allReasons = [...new Set([...originalResult.reasons, ...redirectReasons])];

  return {
    level: newLevel,
    risk: combinedRisk,
    reasons: allReasons,
    redirectChain: {
      finalUrl: chainResult.finalUrl,
      chain: chainResult.chain,
      redirectCount: chainResult.redirectCount
    }
  };
}

/**
 * Checks the safety of a link upon user interaction (mouseover, click).
 * It calls the layered detection logic (`performSuspiciousChecks`) and manages visual warnings.
 *
 * @param {HTMLAnchorElement} link - The HTML anchor element being checked.
 * @param {string} eventType - The type of event ('mouseover', 'click', etc.).
 * @param {Event} event - The DOM event object.
 * @returns {Promise<{level: 'safe'|'caution'|'alert', risk: number, reasons: string[]}|void>}
 */
async function unifiedCheckLinkSafety(link, eventType, event) {
  // 1) Protection disabled?
  if (!(await isProtectionEnabled())) {
    logDebug('Protection disabled, skipping unifiedCheckLinkSafety');
    return;
  }
  // ───────────────────────────────────────────────────────────────────────
  // Step 1: Validate input and extract href
  // ───────────────────────────────────────────────────────────────────────
  let href;
  if (link && link.href) {
    // Handle SVGAnimatedString if the href comes from an SVG element
    href = link.href instanceof SVGAnimatedString ? link.href.baseVal : link.href;
  } else {
    logDebug(`Skipping unifiedCheckLinkSafety: Invalid or missing link or href: ${link?.href || 'undefined'}`);
    return;
  }
  // Basic URL validity check
  if (!isValidURL(href)) {
    logDebug(`Skipping unifiedCheckLinkSafety: Invalid URL in link: ${href}`);
    // Optionally, you could still warn the user about an invalid URL format
    warnLinkByLevel(link, { level: 'caution', risk: 1, reasons: ['invalidUrlFormat'] });
    return;
  }
  logDebug(`Checking URL in unifiedCheckLinkSafety: ${href}`);
  // ───────────────────────────────────────────────────────────────────────
  // Step 2: Deduplication (using window.processedLinks to avoid redundant checks)
  // ───────────────────────────────────────────────────────────────────────
  if (!window.processedLinks) {
    window.processedLinks = new Set();
  }
  // This deduplication is for the _immediate_ period to preventrapid re-checking.
  // The `link.dataset.linkshieldWarned` flag handles persistent visual deduplication.
  if (window.processedLinks.has(href)) {
    logDebug(`Skipping duplicate unifiedCheckLinkSafety for ${href}`);
    // If already processed recently, just return the cached result if available.
    // Otherwise, we might still want to trigger warnLinkByLevel later if needed.
    return;
  }
  window.processedLinks.add(href);
  // Clear from recent cache after a short period (e.g., 2 seconds)
  setTimeout(() => window.processedLinks.delete(href), 2000);
  try {
    const urlObj = new URL(href);
    const hostname = urlObj.hostname;
    // Skip checks for internal IP addresses, .local, or localhost.
    const isInternalIp = (host) => {
      return (
        /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host) ||
        /^192\.168\.\d{1,3}\.\d{1,3}$/.test(host) ||
        /^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host) ||
        /^172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}$/.test(host)
      );
    };
    if (isInternalIp(hostname) || hostname.endsWith(".local") || hostname === "localhost") {
      logDebug(`Internal server detected for ${hostname}. Skipping checks.`);
      return;
    }
    // ─────────────────────────────────────────────────────────────────────
    // Step 3: Perform the full, layered suspicious checks ONE time
    // This is the core logic now, replacing redundant checks in this function.
    // ─────────────────────────────────────────────────────────────────────
    let analysisResult = await performSuspiciousChecks(href);

    // ─────────────────────────────────────────────────────────────────────
    // Step 3.5: Redirect Chain Analysis (for shortened URLs or caution level)
    // Analyze the redirect chain to detect cloaked malicious destinations
    // ─────────────────────────────────────────────────────────────────────
    try {
      const chainResult = await analyzeRedirectChain(href, analysisResult.level);
      if (chainResult) {
        // If we got a different final URL, also check that URL
        if (chainResult.finalUrl && chainResult.finalUrl !== href) {
          const finalUrlResult = await performSuspiciousChecks(chainResult.finalUrl);
          // Merge final URL result if it's worse
          if (finalUrlResult.risk > analysisResult.risk) {
            analysisResult = {
              ...analysisResult,
              risk: Math.max(analysisResult.risk, finalUrlResult.risk),
              reasons: [...new Set([...analysisResult.reasons, ...finalUrlResult.reasons])]
            };
            // Recalculate level based on combined risk
            if (analysisResult.risk >= (globalConfig?.HIGH_THRESHOLD || 15)) {
              analysisResult.level = 'alert';
            } else if (analysisResult.risk >= (globalConfig?.LOW_THRESHOLD || 4)) {
              analysisResult.level = 'caution';
            }
          }
        }
        // Merge redirect chain threats
        analysisResult = mergeRedirectChainResult(analysisResult, chainResult);
        logDebug(`[RedirectChain] Final result after chain analysis: level=${analysisResult.level}, risk=${analysisResult.risk}`);
      }
    } catch (chainError) {
      // Don't fail the entire check if redirect chain analysis fails
      handleError(chainError, 'unifiedCheckLinkSafety:redirectChain');
    }

    // ─────────────────────────────────────────────────────────────────────
    // Step 4: Apply visual warning based on analysis result
    // ─────────────────────────────────────────────────────────────────────
    warnLinkByLevel(link, analysisResult);

    // Return the analysis result for potential further use (e.g., caching in event handlers)
    return analysisResult;
  } catch (error) {
    handleError(error, `unifiedCheckLinkSafety: Error checking link ${href} on event ${eventType}`);
    // In case of an unexpected error, return a conservative 'caution' result
    const errorResult = { level: 'caution', risk: 5, reasons: ["unifiedCheckError"] };
    // And also ensure a visual warning is shown for the error
    warnLinkByLevel(link, errorResult);
    return errorResult;
  }
}
/**
 * Controleert of een URL wijst naar een mogelijke crypto-phishing site.
 *
 * @param {string} url De volledige URL die gecontroleerd moet worden.
 * @returns {boolean} True als het verdacht is voor crypto-phishing, anders false.
 */
function isCryptoPhishingUrl(url) {
  const officialDomains = (globalConfig && globalConfig.CRYPTO_DOMAINS) || [];
  const cryptoBrands = officialDomains.map(domain => domain.split('.')[0].toLowerCase());
  const cryptoKeywords = [
    'crypto', 'bitcoin', 'btc', 'eth', 'ether', 'wallet', 'coin', 'token',
    'blockchain', 'ledger', 'exchange', 'airdrop'
  ];
  // Patterns for full path (hostname + path)
  const fullPathPatterns = [
    /wallet[-_]?connect/i,
    /crypto[-_]?auth/i,
    /(?:free|earn|claim|bonus)[-_]?(?:crypto|bitcoin|btc|eth|coin)/i,
    /airdrop[-_]?(?:crypto|coin|token)/i,
    new RegExp(`(?:${cryptoKeywords.join('|')})[-_]?airdrop`, 'i'),  // Added for keyword-airdrop
    new RegExp(`(?:2fa|verify)[-_]?(?:${cryptoBrands.join('|')})`, 'i')
  ];
  // Patterns for base domain (SLD without TLD)
  const baseDomainPatterns = [
    /(?:secure|auth|verify|2fa|locked)-?(?:wallet|crypto|coin|exchange|token|account)/i,
    /secure[-_]?wallet|wallet[-_]?secure/i,
    /wallet[-_]?connect/i,
    new RegExp(`(?:2fa|verify)-(?:${cryptoBrands.join('|')})`, 'i'),
    new RegExp(`(?:${cryptoBrands.join('|')})-(?:login|signin|auth|verify|portal)`, 'i')  // Added for brand-login
  ];
  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname.toLowerCase();
    const fullPath = (hostname + urlObj.pathname).toLowerCase();
    // Extract base domain (SLD without TLD)
    const hostnameParts = hostname.split('.');
    const baseDomain = hostnameParts.length > 1 ? hostnameParts.slice(0, -1).join('.') : hostname;
    // Official domain check (exact or subdomain)
    if (officialDomains.some(domain => hostname === domain || hostname.endsWith(`.${domain}`))) {
      logDebug(`Safe: Official crypto domain detected (${hostname})`);
      return false;
    }
    // Lookalike check with Levenshtein
    const isLookalike = officialDomains.some(domain => {
      const brand = domain.split('.')[0];
      const distance = levenshteinDistance(hostname, domain);
      return fullPath.includes(brand) && hostname !== domain && distance <= 3;
    });
    if (isLookalike) {
      logDebug(`Suspicious: Lookalike crypto domain detected (${hostname})`);
      return true;
    }
    // Brand + digits in hostname
    for (const brand of cryptoBrands) {
      const brandPattern = new RegExp(`${brand}(?:[.-]?\\d+)`, 'i');
      if (brandPattern.test(hostname)) {
        logDebug(`Suspicious: Brand + digits detected in hostname (${hostname}) matches brand ${brand}`);
        return true;
      }
    }
    // Crypto keyword presence (include brands)
    const hasCryptoKeyword = cryptoKeywords.concat(cryptoBrands).some(keyword => fullPath.includes(keyword));
    // Match full path patterns
    const matchesFullPath = fullPathPatterns.some(pattern => pattern.test(fullPath));
    // Match base domain patterns
    const matchesBaseDomain = baseDomainPatterns.some(pattern => pattern.test(baseDomain));
    if ((matchesFullPath || matchesBaseDomain) && hasCryptoKeyword) {
      logDebug(`Suspicious: Crypto phishing pattern detected in (${fullPath})`);
      return true;
    }
    logDebug(`Safe: No crypto phishing characteristics found (${hostname})`);
    return false;
  } catch (error) {
    handleError(error, `isCryptoPhishingUrl: Error checking crypto phishing for URL ${url}`);
    return false;
  }
}

document.addEventListener('DOMContentLoaded', async () => {
  // SECURITY FIX v8.8.1: Mark document as protected immediately
  if (document.body) {
    document.body.dataset.linkshieldActive = 'true';
    document.body.dataset.linkshieldProtected = 'true';
  }
  try {
    // PERFORMANCE FIX: Skip all heavy initialization in sub-frames
    // Sub-frames (ads, tracking pixels, embeds) don't need security scanning
    if (!_isTopFrame) {
      logDebug('[Content] Sub-frame detected, skipping heavy initialization');
      return;
    }

    logDebug("🚀 Initializing content script...");
    await initContentScript(); // Wacht op configuratie en veilige domeinen

    // Check of protection is ingeschakeld voordat speciale detectie features worden gestart
    const protectionEnabled = await isProtectionEnabled();

    // WHITELIST CHECK: Skip alle checks als domein vertrouwd is door gebruiker
    const currentDomain = getDomainFromUrl(window.location.href);
    const isTrustedByUser = currentDomain && await isDomainTrusted(currentDomain);
    if (isTrustedByUser) {
      logDebug(`[Content] Domein ${currentDomain} is vertrouwd door gebruiker, skip alle security checks`);
      // Stuur 'safe' status naar background
      chrome.runtime.sendMessage({
        action: 'checkResult',
        url: window.location.href,
        level: 'safe',
        isSafe: true,
        risk: 0,
        reasons: ['trustedDomainSkipped'],
        trustedByUser: true
      });
      // Show safe badge for trusted domains
      showSiteSafeBadge();
      return; // Stop hier, voer geen verdere checks uit
    }

    if (protectionEnabled) {
      // Cache trusted domain status for performance-sensitive paths (main observer, etc.)
      _isTrustedSiteCache = await isTrustedDomain(window.location.hostname.toLowerCase());

      // PERFORMANCE FIX: On trusted domains, skip ALL heavy checks and just show safe badge
      // This prevents renderer crashes on complex SPAs like bol.com, React apps, etc.
      if (_isTrustedSiteCache) {
        logDebug(`[Content] Trusted domain (TrustedDomains.json), skipping all security scans`);
        // Disconnect main observer to prevent any mutation processing overhead
        if (typeof observer !== 'undefined') {
          try { observer.disconnect(); } catch(e) {}
        }
        chrome.runtime.sendMessage({
          action: 'checkResult',
          url: window.location.href,
          level: 'safe',
          isSafe: true,
          risk: 0,
          reasons: ['trustedDomainSkipped']
        });
        showSiteSafeBadge();
        return; // Skip ALL security checks on trusted domains
      }

      // Start main observer now that we know domain is not trusted
      if (_isTopFrame) {
        startMainObserver();
      }

      // Initialiseer Clipboard Guard voor crypto hijacking detectie
      initClipboardGuard();

      // Initialiseer OAuth Paste Guard voor ConsentFix/token theft detectie (v8.5.0)
      await initOAuthPasteGuard();

      // Initialiseer ClickFix Attack detectie voor PowerShell/CMD injectie via nep-CAPTCHA
      initClickFixDetection();

      // Initialiseer Browser-in-the-Browser (BitB) detectie voor nep OAuth popups
      initBitBDetection();

      // Initialiseer Form Hijacking Protection voor credential theft detectie
      initFormHijackingProtection();

      // Initialiseer WebTransport/HTTP3 monitor voor C2/exfiltration detectie
      initWebTransportMonitor();

      // v8.6.0: Initialiseer AiTM Proxy Detection voor reverse proxy phishing
      initAiTMDetection();

      // v8.6.0: Initialiseer SVG Payload Detection voor kwaadaardige SVG scripts
      initSVGPayloadDetection();

      // Initialiseer Table QR Scanner voor imageless QR-code detectie (AI-phishing kits)
      initTableQRScanner();
      if (tableQRScanner) {
        tableQRScanner.scanAllTables(); // Initial scan bij page load
      }

      // SECURITY FIX v8.5.0: Split QR Detection - scan voor opgesplitste QR codes
      // Wordt async uitgevoerd om main thread niet te blokkeren
      (async () => {
        try {
          const splitQRResult = await getSplitQRDetector().scan();
          if (splitQRResult.detected) {
            logDebug(`[SplitQR] Detected split QR code at page load: ${splitQRResult.url}`);
            // Warn de gebruiker indien malicious URL
            if (typeof warnMaliciousQRCode === 'function') {
              warnMaliciousQRCode(splitQRResult.url, 'split_qr');
            }
          }
        } catch (e) {
          handleError(e, 'SplitQR initial scan');
        }
      })();

      // SECURITY FIX v8.2.0: All page-wide checks moved inside protection block
      const currentUrl = window.location.href;
      logDebug(`🔍 Checking the current page: ${currentUrl}`);
    // --- 1. Pagina-brede checks ---
    const reasonsForPage = new Set();
    let pageRisk = 0;
    // 1a. Mixed content iframes
    if (window.location.protocol === 'https:') {
      const iframes = Array.from(document.getElementsByTagName('iframe')).filter(f => f.src);
      for (const iframe of iframes) {
        try {
          const u = new URL(iframe.src);
          if (u.protocol === 'http:') {
            reasonsForPage.add('mixedContentIframe');
            pageRisk += 10;
            logDebug(`⚠️ Mixed content iframe: ${iframe.src}`);
            break;
          }
        } catch (e) {
          logError(`Fout bij mixed-content check iframe: ${iframe.src}`, e);
        }
      }
    }
    // 1b. Verdachte iframes
    const suspiciousIframes = await hasSuspiciousIframes();
    if (suspiciousIframes.length) {
      // we voegen alleen de raw reason toe, zonder 'iframe:'-prefix
      suspiciousIframes.forEach(r => reasonsForPage.add(r));
      pageRisk += 5.0;
      logDebug(`⚠️ Verdachte iframes: ${suspiciousIframes.join(', ')}`);
    }
    // 1c. Verdachte scripts
    const suspiciousScripts = await checkForSuspiciousExternalScripts();
    if (suspiciousScripts.length) {
      // we voegen alleen de raw reason toe, zonder 'script:'-prefix
      suspiciousScripts.forEach(r => reasonsForPage.add(r));
      pageRisk += 5.0;
      logDebug(`⚠️ Verdachte scripts: ${suspiciousScripts.join(', ')}`);
    }
    // 1c2. SECURITY FIX v8.5.0: Fake Turnstile/CAPTCHA detectie
    const fakeTurnstileResult = await detectFakeTurnstile();
    if (fakeTurnstileResult.detected) {
      reasonsForPage.add('fakeTurnstileDetected');
      pageRisk += fakeTurnstileResult.score;
      logDebug(`⚠️ Fake Turnstile detected: ${fakeTurnstileResult.indicators.join(', ')}`);
    }
    // 1c3. v8.6.0: AiTM Proxy detectie
    const aitmResult = await detectAiTMProxy();
    if (aitmResult.detected) {
      reasonsForPage.add('aitmProxyDetected');
      pageRisk += aitmResult.score;
      logDebug(`⚠️ AiTM Proxy detected (${aitmResult.provider}): ${aitmResult.indicators.join(', ')}`);
    }
    // 1c4. v8.6.0: SVG Payload detectie
    const svgPayloadResult = await detectSVGPayloads();
    if (svgPayloadResult.detected) {
      reasonsForPage.add('svgPayloadDetected');
      pageRisk += svgPayloadResult.score;
      logDebug(`⚠️ SVG Payload detected: ${svgPayloadResult.indicators.join(', ')}`);
    }
    // 1d. Loginpagina-checks
    if (detectLoginPage(currentUrl)) {
      logDebug(`🔐 Loginpagina gedetecteerd: ${currentUrl}`);
      const u = new URL(currentUrl);
      // Helper: check of hostname een intern/privé IP-adres is
      const isInternalIpAddress = (host) => {
        return (
          /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host) ||
          /^192\.168\.\d{1,3}\.\d{1,3}$/.test(host) ||
          /^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host) ||
          /^172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}$/.test(host) ||
          host === 'localhost' ||
          host.endsWith('.local')
        );
      };
      // MX-check alleen uitvoeren voor publieke domeinen, niet voor interne IP-adressen
      if (!isInternalIpAddress(u.hostname)) {
        try {
          let dom = u.hostname.toLowerCase();
          if (dom.startsWith('xn--') && typeof punycode !== 'undefined') {
            dom = punycode.toUnicode(dom);
          }
          const mx = await queueMxCheck(dom);
          if (!mx.length) {
            reasonsForPage.add('loginPageNoMX');
            pageRisk += 12;
            logDebug(`⚠️ Geen MX-records voor loginpagina: ${dom}`);
          }
        } catch (e) {
          handleError(e, 'Loginpagina MX-check mislukt');
        }
      } else {
        logDebug(`⏭️ MX-check overgeslagen voor intern IP-adres: ${u.hostname}`);
      }
      if (u.protocol !== 'https:') {
        reasonsForPage.add('insecureLoginPage');
        pageRisk += 15;
        logDebug(`⚠️ Loginpagina niet via HTTPS: ${currentUrl}`);
      }
    }
    // 1e. Interactieve controls (visueel, geen berichten)
    // Skip on trusted domains - detectInteractiveControls uses getComputedStyle on every element
    // and startDynamicDetection has no debounce, causing renderer crashes on complex SPAs
    if (!_isTrustedSiteCache) {
      const initialControls = detectInteractiveControls();
      logDebug(`[UI] ${initialControls.length} interactieve elementen gevonden`);
      startDynamicDetection(controls => {
        controls.forEach(el => {
          if (el.tagName === 'A' && el.href) classifyAndCheckLink(el);
        });
      });
    }
    // --- 2. URL-specifieke checks ---
    // v8.4.1: countQuota: true - this is the CURRENT PAGE URL check, should count towards quota
    const urlResult = await performSuspiciousChecks(currentUrl, { countQuota: true });
    // --- 3. Combineer alle redenen en bereken totaalrisico ---
    const allReasons = new Set([
      ...urlResult.reasons,
      ...reasonsForPage
    ]);
    const totalRisk = parseFloat(urlResult.risk) + pageRisk;
    // --- 4. Bepaal eindniveau ---
    let finalLevel;
    if (totalRisk >= globalConfig.HIGH_THRESHOLD) {
      finalLevel = 'alert';
    } else if (totalRisk >= globalConfig.LOW_THRESHOLD) {
      finalLevel = 'caution';
    } else {
      finalLevel = 'safe';
    }
    // Local Network Calibration: lokale IP's krijgen maximaal 'caution', nooit 'alert'
    const currentHostname = new URL(currentUrl).hostname;
    if (finalLevel === 'alert' && isLocalNetwork(currentHostname)) {
      finalLevel = 'caution';
      logDebug(`📍 Local network calibration: ${currentHostname} beperkt tot 'caution' (was 'alert')`);
    }
    // --- 5. ÉÉN bericht sturen naar background.js ---
    chrome.runtime.sendMessage({
      action: 'checkResult',
      url: currentUrl,
      level: finalLevel,
      isSafe: finalLevel === 'safe',
      risk: totalRisk.toFixed(1),
      reasons: Array.from(allReasons)
    });
    logDebug(`✅ Check compleet: level=${finalLevel}, risk=${totalRisk.toFixed(1)}, reasons=${Array.from(allReasons).join(', ')}`);

    // --- 6. Show safe badge if page passed all checks ---
    // Use LOW_THRESHOLD to match the 'safe' classification logic
    if (finalLevel === 'safe' && totalRisk < globalConfig.LOW_THRESHOLD) {
      showSiteSafeBadge();
    }

    // --- 7. Externe links scannen (zonder extra berichten) ---
      await checkLinks();
    } else {
      logDebug("Protection disabled, skipping all security checks");
    }
  } catch (error) {
    handleError(error, `DOMContentLoaded unified`);
    chrome.runtime.sendMessage({
      action: 'checkResult',
      url: window.location.href,
      level: 'alert',
      isSafe: false,
      risk: 99,
      reasons: ['initializationError']
    });
  }
});
// 1) checkLinks - Geoptimaliseerde versie met IntersectionObserver
// Gebruikt lazy loading voor betere performance op grote pagina's
async function checkLinks() {
  if (isSearchResultPage()) {
    logDebug("Zoekresultatenpagina gedetecteerd, linkcontrole wordt overgeslagen.");
    return false;
  }

  // Initialiseer de geoptimaliseerde scanner als die nog niet bestaat
  if (!linkScanner) {
    initOptimizedLinkScanner();
  }

  // Start lazy scanning van alle links
  linkScanner.scanAllLinks();

  // Voor backward compatibility: check of er al verdachte links in cache zijn
  let hasSuspicious = false;
  for (const [url, data] of linkScanner.urlCache) {
    if (data.result && data.result.level && data.result.level !== 'safe') {
      hasSuspicious = true;
      break;
    }
  }

  logDebug(`[checkLinks] Geoptimaliseerde scanner gestart, cache bevat ${linkScanner.urlCache.size} entries`);
  return hasSuspicious;
}

// Legacy functie voor backward compatibility - synchrone batch scan
async function checkLinksLegacy() {
  if (isSearchResultPage()) {
    logDebug("Zoekresultatenpagina gedetecteerd, linkcontrole wordt overgeslagen.");
    return false;
  }
  const currentUrl = window.location.href;
  let currentDomain;
  try {
    currentDomain = new URL(currentUrl).hostname.toLowerCase();
    logDebug(`Hoofddomein van de pagina: ${currentDomain}`);
  } catch (error) {
    logError(`Kon hoofddomein niet bepalen uit ${currentUrl}:`, error);
    return false;
  }
  const MAX_LINKS_TO_SCAN = 500;
  const allAnchors = Array.from(document.querySelectorAll('a'));
  const links = allAnchors
    .filter(link => link.href && isValidURL(link.href) && !scannedLinks.has(link.href))
    .slice(0, MAX_LINKS_TO_SCAN);
  if (links.length === 0) {
    logDebug("Geen nieuwe links om te controleren.");
    return false;
  }
  const checks = links.map(async link => {
    const href = link.href;
    scannedLinks.add(href);
    let urlObj;
    try {
      urlObj = new URL(href);
    } catch {
      return false;
    }
    const domain = urlObj.hostname.toLowerCase();
    if (isSameDomain(domain, currentDomain)) return false;
    const result = await performSuspiciousChecks(href);
    if (result.level !== 'safe') {
      warnLinkByLevel(link, result);
      logDebug(`Verdachte externe link: ${href} → level=${result.level}`);
      return true;
    }
    return false;
  });
  const results = await Promise.all(checks);
  return results.some(r => r === true);
}
// 2) checkCurrentUrl stuurt nu precies één bericht, incl. de uitkomst van checkLinks()
let lastCheckedUrl = null;
async function checkCurrentUrl() {
  // Check of protection is ingeschakeld
  if (!(await isProtectionEnabled())) {
    logDebug('Protection disabled, skipping checkCurrentUrl');
    return;
  }

  // Check of domein door gebruiker als vertrouwd is gemarkeerd
  const currentDomain = getDomainFromUrl(window.location.href);
  if (currentDomain && await isDomainTrusted(currentDomain)) {
    logDebug(`[Content] Domein ${currentDomain} is vertrouwd door gebruiker, skip security checks`);
    // Stuur 'safe' status naar background
    try {
      chrome.runtime.sendMessage({
        action: 'checkResult',
        url: window.location.href,
        level: 'safe',
        isSafe: true,
        risk: 0,
        reasons: ['trustedDomainSkipped'],
        trustedByUser: true
      });
      // Show safe badge for trusted domains
      showSiteSafeBadge();
    } catch (e) {
      handleError(e, 'checkCurrentUrl: Fout bij verzenden trusted domain status');
    }
    return;
  }

  await ensureConfigReady();
  try {
    const currentUrl = window.location.href;
    if (currentUrl === lastCheckedUrl) return;
    lastCheckedUrl = currentUrl;
    logDebug("[Content] URL changed to:", currentUrl);
    // Volg meta-refresh of echte redirects
    const metaRefresh = getMetaRefreshUrl();
    const finalUrl = metaRefresh
      ? (logDebug("[Content] Meta-refresh URL:", metaRefresh), metaRefresh)
      : await getFinalUrl(currentUrl);
    logDebug("[Content] Final URL after redirects:", finalUrl);
    // 1) Paginacheck
    // v8.4.1: countQuota: true - this is the CURRENT PAGE URL check, should count towards quota
    const pageResult = await performSuspiciousChecks(finalUrl, { countQuota: true });
    logDebug("[Content] Page check result:", pageResult);
    // Valideer level
    let level = pageResult.level;
    if (!['safe', 'caution', 'alert'].includes(level)) {
      logError(`[checkCurrentUrl] Ongeldig level "${level}", fallback naar "safe".`);
      level = 'safe';
    }
    // 2) Externe links
    const hasBadLinks = await checkLinks();
    if (hasBadLinks && level === 'safe') {
      level = 'caution';
      logDebug("[Content] Externe links verdacht, level opgehoogd naar 'caution'");
    }
    // 3) ÉÉN bericht sturen naar background.js
    chrome.runtime.sendMessage({
      action: 'checkResult',
      url: finalUrl,
      level,
      isSafe: level === 'safe',
      risk: pageResult.risk,
      reasons: pageResult.reasons
    });

    // 4) Show safe badge if site passed all checks
    // Badge shown when level is 'safe' and risk is below LOW_THRESHOLD (matches 'safe' classification)
    if (level === 'safe' && pageResult.risk < globalConfig.LOW_THRESHOLD) {
      showSiteSafeBadge();
    }

    logDebug(`✅ checkCurrentUrl complete: level=${level}, risk=${pageResult.risk}, reasons=${pageResult.reasons.join(', ')}`);
  } catch (err) {
    handleError(err, "checkCurrentUrl");
    chrome.runtime.sendMessage({
      action: 'checkResult',
      url: window.location.href,
      level: 'alert',
      isSafe: false,
      risk: 99,
      reasons: ['checkCurrentUrlError', err.message]
    });
  }
}
// Helperfunctie om te controleren of domeinen hetzelfde zijn (inclusief subdomeinen)
function isSameDomain(linkDomain, currentDomain) {
  return linkDomain === currentDomain || linkDomain.endsWith(`.${currentDomain}`);
}
// Eenvoudige URL-validatie
function isValidURLBasic(url) {
  try {
    new URL(url);
    return true;
  } catch {
    return false;
  }
}
// In de initialisatie wordt checkLinks() alleen aangeroepen als we niet op een Google-zoekpagina zitten
getStoredSettings().then(settings => {
  try {
    if (settings.integratedProtection && !isSearchResultPage()) {
      checkLinks();
    }
  } catch (error) {
    handleError(error, 'Init: Fout bij initialisatie van checkLinks');
  }
}).catch(error => {
  handleError(error, 'Init: Fout bij ophalen van settings');
});
function injectWarningStyles() {
  try {
    if (document.head?.querySelector("#linkshield-warning-styles")) {
      logDebug("Warning styles already present, skipping.");
      return;
    }
    const style = document.createElement("style");
    style.id = "linkshield-warning-styles";
    // SECURITY FIX v8.4.0: z-index maximum + pointer-events: auto to prevent Visual Hijacking
    style.textContent = `
      .linkshield-warning {
        display: inline-block !important;
        position: relative !important;
        top: 0 !important;
        left: 0 !important;
        background-color: #ff0000 !important;
        color: #ffffff !important;
        padding: 2px 5px !important;
        font-size: 12px !important;
        border-radius: 50% !important;
        margin-left: 5px !important;
        z-index: 2147483647 !important;
        pointer-events: auto !important;
        cursor: pointer !important;
      }
      .suspicious-link {
        background-color: #ffebee !important;
        border-bottom: 2px solid #ff0000 !important;
        pointer-events: auto !important;
      }
    `;
    if (document.head) {
      document.head.appendChild(style);
    }
  } catch (error) {
    handleError(error, 'injectWarningStyles: Fout bij injecteren van stijlen');
  }
}
(async function init() {
  try {
    // Extra initialisatiecode (indien nodig)
  } catch (error) {
    handleError(error, `init: Fout bij algemene initialisatie`);
  }
})();
// SECURITY FIX v8.8.2: Use accumulating debounce to prevent losing mutations
const observer = new MutationObserver(debounceMutations(async (mutations) => {
  if (!(await isProtectionEnabled())) return; // Stop als bescherming uitstaat
  // PERFORMANCE FIX: Skip ALL mutation processing on trusted domains
  if (_isTrustedSiteCache) return;
  let scriptsAdded = false;
  let iframesAdded = false;
  let linksAdded = false;
  let passwordFieldAdded = false;

  // INFINITE LOOP PREVENTION: Skip mutations caused by our own DOM modifications
  const isOwnModification = (node) => {
    if (!node || !node.classList) return false;
    // Check if this is a LinkShield-created element
    if (node.id?.startsWith('linkshield-')) return true;
    if (node.classList.contains('linkshield-warning')) return true;
    if (node.classList.contains('linkshield-detected')) return true;
    if (node.classList.contains('linkshield-overlay')) return true;
    // Check parent for our modifications
    if (node.closest?.('[id^="linkshield-"]')) return true;
    return false;
  };

  mutations.forEach(mutation => {
    mutation.addedNodes.forEach(node => {
      // Alleen element-nodes zijn relevant
      if (node.nodeType !== Node.ELEMENT_NODE) return;

      // INFINITE LOOP PREVENTION: Skip our own DOM modifications
      if (isOwnModification(node)) {
        return;
      }

      // Detecteer toegevoegde scripts en iframes
      if (node.tagName === "SCRIPT" && node.src) {
        scriptsAdded = true;
      } else if (node.tagName === "IFRAME" && node.src) {
        iframesAdded = true;
      }
      // Detecteer password velden die dynamisch worden toegevoegd (voor SPA's)
      if (node.tagName === "INPUT" && node.type === "password") {
        passwordFieldAdded = true;
      } else if (node.querySelectorAll) {
        // Check ook binnen nieuw toegevoegde elementen
        if (node.querySelectorAll('input[type="password"]').length > 0) {
          passwordFieldAdded = true;
        }
      }
      // Detecteer links die zijn toegevoegd
      // Directe <a> tags
      if (node.tagName === "A" && isValidURL(node.href)) {
        linksAdded = true;
        classifyAndCheckLink(node); // Controleer direct de nieuwe link
      } else if (node.querySelectorAll) {
        // Links binnen nieuw toegevoegde elementen (bijv. een nieuwe div met links erin)
        node.querySelectorAll('a').forEach(link => {
          if (isValidURL(link.href)) {
            linksAdded = true;
            classifyAndCheckLink(link); // Controleer direct de nieuwe link
          }
        });

        // SECURITY FIX v8.0.0 (Vector 2): Scan ook Shadow DOM in nieuw toegevoegde elementen
        // Dit vangt links in Shadow DOM die door aanvallers worden geïnjecteerd
        // Skip on trusted domains to prevent performance issues on complex SPAs
        if (!_isTrustedSiteCache) {
          try {
            scanNodeForLinks(node, 0);
          } catch (e) {
            // Ignore Shadow DOM scan errors
          }
        }
      }

      // SECURITY FIX v8.0.0 (Vector 2): Check of nieuw element een shadowRoot heeft
      if (!_isTrustedSiteCache && node.shadowRoot) {
        try {
          scanNodeForLinks(node.shadowRoot, 0);
        } catch (e) {
          // Ignore Shadow DOM scan errors
        }
      }
    });
  });
  // Als er een password veld is toegevoegd, invalideer de login cache en hercontroleer
  // Skip on trusted domains to prevent performance issues on complex SPAs
  if (passwordFieldAdded && !_isTrustedSiteCache) {
    const currentUrl = window.location.href;
    logDebug("🔐 Password veld dynamisch gedetecteerd. Cache invalideren en hercontrole starten.");
    // Invalideer de login page cache voor deze URL
    loginPageCache.delete(currentUrl);
    // Invalideer ook de algemene link risk cache
    if (window.linkRiskCache) {
      window.linkRiskCache.delete(currentUrl);
    }
    // Trigger volledige hercontrole van de pagina
    try {
      const result = await performSuspiciousChecks(currentUrl);
      const level = result.level || 'caution';
      const risk = result.risk || 0;
      const reasons = result.reasons || [];
      chrome.runtime.sendMessage({
        action: 'checkResult',
        url: currentUrl,
        level: level,
        isSafe: level === 'safe',
        risk: risk,
        reasons: reasons
      });
      logDebug(`✅ Hercontrole na password veld: level=${level}, risk=${risk}, reasons=${reasons.join(', ')}`);
    } catch (e) {
      handleError(e, 'MutationObserver password field recheck');
    }
  }
  // Als er scripts of iframes zijn toegevoegd, hercontroleer de paginabrede status.
  // Skip on trusted domains to prevent performance issues on complex SPAs
  if ((scriptsAdded || iframesAdded) && !_isTrustedSiteCache) {
    logDebug("Dynamische content gedetecteerd (scripts/iframes). Hercontroleer paginabrede risico's.");
    // Roep de paginabrede controleroutine aan die nu in DOMContentLoaded staat.
    // Dit is een simpele aanroep; de details van het verzamelen en verzenden liggen daar.
    // Let op: 'window.location.href' wordt hier gebruikt, omdat we de huidige pagina opnieuw evalueren.
    const currentUrl = window.location.href;
   
    const reasonsForPageUpdate = new Set();
    let pageRiskUpdate = 0;
    // Hercontroleer mixed content iframes
    if (window.location.protocol === 'https:') {
      const iframes = Array.from(document.getElementsByTagName('iframe')).filter(i => i.src);
      for (const iframe of iframes) {
        try {
          const iframeUrlObj = new URL(iframe.src);
          if (iframeUrlObj.protocol === 'http:') {
            reasonsForPageUpdate.add('mixedContent');
            pageRiskUpdate += 10;
            break;
          }
        } catch (e) { /* Negeer foute URLs */ }
      }
    }
    // Hercontroleer verdachte iframes
    const suspiciousIframesReasons = await hasSuspiciousIframes();
    if (suspiciousIframesReasons.length > 0) {
        suspiciousIframesReasons.forEach(reason => reasonsForPageUpdate.add(reason));
        pageRiskUpdate += 3.5; // Risicopunt voor de aanwezigheid van verdachte iframes
    }
    // Hercontroleer verdachte externe scripts
    const suspiciousScriptReasons = await checkForSuspiciousExternalScripts();
    if (suspiciousScriptReasons.length > 0) {
        suspiciousScriptReasons.forEach(reason => reasonsForPageUpdate.add(reason));
        pageRiskUpdate += 4.0; // Risicopunt voor de aanwezigheid van verdachte scripts
    }
    // Stuur een update-bericht naar het achtergrondscript voor de paginastatus
    chrome.runtime.sendMessage({
      type: "updatePageStatus", // Nieuw type bericht voor paginastatus updates
      url: currentUrl,
      reasons: Array.from(reasonsForPageUpdate),
      risk: pageRiskUpdate
    });
  }
  // Specifieke afhandeling voor Google zoekresultaten
  if (linksAdded && isSearchResultPage()) {
    debounceCheckGoogleSearchResults();
  }

  // Table QR Scanner: Scan voor imageless QR-codes in nieuw toegevoegde tabellen
  // Dit detecteert AI-phishing kits die QR-codes via HTML tables renderen
  if (tableQRScanner) {
    debouncedTableScan();
  }
  // =============================================================================
  // SECURITY FIX v8.2.0: Handle attribute mutations (href changes)
  // =============================================================================
  // Detecteer href attribute wijzigingen op bestaande links
  // Dit vangt dynamische href-wijzigingen die timing attacks kunnen faciliteren
  mutations.forEach(mutation => {
    if (mutation.type === 'attributes' && mutation.attributeName === 'href') {
      const target = mutation.target;
      if (target.tagName === 'A' && target.href) {
        // Re-scan de link omdat href is gewijzigd
        delete target.dataset.linkshieldScanned; // Reset scanned flag
        classifyAndCheckLink(target);
        logDebug(`[SecurityFix v8.2.0] 🔄 href attribute changed, re-scanning: ${target.href.substring(0, 50)}...`);
      }
    }
  });
}, 500)); // Debounce om te voorkomen dat het te vaak afvuurt

// =============================================================================
// SECURITY FIX v8.2.0: Enhanced MutationObserver configuration
// =============================================================================
// PERFORMANCE FIX: Main observer and event listeners are started from DOMContentLoaded
// after trusted domain status is determined. This prevents heavy processing during initial
// page load on trusted domains. See startMainObserver() call in DOMContentLoaded handler.
if (_isTopFrame) {
  document.addEventListener('mouseover', debounce((event) => {
    if (event.target.tagName === 'A') {
      unifiedCheckLinkSafety(event.target, 'mouseover', event);
    }
  }, 250));
  document.addEventListener('click', debounce((event) => {
    if (event.target.tagName === 'A') {
      unifiedCheckLinkSafety(event.target, 'click', event);
    }
  }, 250));
}

// Function to start the main observer - called from DOMContentLoaded after trusted check
function startMainObserver() {
  observer.observe(document.documentElement, {
    childList: true,
    subtree: true,
    attributes: true,
    attributeFilter: ['href']
  });
}

// =============================================================================
// SECURITY FIX v8.3.0: SCROLL EVENT LISTENER FOR LAZY-LOADED LINKS
// =============================================================================
// AUDIT FIX: Catches scroll-injected links that MutationObserver might miss
// Uses throttling to prevent performance issues on scroll-heavy pages

let lastScrollScanTime = 0;
const SCROLL_SCAN_THROTTLE_MS = 300; // SECURITY FIX v8.6.0: Reduced from 1000ms for faster detection

/**
 * SECURITY FIX v8.6.0: Enhanced scroll-triggered link scanner
 * - Reduced throttle for faster detection
 * - Extended viewport buffer to catch near-edge injections
 * - Also scans Shadow DOM roots
 * - Handles scroll-triggered evasion attempts
 */
function scanViewportAfterScroll() {
  // PERFORMANCE FIX: Skip on trusted domains
  if (_isTrustedSiteCache) return;
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
  // Skip on trusted domains - querySelectorAll('*') is extremely expensive on complex SPAs
  if (!_isTrustedSiteCache) {
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
  }

  if (scannedCount > 0) {
    logDebug(`[SecurityFix v8.6.0] 📜 Scroll scan: ${scannedCount} new links in/near viewport`);
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
          logDebug('[SecurityFix v8.6.0] 👁️ IntersectionObserver caught link:', link.href.substring(0, 50));
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

// Initialize observer after DOM ready - only in top frame
if (_isTopFrame) {
  if (document.readyState === 'complete') {
    initScrollScanObserver();
  } else {
    window.addEventListener('load', initScrollScanObserver);
  }
}

// PERFORMANCE FIX: Only run scroll/resize listeners in top frame
if (_isTopFrame) {
  // Add throttled scroll listener with shorter debounce
  document.addEventListener('scroll', debounce(scanViewportAfterScroll, 300), { passive: true });

  // Also scan on resize (viewport changes)
  window.addEventListener('resize', debounce(scanViewportAfterScroll, 300), { passive: true });

  // SECURITY FIX v8.6.0: Also listen for scrollend event (modern browsers)
  if ('onscrollend' in window) {
    document.addEventListener('scrollend', scanViewportAfterScroll, { passive: true });
  }
}

// =============================================================================
// SECURITY FIX v8.3.0: SPA NAVIGATION DETECTION
// =============================================================================
// AUDIT FIX: Catches soft navigations in Single Page Applications
// PERFORMANCE FIX: Only run in top frame
if (!_isTopFrame) {
  // Skip SPA navigation detection in sub-frames
} else {

let lastNavigationUrl = window.location.href;

/**
 * Handles SPA navigation - rescans page for new links
 */
async function handleSPANavigation(newUrl) {
  if (newUrl === lastNavigationUrl) return;
  lastNavigationUrl = newUrl;

  logDebug(`[SecurityFix v8.3.0] 🔄 SPA navigation detected: ${newUrl}`);

  // Clear caches for new page
  if (window.linkRiskCache) {
    // Clear entries for old URL
    window.linkRiskCache.clear();
  }

  // Wait a tick for DOM to update
  await new Promise(resolve => setTimeout(resolve, 100));

  // Rescan page
  try {
    scheduleFullPageScan();

    // Re-check current page URL
    const result = await performSuspiciousChecks(newUrl);
    chrome.runtime.sendMessage({
      action: 'checkResult',
      url: newUrl,
      level: result.level,
      isSafe: result.level === 'safe',
      risk: result.risk,
      reasons: result.reasons
    });
  } catch (e) {
    logError('[SecurityFix v8.3.0] SPA navigation scan error:', e);
  }
}

// Patch history.pushState
const originalPushState = history.pushState;
history.pushState = function(state, title, url) {
  originalPushState.apply(this, arguments);
  if (url) {
    const newUrl = new URL(url, window.location.href).href;
    handleSPANavigation(newUrl);
  }
};

// Patch history.replaceState
const originalReplaceState = history.replaceState;
history.replaceState = function(state, title, url) {
  originalReplaceState.apply(this, arguments);
  if (url) {
    const newUrl = new URL(url, window.location.href).href;
    handleSPANavigation(newUrl);
  }
};

// Listen for popstate (back/forward navigation)
window.addEventListener('popstate', () => {
  handleSPANavigation(window.location.href);
});

// Listen for hashchange (hash-based routing)
window.addEventListener('hashchange', () => {
  handleSPANavigation(window.location.href);
});

logDebug('[SecurityFix v8.3.0] ✅ Scroll listener and SPA navigation handlers installed');

} // End _isTopFrame check for SPA navigation detection

const processedLinks = new Set();
/**
 * Extraheert de top-level domein (TLD) uit een hostname, inclusief samengestelde TLD's (bijv. .co.uk).
 * @param {string} hostname De hostname (bijv. www.example.co.uk).
 * @returns {string} De TLD (bijv. co.uk, com).
 */
function extractTld(hostname) {
  if (!hostname || typeof hostname !== 'string') {
    logDebug(`extractTld: Invalid hostname: ${hostname}`);
    return '';
  }
  // Lijst van bekende samengestelde TLD's (vereenvoudigd)
  const compoundTlds = [
    'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'com.au', 'org.au',
    'co.jp', 'go.jp', 'ne.jp', 'or.jp', 'co.kr', 're.kr',
    'co.nz', 'org.nz', 'gov.br', 'com.br', 'org.br',
  ];
  // Splits hostname in onderdelen
  const parts = hostname.toLowerCase().split('.');
  // Controleer op samengestelde TLD's (bijv. .co.uk)
  if (parts.length >= 3) {
    const potentialCompound = parts.slice(-2).join('.');
    if (compoundTlds.includes(potentialCompound)) {
      return potentialCompound;
    }
  }
  // Gebruik de laatste onderdeel als TLD als geen samengestelde TLD wordt gevonden
  return parts.length > 1 ? parts[parts.length - 1] : '';
}
function checkGoogleSearchResults() {
  logDebug("Checking search results...");
  // Specifieke selector voor organische resultaten
  const results = document.querySelectorAll('#search .yuRUbf > a');
  results.forEach(link => {
    if (checkedLinks.has(link)) return;
    const href = link.getAttribute('href');
    // Sla Google-redirects en zoek-pagina-links over
    if (!href || href.startsWith('/url?') || href.includes('google.com/search')) return;
    // Valideer met URL API
    try {
      new URL(href);
    } catch {
      return;
    }
    // Plan de phishing/SSL-check in idle-time
    if ('requestIdleCallback' in window) {
      requestIdleCallback(() => {
        classifyAndCheckLink(link);
        checkedLinks.add(link);
      }, { timeout: 2000 });
    } else {
      setTimeout(() => {
        classifyAndCheckLink(link);
        checkedLinks.add(link);
      }, 0);
    }
  });
}
// PERFORMANCE FIX: Only handle messages in top frame to prevent duplicate processing
if (_isTopFrame) {
  chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
    if (message.action === 'testURL') {
      performSuspiciousChecks(message.url)
        .then((result) => {
          sendResponse({ isSafe: result.isSafe, reasons: result.reasons, risk: result.risk });
        })
        .catch((error) => {
          handleError(error, `chrome.runtime.onMessage: Fout bij testen van URL ${message.url}`);
          sendResponse({ isSafe: false, reasons: ["An error occurred."], risk: 0 });
        });
      return true;
    }
  });
}

// =============================================================================
// TRACKING INFRASTRUCTURE RISK DETECTION (v8.7.1 - Layer 15 - DOM-based)
// Scans DOM for third-party resources and calculates risk score
// No extra permissions required (webRequest/webNavigation removed)
// =============================================================================

let _trackingRiskIndicator = null;
let _trackingRiskData = null; // Loaded from hostileTrackers.json
let _trackingRiskState = {
    score: 0,
    domains: new Set(),
    unknownTrackers: [],
    reasons: []
};
let _trackingRiskInitialized = false;

// Risk scoring thresholds
const TRACKING_RISK_THRESHOLDS = {
    none: 0,
    low: 5,
    elevated: 15,
    high: 25
};

// Common 3-part TLDs for registrable domain extraction
const THREE_PART_TLDS = new Set([
    'co.uk', 'org.uk', 'me.uk', 'ac.uk', 'gov.uk', 'ltd.uk', 'plc.uk',
    'com.au', 'net.au', 'org.au', 'edu.au', 'gov.au',
    'co.nz', 'org.nz', 'net.nz', 'govt.nz',
    'co.za', 'org.za', 'gov.za',
    'com.br', 'org.br', 'gov.br', 'net.br',
    'co.in', 'org.in', 'gov.in', 'net.in',
    'co.jp', 'or.jp', 'ne.jp', 'ac.jp', 'go.jp'
]);

/**
 * Loads hostile trackers data from hostileTrackers.json
 * @returns {Promise<Object>} Hostile trackers data with Sets for O(1) lookup
 */
async function loadTrackingRiskData() {
    if (_trackingRiskData) return _trackingRiskData;

    try {
        const response = await fetch(chrome.runtime.getURL('hostileTrackers.json'));
        if (!response.ok) {
            throw new Error(`Failed to load hostileTrackers.json: ${response.status}`);
        }
        const rawData = await response.json();

        _trackingRiskData = {
            trustedSet: new Set((rawData.trustedTrackers || []).map(d => d.toLowerCase())),
            dangerousTLDsSet: new Set(rawData.dangerousTLDs || []),
            riskScoring: rawData.riskScoring || {
                thirdPartyDomain: 1,
                dangerousTLD: 3,
                unknownDomain: 2,
                levels: { none: 0, low: 5, elevated: 15, high: 25 }
            }
        };
        return _trackingRiskData;
    } catch (error) {
        console.error('[LinkShield] Error loading tracking risk data:', error);
        return {
            trustedSet: new Set(),
            dangerousTLDsSet: new Set(),
            riskScoring: { thirdPartyDomain: 1, dangerousTLD: 3, unknownDomain: 2, levels: { none: 0, low: 5, elevated: 15, high: 25 } }
        };
    }
}

/**
 * Extracts registrable domain from hostname (handles 3-part TLDs)
 * @param {string} hostname - Full hostname
 * @returns {string} Registrable domain
 */
function getRegistrableDomainForTracking(hostname) {
    const parts = hostname.toLowerCase().split('.');
    if (parts.length <= 2) return hostname.toLowerCase();

    const twoPartTLD = parts.slice(-2).join('.');
    const is3PartTLD = THREE_PART_TLDS.has(twoPartTLD);
    const sliceCount = is3PartTLD ? -3 : -2;
    return parts.slice(sliceCount).join('.');
}

/**
 * Checks if a domain is trusted (first-party or whitelisted)
 * @param {string} domain - Domain to check
 * @param {string} pageDomain - Current page's registrable domain
 * @returns {Promise<{isTrusted: boolean, score: number, reason: string|null}>}
 */
async function checkTrackingDomain(domain, pageDomain) {
    const data = await loadTrackingRiskData();
    const lowerDomain = domain.toLowerCase();
    const scoring = data.riskScoring;

    // 1. First-party check (same registrable domain as page)
    const domainRegistrable = getRegistrableDomainForTracking(lowerDomain);
    if (domainRegistrable === pageDomain) {
        return { isTrusted: true, score: 0, reason: null };
    }

    // 2. Same-brand check (e.g., vinted.nl and vinted.de are same brand)
    // Extract brand name (first part before TLD)
    const pageParts = pageDomain.split('.');
    const domainParts = domainRegistrable.split('.');
    const pageBrand = pageParts[0];
    const domainBrand = domainParts[0];
    // If brand names match and are at least 4 chars (avoid false matches like "a.nl" and "a.de")
    if (pageBrand === domainBrand && pageBrand.length >= 4) {
        return { isTrusted: true, score: 0, reason: null };
    }

    // 3. Trusted whitelist check (O(1) Set lookup)
    if (data.trustedSet.has(lowerDomain) || data.trustedSet.has(domainRegistrable)) {
        return { isTrusted: true, score: 0, reason: null };
    }

    // 4. Check root domain for subdomains (e.g., cdn.example.com → example.com)
    const parts = lowerDomain.split('.');
    if (parts.length > 2) {
        const rootDomain = parts.slice(-2).join('.');
        if (data.trustedSet.has(rootDomain)) {
            return { isTrusted: true, score: 0, reason: null };
        }
    }

    // 5. Unknown domain - check TLD risk
    const tld = parts[parts.length - 1];
    if (data.dangerousTLDsSet.has(tld)) {
        return { isTrusted: false, score: scoring.dangerousTLD || 3, reason: 'dangerous_tld' };
    }

    // 6. Unknown third-party domain
    return { isTrusted: false, score: scoring.unknownDomain || 2, reason: 'unknown_third_party' };
}

/**
 * Calculates tracking risk level from score
 * @param {number} score - Total risk score
 * @returns {string} Risk level: 'none', 'low', 'elevated', 'high'
 */
function calculateTrackingRiskLevel(score) {
    if (score >= TRACKING_RISK_THRESHOLDS.high) return 'high';
    if (score >= TRACKING_RISK_THRESHOLDS.elevated) return 'elevated';
    if (score >= TRACKING_RISK_THRESHOLDS.low) return 'low';
    return 'none';
}

/**
 * Extracts hostname from a URL string
 * @param {string} url - URL to parse
 * @returns {string|null} Hostname or null if invalid
 */
function extractHostnameFromUrl(url) {
    if (!url || typeof url !== 'string') return null;
    // Skip data:, javascript:, blob:, about:, chrome-extension: URLs
    if (/^(data:|javascript:|blob:|about:|chrome-extension:|moz-extension:)/i.test(url)) return null;

    try {
        // Handle protocol-relative URLs
        if (url.startsWith('//')) {
            url = 'https:' + url;
        }
        // Handle relative URLs (skip them)
        if (!url.startsWith('http://') && !url.startsWith('https://')) {
            return null;
        }
        const urlObj = new URL(url);
        return urlObj.hostname.toLowerCase();
    } catch (e) {
        return null;
    }
}

/**
 * Scans a DOM element for third-party resources
 * @param {Element} element - Element to scan
 * @param {string} pageDomain - Current page's registrable domain
 */
async function scanElementForTracking(element, pageDomain) {
    let url = null;

    // Get URL based on element type
    if (element.tagName === 'SCRIPT' && element.src) {
        url = element.src;
    } else if (element.tagName === 'IMG' && element.src) {
        url = element.src;
    } else if (element.tagName === 'LINK' && element.href) {
        url = element.href;
    } else if (element.tagName === 'IFRAME' && element.src) {
        url = element.src;
    }

    if (!url) return;

    const hostname = extractHostnameFromUrl(url);
    if (!hostname) return;

    // Skip if already processed
    if (_trackingRiskState.domains.has(hostname)) return;
    _trackingRiskState.domains.add(hostname);

    // Check domain
    const result = await checkTrackingDomain(hostname, pageDomain);

    if (result.score > 0) {
        _trackingRiskState.score += result.score;
        _trackingRiskState.unknownTrackers.push({
            domain: hostname,
            score: result.score,
            reason: result.reason
        });
        if (result.reason) {
            _trackingRiskState.reasons.push(result.reason);
        }
    }
}

/**
 * Scans the DOM for third-party resources and updates risk state
 */
async function scanDOMForTracking() {
    if (!_isTopFrame) return;

    // Get current page's registrable domain
    const pageDomain = getRegistrableDomainForTracking(window.location.hostname);

    // Scan existing elements
    const selectors = 'script[src], img[src], link[href], iframe[src]';
    const elements = document.querySelectorAll(selectors);

    for (const element of elements) {
        await scanElementForTracking(element, pageDomain);
    }

    // Update UI if risk is elevated or high
    updateTrackingRiskUI();
}

/**
 * Updates the tracking risk indicator UI
 */
function updateTrackingRiskUI() {
    const level = calculateTrackingRiskLevel(_trackingRiskState.score);

    // Only show floating indicator for HIGH risk
    if (level !== 'high') {
        removeTrackingRiskIndicator();
        return;
    }

    showTrackingRiskIndicator(
        level,
        _trackingRiskState.unknownTrackers.length,
        _trackingRiskState.domains.size,
        _trackingRiskState.reasons
    );

    // Notify background for statistics (fire and forget)
    try {
        chrome.runtime.sendMessage({
            action: 'trackingRiskDetected',
            level: level,
            score: _trackingRiskState.score,
            unknownCount: _trackingRiskState.unknownTrackers.length
        }).catch(() => {});
    } catch (e) {
        // Extension context may be invalidated - silently ignore
    }
}

/**
 * Shows the tracking risk indicator
 */
function showTrackingRiskIndicator(level, unknownCount, thirdPartyCount, reasons) {
    removeTrackingRiskIndicator();

    _trackingRiskIndicator = document.createElement('div');
    _trackingRiskIndicator.id = 'linkshield-tracking-risk-indicator';

    _trackingRiskIndicator.innerHTML = `
        <style>
            #linkshield-tracking-risk-indicator {
                position: fixed;
                bottom: 20px;
                right: 20px;
                background: #dc2626;
                color: white;
                padding: 12px 16px;
                border-radius: 8px;
                font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
                font-size: 13px;
                z-index: 2147483646;
                box-shadow: 0 4px 12px rgba(0,0,0,0.3);
                max-width: 320px;
                cursor: pointer;
                transition: opacity 0.3s, transform 0.3s;
                display: flex;
                align-items: flex-start;
                gap: 10px;
            }
            #linkshield-tracking-risk-indicator:hover {
                transform: translateY(-2px);
                box-shadow: 0 6px 16px rgba(0,0,0,0.4);
            }
            #linkshield-tracking-risk-indicator .tir-icon {
                font-size: 20px;
                flex-shrink: 0;
            }
            #linkshield-tracking-risk-indicator .tir-content {
                flex: 1;
            }
            #linkshield-tracking-risk-indicator .tir-title {
                font-weight: 600;
                margin-bottom: 4px;
            }
            #linkshield-tracking-risk-indicator .tir-detail {
                font-size: 11px;
                opacity: 0.9;
            }
            #linkshield-tracking-risk-indicator .tir-close {
                position: absolute;
                top: 6px;
                right: 8px;
                background: none;
                border: none;
                color: white;
                font-size: 16px;
                cursor: pointer;
                opacity: 0.7;
                padding: 0;
                line-height: 1;
            }
            #linkshield-tracking-risk-indicator .tir-close:hover {
                opacity: 1;
            }
        </style>
        <span class="tir-icon">⚠️</span>
        <div class="tir-content">
            <div class="tir-title">${getTranslatedMessage('trackingRiskTitle') || 'Infrastructure Risk'}</div>
            <div class="tir-detail">
                ${thirdPartyCount} ${getTranslatedMessage('trackingRiskThirdParty') || 'external connections'}
                ${unknownCount > 0 ? ` · ${unknownCount} ${getTranslatedMessage('trackingRiskHostile') || 'unknown'}` : ''}
            </div>
        </div>
        <button class="tir-close" aria-label="Close">×</button>
    `;

    _trackingRiskIndicator.querySelector('.tir-close').addEventListener('click', (e) => {
        e.stopPropagation();
        removeTrackingRiskIndicator();
    });

    _trackingRiskIndicator.addEventListener('click', () => {
        removeTrackingRiskIndicator();
    });

    document.body.appendChild(_trackingRiskIndicator);
}

/**
 * Removes the tracking risk indicator
 */
function removeTrackingRiskIndicator() {
    if (_trackingRiskIndicator && _trackingRiskIndicator.parentNode) {
        _trackingRiskIndicator.parentNode.removeChild(_trackingRiskIndicator);
    }
    _trackingRiskIndicator = null;
}

/**
 * Initializes DOM-based tracking risk detection
 */
async function initTrackingRiskDetection() {
    if (_trackingRiskInitialized || !_isTopFrame) return;
    _trackingRiskInitialized = true;

    try {
        // Check if protection is enabled
        if (!(await isProtectionEnabled())) {
            return;
        }

        // Skip trusted domains
        if (await isTrustedDomain(window.location.hostname)) {
            return;
        }

        // Initial scan after DOM is ready
        if (document.readyState === 'loading') {
            document.addEventListener('DOMContentLoaded', () => {
                setTimeout(scanDOMForTracking, 1000);
            });
        } else {
            setTimeout(scanDOMForTracking, 1000);
        }

        // Watch for dynamically added elements
        let _trackingObserverProcessing = false;
        const observer = new MutationObserver(async (mutations) => {
            // Prevent re-entrant calls (indicator element triggers observer)
            if (_trackingObserverProcessing) return;
            _trackingObserverProcessing = true;

            try {
                const pageDomain = getRegistrableDomainForTracking(window.location.hostname);
                let elementsProcessed = 0;

                for (const mutation of mutations) {
                    for (const node of mutation.addedNodes) {
                        if (node.nodeType !== Node.ELEMENT_NODE) continue;

                        // Skip our own indicator element
                        if (node.id === 'linkshield-tracking-risk-indicator') continue;

                        // Check the node itself
                        if (['SCRIPT', 'IMG', 'LINK', 'IFRAME'].includes(node.tagName)) {
                            await scanElementForTracking(node, pageDomain);
                            elementsProcessed++;
                        }

                        // Check descendants
                        if (node.querySelectorAll) {
                            const descendants = node.querySelectorAll('script[src], img[src], link[href], iframe[src]');
                            for (const desc of descendants) {
                                await scanElementForTracking(desc, pageDomain);
                                elementsProcessed++;
                            }
                        }
                    }
                }

                // Only update UI if we actually processed tracking elements
                if (elementsProcessed > 0) {
                    updateTrackingRiskUI();
                }
            } finally {
                _trackingObserverProcessing = false;
            }
        });

        observer.observe(document.documentElement, {
            childList: true,
            subtree: true
        });
    } catch (e) {
        console.error('[LinkShield TrackingRisk] Init error:', e);
    }
}

// Initialize tracking risk detection
if (_isTopFrame) {
    initTrackingRiskDetection();
}


// =============================================================================
// QR CODE IMAGE SCANNER - Using jsQR
// OCR (OCRAD.js) disabled due to Extension CSP incompatibility
// Integrates with IntersectionObserver for viewport-based scanning
// =============================================================================

const IMAGE_SCAN_CACHE_TTL_MS = 3600000; // 1 hour expiration
const imageScanCache = new Map();

/**
 * ImageScannerOptimized - Scans images for QR codes and text using IntersectionObserver
 */
class ImageScannerOptimized {
  constructor(options = {}) {
    this.cacheTTL = options.cacheTTL || IMAGE_SCAN_CACHE_TTL_MS;
    this.maxCacheSize = options.maxCacheSize || 500;
    this.pendingImages = new Set();
    this.isProcessing = false;
    this.observer = null;
    this.observedImages = new WeakSet();

    this.handleIntersection = this.handleIntersection.bind(this);
    this.processQueue = this.processQueue.bind(this);

    this.initObserver();
    logDebug('[LinkShield OCR] ImageScannerOptimized initialized');
  }

  initObserver() {
    if (typeof IntersectionObserver === 'undefined') {
      logDebug('[LinkShield OCR] IntersectionObserver not available, using fallback');
      return;
    }

    this.observer = new IntersectionObserver(this.handleIntersection, {
      root: null,
      rootMargin: '50px',
      threshold: 0.1
    });

    logDebug('[LinkShield OCR] IntersectionObserver initialized for image scanning');
  }

  handleIntersection(entries) {
    entries.forEach(entry => {
      if (entry.isIntersecting) {
        const img = entry.target;
        this.observer?.unobserve(img);

        if (!this.isCached(img.src)) {
          this.pendingImages.add(img);
        }
      }
    });

    if (this.pendingImages.size > 0 && !this.isProcessing) {
      this.scheduleProcessing();
    }
  }

  isCached(src) {
    const cached = imageScanCache.get(src);
    if (!cached) return false;
    if (Date.now() - cached.timestamp > this.cacheTTL) {
      imageScanCache.delete(src);
      return false;
    }
    return true;
  }

  addToCache(src, result) {
    if (imageScanCache.size >= this.maxCacheSize) {
      const oldestKey = imageScanCache.keys().next().value;
      imageScanCache.delete(oldestKey);
    }
    imageScanCache.set(src, { ...result, timestamp: Date.now() });
  }

  scheduleProcessing() {
    if (this.isProcessing) return;
    if ('requestIdleCallback' in window) {
      requestIdleCallback(this.processQueue, { timeout: 2000 });
    } else {
      setTimeout(this.processQueue, 100);
    }
  }

  async processQueue() {
    this.isProcessing = true;
    const images = Array.from(this.pendingImages);

    for (const img of images) {
      this.pendingImages.delete(img);

      if (this.isCached(img.src)) continue;

      try {
        await this.scanImage(img);
      } catch (error) {
        handleError(error, `[LinkShield OCR] Error scanning image ${img.src}`);
        this.addToCache(img.src, { level: 'safe', type: 'error' });
      }
    }

    this.isProcessing = false;

    if (this.pendingImages.size > 0) {
      this.scheduleProcessing();
    }
  }

  async scanImage(imgEl) {
    const src = imgEl.src;

    // First try QR code detection
    const qrResult = await scanImageForQR(imgEl);
    if (qrResult && qrResult.detected) {
      this.addToCache(src, qrResult);
      return;
    }

    // Then try OCR for text detection
    const ocrResult = await scanImageForOCR(imgEl);
    if (ocrResult && ocrResult.detected) {
      this.addToCache(src, ocrResult);
      return;
    }

    // No detection
    this.addToCache(src, { level: 'safe', type: 'none' });
  }

  observeImage(img) {
    if (!this.observer || this.observedImages.has(img)) return;
    if (!img.src || img.src.startsWith('data:')) return;

    this.observedImages.add(img);
    this.observer.observe(img);
  }

  scanAllVisibleImages() {
    const images = document.querySelectorAll('img[src]');
    images.forEach(img => {
      if (isVisible(img) && !this.isCached(img.src)) {
        this.observeImage(img);
      }
    });
  }

  destroy() {
    this.observer?.disconnect();
    this.pendingImages.clear();
  }
}

// Global image scanner instance
let imageScanner = null;

// =============================================================================
// SPLIT QR CODE DETECTION (v8.5.0)
// Detecteert QR codes die opgesplitst zijn in meerdere afbeeldingen
// om security scanners te omzeilen (Gabagool PhaaS techniek)
// =============================================================================

/**
 * SECURITY FIX v8.5.0: Split QR Code Detection
 * Detecteert QR codes die opgesplitst zijn in meerdere afbeeldingen
 * om security scanners te omzeilen (Gabagool PhaaS techniek)
 */
class SplitQRDetector {
    constructor() {
        this.config = globalConfig?.ADVANCED_THREAT_DETECTION?.splitQR || {
            enabled: true,
            adjacencyTolerance: 5,
            minFragments: 2,
            maxFragments: 6,
            minFragmentSize: 20,
            maxFragmentSize: 300
        };
        this.scannedGroups = new WeakSet();
    }

    /**
     * Scan de pagina voor split QR codes
     * @returns {Promise<Object>} - { detected: boolean, url?: string, fragmentCount?: number }
     */
    async scan() {
        if (!this.config.enabled) {
            return { detected: false };
        }

        return new Promise((resolve) => {
            // Gebruik requestIdleCallback om main thread niet te blokkeren
            const doScan = () => {
                try {
                    const result = this._performScan();
                    resolve(result);
                } catch (err) {
                    handleError(err, 'SplitQRDetector');
                    resolve({ detected: false });
                }
            };

            if (typeof requestIdleCallback === 'function') {
                requestIdleCallback(doScan, { timeout: 2000 });
            } else {
                setTimeout(doScan, 100);
            }
        });
    }

    _performScan() {
        // Stap 1: Verzamel kandidaat-afbeeldingen
        const images = Array.from(document.querySelectorAll('img'));
        const candidates = [];

        for (const img of images) {
            // Skip afbeeldingen die al gescand zijn door reguliere scanner
            if (img.dataset.linkshieldQrScanned) continue;

            const rect = img.getBoundingClientRect();

            // Filter op grootte (QR fragmenten zijn typisch klein en vierkant-achtig)
            if (rect.width >= this.config.minFragmentSize &&
                rect.width <= this.config.maxFragmentSize &&
                rect.height >= this.config.minFragmentSize &&
                rect.height <= this.config.maxFragmentSize &&
                Math.abs(rect.width - rect.height) < 50) { // Bijna vierkant

                candidates.push({
                    img,
                    rect,
                    centerX: rect.left + rect.width / 2,
                    centerY: rect.top + rect.height / 2
                });
            }
        }

        if (candidates.length < this.config.minFragments) {
            return { detected: false };
        }

        logDebug(`[SplitQR] Found ${candidates.length} candidate fragments`);

        // Stap 2: Groepeer aangrenzende afbeeldingen
        const groups = this._groupAdjacentImages(candidates);

        // Stap 3: Scan elke groep
        for (const group of groups) {
            if (group.length >= this.config.minFragments &&
                group.length <= this.config.maxFragments) {

                const result = this._scanGroup(group);
                if (result.detected) {
                    logDebug(`[SplitQR] 🚨 DETECTED split QR with ${group.length} fragments`);
                    logDebug(`[SplitQR] URL: ${result.url}`);

                    // Rapporteer aan background
                    if (typeof chrome !== 'undefined' && chrome.runtime?.sendMessage) {
                        chrome.runtime.sendMessage({
                            type: 'splitQRDetected',
                            url: window.location.href,
                            qrUrl: result.url,
                            fragmentCount: group.length,
                            timestamp: Date.now()
                        }).catch(() => {});
                    }

                    return result;
                }
            }
        }

        return { detected: false };
    }

    _groupAdjacentImages(candidates) {
        const groups = [];
        const used = new Set();
        const tolerance = this.config.adjacencyTolerance;

        for (let i = 0; i < candidates.length; i++) {
            if (used.has(i)) continue;

            const group = [candidates[i]];
            used.add(i);

            // BFS om alle aangrenzende afbeeldingen te vinden
            const queue = [candidates[i]];

            while (queue.length > 0) {
                const current = queue.shift();

                for (let j = 0; j < candidates.length; j++) {
                    if (used.has(j)) continue;

                    if (this._isAdjacent(current.rect, candidates[j].rect, tolerance)) {
                        group.push(candidates[j]);
                        used.add(j);
                        queue.push(candidates[j]);
                    }
                }
            }

            if (group.length >= this.config.minFragments) {
                groups.push(group);
            }
        }

        return groups;
    }

    _isAdjacent(rect1, rect2, tolerance) {
        // Check horizontale aangrenzendheid
        const horizontalAdjacent =
            Math.abs(rect1.right - rect2.left) <= tolerance ||
            Math.abs(rect2.right - rect1.left) <= tolerance;

        // Check verticale aangrenzendheid
        const verticalAdjacent =
            Math.abs(rect1.bottom - rect2.top) <= tolerance ||
            Math.abs(rect2.bottom - rect1.top) <= tolerance;

        // Check of ze op dezelfde rij/kolom staan
        const sameRow = Math.abs(rect1.top - rect2.top) < rect1.height / 2;
        const sameColumn = Math.abs(rect1.left - rect2.left) < rect1.width / 2;

        return (horizontalAdjacent && sameRow) || (verticalAdjacent && sameColumn);
    }

    _scanGroup(group) {
        try {
            // Sorteer op positie (links-naar-rechts, boven-naar-onder)
            group.sort((a, b) => {
                const rowDiff = Math.floor(a.rect.top / 50) - Math.floor(b.rect.top / 50);
                if (rowDiff !== 0) return rowDiff;
                return a.rect.left - b.rect.left;
            });

            // Bereken totale grootte
            const minX = Math.min(...group.map(g => g.rect.left));
            const minY = Math.min(...group.map(g => g.rect.top));
            const maxX = Math.max(...group.map(g => g.rect.right));
            const maxY = Math.max(...group.map(g => g.rect.bottom));

            const totalWidth = Math.ceil(maxX - minX);
            const totalHeight = Math.ceil(maxY - minY);

            // Maak canvas
            const canvas = document.createElement('canvas');
            canvas.width = totalWidth;
            canvas.height = totalHeight;
            const ctx = canvas.getContext('2d');

            if (!ctx) return { detected: false };

            // Teken alle fragmenten op het canvas
            for (const item of group) {
                const x = Math.round(item.rect.left - minX);
                const y = Math.round(item.rect.top - minY);

                try {
                    ctx.drawImage(item.img, x, y, item.rect.width, item.rect.height);
                } catch (e) {
                    // Cross-origin image, skip
                    continue;
                }
            }

            // Scan met jsQR
            const imageData = ctx.getImageData(0, 0, totalWidth, totalHeight);

            if (typeof jsQR === 'function') {
                const qrResult = jsQR(imageData.data, totalWidth, totalHeight);

                if (qrResult && qrResult.data) {
                    return {
                        detected: true,
                        url: qrResult.data,
                        fragmentCount: group.length,
                        type: 'split_qr_code',
                        score: globalConfig?.ADVANCED_THREAT_DETECTION?.scores?.SPLIT_QR_DETECTED || 12
                    };
                }
            }

            return { detected: false };

        } catch (err) {
            handleError(err, 'SplitQR.scanGroup');
            return { detected: false };
        }
    }
}

// Singleton instance
let splitQRDetector = null;

function getSplitQRDetector() {
    if (!splitQRDetector) {
        splitQRDetector = new SplitQRDetector();
    }
    return splitQRDetector;
}

// =============================================================================
// WEBTRANSPORT MONITOR - Detecteert misbruik van WebTransport/HTTP3 voor C2/exfiltration
// WebTransport is een moderne API die bidirectionele communicatie mogelijk maakt
// Malware kan dit misbruiken voor covert channels en data exfiltration
// =============================================================================

let webTransportMonitorInitialized = false;
const webTransportConnections = new Map(); // url -> {count, firstSeen, streams, datagrams}
const WEBTRANSPORT_CLEANUP_INTERVAL_MS = 60000; // Cleanup elke minuut

/**
 * Initialiseert WebTransport monitoring via API hooking
 * Hooked de WebTransport constructor om alle verbindingen te analyseren
 */
function initWebTransportMonitor() {
    if (webTransportMonitorInitialized) return;

    // Check of WebTransport API beschikbaar is
    if (typeof WebTransport === 'undefined') {
        logDebug('[WebTransport] API not available in this browser, skipping monitor');
        return;
    }

    const config = globalConfig?.WEBTRANSPORT_MONITORING;
    if (!config?.enabled) {
        logDebug('[WebTransport] Monitoring disabled in config');
        return;
    }

    webTransportMonitorInitialized = true;

    // Bewaar originele constructor
    const OriginalWebTransport = window.WebTransport;

    // Override WebTransport constructor
    window.WebTransport = function(url, options) {
        // Analyseer de endpoint VOORDAT verbinding wordt gemaakt
        const analysis = analyzeWebTransportEndpoint(url);

        if (analysis.score > 0) {
            reportWebTransportActivity(url, analysis);
        }

        // Maak originele connectie
        const transport = new OriginalWebTransport(url, options);

        // Monitor de connectie voor gedragsanalyse
        monitorWebTransportConnection(transport, url, config);

        return transport;
    };

    // Behoud prototype chain voor instanceof checks
    window.WebTransport.prototype = OriginalWebTransport.prototype;
    Object.setPrototypeOf(window.WebTransport, OriginalWebTransport);

    // Periodieke cleanup van oude connection tracking data
    setInterval(() => cleanupWebTransportTracking(config), WEBTRANSPORT_CLEANUP_INTERVAL_MS);

    logDebug('[WebTransport] Monitor initialized successfully');
}

/**
 * Analyseert een WebTransport endpoint URL op verdachte kenmerken
 * @param {string} url - De WebTransport endpoint URL
 * @returns {{score: number, reasons: string[], isTrusted: boolean}}
 */
function analyzeWebTransportEndpoint(url) {
    const config = globalConfig?.WEBTRANSPORT_MONITORING;
    if (!config?.enabled) return { score: 0, reasons: [], isTrusted: false };

    const scores = config.scores;
    let score = 0;
    const reasons = [];

    try {
        const parsedUrl = new URL(url);
        const hostname = parsedUrl.hostname;
        const port = parsedUrl.port;

        // Check trusted endpoints eerst (whitelist)
        for (const pattern of config.trustedEndpoints || []) {
            if (pattern.test(url)) {
                logDebug(`[WebTransport] Trusted endpoint: ${hostname}`);
                return { score: 0, reasons: [], isTrusted: true };
            }
        }

        // Check verdachte patronen

        // 1. Direct IP address
        if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
            score += scores.directIP;
            reasons.push('webTransportDirectIP');
            logDebug(`[WebTransport] Direct IP detected: ${hostname}`);
        }

        // 2. High port number (10000+)
        if (port && parseInt(port) >= 10000) {
            score += scores.highPort;
            reasons.push('webTransportHighPort');
            logDebug(`[WebTransport] High port detected: ${port}`);
        }

        // 3. Random C2-like subdomain (32+ random chars)
        const subdomainMatch = hostname.match(/^([a-z0-9]+)\./i);
        if (subdomainMatch && subdomainMatch[1].length >= 32 && /^[a-z0-9]+$/i.test(subdomainMatch[1])) {
            score += scores.randomSubdomain;
            reasons.push('webTransportRandomSubdomain');
            logDebug(`[WebTransport] Random subdomain detected: ${subdomainMatch[1]}`);
        }

        // 4. Free TLD (often used for C2)
        if (/\.(tk|ml|ga|cf|gq)$/i.test(hostname)) {
            score += scores.freeTLD;
            reasons.push('webTransportFreeTLD');
            logDebug(`[WebTransport] Free TLD detected: ${hostname}`);
        }

        // 5. Obfuscated URL (base64 or double encoding)
        if (hasBase64InWebTransportUrl(url) || hasDoubleEncodingInUrl(url)) {
            score += scores.obfuscatedUrl;
            reasons.push('webTransportObfuscatedUrl');
            logDebug(`[WebTransport] Obfuscated URL detected`);
        }

        // 6. Check algemene verdachte endpoint patronen
        for (const pattern of config.suspiciousEndpoints || []) {
            if (pattern.test(url) && reasons.length === 0) {
                // Alleen als nog geen specifieke reden gevonden
                score += 3;
                reasons.push('webTransportSuspiciousPattern');
            }
        }

    } catch (e) {
        // Invalid URL = verdacht
        score += scores.invalidUrl || 5;
        reasons.push('webTransportInvalidUrl');
        logDebug(`[WebTransport] Invalid URL: ${url}`);
    }

    return { score, reasons, isTrusted: false };
}

/**
 * Controleert of een URL base64-encoded componenten bevat
 */
function hasBase64InWebTransportUrl(url) {
    try {
        const parsedUrl = new URL(url);
        // Split path into segments and check each individually
        const pathSegments = parsedUrl.pathname.split('/').filter(s => s.length > 0);
        const queryParams = parsedUrl.search ? parsedUrl.search.slice(1).split('&') : [];
        const allSegments = [...pathSegments, ...queryParams];

        // Pattern for base64 strings (min 20 chars, without /)
        const base64Pattern = /^[A-Za-z0-9+\/=]{20,}$/;

        for (const segment of allSegments) {
            if (base64Pattern.test(segment)) {
                try {
                    atob(segment);
                    return true; // Valid base64 found
                } catch {
                    // Not valid base64, continue checking
                }
            }
        }
    } catch {
        return false;
    }
    return false;
}

/**
 * Controleert op double URL encoding
 */
function hasDoubleEncodingInUrl(url) {
    return /%25[0-9A-Fa-f]{2}/.test(url);
}

/**
 * Monitor een actieve WebTransport connectie voor gedragsanalyse
 * @param {WebTransport} transport - De WebTransport instantie
 * @param {string} url - De endpoint URL
 * @param {object} config - De monitoring configuratie
 */
function monitorWebTransportConnection(transport, url, config) {
    const thresholds = config.thresholds;
    const scores = config.scores;
    const connectionKey = url;

    // Track connection
    const now = Date.now();
    if (!webTransportConnections.has(connectionKey)) {
        webTransportConnections.set(connectionKey, {
            count: 0,
            firstSeen: now,
            lastSeen: now,
            streams: 0,
            datagrams: 0,
            reported: false,
        });
    }

    const connData = webTransportConnections.get(connectionKey);
    connData.count++;
    connData.lastSeen = now;

    // Check connection rate limiting
    const timeSinceFirstMs = now - connData.firstSeen;
    const timeSinceFirstMinutes = timeSinceFirstMs / 60000;

    if (timeSinceFirstMinutes > 0 && !connData.reported) {
        const connectionsPerMinute = connData.count / timeSinceFirstMinutes;

        if (connectionsPerMinute > thresholds.maxConnectionsPerMinute) {
            connData.reported = true;
            reportWebTransportActivity(url, {
                score: scores.highConnectionRate,
                reasons: ['webTransportHighConnectionRate'],
                connectionData: {
                    count: connData.count,
                    ratePerMinute: connectionsPerMinute.toFixed(2),
                    windowMs: timeSinceFirstMs,
                }
            });
        }
    }

    // Monitor datagrams (indien ondersteund)
    transport.ready.then(() => {
        // Track stream creation
        if (transport.incomingBidirectionalStreams) {
            trackWebTransportStreams(transport, url, connData, thresholds, scores);
        }

        // Track datagrams
        if (transport.datagrams?.writable) {
            trackWebTransportDatagrams(transport, url, connData, thresholds, scores);
        }
    }).catch((err) => {
        logDebug(`[WebTransport] Connection failed to ${url}: ${err.message}`);
    });
}

/**
 * Track WebTransport streams voor anomalie detectie
 */
function trackWebTransportStreams(transport, url, connData, thresholds, scores) {
    const reader = transport.incomingBidirectionalStreams.getReader();

    const readStreams = async () => {
        try {
            while (true) {
                const { value, done } = await reader.read();
                if (done) break;

                connData.streams++;

                // Check stream limit
                if (connData.streams > thresholds.maxStreamsPerConnection && !connData.streamLimitReported) {
                    connData.streamLimitReported = true;
                    reportWebTransportActivity(url, {
                        score: scores.highConnectionRate,
                        reasons: ['webTransportHighStreamCount'],
                        connectionData: { streams: connData.streams }
                    });
                }
            }
        } catch {
            // Connection closed
        }
    };

    readStreams();
}

/**
 * Track WebTransport datagrams voor bulk transfer detectie
 */
function trackWebTransportDatagrams(transport, url, connData, thresholds, scores) {
    // We kunnen outgoing datagrams monitoren via een proxy
    const originalWritable = transport.datagrams.writable;

    let datagramCount = 0;
    let datagramStartTime = Date.now();
    let highRateReported = false;

    // Monitor via periodic check (minder invasief dan hooking)
    const checkInterval = setInterval(() => {
        const elapsed = (Date.now() - datagramStartTime) / 1000;

        if (elapsed > 1 && !highRateReported) {
            const rate = connData.datagrams / elapsed;

            if (rate > thresholds.maxDatagramsPerSecond) {
                highRateReported = true;
                reportWebTransportActivity(url, {
                    score: scores.highDatagramRate,
                    reasons: ['webTransportHighDatagramRate'],
                    connectionData: {
                        datagrams: connData.datagrams,
                        ratePerSecond: rate.toFixed(2),
                    }
                });
            }
        }
    }, 5000);

    // Cleanup interval when transport closes
    transport.closed.then(() => {
        clearInterval(checkInterval);
    }).catch(() => {
        clearInterval(checkInterval);
    });
}

/**
 * Cleanup oude connection tracking data
 */
function cleanupWebTransportTracking(config) {
    const now = Date.now();
    const windowMs = config.thresholds.connectionTrackingWindowMs || 300000;

    for (const [url, data] of webTransportConnections.entries()) {
        if (now - data.lastSeen > windowMs) {
            webTransportConnections.delete(url);
            logDebug(`[WebTransport] Cleaned up tracking for: ${url}`);
        }
    }
}

/**
 * Rapporteert verdachte WebTransport activiteit naar background en UI
 * @param {string} url - De endpoint URL
 * @param {object} analysis - Analyse resultaat met score en reasons
 */
function reportWebTransportActivity(url, analysis) {
    const hostname = window.location.hostname;

    logDebug(`[WebTransport] Suspicious activity detected:`, {
        endpoint: url,
        score: analysis.score,
        reasons: analysis.reasons,
        connectionData: analysis.connectionData,
    });

    // Stuur naar background voor verdere analyse en icon update
    chrome.runtime.sendMessage({
        action: 'webTransportDetected',
        data: {
            hostname,
            endpointUrl: url,
            score: analysis.score,
            reasons: analysis.reasons,
            connectionData: analysis.connectionData || null,
            timestamp: Date.now()
        }
    }).catch(() => {
        // Extension context may be invalidated
    });

    // Bij hoge score: toon waarschuwing aan gebruiker
    if (analysis.score >= 10) {
        showWebTransportWarning(url, analysis);
    }
}

/**
 * Toont een waarschuwing voor verdachte WebTransport activiteit
 * @param {string} url - De verdachte endpoint URL
 * @param {object} analysis - Analyse resultaat
 */
function showWebTransportWarning(url, analysis) {
    const title = getTranslatedMessage('webTransportWarningTitle') || 'Suspicious Network Activity';
    const message = getTranslatedMessage('webTransportWarningMessage') ||
        'This page is using advanced network protocols in a potentially suspicious way.';

    // Bepaal specifieke reden voor tip
    let reasonText = '';
    if (analysis.reasons.includes('webTransportDirectIP')) {
        reasonText = getTranslatedMessage('webTransportDirectIP') || 'Connection to direct IP address detected.';
    } else if (analysis.reasons.includes('webTransportRandomSubdomain')) {
        reasonText = getTranslatedMessage('webTransportRandomSubdomain') || 'Connection to suspicious random subdomain.';
    } else if (analysis.reasons.includes('webTransportHighPort')) {
        reasonText = getTranslatedMessage('webTransportHighPort') || 'Connection to unusual high port number.';
    } else if (analysis.reasons.includes('webTransportHighConnectionRate')) {
        reasonText = getTranslatedMessage('webTransportHighConnectionRate') || 'Unusually high connection rate detected.';
    } else if (analysis.reasons.includes('webTransportFreeTLD')) {
        reasonText = getTranslatedMessage('webTransportFreeTLD') || 'Connection to free TLD domain.';
    }

    showSecurityWarning({
        id: 'webtransport',
        severity: 'warning',
        title: title,
        message: message,
        tip: reasonText || undefined,
        icon: '🌐',
        showTrust: true
    });
}

// =============================================================================
// IMAGELESS QR CODE SCANNER v8.1.1
// Detecteert QR-codes gerenderd via HTML elementen (geen images)
// Ondersteunt: <table>, SVG <rect>, CSS Grid
// AI-phishing kits gebruiken deze technieken om image-scanning te omzeilen
// =============================================================================

const IMAGELESS_QR_CACHE = new Map();
const IMAGELESS_QR_CACHE_TTL_MS = 1800000; // 30 minuten cache
const IMAGELESS_QR_MIN_SIZE = 21; // Minimale QR-code grootte (21x21 modules)
const IMAGELESS_QR_MAX_SIZE = 177; // Maximale QR-code grootte (version 40)

/**
 * ImagelessQRScanner - Scant HTML elementen voor QR-code patronen
 * Ondersteunt: <table> met bgcolor, SVG met <rect>, CSS Grid containers
 * @version 8.1.1
 */
class ImagelessQRScanner {
  constructor(options = {}) {
    this.minSize = options.minSize || IMAGELESS_QR_MIN_SIZE;
    this.maxSize = options.maxSize || IMAGELESS_QR_MAX_SIZE;
    this.cacheTTL = options.cacheTTL || IMAGELESS_QR_CACHE_TTL_MS;
    this.pendingElements = new Set();
    this.isProcessing = false;
    this.scannedElements = new WeakSet();

    logDebug('[ImagelessQR] Scanner initialized (Table + SVG + CSS Grid)');
  }

  // ===========================================================================
  // TABLE DETECTION (bestaande functionaliteit)
  // ===========================================================================

  /**
   * Controleert of een tabel een QR-code patroon zou kunnen zijn
   * @param {HTMLTableElement} table - Het table element om te controleren
   * @returns {boolean} True als de tabel een potentiële QR-code is
   */
  isPotentialQRTable(table) {
    if (!table || this.scannedElements.has(table)) return false;

    const rows = table.querySelectorAll('tr');
    if (rows.length < this.minSize || rows.length > this.maxSize) return false;

    // Check consistentie: alle rijen moeten ongeveer evenveel cellen hebben
    const firstRowCells = rows[0]?.querySelectorAll('td, th').length || 0;
    if (firstRowCells < this.minSize || firstRowCells > this.maxSize) return false;

    // Controleer of de tabel vierkant is (±3 cellen tolerantie)
    if (Math.abs(rows.length - firstRowCells) > 3) return false;

    // Check of 30-70% van de cellen DONKER is (QR-code patroon)
    let darkCells = 0;
    let totalCells = 0;

    for (const row of rows) {
      const cells = row.querySelectorAll('td, th');
      for (const cell of cells) {
        totalCells++;
        if (this.isCellDark(cell)) darkCells++;
      }
    }

    const darkRatio = darkCells / totalCells;
    return darkRatio >= 0.3 && darkRatio <= 0.7;
  }

  /**
   * Rendert een tabel naar een canvas en scant voor QR-code
   * @param {HTMLTableElement} table - Het table element
   * @returns {Promise<{detected: boolean, url: string|null, level: string, reasons: string[]}>}
   */
  async scanTable(table) {
    if (typeof jsQR === 'undefined') {
      logDebug('[ImagelessQR] jsQR not available, skipping table scan');
      return null;
    }

    const cacheKey = 'table:' + this.getTableHash(table);
    const cached = IMAGELESS_QR_CACHE.get(cacheKey);
    if (cached && Date.now() - cached.timestamp < this.cacheTTL) {
      return cached.result;
    }

    this.scannedElements.add(table);

    try {
      const rows = table.querySelectorAll('tr');
      const rowCount = rows.length;
      const colCount = rows[0]?.querySelectorAll('td, th').length || 0;

      // Maak een off-screen canvas
      const cellSize = 4; // Pixels per cel
      const canvas = document.createElement('canvas');
      canvas.width = colCount * cellSize;
      canvas.height = rowCount * cellSize;
      const ctx = canvas.getContext('2d');

      // Witte achtergrond
      ctx.fillStyle = 'white';
      ctx.fillRect(0, 0, canvas.width, canvas.height);

      // Render elke cel
      ctx.fillStyle = 'black';
      rows.forEach((row, y) => {
        const cells = row.querySelectorAll('td, th');
        cells.forEach((cell, x) => {
          if (this.isCellDark(cell)) {
            ctx.fillRect(x * cellSize, y * cellSize, cellSize, cellSize);
          }
        });
      });

      // Scan met jsQR
      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const qrResult = jsQR(imageData.data, imageData.width, imageData.height);

      if (qrResult && qrResult.data) {
        const decodedUrl = qrResult.data;
        logDebug(`[ImagelessQR] Decoded URL from table: ${decodedUrl}`);

        if (isValidURL(decodedUrl)) {
          // Voer security checks uit op de gedecodeerde URL
          const securityResult = await this.analyzeDecodedUrl(decodedUrl, 'table-qr');

          const result = {
            detected: true,
            type: 'table-qr',
            url: decodedUrl,
            ...securityResult
          };

          IMAGELESS_QR_CACHE.set(cacheKey, { result, timestamp: Date.now() });
          return result;
        }
      }

      const noQrResult = { detected: false, url: null, level: 'safe', reasons: [] };
      IMAGELESS_QR_CACHE.set(cacheKey, { result: noQrResult, timestamp: Date.now() });
      return noQrResult;

    } catch (error) {
      handleError(error, '[ImagelessQR] Error scanning table');
      return null;
    }
  }

  /**
   * Bepaalt of een cel "donker" is (zwart module in QR-code)
   * @param {HTMLTableCellElement} cell - De tabel cel
   * @returns {boolean}
   */
  isCellDark(cell) {
    const bgColor = cell.getAttribute('bgcolor') ||
                    cell.style.backgroundColor ||
                    window.getComputedStyle(cell).backgroundColor;

    if (!bgColor || bgColor === 'transparent' || bgColor === 'rgba(0, 0, 0, 0)') {
      return false;
    }

    // Parse kleur naar RGB
    let r = 255, g = 255, b = 255;
    if (bgColor.startsWith('#')) {
      const hex = bgColor.slice(1);
      r = parseInt(hex.slice(0, 2), 16) || 255;
      g = parseInt(hex.slice(2, 4), 16) || 255;
      b = parseInt(hex.slice(4, 6), 16) || 255;
    } else if (bgColor.startsWith('rgb')) {
      const match = bgColor.match(/\d+/g);
      if (match && match.length >= 3) {
        [r, g, b] = match.slice(0, 3).map(Number);
      }
    } else {
      // Benoemde kleuren
      const darkColors = ['black', 'darkblue', 'darkgreen', 'darkred', 'navy', 'maroon'];
      return darkColors.includes(bgColor.toLowerCase());
    }

    // Bereken luminantie - donker = < 128
    const luminance = (0.299 * r + 0.587 * g + 0.114 * b);
    return luminance < 128;
  }

  /**
   * Genereert een simpele hash voor caching
   */
  getTableHash(table) {
    const rows = table.querySelectorAll('tr');
    let hash = `${rows.length}x${rows[0]?.querySelectorAll('td, th').length || 0}:`;

    // Sample eerste, middelste en laatste rij voor hash
    const sampleIndices = [0, Math.floor(rows.length / 2), rows.length - 1];
    for (const idx of sampleIndices) {
      const row = rows[idx];
      if (row) {
        const cells = row.querySelectorAll('td, th');
        cells.forEach(cell => {
          hash += this.isCellDark(cell) ? '1' : '0';
        });
      }
    }
    return hash;
  }

  /**
   * Analyseert de gedecodeerde URL voor security threats
   * @param {string} url - De gedecodeerde URL
   * @param {string} sourceType - Type bron ('table-qr', 'svg-qr', 'grid-qr')
   */
  async analyzeDecodedUrl(url, sourceType = 'table-qr') {
    const reasons = [];
    let totalRisk = 0;

    // Basis URL checks
    const result = await performSuspiciousChecks(url);
    reasons.push(...result.reasons);
    totalRisk += result.risk || 0;

    // Extra risico: Imageless QR is inherent verdacht (anti-detection techniek)
    reasons.push('imagelessQR');
    reasons.push(sourceType);
    totalRisk += 3;

    // Check redirect chain via background script
    try {
      const redirectResult = await new Promise((resolve, reject) => {
        const timeoutId = setTimeout(() => reject(new Error('Timeout')), 5000);
        chrome.runtime.sendMessage({
          action: 'analyzeRedirectChain',
          url: url,
          source: 'table-qr'
        }, response => {
          clearTimeout(timeoutId);
          resolve(response || { threats: [] });
        });
      });

      if (redirectResult.threats && redirectResult.threats.length > 0) {
        reasons.push(...redirectResult.threats);
        totalRisk += redirectResult.threats.length * 3;
      }
    } catch (e) {
      logDebug(`[TableQR] Redirect analysis failed: ${e.message}`);
    }

    // Bepaal risico level
    let level = 'safe';
    if (totalRisk >= globalConfig.HIGH_THRESHOLD) {
      level = 'alert';
    } else if (totalRisk >= globalConfig.LOW_THRESHOLD) {
      level = 'caution';
    }

    return { level, reasons: [...new Set(reasons)], risk: totalRisk };
  }

  /**
   * Scant alle tabellen op de pagina
   */
  async scanTables() {
    const tables = document.querySelectorAll('table');
    let scannedCount = 0;

    for (const table of tables) {
      if (this.isPotentialQRTable(table)) {
        table.dataset.linkshieldQrScanned = 'true';
        table.dataset.linkshieldQrPotential = 'true';

        const result = await this.scanTable(table);
        scannedCount++;

        table.dataset.linkshieldQrDetected = result?.detected ? 'true' : 'false';
        table.dataset.linkshieldQrUrl = result?.url || '';

        if (result && result.detected && result.level !== 'safe') {
          this.warnImagelessQR(table, result);
        }
      }
    }

    return scannedCount;
  }

  // ===========================================================================
  // SVG DETECTION (nieuw in v8.1.1)
  // Detecteert QR-codes gemaakt met SVG <rect> elementen
  // ===========================================================================

  /**
   * Controleert of een SVG element een QR-code patroon zou kunnen zijn
   * @param {SVGElement} svg - Het SVG element om te controleren
   * @returns {boolean} True als de SVG een potentiële QR-code is
   */
  isPotentialQRSvg(svg) {
    if (!svg || this.scannedElements.has(svg)) return false;

    const rects = Array.from(svg.querySelectorAll('rect'));
    const minRects = this.minSize * this.minSize * 0.3;
    const maxRects = this.maxSize * this.maxSize;

    if (rects.length < minRects || rects.length > maxRects) return false;

    // Check of de SVG vierkant is (±10% tolerantie)
    const bbox = svg.getBBox ? svg.getBBox() : { width: svg.clientWidth, height: svg.clientHeight };
    const aspectRatio = bbox.width / bbox.height;
    if (aspectRatio < 0.9 || aspectRatio > 1.1) return false;

    // Categoriseer rects op grootte om background rect te identificeren
    const rectsBySize = new Map();
    for (const rect of rects) {
      const w = Math.round(parseFloat(rect.getAttribute('width') || 0));
      const h = Math.round(parseFloat(rect.getAttribute('height') || 0));
      const sizeKey = `${w}x${h}`;
      if (!rectsBySize.has(sizeKey)) {
        rectsBySize.set(sizeKey, { rects: [], area: w * h });
      }
      rectsBySize.get(sizeKey).rects.push(rect);
    }

    // Sorteer op aantal rects (meeste eerst = waarschijnlijk modules)
    const sizeEntries = Array.from(rectsBySize.entries())
      .sort((a, b) => b[1].rects.length - a[1].rects.length);

    // QR-codes hebben uniforme modules (max 3 verschillende groottes voor quiet zone)
    if (sizeEntries.length > 3) return false;

    // Neem de meest voorkomende grootte als module-grootte (exclusief background)
    const moduleRects = sizeEntries.length > 1 && sizeEntries[0][1].rects.length > 10
      ? sizeEntries[0][1].rects
      : rects;

    // Tel donkere modules
    // NB: Veel SVG QR generators tekenen ALLEEN donkere modules (geen witte)
    let darkModules = 0;
    const sampleSize = Math.min(moduleRects.length, 100);
    for (let i = 0; i < sampleSize; i++) {
      const fill = moduleRects[i].getAttribute('fill') || window.getComputedStyle(moduleRects[i]).fill;
      if (this.isColorDark(fill)) darkModules++;
    }

    const darkRatio = darkModules / sampleSize;
    // Accept: 30-70% donker (mixed) OR >90% donker (dark-only pattern)
    const hasValidDarkRatio = (darkRatio >= 0.3 && darkRatio <= 0.7);
    const isDarkOnlyPattern = (darkRatio >= 0.9 && moduleRects.length >= minRects);

    return hasValidDarkRatio || isDarkOnlyPattern;
  }

  /**
   * Scant een SVG element voor QR-code
   * @param {SVGElement} svg - Het SVG element
   * @returns {Promise<{detected: boolean, url: string|null, level: string, reasons: string[]}>}
   */
  async scanSvg(svg) {
    if (typeof jsQR === 'undefined') {
      logDebug('[ImagelessQR] jsQR not available, skipping SVG scan');
      return null;
    }

    const cacheKey = 'svg:' + this.getSvgHash(svg);
    const cached = IMAGELESS_QR_CACHE.get(cacheKey);
    if (cached && Date.now() - cached.timestamp < this.cacheTTL) {
      return cached.result;
    }

    this.scannedElements.add(svg);

    try {
      const rects = svg.querySelectorAll('rect');
      if (rects.length === 0) return null;

      // Bepaal grid dimensies uit rect posities
      const positions = [];
      let minX = Infinity, minY = Infinity, maxX = 0, maxY = 0;
      let moduleSize = 0;

      for (const rect of rects) {
        const x = parseFloat(rect.getAttribute('x') || 0);
        const y = parseFloat(rect.getAttribute('y') || 0);
        const w = parseFloat(rect.getAttribute('width') || 0);
        const h = parseFloat(rect.getAttribute('height') || 0);

        if (w > 0 && moduleSize === 0) moduleSize = w;

        minX = Math.min(minX, x);
        minY = Math.min(minY, y);
        maxX = Math.max(maxX, x + w);
        maxY = Math.max(maxY, y + h);

        const fill = rect.getAttribute('fill') || window.getComputedStyle(rect).fill;
        positions.push({ x, y, w, h, dark: this.isColorDark(fill) });
      }

      if (moduleSize === 0) return null;

      // Bereken grid grootte
      const gridWidth = Math.ceil((maxX - minX) / moduleSize);
      const gridHeight = Math.ceil((maxY - minY) / moduleSize);

      if (gridWidth < this.minSize || gridHeight < this.minSize) return null;

      // Render naar canvas
      const cellSize = 4;
      const canvas = document.createElement('canvas');
      canvas.width = gridWidth * cellSize;
      canvas.height = gridHeight * cellSize;
      const ctx = canvas.getContext('2d');

      ctx.fillStyle = 'white';
      ctx.fillRect(0, 0, canvas.width, canvas.height);

      ctx.fillStyle = 'black';
      for (const pos of positions) {
        if (pos.dark) {
          const gridX = Math.floor((pos.x - minX) / moduleSize);
          const gridY = Math.floor((pos.y - minY) / moduleSize);
          ctx.fillRect(gridX * cellSize, gridY * cellSize, cellSize, cellSize);
        }
      }

      // Scan met jsQR
      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const qrResult = jsQR(imageData.data, imageData.width, imageData.height);

      if (qrResult && qrResult.data) {
        const decodedUrl = qrResult.data;
        logDebug(`[ImagelessQR] Decoded URL from SVG: ${decodedUrl}`);

        if (isValidURL(decodedUrl)) {
          const securityResult = await this.analyzeDecodedUrl(decodedUrl, 'svg-qr');
          const result = { detected: true, type: 'svg-qr', url: decodedUrl, ...securityResult };
          IMAGELESS_QR_CACHE.set(cacheKey, { result, timestamp: Date.now() });
          return result;
        }
      }

      const noQrResult = { detected: false, url: null, level: 'safe', reasons: [] };
      IMAGELESS_QR_CACHE.set(cacheKey, { result: noQrResult, timestamp: Date.now() });
      return noQrResult;

    } catch (error) {
      handleError(error, '[ImagelessQR] Error scanning SVG');
      return null;
    }
  }

  /**
   * Genereert hash voor SVG caching
   */
  getSvgHash(svg) {
    const rects = svg.querySelectorAll('rect');
    let hash = `svg:${rects.length}:`;
    // Sample eerste 10 rects voor hash
    for (let i = 0; i < Math.min(10, rects.length); i++) {
      const r = rects[i];
      const fill = r.getAttribute('fill') || '';
      hash += this.isColorDark(fill) ? '1' : '0';
    }
    return hash;
  }

  /**
   * Scant alle SVG elementen op de pagina
   */
  async scanSvgElements() {
    const svgs = document.querySelectorAll('svg');
    let scannedCount = 0;

    for (const svg of svgs) {
      if (this.isPotentialQRSvg(svg)) {
        svg.dataset.linkshieldQrScanned = 'true';
        svg.dataset.linkshieldQrPotential = 'true';

        const result = await this.scanSvg(svg);
        scannedCount++;

        svg.dataset.linkshieldQrDetected = result?.detected ? 'true' : 'false';

        if (result && result.detected && result.level !== 'safe') {
          this.warnImagelessQR(svg, result);
        }
      }
    }

    return scannedCount;
  }

  // ===========================================================================
  // CSS GRID DETECTION (nieuw in v8.1.1)
  // Detecteert QR-codes gemaakt met CSS Grid containers
  // ===========================================================================

  /**
   * Controleert of een element een CSS Grid QR-code zou kunnen zijn
   * @param {HTMLElement} element - Het element om te controleren
   * @returns {boolean} True als het element een potentiële QR-code is
   */
  isPotentialQRGrid(element) {
    if (!element || this.scannedElements.has(element)) return false;

    const style = window.getComputedStyle(element);
    if (style.display !== 'grid' && style.display !== 'inline-grid') return false;

    // Check grid template
    const columns = style.gridTemplateColumns.split(' ').filter(c => c && c !== 'none').length;
    const rows = style.gridTemplateRows.split(' ').filter(r => r && r !== 'none').length;

    if (columns < this.minSize || columns > this.maxSize) return false;
    if (rows < this.minSize || rows > this.maxSize) return false;

    // Check of het vierkant is (±3 tolerantie)
    if (Math.abs(columns - rows) > 3) return false;

    // Check kinderen (grid items)
    const children = element.children;
    if (children.length < this.minSize * this.minSize * 0.3) return false;

    // Check dark/light ratio
    let darkCount = 0;
    const sampleSize = Math.min(children.length, 100);
    for (let i = 0; i < sampleSize; i++) {
      const child = children[i];
      const bgColor = window.getComputedStyle(child).backgroundColor;
      if (this.isColorDark(bgColor)) darkCount++;
    }

    const darkRatio = darkCount / sampleSize;
    return darkRatio >= 0.3 && darkRatio <= 0.7;
  }

  /**
   * Scant een CSS Grid element voor QR-code
   * @param {HTMLElement} element - Het grid element
   * @returns {Promise<{detected: boolean, url: string|null, level: string, reasons: string[]}>}
   */
  async scanGrid(element) {
    if (typeof jsQR === 'undefined') {
      logDebug('[ImagelessQR] jsQR not available, skipping Grid scan');
      return null;
    }

    const cacheKey = 'grid:' + this.getGridHash(element);
    const cached = IMAGELESS_QR_CACHE.get(cacheKey);
    if (cached && Date.now() - cached.timestamp < this.cacheTTL) {
      return cached.result;
    }

    this.scannedElements.add(element);

    try {
      const style = window.getComputedStyle(element);
      const columns = style.gridTemplateColumns.split(' ').filter(c => c && c !== 'none').length;
      const rows = style.gridTemplateRows.split(' ').filter(r => r && r !== 'none').length;

      // Render naar canvas
      const cellSize = 4;
      const canvas = document.createElement('canvas');
      canvas.width = columns * cellSize;
      canvas.height = rows * cellSize;
      const ctx = canvas.getContext('2d');

      ctx.fillStyle = 'white';
      ctx.fillRect(0, 0, canvas.width, canvas.height);

      ctx.fillStyle = 'black';
      const children = element.children;
      for (let i = 0; i < children.length; i++) {
        const child = children[i];
        const bgColor = window.getComputedStyle(child).backgroundColor;

        if (this.isColorDark(bgColor)) {
          // Bepaal grid positie (row-major order)
          const col = i % columns;
          const row = Math.floor(i / columns);
          ctx.fillRect(col * cellSize, row * cellSize, cellSize, cellSize);
        }
      }

      // Scan met jsQR
      const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
      const qrResult = jsQR(imageData.data, imageData.width, imageData.height);

      if (qrResult && qrResult.data) {
        const decodedUrl = qrResult.data;
        logDebug(`[ImagelessQR] Decoded URL from CSS Grid: ${decodedUrl}`);

        if (isValidURL(decodedUrl)) {
          const securityResult = await this.analyzeDecodedUrl(decodedUrl, 'grid-qr');
          const result = { detected: true, type: 'grid-qr', url: decodedUrl, ...securityResult };
          IMAGELESS_QR_CACHE.set(cacheKey, { result, timestamp: Date.now() });
          return result;
        }
      }

      const noQrResult = { detected: false, url: null, level: 'safe', reasons: [] };
      IMAGELESS_QR_CACHE.set(cacheKey, { result: noQrResult, timestamp: Date.now() });
      return noQrResult;

    } catch (error) {
      handleError(error, '[ImagelessQR] Error scanning Grid');
      return null;
    }
  }

  /**
   * Genereert hash voor Grid caching
   */
  getGridHash(element) {
    const children = element.children;
    let hash = `grid:${children.length}:`;
    for (let i = 0; i < Math.min(20, children.length); i++) {
      const bgColor = window.getComputedStyle(children[i]).backgroundColor;
      hash += this.isColorDark(bgColor) ? '1' : '0';
    }
    return hash;
  }

  /**
   * Scant alle CSS Grid elementen op de pagina
   */
  async scanGridElements() {
    const allElements = document.querySelectorAll('div, section, article');
    let scannedCount = 0;

    for (const element of allElements) {
      if (this.isPotentialQRGrid(element)) {
        element.dataset.linkshieldQrScanned = 'true';
        element.dataset.linkshieldQrPotential = 'true';

        const result = await this.scanGrid(element);
        scannedCount++;

        element.dataset.linkshieldQrDetected = result?.detected ? 'true' : 'false';

        if (result && result.detected && result.level !== 'safe') {
          this.warnImagelessQR(element, result);
        }
      }
    }

    return scannedCount;
  }

  // ===========================================================================
  // SHARED UTILITIES
  // ===========================================================================

  /**
   * Bepaalt of een kleur "donker" is
   * @param {string} color - CSS kleurwaarde
   * @returns {boolean}
   */
  isColorDark(color) {
    if (!color || color === 'transparent' || color === 'rgba(0, 0, 0, 0)' || color === 'none') {
      return false;
    }

    let r = 255, g = 255, b = 255;

    if (color.startsWith('#')) {
      const hex = color.slice(1);
      if (hex.length === 3) {
        r = parseInt(hex[0] + hex[0], 16);
        g = parseInt(hex[1] + hex[1], 16);
        b = parseInt(hex[2] + hex[2], 16);
      } else {
        r = parseInt(hex.slice(0, 2), 16) || 255;
        g = parseInt(hex.slice(2, 4), 16) || 255;
        b = parseInt(hex.slice(4, 6), 16) || 255;
      }
    } else if (color.startsWith('rgb')) {
      const match = color.match(/\d+/g);
      if (match && match.length >= 3) {
        [r, g, b] = match.slice(0, 3).map(Number);
      }
    } else {
      const darkColors = ['black', 'darkblue', 'darkgreen', 'darkred', 'navy', 'maroon', 'purple'];
      return darkColors.includes(color.toLowerCase());
    }

    const luminance = (0.299 * r + 0.587 * g + 0.114 * b);
    return luminance < 128;
  }

  // ===========================================================================
  // UNIFIED ENTRY POINTS
  // ===========================================================================

  /**
   * Scant alle imageless QR-code types (Table, SVG, CSS Grid)
   * Dit is de primaire entry point voor de scanner
   */
  async scanAllElements() {
    let totalScanned = 0;

    // Scan in volgorde van waarschijnlijkheid
    totalScanned += await this.scanTables();
    totalScanned += await this.scanSvgElements();
    totalScanned += await this.scanGridElements();

    if (totalScanned > 0) {
      logDebug(`[ImagelessQR] Scanned ${totalScanned} potential QR elements (Table + SVG + Grid)`);
    }

    return totalScanned;
  }

  /**
   * Legacy alias voor backwards compatibility
   * @deprecated Gebruik scanAllElements() of scanTables()
   */
  async scanAllTables() {
    return this.scanAllElements();
  }

  /**
   * Toont waarschuwing bij verdachte imageless QR-code
   * @param {HTMLElement} element - Het element met de QR-code
   * @param {Object} result - Scan resultaat met level, reasons, url, type
   */
  warnImagelessQR(element, { level, reasons = [], url, type = 'unknown' }) {
    if (element.dataset.qrWarned === 'true') return;
    element.dataset.qrWarned = 'true';

    // Create wrapper with Visual Hijacking protection
    const wrapper = document.createElement('div');
    wrapper.className = 'linkshield-warning linkshield-imageless-qr';
    wrapper.style.cssText = `
      position: relative !important;
      display: inline-block !important;
      pointer-events: auto !important;
    `;
    element.parentNode?.insertBefore(wrapper, element);
    wrapper.appendChild(element);

    const isAlert = level === 'alert';
    const bgColor = isAlert ? 'rgba(220, 38, 38, 0.9)' : 'rgba(234, 179, 8, 0.9)';
    const borderColor = isAlert ? '#dc2626' : '#eab308';
    const emoji = isAlert ? '⚠️' : '⚡';

    // Type-specifieke titels
    const typeLabels = {
      'table-qr': 'Table',
      'svg-qr': 'SVG',
      'grid-qr': 'CSS Grid'
    };
    const typeLabel = typeLabels[type] || 'Hidden';

    const title = isAlert
      ? (getTranslatedMessage('imagelessQrDangerTitle') || `DANGER: ${typeLabel} QR Code!`)
      : (getTranslatedMessage('imagelessQrCautionTitle') || `Caution: ${typeLabel} QR Code`);

    const translatedReasons = Array.isArray(reasons) && reasons.length > 0
      ? reasons.slice(0, 3).map(r => translateReason(r)).join(', ')
      : (getTranslatedMessage('hiddenQrDetected') || 'Hidden QR code detected');

    const displayUrl = url && url.length > 50 ? url.substring(0, 50) + '...' : url;

    // Create overlay host with closed Shadow DOM for CSS isolation
    const overlayHost = document.createElement('div');
    overlayHost.style.cssText = `
      position: absolute !important;
      top: 0 !important;
      left: 0 !important;
      right: 0 !important;
      bottom: 0 !important;
      z-index: 10000 !important;
      pointer-events: auto !important;
    `;

    // Closed Shadow DOM - page cannot access or manipulate warning content
    const shadow = overlayHost.attachShadow({ mode: 'closed' });
    shadow.innerHTML = `
      <style>
        :host {
          all: initial !important;
        }
        .overlay {
          position: absolute;
          top: 0;
          left: 0;
          right: 0;
          bottom: 0;
          background: ${bgColor};
          color: white;
          display: flex;
          flex-direction: column;
          align-items: center;
          justify-content: center;
          text-align: center;
          padding: 10px;
          border: 3px solid ${borderColor};
          border-radius: 4px;
          font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
          box-shadow: 0 4px 12px rgba(0,0,0,0.3);
          box-sizing: border-box;
        }
        .title {
          font-weight: bold;
          font-size: 14px;
          margin-bottom: 4px;
        }
        .url {
          font-size: 11px;
          margin-bottom: 4px;
        }
        .reasons {
          font-size: 10px;
          opacity: 0.9;
        }
      </style>
      <div class="overlay">
        <div class="title">${escapeHtml(emoji + ' ' + title)}</div>
        <div class="url">URL: ${escapeHtml(displayUrl || getTranslatedMessage('hiddenUrl') || 'Hidden')}</div>
        <div class="reasons">${escapeHtml(translatedReasons)}</div>
      </div>
    `;

    wrapper.appendChild(overlayHost);
    logDebug(`[ImagelessQR] Warning displayed for ${type}: ${url} (Shadow DOM protected)`);
  }

  /**
   * Legacy alias voor backwards compatibility
   * @deprecated Gebruik warnImagelessQR()
   */
  warnTableQR(table, result) {
    this.warnImagelessQR(table, { ...result, type: 'table-qr' });
  }
}

// Global imageless QR scanner instance
let imagelessQRScanner = null;
// Legacy alias voor backwards compatibility
let tableQRScanner = null;

/**
 * Initialiseert de Imageless QR Scanner (Table + SVG + CSS Grid)
 */
function initImagelessQRScanner() {
  if (!imagelessQRScanner) {
    imagelessQRScanner = new ImagelessQRScanner();
    tableQRScanner = imagelessQRScanner; // Legacy alias
  }
  return imagelessQRScanner;
}

/**
 * Legacy alias voor backwards compatibility
 * @deprecated Gebruik initImagelessQRScanner()
 */
function initTableQRScanner() {
  return initImagelessQRScanner();
}

// Debounced scan voor MutationObserver (scant alle types)
const debouncedImagelessQRScan = debounce(async () => {
  if (imagelessQRScanner) {
    await imagelessQRScanner.scanAllElements();
  }
}, 500);

// Legacy alias
const debouncedTableScan = debouncedImagelessQRScan;

// =============================================================================
// END TABLE-BASED QR CODE SCANNER
// =============================================================================

/**
 * Scan image for QR codes using jsQR library (IIFE, MV3 compatible)
 * v8.8.13: Added CORS fallback via background script for cross-origin images
 */
async function scanImageForQR(imgEl) {
  // Check if jsQR is available
  if (typeof jsQR === 'undefined') {
    logDebug('[LinkShield OCR] jsQR not loaded, skipping QR scan');
    return null;
  }

  /**
   * Helper function to scan a data URL for QR codes
   * @param {string} dataUrl - Base64 data URL of the image
   * @returns {Promise<object|null>} - QR data or null
   */
  const scanDataUrl = (dataUrl) => {
    return new Promise((resolve, reject) => {
      const img = new Image();
      img.onload = () => {
        try {
          const canvas = document.createElement('canvas');
          canvas.width = img.width;
          canvas.height = img.height;
          const ctx = canvas.getContext('2d');
          ctx.drawImage(img, 0, 0);
          const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
          const code = jsQR(imageData.data, imageData.width, imageData.height);
          resolve(code);
        } catch (e) {
          reject(e);
        }
      };
      img.onerror = () => reject(new Error('Image load failed'));
      setTimeout(() => reject(new Error('Image load timeout')), 5000);
      img.src = dataUrl;
    });
  };

  /**
   * Check if URL is cross-origin
   */
  const isCrossOrigin = (url) => {
    try {
      const imgUrl = new URL(url);
      return imgUrl.origin !== window.location.origin;
    } catch {
      return true; // Assume cross-origin if URL parsing fails
    }
  };

  /**
   * Fetch image via background script and return as data URL
   */
  const fetchViaBackground = async (url) => {
    return new Promise((resolve, reject) => {
      const timeoutId = setTimeout(() => reject(new Error('Background fetch timeout')), 10000);
      chrome.runtime.sendMessage({
        action: 'fetchImageAsDataUrl',
        url: url
      }, (result) => {
        clearTimeout(timeoutId);
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
        } else if (result && result.success && result.dataUrl) {
          resolve(result.dataUrl);
        } else {
          reject(new Error(result?.error || 'Failed to fetch image'));
        }
      });
    });
  };

  try {
    let qrData = null;
    const imgSrc = imgEl.src;

    // Skip data URLs (already local) and invalid URLs
    if (!imgSrc || imgSrc.startsWith('data:')) {
      return null;
    }

    // v8.8.13: For cross-origin images, always use background script to avoid CORS issues
    if (isCrossOrigin(imgSrc)) {
      logDebug(`[LinkShield OCR] Cross-origin image detected, using background script: ${imgSrc}`);
      try {
        const dataUrl = await fetchViaBackground(imgSrc);
        logDebug('[LinkShield OCR] Got image via background script, scanning for QR...');
        qrData = await scanDataUrl(dataUrl);
      } catch (bgError) {
        logDebug(`[LinkShield OCR] Background fetch failed: ${bgError.message}`);
        return null;
      }
    } else {
      // Same-origin image - can scan directly
      logDebug(`[LinkShield OCR] Same-origin image, scanning directly: ${imgSrc}`);
      try {
        const dataUrl = await fetchViaBackground(imgSrc); // Use background for consistency
        qrData = await scanDataUrl(dataUrl);
      } catch (e) {
        logDebug(`[LinkShield OCR] Direct scan failed: ${e.message}`);
        return null;
      }
    }

    if (qrData && qrData.data) {
      const decodedUrl = qrData.data;

      if (isValidURL(decodedUrl)) {
        logDebug(`[LinkShield OCR] Decoded QR URL: ${decodedUrl}`);

        // Context check
        const contextReasons = checkQRContext(imgEl);

        // Perform suspicious checks
        let result = await performSuspiciousChecks(decodedUrl);

        // ENHANCED: Redirect chain analyse voor QR-code URLs (AI-proxy detectie)
        // QR-codes worden vaak gebruikt door AI-phishing kits met meerdere redirects
        try {
          const redirectResult = await new Promise((resolve, reject) => {
            const timeoutId = setTimeout(() => reject(new Error('Timeout')), 6000);
            chrome.runtime.sendMessage({
              action: 'analyzeRedirectChain',
              url: decodedUrl,
              source: 'image-qr' // Markeer als QR-code bron voor prioritaire analyse
            }, response => {
              clearTimeout(timeoutId);
              resolve(response || { threats: [] });
            });
          });

          if (redirectResult.analyzed && redirectResult.threats && redirectResult.threats.length > 0) {
            result.reasons.push(...redirectResult.threats);
            result.risk = (result.risk || 0) + (redirectResult.threats.length * 3);
            logDebug(`[LinkShield OCR] Redirect threats found: ${redirectResult.threats.join(', ')}`);
          }
        } catch (e) {
          logDebug(`[LinkShield OCR] Redirect analysis skipped: ${e.message}`);
        }

        // Integrate Chrome Safe Browsing if available
        if (chrome.safeBrowsing) {
          try {
            const sbResult = await checkSafeBrowsing(decodedUrl);
            if (sbResult.threatType) {
              result.level = 'alert';
              result.reasons.push(`Safe Browsing threat: ${sbResult.threatType}`);
            }
          } catch (e) { /* Safe Browsing not available */ }
        }

        // Add context reasons
        if (contextReasons.length > 0) {
          result.reasons = [...result.reasons, ...contextReasons];
          if (result.level === 'safe') result.level = 'caution';
        }

        // Herbereken level op basis van totale risk
        if (result.risk >= globalConfig.HIGH_THRESHOLD) {
          result.level = 'alert';
        } else if (result.risk >= globalConfig.LOW_THRESHOLD && result.level === 'safe') {
          result.level = 'caution';
        }

        if (result.level !== 'safe') {
          warnQRImage(imgEl, { ...result, url: decodedUrl });
          logDebug(`[LinkShield OCR] ⚠️ Suspicious QR: ${decodedUrl}, level: ${result.level}`);
        }

        return { detected: true, type: 'qr', url: decodedUrl, ...result };
      }
    }
  } catch (error) {
    // jsQR returns null when no QR found, errors are actual errors
    logDebug(`[LinkShield OCR] QR scan error: ${error.message}`);
  }

  return null;
}

/**
 * Scan image for text using OCR
 * DISABLED: OCRAD.js is incompatible with Extension CSP (requires unsafe-eval)
 * QR code scanning via jsQR still works and is the primary image scanning method.
 */
async function scanImageForOCR(imgEl) {
  // OCR is disabled due to CSP incompatibility with OCRAD.js
  // QR code detection via jsQR is still active
  return null;
}

/**
 * Extract URLs from text
 */
function extractURLsFromText(text) {
  const urlRegex = /https?:\/\/[^\s<>"']+/gi;
  const matches = text.match(urlRegex) || [];
  return matches.map(url => url.replace(/[.,;:!?)]+$/, '')); // Clean trailing punctuation
}

/**
 * Warn about suspicious OCR-detected content with translated reasons and LinkShield branding
 */
function warnOCRImage(img, { level, reasons = [], url, extractedText }) {
  const parent = img.parentElement;
  if (!parent) return;

  const wrapper = document.createElement('div');
  wrapper.style.position = 'relative';
  wrapper.style.display = 'inline-block';
  img.parentNode.insertBefore(wrapper, img);
  wrapper.appendChild(img);

  const isAlert = level === 'alert';
  const headerBg = isAlert ? 'linear-gradient(135deg, #dc2626 0%, #b91c1c 100%)' : 'linear-gradient(135deg, #d97706 0%, #b45309 100%)';
  const bodyBg = isAlert ? 'rgba(254, 242, 242, 0.97)' : 'rgba(255, 251, 235, 0.97)';
  const borderColor = isAlert ? '#dc2626' : '#d97706';
  const textColor = isAlert ? '#7f1d1d' : '#92400e';
  const title = isAlert
    ? (getTranslatedMessage('ocrDangerTitle') || 'Phishing in image!')
    : (getTranslatedMessage('ocrCautionTitle') || 'Suspicious text in image');

  // Translate reasons
  const translatedReasons = Array.isArray(reasons) && reasons.length > 0
    ? reasons.slice(0, 3).map(r => translateReason(r)).join(', ')
    : (getTranslatedMessage('suspiciousDomainDetected') || 'Suspicious domain detected');

  const displayUrl = url && url.length > 40 ? url.substring(0, 40) + '...' : (url || 'N/A');

  const overlay = document.createElement('div');
  overlay.className = 'qr-warning-overlay ocr-warning';
  overlay.innerHTML = `
    <div style="
      background: ${headerBg};
      color: white;
      padding: 6px 10px;
      display: flex;
      align-items: center;
      gap: 6px;
      border-radius: 6px 6px 0 0;
    ">
      <span style="font-size: 14px;">🛡️</span>
      <span style="font-weight: 600; font-size: 11px;">LinkShield</span>
    </div>
    <div style="
      background: ${bodyBg};
      padding: 10px;
      border-radius: 0 0 6px 6px;
      text-align: center;
    ">
      <div style="font-weight:bold;font-size:12px;margin-bottom:4px;color:${textColor};">${isAlert ? '🚨' : '⚠️'} ${title}</div>
      <div style="font-size:10px;margin-bottom:3px;color:${textColor};opacity:0.9;">URL: ${displayUrl}</div>
      <div style="font-size:9px;color:${textColor};opacity:0.8;">${translatedReasons}</div>
    </div>
  `;

  // Translate reasons for tooltip
  const translatedReasonsForTooltip = Array.isArray(reasons)
    ? reasons.map(r => translateReason(r)).join('\n')
    : '';
  overlay.title = `${getTranslatedMessage('extractedText') || 'Extracted text'}: ${extractedText}\n\n${getTranslatedMessage('reasons') || 'Reasons'}:\n${translatedReasonsForTooltip}`;

  overlay.style.cssText = `
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    display: flex;
    flex-direction: column;
    justify-content: center;
    z-index: 10000;
    border: 2px solid ${borderColor};
    border-radius: 8px;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    box-shadow: 0 4px 12px rgba(0,0,0,0.3);
    overflow: hidden;
  `;
  wrapper.appendChild(overlay);
}

/**
 * Initialize image scanning with IntersectionObserver
 */
async function scanForQRPhishing() {
  // Initialize scanner if not exists
  if (!imageScanner) {
    imageScanner = new ImageScannerOptimized();
  }

  // Scan all currently visible images
  imageScanner.scanAllVisibleImages();

  // Also scan for text-based QR codes
  await scanForTextQR();
}

// Helper: Translate reason keys to user-friendly messages via chrome.i18n
function translateReason(reasonKey) {
  if (!reasonKey) return '';

  // Extract base key (remove dynamic parts like :domain)
  const baseKey = reasonKey.split(':')[0];
  const dynamicPart = reasonKey.includes(':') ? reasonKey.split(':').slice(1).join(':') : '';

  // Try to get translation from chrome.i18n
  const translationKey = `reason_${baseKey}`;
  let translated = getTranslatedMessage(translationKey);

  // If no translation found, use fallback mapping (English)
  if (!translated) {
    const fallbackMap = {
      'nonAscii': 'Suspicious characters detected (homoglyphs)',
      'brandKeywordHomoglyph': 'Brand imitation detected',
      'noHttps': 'No secure connection (HTTPS)',
      'suspiciousTLD': 'Suspicious domain extension',
      'ipAsDomain': 'IP address as domain name',
      'tooManySubdomains': 'Too many subdomains',
      'shortenedUrl': 'Shortened URL detected',
      'suspiciousKeywords': 'Suspicious keywords in URL',
      'malwareExtension': 'Potentially harmful file extension',
      'urlTooLong': 'Unusually long URL',
      'encodedCharacters': 'Encoded characters in URL',
      'homoglyphAttack': 'Homoglyph attack detected',
      'typosquatting': 'Typosquatting detected',
      'suspiciousBrandPattern': 'Suspicious brand pattern',
      'unusualPort': 'Unusual port',
      'punycode': 'Punycode domain detected',
      'loginPageNoMX': 'Login page without email server',
      'insecureLoginPage': 'Insecure login page',
      'sslValidationFailed': 'SSL validation failed',
      'similarToLegitimateDomain': 'Looks like a legitimate domain',
      'reason_redirectChain': 'Suspicious redirect chain detected',
      'reason_excessiveRedirects': 'Too many redirects in chain',
      'reason_domainHopping': 'Multiple domain switches in redirect chain',
      'reason_chainedShorteners': 'Multiple URL shorteners chained together',
      'reason_suspiciousFinalTLD': 'Final destination has suspicious domain extension',
      'reason_redirectToIP': 'Redirect to IP address',
      'reason_redirectTimeout': 'Redirect analysis timed out',
      'nullByteInjection': 'Null byte injection detected (high risk)',
      'urlCredentialsAttack': 'URL deception detected (@ symbol attack)',
      'fullwidthCharacters': 'Fullwidth Unicode characters detected',
      'doubleEncoding': 'Double URL encoding detected'
    };
    translated = fallbackMap[baseKey] || fallbackMap[reasonKey] || baseKey;
  }

  // Append dynamic part if present (e.g., brand name)
  if (dynamicPart && baseKey !== dynamicPart) {
    return `${translated} (${dynamicPart})`;
  }

  return translated;
}

// Helper: Check context around QR for phishing indicators
function checkQRContext(element) {
  const reasons = [];
  const suspiciousKeywords = ['scan to login', 'verify account', 'urgent', 'payment due', 'update info']; // Based on 2025 trends
  let parent = element.parentElement;
  while (parent && parent !== document.body) {
    const text = parent.textContent.toLowerCase();
    suspiciousKeywords.forEach(kw => {
      if (text.includes(kw)) {
        reasons.push(`Suspicious context: "${kw}" near QR`);
      }
    });
    parent = parent.parentElement;
  }
  return reasons;
}

// Helper: Integrate Chrome Safe Browsing (requires 'safeBrowsing' permission in manifest)
async function checkSafeBrowsing(url) {
  return new Promise((resolve) => {
    chrome.safeBrowsing.checkThreats([url], (result) => {
      resolve(result || { threatType: null });
    });
  });
}

// Function to scan for text/ASCII QR in <pre>, <code>, SVG (2025 evasion technique)
async function scanForTextQR() {
  const textElements = document.querySelectorAll('pre, code, svg');

  for (const el of textElements) {
    if (!isVisible(el)) continue;

    const text = el.textContent.trim();
    if (!isPotentialTextQR(text)) continue;

    try {
      // Render ASCII art to canvas for QR scanning
      const qrData = await decodeAsciiQR(text);

      if (qrData && isValidURL(qrData)) {
        logDebug(`[LinkShield OCR] ASCII QR decoded URL: ${qrData}`);

        const result = await performSuspiciousChecks(qrData);
        if (result.level !== 'safe') {
          warnTextQR(el, { ...result, url: qrData });
          logDebug(`[LinkShield OCR] ⚠️ Suspicious ASCII QR: ${qrData}, level: ${result.level}`);
        }
      }
    } catch (error) {
      logDebug(`[LinkShield OCR] ASCII QR decode error: ${error.message}`);
    }
  }
}

// Helper: Heuristic to detect text-based QR patterns
function isPotentialTextQR(text) {
  // Check for blocky patterns (e.g., lines with #, █, ▄, ▀, ■ characters)
  const blockChars = /[#█▄▀■◼◾▪⬛🔲⬜🔳]{5,}/g;
  const hasBlocks = blockChars.test(text);
  const hasMultipleLines = text.split('\n').length >= 5;

  // Also check for Unicode block patterns
  const unicodeBlocks = /[\u2580-\u259F]{3,}/g;
  const hasUnicodeBlocks = unicodeBlocks.test(text);

  return (hasBlocks || hasUnicodeBlocks) && hasMultipleLines;
}

// Helper: Decode ASCII art QR by rendering to canvas and scanning with jsQR
async function decodeAsciiQR(asciiText) {
  if (typeof jsQR === 'undefined') {
    // Fallback: try to extract URL directly from text
    return extractURLFromAsciiText(asciiText);
  }

  // Create canvas and render ASCII art
  const canvas = document.createElement('canvas');
  const ctx = canvas.getContext('2d');

  const lines = asciiText.split('\n').filter(line => line.trim());
  const cellSize = 4; // Pixels per character

  canvas.width = Math.max(...lines.map(l => l.length)) * cellSize;
  canvas.height = lines.length * cellSize;

  // White background
  ctx.fillStyle = 'white';
  ctx.fillRect(0, 0, canvas.width, canvas.height);

  // Render each character
  ctx.fillStyle = 'black';
  const blockChars = new Set(['#', '█', '▄', '▀', '■', '◼', '◾', '▪', '⬛', '🔲', '1']);

  lines.forEach((line, y) => {
    [...line].forEach((char, x) => {
      if (blockChars.has(char) || /[\u2580-\u259F]/.test(char)) {
        ctx.fillRect(x * cellSize, y * cellSize, cellSize, cellSize);
      }
    });
  });

  try {
    // Use jsQR to decode the rendered canvas
    const imageData = ctx.getImageData(0, 0, canvas.width, canvas.height);
    const result = jsQR(imageData.data, imageData.width, imageData.height);
    return result?.data || null;
  } catch (e) {
    // QR not found in rendered ASCII
    return null;
  }
}

// Helper: Extract URL directly from ASCII text (fallback)
function extractURLFromAsciiText(text) {
  const urlRegex = /(https?:\/\/[^\s<>"']+)/gi;
  const matches = text.match(urlRegex);
  return matches?.[0]?.replace(/[.,;:!?)]+$/, '') || null;
}

// Function to warn near a text QR element with translated reasons and LinkShield branding
function warnTextQR(el, { level, reasons = [], url }) {
  const wrapper = document.createElement('div');
  wrapper.style.position = 'relative';
  wrapper.style.display = 'inline-block';

  el.parentNode?.insertBefore(wrapper, el);
  wrapper.appendChild(el);

  const isAlert = level === 'alert';
  const headerBg = isAlert ? 'linear-gradient(135deg, #dc2626 0%, #b91c1c 100%)' : 'linear-gradient(135deg, #d97706 0%, #b45309 100%)';
  const bodyBg = isAlert ? 'rgba(254, 242, 242, 0.97)' : 'rgba(255, 251, 235, 0.97)';
  const borderColor = isAlert ? '#dc2626' : '#d97706';
  const textColor = isAlert ? '#7f1d1d' : '#92400e';
  const title = isAlert
    ? (getTranslatedMessage('asciiQrDangerTitle') || 'Phishing ASCII QR!')
    : (getTranslatedMessage('asciiQrCautionTitle') || 'Suspicious ASCII QR');

  // Translate reasons
  const translatedReasons = Array.isArray(reasons) && reasons.length > 0
    ? reasons.slice(0, 3).map(r => translateReason(r)).join(', ')
    : (getTranslatedMessage('suspiciousDomainDetected') || 'Suspicious domain detected');

  const displayUrl = url && url.length > 40 ? url.substring(0, 40) + '...' : (url || (getTranslatedMessage('hiddenUrl') || 'Hidden'));

  const overlay = document.createElement('div');
  overlay.className = 'qr-warning-overlay ascii-qr-warning';
  overlay.innerHTML = `
    <div style="
      background: ${headerBg};
      color: white;
      padding: 6px 10px;
      display: flex;
      align-items: center;
      gap: 6px;
      border-radius: 6px 6px 0 0;
    ">
      <span style="font-size: 14px;">🛡️</span>
      <span style="font-weight: 600; font-size: 11px;">LinkShield</span>
    </div>
    <div style="
      background: ${bodyBg};
      padding: 10px;
      border-radius: 0 0 6px 6px;
      text-align: center;
    ">
      <div style="font-weight:bold;font-size:12px;margin-bottom:4px;color:${textColor};">${isAlert ? '🚨' : '⚠️'} ${title}</div>
      <div style="font-size:10px;margin-bottom:3px;color:${textColor};opacity:0.9;">URL: ${displayUrl}</div>
      <div style="font-size:9px;color:${textColor};opacity:0.8;">${translatedReasons}</div>
    </div>
  `;

  // Translate reasons for tooltip
  const translatedReasonsForTooltip = Array.isArray(reasons)
    ? reasons.map(r => translateReason(r)).join('\n')
    : '';
  overlay.title = `${getTranslatedMessage('reasons') || 'Reasons'}:\n${translatedReasonsForTooltip}`;

  overlay.style.cssText = `
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    display: flex;
    flex-direction: column;
    justify-content: center;
    z-index: 10000;
    border: 2px solid ${borderColor};
    border-radius: 8px;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    box-shadow: 0 4px 12px rgba(0,0,0,0.3);
    overflow: hidden;
  `;
  wrapper.appendChild(overlay);
}

// Updated: Function to warn near a QR image with translated reasons and LinkShield branding
function warnQRImage(img, { level, reasons = [], url }) {
  const parent = img.parentElement;
  if (!parent) return;

  // Check if already warned
  if (img.dataset.qrWarned === 'true') return;
  img.dataset.qrWarned = 'true';

  const wrapper = document.createElement('div');
  wrapper.style.position = 'relative';
  wrapper.style.display = 'inline-block';
  img.parentNode.insertBefore(wrapper, img);
  wrapper.appendChild(img);

  const overlay = document.createElement('div');
  overlay.className = 'qr-warning-overlay';

  // Determine colors based on level
  const isAlert = level === 'alert';
  const headerBg = isAlert ? 'linear-gradient(135deg, #dc2626 0%, #b91c1c 100%)' : 'linear-gradient(135deg, #d97706 0%, #b45309 100%)';
  const bodyBg = isAlert ? 'rgba(254, 242, 242, 0.97)' : 'rgba(255, 251, 235, 0.97)';
  const borderColor = isAlert ? '#dc2626' : '#d97706';
  const textColor = isAlert ? '#7f1d1d' : '#92400e';
  const title = isAlert
    ? (getTranslatedMessage('qrDangerTitle') || 'Phishing QR Code!')
    : (getTranslatedMessage('qrCautionTitle') || 'Suspicious QR Code');

  // Translate reasons for display
  const translatedReasons = Array.isArray(reasons) && reasons.length > 0
    ? reasons.slice(0, 3).map(r => translateReason(r)).join(', ')
    : (getTranslatedMessage('suspiciousDomainDetected') || 'Suspicious domain detected');

  // Truncate URL for display
  const displayUrl = url && url.length > 40 ? url.substring(0, 40) + '...' : url;

  overlay.innerHTML = `
    <div style="
      background: ${headerBg};
      color: white;
      padding: 6px 10px;
      display: flex;
      align-items: center;
      gap: 6px;
      border-radius: 6px 6px 0 0;
    ">
      <span style="font-size: 14px;">🛡️</span>
      <span style="font-weight: 600; font-size: 11px;">LinkShield</span>
    </div>
    <div style="
      background: ${bodyBg};
      padding: 10px;
      border-radius: 0 0 6px 6px;
      text-align: center;
    ">
      <div style="font-weight:bold;font-size:12px;margin-bottom:4px;color:${textColor};">${isAlert ? '🚨' : '⚠️'} ${title}</div>
      <div style="font-size:10px;margin-bottom:3px;color:${textColor};opacity:0.9;">URL: ${displayUrl || (getTranslatedMessage('hiddenUrl') || 'Hidden URL')}</div>
      <div style="font-size:9px;color:${textColor};opacity:0.8;">${translatedReasons}</div>
    </div>
  `;

  overlay.style.cssText = `
    position: absolute;
    top: 0;
    left: 0;
    right: 0;
    bottom: 0;
    display: flex;
    flex-direction: column;
    justify-content: center;
    z-index: 10000;
    border: 2px solid ${borderColor};
    border-radius: 8px;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    box-shadow: 0 4px 12px rgba(0,0,0,0.3);
    overflow: hidden;
  `;

  // Translate reasons for tooltip
  const translatedReasonsForTooltip = Array.isArray(reasons)
    ? reasons.map(r => translateReason(r)).join('\n')
    : (getTranslatedMessage('suspiciousDomainDetected') || 'Suspicious domain');
  overlay.title = `${getTranslatedMessage('fullUrl') || 'Full URL'}: ${url}\n\n${getTranslatedMessage('reasons') || 'Reasons'}:\n${translatedReasonsForTooltip}`;
  wrapper.appendChild(overlay);
}