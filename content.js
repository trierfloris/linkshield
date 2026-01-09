/**
 * Logt debug-informatie - PRODUCTIE: functie doet niets.
 * @param {string} message - Het bericht om te loggen.
 * @param {...any} optionalParams - Optionele parameters.
 */
function logDebug(message, ...optionalParams) {
  // PRODUCTIE: Logging uitgeschakeld
}
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
 * @param {string} messageKey
 * @returns {string}
 */
function getTranslatedMessage(messageKey) {
  return chrome.i18n.getMessage(messageKey);
}
/**
 * Logt een foutmelding.
 * @param {string} message - Het foutbericht.
 * @param {...any} optionalParams - Optionele parameters.
 */
function logError(message, ...optionalParams) {
  console.error(message, ...optionalParams);
}
/**
 * Centrale foutafhandelingsfunctie die een fout logt met context.
 * @param {Error} error - De fout.
 * @param {string} context - Contextuele informatie over waar de fout is opgetreden.
 */
function handleError(error, context) {
  logError(`[${context}] ${error.message}`, error);
}
// Global configuration
let globalConfig = null;
let globalHomoglyphReverseMap = {};
// Shared constants for throttling and caching
const CHECK_INTERVAL_MS = 5000; // 5 seconds between checks
const CACHE_DURATION_MS = 3600 * 1000; // 1 hour cache expiration
const MAX_CACHE_SIZE = 1000;
const MUTATION_DEBOUNCE_MS = 500; // Increased from 250ms for heavy SPA sites
const warnedDomainsInline = new Set()

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
// Throttle tracking variables (global scope for persistence)
let lastIframeCheck = 0;
let lastScriptCheck = 0;

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
    // Maak waarschuwingsbanner
    const warning = document.createElement('div');
    warning.id = 'linkshield-clipboard-warning';
    warning.style.cssText = `
        position: fixed;
        top: 10px;
        right: 10px;
        background: linear-gradient(135deg, #dc2626 0%, #991b1b 100%);
        color: white;
        padding: 16px 20px;
        border-radius: 8px;
        box-shadow: 0 4px 20px rgba(0,0,0,0.3);
        z-index: 2147483647;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        font-size: 14px;
        max-width: 350px;
        animation: slideIn 0.3s ease-out;
    `;

    const title = type.includes('Crypto')
        ? chrome.i18n.getMessage('clipboardHijackingCryptoTitle') || '⚠️ Crypto Address Hijacking Detected!'
        : chrome.i18n.getMessage('clipboardHijackingTitle') || '⚠️ Clipboard Manipulation Detected!';

    const message = chrome.i18n.getMessage('clipboardHijackingMessage') ||
        'This page is attempting to modify your clipboard. Be careful when pasting wallet addresses.';

    warning.innerHTML = `
        <div style="font-weight: bold; margin-bottom: 8px; font-size: 15px;">${title}</div>
        <div style="opacity: 0.95; line-height: 1.4;">${message}</div>
        <button id="linkshield-clipboard-close" style="
            position: absolute;
            top: 8px;
            right: 8px;
            background: none;
            border: none;
            color: white;
            font-size: 18px;
            cursor: pointer;
            opacity: 0.8;
        ">×</button>
    `;

    // Voeg animatie style toe
    const style = document.createElement('style');
    style.textContent = `
        @keyframes slideIn {
            from { transform: translateX(100%); opacity: 0; }
            to { transform: translateX(0); opacity: 1; }
        }
    `;
    document.head.appendChild(style);
    document.body.appendChild(warning);

    // Close button
    document.getElementById('linkshield-clipboard-close')?.addEventListener('click', () => {
        warning.remove();
    });

    // Auto-remove na 15 seconden
    setTimeout(() => warning.remove(), 15000);
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
function initClickFixDetection() {
    if (clickFixDetectionInitialized) return;
    clickFixDetectionInitialized = true;

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
function scanForClickFixAttack() {
    if (clickFixDetected) return; // Voorkom herhaalde waarschuwingen

    try {
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

        const allContent = textContent + ' ' + codeContent;
        const detectedPatterns = [];
        let totalScore = 0;

        // Check PowerShell patterns
        for (const pattern of patterns.powershell || []) {
            if (pattern.test(allContent)) {
                detectedPatterns.push({ type: 'powershell', pattern: pattern.toString() });
                totalScore += 10; // PowerShell is zeer verdacht
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
                // Check of nearby code PowerShell/CMD bevat
                for (const pattern of [...(patterns.powershell || []), ...(patterns.cmd || [])]) {
                    if (pattern.test(codeText)) {
                        detectedPatterns.push({ type: 'copyButtonNearMaliciousCode', pattern: pattern.toString() });
                        totalScore += 8;
                        break;
                    }
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
    // Verwijder bestaande waarschuwing
    document.getElementById('linkshield-clickfix-warning')?.remove();

    const hasPowerShell = patterns.some(p => p.type === 'powershell');

    const warning = document.createElement('div');
    warning.id = 'linkshield-clickfix-warning';
    warning.style.cssText = `
        position: fixed;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -50%);
        background: linear-gradient(135deg, #dc2626 0%, #7f1d1d 100%);
        color: white;
        padding: 24px 32px;
        border-radius: 12px;
        box-shadow: 0 8px 32px rgba(0,0,0,0.4);
        z-index: 2147483647;
        font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        font-size: 14px;
        max-width: 480px;
        text-align: center;
        animation: pulse 2s infinite;
    `;

    const title = hasPowerShell
        ? (chrome.i18n.getMessage('clickFixPowerShellTitle') || '⚠️ GEVAAR: PowerShell Aanval Gedetecteerd!')
        : (chrome.i18n.getMessage('clickFixCommandTitle') || '⚠️ GEVAAR: Verdacht Commando Gedetecteerd!');

    const message = chrome.i18n.getMessage('clickFixMessage') ||
        'Deze pagina probeert u te misleiden om een kwaadaardig commando uit te voeren. KOPIEER EN PLAK NIETS van deze pagina!';

    const subMessage = chrome.i18n.getMessage('clickFixSubMessage') ||
        'Legitieme websites vragen NOOIT om PowerShell of CMD commando\'s te kopiëren.';

    warning.innerHTML = `
        <div style="font-size: 48px; margin-bottom: 16px;">🚨</div>
        <div style="font-size: 18px; font-weight: bold; margin-bottom: 12px;">${title}</div>
        <div style="margin-bottom: 16px; line-height: 1.5;">${message}</div>
        <div style="font-size: 12px; opacity: 0.9; margin-bottom: 20px;">${subMessage}</div>
        <div style="display: flex; gap: 12px; justify-content: center;">
            <button id="linkshield-clickfix-leave" style="
                background: white;
                color: #dc2626;
                border: none;
                padding: 12px 24px;
                border-radius: 6px;
                cursor: pointer;
                font-weight: bold;
                font-size: 14px;
            ">Verlaat deze pagina</button>
            <button id="linkshield-clickfix-close" style="
                background: transparent;
                color: white;
                border: 1px solid white;
                padding: 12px 24px;
                border-radius: 6px;
                cursor: pointer;
                font-size: 14px;
            ">Ik begrijp het risico</button>
        </div>
    `;

    // Voeg animatie toe
    const style = document.createElement('style');
    style.textContent = `
        @keyframes pulse {
            0%, 100% { box-shadow: 0 8px 32px rgba(220, 38, 38, 0.4); }
            50% { box-shadow: 0 8px 48px rgba(220, 38, 38, 0.6); }
        }
    `;
    document.head.appendChild(style);
    document.body.appendChild(warning);

    // Event listeners
    document.getElementById('linkshield-clickfix-leave')?.addEventListener('click', () => {
        window.history.back();
        setTimeout(() => { window.location.href = 'about:blank'; }, 100);
    });

    document.getElementById('linkshield-clickfix-close')?.addEventListener('click', () => {
        warning.remove();
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
function initBitBDetection() {
    if (bitbDetectionInitialized) return;
    bitbDetectionInitialized = true;

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
function scanForBitBAttack() {
    if (bitbDetected) return;

    try {
        const config = globalConfig?.BITB_DETECTION;
        if (!config) {
            logDebug('[BitB] No config available');
            return;
        }

        const indicators = [];
        let totalScore = 0;

        // 1. Zoek alle potentiële modal/overlay containers
        const overlays = findOverlayContainers();

        for (const overlay of overlays) {
            const result = analyzeOverlayForBitB(overlay, config);
            if (result.score > 0) {
                indicators.push(...result.indicators);
                totalScore += result.score;
            }
        }

        // 2. Globale check voor fake URL bars (ook buiten overlays)
        const fakeUrlBars = detectFakeUrlBarsGlobal(config);
        if (fakeUrlBars.length > 0) {
            indicators.push({ type: 'fakeUrlBarGlobal', count: fakeUrlBars.length });
            totalScore += fakeUrlBars.length * config.scores.fakeUrlBar;
        }

        // Evalueer resultaat
        const thresholds = config.thresholds;
        if (totalScore >= thresholds.critical) {
            bitbDetected = true;
            reportBitBAttack('critical', indicators, totalScore);
        } else if (totalScore >= thresholds.warning) {
            reportBitBAttack('warning', indicators, totalScore);
        } else if (totalScore >= thresholds.log) {
            logDebug(`[BitB] Low confidence: ${JSON.stringify(indicators)}, score: ${totalScore}`);
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

    try {
        const overlayText = (overlay.innerText || '').toLowerCase();

        // 1. Check voor fake URL bar elementen
        const fakeUrlBar = findFakeUrlBarInElement(overlay, config);
        if (fakeUrlBar) {
            indicators.push({
                type: 'fakeUrlBar',
                url: fakeUrlBar.textContent?.substring(0, 60)
            });
            score += scores.fakeUrlBar;
        }

        // 2. Check voor window control buttons (close/minimize/maximize)
        const windowControls = findWindowControls(overlay, config);
        if (windowControls.found) {
            indicators.push({ type: 'windowControls', details: windowControls.details });
            score += scores.windowControls;
        }

        // 3. Check voor login form binnen overlay
        const loginInputs = overlay.querySelectorAll(
            'input[type="password"], input[type="email"], ' +
            'input[name*="password"], input[name*="email"], input[name*="user"]'
        );

        if (loginInputs.length > 0) {
            indicators.push({ type: 'loginForm', inputs: loginInputs.length });
            score += scores.loginFormInOverlay;

            // Extra score als er ook OAuth branding is
            for (const brand of config.oauthBranding || []) {
                if (overlayText.includes(brand.toLowerCase())) {
                    indicators.push({ type: 'oauthBranding', brand });
                    score += scores.oauthBrandingWithForm;
                    break;
                }
            }
        }

        // 4. Check voor padlock/security icons
        if (detectPadlockIcon(overlay)) {
            indicators.push({ type: 'padlockIcon' });
            score += scores.padlockIcon;
        }

        // 5. Check voor OS-achtige window chrome styling
        if (hasWindowChromeStyle(overlay)) {
            indicators.push({ type: 'windowChromeStyle' });
            score += scores.windowChromeStyle;
        }

        // 6. Check voor iframe binnen modal met login
        const iframes = overlay.querySelectorAll('iframe');
        if (iframes.length > 0 && loginInputs.length > 0) {
            indicators.push({ type: 'iframeInModal', count: iframes.length });
            score += scores.iframeInModal;
        }

    } catch (error) {
        handleError(error, '[BitB] analyzeOverlay');
    }

    return { score, indicators };
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

    return { found: details.length > 0, details };
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

        // Heeft een "title bar" achtig kind element
        const hasHeader = element.querySelector(
            '[class*="header"], [class*="title"], [class*="toolbar"], [class*="top-bar"]'
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
    // Verwijder bestaande waarschuwing
    document.getElementById('linkshield-bitb-warning')?.remove();

    const isCritical = severity === 'critical';

    // Design tokens (matching shared.css)
    const colors = {
        danger: '#dc2626',
        dangerLight: '#fef2f2',
        dangerBorder: '#fecaca',
        dangerText: '#991b1b',
        warning: '#d97706',
        warningLight: '#fffbeb',
        warningBorder: '#fde68a',
        warningText: '#92400e',
        textSecondary: '#6b7280',
        surface: '#ffffff',
        border: 'rgba(0, 0, 0, 0.08)'
    };

    const themeColor = isCritical ? colors.danger : colors.warning;
    const themeBg = isCritical ? colors.dangerLight : colors.warningLight;
    const themeBorder = isCritical ? colors.dangerBorder : colors.warningBorder;
    const themeText = isCritical ? colors.dangerText : colors.warningText;

    const warning = document.createElement('div');
    warning.id = 'linkshield-bitb-warning';
    warning.style.cssText = `
        position: fixed;
        top: 20px;
        left: 50%;
        transform: translateX(-50%);
        background: ${colors.surface};
        color: #1f1f1f;
        padding: 20px;
        border-radius: 8px;
        box-shadow: 0 8px 32px rgba(0,0,0,0.15);
        border: 1px solid ${colors.border};
        z-index: 2147483647;
        font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        font-size: 14px;
        max-width: 520px;
        min-width: 320px;
        animation: bitbSlideIn 0.3s ease-out;
    `;

    const title = isCritical
        ? (chrome.i18n.getMessage('bitbAttackCriticalTitle') || 'Critical: Fake Login Window!')
        : (chrome.i18n.getMessage('bitbAttackWarningTitle') || 'Warning: Suspicious Login Popup');

    const message = chrome.i18n.getMessage('bitbAttackMessage') ||
        'This page is showing a fake browser window designed to steal your credentials. Real login popups open in separate browser windows.';

    const tip = chrome.i18n.getMessage('bitbAttackTip') ||
        'Always check the browser address bar for the real URL, not text displayed within the page.';

    const closeButtonText = chrome.i18n.getMessage('bitbClosePageButton') || 'Close this page';
    const dismissButtonText = chrome.i18n.getMessage('bitbDismissButton') || 'I understand the risk';

    warning.innerHTML = `
        <div style="
            display: flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            padding-bottom: 12px;
            margin-bottom: 12px;
            border-bottom: 1px solid ${colors.border};
        ">
            <svg style="width: 20px; height: 20px; color: ${colors.textSecondary};" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/>
            </svg>
            <span style="font-size: 13px; font-weight: 500; color: ${colors.textSecondary}; letter-spacing: 0.3px;">LinkShield Security</span>
        </div>
        <h1 style="
            font-size: 18px;
            text-align: center;
            margin-bottom: 12px;
            font-weight: 600;
            color: ${themeColor};
        ">${isCritical ? '🚨 ' : '⚠️ '}${title}</h1>
        <p style="
            text-align: center;
            color: ${colors.textSecondary};
            margin-bottom: 16px;
            font-size: 14px;
            line-height: 1.5;
        ">${message}</p>
        <div style="
            padding: 12px;
            border-radius: 6px;
            font-size: 14px;
            background-color: ${themeBg};
            color: ${themeText};
            border: 1px solid ${themeBorder};
            margin-bottom: 16px;
        ">
            <strong style="display: block; margin-bottom: 4px;">💡 Tip:</strong>
            ${tip}
        </div>
        <div style="display: flex; gap: 12px; justify-content: center; flex-wrap: wrap;">
            <button id="linkshield-bitb-close-page" style="
                background-color: ${themeColor};
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 6px;
                cursor: pointer;
                font-weight: 500;
                font-size: 14px;
                transition: filter 0.2s ease;
            ">${closeButtonText}</button>
            <button id="linkshield-bitb-dismiss" style="
                background-color: ${colors.textSecondary};
                color: white;
                border: none;
                padding: 10px 20px;
                border-radius: 6px;
                cursor: pointer;
                font-size: 14px;
                transition: filter 0.2s ease;
            ">${dismissButtonText}</button>
        </div>
    `;

    // Voeg animatie en hover styles toe
    const style = document.createElement('style');
    style.id = 'linkshield-bitb-styles';
    style.textContent = `
        @keyframes bitbSlideIn {
            from { opacity: 0; transform: translateX(-50%) translateY(-20px); }
            to { opacity: 1; transform: translateX(-50%) translateY(0); }
        }
        #linkshield-bitb-close-page:hover,
        #linkshield-bitb-dismiss:hover {
            filter: brightness(90%);
        }
    `;
    if (!document.getElementById('linkshield-bitb-styles')) {
        document.head.appendChild(style);
    }
    document.body.appendChild(warning);

    // Event listeners
    document.getElementById('linkshield-bitb-close-page')?.addEventListener('click', () => {
        window.history.back();
        setTimeout(() => { window.location.href = 'about:blank'; }, 100);
    });

    document.getElementById('linkshield-bitb-dismiss')?.addEventListener('click', () => {
        warning.remove();
    });

    // Auto-remove na 30 seconden voor warnings (niet voor critical)
    if (!isCritical) {
        setTimeout(() => warning.remove(), 30000);
    }
}

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
      't.ly','tr.im','urlz.fr','vzturl.com','yourls.org','zi.ma','qr.ae'
    ]);
  }
  cfg.SHORTENED_URL_DOMAINS = new Set(
    Array.from(cfg.SHORTENED_URL_DOMAINS).filter(d => typeof d === 'string' && d.trim().length > 0)
  );
  logDebug(`Validated SHORTENED_URL_DOMAINS: ${Array.from(cfg.SHORTENED_URL_DOMAINS).join(', ')}`);
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
 * Haalt de registratiedatum op via de RDAP.org aggregator (met CORS-headers).
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
    const resp = await fetch(`https://rdap.org/domain/${domain}`, {
      redirect: 'follow',
      mode: 'cors',
      headers: { 'Accept': 'application/json' }
    });
    if (resp.status === 404) {
      logError(`RDAP.org kent geen data voor ${domain} (404)`);
      rdapCache.set(domain, { data: null, timestamp: Date.now() }); // Cache null-resultaat ook
      return null;
    }
    if (!resp.ok) {
      logError(`RDAP.org HTTP ${resp.status} voor ${domain}`);
      rdapCache.set(domain, { data: null, timestamp: Date.now() }); // Cache null-resultaat ook
      return null;
    }
    const data = await resp.json();
    const regEvent = Array.isArray(data.events)
      ? data.events.find(e => e.eventAction === 'registration')
      : null;
    const creationDate = regEvent && regEvent.eventDate
      ? new Date(regEvent.eventDate)
      : null;
    rdapCache.set(domain, { data: creationDate, timestamp: Date.now() }); // Cache het resultaat
    return creationDate;
  } catch (e) {
    logError(`RDAP.org fetch fout voor ${domain}:`, e);
    rdapCache.set(domain, { data: null, timestamp: Date.now() }); // Cache null bij fout
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

    return {
      backgroundSecurity: Boolean(settings.backgroundSecurity),
      integratedProtection: Boolean(settings.integratedProtection)
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
  const metaTag = document.querySelector('meta[http-equiv="refresh"]');
  if (metaTag) {
    const content = metaTag.getAttribute('content');
    const match = content.match(/url=(.+)/i);
    if (match) return match[1];
  }
  return null;
}
function performSingleCheck(condition, riskWeight, reason, severity = "medium") {
  if (condition) {
    return { riskWeight, reason, severity };
  }
  return null;
}
function applyChecks(checks, reasons, totalRiskRef) {
  logDebug("Starting applyChecks: Current risk:", totalRiskRef.value);
  checks.forEach(({ condition, weight, reason, severity }) => {
    if (condition) {
      reasons.add(`${reason} (${severity})`);
      totalRiskRef.value += weight;
      logDebug(`✅ Risico toegevoegd: ${reason} (${severity}) | Huidige risicoscore: ${totalRiskRef.value}`);
    }
  });
  logDebug("Finished applyChecks: Final risk:", totalRiskRef.value);
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
function createAnalysisResult(isSafe, reasons, risk) {
  logDebug("Generated analysis result:", { isSafe, reasons, risk });
  return { isSafe, reasons, risk };
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
      threshold: 0
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
   */
  async scanLink(link) {
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

    // 1. Normale document links
    const links = document.querySelectorAll('a[href]');
    links.forEach(link => {
      if (isValidURL(link.href) && !scannedLinks.has(link.href)) {
        this.observe(link);
        observedCount++;
      }
    });

    // 2. Shadow DOM links
    const shadowLinks = this.scanShadowDOM(document.body);
    shadowLinks.forEach(link => {
      if (isValidURL(link.href) && !scannedLinks.has(link.href)) {
        this.observe(link);
        observedCount++;
      }
    });

    // 3. Same-origin iframe links
    const iframeLinks = this.scanIframeLinks();
    iframeLinks.forEach(link => {
      if (isValidURL(link.href) && !scannedLinks.has(link.href)) {
        this.observe(link);
        observedCount++;
      }
    });

    logDebug(`[LinkScanner] ${observedCount} links worden geobserveerd (incl. Shadow DOM en iframes)`);
  }

  /**
   * Recursief scannen van Shadow DOM voor links
   * @param {Element} root - Root element om te scannen
   * @param {number} depth - Huidige diepte (max 5)
   * @returns {Array} Array van gevonden link elementen
   */
  scanShadowDOM(root, depth = 0) {
    const MAX_SHADOW_DEPTH = 5;
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
   *
   * @param {Element|Document} root - Root element om te scannen
   * @param {number} depth - Huidige recursie diepte
   * @returns {{detected: boolean, forms: Array, overlays: Array, reasons: string[]}}
   */
  scanShadowDOMForPhishing(root, depth = 0) {
    const MAX_SHADOW_DEPTH = 5;
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
   * Scant same-origin iframes voor links
   * @returns {Array} Array van gevonden link elementen
   */
  scanIframeLinks() {
    const MAX_IFRAME_DEPTH = 3;
    const links = [];
    const currentOrigin = window.location.origin;

    try {
      const iframes = document.querySelectorAll('iframe');

      iframes.forEach(iframe => {
        try {
          // Check of iframe same-origin is
          const iframeSrc = iframe.src;
          if (!iframeSrc) return;

          const iframeOrigin = new URL(iframeSrc).origin;

          // Alleen same-origin iframes scannen (security restriction)
          if (iframeOrigin !== currentOrigin) {
            logDebug(`[LinkScanner] Cross-origin iframe geskipt: ${iframeSrc}`);
            return;
          }

          // Probeer toegang tot iframe content
          const iframeDoc = iframe.contentDocument || iframe.contentWindow?.document;
          if (!iframeDoc) return;

          // Scan links in iframe
          const iframeLinks = iframeDoc.querySelectorAll('a[href]');
          iframeLinks.forEach(link => links.push(link));

          // Check voor Shadow DOM in iframe
          const shadowLinks = this.scanShadowDOM(iframeDoc.body);
          links.push(...shadowLinks);

        } catch (e) {
          // SecurityError bij cross-origin - dit is verwacht gedrag
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
    { func: () => (globalConfig.SUSPICIOUS_TLDS instanceof RegExp) && globalConfig.SUSPICIOUS_TLDS.test(domain), score: 3, messageKey: "suspiciousAdTLD" },
    // isHomoglyphAttack voegt al redenen toe aan een Set, dus hier return we alleen true/false
    { func: async () => await isHomoglyphAttack(domain, homoglyphMap, knownBrands, extractTld(domain), new Set()), score: 4, messageKey: "homoglyphAdAttack" },
    { func: () => /^(amazon|google|microsoft|paypal)/i.test(domain) && !knownBrands.includes(domain), score: 5, messageKey: "brandMisuse" } // Controleer op misuse, niet legitiem gebruik
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
      const isLocalNetwork = (host) => {
        return (
          /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host) ||
          /^192\.168\.\d{1,3}\.\d{1,3}$/.test(host) ||
          /^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host) ||
          /^172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}$/.test(host) ||
          host === 'localhost' ||
          host.endsWith('.local')
        );
      };
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
function classifyAndCheckLink(link) {
  if (!link || !link.href) {
    logDebug(`Skipping classification: Invalid or missing link: ${link || 'undefined'}`);
    return; // Sla volledig ongeldige links over
  }
  // Haal de href op, rekening houdend met SVGAnimatedString
  const href = link.href instanceof SVGAnimatedString ? link.href.baseVal : link.href;
  // Log voor debugging, inclusief type en SVG-status
  logDebug(`Classifying link: ${href || 'undefined'}, Type: ${typeof link.href}, Is SVG: ${link.ownerSVGElement ? 'yes' : 'no'}`);
  // Controleer of href een geldige URL is
  if (!isValidURL(href)) {
    logDebug(`Skipping classification: Invalid URL in link: ${href || 'undefined'}`);
    return;
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
        z-index: 99999;
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
  // Verwijder oude styling/iconen
  clearWarning(link);
  injectWarningIconStyles();
  if (level === 'safe') {
    return;
  }
  // Vertaal de reden-keys (houd camelCase, vervang alleen ongeldige tekens)
  const translatedReasons = reasons.map(r => {
    const key = r.replace(/[^a-zA-Z0-9_]/g, '_');
    return chrome.i18n.getMessage(key) || r;
  });
  // Alert: direct rood icoon, geen extra logica
  if (level === 'alert') {
    addIcon(link, '❗️', 'high-risk-warning', translatedReasons);
    return;
  }
  // Caution: geel icoon pas bij hover/focus, met stay-open als je naar het icoon beweegt
  if (level === 'caution') {
    let hideTimeout;
    const show = () => {
      clearTimeout(hideTimeout);
      // Voeg het icoon maar één keer toe
      if (!link.querySelector('.phishing-warning-icon')) {
        addIcon(link, '⚠️', 'moderate-warning', translatedReasons);
        // Zodra het icoon er is, zorg dat hover over icoon ook 'show' blijft triggeren
        const icon = link.querySelector('.phishing-warning-icon');
        icon.addEventListener('mouseenter', show);
        icon.addEventListener('mouseleave', hide);
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
function injectWarningIconStyles() {
    if (!document.head.querySelector('#phishing-warning-styles')) {
        const style = document.createElement('style');
        style.id = 'phishing-warning-styles';
        style.textContent = `
            .phishing-warning-icon {
                position: relative;
                vertical-align: middle;
                margin-left: 5px;
                cursor: help;
                transition: color 0.3s ease;
            }
            .subtle-warning {
                font-size: 12px;
                color: #ff9800; /* Softer orange */
            }
            .high-risk-warning {
                font-size: 16px;
                color: #ff0000;
            }
            .high-risk-link {
                border: 1px dashed #ff0000;
                color: #ff0000;
            }
            .moderate-warning {
                font-size: 14px;
                color: #ff5722; /* Orange-red */
            }
            .moderate-risk-link {
                border: 1px dotted #ff5722;
            }
            .phishing-warning-icon:hover {
                color: #d32f2f; /* Darker red on hover */
            }
            /* NIEUWE FALLBACK STIJLEN HIERONDER */
            .high-risk-link-fallback {
                outline: 2px dashed #ff0000 !important; /* Een zichtbare rand als fallback */
                outline-offset: 2px !important;
                box-shadow: 0 0 5px rgba(255, 0, 0, 0.5) !important; /* Optionele schaduw */
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
    const isTrusted = safeDomains.some(trustedDomain => {
        // Controleer op exacte match (bv. "facebook.com")
        // OF op een subdomein (bv. "business.facebook.com")
        return fullHostname === trustedDomain || fullHostname.endsWith(`.${trustedDomain}`);
    });
   
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
    // 2. Phishing-trefwoorden (contextuele indicator)
    if (urlParts.some(word => globalConfig.PHISHING_KEYWORDS.has(word))) {
      addRisk(1.5, "suspiciousKeywords", "low"); // Was 10
    }
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
    if (/^(?:https?:\/\/)?(\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:\/|$)/.test(url)) {
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
    // 8. Verdachte TLD's (sterke technische indicator)
    if (globalConfig.SUSPICIOUS_TLDS.test(domain)) {
      addRisk(7, "suspiciousTLD", "high"); // Was 15
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
function detectLoginPage(url = window.location.href) {
  try {
    const loginPatterns = /(login|signin|wp-login|auth|authenticate)/i;
    const urlIndicatesLogin = loginPatterns.test(url);
    const hasPasswordField = !!document.querySelector('input[type="password"]');
    logDebug(`Login detection: URL indication: ${urlIndicatesLogin}, Password field: ${hasPasswordField}`);
    return urlIndicatesLogin || hasPasswordField;
  } catch (error) {
    handleError(error, `detectLoginPage: Fout bij detecteren van loginpagina voor URL ${url}`);
    return false;
  }
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
    if (url.pathname.includes('@') || url.pathname.includes('%40')) {
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
          'google-analytics.com',
          'googletagmanager.com',
          'doubleclick.net',
          'bing.com/action',
          'linkedin.com/px',
          'twitter.com/i/adsct'
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
const homoglyphConfig = globalConfig.HOMOGLYPHS || DEFAULT_HOMOGLYPHS;
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
async function performSuspiciousChecks(url) {
  await ensureConfigReady();
  // 1) Cache lookup
  const cachedEntry = window.linkRiskCache.get(url);
  if (cachedEntry && Date.now() - cachedEntry.timestamp < CACHE_TTL_MS) {
    logDebug(`Cache hit voor verdachte controles: ${url}`);
    return cachedEntry.result;
  }
  // 2) Feature flag
  if (!await isProtectionEnabled()) {
    const fallback = { level: 'safe', risk: 0, reasons: [] };
    window.linkRiskCache.set(url, { result: fallback, timestamp: Date.now() });
    return fallback;
  }
  const reasons = new Set();
  const totalRiskRef = { value: 0 };
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
  // 4) Early exits voor niet-http(s) protocollen, met verbeterde javascript: handling
  const nonHttpProtocols = ['mailto:', 'tel:', 'ftp:', 'javascript:'];
  if (nonHttpProtocols.includes(urlObj.protocol)) {
    logDebug(`Niet-HTTP protocol gedetecteerd: ${urlObj.protocol}`);
    if (urlObj.protocol === 'javascript:') {
      const clean = url.trim().toLowerCase();
      // Alleen flaggen als het geen harmless shorthand is én er verdacht script in zit
      if (!harmlessJsProtocols.includes(clean) && hasJavascriptScheme(clean)) {
        reasons.add('javascriptScheme');
        totalRiskRef.value += 8;
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
  // Helper: check of hostname een intern/privé IP-adres is (voor level calibratie)
  const isLocalNetwork = (host) => {
    return (
      /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host) ||
      /^192\.168\.\d{1,3}\.\d{1,3}$/.test(host) ||
      /^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host) ||
      /^172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}$/.test(host) ||
      host === 'localhost' ||
      host.endsWith('.local')
    );
  };
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
    // Verdachte TLD's
    {
      condition: (globalConfig.SUSPICIOUS_TLDS instanceof RegExp)
        ? globalConfig.SUSPICIOUS_TLDS.test(hostNFC)
        : false,
      weight: 7,
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
    const staticChecks = [
        {
            condition: (globalConfig.SUSPICIOUS_TLDS instanceof RegExp)
                       && globalConfig.SUSPICIOUS_TLDS.test(hostNFC),
            weight: 6,
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
    { func: async () => await isFreeHostingDomain(url), messageKey: 'freeHosting', risk: 5 },
    { func: async () => await hasSuspiciousKeywords(url), messageKey: 'suspiciousKeywords', risk: 2.0 },
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
    {
      func: () => isFreeHostingDomain(url),
      messageKey: 'freeHosting',
      risk: 4 // Was 5. Verlaagd, maar blijft een belangrijke contextuele factor.
    },
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
    {
      func: () => hasSuspiciousKeywords(url),
      messageKey: 'suspiciousKeywords',
      risk: 1.5 // Was 2.0. Verlaagd, dit is een van de zwakste indicatoren.
    },
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
function hasUnusualPort(url) {
  const commonPorts = [80, 443];
  try {
    const urlObj = new URL(url);
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
    const domain = new URL(url).hostname.toLowerCase().replace(/^www\./, "");
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
    if (/[-]{2,}/.test(domain)) {
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
            // Check of brand voorkomt als substring in subdomeinen
            if (subdomainStr.includes(brand)) {
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

function hasMetaRedirect() {
  const metaTag = document.querySelector("meta[http-equiv='refresh']");
  return Boolean(metaTag && /^\s*\d+\s*;\s*url=/i.test(metaTag.getAttribute("content")));
}
function markAsDetected(el) {
  el.classList.add('linkshield-detected');
}
function checkControl(el) {
  const tag = el.tagName.toUpperCase();
  const role = el.getAttribute('role');
  const href = el.getAttribute('href');
  const type = el.getAttribute('type');
  const isClickable =
    href?.startsWith('http') ||
    typeof el.onclick === 'function' ||
    tag === 'BUTTON' ||
    (tag === 'INPUT' && type === 'submit') ||
    role === 'button';
  if (isClickable) {
    el.classList.add('linkshield-detected');
    logDebug('✅ Element herkend als interactief:', el);
  }
}
document.addEventListener('DOMContentLoaded', async () => {
  try {
    logDebug("🚀 Initializing content script...");
    await initContentScript(); // Wacht op configuratie en veilige domeinen

    // Check of protection is ingeschakeld voordat speciale detectie features worden gestart
    const protectionEnabled = await isProtectionEnabled();

    // WHITELIST CHECK: Skip alle checks als domein vertrouwd is door gebruiker
    const currentDomain = getDomainFromUrl(window.location.href);
    if (currentDomain && await isDomainTrusted(currentDomain)) {
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
      return; // Stop hier, voer geen verdere checks uit
    }

    if (protectionEnabled) {
      // Initialiseer Clipboard Guard voor crypto hijacking detectie
      initClipboardGuard();

      // Initialiseer ClickFix Attack detectie voor PowerShell/CMD injectie via nep-CAPTCHA
      initClickFixDetection();

      // Initialiseer Browser-in-the-Browser (BitB) detectie voor nep OAuth popups
      initBitBDetection();

      // Initialiseer Table QR Scanner voor imageless QR-code detectie (AI-phishing kits)
      initTableQRScanner();
      if (tableQRScanner) {
        tableQRScanner.scanAllTables(); // Initial scan bij page load
      }
    } else {
      logDebug("Protection disabled, skipping special detection features initialization");
    }
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
    const initialControls = detectInteractiveControls();
    logDebug(`[UI] ${initialControls.length} interactieve elementen gevonden`);
    startDynamicDetection(controls => {
      controls.forEach(el => {
        if (el.tagName === 'A' && el.href) classifyAndCheckLink(el);
      });
    });
    // --- 2. URL-specifieke checks ---
    const urlResult = await performSuspiciousChecks(currentUrl);
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
    const isLocalNetwork = (host) => {
      return (
        /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host) ||
        /^192\.168\.\d{1,3}\.\d{1,3}$/.test(host) ||
        /^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host) ||
        /^172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}$/.test(host) ||
        host === 'localhost' ||
        host.endsWith('.local')
      );
    };
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
    // --- 6. Externe links scannen (zonder extra berichten) ---
    await checkLinks();
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
    chrome.runtime.sendMessage({
      action: 'checkResult',
      url: window.location.href,
      level: 'safe',
      isSafe: true,
      risk: 0,
      reasons: ['trustedDomainSkipped'],
      trustedByUser: true
    });
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
    const pageResult = await performSuspiciousChecks(finalUrl);
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
  if (settings.integratedProtection && !isSearchResultPage()) {
    checkLinks();
  }
});
function injectWarningStyles() {
  if (document.head.querySelector("#linkshield-warning-styles")) {
    logDebug("Warning styles already present, skipping.");
    return;
  }
  const style = document.createElement("style");
  style.id = "linkshield-warning-styles";
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
      z-index: 1000 !important;
      cursor: pointer !important;
    }
    .suspicious-link {
      background-color: #ffebee !important;
      border-bottom: 2px solid #ff0000 !important;
    }
  `;
  document.head.appendChild(style);
}
(async function init() {
  try {
    // Extra initialisatiecode (indien nodig)
  } catch (error) {
    handleError(error, `init: Fout bij algemene initialisatie`);
  }
})();
const observer = new MutationObserver(debounce(async (mutations) => {
  if (!(await isProtectionEnabled())) return; // Stop als bescherming uitstaat
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
      }
    });
  });
  // Als er een password veld is toegevoegd, invalideer de login cache en hercontroleer
  if (passwordFieldAdded) {
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
  // We roepen de paginabrede logica die al in DOMContentLoaded staat opnieuw aan.
  if (scriptsAdded || iframesAdded) {
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
}, 500)); // Debounce om te voorkomen dat het te vaak afvuurt
observer.observe(document.documentElement, { childList: true, subtree: true });
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


// =============================================================================
// QR CODE IMAGE SCANNER - Using jsQR
// OCR (OCRAD.js) disabled due to Chrome Extension CSP incompatibility
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
// TABLE-BASED QR CODE SCANNER (Imageless QR Detection)
// Detecteert QR-codes die via HTML <table> elementen worden gerenderd
// AI-phishing kits gebruiken deze techniek om image-scanning te omzeilen
// =============================================================================

const TABLE_QR_CACHE = new Map();
const TABLE_QR_CACHE_TTL_MS = 1800000; // 30 minuten cache
const TABLE_QR_MIN_SIZE = 21; // Minimale QR-code grootte (21x21 modules)
const TABLE_QR_MAX_SIZE = 177; // Maximale QR-code grootte (version 40)

/**
 * TableQRScanner - Scant <table> elementen voor QR-code patronen
 * AI-phishing kits gebruiken tables met bgcolor om QR-codes te renderen zonder images
 */
class TableQRScanner {
  constructor(options = {}) {
    this.minSize = options.minSize || TABLE_QR_MIN_SIZE;
    this.maxSize = options.maxSize || TABLE_QR_MAX_SIZE;
    this.cacheTTL = options.cacheTTL || TABLE_QR_CACHE_TTL_MS;
    this.pendingTables = new Set();
    this.isProcessing = false;
    this.scannedTables = new WeakSet();

    logDebug('[TableQR] TableQRScanner initialized');
  }

  /**
   * Controleert of een tabel een QR-code patroon zou kunnen zijn
   * @param {HTMLTableElement} table - Het table element om te controleren
   * @returns {boolean} True als de tabel een potentiële QR-code is
   */
  isPotentialQRTable(table) {
    if (!table || this.scannedTables.has(table)) return false;

    const rows = table.querySelectorAll('tr');
    if (rows.length < this.minSize || rows.length > this.maxSize) return false;

    // Check consistentie: alle rijen moeten ongeveer evenveel cellen hebben
    const firstRowCells = rows[0]?.querySelectorAll('td, th').length || 0;
    if (firstRowCells < this.minSize || firstRowCells > this.maxSize) return false;

    // Controleer of de tabel vierkant is (±3 cellen tolerantie)
    if (Math.abs(rows.length - firstRowCells) > 3) return false;

    // Check of minstens 30% van de cellen een achtergrondkleur heeft
    let coloredCells = 0;
    let totalCells = 0;

    for (const row of rows) {
      const cells = row.querySelectorAll('td, th');
      for (const cell of cells) {
        totalCells++;
        const bgColor = cell.getAttribute('bgcolor') ||
                        cell.style.backgroundColor ||
                        window.getComputedStyle(cell).backgroundColor;

        if (bgColor && bgColor !== 'transparent' && bgColor !== 'rgba(0, 0, 0, 0)') {
          coloredCells++;
        }
      }
    }

    const colorRatio = coloredCells / totalCells;
    return colorRatio >= 0.3 && colorRatio <= 0.7; // QR-codes hebben typisch 30-70% zwarte modules
  }

  /**
   * Rendert een tabel naar een canvas en scant voor QR-code
   * @param {HTMLTableElement} table - Het table element
   * @returns {Promise<{detected: boolean, url: string|null, level: string, reasons: string[]}>}
   */
  async scanTable(table) {
    if (typeof jsQR === 'undefined') {
      logDebug('[TableQR] jsQR not available, skipping table scan');
      return null;
    }

    const cacheKey = this.getTableHash(table);
    const cached = TABLE_QR_CACHE.get(cacheKey);
    if (cached && Date.now() - cached.timestamp < this.cacheTTL) {
      return cached.result;
    }

    this.scannedTables.add(table);

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
        logDebug(`[TableQR] Decoded URL from table: ${decodedUrl}`);

        if (isValidURL(decodedUrl)) {
          // Voer security checks uit op de gedecodeerde URL
          const securityResult = await this.analyzeDecodedUrl(decodedUrl, table);

          const result = {
            detected: true,
            type: 'table-qr',
            url: decodedUrl,
            ...securityResult
          };

          TABLE_QR_CACHE.set(cacheKey, { result, timestamp: Date.now() });
          return result;
        }
      }

      const noQrResult = { detected: false, url: null, level: 'safe', reasons: [] };
      TABLE_QR_CACHE.set(cacheKey, { result: noQrResult, timestamp: Date.now() });
      return noQrResult;

    } catch (error) {
      handleError(error, '[TableQR] Error scanning table');
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
   */
  async analyzeDecodedUrl(url, tableElement) {
    const reasons = [];
    let totalRisk = 0;

    // Basis URL checks
    const result = await performSuspiciousChecks(url);
    reasons.push(...result.reasons);
    totalRisk += result.risk || 0;

    // Extra risico: Table-gebaseerde QR is inherent verdacht (anti-detection techniek)
    reasons.push('tableBasedQR');
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
   * Scant alle tabellen op de pagina (debounced)
   */
  async scanAllTables() {
    const tables = document.querySelectorAll('table');
    let scannedCount = 0;

    for (const table of tables) {
      if (this.isPotentialQRTable(table)) {
        const result = await this.scanTable(table);
        scannedCount++;

        if (result && result.detected && result.level !== 'safe') {
          this.warnTableQR(table, result);
        }
      }
    }

    if (scannedCount > 0) {
      logDebug(`[TableQR] Scanned ${scannedCount} potential QR tables`);
    }
  }

  /**
   * Toont waarschuwing bij verdachte table QR-code
   */
  warnTableQR(table, { level, reasons = [], url }) {
    if (table.dataset.qrWarned === 'true') return;
    table.dataset.qrWarned = 'true';

    const wrapper = document.createElement('div');
    wrapper.className = 'linkshield-warning';
    wrapper.style.position = 'relative';
    wrapper.style.display = 'inline-block';
    table.parentNode?.insertBefore(wrapper, table);
    wrapper.appendChild(table);

    const isAlert = level === 'alert';
    const bgColor = isAlert ? 'rgba(220, 38, 38, 0.9)' : 'rgba(234, 179, 8, 0.9)';
    const borderColor = isAlert ? '#dc2626' : '#eab308';
    const emoji = isAlert ? '⚠️' : '⚡';
    const title = isAlert
      ? (chrome.i18n.getMessage('tableQrDangerTitle') || 'GEVAAR: Verborgen QR-code!')
      : (chrome.i18n.getMessage('tableQrCautionTitle') || 'Let op: Verborgen QR-code');

    const translatedReasons = Array.isArray(reasons) && reasons.length > 0
      ? reasons.slice(0, 3).map(r => translateReason(r)).join(', ')
      : (chrome.i18n.getMessage('hiddenQrDetected') || 'Verborgen QR-code gedetecteerd');

    const displayUrl = url && url.length > 50 ? url.substring(0, 50) + '...' : url;

    const overlay = document.createElement('div');
    overlay.className = 'linkshield-overlay table-qr-warning';
    overlay.innerHTML = `
      <div style="font-weight:bold;font-size:14px;margin-bottom:4px;">${emoji} ${title}</div>
      <div style="font-size:11px;margin-bottom:4px;">URL: ${displayUrl || 'Verborgen'}</div>
      <div style="font-size:10px;opacity:0.9;">${translatedReasons}</div>
    `;

    overlay.style.cssText = `
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
      z-index: 10000;
      border: 3px solid ${borderColor};
      border-radius: 4px;
      font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
      box-shadow: 0 4px 12px rgba(0,0,0,0.3);
    `;

    wrapper.appendChild(overlay);
    logDebug(`[TableQR] Warning displayed for table QR: ${url}`);
  }
}

// Global table QR scanner instance
let tableQRScanner = null;

/**
 * Initialiseert de Table QR Scanner
 */
function initTableQRScanner() {
  if (!tableQRScanner) {
    tableQRScanner = new TableQRScanner();
  }
  return tableQRScanner;
}

// Debounced table scan voor MutationObserver
const debouncedTableScan = debounce(async () => {
  if (tableQRScanner) {
    await tableQRScanner.scanAllTables();
  }
}, 500);

// =============================================================================
// END TABLE-BASED QR CODE SCANNER
// =============================================================================

/**
 * Scan image for QR codes using jsQR library (IIFE, MV3 compatible)
 */
async function scanImageForQR(imgEl) {
  // Check if jsQR is available
  if (typeof jsQR === 'undefined') {
    logDebug('[LinkShield OCR] jsQR not loaded, skipping QR scan');
    return null;
  }

  try {
    // Load image and draw to canvas for jsQR
    const qrData = await new Promise((resolve, reject) => {
      const img = new Image();
      img.crossOrigin = 'anonymous';

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
      img.src = imgEl.src;
    });

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
 * DISABLED: OCRAD.js is incompatible with Chrome Extension CSP (requires unsafe-eval)
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
 * Warn about suspicious OCR-detected content with translated reasons
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
  const bgColor = isAlert ? 'rgba(220, 38, 38, 0.85)' : 'rgba(234, 179, 8, 0.85)';
  const borderColor = isAlert ? '#dc2626' : '#eab308';
  const title = isAlert
    ? (chrome.i18n.getMessage('ocrDangerTitle') || 'GEVAAR: Phishing gedetecteerd in afbeelding!')
    : (chrome.i18n.getMessage('ocrCautionTitle') || 'Let op: Verdachte tekst in afbeelding');

  // Translate reasons
  const translatedReasons = Array.isArray(reasons) && reasons.length > 0
    ? reasons.slice(0, 3).map(r => translateReason(r)).join(', ')
    : (chrome.i18n.getMessage('suspiciousDomainDetected') || 'Verdacht domein gedetecteerd');

  const displayUrl = url && url.length > 40 ? url.substring(0, 40) + '...' : (url || 'N/A');

  const overlay = document.createElement('div');
  overlay.className = 'qr-warning-overlay ocr-warning';
  overlay.innerHTML = `
    <div style="font-weight:bold;margin-bottom:4px;">${isAlert ? '⚠️' : '⚡'} ${title}</div>
    <div style="font-size:10px;margin-bottom:3px;">URL: ${displayUrl}</div>
    <div style="font-size:9px;opacity:0.9;">${translatedReasons}</div>
  `;

  // Translate reasons for tooltip
  const translatedReasonsForTooltip = Array.isArray(reasons)
    ? reasons.map(r => translateReason(r)).join('\n')
    : '';
  overlay.title = `${chrome.i18n.getMessage('extractedText') || 'Geëxtraheerde tekst'}: ${extractedText}\n\n${chrome.i18n.getMessage('reasons') || 'Redenen'}:\n${translatedReasonsForTooltip}`;

  overlay.style.cssText = `
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
    font-size: 11px;
    padding: 8px;
    z-index: 10000;
    border: 2px solid ${borderColor};
    border-radius: 4px;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
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
  let translated = chrome.i18n.getMessage(translationKey);

  // If no translation found, use fallback mapping
  if (!translated) {
    const fallbackMap = {
      'nonAscii': 'Verdachte tekens gedetecteerd (homoglyphs)',
      'brandKeywordHomoglyph': 'Imitatie van een bekend merk gedetecteerd',
      'noHttps': 'Geen beveiligde verbinding (HTTPS)',
      'suspiciousTLD': 'Verdachte domeinextensie',
      'ipAsDomain': 'IP-adres als domeinnaam',
      'tooManySubdomains': 'Te veel subdomeinen',
      'shortenedUrl': 'Verkorte URL gedetecteerd',
      'suspiciousKeywords': 'Verdachte trefwoorden in URL',
      'malwareExtension': 'Potentieel schadelijke bestandsextensie',
      'urlTooLong': 'Ongewoon lange URL',
      'encodedCharacters': 'Gecodeerde tekens in URL',
      'homoglyphAttack': 'Homoglyph-aanval gedetecteerd',
      'typosquatting': 'Typosquatting gedetecteerd',
      'suspiciousBrandPattern': 'Verdacht merkpatroon',
      'unusualPort': 'Ongebruikelijke poort',
      'punycode': 'Punycode domein gedetecteerd',
      'loginPageNoMX': 'Inlogpagina zonder e-mailserver',
      'insecureLoginPage': 'Onveilige inlogpagina',
      'sslValidationFailed': 'SSL-validatie mislukt',
      'similarToLegitimateDomain': 'Lijkt op legitiem domein',
      'reason_redirectChain': 'Verdachte redirect-keten gedetecteerd',
      'reason_excessiveRedirects': 'Te veel redirects in keten',
      'reason_domainHopping': 'Meerdere domeinwisselingen in redirect-keten',
      'reason_chainedShorteners': 'Meerdere URL-verkorters achter elkaar',
      'reason_suspiciousFinalTLD': 'Einddoel heeft verdachte domeinextensie',
      'reason_redirectToIP': 'Redirect naar IP-adres',
      'reason_redirectTimeout': 'Redirect-analyse time-out',
      'nullByteInjection': 'Null byte injectie gedetecteerd (hoog risico)',
      'urlCredentialsAttack': 'URL misleiding gedetecteerd (@-symbool aanval)',
      'fullwidthCharacters': 'Fullwidth Unicode karakters gedetecteerd',
      'doubleEncoding': 'Dubbele URL-codering gedetecteerd'
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

// Function to warn near a text QR element with translated reasons
function warnTextQR(el, { level, reasons = [], url }) {
  const wrapper = document.createElement('div');
  wrapper.style.position = 'relative';
  wrapper.style.display = 'inline-block';

  el.parentNode?.insertBefore(wrapper, el);
  wrapper.appendChild(el);

  const isAlert = level === 'alert';
  const bgColor = isAlert ? 'rgba(220, 38, 38, 0.85)' : 'rgba(234, 179, 8, 0.85)';
  const borderColor = isAlert ? '#dc2626' : '#eab308';
  const title = isAlert
    ? (chrome.i18n.getMessage('asciiQrDangerTitle') || 'GEVAAR: Phishing ASCII QR!')
    : (chrome.i18n.getMessage('asciiQrCautionTitle') || 'Let op: Verdachte ASCII QR');

  // Translate reasons
  const translatedReasons = Array.isArray(reasons) && reasons.length > 0
    ? reasons.slice(0, 3).map(r => translateReason(r)).join(', ')
    : (chrome.i18n.getMessage('suspiciousDomainDetected') || 'Verdacht domein gedetecteerd');

  const displayUrl = url && url.length > 40 ? url.substring(0, 40) + '...' : (url || (chrome.i18n.getMessage('hiddenUrl') || 'Verborgen'));

  const overlay = document.createElement('div');
  overlay.className = 'qr-warning-overlay ascii-qr-warning';
  overlay.innerHTML = `
    <div style="font-weight:bold;margin-bottom:4px;">${isAlert ? '⚠️' : '⚡'} ${title}</div>
    <div style="font-size:10px;margin-bottom:3px;">URL: ${displayUrl}</div>
    <div style="font-size:9px;opacity:0.9;">${translatedReasons}</div>
  `;

  // Translate reasons for tooltip
  const translatedReasonsForTooltip = Array.isArray(reasons)
    ? reasons.map(r => translateReason(r)).join('\n')
    : '';
  overlay.title = `${chrome.i18n.getMessage('reasons') || 'Redenen'}:\n${translatedReasonsForTooltip}`;

  overlay.style.cssText = `
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
    font-size: 11px;
    padding: 8px;
    z-index: 10000;
    border: 2px solid ${borderColor};
    border-radius: 4px;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
  `;
  wrapper.appendChild(overlay);
}

// Updated: Function to warn near a QR image with translated reasons
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
  const bgColor = isAlert ? 'rgba(220, 38, 38, 0.9)' : 'rgba(234, 179, 8, 0.9)';
  const borderColor = isAlert ? '#dc2626' : '#eab308';
  const emoji = isAlert ? '⚠️' : '⚡';
  const title = isAlert
    ? (chrome.i18n.getMessage('qrDangerTitle') || 'GEVAAR: Phishing QR-code!')
    : (chrome.i18n.getMessage('qrCautionTitle') || 'Let op: Verdachte QR-code');

  // Translate reasons for display
  const translatedReasons = Array.isArray(reasons) && reasons.length > 0
    ? reasons.slice(0, 3).map(r => translateReason(r)).join(', ')
    : (chrome.i18n.getMessage('suspiciousDomainDetected') || 'Verdacht domein gedetecteerd');

  // Truncate URL for display
  const displayUrl = url && url.length > 50 ? url.substring(0, 50) + '...' : url;

  overlay.innerHTML = `
    <div style="font-weight:bold;font-size:14px;margin-bottom:4px;">${emoji} ${title}</div>
    <div style="font-size:11px;margin-bottom:4px;">URL: ${displayUrl || (chrome.i18n.getMessage('hiddenUrl') || 'Verborgen URL')}</div>
    <div style="font-size:10px;opacity:0.9;">${translatedReasons}</div>
  `;

  overlay.style.cssText = `
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
    z-index: 10000;
    border: 3px solid ${borderColor};
    border-radius: 4px;
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
    box-shadow: 0 4px 12px rgba(0,0,0,0.3);
  `;

  // Translate reasons for tooltip
  const translatedReasonsForTooltip = Array.isArray(reasons)
    ? reasons.map(r => translateReason(r)).join('\n')
    : (chrome.i18n.getMessage('suspiciousDomainDetected') || 'Verdacht domein');
  overlay.title = `${chrome.i18n.getMessage('fullUrl') || 'Volledige URL'}: ${url}\n\n${chrome.i18n.getMessage('reasons') || 'Redenen'}:\n${translatedReasonsForTooltip}`;
  wrapper.appendChild(overlay);
}

// New: Report phishing (e.g., to PhishTank or custom endpoint)
function reportPhishing(url) {
  // Placeholder: Send to background.js or external API
  chrome.runtime.sendMessage({ action: 'reportPhishing', url });
  alert('Reported! Thank you for helping improve security.');
}