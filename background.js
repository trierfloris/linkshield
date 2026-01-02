// =================================================================================
// LINKSHIELD BACKGROUND SERVICE WORKER - PRODUCTIE
// =================================================================================

// ==== Globale Instellingen en Debugging ====
// Let op: IS_PRODUCTION bepaalt hier of de console.log/warn/info volledig worden overschreven.
// Als IS_PRODUCTION true is, worden ALLE console.log/warn/info overschreven, ongeacht DEBUG_MODE in config.
// Voor volledige controle via config.DEBUG_MODE, verwijder het IS_PRODUCTION blok hieronder.
const IS_PRODUCTION = true; // Zet op 'true' voor productie build.
const CACHE_TTL = 24 * 60 * 60 * 1000;

// Overschrijf console-functies voor productieomgeving als IS_PRODUCTION true is.
// Anders wordt de controle overgelaten aan globalThresholds.DEBUG_MODE binnen de functies.
if (IS_PRODUCTION) {
    console.log = function() {};
    console.warn = function() {};
    console.info = function() {};
    // console.error blijft intact
}


// ==== Globale Drempels en Configuratie Lading ====
// Deze worden gebruikt in het background script zelf
let globalThresholds = {
    LOW_THRESHOLD: 4,
    MEDIUM_THRESHOLD: 8,
    HIGH_THRESHOLD: 15,
    DOMAIN_AGE_MIN_RISK: 5,
    YOUNG_DOMAIN_RISK: 5,
    YOUNG_DOMAIN_THRESHOLD_DAYS: 7, // Correcte spelling
    DEBUG_MODE: false // Wordt overschreven door opgeslagen config
};

/**
 * Laadt de risicodrempels en debug-modus vanuit chrome.storage.sync.
 * Deze functie wordt aangeroepen bij opstarten en bij wijzigingen in de sync storage.
 */
async function loadThresholdsFromStorage() {
    try {
        const storedConfig = await chrome.storage.sync.get([
            'LOW_THRESHOLD', 'MEDIUM_THRESHOLD', 'HIGH_THRESHOLD',
            'DOMAIN_AGE_MIN_RISK', 'YOUNG_DOMAIN_RISK', 'YOUNG_DOMAIN_THRESHOLD_DAYS',
            'DEBUG_MODE'
        ]);
        // Gebruik Object.assign om de globale variabele bij te werken
        Object.assign(globalThresholds, storedConfig);
    } catch (error) {
        console.error("Error loading thresholds from storage:", error);
    }
}

// Laad de drempels direct bij het opstarten van de service worker
loadThresholdsFromStorage()
  .then(() => restoreIconState())
  .catch(err => console.error("[INIT] Fout bij laden thresholds of herstellen icon:", err));

/**
 * Voert licentie/trial check uit bij startup en past instellingen aan indien nodig
 * Deze functie wordt aangeroepen nadat alle functies gedefinieerd zijn
 */
async function performStartupLicenseCheck() {
  try {
    const isAllowed = await isBackgroundSecurityAllowed();

    if (!isAllowed) {
      // Trial verlopen zonder licentie - forceer backgroundSecurity uit
      await chrome.storage.sync.set({ backgroundSecurity: false });
      await clearDynamicRules();
      await manageDNRules();
    }
  } catch (err) {
    console.error("[INIT] Fout bij startup licentie check:", err);
  }
}


// ==== Icon Animation and Tab Safety (Vroegere declaratie om ReferenceError te voorkomen) ====
// De functies die door event listeners worden aangeroepen moeten hier al gedefinieerd zijn.

let iconState = true; // Voor de toggleIcon animatie
let activeAnimationInterval = null;
let animationTimeout = null;

/** Toggles the extension icon between green and red */
function toggleIcon() {
    chrome.action.setIcon({
        path: iconState ? {
            "16": "icons/green-circle-16.png",
            "48": "icons/green-circle-48.png",
            "128": "icons/green-circle-128.png"
        } : {
            "16": "icons/red-circle-16.png",
            "48": "icons/red-circle-48.png",
            "128": "icons/red-circle-128.png"
        }
    });
    iconState = !iconState;
}

/** Stops the icon animation */
function stopIconAnimation() {
    if (activeAnimationInterval) {
        clearInterval(activeAnimationInterval);
        activeAnimationInterval = null;
    }
    if (animationTimeout) {
        clearTimeout(animationTimeout);
        animationTimeout = null;
    }
}

/** Starts a smooth icon animation for a specified duration */
function startSmoothIconAnimation(duration = 30000, interval = 500) { // Standaard interval naar 500ms
    stopIconAnimation(); // Stop een eventueel lopende animatie

    let elapsed = 0;
    activeAnimationInterval = setInterval(() => {
        toggleIcon();
        elapsed += interval;
        if (elapsed >= duration) {
            clearInterval(activeAnimationInterval);
            activeAnimationInterval = null;
        }
    }, interval);

    animationTimeout = setTimeout(() => {
        if (activeAnimationInterval) { // Zorg ervoor dat het interval nog actief is
            clearInterval(activeAnimationInterval);
            activeAnimationInterval = null;
        }
        animationTimeout = null; // Clear de timeout ID
        resetIconToNeutral(); // Optioneel: zet terug naar neutraal na animatie
    }, duration);
}

/** Resets the icon to a neutral state (green) */
function resetIconToNeutral() {
    chrome.action.setIcon({
        path: {
            "16": "icons/green-circle-16.png",
            "48": "icons/green-circle-48.png",
            "128": "icons/green-circle-128.png"
        }
    });
    chrome.action.setTitle({ title: chrome.i18n.getMessage("neutralIconTitle") || "Performing safety check..." });
}


 // === ICON STATE RESTORE BIJ STARTUP/INSTALL ===
/** Haalt de laatste status uit storage en zet het icoon correct */
async function restoreIconState() {
  try {
    const { currentSiteStatus } = await chrome.storage.local.get("currentSiteStatus");
    if (currentSiteStatus && currentSiteStatus.level) {
      await updateIconBasedOnSafety(
        currentSiteStatus.level,
        currentSiteStatus.reasons,
        currentSiteStatus.risk,
        currentSiteStatus.url
      );
    }
  } catch (e) {
    console.error("[RESTORE ICON] Fout bij herstellen icon state:", e);
  }
}



/** Resets the current site status in storage */
async function resetCurrentSiteStatus() {
    try {
        await chrome.storage.local.remove("currentSiteStatus");
        if (globalThresholds.DEBUG_MODE) console.log("currentSiteStatus reset in storage.");
    } catch (error) {
        console.error("[ERROR] Error resetting currentSiteStatus:", error);
    }
}



/**
 * Updates the extension icon based on site safety level.
 * Ongeldige, lege of undefined 'level' wordt beschouwd als 'safe' (groen).
 *
 * @param {string} level     - 'safe', 'caution', 'alert' of anders/undefined
 * @param {string[]} reasons
 * @param {number} risk
 * @param {string} url
 */
async function updateIconBasedOnSafety(level, reasons, risk, url) {
    // 1) Normalize en fallback
    const raw = level;
    let lvl = (typeof level === 'string') ? level.trim().toLowerCase() : '';
    if (!['safe', 'caution', 'alert'].includes(lvl)) {
        console.warn(`[updateIconBasedOnSafety] invalid or empty level "${raw}", defaulting to 'safe'`);
        lvl = 'safe';
    }


    // 2) Status opslaan (om popup/dynamic de juiste data te geven)
    const status = { level: lvl, reasons, risk, url, isSafe: lvl === 'safe' };
    await chrome.storage.local.set({ currentSiteStatus: status });

    // 3) Icon mapping
    const iconMap = {
        safe:    { "16": "icons/green-circle-16.png",  "48": "icons/green-circle-48.png",  "128": "icons/green-circle-128.png" },
        caution: { "16": "icons/yellow-circle-16.png", "48": "icons/yellow-circle-48.png", "128": "icons/yellow-circle-128.png" },
        alert:   { "16": "icons/red-circle-16.png",    "48": "icons/red-circle-48.png",    "128": "icons/red-circle-128.png" }
    };
    chrome.action.setIcon({ path: iconMap[lvl] });

    // 4) Tooltip samenstellen uit i18n-title + vertaalde redenen
    const titleKey = lvl === 'alert' ?
        'siteAlertTitle' :
        lvl === 'caution' ?
        'siteCautionTitle' :
        'siteSafeTitle';

    let tooltip = chrome.i18n.getMessage(titleKey) || '';
    if (Array.isArray(reasons) && reasons.length) {
        const reasonTexts = reasons
            .map(key => chrome.i18n.getMessage(key))
            .filter(text => text && text.trim().length > 0)
            .join('\n');
        if (reasonTexts) {
            tooltip += '\n' + reasonTexts;
        }
    }
    chrome.action.setTitle({ title: tooltip });

    // 5) Animatie alleen bij 'alert'
    if (lvl === 'alert') {
        if (globalThresholds.DEBUG_MODE) {
            console.log(`[ICON ANIMATION] Level is 'alert', animatie wordt gestart.`);
        }
        startSmoothIconAnimation(60000, 500);
    } else {
        if (globalThresholds.DEBUG_MODE) {
            console.log(`[ICON ANIMATION] Level is '${lvl}', animatie wordt gestopt (indien actief).`);
        }
        stopIconAnimation();
    }
}











// ==== Rule Management and Fetching (Declarative Net Request) ====

let isUpdatingRules = false; // Debounce flag to prevent overlapping updates
let lastUpdate = 0; // Timestamp of the last update for additional control

/** Manages the enabling/disabling of declarativeNetRequest rulesets based on settings and license */
async function manageDNRules() {
    try {
        const { backgroundSecurity } = await chrome.storage.sync.get('backgroundSecurity');

        // LICENTIE CHECK: Controleer of achtergrondbeveiliging toegestaan is
        const isAllowed = await isBackgroundSecurityAllowed();

        // Alleen inschakelen als backgroundSecurity AAN staat EN licentie/trial actief is
        if (backgroundSecurity && isAllowed) {
            await chrome.declarativeNetRequest.updateEnabledRulesets({
                enableRulesetIds: ["ruleset_1"]
            });
            if (globalThresholds.DEBUG_MODE) console.log("DNR Ruleset 1 enabled.");
        } else {
            await chrome.declarativeNetRequest.updateEnabledRulesets({
                disableRulesetIds: ["ruleset_1"]
            });
            if (globalThresholds.DEBUG_MODE) {
                if (!isAllowed) {
                    console.log("DNR Ruleset 1 disabled: trial verlopen zonder licentie.");
                } else {
                    console.log("DNR Ruleset 1 disabled: backgroundSecurity is off.");
                }
            }
        }
    } catch (error) {
        console.error("Error managing DNR rules:", error);
    }
}

/** Fetches and loads dynamic rules from a remote source */
async function fetchAndLoadRules() {
    if (isUpdatingRules) {
        if (globalThresholds.DEBUG_MODE) console.log("Already updating rules, skipping.");
        return;
    }

    // LICENTIE CHECK: Stop als trial verlopen is zonder licentie
    const isAllowed = await isBackgroundSecurityAllowed();
    if (!isAllowed) {
        if (globalThresholds.DEBUG_MODE) console.log("fetchAndLoadRules overgeslagen: trial verlopen zonder licentie.");
        await clearDynamicRules(); // Verwijder bestaande regels
        return;
    }

    isUpdatingRules = true;

    // Hardgecodeerde whitelist voor kritieke Google/Microsoft/Apple domeinen
    const HARDCODED_WHITELIST = [
        "accounts.google.com", "mail.google.com", "drive.google.com", "docs.google.com",
        "calendar.google.com", "apis.google.com", "oauth2.googleapis.com", "www.googleapis.com",
        "storage.googleapis.com", "fonts.googleapis.com", "fonts.gstatic.com", "www.google.com",
        "translate.google.com", "chrome.google.com", "clients1.google.com", "ssl.gstatic.com",
        "lh3.googleusercontent.com", "google.com", // fallback voor wildcard
        "microsoftonline.com", "login.microsoft.com", "outlook.live.com", "apple.com"
    ];

    function isWhitelisted(urlFilter) {
        return HARDCODED_WHITELIST.some(domain => urlFilter.includes(domain));
    }

    try {
        const { backgroundSecurity } = await chrome.storage.sync.get('backgroundSecurity');
        if (!backgroundSecurity) {
            await clearDynamicRules();
            if (globalThresholds.DEBUG_MODE) console.log("Background security is off, dynamic rules cleared.");
            return;
        }

        const rulesResponse = await fetchWithRetry('https://linkshield.nl/files/rules.json');
        if (!rulesResponse.ok) {
            throw new Error(`Failed to fetch rules: ${rulesResponse.status}`);
        }

        const newRules = await rulesResponse.json();
        if (!Array.isArray(newRules) || newRules.length === 0) {
            throw new Error("Invalid or empty rules from remote source.");
        }

        // Stap 1: Verwijder bestaande regels in batches
        let remainingRules = await chrome.declarativeNetRequest.getDynamicRules();
        if (globalThresholds.DEBUG_MODE) console.log(`Clearing ${remainingRules.length} existing dynamic rules.`);
        while (remainingRules.length > 0) {
            const batch = remainingRules.slice(0, 500).map(rule => rule.id);
            await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: batch });
            await new Promise(resolve => setTimeout(resolve, 200)); // Kleine pauze om API-limieten te respecteren
            remainingRules = await chrome.declarativeNetRequest.getDynamicRules();
        }
        if (globalThresholds.DEBUG_MODE) console.log("All dynamic rules cleared.");


        // Stap 2: Filter regels met whitelistcheck en unieke ID’s
        const { lastCounter = 1000000 } = await chrome.storage.local.get('lastCounter');
        let counter = Math.max(1000000, Math.floor(lastCounter)); // Start ID's vanaf 1M
        const validDynamicRules = [];
        const seenIds = new Set(); // Voor unieke IDs

        for (const rule of newRules) {
            // Basisvalidatie van de regelstructuur
            if (!rule.condition?.urlFilter || !rule.action || typeof rule.priority !== 'number') {
                if (globalThresholds.DEBUG_MODE) console.warn(`Skipping malformed rule:`, rule);
                continue;
            }

            // Whitelist check
            if (isWhitelisted(rule.condition.urlFilter)) {
                if (globalThresholds.DEBUG_MODE) console.warn(`[WHITELIST] Skipping rule for whitelisted domain: ${rule.condition.urlFilter}`);
                continue;
            }

            // Geef een unieke ID aan de regel
            const ruleId = Math.floor(counter++);
            if (!Number.isInteger(ruleId)) { // Double-check for integer ID
                throw new Error(`[ERROR] Generated rule ID is not an integer: ${ruleId}`);
            }
            if (seenIds.has(ruleId)) { // Prevent duplicate IDs
                if (globalThresholds.DEBUG_MODE) console.warn(`Skipping rule with duplicate ID: ${ruleId}`);
                continue;
            }
            seenIds.add(ruleId);

            validDynamicRules.push({
                id: ruleId,
                priority: rule.priority,
                action: rule.action,
                condition: {
                    urlFilter: rule.condition.urlFilter,
                    // Zorg voor een default resourceTypes als deze ontbreekt
                    resourceTypes: rule.condition.resourceTypes || ['main_frame', 'script', 'xmlhttprequest', 'sub_frame'],
                },
            });
        }

        if (validDynamicRules.length === 0) {
            throw new Error("No valid rules remain after filtering.");
        }
        if (globalThresholds.DEBUG_MODE) console.log(`Adding ${validDynamicRules.length} new dynamic rules.`);

        // Stap 3: Voeg nieuwe regels toe in batches
        const addBatchSize = 1000;
        for (let i = 0; i < validDynamicRules.length; i += addBatchSize) {
            const batch = validDynamicRules.slice(i, i + addBatchSize);
            await chrome.declarativeNetRequest.updateDynamicRules({ addRules: batch });
            await new Promise(resolve => setTimeout(resolve, 200)); // Kleine pauze
        }

        await chrome.storage.local.set({ lastCounter: counter });
        await updateLastRuleUpdate();
        if (globalThresholds.DEBUG_MODE) console.log("Dynamic rules loaded successfully.");

    } catch (error) {
        console.error("[ERROR] fetchAndLoadRules:", error.message);
    } finally {
        isUpdatingRules = false;
    }
}


/** Clears all dynamic rules in batches */
async function clearDynamicRules() {
    let remainingRules = await chrome.declarativeNetRequest.getDynamicRules();
    while (remainingRules.length > 0) {
        const batch = remainingRules.slice(0, 500).map(rule => rule.id);
        await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: batch });
        await new Promise(resolve => setTimeout(resolve, 200));
        remainingRules = await chrome.declarativeNetRequest.getDynamicRules();
    }
    if (globalThresholds.DEBUG_MODE) console.log("All dynamic rules have been cleared.");
}

/** Updates the timestamp of the last rule update */
async function updateLastRuleUpdate() {
    const now = new Date().toISOString();
    try {
        await chrome.storage.local.set({ lastRuleUpdate: now });
        if (globalThresholds.DEBUG_MODE) console.log("Last rule update timestamp saved:", now);
    } catch (error) {
        console.error('[ERROR] Error saving lastRuleUpdate:', error.message);
    }
}


// ==== Redirect Chain Analysis (v7.1) ====

// Cache voor redirect chain resultaten (voorkomt dubbele scans)
const redirectChainCache = new Map();
const REDIRECT_CACHE_TTL = 30 * 60 * 1000; // 30 minuten cache

// Bekende URL shorteners (moet synchroon beschikbaar zijn)
const KNOWN_SHORTENERS = new Set([
    'bit.ly', 't.co', 'tinyurl.com', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
    'rebrand.ly', 'cutt.ly', 'short.io', 't.ly', 'rb.gy', 'shorturl.at',
    'tiny.cc', 'urlz.fr', 'v.gd', 's.id', 'qr.ae', 'clk.sh', 'dub.sh',
    'linktr.ee', 'lnk.to', 'bl.ink', 'soo.gd', 'u.to', 'x.co', 'zi.ma'
]);

/**
 * Analyseert de redirect chain van een URL
 * @param {string} url - De te analyseren URL
 * @param {number} timeout - Timeout in milliseconden (default 3000)
 * @returns {Promise<{finalUrl: string, chain: string[], redirectCount: number, threats: string[], error?: string}>}
 */
async function traceRedirectChain(url, timeout = 3000) {
    // Cache check
    const cached = redirectChainCache.get(url);
    if (cached && (Date.now() - cached.timestamp < REDIRECT_CACHE_TTL)) {
        if (globalThresholds.DEBUG_MODE) console.log(`[RedirectChain] Cache hit voor ${url}`);
        return cached.result;
    }

    const chain = [url];
    let currentUrl = url;
    let redirectCount = 0;
    const maxRedirects = 10;
    const threats = [];
    const visitedDomains = new Set();

    try {
        // Extract initial domain
        try {
            visitedDomains.add(new URL(url).hostname.toLowerCase());
        } catch (e) {
            // Invalid URL
        }

        while (redirectCount < maxRedirects) {
            // AbortController voor timeout
            const controller = new AbortController();
            const timeoutId = setTimeout(() => controller.abort(), timeout);

            try {
                const response = await fetch(currentUrl, {
                    method: 'HEAD',
                    redirect: 'manual', // Volg niet automatisch, we willen elke stap zien
                    signal: controller.signal,
                    headers: {
                        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                    }
                });

                clearTimeout(timeoutId);

                // Check voor redirect status codes
                if ([301, 302, 303, 307, 308].includes(response.status)) {
                    const location = response.headers.get('Location');
                    if (!location) break;

                    // Converteer relatieve URL naar absoluut
                    try {
                        currentUrl = new URL(location, currentUrl).href;
                    } catch (e) {
                        // Ongeldige redirect URL
                        threats.push('invalidRedirectUrl');
                        break;
                    }

                    chain.push(currentUrl);
                    redirectCount++;

                    // Track domeinen voor domain hopping detectie
                    try {
                        const newDomain = new URL(currentUrl).hostname.toLowerCase();
                        visitedDomains.add(newDomain);
                    } catch (e) {
                        // URL parsing error
                    }
                } else {
                    // Geen redirect meer, eindbestemming bereikt
                    break;
                }
            } catch (fetchError) {
                clearTimeout(timeoutId);

                if (fetchError.name === 'AbortError') {
                    threats.push('redirectTimeout');
                    if (globalThresholds.DEBUG_MODE) console.log(`[RedirectChain] Timeout voor ${currentUrl}`);
                }
                // Bij andere fouten (CORS, netwerk), stop gracefully
                break;
            }
        }

        // Threat analyse op de chain
        analyzeRedirectChainThreats(chain, visitedDomains, redirectCount, threats);

        const result = {
            finalUrl: currentUrl,
            chain: chain,
            redirectCount: redirectCount,
            threats: threats,
            domainCount: visitedDomains.size
        };

        // Cache resultaat
        redirectChainCache.set(url, { result, timestamp: Date.now() });

        // Cache cleanup (max 500 entries)
        if (redirectChainCache.size > 500) {
            const oldestKey = redirectChainCache.keys().next().value;
            redirectChainCache.delete(oldestKey);
        }

        return result;

    } catch (error) {
        console.error(`[RedirectChain] Fout bij analyseren van ${url}:`, error);
        return {
            finalUrl: url,
            chain: [url],
            redirectCount: 0,
            threats: [],
            error: error.message
        };
    }
}

/**
 * Analyseert de redirect chain op verdachte patronen
 */
function analyzeRedirectChainThreats(chain, visitedDomains, redirectCount, threats) {
    // 1. Excessive redirects (>5 is verdacht)
    if (redirectCount > 5) {
        threats.push('excessiveRedirects');
    }

    // 2. Domain hopping (>2 verschillende domeinen)
    if (visitedDomains.size > 2) {
        threats.push('domainHopping');
    }

    // 3. Shortener in het midden van de chain (niet alleen aan het begin)
    for (let i = 1; i < chain.length; i++) {
        try {
            const domain = new URL(chain[i]).hostname.toLowerCase().replace(/^www\./, '');
            if (KNOWN_SHORTENERS.has(domain)) {
                threats.push('chainedShorteners');
                break;
            }
        } catch (e) {
            // URL parsing error
        }
    }

    // 4. Verdachte TLD aan het einde
    if (chain.length > 0) {
        const finalUrl = chain[chain.length - 1];
        try {
            const finalDomain = new URL(finalUrl).hostname.toLowerCase();
            if (/\.(xyz|top|club|tk|ml|ga|cf|gq|buzz|rest|icu|cyou|cfd)$/i.test(finalDomain)) {
                threats.push('suspiciousFinalTLD');
            }
        } catch (e) {
            // URL parsing error
        }
    }

    // 5. Redirect naar IP adres
    for (const url of chain.slice(1)) { // Skip eerste URL
        try {
            const host = new URL(url).hostname;
            if (/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/.test(host)) {
                threats.push('redirectToIP');
                break;
            }
        } catch (e) {
            // URL parsing error
        }
    }
}

/**
 * Controleert of een URL een bekende shortener is
 */
function isKnownShortener(url) {
    try {
        const domain = new URL(url).hostname.toLowerCase().replace(/^www\./, '');
        return KNOWN_SHORTENERS.has(domain);
    } catch (e) {
        return false;
    }
}

/** Fetches a URL with retry logic */
async function fetchWithRetry(url, options, maxRetries = 3, retryDelay = 1000) {
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
        try {
            const response = await fetch(url, options);
            if (response.status === 404) {
                // Specifieke afhandeling voor 404, kan betekenen dat de resource niet bestaat
                return response;
            }
            if (!response.ok) {
                throw new Error(`HTTP error, status = ${response.status}`);
            }
            return response;
        } catch (error) {
            if (attempt < maxRetries) {
                if (globalThresholds.DEBUG_MODE) console.warn(`Fetch attempt ${attempt} failed for ${url}: ${error.message}. Retrying in ${retryDelay}ms...`);
                await new Promise(r => setTimeout(r, retryDelay));
            } else {
                if (globalThresholds.DEBUG_MODE) console.error(`Fetch failed after ${maxRetries} attempts for ${url}:`, error);
                throw error;
            }
        }
    }
}


// ==== License Validation ====

// Gumroad Product ID's (volledige ID, niet de permalink)
const LINKSHIELD_ID = 'SGJcxK8Uy2PnPpkgLkso7w==';
const CLICKMATE_ID = 'zdfmya';

/**
 * Valideert een licentiesleutel tegen alle ondersteunde Gumroad producten.
 * Probeert eerst LinkShield, daarna ClickMate.
 * @param {string} licenseKey - De licentiesleutel om te valideren
 * @returns {Promise<{success: boolean, email?: string, error?: string}>}
 */
async function validateLicenseKey(licenseKey) {
    const cleanKey = licenseKey.trim();

    // We proberen beide ID's, omdat ClickMate-klanten soms ook LinkShield gebruiken
    const productIds = [LINKSHIELD_ID, CLICKMATE_ID];

    for (const productId of productIds) {
        try {
            const response = await fetch('https://api.gumroad.com/v2/licenses/verify', {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    'Accept': 'application/json'
                },
                body: JSON.stringify({
                    product_id: productId,
                    license_key: cleanKey
                })
            });

            const data = await response.json();

            if (data.success && data.purchase) {
                // Check op refunds
                if (data.purchase.refunded || data.purchase.chargebacked) {
                    continue;
                }

                // SUCCES! Sla de gegevens op
                await chrome.storage.sync.set({
                    licenseKey: cleanKey,
                    licenseValid: true,
                    licenseEmail: data.purchase.email,
                    licenseValidatedAt: Date.now()
                });

                return { success: true, email: data.purchase.email };
            }
        } catch (error) {
            console.error(`[License] Fout tijdens aanroep voor ${productId}:`, error);
        }
    }

    // Als beide mislukken
    return { success: false, error: "Licentie niet gevonden voor LinkShield of ClickMate." };
}

/** Revalidates stored license key in the background - probeert beide producten */
async function revalidateLicense() {
    try {
        const data = await chrome.storage.sync.get(['licenseKey', 'licenseValid']);

        if (!data.licenseKey || !data.licenseValid) {
            return { revalidated: false, reason: 'No valid license to revalidate' };
        }

        // Probeer beide product ID's
        const productIds = [LINKSHIELD_ID, CLICKMATE_ID];

        for (const productId of productIds) {
            try {
                const response = await fetch('https://api.gumroad.com/v2/licenses/verify', {
                    method: 'POST',
                    headers: {
                        'Content-Type': 'application/json',
                        'Accept': 'application/json'
                    },
                    body: JSON.stringify({
                        product_id: productId,
                        license_key: data.licenseKey
                    })
                });

                const result = await response.json();

                if (result.success && result.purchase) {
                    // Check for refunded/chargebacked status
                    if (result.purchase.refunded || result.purchase.chargebacked || result.purchase.disputed) {
                        continue; // Probeer volgende product
                    }

                    // License still valid - update timestamp
                    await chrome.storage.sync.set({
                        licenseValid: true,
                        licenseValidatedAt: Date.now()
                    });
                    return { revalidated: true, valid: true };
                }
            } catch (err) {
                console.error(`[License] Error revalidating with ${productId}:`, err);
            }
        }

        // Beide producten gefaald - markeer als ongeldig
        await chrome.storage.sync.set({
            licenseValid: false,
            licenseValidatedAt: Date.now()
        });
        return { revalidated: true, valid: false };

    } catch (error) {
        // Network error - don't change license status (fail-safe)
        console.error("[License] Revalidation network error:", error);
        return { revalidated: false, reason: 'Network error', networkError: true };
    }
}

// ==== Trial Period Management ====

const TRIAL_DAYS = 30;
const MS_PER_DAY = 24 * 60 * 60 * 1000;

// Gecachete trial status voor performance (voorkomt herhaalde storage reads)
let cachedTrialStatus = null;
let trialStatusCacheTime = 0;
const TRIAL_CACHE_TTL = 60000; // 1 minuut cache TTL

/**
 * Haalt gecachete trial status op of leest uit storage indien cache verlopen
 * @returns {Promise<{isActive: boolean, daysRemaining: number, isExpired: boolean, hasLicense: boolean}>}
 */
async function getCachedTrialStatus() {
    const now = Date.now();

    // Gebruik cache als deze nog geldig is
    if (cachedTrialStatus && (now - trialStatusCacheTime) < TRIAL_CACHE_TTL) {
        return cachedTrialStatus;
    }

    // Cache verlopen of niet aanwezig, haal nieuwe status op
    cachedTrialStatus = await checkTrialStatus();
    trialStatusCacheTime = now;
    return cachedTrialStatus;
}

/**
 * Invalideert de trial status cache (bijv. na licentie activatie)
 */
function invalidateTrialCache() {
    cachedTrialStatus = null;
    trialStatusCacheTime = 0;
}

/**
 * Controleert of achtergrondbeveiliging toegestaan is op basis van licentie/trial
 * @returns {Promise<boolean>}
 */
async function isBackgroundSecurityAllowed() {
    const status = await getCachedTrialStatus();
    const allowed = status.hasLicense || status.isActive;

    return allowed;
}

/**
 * Controleert de status van de proefperiode
 * @returns {Promise<{isActive: boolean, daysRemaining: number, isExpired: boolean, hasLicense: boolean}>}
 */
async function checkTrialStatus() {
    try {
        const data = await chrome.storage.sync.get(['installDate', 'trialDays', 'licenseKey', 'licenseValid']);

        // Als er een geldige licentie is, is de proefperiode niet relevant
        if (data.licenseValid === true) {
            return {
                isActive: false,
                daysRemaining: 0,
                isExpired: false,
                hasLicense: true
            };
        }

        // Als er geen installatiedatum is, stel deze nu in (voor bestaande installaties)
        if (!data.installDate) {
            const now = Date.now();
            await chrome.storage.sync.set({ installDate: now, trialDays: TRIAL_DAYS });
            return {
                isActive: true,
                daysRemaining: TRIAL_DAYS,
                isExpired: false,
                hasLicense: false
            };
        }

        const installDate = data.installDate;
        const trialDays = data.trialDays || TRIAL_DAYS;
        const now = Date.now();
        const daysSinceInstall = Math.floor((now - installDate) / MS_PER_DAY);
        const daysRemaining = Math.max(0, trialDays - daysSinceInstall);
        const isExpired = daysRemaining <= 0;

        return {
            isActive: !isExpired,
            daysRemaining: daysRemaining,
            isExpired: isExpired,
            hasLicense: false
        };
    } catch (error) {
        console.error("[Trial] Error checking trial status:", error);
        // Bij fout, ga uit van actieve proefperiode
        return {
            isActive: true,
            daysRemaining: TRIAL_DAYS,
            isExpired: false,
            hasLicense: false
        };
    }
}

/**
 * Controleert of premium functies beschikbaar zijn (licentie OF actieve proefperiode)
 * @returns {Promise<boolean>}
 */
async function isPremiumActive() {
    const status = await checkTrialStatus();
    return status.hasLicense || status.isActive;
}


// ==== SSL Labs Check (Wordt aangeroepen vanuit content script via message) ====

const sslCache = new Map();

/** Checks SSL/TLS configuration using SSL Labs API */
async function checkSslLabs(domain) {
    if (globalThresholds.DEBUG_MODE) console.log(`[checkSslLabs] Starting for ${domain}`);
    try {
        const cachedSsl = sslCache.get(domain);
        if (cachedSsl && Date.now() - cachedSsl.timestamp < 24 * 60 * 60 * 1000) {
            if (globalThresholds.DEBUG_MODE) console.log(`[checkSslLabs] Cache hit voor ${domain}`);
            return cachedSsl.result;
        }

        if (globalThresholds.DEBUG_MODE) console.log(`[checkSslLabs] Fetching SSL data for ${domain}`);
        const response = await fetchWithRetry(
            `https://api.ssllabs.com/api/v3/analyze?host=${domain}&maxAge=86400`, { mode: 'cors' }
        );

        if (globalThresholds.DEBUG_MODE) console.log(`[checkSslLabs] Response status for ${domain}: ${response.status}`);
        if (response.status === 429) {
            if (globalThresholds.DEBUG_MODE) console.warn(`[checkSslLabs] Rate limit bereikt voor ${domain}`);
            // Bij rate limit, retourneer een 'onbekend' maar niet-foutief resultaat
            const result = { isValid: true, reason: "Rate limit, SSL-check overgeslagen" };
            sslCache.set(domain, { result, timestamp: Date.now() });
            return result;
        }

        if (!response.ok) {
            throw new Error(`HTTP-fout: ${response.status}`);
        }

        const data = await response.json();
        if (globalThresholds.DEBUG_MODE) console.log(`[checkSslLabs] Full response data for ${domain}:`, data);

        if (data.status === "READY" && data.endpoints && data.endpoints.length > 0) {
            const allEndpointsFailed = data.endpoints.every(endpoint =>
                endpoint.statusMessage === "Unable to connect to the server"
            );
            if (allEndpointsFailed) {
                if (globalThresholds.DEBUG_MODE) console.log(`[checkSslLabs] Alle endpoints onbereikbaar voor ${domain}`);
                const result = { isValid: false, reason: "Server onbereikbaar voor SSL-analyse" };
                sslCache.set(domain, { result, timestamp: Date.now() });
                return result;
            }
            const grade = data.endpoints[0].grade || "Unknown";
            // Beschouw A en A+ als geldig, of pas dit aan naar jouw veiligheidsstandaard
            const isValid = ["A", "A+", "B", "C"].includes(grade); // Flexibelere validatie
            const result = {
                isValid,
                reason: isValid ? `Geldig certificaat (Grade: ${grade})` : `Onveilige SSL (Grade: ${grade})`
            };
            sslCache.set(domain, { result, timestamp: Date.now() });
            if (globalThresholds.DEBUG_MODE) console.log(`[checkSslLabs] Resultaat voor ${domain}: ${grade}`);
            return result;
        } else if (data.status === "ERROR") {
            if (globalThresholds.DEBUG_MODE) console.warn(`[checkSslLabs] SSL Labs fout voor ${domain}: ${data.statusMessage}`);
            const result = { isValid: false, reason: `SSL Labs fout: ${data.statusMessage || "Onbekende fout"}` };
            sslCache.set(domain, { result, timestamp: Date.now() });
            return result;
        } else if (data.status === "IN_PROGRESS") {
            // Als de scan nog bezig is, geef aan dat het onzeker is, maar blokkeer niet direct
            if (globalThresholds.DEBUG_MODE) console.log(`[checkSslLabs] SSL-scan in uitvoering voor ${domain}`);
            const result = { isValid: true, reason: "SSL-scan in uitvoering, nog geen resultaat" };
            // Cache dit resultaat ook, maar met een kortere TTL als je snel wilt herchecken
            sslCache.set(domain, { result, timestamp: Date.now() });
            return result;
        } else {
            if (globalThresholds.DEBUG_MODE) console.warn(`[checkSslLabs] Onverwachte responsstatus voor ${domain}: ${data.status}`);
            const result = { isValid: false, reason: "Onverwachte SSL Labs respons" };
            sslCache.set(domain, { result, timestamp: Date.now() });
            return result;
        }
    } catch (error) {
        console.error(`[checkSslLabs] Fout bij SSL-check voor ${domain}:`, error);
        // Bij netwerkfouten, rate limits of timeouts, beschouw het als tijdelijk onbereikbaar
        if (error.message.includes("network") || error.message.includes("fetch") || error.message.includes("429") || error.message.includes("timeout")) {
            const result = { isValid: true, reason: "Netwerkfout of rate limit, SSL-check overgeslagen" };
            sslCache.set(domain, { result, timestamp: Date.now() });
            return result;
        }
        return { isValid: false, reason: `SSL-check mislukt: ${error.message}` };
    }
}

// Cache-schoonmaak voor sslCache (elke 24 uur)
setInterval(() => {
    const now = Date.now();
    for (const [domain, { timestamp }] of sslCache) {
        if (now - timestamp >= 24 * 60 * 60 * 1000) {
            sslCache.delete(domain);
            if (globalThresholds.DEBUG_MODE) console.log(`[DEBUG] Verwijderd verlopen SSL-cache voor ${domain}`);
        }
    }
}, 24 * 60 * 60 * 1000);


// ==== Installation and Alarms ====

chrome.runtime.onInstalled.addListener(async (details) => {
    try {
        if (details.reason === "install") {
            const defaultSettings = {
                backgroundSecurity: true,
                integratedProtection: true,
                // Stel ook de default thresholds in bij de eerste installatie
                LOW_THRESHOLD: 3,
                MEDIUM_THRESHOLD: 7,
                HIGH_THRESHOLD: 12,
                DOMAIN_AGE_MIN_RISK: 5,
                YOUNG_DOMAIN_RISK: 5,
                YOUNG_DOMAIN_THRESHOLD_DAYS: 7,
                DEBUG_MODE: false, // Default off
                // Proefperiode: sla installatiedatum op
                installDate: Date.now(),
                trialDays: 30
            };

            await chrome.storage.sync.set(defaultSettings);
            if (globalThresholds.DEBUG_MODE) console.log("Default settings saved on install with trial period.");

            chrome.tabs.create({ url: "https://linkshield.nl/#install" });

            chrome.notifications.create("pinReminder", {
                type: "basic",
                iconUrl: "icons/icon128.png",
                title: chrome.i18n.getMessage("installNotificationTitle") || "Extensie Geïnstalleerd!",
                message: chrome.i18n.getMessage("installNotificationMessage") || "Speld de extensie vast aan je werkbalk voor snelle toegang. Klik op het extensie-icoon en selecteer 'Vastzetten'. Dit icoon waarschuwt je als een site onveilig is.",
                priority: 2
            });
        }

        // Zorg ervoor dat thresholds geladen zijn voordat regels worden opgehaald
        await loadThresholdsFromStorage();
        await fetchAndLoadRules();
        await manageDNRules(); // Activeer/deactiveer regels op basis van initiële instellingen

        chrome.alarms.create("fetchRulesHourly", {
            periodInMinutes: 60
        });
        if (globalThresholds.DEBUG_MODE) console.log("Hourly rule fetch alarm created.");

        // Create daily license check alarm (every 24 hours = 1440 minutes)
        chrome.alarms.create("daily_license_check", {
            periodInMinutes: 1440
        });
        if (globalThresholds.DEBUG_MODE) console.log("Daily license check alarm created.");

    } catch (error) {
        console.error("Error during extension installation or update:", error);
    }
});

chrome.alarms.onAlarm.addListener(async (alarm) => {
    if (alarm.name === "fetchRulesHourly") {
        if (globalThresholds.DEBUG_MODE) console.log("Hourly alarm triggered: fetching rules.");
        await loadThresholdsFromStorage(); // Laad thresholds opnieuw voor het geval ze zijn veranderd
        fetchAndLoadRules().catch(error => {
            console.error("[ERROR] Error fetching rules via alarm:", error.message);
        });
    }

    if (alarm.name === "daily_license_check") {
        if (globalThresholds.DEBUG_MODE) console.log("Daily license check alarm triggered.");
        revalidateLicense().catch(error => {
            console.error("[ERROR] Error revalidating license via alarm:", error.message);
        });
    }
});


// ==== Message Listener (Hoofdcommunicatie met Content Scripts) ====
// =================== HIERONDER STAAT DE VOLLEDIG GECORRIGEERDE LISTENER ===================


chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    if (globalThresholds.DEBUG_MODE) {
        console.log(`[Background Script] Received message:`, request, sender);
    }

    switch (request.type || request.action) {

        case 'validateLicense':
            validateLicenseKey(request.licenseKey)
                .then(result => {
                    // Invalideer cache bij succesvolle licentie activatie
                    if (result.success) {
                        invalidateTrialCache();
                        // Heractiveer achtergrondbeveiliging met nieuwe status
                        manageDNRules();
                        fetchAndLoadRules();
                    }
                    sendResponse(result);
                })
                .catch(error => {
                    console.error("[validateLicense] Error:", error);
                    sendResponse({ success: false, error: "License validation failed" });
                });
            return true;

        case 'checkLicense':
            chrome.storage.sync.get(['licenseKey', 'licenseValid', 'licenseEmail', 'licenseValidatedAt'])
                .then(data => {
                    sendResponse({
                        hasLicense: data.licenseValid === true,
                        licenseKey: data.licenseKey || '',
                        email: data.licenseEmail || '',
                        validatedAt: data.licenseValidatedAt || null
                    });
                })
                .catch(error => {
                    console.error("[checkLicense] Error:", error);
                    sendResponse({ hasLicense: false, error: error.message });
                });
            return true;

        case 'checkTrialStatus':
            checkTrialStatus()
                .then(status => sendResponse(status))
                .catch(error => {
                    console.error("[checkTrialStatus] Error:", error);
                    sendResponse({ isActive: true, daysRemaining: 30, isExpired: false, hasLicense: false });
                });
            return true;

        case 'isPremiumActive':
            isPremiumActive()
                .then(isActive => sendResponse({ isPremium: isActive }))
                .catch(error => {
                    console.error("[isPremiumActive] Error:", error);
                    sendResponse({ isPremium: true });
                });
            return true;

        case 'checkUrl':
            sendResponse({ status: "not_implemented" });
            return true;

        case 'analyzeRedirectChain': {
            // Redirect Chain Analysis (v7.1)
            const targetUrl = request.url;
            const shouldAnalyze = request.force || isKnownShortener(targetUrl) || request.level === 'caution';

            if (!shouldAnalyze) {
                sendResponse({
                    analyzed: false,
                    reason: 'not_eligible',
                    finalUrl: targetUrl,
                    chain: [targetUrl],
                    threats: []
                });
                return true;
            }

            traceRedirectChain(targetUrl, 3000)
                .then(result => {
                    sendResponse({
                        analyzed: true,
                        ...result
                    });
                })
                .catch(error => {
                    console.error("[analyzeRedirectChain] Error:", error);
                    sendResponse({
                        analyzed: false,
                        error: error.message,
                        finalUrl: targetUrl,
                        chain: [targetUrl],
                        threats: []
                    });
                });
            return true; // Async response
        }

        case 'checkResult': {
            const { url, level, reasons, risk } = request;

            (async () => {
                try {
                    // LICENTIE CHECK: Controleer of achtergrondscans toegestaan zijn
                    const isAllowed = await isBackgroundSecurityAllowed();
                    if (!isAllowed) {
                        if (globalThresholds.DEBUG_MODE) {
                            console.log("[Background] checkResult overgeslagen: trial verlopen zonder licentie.");
                        }
                        sendResponse({ status: 'skipped', reason: 'trial_expired' });
                        return;
                    }

                    const { integratedProtection } = await chrome.storage.sync.get('integratedProtection');
                    if (!integratedProtection) {
                        if (globalThresholds.DEBUG_MODE) {
                            console.log("Integrated protection is off, skipping update.");
                        }
                        sendResponse({ status: 'skipped' });
                        return;
                    }

                    const statusToStore = {
                        url,
                        level,
                        risk: Number(risk),
                        reasons: Array.isArray(reasons) ? reasons : []
                    };

                    if (globalThresholds.DEBUG_MODE) {
                        console.log("[Background Script] Storing status:", statusToStore);
                    }

                    await chrome.storage.local.set({ currentSiteStatus: statusToStore });
                    await updateIconBasedOnSafety(level, reasons, risk, url);
                    sendResponse({ status: 'received' });
                } catch (error) {
                    console.error("[Background] Error handling checkResult:", error);
                    sendResponse({ status: 'error', error: error.message });
                }
            })();

            return true;
        }

        case 'updatePageStatus': {
            const { url: pageUrl, reasons: pageReasons, risk: pageRisk } = request;
            if (globalThresholds.DEBUG_MODE) {
                console.log(`[Background] updatePageStatus voor URL: ${pageUrl}`);
            }

            chrome.storage.local.get("currentSiteStatus")
                .then(async ({ currentSiteStatus }) => {
                    let combinedRisk = pageRisk;
                    let combinedReasons = new Set(pageReasons);
                    let currentLevel = 'safe';

                    if (currentSiteStatus && currentSiteStatus.url === pageUrl) {
                        combinedRisk += currentSiteStatus.risk;
                        currentSiteStatus.reasons.forEach(r => combinedReasons.add(r));
                        currentLevel = (currentSiteStatus.level === 'alert')
                            ? 'alert'
                            : (currentSiteStatus.level === 'caution' ? 'caution' : currentLevel);
                    }

                    if (combinedRisk >= globalThresholds.HIGH_THRESHOLD) {
                        currentLevel = 'alert';
                    } else if (combinedRisk >= globalThresholds.LOW_THRESHOLD) {
                        currentLevel = 'caution';
                    }

                    const finalStatus = {
                        url: pageUrl,
                        level: currentLevel,
                        risk: combinedRisk,
                        reasons: Array.from(combinedReasons)
                    };

                    if (globalThresholds.DEBUG_MODE) {
                        console.log("[Background] Opslaan gecombineerde status:", finalStatus);
                    }

                    await chrome.storage.local.set({ currentSiteStatus: finalStatus });
                })
                .catch(error => {
                    console.error("[updatePageStatus] Fout bij combineren status:", error);
                });

            return true;
        }

        case 'getStatus':
            chrome.storage.local.get("currentSiteStatus")
                .then(({ currentSiteStatus }) =>
                    sendResponse(currentSiteStatus || { level: 'safe', reasons: ["No status"], url: null, risk: 0 })
                )
                .catch(error => {
                    console.error("[getStatus] Error:", error);
                    sendResponse({ level: 'safe', reasons: ["Error"], url: null, risk: 0 });
                });
            return true;

        // --- START VAN DE VERNIEUWDE 'checkSslLabs' CASE ---
        case 'checkSslLabs': {
            const domain = request.domain;

            // 1. Controleer eerst de cache
            const cached = sslCache.get(domain);
            if (cached && (Date.now() - cached.timestamp < CACHE_TTL)) {
                if (globalThresholds.DEBUG_MODE) {
                    console.log(`[Cache HIT] SSL-status voor ${domain} uit cache gehaald.`);
                }
                sendResponse(cached.result);
                return; // synchroon
            }

            if (globalThresholds.DEBUG_MODE) {
                console.log(`[API Call] SSL-status voor ${domain} opvragen...`);
            }

            fetch(`https://api.ssllabs.com/api/v3/analyze?host=${domain}&all=done&fromCache=on&maxAge=24`)
                .then(response => {
                    if (!response.ok) {
                        throw new Error(`API status was ${response.status}, niet 200. Check wordt overgeslagen.`);
                    }
                    return response.json();
                })
                .then(data => {
                    if (data.status === 'ERROR') {
                        throw new Error(`API retourneerde een foutstatus voor domein ${domain}`);
                    }

                    const endpoint = data.endpoints && data.endpoints.length > 0 ? data.endpoints[0] : null;
                    const grade = endpoint?.grade;
                    
                    let result;
                    if (grade) {
                        const isActuallyInvalid = ['F', 'T', 'M'].includes(grade);
                        result = {
                            isValid: !isActuallyInvalid,
                            reason: isActuallyInvalid
                                ? `Ongeldig certificaat gedetecteerd (Grade: ${grade})`
                                : `Geldig certificaat (Grade: ${grade})`
                        };
                    } else {
                        result = {
                            isValid: true,
                            reason: 'Certificaatstatus kon niet worden bepaald, aangenomen als OK.'
                        };
                    }
                    
                    sslCache.set(domain, { timestamp: Date.now(), result });
                    sendResponse(result);
                })
                .catch(error => {
                    console.error(`SSL Labs check voor ${domain} is definitief mislukt:`, error.message);
                    const safeFallback = {
                        isValid: true,
                        reason: 'De certificaat-check kon niet worden uitgevoerd.'
                    };
                    
                    sslCache.set(domain, { timestamp: Date.now(), result: safeFallback });
                    sendResponse(safeFallback);
                });

            return true; // houd port open voor async
        }
        // --- EINDE VAN DE VERNIEUWDE 'checkSslLabs' CASE ---

        default:
            console.warn("[onMessage] Onbekend berichttype:", request.type || request.action);
            sendResponse({ success: false, error: "Unknown message type" });
            return true;
    }
});



// === Zorg dat hierna pas je uninstall-URL komt ===
chrome.runtime.setUninstallURL("https://linkshield.nl/#uninstall");



// ==== Event Listeners voor Browser/Tab Activiteit ====

// Luister naar tab updates en activatie om de status te resetten
chrome.tabs.onUpdated.addListener(async (tabId, changeInfo, tab) => {
    // Reageer alleen als de URL daadwerkelijk is veranderd (en het een volledige URL is)
    if (changeInfo.url && tab.url && tab.url.startsWith('http')) {
        stopIconAnimation(); // Stop animatie bij navigatie
        await resetCurrentSiteStatus(); // Reset de opgeslagen status voor de nieuwe URL
        resetIconToNeutral(); // Zet icoon naar neutraal (groen)
    }
});

chrome.tabs.onActivated.addListener(async ({ tabId }) => {
    stopIconAnimation(); // Stop animatie bij tab-switch
    await resetCurrentSiteStatus(); // Reset de opgeslagen status
    resetIconToNeutral(); // Zet icoon naar neutraal (groen)
});


chrome.action.onClicked.addListener(async (tab) => {
    try {
        // Optioneel: als je wilt dat een klik op het icoon de status reset of de popup opent
        // Voor nu resetten we de status als de site veilig is (omdat de popup dan niet veel toont)
        // en laten we de popup de gedetailleerde info tonen.
        const { currentSiteStatus } = await chrome.storage.local.get("currentSiteStatus");
        if (currentSiteStatus && currentSiteStatus.level === 'safe') { // Als de site veilig is, en je wilt een reset mogelijk maken
            await chrome.storage.local.remove("currentSiteStatus");
            if (globalThresholds.DEBUG_MODE) console.log("currentSiteStatus cleared on icon click for a safe site.");
            resetIconToNeutral();
        }
    } catch (error) {
        console.error("[ERROR] chrome.action.onClicked error:", error);
    }
});

// Bewaar de laatste verwerkte status om dubbele icon-updates te vermijden
let lastStatusKey = null;

// Listener voor wijzigingen in storage.
// Reageert op wijzigingen in sync (voor rules fetch) en local (voor icon updates).
chrome.storage.onChanged.addListener(async (changes, area) => {
  if (area === "sync") {
    // Update thresholds als sync config verandert
    if (
      'LOW_THRESHOLD' in changes ||
      'MEDIUM_THRESHOLD' in changes ||
      'HIGH_THRESHOLD' in changes ||
      'DOMAIN_AGE_MIN_RISK' in changes ||
      'YOUNG_DOMAIN_RISK' in changes ||
      'YOUNG_DOMAIN_THRESHOLD_DAYS' in changes ||
      'DEBUG_MODE' in changes
    ) {
      await loadThresholdsFromStorage();
    }

    // LICENTIE/TRIAL SYNCHRONISATIE: Reageer op wijzigingen in licentie of trial status
    if ('licenseValid' in changes || 'installDate' in changes || 'trialDays' in changes) {
      invalidateTrialCache();

      // Controleer of achtergrondbeveiliging (de)geactiveerd moet worden
      const isAllowed = await isBackgroundSecurityAllowed();

      // Update DNR regels op basis van nieuwe status
      await manageDNRules();

      // Als licentie nu geldig is (was ongeldig), herlaad regels
      if ('licenseValid' in changes && changes.licenseValid.newValue === true) {
        await fetchAndLoadRules();
      }

      // Als licentie nu ongeldig is (was geldig) of trial verlopen, verwijder regels
      if (!isAllowed) {
        await clearDynamicRules();
      }
    }

    // Regel updates als backgroundSecurity verandert
    if ("backgroundSecurity" in changes) {
      const now = Date.now();
      if (now - lastUpdate < 300000) { // 5 minuten debounce
        if (globalThresholds.DEBUG_MODE) {
          console.log("Too soon for another rules update. Skipping.");
        }
        return;
      }
      lastUpdate = now;
      if (globalThresholds.DEBUG_MODE) {
        console.log("backgroundSecurity changed. Updating DNR rules.");
      }
      await fetchAndLoadRules();
      await manageDNRules();
    }
  }

  // Reageer op veranderingen in currentSiteStatus om het icoon bij te werken
  if (area === "local" && changes.currentSiteStatus) {
    const { oldValue, newValue } = changes.currentSiteStatus;

    // Negeer deletes, duplicate writes en writes vanuit updateIcon (aanwezigheid van isSafe)
    if (
      !newValue ||
      JSON.stringify(oldValue) === JSON.stringify(newValue) ||
      newValue.hasOwnProperty('isSafe')
    ) {
      if (globalThresholds.DEBUG_MODE) {
        console.log("[STORAGE LISTENER] currentSiteStatus ignored:", { oldValue, newValue });
      }
      return;
    }

    const { level, reasons, risk, url } = newValue;
    await updateIconBasedOnSafety(level, reasons, risk, url);
  }
});



chrome.runtime.onStartup.addListener(async () => {
  await restoreIconState();
  // Voer licentie check uit bij browser startup
  await performStartupLicenseCheck();
});

chrome.runtime.onInstalled.addListener(async (details) => {
  if (details.reason === "install" || details.reason === "update") {
    await restoreIconState();
    // Voer licentie check uit na installatie of update
    await performStartupLicenseCheck();
  }
});

// Voer ook direct een licentie check uit wanneer de service worker start
// Dit vangt gevallen op waarin de browser al open was
setTimeout(() => {
  performStartupLicenseCheck().catch(err =>
    console.error("[INIT] Vertraagde licentie check mislukt:", err)
  );
}, 1000); // 1 seconde vertraging om te zorgen dat alle functies geladen zijn