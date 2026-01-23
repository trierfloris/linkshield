// =================================================================================
// LINKSHIELD BACKGROUND SERVICE WORKER - PRODUCTIE
// =================================================================================

// ==== Globale Instellingen en Debugging ====
const IS_PRODUCTION = true;
const CACHE_TTL = 24 * 60 * 60 * 1000;
const API_TIMEOUT_MS = 5000; // 5 seconden timeout voor API calls (verlaagd van 10s)

// ==== License & Trial Constants (MUST be early for quota functions) ====
const MS_PER_DAY = 24 * 60 * 60 * 1000;
const TRIAL_DAYS = 30;

// ==== Globale Drempels en Configuratie ====
// MUST be early - used by functions that run at startup (loadSslLabsRateLimitState, initializeProtectionImmediately)
let globalThresholds = {
    LOW_THRESHOLD: 4,
    MEDIUM_THRESHOLD: 8,
    HIGH_THRESHOLD: 15,
    DOMAIN_AGE_MIN_RISK: 5,
    YOUNG_DOMAIN_RISK: 5,
    YOUNG_DOMAIN_THRESHOLD_DAYS: 7,
    DEBUG_MODE: false // Wordt overschreven door opgeslagen config
};

/**
 * Veilige i18n wrapper met null checks
 * @param {string} key - De i18n message key
 * @param {string} [fallback] - Optionele fallback waarde
 * @returns {string}
 */
function safeGetMessage(key, fallback) {
  try {
    if (typeof chrome !== 'undefined' && chrome.i18n && typeof chrome.i18n.getMessage === 'function') {
      const msg = chrome.i18n.getMessage(key);
      return msg || fallback || key;
    }
  } catch (e) {
    // Ignore - extension context might be invalidated
  }
  return fallback || key;
}

/**
 * PERFORMANCE FIX v8.1.0: Non-blocking protection initialization
 * Called IMMEDIATELY at startup to enable protection.
 * v8.4.0: Automatic Protection is ALWAYS FREE - no trial check needed
 */
async function initializeProtectionImmediately() {
    const startTime = Date.now();
    try {
        // v8.4.0: Ensure protection settings are enabled (fix corrupted state from previous versions)
        // Automatic Protection is always free, so these should always be true by default
        const settings = await chrome.storage.sync.get(['backgroundSecurity', 'integratedProtection']);
        if (settings.backgroundSecurity === false || settings.integratedProtection === false) {
            console.log('[INIT-FAST] Resetting protection settings to enabled (v8.4.0 migration)');
            await chrome.storage.sync.set({ backgroundSecurity: true, integratedProtection: true });
        }

        // v8.4.0: Always enable protection - Automatic Protection is FREE
        await manageDNRules();
        console.log(`[INIT-FAST] Protection enabled in ${Date.now() - startTime}ms (always free)`);
        return { initialized: true, timeMs: Date.now() - startTime };
    } catch (err) {
        console.error("[INIT-FAST] Error:", err);
        // Try to enable protection anyway on error
        try {
            await chrome.storage.sync.set({ backgroundSecurity: true });
            await manageDNRules();
            console.warn("[INIT-FAST] Protection enabled despite error");
        } catch (e) { /* ignore */ }
        return { initialized: false, error: err.message };
    }
}

// ==== SSL Labs Rate Limiting & Caching ====
const SSL_LABS_MIN_INTERVAL_MS = 10000; // Minimaal 10 seconden tussen requests
const SSL_LABS_CACHE_TTL = 24 * 60 * 60 * 1000; // 24 uur cache
const SSL_LABS_ERROR_CACHE_TTL = 30 * 60 * 1000; // 30 minuten cache voor errors (voorkomt spam bij 529)

// SECURITY FIX v7.9.3: Persistente state voor Service Worker resilience
// In-memory state wordt aangevuld met chrome.storage.session voor persistentie
let sslLabsLastRequestTime = 0; // In-memory cache (snel), backed by storage.session

/**
 * Laadt SSL Labs rate limit state uit chrome.storage.session
 * Wordt aangeroepen bij SW startup om state te herstellen
 */
async function loadSslLabsRateLimitState() {
    try {
        const data = await chrome.storage.session.get(['sslLabsLastRequestTime']);
        if (data.sslLabsLastRequestTime) {
            sslLabsLastRequestTime = data.sslLabsLastRequestTime;
            if (globalThresholds.DEBUG_MODE) {
                console.log(`[SSL Labs] Rate limit state hersteld: laatste request ${Date.now() - sslLabsLastRequestTime}ms geleden`);
            }
        }
    } catch (error) {
        // storage.session niet beschikbaar (oudere Chrome versie) - gebruik alleen in-memory
        console.error('[SSL Labs] Kon rate limit state niet laden:', error);
    }
}

/**
 * Slaat SSL Labs rate limit timestamp op in chrome.storage.session
 * @param {number} timestamp - De timestamp om op te slaan
 */
async function saveSslLabsRateLimitState(timestamp) {
    try {
        await chrome.storage.session.set({ sslLabsLastRequestTime: timestamp });
    } catch (error) {
        // storage.session niet beschikbaar - negeer, in-memory werkt nog steeds
        if (globalThresholds.DEBUG_MODE) {
            console.error('[SSL Labs] Kon rate limit state niet opslaan:', error);
        }
    }
}

// Laad rate limit state bij SW startup
loadSslLabsRateLimitState();

// =================================================================================
// SCAN QUOTA MANAGEMENT (v8.4.0)
// Gratis gebruikers: max 20 unieke domeinen per dag
// Premium/Trial gebruikers: unlimited
// =================================================================================

const DAILY_SCAN_QUOTA = 20; // Max unieke domeinen per dag voor gratis users

/**
 * Haalt de huidige scan quota status op
 * @returns {Promise<{domainsScanned: string[], count: number, limit: number, resetAt: number, isUnlimited: boolean}>}
 */
async function getScanQuotaStatus() {
    try {
        // v8.4.0 FIX: Use storage.local instead of sync to avoid MAX_WRITE_OPERATIONS_PER_MINUTE quota
        const [quotaData, trialStatus] = await Promise.all([
            chrome.storage.local.get(['scanQuota']),
            checkTrialStatus()
        ]);

        const isUnlimited = trialStatus.hasLicense || trialStatus.isActive;
        const now = Date.now();
        const quota = quotaData.scanQuota || { domains: [], resetAt: getNextResetTime() };

        // Check of quota gereset moet worden
        if (now >= quota.resetAt) {
            const newQuota = { domains: [], resetAt: getNextResetTime() };
            await chrome.storage.local.set({ scanQuota: newQuota });

            // v8.4.0: Auto-enable Smart Link Scanning when quota resets (for free users)
            if (!isUnlimited) {
                await chrome.storage.sync.set({ integratedProtection: true });
                // Notify popup about the reset
                chrome.runtime.sendMessage({ type: 'quotaReset' }).catch(() => {});
            }

            return {
                domainsScanned: [],
                count: 0,
                limit: DAILY_SCAN_QUOTA,
                resetAt: newQuota.resetAt,
                isUnlimited
            };
        }

        return {
            domainsScanned: quota.domains || [],
            count: (quota.domains || []).length,
            limit: DAILY_SCAN_QUOTA,
            resetAt: quota.resetAt,
            isUnlimited
        };
    } catch (error) {
        console.error('[ScanQuota] Error getting status:', error);
        return {
            domainsScanned: [],
            count: 0,
            limit: DAILY_SCAN_QUOTA,
            resetAt: getNextResetTime(),
            isUnlimited: true // Fail-safe: allow scanning on error
        };
    }
}

/**
 * Berekent de volgende reset tijd (middernacht UTC)
 * @returns {number} Timestamp van volgende reset
 */
function getNextResetTime() {
    const now = new Date();
    const tomorrow = new Date(Date.UTC(
        now.getUTCFullYear(),
        now.getUTCMonth(),
        now.getUTCDate() + 1,
        0, 0, 0, 0
    ));
    return tomorrow.getTime();
}

/**
 * Controleert of een domein gescand mag worden
 * @param {string} domain - Het domein om te controleren
 * @returns {Promise<{allowed: boolean, reason: string, quotaStatus: object}>}
 */
async function canScanDomain(domain) {
    try {
        // v8.4.0 FIX: Allow empty domains (e.g., from mailto: URLs) without counting
        if (!domain || domain.trim() === '') {
            return { allowed: true, reason: 'empty_domain' };
        }

        const status = await getScanQuotaStatus();

        // Premium/trial users hebben geen limiet
        if (status.isUnlimited) {
            return {
                allowed: true,
                reason: 'unlimited',
                quotaStatus: status
            };
        }

        // Check of domein al gescand is vandaag (telt niet mee)
        if (status.domainsScanned.includes(domain)) {
            return {
                allowed: true,
                reason: 'already_scanned',
                quotaStatus: status
            };
        }

        // Check quota limiet
        if (status.count >= status.limit) {
            return {
                allowed: false,
                reason: 'quota_exceeded',
                quotaStatus: status
            };
        }

        return {
            allowed: true,
            reason: 'within_quota',
            quotaStatus: status
        };
    } catch (error) {
        console.error('[ScanQuota] Error checking domain:', error);
        return {
            allowed: true, // Fail-safe
            reason: 'error',
            quotaStatus: null
        };
    }
}

/**
 * Registreert dat een domein is gescand
 * @param {string} domain - Het gescande domein
 * @returns {Promise<{recorded: boolean, quotaStatus: object}>}
 */
async function recordDomainScan(domain) {
    try {
        // v8.4.0 FIX: Skip empty domains (e.g., from mailto: URLs)
        if (!domain || domain.trim() === '') {
            return { recorded: false, reason: 'empty_domain' };
        }

        const status = await getScanQuotaStatus();

        // Premium/trial users: geen tracking nodig
        if (status.isUnlimited) {
            return { recorded: false, quotaStatus: status };
        }

        // Domein al gescand vandaag: geen actie
        if (status.domainsScanned.includes(domain)) {
            return { recorded: false, quotaStatus: status };
        }

        // Voeg domein toe aan lijst
        const newDomains = [...status.domainsScanned, domain];
        const newQuota = {
            domains: newDomains,
            resetAt: status.resetAt
        };
        await chrome.storage.local.set({ scanQuota: newQuota });

        // v8.4.0 FIX: Broadcast quota update to popup (storage.local events don't propagate to popup in MV3)
        chrome.runtime.sendMessage({ type: 'quotaUpdated', count: newDomains.length }).catch(() => {
            // Popup might not be open - ignore error
        });

        return {
            recorded: true,
            quotaStatus: {
                ...status,
                domainsScanned: newDomains,
                count: newDomains.length
            }
        };
    } catch (error) {
        console.error('[ScanQuota] Error recording scan:', error);
        return { recorded: false, quotaStatus: null };
    }
}

/**
 * Reset de scan quota (wordt aangeroepen door alarm of handmatig)
 */
async function resetScanQuota() {
    try {
        const newQuota = { domains: [], resetAt: getNextResetTime() };
        await chrome.storage.local.set({ scanQuota: newQuota });
        if (globalThresholds.DEBUG_MODE) {
            console.log('[ScanQuota] Quota reset completed');
        }
    } catch (error) {
        console.error('[ScanQuota] Error resetting quota:', error);
    }
}

// =============================================================================
// SECURITY FIX v8.5.0: Advanced Threat Detection Statistics
// =============================================================================

/**
 * Increment teller voor geblokkeerde dreigingen (voor popup statistieken)
 * @param {string} threatType - Type dreiging (oauth_theft, fake_turnstile, split_qr)
 */
async function incrementBlockedThreatsCount(threatType) {
    try {
        const key = `blocked_${threatType}_count`;
        const result = await chrome.storage.local.get([key, 'blocked_total_count', 'threats_today']);
        const current = result[key] || 0;
        const total = result.blocked_total_count || 0;
        const threatsToday = result.threats_today || 0;

        await chrome.storage.local.set({
            [key]: current + 1,
            blocked_total_count: total + 1,
            threats_today: threatsToday + 1
        });

        if (globalThresholds.DEBUG_MODE) {
            console.log(`[ThreatStats] Incremented ${threatType}: ${current + 1} (total: ${total + 1})`);
        }
    } catch (e) {
        // Ignore storage errors
    }
}

/**
 * Placeholder functie voor URL reputatie check
 * Kan later geïntegreerd worden met Google Safe Browsing of andere APIs
 * @param {string} url - De URL om te checken
 * @returns {Promise<{malicious: boolean, score: number}>}
 */
async function checkUrlReputation(url) {
    // Placeholder - in productie zou dit een echte API call zijn
    // naar Safe Browsing, VirusTotal, of een eigen reputatie service
    try {
        // Basis check: is het een bekende phishing/malware TLD?
        const urlObj = new URL(url);
        const hostname = urlObj.hostname.toLowerCase();
        const tld = hostname.split('.').pop();

        // Snelle check tegen bekende slechte TLDs
        const dangerousTLDs = ['tk', 'ml', 'ga', 'cf', 'gq', 'xyz', 'top', 'click', 'zip'];
        if (dangerousTLDs.includes(tld)) {
            return { malicious: true, score: 8 };
        }

        return { malicious: false, score: 0 };
    } catch (e) {
        return { malicious: false, score: 0 };
    }
}

// Overschrijf console-functies voor productieomgeving
if (IS_PRODUCTION) {
    console.log = function () { };
    console.warn = function () { };
    console.info = function () { };
    // SECURITY FIX: Ook console.error sanitizen om gevoelige data te verbergen
    const originalError = console.error;
    console.error = function (...args) {
        // Filter gevoelige informatie uit error logs
        const sanitizedArgs = args.map(arg => {
            if (typeof arg === 'string') {
                // Verwijder potentiële license keys, URLs met credentials, etc.
                return arg
                    .replace(/license[_-]?key[=:]\s*['"]?[A-Za-z0-9-]+['"]?/gi, 'license_key=[REDACTED]')
                    .replace(/[A-Za-z0-9+/=]{20,}/g, '[REDACTED_TOKEN]')
                    .replace(/https?:\/\/[^@\s]+@/g, 'https://[REDACTED]@');
            }
            return arg;
        });
        originalError.apply(console, sanitizedArgs);
    };
}

/**
 * Fetch met timeout - voorkomt dat extension hangt bij trage/dode API's
 * @param {string} url - De URL om te fetchen
 * @param {object} options - Fetch opties
 * @param {number} timeout - Timeout in ms (default: API_TIMEOUT_MS)
 * @returns {Promise<Response>}
 */
async function fetchWithTimeout(url, options = {}, timeout = API_TIMEOUT_MS) {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), timeout);

    try {
        const response = await fetch(url, {
            ...options,
            signal: controller.signal
        });
        return response;
    } finally {
        clearTimeout(timeoutId);
    }
}

// ==== License Grace Period Constants ====
const LICENSE_GRACE_PERIOD_DAYS = 7;
const LICENSE_GRACE_PERIOD_MS = LICENSE_GRACE_PERIOD_DAYS * MS_PER_DAY;

// ==== SECURITY FIX: Fail-Safe Mode ====
// Bij licentie-validatie fouten: BEHOUD bestaande bescherming in plaats van uitschakelen
// Dit voorkomt dat een aanvaller via DDoS op de licentieserver alle gebruikers kan "ontwapenen"
const FAIL_SAFE_MODE = true;

// ==== SECURITY FIX v8.7.0: Emergency Mode - Safe-by-Default ====
// Als de licentieserver niet reageert, gaat de extensie in Emergency Mode
// Bescherming blijft ALTIJD actief, ongeacht serverstatus
// Gebruikt lastKnownValid timestamp in chrome.storage.local voor offline validatie
const EMERGENCY_MODE_ENABLED = true;
const EMERGENCY_MODE_MAX_OFFLINE_DAYS = 30; // Max dagen offline voordat UI waarschuwing toont

/**
 * SECURITY FIX v8.7.0: Slaat lastKnownValid timestamp op
 * Wordt gebruikt voor Emergency Mode offline validatie
 */
async function setLastKnownValid() {
    try {
        const now = Date.now();
        await chrome.storage.local.set({
            lastKnownValid: now,
            emergencyModeActive: false
        });
        if (globalThresholds.DEBUG_MODE) {
            console.log('[EmergencyMode] lastKnownValid updated:', new Date(now).toISOString());
        }
    } catch (error) {
        console.error('[EmergencyMode] Failed to set lastKnownValid:', error);
    }
}

/**
 * SECURITY FIX v8.7.0: Haalt lastKnownValid timestamp op
 * @returns {Promise<{lastKnownValid: number, daysSinceValid: number, isEmergencyMode: boolean}>}
 */
async function getEmergencyModeStatus() {
    try {
        const data = await chrome.storage.local.get(['lastKnownValid', 'emergencyModeActive']);
        const now = Date.now();

        if (!data.lastKnownValid) {
            // Geen lastKnownValid - eerste gebruik, stel nu in
            await setLastKnownValid();
            return { lastKnownValid: now, daysSinceValid: 0, isEmergencyMode: false };
        }

        const daysSinceValid = Math.floor((now - data.lastKnownValid) / MS_PER_DAY);
        const isEmergencyMode = data.emergencyModeActive === true;

        return { lastKnownValid: data.lastKnownValid, daysSinceValid, isEmergencyMode };
    } catch (error) {
        console.error('[EmergencyMode] Failed to get status:', error);
        // Bij error, neem aan dat we in emergency mode moeten blijven
        return { lastKnownValid: Date.now(), daysSinceValid: 0, isEmergencyMode: true };
    }
}

/**
 * SECURITY FIX v8.7.0: Activeert Emergency Mode
 * Bescherming blijft actief, maar gebruiker wordt geïnformeerd
 */
async function activateEmergencyMode(reason) {
    try {
        await chrome.storage.local.set({ emergencyModeActive: true, emergencyModeReason: reason });

        // Toon notificatie aan gebruiker
        chrome.notifications.create('emergency_mode_' + Date.now(), {
            type: 'basic',
            iconUrl: 'icons/icon128.png',
            title: safeGetMessage('emergencyModeTitle') || 'Emergency Protection Mode',
            message: safeGetMessage('emergencyModeMessage') ||
                'LinkShield is running in Emergency Mode. Protection remains fully active. Please check your internet connection.',
            priority: 1
        });

        // Zet badge om aan te geven dat we in emergency mode zijn
        await chrome.action.setBadgeText({ text: 'E' });
        await chrome.action.setBadgeBackgroundColor({ color: '#ff9800' }); // Orange

        console.warn('[EmergencyMode] ACTIVATED - Reason:', reason);
    } catch (error) {
        console.error('[EmergencyMode] Failed to activate:', error);
    }
}

/**
 * SECURITY FIX v8.7.0: Deactiveert Emergency Mode na succesvolle validatie
 */
async function deactivateEmergencyMode() {
    try {
        const data = await chrome.storage.local.get(['emergencyModeActive']);
        if (data.emergencyModeActive) {
            await chrome.storage.local.set({ emergencyModeActive: false, emergencyModeReason: null });
            await setLastKnownValid();

            // Verwijder emergency badge
            await chrome.action.setBadgeText({ text: '' });

            console.log('[EmergencyMode] DEACTIVATED - Normal operation resumed');
        }
    } catch (error) {
        console.error('[EmergencyMode] Failed to deactivate:', error);
    }
}

/**
 * Controleert of de licentie grace period is verlopen
 * VROEG GEDEFINIEERD: Deze functie wordt gebruikt in performStartupLicenseCheck
 * @returns {Promise<{expired: boolean, daysSinceValidation: number, graceRemaining: number}>}
 */
async function checkLicenseGracePeriod() {
    try {
        const data = await chrome.storage.sync.get(['licenseValid', 'lastSuccessfulValidation']);

        // Als er geen licentie is, is grace period niet van toepassing
        if (!data.licenseValid) {
            return { expired: false, daysSinceValidation: 0, graceRemaining: 0, noLicense: true };
        }

        // Als er geen lastSuccessfulValidation is, stel deze nu in (voor bestaande installaties)
        if (!data.lastSuccessfulValidation) {
            const now = Date.now();
            await chrome.storage.sync.set({ lastSuccessfulValidation: now });
            return { expired: false, daysSinceValidation: 0, graceRemaining: LICENSE_GRACE_PERIOD_DAYS, noLicense: false };
        }

        const now = Date.now();
        const timeSinceValidation = now - data.lastSuccessfulValidation;
        const daysSinceValidation = Math.floor(timeSinceValidation / MS_PER_DAY);
        const graceRemaining = Math.max(0, LICENSE_GRACE_PERIOD_DAYS - daysSinceValidation);
        const expired = timeSinceValidation > LICENSE_GRACE_PERIOD_MS;

        if (globalThresholds.DEBUG_MODE) {
            console.log(`[Grace Period] Dagen sinds validatie: ${daysSinceValidation}, Resterend: ${graceRemaining}, Verlopen: ${expired}`);
        }

        return { expired, daysSinceValidation, graceRemaining, noLicense: false };
    } catch (error) {
        console.error("[Grace Period] Error checking grace period:", error);
        // Bij error, neem aan dat grace nog geldig is om legitieme gebruikers niet te blokkeren
        return { expired: false, daysSinceValidation: 0, graceRemaining: LICENSE_GRACE_PERIOD_DAYS, error: true };
    }
}

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
 *
 * SECURITY FIX v7.9.1: Implementeert FAIL_SAFE_MODE
 * Bij netwerk fouten of server outages wordt bescherming BEHOUDEN in plaats van uitgeschakeld
 *
 * SECURITY FIX v7.9.2: Respecteert explicitlyInvalidated flag
 * Wanneer de server EXPLICIET bevestigt dat een licentie ongeldig is, wordt FAIL_SAFE genegeerd
 *
 * SECURITY FIX v8.0.0: KRITIEK - manageDNRules() wordt ALTIJD aangeroepen
 * Voorheen werd manageDNRules() overgeslagen bij early returns, waardoor DNR rulesets
 * niet werden geactiveerd bij browser restart tijdens server outage
 */
async function performStartupLicenseCheck() {
    // Track of de server EXPLICIET heeft gezegd dat de licentie ongeldig is
    // Dit onderscheidt "server onbereikbaar" van "server zegt NEE"
    let explicitlyInvalidated = false;

    try {
        const data = await chrome.storage.sync.get(['licenseValid', 'lastSuccessfulValidation']);

        // Als er een licentie is, controleer grace period en forceer revalidatie indien nodig
        if (data.licenseValid) {
            const graceStatus = await checkLicenseGracePeriod();

            // Als meer dan 3 dagen sinds laatste validatie, forceer online check
            // Dit zorgt ervoor dat we niet wachten tot het laatste moment
            const REVALIDATION_THRESHOLD_DAYS = 3;
            if (graceStatus.daysSinceValidation >= REVALIDATION_THRESHOLD_DAYS) {
                if (globalThresholds.DEBUG_MODE) {
                    console.log(`[INIT] ${graceStatus.daysSinceValidation} dagen sinds laatste validatie, forceer revalidatie...`);
                }

                const result = await revalidateLicense();

                // SECURITY FIX: Onderscheid netwerk errors van echte invalidatie
                if (result.networkError) {
                    // SECURITY FIX v8.7.0: Emergency Mode - bescherming blijft ALTIJD actief
                    console.warn("[INIT] Revalidatie gefaald door netwerk - EMERGENCY MODE actief");

                    if (EMERGENCY_MODE_ENABLED) {
                        await activateEmergencyMode('license_server_unreachable');
                    } else if (FAIL_SAFE_MODE) {
                        await showFailSafeNotification('network_error');
                    }

                    // CRITICAL: Bescherming ALTIJD activeren bij netwerk errors
                    await manageDNRules();
                    return;
                }

                if (!result.revalidated && graceStatus.expired) {
                    // Revalidatie mislukt EN grace period verlopen
                    if (FAIL_SAFE_MODE) {
                        // FAIL_SAFE: Bij twijfel, behoud bescherming
                        console.warn("[INIT] Grace period verlopen maar FAIL_SAFE mode actief - bescherming behouden");
                        await showFailSafeNotification('grace_expired_failsafe');
                        // SECURITY FIX v8.0.0: ALTIJD manageDNRules() aanroepen om rulesets te activeren!
                        await manageDNRules();
                        return;
                    }

                    if (globalThresholds.DEBUG_MODE) {
                        console.log("[INIT] Revalidatie mislukt en grace period verlopen - licentie wordt ongeldig");
                    }
                    await chrome.storage.sync.set({ licenseValid: false });
                    invalidateTrialCache();
                } else if (result.revalidated && !result.valid) {
                    // Server zegt EXPLICIET dat licentie ongeldig is - dit is GEEN fail-safe scenario
                    // De server heeft bevestigd dat de licentie niet meer geldig is
                    if (globalThresholds.DEBUG_MODE) {
                        console.log("[INIT] Licentie is niet meer geldig volgens server");
                    }

                    // SECURITY FIX v7.9.2: Markeer als expliciet geïnvalideerd
                    // Dit zorgt ervoor dat FAIL_SAFE_MODE wordt genegeerd voor deze sessie
                    if (result.explicitlyInvalidated) {
                        explicitlyInvalidated = true;
                        console.log("[INIT] Server heeft licentie EXPLICIET geïnvalideerd - FAIL_SAFE wordt genegeerd");
                    }

                    invalidateTrialCache();
                }
            }
        }

        // v8.4.0: Automatic Protection is ALWAYS FREE
        // DNR rules are always enabled regardless of trial/license status
        // Only Smart Link Scanning has quota limits after trial expires
        await manageDNRules();
        console.log("[INIT] Automatic Protection enabled (always free)");
    } catch (err) {
        console.error("[INIT] Fout bij startup licentie check:", err);
        // SECURITY FIX: Bij ELKE error, behoud bescherming als FAIL_SAFE_MODE actief is
        // MAAR niet als de licentie al expliciet is geïnvalideerd
        if (FAIL_SAFE_MODE && !explicitlyInvalidated) {
            console.warn("[INIT] Error tijdens licentie check - FAIL_SAFE: bescherming behouden");
            await showFailSafeNotification('error_failsafe');
        }
        // SECURITY FIX v8.0.0: Ook bij errors, probeer rulesets te activeren
        // Dit zorgt voor bescherming zelfs als de licentie check faalt
        try {
            await manageDNRules();
        } catch (ruleError) {
            console.error("[INIT] Kon DNR rules niet activeren na error:", ruleError);
        }
    }
}

/**
 * Toont een notificatie aan de gebruiker dat fail-safe mode actief is
 * @param {string} reason - Reden voor fail-safe ('network_error', 'grace_expired_failsafe', 'protection_preserved', 'error_failsafe')
 */
async function showFailSafeNotification(reason) {
    try {
        // Toon badge waarschuwing
        await chrome.action.setBadgeText({ text: '!' });
        await chrome.action.setBadgeBackgroundColor({ color: '#f59e0b' }); // Amber/warning

        // Bepaal notificatie tekst op basis van reden
        let title, message;
        switch (reason) {
            case 'network_error':
                title = safeGetMessage('failSafeNetworkTitle') || 'License Check Failed';
                message = safeGetMessage('failSafeNetworkMessage') ||
                    'Could not verify license due to network issues. Protection remains active in safe mode.';
                break;
            case 'grace_expired_failsafe':
                title = safeGetMessage('failSafeGraceTitle') || 'License Verification Needed';
                message = safeGetMessage('failSafeGraceMessage') ||
                    'Please connect to the internet to verify your license. Protection remains active.';
                break;
            case 'protection_preserved':
                title = safeGetMessage('failSafePreservedTitle') || 'Protection Active';
                message = safeGetMessage('failSafePreservedMessage') ||
                    'Your protection rules are preserved. Please verify your license when possible.';
                break;
            case 'fresh_install_failsafe':
                title = safeGetMessage('failSafeFreshInstallTitle') || 'Protection Enabled';
                message = safeGetMessage('failSafeFreshInstallMessage') ||
                    'LinkShield protection is active. Please verify your license when possible.';
                break;
            default:
                title = safeGetMessage('failSafeDefaultTitle') || 'Safe Mode Active';
                message = safeGetMessage('failSafeDefaultMessage') ||
                    'LinkShield is running in safe mode. Protection remains active.';
        }

        // Maak notificatie aan
        chrome.notifications.create(`failsafe_${reason}_${Date.now()}`, {
            type: 'basic',
            iconUrl: 'icons/icon128.png',
            title: title,
            message: message,
            priority: 1
        });

        // Sla fail-safe status op voor popup weergave
        await chrome.storage.local.set({
            failSafeActive: true,
            failSafeReason: reason,
            failSafeTimestamp: Date.now()
        });

    } catch (error) {
        console.error("[FAIL_SAFE] Error showing notification:", error);
    }
}


// ==== Icon State Management (MV3 Compatible - NO setInterval) ====
// MV3 FIX: Service Workers zijn ephemeral en kunnen slapen na ~30 seconden.
// setInterval en in-memory state werken NIET betrouwbaar.
// Gebruik chrome.action.setBadgeText voor persistente visuele feedback.

/**
 * Sets a warning badge on the extension icon
 * MV3 SAFE: Badge text persists even when service worker sleeps
 * @param {string} text - Badge text ("!" for alert, "?" for caution, "" for safe)
 * @param {string} color - Badge background color
 */
async function setIconBadge(text, color) {
    try {
        await chrome.action.setBadgeText({ text: text });
        await chrome.action.setBadgeBackgroundColor({ color: color });
    } catch (e) {
        // Ignore errors when tab is closed
    }
}

/**
 * Shows alert badge (high risk) - RED with "!"
 */
function showAlertBadge() {
    setIconBadge("!", "#DC3545"); // Bootstrap danger red
}

/**
 * Shows caution badge (medium risk) - YELLOW with "?"
 */
function showCautionBadge() {
    setIconBadge("?", "#FFC107"); // Bootstrap warning yellow
}

/**
 * Clears the badge (safe/no issues)
 */
function clearBadge() {
    setIconBadge("", "#000000");
}

/** Stops any icon animation (legacy compatibility - now just clears badge) */
function stopIconAnimation() {
    clearBadge();
}

/**
 * MV3 FIX: Replaced setInterval animation with static badge
 * This function now sets a persistent warning badge instead of animating
 */
function startSmoothIconAnimation(duration = 30000, interval = 500) {
    // MV3 FIX: Animation via setInterval doesn't work reliably in Service Workers
    // Instead, we set a static alert badge that persists
    showAlertBadge();

    // Use chrome.alarms for delayed badge removal (MV3 safe)
    // Note: minimum alarm delay is 1 minute in MV3
    // v8.8.14: Clear existing alarm first to prevent alarm buildup (max 500 limit)
    chrome.alarms.clear('clearAlertBadge', () => {
        chrome.alarms.create('clearAlertBadge', { delayInMinutes: 1 });
    });
}

/** Resets the icon to a neutral state (green) */
function resetIconToNeutral() {
    try {
        chrome.action.setIcon({
            path: {
                "16": "icons/green-circle-16.png",
                "48": "icons/green-circle-48.png",
                "128": "icons/green-circle-128.png"
            }
        });
        clearBadge();
        chrome.action.setTitle({ title: safeGetMessage("neutralIconTitle") || "Performing safety check..." });
    } catch (error) {
        console.error("[ERROR] resetIconToNeutral error:", error);
    }
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
        safe: { "16": "icons/green-circle-16.png", "48": "icons/green-circle-48.png", "128": "icons/green-circle-128.png" },
        caution: { "16": "icons/yellow-circle-16.png", "48": "icons/yellow-circle-48.png", "128": "icons/yellow-circle-128.png" },
        alert: { "16": "icons/red-circle-16.png", "48": "icons/red-circle-48.png", "128": "icons/red-circle-128.png" }
    };
    chrome.action.setIcon({ path: iconMap[lvl] });

    // 4) Tooltip samenstellen uit i18n-title + vertaalde redenen
    const titleKey = lvl === 'alert' ?
        'siteAlertTitle' :
        lvl === 'caution' ?
            'siteCautionTitle' :
            'siteSafeTitle';

    let tooltip = safeGetMessage(titleKey) || '';
    if (Array.isArray(reasons) && reasons.length) {
        const reasonTexts = reasons
            .map(key => safeGetMessage(key))
            .filter(text => text && text.trim().length > 0)
            .join('\n');
        if (reasonTexts) {
            tooltip += '\n' + reasonTexts;
        }
    }
    chrome.action.setTitle({ title: tooltip });

    // 5) MV3 FIX: Gebruik badge in plaats van animatie
    // Badges zijn persistent en werken ook als Service Worker slaapt
    if (lvl === 'alert') {
        if (globalThresholds.DEBUG_MODE) {
            console.log(`[ICON BADGE] Level is 'alert', rode badge wordt getoond.`);
        }
        showAlertBadge(); // Shows "!" in red
    } else if (lvl === 'caution') {
        if (globalThresholds.DEBUG_MODE) {
            console.log(`[ICON BADGE] Level is 'caution', gele badge wordt getoond.`);
        }
        showCautionBadge(); // Shows "?" in yellow
    } else {
        if (globalThresholds.DEBUG_MODE) {
            console.log(`[ICON BADGE] Level is '${lvl}', badge wordt verwijderd.`);
        }
        clearBadge();
    }
}











// ==== Rule Management and Fetching (Declarative Net Request) ====

let isUpdatingRules = false; // Debounce flag to prevent overlapping updates
let lastUpdate = 0; // Timestamp of the last update for additional control

/** Manages the enabling/disabling of declarativeNetRequest rulesets based on settings */
async function manageDNRules() {
    try {
        const { backgroundSecurity } = await chrome.storage.sync.get('backgroundSecurity');

        // v8.4.0: Removed trial check - Automatic Protection (DNR rules) is ALWAYS FREE
        // DNR rules only depend on user's backgroundSecurity setting, not trial status
        if (backgroundSecurity !== false) {
            await chrome.declarativeNetRequest.updateEnabledRulesets({
                enableRulesetIds: ["ruleset_1"]
            });
            if (globalThresholds.DEBUG_MODE) console.log("DNR Ruleset 1 enabled.");
        } else {
            await chrome.declarativeNetRequest.updateEnabledRulesets({
                disableRulesetIds: ["ruleset_1"]
            });
            if (globalThresholds.DEBUG_MODE) {
                console.log("DNR Ruleset 1 disabled: backgroundSecurity is off.");
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

    // v8.4.0: Removed trial check - Automatic Protection (dynamic rules) is ALWAYS FREE
    // Dynamic rules are fetched regardless of trial status

    isUpdatingRules = true;

    // Hardgecodeerde whitelist voor kritieke OAuth/API endpoints
    // SECURITY FIX: docs.google.com, drive.google.com, forms.google.com VERWIJDERD
    // Deze services worden misbruikt voor phishing (Google Forms phishing, kwaadaardige Docs links)
    // Alleen technische endpoints die noodzakelijk zijn voor authenticatie/API's blijven gewhitelist
    const HARDCODED_WHITELIST = new Set([
        // Google OAuth en technische APIs (vereist voor authenticatie)
        "accounts.google.com", "apis.google.com", "oauth2.googleapis.com", "www.googleapis.com",
        // Google CDN/Fonts (veilige statische content)
        "fonts.googleapis.com", "fonts.gstatic.com", "ssl.gstatic.com",
        // Google Core services (zoeken, vertalen)
        "www.google.com", "translate.google.com", "chrome.google.com",
        // Google technische endpoints
        "clients1.google.com", "lh3.googleusercontent.com",
        // Microsoft OAuth/Login
        "microsoftonline.com", "login.microsoft.com", "login.live.com",
        // Microsoft productie endpoints
        "outlook.live.com",
        // Apple OAuth
        "appleid.apple.com",
        // Note: office.com, office365.com VERWIJDERD - kunnen misbruikt worden
        // Note: mail.google.com, calendar.google.com behouden - legitieme services
        "mail.google.com", "calendar.google.com"
    ]);

    /**
     * SECURITY FIX: Verbeterde whitelist check die exact domein matching doet
     * in plaats van simpele substring matching om bypasses te voorkomen.
     * @param {string} urlFilter - Het URL filter patroon uit de regel
     * @returns {boolean} - true als het domein gewhitelist is
     */
    function isWhitelisted(urlFilter) {
        // Extraheer het domein uit het urlFilter patroon
        // Patronen kunnen zijn: "*://domain.com/*", "||domain.com^", etc.
        const cleanFilter = urlFilter
            .replace(/^\*:\/\//, '')      // Verwijder *://
            .replace(/^\|\|/, '')          // Verwijder ||
            .replace(/\^.*$/, '')          // Verwijder ^ en alles erna
            .replace(/\/.*$/, '')          // Verwijder pad
            .replace(/^\*\./, '')          // Verwijder *. wildcard
            .replace(/\*$/, '')            // Verwijder trailing *
            .toLowerCase();

        // Exact match check
        if (HARDCODED_WHITELIST.has(cleanFilter)) {
            return true;
        }

        // Subdomein check: check of het een subdomein is van een gewhitelist domein
        for (const whitelistedDomain of HARDCODED_WHITELIST) {
            if (cleanFilter.endsWith('.' + whitelistedDomain)) {
                return true;
            }
        }

        return false;
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
// SECURITY FIX v8.0.1 (Vector 4): Persistente cache voor SW resilience
const redirectChainCache = new Map();
const REDIRECT_CACHE_TTL = 30 * 60 * 1000; // 30 minuten cache
const REDIRECT_CACHE_MAX_PERSIST = 100; // Max entries om op te slaan (voorkom quota overschrijding)

/**
 * Laadt redirect chain cache uit chrome.storage.session
 * SECURITY FIX v8.0.1: Voorkomt state verlies bij SW suspension
 */
async function loadRedirectChainCache() {
    try {
        const data = await chrome.storage.session.get(['redirectChainCacheData']);
        if (data.redirectChainCacheData && Array.isArray(data.redirectChainCacheData)) {
            const now = Date.now();
            let restored = 0;
            for (const [url, entry] of data.redirectChainCacheData) {
                // Alleen nog geldige entries herstellen
                if (entry && entry.timestamp && (now - entry.timestamp < REDIRECT_CACHE_TTL)) {
                    redirectChainCache.set(url, entry);
                    restored++;
                }
            }
            if (globalThresholds.DEBUG_MODE && restored > 0) {
                console.log(`[RedirectChain] Cache hersteld: ${restored} entries`);
            }
        }
    } catch (error) {
        if (globalThresholds.DEBUG_MODE) {
            console.error('[RedirectChain] Kon cache niet laden:', error);
        }
    }
}

/**
 * Slaat redirect chain cache op in chrome.storage.session
 * SECURITY FIX v8.0.1: Beperkt tot recente entries voor performance
 */
async function saveRedirectChainCache() {
    try {
        // Converteer Map naar Array en beperk tot meest recente entries
        const entries = [...redirectChainCache.entries()]
            .filter(([_, entry]) => Date.now() - entry.timestamp < REDIRECT_CACHE_TTL)
            .sort((a, b) => b[1].timestamp - a[1].timestamp)
            .slice(0, REDIRECT_CACHE_MAX_PERSIST);

        await chrome.storage.session.set({ redirectChainCacheData: entries });
    } catch (error) {
        if (globalThresholds.DEBUG_MODE) {
            console.error('[RedirectChain] Kon cache niet opslaan:', error);
        }
    }
}

// Laad redirect chain cache bij SW startup
loadRedirectChainCache();

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
    const visitedUrls = new Set(); // SECURITY FIX: Track bezochte URLs voor circular detectie

    try {
        // Extract initial domain
        try {
            visitedDomains.add(new URL(url).hostname.toLowerCase());
            visitedUrls.add(url); // Track initiële URL
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

                // MV3 FIX: Cross-origin redirects geven 'opaqueredirect' response type
                // In dat geval kunnen we de Location header niet lezen
                if (response.type === 'opaqueredirect') {
                    if (globalThresholds.DEBUG_MODE) {
                        console.log(`[RedirectChain] Opaque redirect gedetecteerd, fallback naar follow mode`);
                    }

                    // Fallback: Doe een nieuwe request met redirect: 'follow' om de finale URL te krijgen
                    try {
                        const followController = new AbortController();
                        const followTimeoutId = setTimeout(() => followController.abort(), timeout);

                        const followResponse = await fetch(currentUrl, {
                            method: 'HEAD',
                            redirect: 'follow',
                            signal: followController.signal,
                            headers: {
                                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
                            }
                        });

                        clearTimeout(followTimeoutId);

                        // De finale URL is beschikbaar via response.url
                        const finalUrl = followResponse.url;
                        if (finalUrl && finalUrl !== currentUrl) {
                            // We weten niet hoeveel redirects er waren, maar we kennen het eindpunt
                            try {
                                const finalDomain = new URL(finalUrl).hostname.toLowerCase();
                                if (!visitedDomains.has(finalDomain)) {
                                    visitedDomains.add(finalDomain);
                                }
                            } catch (e) { }

                            chain.push(finalUrl);
                            currentUrl = finalUrl;
                            redirectCount++; // Minimaal 1 redirect
                            threats.push('opaqueRedirectChain'); // Markeer dat we niet elke stap konden zien
                        }
                    } catch (e) {
                        if (globalThresholds.DEBUG_MODE) {
                            console.log(`[RedirectChain] Fallback fetch failed:`, e.message);
                        }
                    }
                    break; // Stop de loop, we hebben wat we kunnen krijgen
                }

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

                    // SECURITY FIX: Vroege circular redirect detectie
                    if (visitedUrls.has(currentUrl)) {
                        threats.push('circularRedirect');
                        if (globalThresholds.DEBUG_MODE) {
                            console.log(`[RedirectChain] Circular redirect gedetecteerd: ${currentUrl}`);
                        }
                        break; // Stop de loop bij circular redirect
                    }
                    visitedUrls.add(currentUrl);

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

        // SECURITY FIX: Timestamp-based cache cleanup in plaats van FIFO
        // Verwijder verouderde entries EN limiteer grootte
        const now = Date.now();
        if (redirectChainCache.size > 400) { // Begin cleanup bij 400 om burst te voorkomen
            for (const [key, value] of redirectChainCache) {
                // Verwijder entries ouder dan TTL
                if (now - value.timestamp > REDIRECT_CACHE_TTL) {
                    redirectChainCache.delete(key);
                }
                // Stop als we onder 300 zijn
                if (redirectChainCache.size <= 300) break;
            }
        }

        // SECURITY FIX v8.0.1 (Vector 4): Persist cache voor SW resilience
        // Gebruik debounced save om storage spam te voorkomen
        saveRedirectChainCache();

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
 * Inclusief Smart Redirect scoring voor opaque redirects
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
    let hasSuspiciousFinalTLD = false;
    if (chain.length > 0) {
        const finalUrl = chain[chain.length - 1];
        try {
            const finalDomain = new URL(finalUrl).hostname.toLowerCase();
            if (/\.(xyz|top|club|tk|ml|ga|cf|gq|buzz|rest|icu|cyou|cfd)$/i.test(finalDomain)) {
                threats.push('suspiciousFinalTLD');
                hasSuspiciousFinalTLD = true;
            }
        } catch (e) {
            // URL parsing error
        }
    }

    // 5. Redirect naar IP adres
    let redirectsToIP = false;
    for (const url of chain.slice(1)) { // Skip eerste URL
        try {
            const host = new URL(url).hostname;
            if (/^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/.test(host)) {
                threats.push('redirectToIP');
                redirectsToIP = true;
                break;
            }
        } catch (e) {
            // URL parsing error
        }
    }

    // 6. Smart Opaque Redirect Scoring
    // Verhoog de ernst van opaqueRedirectChain op basis van context
    if (threats.includes('opaqueRedirectChain')) {
        // Verwijder de basis threat en voeg de juiste variant toe
        const opaqueIndex = threats.indexOf('opaqueRedirectChain');
        if (opaqueIndex > -1) {
            threats.splice(opaqueIndex, 1);
        }

        // Bepaal de ernst op basis van combinaties
        if (redirectsToIP) {
            // Opaque + redirect naar IP = hoogste risico (+10)
            threats.push('opaqueRedirectToIP');
        } else if (hasSuspiciousFinalTLD) {
            // Opaque + verdachte TLD = hoog risico (+6)
            threats.push('opaqueRedirectSuspiciousTLD');
        } else {
            // Standaard opaque redirect (+3)
            threats.push('opaqueRedirectChain');
        }
    }
}

/**
 * Berekent de risicoscore voor redirect chain threats
 * @param {string[]} threats - Array van threat identifiers
 * @returns {number} - Totale risicoscore
 */
function calculateRedirectChainScore(threats) {
    let score = 0;
    const scoreMap = {
        'excessiveRedirects': 5,
        'domainHopping': 4,
        'chainedShorteners': 4,
        'suspiciousFinalTLD': 5,
        'redirectToIP': 6,
        'circularRedirect': 4,
        'redirectTimeout': 3,
        'invalidRedirectUrl': 3,
        // Smart Opaque Redirect scores
        'opaqueRedirectChain': 3,        // Basis
        'opaqueRedirectSuspiciousTLD': 6, // Opaque + verdachte TLD
        'opaqueRedirectToIP': 10,         // Opaque + IP redirect
        'opaqueRedirectNRD': 8            // Opaque + nieuw domein (indien gecombineerd)
    };

    for (const threat of threats) {
        score += scoreMap[threat] || 0;
    }

    return score;
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

/** Fetches a URL with retry logic AND timeout protection */
async function fetchWithRetry(url, options = {}, maxRetries = 3, retryDelay = 1000) {
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
        try {
            // REGRESSIE FIX: Gebruik fetchWithTimeout om hangs te voorkomen
            const response = await fetchWithTimeout(url, options, API_TIMEOUT_MS);
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

// Lemon Squeezy Variant ID
const LEMON_SQUEEZY_VARIANT_ID = '1193408';

/**
 * Valideert en activeert een licentiesleutel via de Lemon Squeezy License API.
 * Gebruikt het /activate endpoint om de licentie te activeren voor deze extensie-installatie.
 * @param {string} licenseKey - De licentiesleutel om te valideren en activeren
 * @returns {Promise<{success: boolean, email?: string, error?: string}>}
 */
async function validateLicenseKey(licenseKey) {
    const cleanKey = licenseKey.trim();

    try {
        // Lemon Squeezy License Activation API
        // Docs: https://docs.lemonsqueezy.com/api/license-keys
        const response = await fetchWithTimeout('https://api.lemonsqueezy.com/v1/licenses/activate', {
            method: 'POST',
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                license_key: cleanKey,
                instance_name: 'Browser_Extension_User'
            })
        }, API_TIMEOUT_MS);

        const data = await response.json();

        // Lemon Squeezy retourneert activated: true bij succesvolle activatie
        // en license_key.status moet 'active' zijn
        if (data.activated === true && data.license_key && data.license_key.status === 'active') {
            // Haal email op uit de meta data indien beschikbaar
            const customerEmail = data.meta?.customer_email || data.license_key?.customer_email || '';

            // SUCCES! Sla de gegevens op
            const now = Date.now();
            await chrome.storage.sync.set({
                licenseKey: cleanKey,
                licenseValid: true,
                licenseEmail: customerEmail,
                licenseValidatedAt: now,
                // Sla ook instance_id op voor eventuele deactivatie later
                licenseInstanceId: data.instance?.id || '',
                // Grace period: sla laatste succesvolle validatie op
                lastSuccessfulValidation: now
            });

            return { success: true, email: customerEmail };
        }

        // Check voor specifieke foutmeldingen van Lemon Squeezy
        if (data.error) {
            return { success: false, error: data.error };
        }

        // Als activated false is maar geen error, generieke foutmelding
        if (data.activated === false) {
            return { success: false, error: data.error || 'Licentie kon niet worden geactiveerd.' };
        }

        // Andere onverwachte responses
        return { success: false, error: 'Onverwachte respons van licentieserver.' };

    } catch (error) {
        console.error('[License] Fout tijdens Lemon Squeezy activatie:', error);
        return { success: false, error: 'Netwerkfout tijdens licentievalidatie.' };
    }
}

/**
 * Deactiveert de huidige licentiesleutel via de Lemon Squeezy License API.
 * Gebruikt het /deactivate endpoint om de licentie-instance vrij te geven.
 * @returns {Promise<{success: boolean, error?: string}>}
 */
async function deactivateLicenseKey() {
    try {
        const data = await chrome.storage.sync.get(['licenseKey', 'licenseInstanceId']);

        if (!data.licenseKey || !data.licenseInstanceId) {
            return { success: false, error: 'Geen actieve licentie gevonden om te deactiveren.' };
        }

        // Lemon Squeezy License Deactivation API
        const response = await fetchWithTimeout('https://api.lemonsqueezy.com/v1/licenses/deactivate', {
            method: 'POST',
            headers: {
                'Accept': 'application/json',
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({
                license_key: data.licenseKey,
                instance_id: data.licenseInstanceId
            })
        }, 15000);

        const result = await response.json();

        if (globalThresholds.DEBUG_MODE) {
            console.log('[License] Lemon Squeezy deactivate response:', result);
        }

        if (result.deactivated === true || (result.meta && result.meta.store_id)) {
            // Deactivatie geslaagd - verwijder lokale licentiegegevens
            await chrome.storage.sync.remove(['licenseKey', 'licenseValid', 'licenseEmail', 'licenseInstanceId', 'lastLicenseValidation']);

            // Invalideer cache
            invalidateTrialCache();

            console.log('[License] Licentie succesvol gedeactiveerd');
            return { success: true };
        }

        // Check voor foutmeldingen
        if (result.error) {
            return { success: false, error: result.error };
        }

        return { success: false, error: 'Deactivatie mislukt. Probeer het opnieuw.' };

    } catch (error) {
        console.error('[License] Fout tijdens Lemon Squeezy deactivatie:', error);
        return { success: false, error: 'Netwerkfout tijdens deactivatie.' };
    }
}

/**
 * Revalidates stored license key in the background via Lemon Squeezy /validate endpoint
 *
 * SECURITY FIX v7.9.2: Verbeterde response handling
 * - Check response.ok VOOR JSON parsing (voorkomt dat HTTP 500 met JSON body als invalidatie wordt gezien)
 * - Retourneert explicitlyInvalidated flag wanneer server EXPLICIET zegt dat licentie ongeldig is
 *
 * @returns {Promise<{revalidated: boolean, valid?: boolean, networkError?: boolean, explicitlyInvalidated?: boolean}>}
 */
async function revalidateLicense() {
    try {
        const data = await chrome.storage.sync.get(['licenseKey', 'licenseValid', 'licenseInstanceId']);

        if (!data.licenseKey || !data.licenseValid) {
            return { revalidated: false, reason: 'No valid license to revalidate' };
        }



        try {
            // Lemon Squeezy License Validation API
            const response = await fetchWithTimeout('https://api.lemonsqueezy.com/v1/licenses/validate', {
                method: 'POST',
                headers: {
                    'Accept': 'application/json',
                    'Content-Type': 'application/json'
                },
                body: JSON.stringify({
                    license_key: data.licenseKey,
                    instance_id: data.licenseInstanceId || ''
                })
            }, API_TIMEOUT_MS);

            // SECURITY FIX Test 2: Check response.ok VOOR JSON parsing
            // Dit voorkomt dat HTTP 500 errors met JSON body als invalidatie worden behandeld
            if (!response.ok) {
                console.warn(`[License] Server returned HTTP ${response.status} - treating as network error`);
                return { revalidated: false, reason: `HTTP ${response.status}`, networkError: true };
            }

            const result = await response.json();

            // Lemon Squeezy retourneert valid: true en license_key.status moet 'active' zijn
            if (result.valid === true && result.license_key && result.license_key.status === 'active') {
                // License still valid - update timestamp EN lastSuccessfulValidation
                const now = Date.now();
                await chrome.storage.sync.set({
                    licenseValid: true,
                    licenseValidatedAt: now,
                    lastSuccessfulValidation: now // Grace period reset
                });

                // SECURITY FIX v8.7.0: Update lastKnownValid en deactiveer emergency mode
                if (EMERGENCY_MODE_ENABLED) {
                    await setLastKnownValid();
                    await deactivateEmergencyMode();
                }

                return { revalidated: true, valid: true };
            }

            // SECURITY FIX Test 4: Server zegt EXPLICIET dat licentie ongeldig is
            // Dit is GEEN fail-safe scenario - de server heeft definitief bevestigd dat de licentie niet geldig is
            // Markeer dit met explicitlyInvalidated flag zodat performStartupLicenseCheck dit kan onderscheiden
            await chrome.storage.sync.set({
                licenseValid: false,
                licenseValidatedAt: Date.now()
                // Let op: lastSuccessfulValidation wordt NIET bijgewerkt
            });

            if (globalThresholds.DEBUG_MODE) {
                console.log("[License] Server explicitly invalidated license:", result.license_key?.status || 'unknown status');
            }

            return {
                revalidated: true,
                valid: false,
                explicitlyInvalidated: true,  // CRITICAL: Dit signaleert dat FAIL_SAFE NIET van toepassing is
                reason: result.license_key?.status || 'invalid'
            };

        } catch (err) {
            console.error('[License] Error revalidating with Lemon Squeezy:', err);
            // SECURITY FIX v8.7.0: Bij netwerk error, activeer Emergency Mode
            // Bescherming blijft ALTIJD actief - Safe-by-Default
            if (EMERGENCY_MODE_ENABLED) {
                await activateEmergencyMode('network_timeout');
            }
            return { revalidated: false, reason: 'Network error', networkError: true, emergencyMode: true };
        }

    } catch (error) {
        // Storage error - don't change license status (fail-safe)
        console.error("[License] Revalidation storage error:", error);
        return { revalidated: false, reason: 'Storage error', storageError: true };
    }
}

// ==== Trial Period Management (constants defined earlier in file) ====

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

    // Als trial actief is, altijd toegestaan
    if (status.isActive) {
        return true;
    }

    // Als er een licentie is, check de grace period
    if (status.hasLicense) {
        const graceStatus = await checkLicenseGracePeriod();

        // Als grace period verlopen is, licentie is niet meer geldig
        if (graceStatus.expired) {
            if (globalThresholds.DEBUG_MODE) {
                console.log("[Security] Licentie grace period verlopen - achtergrondbeveiliging uitgeschakeld");
            }
            return false;
        }

        return true;
    }

    // Geen trial en geen licentie
    return false;
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

/**
 * Laadt SSL cache uit chrome.storage.local voor persistentie tussen sessies
 */
async function loadSslCacheFromStorage() {
    try {
        const { sslLabsCache } = await chrome.storage.local.get('sslLabsCache');
        if (sslLabsCache && typeof sslLabsCache === 'object') {
            const now = Date.now();
            let loadedCount = 0;
            for (const [domain, data] of Object.entries(sslLabsCache)) {
                // Alleen laden als cache nog geldig is
                const ttl = data.isError ? SSL_LABS_ERROR_CACHE_TTL : SSL_LABS_CACHE_TTL;
                if (now - data.timestamp < ttl) {
                    sslCache.set(domain, data);
                    loadedCount++;
                }
            }
            if (globalThresholds.DEBUG_MODE) {
                console.log(`[SSL Cache] ${loadedCount} entries geladen uit storage`);
            }
        }
    } catch (error) {
        console.error('[SSL Cache] Fout bij laden cache:', error);
    }
}

/**
 * Slaat SSL cache op in chrome.storage.local voor persistentie
 */
async function saveSslCacheToStorage() {
    try {
        const cacheObj = {};
        for (const [domain, data] of sslCache) {
            cacheObj[domain] = data;
        }
        await chrome.storage.local.set({ sslLabsCache: cacheObj });
    } catch (error) {
        console.error('[SSL Cache] Fout bij opslaan cache:', error);
    }
}

/**
 * Rate-limited SSL Labs API call
 * Wacht tot het veilig is om een request te doen
 *
 * SECURITY FIX v7.9.3: Rate limit state wordt gepersisteerd naar chrome.storage.session
 * Dit voorkomt dat de SW na suspend/restart de rate limit "vergeet" en API spam veroorzaakt
 *
 * @param {string} domain - Het domein om te checken
 * @returns {Promise<{isValid: boolean, reason: string}>}
 */
async function checkSslLabsWithRateLimit(domain) {
    const now = Date.now();
    const timeSinceLastRequest = now - sslLabsLastRequestTime;

    // Als we te snel zijn, wacht
    if (timeSinceLastRequest < SSL_LABS_MIN_INTERVAL_MS) {
        const waitTime = SSL_LABS_MIN_INTERVAL_MS - timeSinceLastRequest;
        if (globalThresholds.DEBUG_MODE) {
            console.log(`[SSL Labs] Rate limit: wacht ${waitTime}ms voor ${domain}`);
        }
        await new Promise(resolve => setTimeout(resolve, waitTime));
    }

    // Update timestamp VOOR de request (in-memory + persistent)
    const requestTimestamp = Date.now();
    sslLabsLastRequestTime = requestTimestamp;
    // SECURITY FIX v7.9.3: Persisteer naar storage.session (fire-and-forget, niet await)
    saveSslLabsRateLimitState(requestTimestamp);

    try {
        const response = await fetchWithTimeout(
            `https://api.ssllabs.com/api/v3/analyze?host=${domain}&fromCache=on&maxAge=86400`,
            { mode: 'cors' },
            API_TIMEOUT_MS
        );

        // Handle rate limit responses (429 en 529)
        if (response.status === 429 || response.status === 529) {
            if (globalThresholds.DEBUG_MODE) {
                console.warn(`[SSL Labs] Rate limit (${response.status}) voor ${domain}`);
            }
            const result = {
                isValid: true,
                reason: "SSL Labs overbelast, check overgeslagen",
                isError: true
            };
            sslCache.set(domain, { result, timestamp: Date.now(), isError: true });
            return result;
        }

        if (!response.ok) {
            throw new Error(`HTTP ${response.status}`);
        }

        const data = await response.json();

        if (data.status === "READY" && data.endpoints && data.endpoints.length > 0) {
            const allEndpointsFailed = data.endpoints.every(endpoint =>
                endpoint.statusMessage === "Unable to connect to the server"
            );
            if (allEndpointsFailed) {
                const result = { isValid: false, reason: "Server onbereikbaar voor SSL-analyse" };
                sslCache.set(domain, { result, timestamp: Date.now() });
                return result;
            }
            const grade = data.endpoints[0].grade || "Unknown";
            const isValid = ["A", "A+", "B", "C"].includes(grade);
            const result = {
                isValid,
                reason: isValid ? `Geldig certificaat (Grade: ${grade})` : `Onveilige SSL (Grade: ${grade})`
            };
            sslCache.set(domain, { result, timestamp: Date.now() });
            if (globalThresholds.DEBUG_MODE) {
                console.log(`[SSL Labs] Resultaat voor ${domain}: ${grade}`);
            }
            return result;
        } else if (data.status === "ERROR") {
            const result = {
                isValid: false,
                reason: `SSL Labs fout: ${data.statusMessage || "Onbekende fout"}`,
                isError: true
            };
            sslCache.set(domain, { result, timestamp: Date.now(), isError: true });
            return result;
        } else if (data.status === "IN_PROGRESS" || data.status === "DNS") {
            const result = { isValid: true, reason: "SSL-scan in uitvoering" };
            // Korte cache voor in-progress scans
            sslCache.set(domain, { result, timestamp: Date.now(), isError: true });
            return result;
        } else {
            const result = { isValid: true, reason: "SSL-status onbekend" };
            sslCache.set(domain, { result, timestamp: Date.now() });
            return result;
        }
    } catch (error) {
        if (globalThresholds.DEBUG_MODE) {
            console.error(`[SSL Labs] Fout voor ${domain}:`, error.message);
        }
        const result = {
            isValid: true,
            reason: "SSL-check kon niet worden uitgevoerd",
            isError: true
        };
        sslCache.set(domain, { result, timestamp: Date.now(), isError: true });
        return result;
    }
}

/** Checks SSL/TLS configuration using SSL Labs API with rate limiting */
async function checkSslLabs(domain) {
    if (globalThresholds.DEBUG_MODE) {
        console.log(`[checkSslLabs] Starting for ${domain}`);
    }

    // Check cache eerst
    const cached = sslCache.get(domain);
    if (cached) {
        const ttl = cached.isError ? SSL_LABS_ERROR_CACHE_TTL : SSL_LABS_CACHE_TTL;
        if (Date.now() - cached.timestamp < ttl) {
            if (globalThresholds.DEBUG_MODE) {
                console.log(`[checkSslLabs] Cache hit voor ${domain}`);
            }
            return cached.result;
        }
        // Cache verlopen, verwijder
        sslCache.delete(domain);
    }

    // Rate-limited API call
    const result = await checkSslLabsWithRateLimit(domain);

    // Periodiek cache opslaan (niet bij elke call)
    if (Math.random() < 0.1) { // 10% kans om op te slaan
        saveSslCacheToStorage();
    }

    return result;
}

// Laad cache bij startup
loadSslCacheFromStorage();

// MV3 FIX: Cache-schoonmaak via chrome.alarms (elke 30 minuten)
// setInterval werkt niet betrouwbaar in Service Workers - alarm wordt aangemaakt in onInstalled
// Handler: zie chrome.alarms.onAlarm listener voor "cleanSSLCache"

// v8.8.14: In-memory Set to prevent race conditions in blockMaliciousNavigation
const pendingBlockUrls = new Set();

// ==== Installation and Alarms ====

// v8.8.14: Startup cleanup for alarms (runs on every service worker start)
(async () => {
    try {
        const allAlarms = await chrome.alarms.getAll();
        // Keep only the important recurring alarms, clean up everything else
        const keepAlarms = ['fetchRulesHourly', 'license_revalidation_check', 'cleanSSLCache', 'clearAlertBadge', 'resetScanQuota'];
        const alarmsToClean = allAlarms.filter(a => !keepAlarms.includes(a.name));

        if (alarmsToClean.length > 0) {
            console.log(`[Alarms] Cleaning up ${alarmsToClean.length} old alarms...`);
            for (const alarm of alarmsToClean) {
                await chrome.alarms.clear(alarm.name);
            }
            console.log('[Alarms] Cleanup complete');
        }
    } catch (e) {
        console.warn('[Alarms] Startup cleanup error:', e);
    }
})();

chrome.runtime.onInstalled.addListener(async (details) => {
    try {
        if (details.reason === "install") {
            const defaultSettings = {
                backgroundSecurity: true,
                integratedProtection: true,
                // Stel ook de default thresholds in bij de eerste installatie
                // GESYNCHRONISEERD met config.js waarden (4/8/15)
                LOW_THRESHOLD: 4,
                MEDIUM_THRESHOLD: 8,
                HIGH_THRESHOLD: 15,
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
                title: safeGetMessage("installNotificationTitle") || "Extension Installed!",
                message: safeGetMessage("installNotificationMessage") || "Pin the extension to your toolbar for quick access. Click the extension icon and select 'Pin'. This icon will warn you when a site is unsafe.",
                priority: 2
            });
        }

        // Zorg ervoor dat thresholds geladen zijn voordat regels worden opgehaald
        await loadThresholdsFromStorage();
        await fetchAndLoadRules();
        await manageDNRules(); // Activeer/deactiveer regels op basis van initiële instellingen

        // v8.8.14: Clean up all existing alarms to prevent buildup (max 500 limit)
        // Then recreate only the necessary recurring alarms
        try {
            await chrome.alarms.clearAll();
            console.log("[Alarms] Cleared all existing alarms on install/update");
        } catch (e) {
            console.warn("[Alarms] Could not clear alarms:", e);
        }

        chrome.alarms.create("fetchRulesHourly", {
            periodInMinutes: 60
        });
        if (globalThresholds.DEBUG_MODE) console.log("Hourly rule fetch alarm created.");

        // Create license check alarm (every 12 hours = 720 minutes)
        // Verhoogde frequentie voor betere beveiliging tegen storage manipulatie
        chrome.alarms.create("license_revalidation_check", {
            periodInMinutes: 720
        });
        if (globalThresholds.DEBUG_MODE) console.log("License revalidation alarm created (12h interval).");

        // MV3 FIX: SSL cache cleanup alarm (every 30 minutes)
        // Vervangt setInterval die niet werkt in Service Workers
        chrome.alarms.create("cleanSSLCache", {
            periodInMinutes: 30
        });
        if (globalThresholds.DEBUG_MODE) console.log("SSL cache cleanup alarm created (30min interval).");

        // v8.4.0: Scan quota reset alarm (midnight UTC daily)
        // Calculates minutes until next midnight UTC
        const now = new Date();
        const nextMidnightUTC = new Date(Date.UTC(
            now.getUTCFullYear(),
            now.getUTCMonth(),
            now.getUTCDate() + 1,
            0, 0, 0, 0
        ));
        const minutesUntilReset = Math.ceil((nextMidnightUTC.getTime() - now.getTime()) / 60000);
        chrome.alarms.create("resetScanQuota", {
            delayInMinutes: minutesUntilReset,
            periodInMinutes: 24 * 60 // Repeat daily
        });
        if (globalThresholds.DEBUG_MODE) console.log(`Scan quota reset alarm created (next reset in ${minutesUntilReset} minutes).`);

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

    if (alarm.name === "license_revalidation_check") {
        if (globalThresholds.DEBUG_MODE) console.log("License revalidation alarm triggered (12h interval).");

        // v8.4.0: Automatic Protection is ALWAYS FREE
        // License revalidation only updates license status for quota purposes
        // It does NOT disable protection (backgroundSecurity stays unchanged)
        (async () => {
            try {
                const result = await revalidateLicense();

                // Update license validity status (affects quota, not protection)
                if (result.revalidated && !result.valid) {
                    await chrome.storage.sync.set({ licenseValid: false });
                    invalidateTrialCache();
                    if (globalThresholds.DEBUG_MODE) {
                        console.log("[Alarm] License marked invalid (only affects quota, not protection)");
                    }
                }

                // Always ensure DNR rules are active
                await manageDNRules();
            } catch (error) {
                console.error("[ERROR] Error in license revalidation alarm:", error.message);
                // Ensure protection stays active on error
                await manageDNRules();
            }
        })();
    }

    // MV3 FIX: SSL cache cleanup (replaces setInterval)
    if (alarm.name === "cleanSSLCache") {
        const now = Date.now();
        let cleanedCount = 0;
        for (const [domain, data] of sslCache) {
            const ttl = data.isError ? SSL_LABS_ERROR_CACHE_TTL : SSL_LABS_CACHE_TTL;
            if (now - data.timestamp >= ttl) {
                sslCache.delete(domain);
                cleanedCount++;
            }
        }
        if (cleanedCount > 0 && globalThresholds.DEBUG_MODE) {
            console.log(`[SSL Cache] ${cleanedCount} verlopen entries verwijderd`);
        }
        // Sla cache op
        saveSslCacheToStorage();
        if (globalThresholds.DEBUG_MODE) console.log("SSL cache cleanup completed via alarm.");
    }

    // v8.4.0: Scan quota daily reset
    if (alarm.name === "resetScanQuota") {
        await resetScanQuota();
        if (globalThresholds.DEBUG_MODE) console.log("[ScanQuota] Daily quota reset completed via alarm.");
    }

    // MV3 FIX: Clear alert badge after delay (replaces setInterval animation)
    if (alarm.name === "clearAlertBadge") {
        clearBadge();
        if (globalThresholds.DEBUG_MODE) console.log("Alert badge cleared via alarm.");
    }

    // SECURITY FIX v8.0.0 (Vector 3): Auto-cleanup voor Visual Hijacking block rules
    if (alarm.name.startsWith("cleanup_visual_hijack_")) {
        const ruleId = parseInt(alarm.name.replace("cleanup_visual_hijack_", ""), 10);

        (async () => {
            try {
                // Verwijder de DNR regel
                await chrome.declarativeNetRequest.updateDynamicRules({
                    removeRuleIds: [ruleId]
                });

                // Verwijder uit tracking
                const { visualHijackingRules = [] } = await chrome.storage.session.get('visualHijackingRules');
                const filtered = visualHijackingRules.filter(r => r.ruleId !== ruleId);
                await chrome.storage.session.set({ visualHijackingRules: filtered });

                if (globalThresholds.DEBUG_MODE) {
                    console.log(`[Visual Hijacking Protection] Auto-cleaned rule ${ruleId}`);
                }
            } catch (error) {
                console.error('[Visual Hijacking Protection] Cleanup error:', error);
            }
        })();
    }
});


// ==== Message Listener (Hoofdcommunicatie met Content Scripts) ====
// =================== SECURITY: Sender validatie toegevoegd ===================

/**
 * Valideert of de sender een vertrouwde bron is
 * @param {object} sender - Chrome message sender object
 * @returns {boolean} - true als sender vertrouwd is
 */
function isValidSender(sender) {
    // Accepteer berichten van:
    // 1. Extension zelf (popup, background, etc.)
    // 2. Content scripts van onze extensie (hebben sender.id)
    if (sender.id === chrome.runtime.id) {
        return true;
    }
    // Blokkeer berichten van onbekende bronnen
    return false;
}

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    // SECURITY: Valideer sender voordat we berichten verwerken
    if (!isValidSender(sender)) {
        console.error("[Security] Blocked message from untrusted sender:", sender.origin || sender.url);
        sendResponse({ error: 'Unauthorized sender', blocked: true });
        return false;
    }

    if (globalThresholds.DEBUG_MODE) {
        console.log(`[Background Script] Received message:`, request, sender);
    }

    switch (request.type || request.action) {

        case 'validateLicense':
            validateLicenseKey(request.licenseKey)
                .then(async (result) => {
                    // Invalideer cache bij succesvolle licentie activatie
                    if (result.success) {
                        invalidateTrialCache();
                        // v8.4.0: Enable both protection features when license is activated
                        await chrome.storage.sync.set({
                            backgroundSecurity: true,
                            integratedProtection: true
                        });
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

        case 'deactivateLicense':
            deactivateLicenseKey()
                .then(result => {
                    if (result.success) {
                        // Heractiveer achtergrondbeveiliging met nieuwe status (nu trial/free)
                        manageDNRules();
                    }
                    sendResponse(result);
                })
                .catch(error => {
                    console.error("[deactivateLicense] Error:", error);
                    sendResponse({ success: false, error: "License deactivation failed" });
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

        case 'checkGracePeriod':
            checkLicenseGracePeriod()
                .then(status => sendResponse(status))
                .catch(error => {
                    console.error("[checkGracePeriod] Error:", error);
                    sendResponse({ expired: false, daysSinceValidation: 0, graceRemaining: LICENSE_GRACE_PERIOD_DAYS });
                });
            return true;

        case 'forceRevalidation':
            // Forceer een online licentie validatie
            (async () => {
                try {
                    const result = await revalidateLicense();
                    if (result.revalidated) {
                        invalidateTrialCache();
                    }
                    sendResponse(result);
                } catch (error) {
                    console.error("[forceRevalidation] Error:", error);
                    sendResponse({ revalidated: false, error: error.message });
                }
            })();
            return true;

        case 'isPremiumActive':
            isPremiumActive()
                .then(isActive => sendResponse({ isPremium: isActive }))
                .catch(error => {
                    console.error("[isPremiumActive] Error:", error);
                    sendResponse({ isPremium: true });
                });
            return true;

        // v8.4.0: Scan Quota Management
        case 'getScanQuota':
            getScanQuotaStatus()
                .then(status => sendResponse(status))
                .catch(error => {
                    console.error("[getScanQuota] Error:", error);
                    sendResponse({ count: 0, limit: DAILY_SCAN_QUOTA, isUnlimited: true });
                });
            return true;

        case 'canScanDomain':
            canScanDomain(request.domain)
                .then(result => sendResponse(result))
                .catch(error => {
                    console.error("[canScanDomain] Error:", error);
                    sendResponse({ allowed: true, reason: 'error' });
                });
            return true;

        case 'recordDomainScan':
            recordDomainScan(request.domain)
                .then(result => sendResponse(result))
                .catch(error => {
                    console.error("[recordDomainScan] Error:", error);
                    sendResponse({ recorded: false });
                });
            return true;

        case 'checkUrl':
            sendResponse({ status: "not_implemented" });
            return true;

        case 'analyzeRedirectChain': {
            // Redirect Chain Analysis (v7.1) - Enhanced for QR code URLs
            const targetUrl = request.url;
            const source = request.source || 'unknown';

            // QR-code URLs worden ALTIJD geanalyseerd (AI-proxy redirect detectie)
            // Dit is cruciaal voor het ontmaskeren van AI-phishing redirects
            const isQRSource = source === 'table-qr' || source === 'image-qr' || source === 'qr' || source === 'ascii-qr';
            const shouldAnalyze = request.force || isQRSource || isKnownShortener(targetUrl) || request.level === 'caution';

            if (globalThresholds.DEBUG_MODE && isQRSource) {
                console.log(`[RedirectChain] QR-code URL detected (source: ${source}), forcing analysis: ${targetUrl}`);
            }

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

            // Langere timeout voor QR URLs (kunnen meer redirects hebben)
            const timeout = isQRSource ? 5000 : 3000;
            traceRedirectChain(targetUrl, timeout)
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
                    // v8.4.0: Removed trial check - Automatic Protection (icon badges) is ALWAYS FREE
                    // Only Smart Link Scanning has quota limits, not icon badge updates
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

            // Gebruik de centrale rate-limited checkSslLabs functie
            checkSslLabs(domain)
                .then(result => {
                    sendResponse(result);
                })
                .catch(error => {
                    console.error(`[checkSslLabs message] Fout voor ${domain}:`, error.message);
                    sendResponse({
                        isValid: true,
                        reason: 'SSL-check kon niet worden uitgevoerd'
                    });
                });

            return true; // houd port open voor async
        }
        // --- EINDE VAN DE VERNIEUWDE 'checkSslLabs' CASE ---

        case 'bitbDetected':
            // Browser-in-the-Browser (BitB) aanval gedetecteerd door content script
            if (globalThresholds.DEBUG_MODE) {
                console.log(`[BitB Detection] Attack detected on tab ${sender.tab?.id}:`, request.data);
            }

            // Toon alert badge op de extensie-icon voor deze tab
            if (sender.tab?.id) {
                chrome.action.setBadgeText({ text: '!', tabId: sender.tab.id });
                chrome.action.setBadgeBackgroundColor({ color: '#dc2626', tabId: sender.tab.id });
                chrome.action.setTitle({
                    title: safeGetMessage('bitbWarningTitle') || 'Fake Login Window Detected!',
                    tabId: sender.tab.id
                });

                // Log de aanval voor debugging/analytics
                console.warn(`[BitB Detection] BitB attack detected on ${sender.tab.url || 'unknown URL'}. Score: ${request.data?.score || 'N/A'}. Indicators: ${JSON.stringify(request.data?.indicators || [])}`);
            }

            sendResponse({ received: true, action: 'bitb_warning_shown' });
            return true;

        case 'webTransportDetected':
            // WebTransport/HTTP3 verdachte activiteit gedetecteerd door content script
            if (globalThresholds.DEBUG_MODE) {
                console.log(`[WebTransport] Suspicious activity on tab ${sender.tab?.id}:`, request.data);
            }

            // Update badge en icon gebaseerd op score
            if (sender.tab?.id && request.data?.score) {
                const score = request.data.score;

                if (score >= 10) {
                    // Hoge score = alert niveau
                    chrome.action.setBadgeText({ text: '!', tabId: sender.tab.id });
                    chrome.action.setBadgeBackgroundColor({ color: '#f59e0b', tabId: sender.tab.id }); // Amber/warning
                    chrome.action.setTitle({
                        title: safeGetMessage('webTransportWarningTitle') || 'Suspicious Network Activity Detected',
                        tabId: sender.tab.id
                    });

                    // Log de activiteit
                    console.warn(`[WebTransport] Suspicious activity on ${sender.tab.url || 'unknown URL'}. ` +
                        `Endpoint: ${request.data.endpointUrl || 'N/A'}. ` +
                        `Score: ${score}. ` +
                        `Reasons: ${JSON.stringify(request.data.reasons || [])}`);
                } else if (score >= 5) {
                    // Medium score = caution niveau
                    chrome.action.setBadgeText({ text: '?', tabId: sender.tab.id });
                    chrome.action.setBadgeBackgroundColor({ color: '#ffc107', tabId: sender.tab.id });
                }
            }

            sendResponse({ received: true, score: request.data?.score || 0 });
            return true;

        // =========================================================================
        // SECURITY FIX v8.0.0 (Vector 3): Network-level blocking voor Visual Hijacking
        // =========================================================================
        // Deze handler blokkeert navigatie naar gevaarlijke URLs op netwerk-niveau.
        // Dit voorkomt dat aanvallers via z-index/pointer-events manipulatie
        // gebruikers naar malicieuze sites kunnen leiden.
        case 'blockMaliciousNavigation': {
            const targetUrl = request.url;
            const reason = request.reason || 'visual_hijacking_protection';
            const tabId = sender.tab?.id;

            (async () => {
                try {
                    // v8.8.14: In-memory lock to prevent race conditions
                    if (pendingBlockUrls.has(targetUrl)) {
                        sendResponse({ blocked: true, alreadyPending: true });
                        return;
                    }
                    pendingBlockUrls.add(targetUrl);

                    // v8.8.14: Check if this URL is already blocked to prevent duplicates
                    const { visualHijackingRules = [] } = await chrome.storage.session.get('visualHijackingRules');
                    const existingRule = visualHijackingRules.find(r => r.url === targetUrl);
                    if (existingRule) {
                        // URL already blocked, return existing rule
                        pendingBlockUrls.delete(targetUrl);
                        sendResponse({ blocked: true, ruleId: existingRule.ruleId, alreadyBlocked: true });
                        return;
                    }

                    // Haal bestaande regel IDs op om duplicaten te voorkomen
                    const existingRules = await chrome.declarativeNetRequest.getDynamicRules();
                    const existingIds = new Set(existingRules.map(r => r.id));

                    // v8.8.14: Use crypto for better randomness to avoid race condition duplicates
                    // DNR regel IDs moeten positieve integers zijn, range 900000-999999
                    let ruleId;
                    let attempts = 0;
                    const maxAttempts = 1000;

                    do {
                        // Use crypto.getRandomValues for better randomness
                        const randomArray = new Uint32Array(1);
                        crypto.getRandomValues(randomArray);
                        ruleId = 900000 + (randomArray[0] % 100000);
                        attempts++;
                    } while (existingIds.has(ruleId) && attempts < maxAttempts);

                    if (attempts >= maxAttempts) {
                        throw new Error('Could not generate unique rule ID - too many active rules');
                    }

                    // Extraheer hostname voor URL filter
                    let urlFilter;
                    try {
                        const urlObj = new URL(targetUrl);
                        // Gebruik volledige URL voor specifieke blocking
                        urlFilter = targetUrl;
                    } catch (e) {
                        // Fallback naar ruwe URL als parsing faalt
                        urlFilter = targetUrl;
                    }

                    // Voeg tijdelijke DNR regel toe
                    await chrome.declarativeNetRequest.updateDynamicRules({
                        addRules: [{
                            id: ruleId,
                            priority: 1,
                            action: {
                                type: 'redirect',
                                redirect: {
                                    // Redirect naar onze blocked page met context
                                    extensionPath: `/alert.html?blocked=true&url=${encodeURIComponent(targetUrl)}&reason=${encodeURIComponent(reason)}`
                                }
                            },
                            condition: {
                                urlFilter: urlFilter,
                                resourceTypes: ['main_frame']
                            }
                        }]
                    });

                    if (globalThresholds.DEBUG_MODE) {
                        console.log(`[Visual Hijacking Protection] Blocked URL: ${targetUrl}, Rule ID: ${ruleId}`);
                    }

                    // Sla regel ID op voor cleanup tracking (reuse variable from earlier check)
                    visualHijackingRules.push({
                        ruleId,
                        url: targetUrl,
                        tabId,
                        createdAt: Date.now()
                    });
                    await chrome.storage.session.set({ visualHijackingRules });

                    // Schedule auto-cleanup na 5 minuten
                    // v8.8.14: Clear existing alarm first to prevent duplicates
                    const alarmName = `cleanup_visual_hijack_${ruleId}`;
                    chrome.alarms.clear(alarmName, () => {
                        chrome.alarms.create(alarmName, { delayInMinutes: 5 });
                    });

                    // v8.8.14: Remove from pending set after successful block
                    pendingBlockUrls.delete(targetUrl);
                    sendResponse({ blocked: true, ruleId });

                } catch (error) {
                    // v8.8.14: Always clean up pending set on error
                    pendingBlockUrls.delete(targetUrl);
                    console.error('[Visual Hijacking Protection] Error adding block rule:', error);
                    sendResponse({ blocked: false, error: error.message });
                }
            })();
            return true;
        }

        // Handler voor het verwijderen van visual hijacking block rules
        case 'unblockMaliciousNavigation': {
            const ruleId = request.ruleId;

            (async () => {
                try {
                    await chrome.declarativeNetRequest.updateDynamicRules({
                        removeRuleIds: [ruleId]
                    });

                    // Verwijder uit tracking
                    const { visualHijackingRules = [] } = await chrome.storage.session.get('visualHijackingRules');
                    const filtered = visualHijackingRules.filter(r => r.ruleId !== ruleId);
                    await chrome.storage.session.set({ visualHijackingRules: filtered });

                    sendResponse({ unblocked: true });
                } catch (error) {
                    console.error('[Visual Hijacking Protection] Error removing block rule:', error);
                    sendResponse({ unblocked: false, error: error.message });
                }
            })();
            return true;
        }

        // v8.8.13: CORS fallback for QR code scanning - fetch cross-origin images as data URL
        case 'fetchImageAsDataUrl': {
            const imageUrl = request.url;

            if (!imageUrl || typeof imageUrl !== 'string') {
                sendResponse({ success: false, error: 'Invalid URL' });
                return true;
            }

            // Security: Only allow http/https URLs
            if (!imageUrl.startsWith('http://') && !imageUrl.startsWith('https://')) {
                sendResponse({ success: false, error: 'Invalid protocol' });
                return true;
            }

            (async () => {
                try {
                    const response = await fetch(imageUrl, {
                        method: 'GET',
                        credentials: 'omit' // Don't send cookies for privacy
                    });

                    if (!response.ok) {
                        sendResponse({ success: false, error: `HTTP ${response.status}` });
                        return;
                    }

                    const contentType = response.headers.get('content-type') || 'image/png';

                    // Security: Only allow image content types
                    if (!contentType.startsWith('image/')) {
                        sendResponse({ success: false, error: 'Not an image' });
                        return;
                    }

                    const blob = await response.blob();
                    const reader = new FileReader();

                    reader.onloadend = () => {
                        sendResponse({ success: true, dataUrl: reader.result });
                    };

                    reader.onerror = () => {
                        sendResponse({ success: false, error: 'Failed to read image' });
                    };

                    reader.readAsDataURL(blob);
                } catch (error) {
                    sendResponse({ success: false, error: error.message || 'Failed to fetch' });
                }
            })();
            return true;
        }

        // v8.8.14: RDAP fetch via background to avoid CORS issues in content script
        case 'fetchRdapData': {
            const domain = request.domain;

            if (!domain || typeof domain !== 'string') {
                sendResponse({ success: false, error: 'Invalid domain' });
                return true;
            }

            (async () => {
                try {
                    const response = await fetch(`https://rdap.org/domain/${domain}`, {
                        method: 'GET',
                        headers: { 'Accept': 'application/json' }
                    });

                    if (response.status === 404) {
                        sendResponse({ success: true, data: null, notFound: true });
                        return;
                    }

                    if (!response.ok) {
                        sendResponse({ success: false, error: `HTTP ${response.status}` });
                        return;
                    }

                    const data = await response.json();
                    sendResponse({ success: true, data });
                } catch (error) {
                    sendResponse({ success: false, error: error.message || 'Failed to fetch RDAP' });
                }
            })();
            return true;
        }

        case 'formHijackingDetected':
            // Update icon naar rood
            chrome.action.setIcon({
                path: {
                    16: 'icons/red-circle-16.png',
                    48: 'icons/red-circle-48.png',
                    128: 'icons/red-circle-128.png'
                },
                tabId: sender.tab?.id
            }).catch(() => {});

            // Log voor debugging
            console.log('[LinkShield] Form hijacking detected:', request.data);

            sendResponse({ success: true });
            break;

        // =====================================================================
        // SECURITY FIX v8.5.0: Advanced Threat Detection message handlers
        // =====================================================================

        case 'oauthTheftAttempt':
            if (globalThresholds.DEBUG_MODE) {
                console.log('[LinkShield] OAuth theft attempt blocked:', request);
            }
            // Optioneel: sla op voor statistieken
            incrementBlockedThreatsCount('oauth_theft');
            // Update icon naar rood voor kritieke bedreiging
            chrome.action.setIcon({
                path: {
                    16: 'icons/red-circle-16.png',
                    48: 'icons/red-circle-48.png',
                    128: 'icons/red-circle-128.png'
                },
                tabId: sender.tab?.id
            }).catch(() => {});
            sendResponse({ success: true });
            break;

        case 'fakeTurnstileDetected':
            if (globalThresholds.DEBUG_MODE) {
                console.log('[LinkShield] Fake Turnstile detected:', request);
            }
            incrementBlockedThreatsCount('fake_turnstile');
            // Update icon naar oranje voor waarschuwing
            chrome.action.setIcon({
                path: {
                    16: 'icons/orange-circle-16.png',
                    48: 'icons/orange-circle-48.png',
                    128: 'icons/orange-circle-128.png'
                },
                tabId: sender.tab?.id
            }).catch(() => {});
            sendResponse({ success: true });
            break;

        case 'splitQRDetected':
            if (globalThresholds.DEBUG_MODE) {
                console.log('[LinkShield] Split QR detected:', request);
            }
            incrementBlockedThreatsCount('split_qr');
            // Optioneel: check de QR URL tegen reputatie API
            if (request.qrUrl) {
                checkUrlReputation(request.qrUrl).then(result => {
                    if (result && result.malicious) {
                        // Update badge of notificatie
                        chrome.action.setBadgeText({ text: '!', tabId: sender.tab?.id }).catch(() => {});
                        chrome.action.setBadgeBackgroundColor({ color: '#dc2626', tabId: sender.tab?.id }).catch(() => {});
                    }
                }).catch(() => {});
            }
            sendResponse({ success: true });
            break;

        case 'aitmProxyDetected':
            if (globalThresholds.DEBUG_MODE) {
                console.log('[LinkShield] AiTM Proxy detected:', request);
            }
            incrementBlockedThreatsCount('aitm_proxy');
            // Update icon naar rood (critical)
            chrome.action.setIcon({
                path: {
                    16: 'icons/red-circle-16.png',
                    48: 'icons/red-circle-48.png',
                    128: 'icons/red-circle-128.png'
                },
                tabId: sender.tab?.id
            }).catch(() => {});
            chrome.action.setBadgeText({ text: '!', tabId: sender.tab?.id }).catch(() => {});
            chrome.action.setBadgeBackgroundColor({ color: '#dc2626', tabId: sender.tab?.id }).catch(() => {});
            sendResponse({ success: true });
            break;

        case 'svgPayloadDetected':
            if (globalThresholds.DEBUG_MODE) {
                console.log('[LinkShield] SVG Payload detected:', request);
            }
            incrementBlockedThreatsCount('svg_payload');
            // Update icon naar rood (critical)
            chrome.action.setIcon({
                path: {
                    16: 'icons/red-circle-16.png',
                    48: 'icons/red-circle-48.png',
                    128: 'icons/red-circle-128.png'
                },
                tabId: sender.tab?.id
            }).catch(() => {});
            sendResponse({ success: true });
            break;

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
    try {
        // Reageer alleen als de URL daadwerkelijk is veranderd (en het een volledige URL is)
        if (changeInfo.url && tab?.url && tab.url.startsWith('http')) {
            stopIconAnimation(); // Stop animatie bij navigatie
            await resetCurrentSiteStatus(); // Reset de opgeslagen status voor de nieuwe URL
            resetIconToNeutral(); // Zet icoon naar neutraal (groen)
        }
    } catch (error) {
        console.error("[ERROR] chrome.tabs.onUpdated error:", error);
    }
});

chrome.tabs.onActivated.addListener(async ({ tabId }) => {
    try {
        stopIconAnimation(); // Stop animatie bij tab-switch
        await resetCurrentSiteStatus(); // Reset de opgeslagen status
        resetIconToNeutral(); // Zet icoon naar neutraal (groen)
    } catch (error) {
        console.error("[ERROR] chrome.tabs.onActivated error:", error);
    }
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
    try {
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

                // v8.4.0: Automatic Protection is ALWAYS FREE - no license check needed
                // Just update DNR rules and refresh if license becomes valid
                await manageDNRules();

                // Als licentie nu geldig is (was ongeldig), herlaad regels
                if ('licenseValid' in changes && changes.licenseValid.newValue === true) {
                    await fetchAndLoadRules();
                }

                // v8.4.0: Removed rule clearing on trial expiry - protection stays active
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
    } catch (error) {
        console.error("[ERROR] chrome.storage.onChanged error:", error);
    }
});



chrome.runtime.onStartup.addListener(async () => {
    try {
        // PERFORMANCE FIX v8.1.0: Initialize protection IMMEDIATELY (non-blocking)
        await initializeProtectionImmediately();
        await restoreIconState();

        // Run license validation in BACKGROUND (don't await - non-blocking)
        performStartupLicenseCheck().catch(err =>
            console.error("[INIT] Background license check failed:", err)
        );
    } catch (error) {
        console.error("[ERROR] chrome.runtime.onStartup error:", error);
    }
});

chrome.runtime.onInstalled.addListener(async (details) => {
    try {
        if (details.reason === "install" || details.reason === "update") {
            // PERFORMANCE FIX v8.1.0: Initialize protection IMMEDIATELY
            await initializeProtectionImmediately();
            await restoreIconState();

            // Run license validation in BACKGROUND (don't await)
            performStartupLicenseCheck().catch(err =>
                console.error("[INIT] Background license check failed:", err)
            );
        }
    } catch (error) {
        console.error("[ERROR] chrome.runtime.onInstalled (second) error:", error);
    }
});

// PERFORMANCE FIX v8.1.0: Initialize protection immediately when service worker starts
// This is the fastest path - protection is active within milliseconds
initializeProtectionImmediately().then(result => {
    console.log("[INIT] Immediate initialization complete:", result);
}).catch(err => {
    console.error("[INIT] Immediate initialization failed:", err);
});

// Run full license validation after 2 seconds (background, non-blocking)
setTimeout(() => {
    performStartupLicenseCheck().catch(err =>
        console.error("[INIT] Delayed license check failed:", err)
    );
}, 2000);

