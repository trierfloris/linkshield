/**
 * SECURITY FIX v8.7.0: Emergency Mode - Safe-by-Default License Logic
 *
 * Changes:
 * 1. Add EMERGENCY_MODE constant
 * 2. Implement lastKnownValid timestamp in chrome.storage.local
 * 3. Protection ALWAYS remains active on server timeout
 * 4. Add emergency mode notification
 */

const fs = require('fs');
const path = require('path');

const bgPath = path.join(__dirname, '..', 'background.js');
let content = fs.readFileSync(bgPath, 'utf8');
content = content.replace(/\r\n/g, '\n');

// 1. Add Emergency Mode constants after FAIL_SAFE_MODE
const oldConstants = `// ==== SECURITY FIX: Fail-Safe Mode ====
// Bij licentie-validatie fouten: BEHOUD bestaande bescherming in plaats van uitschakelen
// Dit voorkomt dat een aanvaller via DDoS op de licentieserver alle gebruikers kan "ontwapenen"
const FAIL_SAFE_MODE = true;`;

const newConstants = `// ==== SECURITY FIX: Fail-Safe Mode ====
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
            title: chrome.i18n.getMessage('emergencyModeTitle') || 'Emergency Protection Mode',
            message: chrome.i18n.getMessage('emergencyModeMessage') ||
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
}`;

if (content.includes(oldConstants)) {
    content = content.replace(oldConstants, newConstants);
    console.log('SUCCESS: Added Emergency Mode constants and functions');
} else {
    console.log('ERROR: Could not find FAIL_SAFE_MODE constant');
}

// 2. Modify revalidateLicense to use Emergency Mode
const oldRevalidateSuccess = `            // License still valid - update timestamp EN lastSuccessfulValidation
                const now = Date.now();
                await chrome.storage.sync.set({
                    licenseValid: true,
                    licenseValidatedAt: now,
                    lastSuccessfulValidation: now // Grace period reset
                });
                return { revalidated: true, valid: true };`;

const newRevalidateSuccess = `            // License still valid - update timestamp EN lastSuccessfulValidation
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

                return { revalidated: true, valid: true };`;

if (content.includes(oldRevalidateSuccess)) {
    content = content.replace(oldRevalidateSuccess, newRevalidateSuccess);
    console.log('SUCCESS: Updated revalidateLicense success path');
} else {
    console.log('WARNING: Could not find revalidateLicense success path');
}

// 3. Modify network error handling to activate Emergency Mode
const oldNetworkError = `            // SECURITY FIX: Bij netwerk error, update NIET lastSuccessfulValidation
            // De grace period blijft doorlopen - na 7 dagen zonder succesvolle check
            // wordt de licentie automatisch ongeldig
            // Dit voorkomt dat iemand offline blijft om validatie te ontwijken
            return { revalidated: false, reason: 'Network error', networkError: true };`;

const newNetworkError = `            // SECURITY FIX v8.7.0: Bij netwerk error, activeer Emergency Mode
            // Bescherming blijft ALTIJD actief - Safe-by-Default
            if (EMERGENCY_MODE_ENABLED) {
                await activateEmergencyMode('network_timeout');
            }
            return { revalidated: false, reason: 'Network error', networkError: true, emergencyMode: true };`;

if (content.includes(oldNetworkError)) {
    content = content.replace(oldNetworkError, newNetworkError);
    console.log('SUCCESS: Updated network error handling with Emergency Mode');
} else {
    console.log('WARNING: Could not find network error handling');
}

// 4. Modify performStartupLicenseCheck to always enable protection in Emergency Mode
const oldStartupNetworkError = `                if (result.networkError && FAIL_SAFE_MODE) {
                    // Netwerk error + FAIL_SAFE: behoud bescherming, toon waarschuwing
                    console.warn("[INIT] Revalidatie gefaald door netwerk - FAIL_SAFE mode actief, bescherming behouden");
                    await showFailSafeNotification('network_error');
                    // SECURITY FIX v8.0.0: ALTIJD manageDNRules() aanroepen om rulesets te activeren!
                    await manageDNRules();
                    return;
                }`;

const newStartupNetworkError = `                if (result.networkError) {
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
                }`;

if (content.includes(oldStartupNetworkError)) {
    content = content.replace(oldStartupNetworkError, newStartupNetworkError);
    console.log('SUCCESS: Updated startup network error handling');
} else {
    console.log('WARNING: Could not find startup network error handling');
}

// 5. Add Emergency Mode check at very start of initializeProtectionImmediately
const oldInitProtection = `async function initializeProtectionImmediately() {
    const startTime = Date.now();
    try {
        // Read cached status - this is fast (local storage)
        const data = await chrome.storage.sync.get([
            'licenseValid',
            'trialStartDate',
            'backgroundSecurity'
        ]);`;

const newInitProtection = `async function initializeProtectionImmediately() {
    const startTime = Date.now();
    try {
        // SECURITY FIX v8.7.0: Check Emergency Mode status FIRST
        // Als Emergency Mode actief is, bescherming ALTIJD inschakelen
        if (EMERGENCY_MODE_ENABLED) {
            const emergencyStatus = await getEmergencyModeStatus();
            if (emergencyStatus.isEmergencyMode) {
                console.warn('[INIT-FAST] Emergency Mode active - enabling protection unconditionally');
                await manageDNRules();
                return { initialized: true, emergencyMode: true, timeMs: Date.now() - startTime };
            }
        }

        // Read cached status - this is fast (local storage)
        const data = await chrome.storage.sync.get([
            'licenseValid',
            'trialStartDate',
            'backgroundSecurity'
        ]);`;

if (content.includes(oldInitProtection)) {
    content = content.replace(oldInitProtection, newInitProtection);
    console.log('SUCCESS: Added Emergency Mode check to initializeProtectionImmediately');
} else {
    console.log('WARNING: Could not find initializeProtectionImmediately');
}

// Write the file
content = content.replace(/\n/g, '\r\n');
fs.writeFileSync(bgPath, content, 'utf8');
console.log('\nDONE: Emergency Mode implementation complete');
