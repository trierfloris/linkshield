
const IS_PRODUCTION = true; // Zorg dat dit op 'true' staat wanneer je de extensie voor productie compileert/verpakt.
                           // Zet dit op 'false' tijdens ontwikkeling om alle console-meldingen te zien.

// Overschrijf console-functies voor productieomgeving
if (IS_PRODUCTION) {
    console.log = function() {};
    console.warn = function() {};
    console.info = function() {};
    // console.error blijft intact, zodat je fouten kunt blijven loggen in productie
}


// --- Rule Management and Fetching ---

let isUpdatingRules = false; // Debounce flag to prevent overlapping updates
let lastUpdate = 0; // Timestamp of the last update for additional control

/** Manages the enabling/disabling of declarativeNetRequest rulesets based on settings */
async function manageDNRules() {
    try {
        const { backgroundSecurity } = await chrome.storage.sync.get('backgroundSecurity');
        if (backgroundSecurity) {
            await chrome.declarativeNetRequest.updateEnabledRulesets({
                enableRulesetIds: ["ruleset_1"]
            });
        } else {
            await chrome.declarativeNetRequest.updateEnabledRulesets({
                disableRulesetIds: ["ruleset_1"]
            });
        }
    } catch (error) {
        console.error("Error managing DNR rules:", error);
    }
}

/** Fetches and loads dynamic rules from a remote source */
async function fetchAndLoadRules() {
    if (isUpdatingRules) return;
    isUpdatingRules = true;

    const HARDCODED_WHITELIST = [
        "accounts.google.com",
        "mail.google.com",
        "drive.google.com",
        "docs.google.com",
        "calendar.google.com",
        "apis.google.com",
        "oauth2.googleapis.com",
        "www.googleapis.com",
        "storage.googleapis.com",
        "fonts.googleapis.com",
        "fonts.gstatic.com",
        "www.google.com",
        "translate.google.com",
        "chrome.google.com",
        "clients1.google.com",
        "ssl.gstatic.com",
        "lh3.googleusercontent.com",
        "google.com", // fallback voor wildcard
        // Andere kritieke providers:
        "microsoftonline.com",
        "login.microsoft.com",
        "outlook.live.com",
        "apple.com"
    ];


    function isWhitelisted(urlFilter) {
        return HARDCODED_WHITELIST.some(domain => urlFilter.includes(domain));
    }

    try {
        const { backgroundSecurity } = await chrome.storage.sync.get('backgroundSecurity');
        if (!backgroundSecurity) {
            await clearDynamicRules();
            return;
        }

        const rulesResponse = await fetchWithRetry('https://linkshield.nl/files/rules.json');
        if (!rulesResponse.ok) {
            throw new Error(`Failed to fetch rules: ${rulesResponse.status}`);
        }

        const newRules = await rulesResponse.json();
        if (!Array.isArray(newRules) || newRules.length === 0) {
            throw new Error("Invalid or empty rules");
        }

        // Stap 1: Verwijder bestaande regels in batches
        let remainingRules = await chrome.declarativeNetRequest.getDynamicRules();
        while (remainingRules.length > 0) {
            const batch = remainingRules.slice(0, 500).map(rule => rule.id);
            await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: batch });
            await new Promise(resolve => setTimeout(resolve, 200));
            remainingRules = await chrome.declarativeNetRequest.getDynamicRules();
        }

        // Stap 2: Forceer reset met tijdelijke regel
        await chrome.declarativeNetRequest.updateDynamicRules({
            addRules: [{
                id: 1,
                priority: 1,
                action: { type: 'allow' },
                condition: { resourceTypes: ['main_frame'] }
            }]
        });
        await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: [1] });

        // Stap 3: Filter regels met whitelistcheck en unieke ID’s
        const { lastCounter = 1000000 } = await chrome.storage.local.get('lastCounter');
        let counter = Math.max(1000000, Math.floor(lastCounter));
        const validDynamicRules = [];
        const seenIds = new Set();

        for (const rule of newRules) {
            if (!rule.condition?.urlFilter || !rule.action || typeof rule.priority !== 'number') {
                continue;
            }

            if (isWhitelisted(rule.condition.urlFilter)) {
                console.warn(`[WHITELIST] Overslaan van regel met domein: ${rule.condition.urlFilter}`); // Deze wordt uitgeschakeld in productie
                continue;
            }

            const ruleId = Math.floor(counter++);
            if (!Number.isInteger(ruleId)) {
                throw new Error(`[ERROR] Rule ID is not an integer: ${ruleId}`);
            }
            if (seenIds.has(ruleId)) continue;
            seenIds.add(ruleId);

            validDynamicRules.push({
                id: ruleId,
                priority: rule.priority,
                action: rule.action,
                condition: {
                    urlFilter: rule.condition.urlFilter,
                    resourceTypes: rule.condition.resourceTypes || ['main_frame'],
                },
            });
        }

        if (validDynamicRules.length === 0) {
            throw new Error("No valid rules after filtering");
        }

        // Stap 4: Voeg nieuwe regels toe in batches
        const addBatchSize = 1000;
        for (let i = 0; i < validDynamicRules.length; i += addBatchSize) {
            const batch = validDynamicRules.slice(i, i + addBatchSize);
            await chrome.declarativeNetRequest.updateDynamicRules({ addRules: batch });
            await new Promise(resolve => setTimeout(resolve, 200));
        }

        await chrome.storage.local.set({ lastCounter: counter });
        await updateLastRuleUpdate();
    } catch (error) {
        console.error("[ERROR] fetchAndLoadRules:", error.message); // Deze blijft zichtbaar
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
}

/** Updates the timestamp of the last rule update */
async function updateLastRuleUpdate() {
    const now = new Date().toISOString();
    try {
        await chrome.storage.local.set({ lastRuleUpdate: now });
    } catch (error) {
        console.error('[ERROR] Error saving lastRuleUpdate:', error.message); // Deze blijft zichtbaar
    }
}

/** Fetches a URL with retry logic */
async function fetchWithRetry(url, options, maxRetries = 3, retryDelay = 1000) {
    for (let attempt = 1; attempt <= maxRetries; attempt++) {
        try {
            const response = await fetch(url, options);
            if (response.status === 404) {
                return response;
            }
            if (!response.ok) {
                throw new Error(`HTTP error, status = ${response.status}`);
            }
            return response;
        } catch (error) {
            if (attempt < maxRetries) {
                await new Promise(r => setTimeout(r, retryDelay));
            } else {
                throw error;
            }
        }
    }
}

// --- License Validation ---

/** Validates a license key against Gumroad API */
async function validateLicenseKey(licenseKey) {
    try {
        const response = await fetchWithRetry('https://api.gumroad.com/v2/licenses/verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ product_id: 'iiiJel9dwJ9Vj6GVgU_T4w==', license_key: licenseKey })
        });

        if (!response.ok) {
            throw new Error(`Server returned error: ${response.status}`);
        }

        const result = await response.json();
        return result.success && result.purchase.license_key === licenseKey;
    } catch (error) {
        // Hier kan je een console.error toevoegen als de validatie faalt
        // console.error("License validation failed:", error);
        return false;
    }
}

// --- Suspicious Link Handling ---

/** Adds a URL to the list of suspicious URLs */
async function handleSuspiciousLink(url) {
    try {
        const { suspiciousUrls = [] } = await chrome.storage.sync.get('suspiciousUrls');
        const urls = new Set(suspiciousUrls);
        if (!urls.has(url)) {
            urls.add(url);
            await chrome.storage.sync.set({ suspiciousUrls: Array.from(urls) });
        }
    } catch (error) {
        console.error("[ERROR] handleSuspiciousLink:", error.message); // Deze blijft zichtbaar
    }
}

// --- SSL Labs Check ---

const sslCache = new Map();

/** Checks SSL/TLS configuration using SSL Labs API */
async function checkSslLabs(domain) {
    // console.log(`[checkSslLabs] Starting for ${domain}`); // Deze wordt uitgeschakeld in productie
    try {
        const cachedSsl = sslCache.get(domain);
        if (cachedSsl && Date.now() - cachedSsl.timestamp < 24 * 60 * 60 * 1000) {
            // console.log(`[checkSslLabs] Cache hit voor ${domain}`); // Deze wordt uitgeschakeld in productie
            return cachedSsl.result;
        }

        // console.log(`[checkSslLabs] Fetching SSL data for ${domain}`); // Deze wordt uitgeschakeld in productie
        const response = await fetchWithRetry(
            `https://api.ssllabs.com/api/v3/analyze?host=${domain}&maxAge=86400`,
            { mode: 'cors' }
        );

        // console.log(`[checkSslLabs] Response status for ${domain}: ${response.status}`); // Deze wordt uitgeschakeld in productie
        if (response.status === 429) {
            // console.log(`[checkSslLabs] Rate limit bereikt voor ${domain}`); // Deze wordt uitgeschakeld in productie
            return { isValid: true, reason: "Rate limit, SSL-check overgeslagen" };
        }

        if (!response.ok) {
            throw new Error(`HTTP-fout: ${response.status}`); // Dit triggert de catch-blok
        }

        const data = await response.json();
        // console.log(`[checkSslLabs] Full response data for ${domain}:`, JSON.stringify(data)); // Deze wordt uitgeschakeld in productie

        if (data.status === "READY" && data.endpoints && data.endpoints.length > 0) {
            const allEndpointsFailed = data.endpoints.every(endpoint =>
                endpoint.statusMessage === "Unable to connect to the server"
            );
            if (allEndpointsFailed) {
                // console.log(`[checkSslLabs] Alle endpoints onbereikbaar voor ${domain}`); // Deze wordt uitgeschakeld in productie
                return { isValid: false, reason: "Server onbereikbaar voor SSL-analyse" };
            }
            const grade = data.endpoints[0].grade || "Unknown";
            const isValid = ["A", "A+"].includes(grade);
            const result = {
                isValid,
                reason: isValid ? "Geldig certificaat" : `Onveilige SSL (grade: ${grade})`
            };
            sslCache.set(domain, { result, timestamp: Date.now() });
            // console.log(`[checkSslLabs] Resultaat voor ${domain}: ${grade}`); // Deze wordt uitgeschakeld in productie
            return result;
        } else if (data.status === "ERROR") {
            // console.log(`[checkSslLabs] SSL Labs fout voor ${domain}: ${data.statusMessage}`); // Deze wordt uitgeschakeld in productie
            return { isValid: false, reason: `SSL Labs fout: ${data.statusMessage || "Onbekende fout"}` };
        } else if (data.status === "IN_PROGRESS" || !data.endpoints || data.endpoints.length === 0) {
            // console.log(`[checkSslLabs] SSL-scan niet voltooid of geen endpoints voor ${domain}`); // Deze wordt uitgeschakeld in productie
            return { isValid: true, reason: "SSL-scan in uitvoering, nog geen resultaat" };
        } else {
            // console.log(`[checkSslLabs] Onverwachte respons voor ${domain}`); // Deze wordt uitgeschakeld in productie
            return { isValid: false, reason: "Onverwachte SSL Labs respons" };
        }
    } catch (error) {
        console.error(`[checkSslLabs] Fout bij SSL-check voor ${domain}:`, error); // Deze blijft zichtbaar
        if (error.message.includes("network") || error.message.includes("fetch") || error.message.includes("429")) {
            // console.log(`[checkSslLabs] Netwerkfout of rate limit, fallback gebruikt voor ${domain}`); // Deze wordt uitgeschakeld in productie
            return { isValid: true, reason: "Netwerkfout of rate limit, SSL-check overgeslagen" };
        }
        return { isValid: false, reason: `SSL-check mislukt: ${error.message}` };
    }
}
// Cache-schoonmaak voor sslCache
setInterval(() => {
    const now = Date.now();
    for (const [domain, { timestamp }] of sslCache) {
        if (now - timestamp >= 24 * 60 * 60 * 1000) {
            sslCache.delete(domain);
            // console.log(`[DEBUG] Verwijderd verlopen SSL-cache voor ${domain}`); // Deze wordt uitgeschakeld in productie
        }
    }
}, 24 * 60 * 60 * 1000); // Elke 24 uur

// --- Installation and Alarms ---

chrome.runtime.onInstalled.addListener(async (details) => {
    try {
        if (details.reason === "install") {
            const defaultSettings = {
                backgroundSecurity: true,
                integratedProtection: true
            };

            await chrome.storage.sync.set(defaultSettings);

            chrome.tabs.create({ url: "https://linkshield.nl/#install" });

            chrome.notifications.create("pinReminder", {
                type: "basic",
                iconUrl: "icons/icon128.png",
                title: "Extension Installed!",
                message: "Pin the extension to your toolbar for quick access. Click the extension icon and select 'Pin'. This icon will alert you if a site is unsafe.",
                priority: 2
            });
        }

        await fetchAndLoadRules();

        chrome.alarms.create("fetchRulesHourly", {
            periodInMinutes: 60
        });
    } catch (error) {
        console.error("Error during extension installation or update:", error); // Deze blijft zichtbaar
    }
});

chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === "fetchRulesHourly") {
        fetchAndLoadRules().catch(error => {
            console.error("[ERROR] Error fetching rules via alarm:", error.message); // Deze blijft zichtbaar
        });
    }
});

// --- Message Listener ---

chrome.runtime.onMessage.addListener((request, sender, sendResponse) => {
    // --- DEBUG LOG START ---
    console.log(`[Background Script] Received message:`, request); // Deze wordt uitgeschakeld in productie
    console.log(`[Background Script] Sender:`, sender); // Deze wordt uitgeschakeld in productie
    // --- DEBUG LOG END ---

    switch (request.type || request.action) {
        case 'validateLicense':
            validateLicenseKey(request.licenseKey)
                .then(result => sendResponse({ success: result }))
                .catch(error => {
                    console.error("[validateLicense] Error:", error); // Deze blijft zichtbaar
                    sendResponse({ success: false, error: "License validation failed" });
                });
            return true;

        case 'checkUrl':
            sendResponse({ status: "not_implemented" });
            return true;

        case 'checkResult':
            const { url, isSafe, reasons, risk } = request; // Destructure all properties

            // --- DEBUG LOG START ---
            // Log de extractie van redenen hier
            console.log(`[Background Script] Processing checkResult for URL: ${url}`); // Deze wordt uitgeschakeld in productie
            console.log(`[Background Script] Reasons extracted from message:`, reasons); // Deze wordt uitgeschakeld in productie
            console.log(`[Background Script] Risk extracted from message:`, risk); // Deze wordt uitgeschakeld in productie
            // --- DEBUG LOG END ---

            chrome.storage.sync.get(['integratedProtection'])
                .then(settings => {
                    if (!settings.integratedProtection) {
                        sendResponse({ status: 'skipped' });
                    } else {
                        const statusToStore = {
                            url,
                            isSafe,
                            risk: Number(risk), // Zorg ervoor dat risico een nummer is
                            reasons: Array.isArray(reasons) ? reasons : [] // Zorg dat het een array is
                        };

                        // --- DEBUG LOG START ---
                        // Log het object dat naar chrome.storage.local wordt gestuurd
                        console.log(`[Background Script] Storing in chrome.storage.local:`, statusToStore); // Deze wordt uitgeschakeld in productie
                        // --- DEBUG LOG END ---

                        chrome.storage.local.set({ currentSiteStatus: statusToStore })
                            .then(() => {
                                console.log(`[Background Script] Successfully saved status for ${url}`); // Deze wordt uitgeschakeld in productie
                                // updateIconBasedOnSafety is al verplaatst om te reageren op storage changes.
                                // Deze wordt nu niet meer hier aangeroepen.
                                sendResponse({ status: 'received' });
                            })
                            .catch(error => {
                                console.error(`[Background Script] Error saving status to local storage:`, error); // Deze blijft zichtbaar
                                sendResponse({ status: 'error', error: error.message });
                            });
                    }
                })
                .catch(error => {
                    console.error("[checkResult] Storage settings error:", error); // Deze blijft zichtbaar
                    sendResponse({ status: 'error', error: "Storage settings error" });
                });
            return true; // Moet `true` retourneren voor asynchrone sendResponse

        case 'getStatus':
            chrome.storage.local.get("currentSiteStatus")
                .then(({ currentSiteStatus }) => {
                    sendResponse(currentSiteStatus || { isSafe: null, reasons: ["No status found"], url: null });
                })
                .catch(error => {
                    console.error("[getStatus] Error:", error); // Deze blijft zichtbaar
                    sendResponse({ isSafe: null, reasons: ["Storage error"], url: null });
                });
            return true;

        case 'alert':
            chrome.notifications.create({
                type: 'basic',
                iconUrl: 'icons/icon128.png',
                title: 'Warning',
                message: request.message || 'This page contains suspicious links!',
                priority: 2
            });
            sendResponse({ status: 'alert_shown' });
            return true;

        case 'checkSslLabs':
            // console.log("[Background] Starting SSL check for domain:", request.domain); // Deze wordt uitgeschakeld in productie
            checkSslLabs(request.domain)
                .then(sslResult => {
                    // console.log("[Background] SSL check result:", sslResult); // Deze wordt uitgeschakeld in productie
                    sendResponse(sslResult);
                })
                .catch(error => {
                    console.error("[checkSslLabs] Error:", error); // Deze blijft zichtbaar
                    sendResponse({ isValid: false, reason: "SSL check failed: " + error.message });
                });
            return true;

        default:
            console.warn("[onMessage] Unknown request type:", request.type || request.action); // Deze wordt uitgeschakeld in productie
            sendResponse({ success: false, error: "Unknown message type" });
            return true;
    }
});

// --- Icon Animation and Tab Safety ---

let iconState = true;
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

/** Starts a smooth icon animation for a specified duration */
function startSmoothIconAnimation(duration = 30000, interval = 5000) {
    stopIconAnimation();

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
        if (activeAnimationInterval) {
            clearInterval(activeAnimationInterval);
            activeAnimationInterval = null;
        }
        animationTimeout = null;
    }, duration);
}

/** Resets the current site status in storage */
async function resetCurrentSiteStatus() {
    try {
        await chrome.storage.local.remove("currentSiteStatus");
    } catch (error) {
        console.error("[ERROR] Error resetting currentSiteStatus:", error); // Deze blijft zichtbaar
    }
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.url) {
        stopIconAnimation();
        resetCurrentSiteStatus();
    }
});

chrome.tabs.onActivated.addListener(async ({ tabId }) => {
    stopIconAnimation();
    resetIconToNeutral();
    await resetCurrentSiteStatus();
    const tab = await chrome.tabs.get(tabId);
    if (tab && tab.url) checkTabSafety(tab.url);
});

/** Resets the icon to a neutral state */
function resetIconToNeutral() {
    chrome.action.setIcon({
        path: {
            "16": "icons/green-circle-16.png",
            "48": "icons/green-circle-48.png",
            "128": "icons/green-circle-128.png"
        }
    });
    chrome.action.setTitle({ title: "Performing safety check..." });
}

let checkedUrls = new Map();

/** Checks the safety of a tab's URL */
function checkTabSafety(url) {
    const now = Date.now();
    if (checkedUrls.has(url) && now - checkedUrls.get(url) < 60000) {
        return;
    }
    checkedUrls.set(url, now);

    chrome.storage.local.get("currentSiteStatus", (result) => {
        const status = result.currentSiteStatus;
        if (status && status.url === url) {
            // Deze handleSafetyCheck wordt overgeslagen als `updateIconBasedOnSafety`
            // direct op de storage change reageert, wat nu het geval is.
            // Dit kan nu mogelijk overbodig zijn en verwijderd worden, afhankelijk
            // van de exacte flow die je wilt.
            handleSafetyCheck(status.isSafe, url, status.risk);
        } else {
            chrome.storage.sync.get("suspiciousUrls", (syncResult) => {
                const suspiciousUrls = syncResult.suspiciousUrls || [];
                const isSafe = !suspiciousUrls.includes(url);
                handleSafetyCheck(isSafe, url);
            });
        }
    });
}

setInterval(() => {
    const now = Date.now();
    checkedUrls.forEach((timestamp, url) => {
        if (now - timestamp > 60000) {
            checkedUrls.delete(url);
        }
    });
}, 60000);

/** Handles the safety check result for a URL */
function handleSafetyCheck(isSafe, url, risk = 0) {
    if (!isSafe) {
        chrome.action.setIcon({
            path: { "16": "icons/red-circle-16.png", "48": "icons/red-circle-48.png", "128": "icons/red-circle-128.png" }
        });
        chrome.action.setTitle({ title: `Unsafe site detected (Risk: ${risk})` });
        const animationSpeed = risk >= 10 ? 500 : risk >= 5 ? 1000 : 2000;
        startSmoothIconAnimation(30000, animationSpeed);
        handleSuspiciousLink(url);
    } else {
        chrome.action.setIcon({
            path: { "16": "icons/green-circle-16.png", "48": "icons/green-circle-48.png", "128": "icons/green-circle-128.png" }
        });
        chrome.action.setTitle({ title: "Site is safe." });
    }
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

chrome.action.onClicked.addListener(async () => {
    try {
        const { currentSiteStatus } = await chrome.storage.local.get("currentSiteStatus");
        if (currentSiteStatus && currentSiteStatus.isSafe) {
            await chrome.storage.local.remove("currentSiteStatus");
        }
    } catch (error) {
        // Optional: log error if needed
    }
});

chrome.storage.onChanged.addListener((changes, area) => {
    if (area === "sync" && "backgroundSecurity" in changes) {
        const now = Date.now();
        if (now - lastUpdate < 300000) {
            // console.log("[DEBUG] Too soon for another update. Skipping."); // Deze wordt uitgeschakeld in productie
            return;
        }
        lastUpdate = now;
        // console.log("backgroundSecurity changed. Updating DNR rules..."); // Deze wordt uitgeschakeld in productie
        fetchAndLoadRules();
    }
    // --- DEBUG LOG START ---
    // Toegevoegd: Listener voor veranderingen in local storage, om updateIconBasedOnSafety te triggeren
    if (area === "local" && changes.currentSiteStatus && changes.currentSiteStatus.newValue) {
        const { isSafe, reasons, risk, url } = changes.currentSiteStatus.newValue;
        console.log(`[Background Script - onChanged] Detected currentSiteStatus change. New value:`, changes.currentSiteStatus.newValue); // Deze wordt uitgeschakeld in productie
        updateIconBasedOnSafety(isSafe, reasons, risk, url);
    }
    // --- DEBUG LOG END ---
});

chrome.runtime.setUninstallURL("https://linkshield.nl/#uninstall");

/** Updates the extension icon based on site safety */
async function updateIconBasedOnSafety(isSafe, reasons, risk, url) {
    // --- DEBUG LOG START ---
    console.log(`[Background Script - updateIconBasedOnSafety] Called with: isSafe=${isSafe}, reasons=`, reasons, `, risk=${risk}, url=${url}`); // Deze wordt uitgeschakeld in productie
    // --- DEBUG LOG END ---

    const iconPaths = isSafe
        ? { "16": "icons/green-circle-16.png", "48": "icons/green-circle-48.png", "128": "icons/green-circle-128.png" }
        : { "16": "icons/red-circle-16.png", "48": "icons/red-circle-48.png", "128": "icons/red-circle-128.png" };

    chrome.action.setIcon({ path: iconPaths });
    chrome.action.setTitle({
        title: isSafe ? "This site is safe." : `Unsafe site detected (Risk: ${risk}):\n${reasons.join("\n")}`
    });

    try {
        // De opslag gebeurt al in de message listener, dus deze opslag is overbodig.
        // Als je wilt dat de icon update een direct resultaat is van de opslag,
        // zorg dan dat deze functie wordt getriggerd door de storage listener,
        // zoals nu gedaan is in de chrome.storage.onChanged listener.
        // Verwijder de onderstaande set-regel als je dit niet twee keer wilt opslaan.
        // await chrome.storage.local.set({
        //     currentSiteStatus: { isSafe, reasons, risk: Number(risk), url }
        // });
    } catch (error) {
        console.error("[ERROR] updateIconBasedOnSafety: Failed to save currentSiteStatus:", error.message); // Deze blijft zichtbaar
    }

    if (!isSafe) {
        const animationSpeed = risk >= 10 ? 500 : risk >= 5 ? 1000 : 2000;
        startSmoothIconAnimation(60000, animationSpeed);
    }
}