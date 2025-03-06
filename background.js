// --- Rule Management and Fetching ---

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
        // Uncomment the next line for debugging if needed:
        // console.error("Error managing DNR rules:", error);
    }
}

async function fetchAndLoadRules() {
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
            handleBackgroundError(new Error("Invalid or empty rules"), "fetchAndLoadRules");
            return;
        }

        // Valideer en filter regels
        const { lastCounter = 1000000 } = await chrome.storage.local.get('lastCounter');
        let counter = Math.max(1000000, Math.floor(lastCounter)); // Zorg voor een minimum ID
        const validDynamicRules = [];
        const seenIds = new Set();

        for (const rule of newRules) {
            if (!rule.condition?.urlFilter || !rule.action || typeof rule.priority !== 'number') {
                continue; // Sla ongeldige regels over
            }
            const ruleId = counter++;
            if (seenIds.has(ruleId)) continue; // Voorkom duplicaten
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
            handleBackgroundError(new Error("No valid rules after filtering"), "fetchAndLoadRules");
            return;
        }

        await clearDynamicRules();
        const addBatchSize = 1000;
        for (let i = 0; i < validDynamicRules.length; i += addBatchSize) {
            const batch = validDynamicRules.slice(i, i + addBatchSize);
            await chrome.declarativeNetRequest.updateDynamicRules({ addRules: batch });
            await new Promise(resolve => setTimeout(resolve, 200)); // Prevent throttling
        }

        await chrome.storage.local.set({ lastCounter: counter });
        await updateLastRuleUpdate();
    } catch (error) {
        handleBackgroundError(error, "fetchAndLoadRules");
        // Fallback: behoud bestaande regels als fetch mislukt
    }
}

async function clearDynamicRules() {
    let remainingRules = await chrome.declarativeNetRequest.getDynamicRules();
    while (remainingRules.length > 0) {
        const batch = remainingRules.slice(0, 500).map(rule => rule.id);
        await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: batch });
        await new Promise(resolve => setTimeout(resolve, 200));
        remainingRules = await chrome.declarativeNetRequest.getDynamicRules();
    }
}
async function updateLastRuleUpdate() {
    const now = new Date().toISOString();
    try {
        await chrome.storage.local.set({ lastRuleUpdate: now });
    } catch (error) {
        // Uncomment the next line for debugging if needed:
        // console.error('[extension] Error saving lastRuleUpdate:', error.message);
    }
}

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
        return false;
    }
}

// --- Suspicious Link Handling ---

async function handleSuspiciousLink(url) {
    try {
        const { suspiciousUrls = [] } = await chrome.storage.sync.get('suspiciousUrls');
        const urls = new Set(suspiciousUrls);
        if (!urls.has(url)) {
            urls.add(url);
            await chrome.storage.sync.set({ suspiciousUrls: Array.from(urls) });
        }
    } catch (error) {
        handleBackgroundError(error, "handleSuspiciousLink");
    }
}

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
        // Uncomment the next line for debugging if needed:
        // console.error("Error during extension installation or update:", error);
    }
});

chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === "fetchRulesHourly") {
        fetchAndLoadRules().catch(error => {
            // Uncomment the next line for debugging if needed:
            // console.error("[extension] Error fetching rules via alarm:", error.message);
        });
    }
});

// --- Message Listener ---

chrome.runtime.onMessage.addListener(async (request, sender, sendResponse) => {
    try {
        switch (request.type || request.action) {
            case 'validateLicense':
                try {
                    const result = await validateLicenseKey(request.licenseKey);
                    sendResponse({ success: result });
                } catch (error) {
                    //console.error("[validateLicense] Error:", error);
                    sendResponse({ success: false, error: error.message });
                }
                return true; // Nodig voor async response

            case 'checkUrl':
                try {
                    const result = await checkUrlSafety(request.url);
                    sendResponse(result);
                } catch (error) {
                    //console.error("[checkUrl] Error:", error);
                    sendResponse({ status: "error", message: error.message });
                }
                return true;

            case 'checkResult':
                try {
                    const settings = await chrome.storage.sync.get(['integratedProtection']);
                    if (!settings.integratedProtection) {
                        sendResponse({ status: 'skipped' });
                    } else {
                        const { isSafe, reasons, risk, url } = request; // Haal risk expliciet uit het request
                        await updateIconBasedOnSafety(isSafe, reasons, risk, url); // Gebruik async versie
                        sendResponse({ status: 'received' });
                    }
                } catch (error) {
                    sendResponse({ status: 'error', error: error.message });
                }
                return true;

            case 'getStatus':
                try {
                    const { currentSiteStatus } = await chrome.storage.local.get("currentSiteStatus");
                    sendResponse(currentSiteStatus || { isSafe: null, reasons: ["Geen status gevonden"], url: null });
                } catch (error) {
                    //console.error("[getStatus] Error:", error);
                    sendResponse({ isSafe: null, reasons: ["Fout bij ophalen status"], url: null });
                }
                return true;

            case 'alert':
                try {
                    chrome.notifications.create({
                        type: 'basic',
                        iconUrl: 'icons/icon128.png', // Controleer of dit pad klopt
                        title: 'Waarschuwing',
                        message: request.message || 'Deze pagina bevat verdachte links!',
                        priority: 2
                    });
                    sendResponse({ status: 'alert_shown' });
                } catch (error) {
                    //console.error("[alert] Error showing notification:", error);
                    sendResponse({ status: 'error', error: error.message });
                }
                return true;

            default:
                //console.warn("[onMessage] Onbekend request type:", request.type || request.action);
                sendResponse({ success: false, error: "Unknown message type" });
        }
    } catch (error) {
        //console.error("[onMessage] Algemene fout:", error);
        sendResponse({ success: false, error: "Interne fout" });
    }
    return true;
});

// --- Icon Animation and Tab Safety ---

let iconState = true;
let activeAnimationInterval = null;
let animationTimeout = null;

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

async function resetCurrentSiteStatus() {
    try {
        await chrome.storage.local.remove("currentSiteStatus");
    } catch (error) {
        // Uncomment the next line for debugging if needed:
        // console.error("[ERROR] Error resetting currentSiteStatus:", error);
    }
}

chrome.tabs.onUpdated.addListener((tabId, changeInfo, tab) => {
    if (changeInfo.url) {
        stopIconAnimation();  // Stop animation when a new URL is loaded in the same tab
        resetCurrentSiteStatus();
    }
});

chrome.tabs.onActivated.addListener(async ({ tabId }) => {
    stopIconAnimation();
    resetIconToNeutral(); // Reset naar neutrale staat
    await resetCurrentSiteStatus();
    const tab = await chrome.tabs.get(tabId);
    if (tab && tab.url) checkTabSafety(tab.url);
});

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

function checkTabSafety(url) {
    const now = Date.now();
    if (checkedUrls.has(url) && now - checkedUrls.get(url) < 60000) {
        return;
    }
    checkedUrls.set(url, now);

    chrome.storage.local.get("currentSiteStatus", (result) => {
        const status = result.currentSiteStatus;
        if (status && status.url === url) {
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

function handleSafetyCheck(isSafe, url, risk = 0) {
    if (!isSafe) {
        chrome.action.setIcon({
            path: { "16": "icons/red-circle-16.png", "48": "icons/red-circle-48.png", "128": "icons/red-circle-128.png" }
        });
        chrome.action.setTitle({ title: `Unsafe site detected (Risk: ${risk})` });
        const animationSpeed = risk >= 10 ? 500 : risk >= 5 ? 1000 : 2000;
        startSmoothIconAnimation(30000, animationSpeed);
        handleSuspiciousLink(url); // Voeg toe aan suspiciousUrls
    } else {
        chrome.action.setIcon({
            path: { "16": "icons/green-circle-16.png", "48": "icons/green-circle-48.png", "128": "icons/green-circle-128.png" }
        });
        chrome.action.setTitle({ title: "Site is safe." });
    }
}

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

chrome.storage.onChanged.addListener(async (changes, namespace) => {
    if (changes.backgroundSecurity) {
        // console.log("backgroundSecurity changed. Updating DNR rules...");
        await manageDNRules();
        await fetchAndLoadRules();
    }
});

chrome.runtime.setUninstallURL("https://linkshield.nl/#uninstall");

async function updateIconBasedOnSafety(isSafe, reasons, risk, url) {
    const iconPaths = isSafe
        ? { "16": "icons/green-circle-16.png", "48": "icons/green-circle-48.png", "128": "icons/green-circle-128.png" }
        : { "16": "icons/red-circle-16.png", "48": "icons/red-circle-48.png", "128": "icons/red-circle-128.png" };

    chrome.action.setIcon({ path: iconPaths });
    chrome.action.setTitle({
        title: isSafe ? "This site is safe." : `Unsafe site detected (Risk: ${risk}):\n${reasons.join("\n")}`
    });

    try {
        await chrome.storage.local.set({
            currentSiteStatus: { isSafe, reasons, risk: Number(risk), url }
        });
    } catch (error) {
        handleBackgroundError(error, "updateIconBasedOnSafety: Failed to save currentSiteStatus");
    }

    if (!isSafe) {
        const animationSpeed = risk >= 10 ? 500 : risk >= 5 ? 1000 : 2000; // Sneller bij hoger risico
        startSmoothIconAnimation(60000, animationSpeed);
    }
}
