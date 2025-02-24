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
            // Background security is disabled. Remove all active rules.
            let remainingRules = await chrome.declarativeNetRequest.getDynamicRules();
            while (remainingRules.length > 0) {
                const batch = remainingRules.slice(0, 500).map(rule => rule.id);
                await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: batch });
                await new Promise(resolve => setTimeout(resolve, 200)); // Prevent throttling
                remainingRules = await chrome.declarativeNetRequest.getDynamicRules();
            }
            return; // Stop here if background security is off.
        }

        // If background security is enabled, fetch new rules.
        const rulesResponse = await fetchWithRetry('https://linkshield.nl/files/rules.json');

        if (!rulesResponse.ok) {
            throw new Error('Error fetching rules.');
        }

        const newRules = await rulesResponse.json();

        // Remove existing dynamic rules before adding new ones.
        let remainingRules = await chrome.declarativeNetRequest.getDynamicRules();
        while (remainingRules.length > 0) {
            const batch = remainingRules.slice(0, 500).map(rule => rule.id);
            await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: batch });
            await new Promise(resolve => setTimeout(resolve, 200));
            remainingRules = await chrome.declarativeNetRequest.getDynamicRules();
        }

        if (!Array.isArray(newRules) || newRules.length === 0) {
            return;
        }

        const { lastCounter = 1000000 } = await chrome.storage.local.get('lastCounter');
        let counter = Math.floor(lastCounter);

        const validDynamicRules = [];
        for (const rule of newRules) {
            if (!rule.condition?.urlFilter || !rule.action) {
                continue;
            }

            const ruleId = Math.floor(counter++);
            if (!Number.isInteger(ruleId)) {
                throw new Error(`[ERROR] Rule ID is not an integer: ${ruleId}`);
            }

            validDynamicRules.push({
                id: ruleId,
                priority: rule.priority || 1,
                action: rule.action,
                condition: {
                    urlFilter: rule.condition.urlFilter,
                    resourceTypes: rule.condition.resourceTypes || ['main_frame'],
                },
            });
        }

        await chrome.storage.local.set({ lastCounter: counter });

        const addBatchSize = 1000;
        for (let i = 0; i < validDynamicRules.length; i += addBatchSize) {
            const batch = validDynamicRules.slice(i, i + addBatchSize);
            await chrome.declarativeNetRequest.updateDynamicRules({ addRules: batch });
        }

        await updateLastRuleUpdate();
    } catch (error) {
        // Uncomment the next line for debugging if needed:
        // console.error('Error fetching and loading rules:', error.message);
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
    chrome.storage.sync.get('suspiciousUrls', (result) => {
        const urls = new Set(result.suspiciousUrls || []);
        if (!urls.has(url)) {
            urls.add(url);
            chrome.storage.sync.set({ suspiciousUrls: Array.from(urls) });
        }
    });
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
                chrome.storage.sync.get(['integratedProtection'], (settings) => {
                    if (!settings.integratedProtection) {
                        sendResponse({ status: 'skipped' });
                        return;
                    }
                    const { isSafe, reasons, risk, url } = request; // Haal risk expliciet uit het request
                    updateIconBasedOnSafety(isSafe, reasons, risk, url); // Geef risk mee aan de functie
                    sendResponse({ status: 'received' });
                });
                return true; // Nodig omdat sendResponse in een callback zit

            case 'getStatus':
                try {
                    const { currentSiteStatus } = await chrome.storage.local.get("currentSiteStatus");
                    sendResponse(currentSiteStatus || { isSafe: null, reasons: ["Geen status gevonden"], url: null });
                } catch (error) {
                    //console.error("[getStatus] Error:", error);
                    sendResponse({ isSafe: null, reasons: ["Fout bij ophalen status"], url: null });
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

chrome.tabs.onActivated.addListener(({ tabId }) => {
    stopIconAnimation();  // Stop animation when switching tabs
    resetCurrentSiteStatus();
    chrome.tabs.get(tabId, (tab) => {
        if (tab && tab.url) {
            checkTabSafety(tab.url);
        }
    });
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
    chrome.storage.local.get("suspiciousUrls", ({ suspiciousUrls = [] }) => {
        const isSafe = !suspiciousUrls.includes(url);
        handleSafetyCheck(isSafe, url);
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

function handleSafetyCheck(isSafe, url) {
    if (!isSafe) {
        chrome.action.setIcon({
            path: {
                "16": "icons/red-circle-16.png",
                "48": "icons/red-circle-48.png",
                "128": "icons/red-circle-128.png"
            }
        });
        chrome.action.setTitle({ title: "Unsafe site detected!" });
        startSmoothIconAnimation(30000, 2000);
    } else {
        chrome.action.setIcon({
            path: {
                "16": "icons/green-circle-16.png",
                "48": "icons/green-circle-48.png",
                "128": "icons/green-circle-128.png"
            }
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

chrome.action.onClicked.addListener(() => {
    chrome.storage.local.get("currentSiteStatus", ({ currentSiteStatus }) => {
        if (currentSiteStatus && currentSiteStatus.isSafe) {
            chrome.storage.local.remove("currentSiteStatus");
        }
    });
});

chrome.storage.onChanged.addListener(async (changes, namespace) => {
    if (changes.backgroundSecurity) {
        // console.log("backgroundSecurity changed. Updating DNR rules...");
        await manageDNRules();
        await fetchAndLoadRules();
    }
});

chrome.runtime.setUninstallURL("https://linkshield.nl/#uninstall");

function updateIconBasedOnSafety(isSafe, reasons, risk, url) {
    //console.log("🛠 updateIconBasedOnSafety() aangeroepen:", { isSafe, reasons, risk, url });

    chrome.action.setIcon({
        path: isSafe
            ? {
                "16": "icons/green-circle-16.png",
                "48": "icons/green-circle-48.png",
                "128": "icons/green-circle-128.png"
            }
            : {
                "16": "icons/red-circle-16.png",
                "48": "icons/red-circle-48.png",
                "128": "icons/red-circle-128.png"
            }
    });

    chrome.action.setTitle({
        title: isSafe ? "This site is safe." : `Unsafe site detected:\n${reasons.join("\n")}`
    });

    chrome.storage.local.set({
        currentSiteStatus: { isSafe, reasons, risk, url }
    }, () => {
        if (chrome.runtime.lastError) {
            //console.error("❌ Fout bij opslaan van currentSiteStatus:", chrome.runtime.lastError);
        } else {
            //console.log("✅ currentSiteStatus succesvol opgeslagen!", { isSafe, reasons, risk, url });
        }
    });

    if (!isSafe) {
        startSmoothIconAnimation(60000, 1000);
    }
}




