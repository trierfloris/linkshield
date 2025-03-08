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
        //console.error("Error managing DNR rules:", error);
    }
}

/** Fetches and loads dynamic rules from a remote source */
async function fetchAndLoadRules() {
    if (isUpdatingRules) {
        console.log("[DEBUG] Rule update already in progress. Skipping.");
        return;
    }
    isUpdatingRules = true;
    try {
        const { backgroundSecurity } = await chrome.storage.sync.get('backgroundSecurity');
        if (!backgroundSecurity) {
            await clearDynamicRules();
            return;
        }

        console.log("[DEBUG] Starting rule fetch...");
        const rulesResponse = await fetchWithRetry('https://linkshield.nl/files/rules.json');
        if (!rulesResponse.ok) {
            throw new Error(`Failed to fetch rules: ${rulesResponse.status}`);
        }

        const newRules = await rulesResponse.json();
        console.log(`[DEBUG] Number of new rules received: ${newRules.length}`);

        if (!Array.isArray(newRules) || newRules.length === 0) {
            throw new Error("Invalid or empty rules");
        }

        // Step 1: Iteratively remove existing rules
        let remainingRules = await chrome.declarativeNetRequest.getDynamicRules();
        while (remainingRules.length > 0) {
            const batch = remainingRules.slice(0, 500).map(rule => rule.id); // Max 500 per batch
            await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: batch });
            console.info(`[DEBUG] Batch of ${batch.length} rules removed.`);
            await new Promise(resolve => setTimeout(resolve, 200)); // Short delay
            remainingRules = await chrome.declarativeNetRequest.getDynamicRules();
        }
        console.info('[DEBUG] All dynamic rules successfully removed.');

        // Step 2: Force Chrome reset with temporary rule
        await chrome.declarativeNetRequest.updateDynamicRules({
            addRules: [{ id: 1, priority: 1, action: { type: 'allow' }, condition: { resourceTypes: ['main_frame'] } }]
        });
        await chrome.declarativeNetRequest.updateDynamicRules({ removeRuleIds: [1] });

        // Step 3: Validate and filter rules with unique integer IDs
        const { lastCounter = 1000000 } = await chrome.storage.local.get('lastCounter');
        let counter = Math.max(1000000, Math.floor(lastCounter)); // Ensure minimum ID
        const validDynamicRules = [];
        const seenIds = new Set();

        for (const rule of newRules) {
            if (!rule.condition?.urlFilter || !rule.action || typeof rule.priority !== 'number') {
                continue; // Skip invalid rules
            }
            const ruleId = Math.floor(counter++);
            if (!Number.isInteger(ruleId)) {
                throw new Error(`[ERROR] Rule ID is not an integer: ${ruleId}`);
            }
            if (seenIds.has(ruleId)) continue; // Prevent duplicates
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

        console.log(`[DEBUG] Number of valid rules after filtering: ${validDynamicRules.length}`);

        if (validDynamicRules.length === 0) {
            throw new Error("No valid rules after filtering");
        }

        // Step 4: Add new rules in batches
        const addBatchSize = 1000;
        for (let i = 0; i < validDynamicRules.length; i += addBatchSize) {
            const batch = validDynamicRules.slice(i, i + addBatchSize);
            await chrome.declarativeNetRequest.updateDynamicRules({ addRules: batch });
            console.info(`[DEBUG] Batch of ${batch.length} rules added.`);
            await new Promise(resolve => setTimeout(resolve, 200)); // Prevent throttling
        }

        console.log(`[DEBUG] All dynamic rules successfully added.`);

        await chrome.storage.local.set({ lastCounter: counter });
        await updateLastRuleUpdate();
    } catch (error) {
        console.error("[ERROR] fetchAndLoadRules:", error.message);
        // Fallback: retain existing rules if fetch fails
    } finally {
        isUpdatingRules = false; // Reset flag
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
        //console.error('[ERROR] Error saving lastRuleUpdate:', error.message);
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
        //console.error("[ERROR] handleSuspiciousLink:", error.message);
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
        //console.error("Error during extension installation or update:", error);
    }
});

chrome.alarms.onAlarm.addListener((alarm) => {
    if (alarm.name === "fetchRulesHourly") {
        fetchAndLoadRules().catch(error => {
            //console.error("[ERROR] Error fetching rules via alarm:", error.message);
        });
    }
});

// --- Message Listener ---

chrome.runtime.onMessage.addListener(async (request, sender, sendResponse) => {
    try {
        switch (request.type || request.action) {
            case 'validateLicense':
                const result = await validateLicenseKey(request.licenseKey);
                sendResponse({ success: result });
                return true; // Needed for async response

            case 'checkUrl':
                // Placeholder: implement checkUrlSafety if needed
                sendResponse({ status: "not_implemented" });
                return true;

            case 'checkResult':
                const settings = await chrome.storage.sync.get(['integratedProtection']);
                if (!settings.integratedProtection) {
                    sendResponse({ status: 'skipped' });
                } else {
                    const { isSafe, reasons, risk, url } = request;
                    await updateIconBasedOnSafety(isSafe, reasons, risk, url);
                    sendResponse({ status: 'received' });
                }
                return true;

            case 'getStatus':
                const { currentSiteStatus } = await chrome.storage.local.get("currentSiteStatus");
                sendResponse(currentSiteStatus || { isSafe: null, reasons: ["No status found"], url: null });
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

            default:
                //console.warn("[onMessage] Unknown request type:", request.type || request.action);
                sendResponse({ success: false, error: "Unknown message type" });
        }
    } catch (error) {
        //console.error("[onMessage] General error:", error);
        sendResponse({ success: false, error: "Internal error" });
    }
    return true;
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
        //console.error("[ERROR] Error resetting currentSiteStatus:", error);
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
        if (now - lastUpdate < 300000) { // 5 minutes
            //console.log("[DEBUG] Too soon for another update. Skipping.");
            return;
        }
        lastUpdate = now;
        //console.log("backgroundSecurity changed. Updating DNR rules...");
        fetchAndLoadRules();
    }
});

chrome.runtime.setUninstallURL("https://linkshield.nl/#uninstall");

/** Updates the extension icon based on site safety */
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
        //console.error("[ERROR] updateIconBasedOnSafety: Failed to save currentSiteStatus:", error.message);
    }

    if (!isSafe) {
        const animationSpeed = risk >= 10 ? 500 : risk >= 5 ? 1000 : 2000; // Faster for higher risk
        startSmoothIconAnimation(60000, animationSpeed);
    }
}