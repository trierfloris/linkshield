// caution.js
// Mirror van alert.js met gele styling en dynamische i18n voor risiconiveau

/**
 * Veilige wrapper voor chrome.i18n.getMessage met null checks
 * @param {string} messageKey
 * @returns {string}
 */
function safeGetMessage(messageKey) {
    try {
        if (typeof chrome !== 'undefined' && chrome.i18n && typeof chrome.i18n.getMessage === 'function') {
            return chrome.i18n.getMessage(messageKey) || '';
        }
    } catch (e) {
        // Ignore - extension context might be invalidated
    }
    return '';
}

document.addEventListener('DOMContentLoaded', () => {
    const maxRetries = 5;
    let retryCount = 0;
    let currentDomain = null; // Track het huidige domein voor de trust-button

    // Element references
    const el = {
        title:    document.querySelector('[data-i18n="alertTitle"]'),
        message:  document.querySelector('[data-i18n="alertMessage"]'),
        siteName: document.getElementById('site-name'),
        urlLink:  document.getElementById('url-link'),
        severity: document.getElementById('severity-text'),
        reasons:  document.getElementById('reason-list'),
        advice:   document.getElementById('advice'),
        closeBtn: document.getElementById('close-warning'),
        trustDomainBtn: document.getElementById('trust-domain')
    };

    // Vul statische i18n teksten
    document.querySelectorAll('[data-i18n]').forEach(node => {
        const key = node.getAttribute('data-i18n');
        node.textContent = safeGetMessage(key) || '';
    });

    // Hulpfunctie voor delay
    const wait = ms => new Promise(res => setTimeout(res, ms));

    // Update UI met status
    function updateStatus(status) {
        if (!status || typeof status !== 'object') return;
        const { level, reasons, risk, url } = status;

        // Hostname & URL
        try {
            const u = new URL(url);
            currentDomain = u.hostname; // Track domein voor trust-button
            el.siteName.textContent = u.hostname;
            el.urlLink.href = url;
            el.urlLink.textContent = url;
        } catch {
            currentDomain = null;
        }

        // Dynamisch risiconiveau via i18n
        let riskKey;
        switch (level) {
            case 'alert':
                riskKey = 'highRisk';
                break;
            case 'caution':
                riskKey = 'mediumRisk';
                break;
            default:
                riskKey = 'lowRisk';
        }
        el.severity.textContent = safeGetMessage(riskKey) || risk;

        // Redenenlijst met vertaling
        el.reasons.innerHTML = '';
        if (Array.isArray(reasons) && reasons.length) {
            reasons.forEach(key => {
                const msg = safeGetMessage(key);
                const li = document.createElement('li');
                li.textContent = msg || key;
                el.reasons.appendChild(li);
            });
        } else {
            const li = document.createElement('li');
            li.textContent = safeGetMessage('noSuspiciousFeatures') || '';
            el.reasons.appendChild(li);
        }
    }

    // Haal status op met retry-logic
    async function loadStatus() {
        const { currentSiteStatus } = await chrome.storage.local.get('currentSiteStatus');
        if (currentSiteStatus && Array.isArray(currentSiteStatus.reasons)) {
            updateStatus(currentSiteStatus);
        } else if (retryCount < maxRetries) {
            retryCount++;
            await wait(500);
            return loadStatus();
        }
    }
    loadStatus();

    // Live updates
    chrome.storage.onChanged.addListener((changes, area) => {
        if (area === 'local' && changes.currentSiteStatus?.newValue) {
            updateStatus(changes.currentSiteStatus.newValue);
        }
    });

    // Trust Domain Button - voeg domein toe aan whitelist
    el.trustDomainBtn?.addEventListener('click', async () => {
        if (!currentDomain) return;

        try {
            // Haal huidige whitelist op
            const { trustedDomains = [] } = await chrome.storage.sync.get('trustedDomains');

            // Voeg domein toe als het nog niet bestaat
            if (!trustedDomains.includes(currentDomain)) {
                trustedDomains.push(currentDomain);
                await chrome.storage.sync.set({ trustedDomains });
            }

            // Reset de huidige site status naar safe
            const { currentSiteStatus } = await chrome.storage.local.get('currentSiteStatus');
            if (currentSiteStatus && currentSiteStatus.url) {
                await chrome.storage.local.set({
                    currentSiteStatus: {
                        ...currentSiteStatus,
                        level: 'safe',
                        isSafe: true,
                        trustedByUser: true
                    }
                });

                // Navigeer terug naar de originele URL via chrome.tabs API
                const originalUrl = currentSiteStatus.url;
                chrome.tabs.query({ active: true, currentWindow: true }, (tabs) => {
                    if (tabs[0]) {
                        chrome.tabs.update(tabs[0].id, { url: originalUrl });
                    }
                });
            }

            // Sluit popup
            window.close();
        } catch (error) {
            console.error('[Caution] Fout bij toevoegen aan whitelist:', error);
        }
    });

    // Close Button
    el.closeBtn?.addEventListener('click', () => window.close());
});
