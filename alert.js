// alert.js
// Bijgewerkt om risiconiveau te kiezen op basis van 'level' ipv numerieke thresholds

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

document.addEventListener('DOMContentLoaded', async () => {
    const maxRetries = 5;
    let retryCount = 0;
    let currentDomain = null; // Track het huidige domein voor de trust-button

    // DOM-elementen cachen
    const elements = {
        severityText: document.getElementById('severity-text'),
        siteName:     document.getElementById('site-name'),
        urlLink:      document.getElementById('url-link'),
        reasonList:   document.getElementById('reason-list'),
        adviceCheckUrl: document.querySelector('.advice [data-i18n="adviceCheckUrl"]'),
        trustDomainBtn: document.getElementById('trust-domain'),
        closeBtn: document.getElementById('close-warning')
    };

    // Helper delay
    const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

    // i18n statische labels
    document.querySelectorAll('[data-i18n]').forEach(el => {
        const key = el.getAttribute('data-i18n');
        el.textContent = safeGetMessage(key) || '';
    });

    // Update UI met status
    function updateSiteStatus(status) {
        if (!status || typeof status !== 'object' || !('level' in status)) {
            elements.severityText.textContent = safeGetMessage('siteStatusNotAvailable');
            return;
        }
        const { level, reasons, url } = status;

        // Hostname & URL
        try {
            const u = new URL(url);
            currentDomain = u.hostname; // Track domein voor trust-button
            elements.siteName.textContent = u.hostname;
            elements.urlLink.href = url;
            elements.urlLink.textContent = url;
        } catch {
            currentDomain = null;
            elements.siteName.textContent = safeGetMessage('invalidUrl');
            elements.urlLink.textContent = url;
            elements.urlLink.href = url;
        }

        // Risico-tekst kiezen op basis van level
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
        elements.severityText.textContent = safeGetMessage(riskKey);

        // Redenenlijst
        elements.reasonList.innerHTML = '';
        if (Array.isArray(reasons) && reasons.length) {
            reasons.forEach(reasonKey => {
                const msg = safeGetMessage(reasonKey);
                const li = document.createElement('li');
                li.textContent = msg || reasonKey;
                elements.reasonList.appendChild(li);
            });
        } else {
            const li = document.createElement('li');
            li.textContent = safeGetMessage('noSuspiciousFeatures');
            elements.reasonList.appendChild(li);
        }

        // Advies tonen (altijd adviceCheckUrl)
        elements.adviceCheckUrl.textContent = safeGetMessage('adviceCheckUrl');
    }

    // Status ophalen met retry
    async function fetchStatus() {
        const { currentSiteStatus } = await chrome.storage.local.get('currentSiteStatus');
        if (currentSiteStatus && typeof currentSiteStatus === 'object') {
            updateSiteStatus(currentSiteStatus);
        } else if (retryCount < maxRetries) {
            retryCount++;
            await delay(500);
            return fetchStatus();
        }
    }
    await fetchStatus();

    // Luister naar storage veranderingen
    chrome.storage.onChanged.addListener((changes, area) => {
        if (area === 'local' && changes.currentSiteStatus?.newValue) {
            updateSiteStatus(changes.currentSiteStatus.newValue);
        }
    });

    // Trust Domain Button - voeg domein toe aan whitelist
    elements.trustDomainBtn?.addEventListener('click', async () => {
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
            if (currentSiteStatus) {
                await chrome.storage.local.set({
                    currentSiteStatus: {
                        ...currentSiteStatus,
                        level: 'safe',
                        isSafe: true,
                        trustedByUser: true
                    }
                });
            }

            // Sluit het venster
            window.close();
        } catch (error) {
            console.error('[Alert] Fout bij toevoegen aan whitelist:', error);
        }
    });

    // Close Button - sluit de huidige tab (niet alleen het venster)
    elements.closeBtn?.addEventListener('click', async () => {
        try {
            // Gebruik chrome.tabs API om de huidige tab te sluiten
            const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
            if (tabs[0]?.id) {
                await chrome.tabs.remove(tabs[0].id);
            }
        } catch (error) {
            // Fallback naar window.close() als tabs API niet beschikbaar is
            console.error('[Alert] Fout bij sluiten tab:', error);
            window.close();
        }
    });
});