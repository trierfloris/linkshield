// alert.js
// Bijgewerkt om risiconiveau te kiezen op basis van 'level' ipv numerieke thresholds


document.addEventListener('DOMContentLoaded', async () => {
    const maxRetries = 5;
    let retryCount = 0;

    // DOM-elementen cachen
    const elements = {
        severityText: document.getElementById('severity-text'),
        siteName:     document.getElementById('site-name'),
        urlLink:      document.getElementById('url-link'),
        reasonList:   document.getElementById('reason-list'),
        adviceCheckUrl: document.querySelector('.advice [data-i18n="adviceCheckUrl"]')
    };

    // Helper delay
    const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

    // i18n statische labels
    document.querySelectorAll('[data-i18n]').forEach(el => {
        const key = el.getAttribute('data-i18n');
        el.textContent = chrome.i18n.getMessage(key) || '';
    });

    // Update UI met status
    function updateSiteStatus(status) {
        if (!status || typeof status !== 'object' || !('level' in status)) {
            elements.severityText.textContent = chrome.i18n.getMessage('siteStatusNotAvailable');
            return;
        }
        const { level, reasons, url } = status;

        // Hostname & URL
        try {
            const u = new URL(url);
            elements.siteName.textContent = u.hostname;
            elements.urlLink.href = url;
            elements.urlLink.textContent = url;
        } catch {
            elements.siteName.textContent = chrome.i18n.getMessage('invalidUrl');
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
        elements.severityText.textContent = chrome.i18n.getMessage(riskKey);

        // Redenenlijst
        elements.reasonList.innerHTML = '';
        if (Array.isArray(reasons) && reasons.length) {
            reasons.forEach(reasonKey => {
                const msg = chrome.i18n.getMessage(reasonKey);
                const li = document.createElement('li');
                li.textContent = msg || reasonKey;
                elements.reasonList.appendChild(li);
            });
        } else {
            const li = document.createElement('li');
            li.textContent = chrome.i18n.getMessage('noSuspiciousFeatures');
            elements.reasonList.appendChild(li);
        }

        // Advies tonen (altijd adviceCheckUrl)
        elements.adviceCheckUrl.textContent = chrome.i18n.getMessage('adviceCheckUrl');
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
});