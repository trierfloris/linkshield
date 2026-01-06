// caution.js
// Mirror van alert.js met gele styling en dynamische i18n voor risiconiveau

document.addEventListener('DOMContentLoaded', () => {
    const maxRetries = 5;
    let retryCount = 0;

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
        markSafe: document.getElementById('mark-safe')
    };

    // Vul statische i18n teksten
    document.querySelectorAll('[data-i18n]').forEach(node => {
        const key = node.getAttribute('data-i18n');
        node.textContent = chrome.i18n.getMessage(key) || '';
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
            el.siteName.textContent = u.hostname;
            el.urlLink.href = url;
            el.urlLink.textContent = url;
        } catch {}

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
        el.severity.textContent = chrome.i18n.getMessage(riskKey) || risk;

        // Redenenlijst met vertaling
        el.reasons.innerHTML = '';
        if (Array.isArray(reasons) && reasons.length) {
            reasons.forEach(key => {
                const msg = chrome.i18n.getMessage(key);
                const li = document.createElement('li');
                li.textContent = msg || key;
                el.reasons.appendChild(li);
            });
        } else {
            const li = document.createElement('li');
            li.textContent = chrome.i18n.getMessage('noSuspiciousFeatures') || '';
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

    // Knoppen
    el.closeBtn?.addEventListener('click', () => window.close());
    el.markSafe?.addEventListener('click', () => {
        chrome.storage.local.get('currentSiteStatus', ({ currentSiteStatus }) => {
            const newStatus = { ...currentSiteStatus, level: 'safe', isSafe: true };
            chrome.storage.local.set({ currentSiteStatus: newStatus }, () => window.close());
        });
    });
});
