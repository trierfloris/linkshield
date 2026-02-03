document.addEventListener('DOMContentLoaded', () => {
    // Debugging is uitgeschakeld; console.log/console.error blijven uit

    /**
     * Centrale error handler voor dynamic.js
     * @param {Error} error - De error
     * @param {string} context - Context waar de error optrad
     */
    function handleError(error, context) {
        // Alleen loggen in development of als DEBUG_MODE aan staat
        if (typeof console !== 'undefined' && console.error) {
            console.error(`[LinkShield Dynamic][${context}]`, error?.message || error);
        }
    }

    /**
     * Valideert of de site-status het verwachte format heeft.
     * @param {any} status
     * @returns {boolean}
     */
    function validateSiteStatus(status) {
        return status && typeof status === 'object' &&
            ('level' in status) && typeof status.level === 'string';
    }

    /**
     * Extraheert hostname uit een URL string
     * @param {string} url - De URL
     * @returns {string|null} - De hostname of null bij fout
     */
    function getHostname(url) {
        if (!url || typeof url !== 'string') return null;
        try {
            return new URL(url).hostname.toLowerCase();
        } catch (e) {
            return null;
        }
    }

    /**
     * FIX BUG-002: Controleert of de currentSiteStatus overeenkomt met de actieve tab
     * Dit voorkomt dat de status van een andere tab wordt getoond
     */
    async function getActiveTabAndValidateStatus() {
        try {
            // Haal de actieve tab op
            const tabs = await chrome.tabs.query({ active: true, currentWindow: true });
            const activeTab = tabs[0];

            if (!activeTab || !activeTab.url) {
                // Kan actieve tab niet bepalen, fallback naar popup
                window.location.replace(chrome.runtime.getURL('popup.html'));
                return;
            }

            // Skip chrome://, about:, edge:// en andere speciale URLs
            const activeUrl = activeTab.url;
            if (activeUrl.startsWith('chrome://') ||
                activeUrl.startsWith('chrome-extension://') ||
                activeUrl.startsWith('about:') ||
                activeUrl.startsWith('edge://') ||
                activeUrl.startsWith('moz-extension://')) {
                window.location.replace(chrome.runtime.getURL('popup.html'));
                return;
            }

            // Haal de currentSiteStatus op
            const { currentSiteStatus } = await chrome.storage.local.get('currentSiteStatus');

            // Valideer de status
            if (!validateSiteStatus(currentSiteStatus)) {
                window.location.replace(chrome.runtime.getURL('popup.html'));
                return;
            }

            // FIX BUG-002: Vergelijk hostnames om te voorkomen dat status van andere tab wordt getoond
            const activeHostname = getHostname(activeUrl);
            const statusHostname = getHostname(currentSiteStatus.url);

            if (!activeHostname || !statusHostname || activeHostname !== statusHostname) {
                // Status is van een andere tab/site, toon normale popup
                // Dit voorkomt dat een warning voor site A wordt getoond op site B
                window.location.replace(chrome.runtime.getURL('popup.html'));
                return;
            }

            // Status is voor de juiste tab, redirect naar de juiste pagina
            const lvl = currentSiteStatus.level.trim().toLowerCase();
            switch (lvl) {
                case 'alert':
                    window.location.replace(chrome.runtime.getURL('alert.html'));
                    break;
                case 'caution':
                    window.location.replace(chrome.runtime.getURL('caution.html'));
                    break;
                case 'safe':
                default:
                    window.location.replace(chrome.runtime.getURL('popup.html'));
            }
        } catch (error) {
            handleError(error, 'getActiveTabAndValidateStatus');
            // Bij fout, fallback naar normale popup
            window.location.replace(chrome.runtime.getURL('popup.html'));
        }
    }

    // Start de validatie
    getActiveTabAndValidateStatus();
});
