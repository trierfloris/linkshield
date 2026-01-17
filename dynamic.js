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

    // Haal de huidige site-status op uit storage
    chrome.storage.local.get('currentSiteStatus', ({ currentSiteStatus }) => {
        if (chrome.runtime.lastError) {
            document.body.innerHTML =
                '<h2>Fout bij laden</h2>' +
                '<p>Kan site-status niet ophalen.</p>';
            return;
        }

        // Valideer de opgehaalde status
        if (!validateSiteStatus(currentSiteStatus)) {
            // Standaard naar normale popup
            window.location.replace(chrome.runtime.getURL('popup.html'));
            return;
        }

        // Bepaal actie op basis van level
        // FIX BUG-001: Gebruik replace() ipv href om back-button escape te voorkomen
        const lvl = currentSiteStatus.level.trim().toLowerCase();
        switch (lvl) {
            case 'alert':
                // Hoge urgentie - replace voorkomt back-navigatie
                window.location.replace(chrome.runtime.getURL('alert.html'));
                break;
            case 'caution':
                // Milde waarschuwing
                window.location.replace(chrome.runtime.getURL('caution.html'));
                break;
            case 'safe':
            default:
                // Veilig of onbekend
                window.location.replace(chrome.runtime.getURL('popup.html'));
        }
    });
});
