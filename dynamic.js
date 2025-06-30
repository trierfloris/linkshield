document.addEventListener('DOMContentLoaded', () => {
    // Debugging is uitgeschakeld; console.log/console.error blijven uit

    /**
     * Centrale foutafhandelingsfunctie.
     * @param {Error} error - De opgetreden fout.
     * @param {string} context - De context waarin de fout optrad.
     */
    function handleError(error, context) {
        // Logging uitgeschakeld
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
            window.location.href = chrome.runtime.getURL('popup.html');
            return;
        }

        // Bepaal actie op basis van level
        const lvl = currentSiteStatus.level.trim().toLowerCase();
        switch (lvl) {
            case 'alert':
                // Hoge urgentie
                window.location.href = chrome.runtime.getURL('alert.html');
                break;
            case 'caution':
                // Milde waarschuwing
                window.location.href = chrome.runtime.getURL('caution.html');
                break;
            case 'safe':
            default:
                // Veilig of onbekend
                window.location.href = chrome.runtime.getURL('popup.html');
        }
    });
});
