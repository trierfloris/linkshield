document.addEventListener('DOMContentLoaded', () => {
    // Debugging is uitgeschakeld, dus alle console.log/console.error worden niet gebruikt.
    // console.log("Dynamic popup geladen. Bezig met ophalen van site-status...");

    /**
     * Centrale foutafhandelingsfunctie.
     * In deze versie doet deze functie niets (logging uitgeschakeld).
     * @param {Error} error - De opgetreden fout.
     * @param {string} context - De context waarin de fout optrad.
     */
    function handleError(error, context) {
        // Logging uitgeschakeld: 
        // console.error(`[${context}] ${error.message}`, error);
    }

    /**
     * Valideert of de site-status het verwachte format heeft.
     * @param {any} status - De opgehaalde status.
     * @returns {boolean} True als status geldig is, anders false.
     */
    function validateSiteStatus(status) {
        return status && typeof status === 'object' && 
            ('isSafe' in status) && (typeof status.isSafe === 'boolean');
    }

    // Probeer de huidige site-status op te halen
    chrome.storage.local.get("currentSiteStatus", ({ currentSiteStatus }) => {
        if (chrome.runtime.lastError) {
            // Logging uitgeschakeld:
            // console.error("Fout bij ophalen van site-status:", chrome.runtime.lastError.message);
            document.body.innerHTML = "<h2>Fout bij laden</h2><p>Kan site-status niet ophalen.</p>";
            return;
        }

        // Valideer de opgehaalde site-status
        if (!validateSiteStatus(currentSiteStatus)) {
            // Geen geldige status gevonden; standaard naar popup.html
            // console.warn("Ongeldige of ontbrekende site-status. Standaard naar popup.html.");
            window.location.href = chrome.runtime.getURL("popup.html");
            return;
        }

        // Site-status is geldig
        // console.log("Huidige site-status:", currentSiteStatus);

        if (!currentSiteStatus.isSafe) {
            // console.log("Onveilige site gedetecteerd. Doorsturen naar alert.html...");
            window.location.href = chrome.runtime.getURL("alert.html");
        } else {
            // console.log("Veilige site gedetecteerd. Doorsturen naar popup.html...");
            window.location.href = chrome.runtime.getURL("popup.html");
        }
    });
});
