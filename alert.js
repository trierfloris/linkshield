document.addEventListener('DOMContentLoaded', async () => {
    const maxRetries = 5;
    let retryCount = 0;

    // **Internationalisatie van elementen met data-i18n attributen**
    document.querySelectorAll("[data-i18n]").forEach(element => {
        const messageKey = element.getAttribute("data-i18n");
        if (!messageKey) return;
        element.textContent = chrome.i18n.getMessage(messageKey) || chrome.i18n.getMessage("loadingMessage") || "Een moment, het systeem voert controles uit...";
    });

    // **Functie om de site-status bij te werken in de UI**
    function updateSiteStatus(status) {
        // Controleer of status undefined is
        if (!status) {
            console.error("❌ Status is undefined");
            document.getElementById('severity-text').textContent = chrome.i18n.getMessage("siteStatusNotAvailable") || "⚠️ Site-status niet beschikbaar.";
            return;
        }

        // Destructureren van de status-eigenschappen
        const { isSafe, reasons, risk, url } = status;

        // **URL-verwerking met validatie**
        if (typeof url === 'string' && url.trim()) {
            try {
                document.getElementById('site-name').textContent = new URL(url).hostname;
                document.getElementById('url-link').textContent = url;
                document.getElementById('url-link').href = url;
            } catch (error) {
                console.error("❌ Fout bij URL verwerken:", error);
                document.getElementById('site-name').textContent = chrome.i18n.getMessage("invalidUrl") || "Ongeldige URL";
            }
        } else {
            document.getElementById('site-name').textContent = chrome.i18n.getMessage("invalidUrl") || "Ongeldige URL";
        }

        // **Risico-classificatie**
        let severityText = chrome.i18n.getMessage("unknownRisk") || "⚠️ Onbekend risico";
        let severityColor = "gray";

        if (risk >= 10) {
            severityText = chrome.i18n.getMessage("highRisk") || "🔴 Hoog risico: zeer gevaarlijk!";
            severityColor = "red";
        } else if (risk >= 4) {
            severityText = chrome.i18n.getMessage("mediumRisk") || "🟠 Medium risico: wees voorzichtig.";
            severityColor = "orange";
        } else {
            severityText = chrome.i18n.getMessage("lowRisk") || "🟢 Laag risico: waarschijnlijk veilig.";
            severityColor = "green";
        }

        document.getElementById('severity-text').textContent = severityText;
        document.getElementById('severity-text').style.color = severityColor;

        // **Redenenlijst genereren**
        const reasonList = document.getElementById('reason-list');
        reasonList.innerHTML = "";
        if (!Array.isArray(reasons) || reasons.length === 0) {
            reasonList.innerHTML = `<li>${chrome.i18n.getMessage("noSuspiciousFeatures") || "✅ Geen verdachte kenmerken."}</li>`;
        } else {
            reasons.forEach(reason => {
                const li = document.createElement('li');
                // Splits de reden op ": " om sleutel en extra info te scheiden
                const [key, ...extraInfo] = reason.split(": ");
                const translatedMessage = chrome.i18n.getMessage(key);
                if (translatedMessage) {
                    // Als er extra info is, voeg deze toe
                    li.textContent = extraInfo.length > 0 ? `${translatedMessage} (${extraInfo.join(": ")})` : translatedMessage;
                } else {
                    // Fallback als vertaling mislukt
                    li.textContent = `⚠️ ${reason}`;
                }
                reasonList.appendChild(li);
            });
        }

        // **Advies tonen**
        document.getElementById('advice').textContent = chrome.i18n.getMessage("adviceCheckUrl") ||
            "🔍 Open deze link alleen als je zeker weet dat het veilig is.";
    }

    // **Functie om site-status op te halen met retry-logica (async/await versie)**
    async function getSiteStatus() {
        try {
            const { currentSiteStatus } = await chrome.storage.local.get("currentSiteStatus");
            console.log("currentSiteStatus:", currentSiteStatus); // Logging voor debugging
            if (currentSiteStatus && typeof currentSiteStatus === 'object') {
                updateSiteStatus(currentSiteStatus);
            } else if (retryCount < maxRetries) {
                retryCount++;
                setTimeout(getSiteStatus, 1000); // Probeer opnieuw na 1 seconde
            } else {
                document.getElementById('severity-text').textContent = chrome.i18n.getMessage("siteStatusNotAvailable") || "⚠️ Site-status niet beschikbaar.";
            }
        } catch (error) {
            console.error("❌ Fout bij ophalen van site-status:", error);
            if (retryCount < maxRetries) {
                retryCount++;
                setTimeout(getSiteStatus, 1000);
            } else {
                document.getElementById('severity-text').textContent = chrome.i18n.getMessage("siteStatusNotAvailable") || "⚠️ Site-status niet beschikbaar.";
            }
        }
    }

    // **Initiële oproep om de status op te halen**
    await getSiteStatus();

    // **Luister naar veranderingen in chrome.storage.local**
    chrome.storage.onChanged.addListener((changes, namespace) => {
        if (namespace === "local" && changes.currentSiteStatus && changes.currentSiteStatus.newValue) {
            updateSiteStatus(changes.currentSiteStatus.newValue);
        }
    });
});
