document.addEventListener('DOMContentLoaded', async () => {
    const maxRetries = 5;
    let retryCount = 0;

    // **DOM-elementen cachen**
    const elements = {
        severityText: document.getElementById('severity-text'),
        siteName: document.getElementById('site-name'),
        urlLink: document.getElementById('url-link'),
        reasonList: document.getElementById('reason-list'),
        advice: document.getElementById('advice')
    };

    // Controleer of alle DOM-elementen bestaan
    for (const [key, element] of Object.entries(elements)) {
        if (!element) console.error(`❌ Element '${key}' niet gevonden in DOM`);
    }

    // **Hulpfunctie voor delay**
    const delay = ms => new Promise(resolve => setTimeout(resolve, ms));

    // **Internationalisatie van elementen met data-i18n attributen**
    document.querySelectorAll("[data-i18n]").forEach(element => {
        const messageKey = element.getAttribute("data-i18n");
        if (!messageKey) return;
        element.textContent = chrome.i18n.getMessage(messageKey) || chrome.i18n.getMessage("loadingMessage") || "Een moment, het systeem voert controles uit...";
    });

    // **Functie om de site-status bij te werken in de UI**
    function updateSiteStatus(status) {
        if (!status || typeof status !== 'object') {
            console.error("❌ Status is ongeldig of undefined");
            if (elements.severityText) {
                elements.severityText.textContent = chrome.i18n.getMessage("siteStatusNotAvailable") || "⚠️ Site-status niet beschikbaar.";
            }
            return;
        }

        const { isSafe, reasons, risk, url } = status;

        // **URL-verwerking met validatie**
        if (typeof url === 'string' && url.trim() && /^https?:\/\//i.test(url)) {
            try {
                const parsedUrl = new URL(url);
                if (elements.siteName) elements.siteName.textContent = parsedUrl.hostname;
                if (elements.urlLink) {
                    elements.urlLink.textContent = url;
                    elements.urlLink.href = url;
                }
            } catch (error) {
                console.error("❌ Fout bij URL verwerken:", error);
                if (elements.siteName) elements.siteName.textContent = chrome.i18n.getMessage("invalidUrl") || "Ongeldige URL";
                if (elements.urlLink) {
                    elements.urlLink.textContent = "";
                    elements.urlLink.href = "#";
                }
            }
        } else {
            if (elements.siteName) elements.siteName.textContent = chrome.i18n.getMessage("invalidUrl") || "Ongeldige URL";
            if (elements.urlLink) {
                elements.urlLink.textContent = "";
                elements.urlLink.href = "#";
            }
        }

        // **Risico-classificatie**
        const riskValue = Number(risk) || 0; // Fallback naar 0 als niet numeriek
        let severityText = chrome.i18n.getMessage("unknownRisk") || "⚠️ Onbekend risico";
        let severityColor = "gray";

        if (riskValue >= 10) {
            severityText = chrome.i18n.getMessage("highRisk") || "🔴 Hoog risico: zeer gevaarlijk!";
            severityColor = "red";
        } else if (riskValue >= 4) {
            severityText = chrome.i18n.getMessage("mediumRisk") || "🟠 Medium risico: wees voorzichtig.";
            severityColor = "orange";
        } else {
            severityText = chrome.i18n.getMessage("lowRisk") || "🟢 Laag risico: waarschijnlijk veilig.";
            severityColor = "green";
        }

        if (elements.severityText) {
            elements.severityText.textContent = severityText;
            elements.severityText.style.color = severityColor;
        }

        // **Redenenlijst genereren**
        if (elements.reasonList) {
            elements.reasonList.innerHTML = ""; // Reset lijst
            if (!Array.isArray(reasons) || reasons.length === 0) {
                const li = document.createElement('li');
                li.textContent = chrome.i18n.getMessage("noSuspiciousFeatures") || "✅ Geen verdachte kenmerken.";
                elements.reasonList.appendChild(li);
            } else {
                reasons.forEach(reason => {
                    if (typeof reason !== 'string') return; // Skip ongeldige redenen
                    const li = document.createElement('li');
                    const [key, ...extraInfo] = reason.split(": ");
                    const translatedMessage = chrome.i18n.getMessage(key);
                    li.textContent = translatedMessage
                        ? (extraInfo.length > 0 ? `${translatedMessage} (${extraInfo.join(": ")})` : translatedMessage)
                        : `⚠️ ${reason}`;
                    elements.reasonList.appendChild(li);
                });
            }
        }

        // **Advies tonen**
        if (elements.advice) {
            elements.advice.textContent = chrome.i18n.getMessage("adviceCheckUrl") || "🔍 Open deze link alleen als je zeker weet dat het veilig is.";
        }
    }

    // **Functie om site-status op te halen met retry-logica**
    async function getSiteStatus() {
        try {
            const { currentSiteStatus } = await chrome.storage.local.get("currentSiteStatus");
            console.log("currentSiteStatus:", currentSiteStatus);
            const requiredKeys = ['isSafe', 'reasons', 'risk', 'url'];
            if (currentSiteStatus && typeof currentSiteStatus === 'object' && requiredKeys.every(key => key in currentSiteStatus)) {
                updateSiteStatus(currentSiteStatus);
            } else if (retryCount < maxRetries) {
                retryCount++;
                await delay(1000); // Wacht 1 seconde
                await getSiteStatus(); // Recursieve oproep
            } else if (elements.severityText) {
                elements.severityText.textContent = chrome.i18n.getMessage("siteStatusNotAvailable") || "⚠️ Site-status niet beschikbaar.";
            }
        } catch (error) {
            console.error("❌ Fout bij ophalen van site-status:", error);
            if (retryCount < maxRetries) {
                retryCount++;
                await delay(1000);
                await getSiteStatus();
            } else if (elements.severityText) {
                elements.severityText.textContent = chrome.i18n.getMessage("siteStatusNotAvailable") || "⚠️ Site-status niet beschikbaar.";
            }
        }
    }

    // **Initiële oproep om de status op te halen**
    await getSiteStatus();

    // **Luister naar veranderingen in chrome.storage.local**
    const storageListener = (changes, namespace) => {
        if (namespace === "local" && changes.currentSiteStatus && changes.currentSiteStatus.newValue) {
            updateSiteStatus(changes.currentSiteStatus.newValue);
        }
    };
    chrome.storage.onChanged.addListener(storageListener);

    // **Cleanup bij sluiten van de pop-up**
    window.addEventListener('unload', () => {
        chrome.storage.onChanged.removeListener(storageListener);
    });
});