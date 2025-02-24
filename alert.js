document.addEventListener('DOMContentLoaded', () => {
    console.log("🚀 Alert.js geladen!");

    const loadingMessage = chrome.i18n.getMessage("loadingMessage") || "Een moment, het systeem voert controles uit...";
    const maxRetries = 5;
    let retryCount = 0;

    document.querySelectorAll("[data-i18n]").forEach(element => {
        const messageKey = element.getAttribute("data-i18n");
        if (!messageKey) return;
        element.textContent = chrome.i18n.getMessage(messageKey) || loadingMessage;
    });

    function updateSiteStatus(status) {
        if (!status) {
            document.getElementById('severity-text').textContent = chrome.i18n.getMessage("cannotRetrieveSiteStatus") || "⚠️ Kan site-status niet ophalen.";
            if (retryCount < maxRetries) {
                retryCount++;
                setTimeout(getSiteStatus, 1000); // Probeer opnieuw na 1 seconde
            }
            return;
        }

        console.log("✅ Site-status ontvangen:", status);
        const { isSafe, reasons, risk, url } = status;

        try {
            document.getElementById('site-name').textContent = new URL(url).hostname;
            document.getElementById('url-link').textContent = url;
            document.getElementById('url-link').href = url;
        } catch (error) {
            console.error("❌ Fout bij URL verwerken:", error);
        }

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

        const reasonList = document.getElementById('reason-list');
        reasonList.innerHTML = "";

        if (Array.isArray(reasons) && reasons.length > 0) {
            reasons.forEach(reason => {
                const li = document.createElement('li');
                li.textContent = chrome.i18n.getMessage(reason) || `⚠️ ${reason}`;
                reasonList.appendChild(li);
            });
        } else {
            reasonList.innerHTML = `<li>${chrome.i18n.getMessage("noSuspiciousFeatures") || "✅ Geen verdachte kenmerken."}</li>`;
        }

        document.getElementById('advice').textContent = chrome.i18n.getMessage("adviceCheckUrl") ||
            "🔍 Open deze link alleen als je zeker weet dat het veilig is.";
    }

    function getSiteStatus() {
        chrome.storage.local.get("currentSiteStatus", ({ currentSiteStatus }) => {
            if (currentSiteStatus) {
                updateSiteStatus(currentSiteStatus);
            } else {
                document.getElementById('severity-text').textContent = chrome.i18n.getMessage("siteStatusNotAvailable") || "⚠️ Site-status niet beschikbaar.";
            }
        });
    }

    getSiteStatus();

    chrome.storage.onChanged.addListener((changes, namespace) => {
        if (namespace === "local" && changes.currentSiteStatus) {
            updateSiteStatus(changes.currentSiteStatus.newValue);
        }
    });
});