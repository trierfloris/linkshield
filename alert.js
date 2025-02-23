document.addEventListener('DOMContentLoaded', () => {
    console.log("🚀 Alert.js geladen!");

    const loadingMessage = "One moment, the system is doing some checks...";
    const maxRetries = 5;
    let retryCount = 0;

    document.querySelectorAll("[data-i18n]").forEach(element => {
        const messageKey = element.getAttribute("data-i18n");
        if (!messageKey) return;
        element.textContent = chrome.i18n.getMessage(messageKey) || loadingMessage;
    });

    function updateSiteStatus(status) {
        if (!status) {
            //console.error("❌ Geen site-status ontvangen. Mogelijk is de extensie niet correct geladen.");
            document.getElementById('severity-text').textContent = "⚠️ Kan site-status niet ophalen.";
            if (retryCount < maxRetries) {
                retryCount++;
                //console.log(`🔄 Opnieuw proberen (${retryCount}/${maxRetries})...`);
                setTimeout(getSiteStatus, 1000); // Probeer het opnieuw na 1 seconde
            }
            return;
        }

        //console.log("✅ Site-status ontvangen:", status);
        const { isSafe, reasons, url } = status;

        try {
            document.getElementById('site-name').textContent = new URL(url).hostname;
            document.getElementById('url-link').textContent = url;
            document.getElementById('url-link').href = url;
        } catch (error) {
            //console.error("❌ Fout bij URL verwerken:", error);
        }

        if (!isSafe) {
            document.getElementById('severity-text').textContent = chrome.i18n.getMessage("severityMediumRisk") ||
                "⚠️ Medium risico: mogelijk onveilig. Wees voorzichtig.";
            document.getElementById('severity-text').style.color = "orange";

            const reasonList = document.getElementById('reason-list');
            reasonList.innerHTML = "";

            if (Array.isArray(reasons) && reasons.length > 0) {
                reasons.forEach(reason => {
                    //console.log("📌 Reden ontvangen:", reason);
                    const li = document.createElement('li');
                    li.textContent = chrome.i18n.getMessage(reason) || `⚠️ ${reason}`;
                    reasonList.appendChild(li);
                });
            } else {
                reasonList.innerHTML = "<li>✅ Geen verdachte kenmerken.</li>";
            }
        }

        document.getElementById('advice').textContent = chrome.i18n.getMessage("adviceCheckUrl") ||
            "🔍 Open deze link alleen als je zeker weet dat deze veilig is.";
    }

    function getSiteStatus() {
        chrome.storage.local.get("currentSiteStatus", ({ currentSiteStatus }) => {
            if (currentSiteStatus) {
                //console.log("📥 Status opgehaald:", currentSiteStatus);
                updateSiteStatus(currentSiteStatus);
            } else {
                //console.warn("⚠️ Geen site-status gevonden in chrome.storage.local.");
                document.getElementById('severity-text').textContent = "⚠️ Site-status niet beschikbaar.";
            }
        });
    }

    getSiteStatus();

    chrome.storage.onChanged.addListener((changes, namespace) => {
        if (namespace === "local" && changes.currentSiteStatus) {
            //console.log("🔄 Site-status bijgewerkt:", changes.currentSiteStatus.newValue);
            updateSiteStatus(changes.currentSiteStatus.newValue);
        }
    });
});
