// =============================
// popup.js - Versie met hard-coded FREE_END_DATE
// =============================

document.addEventListener('DOMContentLoaded', function () {
    // Elementverwijzingen
    const saveButton = document.getElementById('saveSettings');
    const showLicenseForm = document.getElementById('showLicenseForm');
    const licenseForm = document.getElementById('licenseForm');
    const validateButton = document.getElementById('validateButton');
    const licenseInput = document.getElementById('licenseInput');
    const licenseMessage = document.getElementById('licenseMessage');
    const backgroundSecurity = document.getElementById('backgroundSecurity');
    const integratedProtection = document.getElementById('integratedProtection');
    const lastRuleUpdateDisplay = document.getElementById('lastRuleUpdateDisplay');
    const confirmationMessage = document.getElementById('confirmationMessage');
    const premiumFeature = document.getElementById('premiumFeature');
    const activationMessage = document.getElementById('activationMessage');

    // Hard-coded einddatum voor de proefperiode
    const FREE_END_DATE = new Date('2026-01-01T23:59:59');

    // -------------------------------
    // Hulpfunctions
    // -------------------------------

    /**
     * Centrale foutafhandeling.
     * @param {Error} error - De fout.
     * @param {string} context - Context waarin de fout optrad.
     */
    function handleError(error, context) {
        console.error(`[${context}] ${error.message}`, error);
        showConfirmationMessage(chrome.i18n.getMessage("errorOccurred"), 'red');
    }

    /**
     * Tekst instellen van een element als het bestaat, met een fallback.
     * @param {string} id - Element-ID.
     * @param {string} messageKey - i18n-sleutel.
     * @param {string} [fallback] - Optionele fallback-tekst.
     */
    function setText(id, messageKey, fallback = '') {
        const element = document.getElementById(id);
        if (element) {
            element.textContent = chrome.i18n.getMessage(messageKey) || fallback;
        }
    }

    // -------------------------------
    // Vertalingen laden
    // -------------------------------
    function loadTranslations() {
        setText('extName', 'extName');
        setText('extDescription', 'extDescription');
        setText('backgroundAnalysisTitle', 'backgroundAnalysisTitle');
        setText('backgroundAnalysisFeature', 'backgroundAnalysisFeature');
        setText('backgroundAnalysisDescription', 'backgroundAnalysisDescription');
        setText('integratedProtectionFeature', 'integratedProtectionFeature');
        setText('integratedProtectionDescription', 'integratedProtectionDescription');
        setText('premiumFeatureMessage', 'premiumFeatureMessage');
        setText('upgradeMessage', 'upgradeMessage');
        setText('saveSettings', 'saveSettings');
        setText('confirmationMessage', 'confirmationMessage');
        setText('licenseLabel', 'licenseLabel');
        setText('validateButton', 'validateButton');
        setText('licenseIndicator', 'licenseFreemium');
    }

    // -------------------------------
    // Proefperiode en UI-hulpfuncties
    // -------------------------------

    function isFreeTrialPeriod() {
        return new Date() <= FREE_END_DATE;
    }

    function showConfirmationMessage(message, color = 'green', duration = 3000) {
        if (confirmationMessage) {
            confirmationMessage.textContent = message;
            confirmationMessage.style.display = 'block';
            confirmationMessage.style.color = color;
            setTimeout(() => {
                confirmationMessage.style.display = 'none';
            }, duration);
        }
    }

    function updateUIForTrialPeriod(isFreeTrial) {
        if (backgroundSecurity) backgroundSecurity.disabled = !isFreeTrial;
        if (showLicenseForm) showLicenseForm.disabled = isFreeTrial;
        if (activationMessage) activationMessage.style.display = isFreeTrial ? 'none' : 'block';
    }

    // -------------------------------
    // Instellingen initialiseren
    // -------------------------------

    async function initializeSettings() {
        try {
            let result = await chrome.storage.sync.get(['backgroundSecurity', 'integratedProtection']);
            result = result || {};

            if (typeof result !== "object" || !("backgroundSecurity" in result) || !("integratedProtection" in result)) {
                console.warn("Ongeldige opslagdata gevonden. Standaardinstellingen worden gebruikt.");
                result = { backgroundSecurity: false, integratedProtection: false };
            }

            if (backgroundSecurity) backgroundSecurity.checked = result.backgroundSecurity;
            if (integratedProtection) integratedProtection.checked = result.integratedProtection;

            const isTrial = isFreeTrialPeriod();
            updateUIForTrialPeriod(isTrial);
        } catch (error) {
            handleError(error, "initializeSettings");
        }
    }

    async function displayLastRuleUpdate() {
        try {
            const { lastRuleUpdate } = await chrome.storage.local.get('lastRuleUpdate');
            if (lastRuleUpdate && lastRuleUpdateDisplay) {
                const locale = chrome.i18n.getUILanguage() || 'en-US';
                lastRuleUpdateDisplay.innerHTML = chrome.i18n.getMessage("lastRuleUpdate") +
                    "<br>" +
                    new Intl.DateTimeFormat(locale, {
                        day: '2-digit',
                        month: 'long',
                        year: 'numeric',
                        hour: '2-digit',
                        minute: '2-digit',
                        second: '2-digit',
                        hour12: false,
                        timeZone: 'Europe/Amsterdam'
                    }).format(new Date(lastRuleUpdate));
            } else if (lastRuleUpdateDisplay) {
                lastRuleUpdateDisplay.textContent = chrome.i18n.getMessage("lastRuleUpdateNone");
            }
        } catch (error) {
            handleError(error, "displayLastRuleUpdate");
        }
    }

    // -------------------------------
    // Popup UI-logica
    // -------------------------------

    if (saveButton) {
        saveButton.addEventListener('click', async function () {
            const settings = {
                backgroundSecurity: backgroundSecurity ? backgroundSecurity.checked : false,
                integratedProtection: integratedProtection ? integratedProtection.checked : false,
            };

            try {
                await chrome.storage.sync.set(settings);
                showConfirmationMessage(chrome.i18n.getMessage("settingsSaved"));
            } catch (error) {
                handleError(error, "saveSettings");
            }
        });
    }

    if (showLicenseForm && licenseForm) {
        showLicenseForm.addEventListener('click', function () {
            this.style.display = 'none';
            licenseForm.style.display = 'block';
        });
    }

    if (validateButton && licenseInput && licenseForm && showLicenseForm) {
        validateButton.addEventListener('click', async function () {
            validateButton.textContent = chrome.i18n.getMessage("validatingLicense");
            validateButton.disabled = true;

            const licenseCode = licenseInput.value;
            try {
                const response = await new Promise((resolve, reject) => {
                    chrome.runtime.sendMessage(
                        { type: 'validateLicense', licenseKey: licenseCode },
                        (response) => {
                            if (chrome.runtime.lastError) reject(chrome.runtime.lastError);
                            else resolve(response);
                        }
                    );
                });

                validateButton.textContent = chrome.i18n.getMessage("validateButton");
                validateButton.disabled = false;

                if (!response || !response.success) {
                    showConfirmationMessage(chrome.i18n.getMessage("invalidLicense"), 'red', 5000);
                } else {
                    await chrome.storage.sync.set({ license: { valid: true, code: licenseCode } });
                    showConfirmationMessage(chrome.i18n.getMessage("licenseActivated"));
                    licenseForm.style.display = 'none';
                    showLicenseForm.style.display = 'block';
                }
            } catch (error) {
                validateButton.textContent = chrome.i18n.getMessage("validateButton");
                validateButton.disabled = false;
                handleError(error, "validateLicenseButton");
            }
        });
    }

    async function updateLicenseIndicator() {
        const licenseIndicator = document.getElementById('licenseIndicator');
        const { license } = await chrome.storage.sync.get('license');
        if (license && license.valid && licenseIndicator) {
            licenseIndicator.textContent = `License: ${license.code}`;
        } else if (licenseIndicator) {
            licenseIndicator.textContent = 'License: Freemium';
        }
    }

    (async function initializePopup() {
        loadTranslations();
        if (confirmationMessage) confirmationMessage.style.display = 'none';
        if (premiumFeature) premiumFeature.style.display = 'none';
        if (licenseForm) licenseForm.style.display = 'none';

        await initializeSettings();
        await displayLastRuleUpdate();
        await updateLicenseIndicator();
    })();
});

// Containerbreedte instellen
const container = document.querySelector('.container');
if (container) {
    container.style.width = "225px";
}