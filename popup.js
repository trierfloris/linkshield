// =============================
// popup.js - Aangepaste Versie
// =============================

document.addEventListener('DOMContentLoaded', function () {
    // Elementreferenties
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
    const licenseStatus = chrome.i18n.getMessage('licenseStatus'); // "License:" label
    const licenseFreemium = chrome.i18n.getMessage('licenseFreemium'); // "Freemium" label

    // Free trial end date (hard-coded)
    const FREE_END_DATE = new Date('2025-03-01T23:59:59');

    // -------------------------------
    // Helper Functies
    // -------------------------------

    /**
     * Centrale foutafhandelingsfunctie.
     * @param {Error} error - De fout.
     * @param {string} context - Context waarin de fout optrad.
     */
    function handleError(error, context) {
        console.error(`[${context}] ${error.message}`, error);
    }

    /**
     * Update de tekst van een element als het bestaat, met fallback.
     * @param {string} id - De ID van het element.
     * @param {string} messageKey - De i18n key.
     * @param {string} [fallback] - Een optionele fallbacktekst.
     */
    function setText(id, messageKey, fallback = '') {
        const element = document.getElementById(id);
        if (element) {
            const translated = chrome.i18n.getMessage(messageKey) || fallback;
            element.textContent = translated;
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
        setText('licenseStatus', 'licenseStatus');
        setText('licenseIndicator', 'licenseFreemium');
    }

    // -------------------------------
    // Free Trial en UI Helpers
    // -------------------------------

    const isFreeTrialPeriod = () => new Date() <= FREE_END_DATE;

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
        if (backgroundSecurity) {
            backgroundSecurity.disabled = !isFreeTrial;
        }
        if (showLicenseForm) {
            showLicenseForm.disabled = isFreeTrial;
        }
        if (activationMessage) {
            activationMessage.style.display = isFreeTrial ? 'none' : 'block';
        }
    }

    // -------------------------------
    // Instellingen initialiseren
    // -------------------------------

    /**
     * Valideert of de storage data het juiste format heeft.
     * @param {object} data
     * @returns {boolean}
     */
    function validateStorageData(data) {
        return typeof data === "object" &&
            "backgroundSecurity" in data &&
            typeof data.backgroundSecurity === "boolean" &&
            "integratedProtection" in data &&
            typeof data.integratedProtection === "boolean";
    }

    async function initializeSettings() {
        try {
            let result = await chrome.storage.sync.get(['backgroundSecurity', 'integratedProtection']);
            result = result || {};

            if (!validateStorageData(result)) {
                console.warn("Invalid storage data found. Using default settings.");
                result = { backgroundSecurity: false, integratedProtection: false };
            }

            if (backgroundSecurity) {
                backgroundSecurity.checked = result.backgroundSecurity;
            }
            if (integratedProtection) {
                integratedProtection.checked = result.integratedProtection;
            }

            updateUIForTrialPeriod(isFreeTrialPeriod());
        } catch (error) {
            handleError(error, "initializeSettings");
        }
    }

    async function displayLastRuleUpdate() {
        try {
            const data = await chrome.storage.local.get('lastRuleUpdate');
            if (data.lastRuleUpdate && lastRuleUpdateDisplay) {
                lastRuleUpdateDisplay.textContent = chrome.i18n.getMessage("lastRuleUpdate") +
                    new Intl.DateTimeFormat('nl-NL', {
                        day: '2-digit',
                        month: 'long',
                        year: 'numeric',
                        hour: '2-digit',
                        minute: '2-digit',
                        second: '2-digit',
                        hour12: false,
                        timeZone: 'Europe/Amsterdam'
                    }).format(new Date(data.lastRuleUpdate));
            } else if (lastRuleUpdateDisplay) {
                lastRuleUpdateDisplay.textContent = chrome.i18n.getMessage("lastRuleUpdateNone");
            }
        } catch (error) {
            handleError(error, "displayLastRuleUpdate");
        }
    }

    // -------------------------------
    // Popup UI Logica
    // -------------------------------

    if (saveButton) {
        saveButton.addEventListener('click', async function () {
            const settings = {
                backgroundSecurity: backgroundSecurity ? backgroundSecurity.checked : false,
                integratedProtection: integratedProtection ? integratedProtection.checked : false,
            };

            if (!validateStorageData(settings)) {
                console.error("Attempt to save invalid settings:", settings);
                showConfirmationMessage(chrome.i18n.getMessage("invalidSettings"), "red");
                return;
            }

            try {
                await chrome.storage.sync.set(settings);
                showConfirmationMessage(chrome.i18n.getMessage("settingsSaved"));
            } catch (error) {
                handleError(error, "saveSettings");
                showConfirmationMessage(chrome.i18n.getMessage("settingsSaveError"), 'red');
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
                            if (chrome.runtime.lastError) {
                                reject(chrome.runtime.lastError);
                            } else {
                                resolve(response);
                            }
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
                    updatePremiumFeatures(true);
                    licenseForm.style.display = 'none';
                    showLicenseForm.style.display = 'block';
                }
            } catch (error) {
                validateButton.textContent = chrome.i18n.getMessage("validateButton");
                validateButton.disabled = false;
                handleError(error, "validateLicenseButton");
                showConfirmationMessage(chrome.i18n.getMessage("licenseError"), 'red', 5000);
            }
        });
    }

    function updatePremiumFeatures(isLicensed) {
        const upgradePrompt = document.getElementById('upgradePrompt');
        const licenseSection = document.getElementById('licenseSection');

        if (isLicensed || isFreeTrialPeriod()) {
            if (premiumFeature) premiumFeature.style.display = 'block';
            if (upgradePrompt) upgradePrompt.style.display = 'none';
            if (licenseSection) licenseSection.style.display = 'none';
        } else {
            if (premiumFeature) premiumFeature.style.display = 'none';
            if (upgradePrompt) upgradePrompt.style.display = 'block';
            if (licenseSection) licenseSection.style.display = 'block';
        }
    }

    async function updateLicenseIndicator() {
        const licenseIndicator = document.getElementById('licenseIndicator');
        const licenseImageContainer = document.getElementById('licenseImageContainer');

        if (licenseImageContainer) {
            licenseImageContainer.innerHTML = '';
        }

        const { license } = await chrome.storage.sync.get('license');
        if (license && license.valid) {
            if (licenseIndicator) {
                licenseIndicator.textContent = `License: ${license.code}`;
            }
        } else {
            if (licenseIndicator) {
                licenseIndicator.textContent = 'License: Freemium';
            }

            if (licenseImageContainer) {
                const link = document.createElement('a');
                link.href = 'https://buymeacoffee.com/linkshield.nl';
                link.target = '_blank';
                link.rel = 'noopener noreferrer';

                const img = document.createElement('img');
                img.src = 'icons/buymeacoffee.png';
                img.alt = 'Support with Buy Me a Coffee';
                img.style.width = '100px';
                img.style.marginTop = '10px';

                link.appendChild(img);
                licenseImageContainer.appendChild(link);
            }
        }
    }

    chrome.storage.onChanged.addListener((changes, namespace) => {
        if (namespace === 'local' && changes.lastRuleUpdate && lastRuleUpdateDisplay) {
            const newValue = changes.lastRuleUpdate.newValue;
            lastRuleUpdateDisplay.textContent = newValue
                ? chrome.i18n.getMessage("lastRuleUpdate") + new Date(newValue).toLocaleString()
                : chrome.i18n.getMessage("lastRuleUpdateNone");
        }
    });

    (async function initializePopup() {
        loadTranslations();
        if (confirmationMessage) confirmationMessage.style.display = 'none';
        if (premiumFeature) premiumFeature.style.display = 'none';
        if (licenseForm) licenseForm.style.display = 'none';

        await initializeSettings();
        await displayLastRuleUpdate();
    })();

});

// Stel de containerbreedte in als het element bestaat
const container = document.querySelector('.container');
if (container) {
    container.style.width = "225px";
}
