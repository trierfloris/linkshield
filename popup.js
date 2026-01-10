// =============================
// popup.js - Volledig meertalige versie
// =============================

document.addEventListener('DOMContentLoaded', function () {
    // Elementverwijzingen - Basis
    const saveButton = document.getElementById('saveSettings');
    const backgroundSecurity = document.getElementById('backgroundSecurity');
    const integratedProtection = document.getElementById('integratedProtection');
    const lastRuleUpdateDisplay = document.getElementById('lastRuleUpdateDisplay');
    const confirmationMessage = document.getElementById('confirmationMessage');

    // Licentie-elementen
    const licenseStatusBox = document.getElementById('licenseStatusBox');
    const licenseTrialView = document.getElementById('licenseTrialView');
    const licenseExpiredView = document.getElementById('licenseExpiredView');
    const licensePremiumView = document.getElementById('licensePremiumView');
    const licenseTrialTitle = document.getElementById('licenseTrialTitle');
    const premiumEmail = document.getElementById('premiumEmail');
    const premiumBadge = document.getElementById('premiumBadge');
    const licenseKeyInput = document.getElementById('licenseKeyInput');
    const activateLicenseBtn = document.getElementById('activateLicenseBtn');
    const licenseErrorMsg = document.getElementById('licenseErrorMsg');

    // Trial status cache
    let trialStatus = null;

    // -------------------------------
    // i18n Hulpfuncties
    // -------------------------------

    /**
     * Haalt een vertaling op met optionele placeholders
     * @param {string} key - i18n sleutel
     * @param {Array} substitutions - Optionele waarden voor placeholders
     * @returns {string}
     */
    function getMessage(key, substitutions = []) {
        return chrome.i18n.getMessage(key, substitutions) || key;
    }

    /**
     * Stelt tekst in voor een element met fallback
     * @param {string} id - Element ID
     * @param {string} messageKey - i18n sleutel
     * @param {Array} substitutions - Optionele placeholders
     */
    function setText(id, messageKey, substitutions = []) {
        const element = document.getElementById(id);
        if (element) {
            element.textContent = getMessage(messageKey, substitutions);
        }
    }

    /**
     * Stelt placeholder attribuut in voor een input element
     * @param {string} id - Element ID
     * @param {string} messageKey - i18n sleutel
     */
    function setPlaceholder(id, messageKey) {
        const element = document.getElementById(id);
        if (element) {
            element.placeholder = getMessage(messageKey);
        }
    }

    // -------------------------------
    // Vertalingen laden
    // -------------------------------
    function loadTranslations() {
        // Basis elementen
        setText('extName', 'extNameFull');
        setText('extDescription', 'extDescriptionFull');

        // Sectie titels en features
        setText('backgroundAnalysisTitle', 'backgroundAnalysisTitle');
        setText('backgroundAnalysisFeature', 'backgroundAnalysisFeature');
        setText('backgroundAnalysisDescription', 'backgroundAnalysisDescription');
        setText('integratedProtectionFeature', 'integratedProtectionFeature');
        setText('integratedProtectionDescription', 'integratedProtectionDescription');
        setText('premiumBadge', 'premiumBadge');

        // Knoppen
        setText('saveSettings', 'saveSettings');
        setText('activateLicenseBtn', 'licenseActivateButton');

        // Licentie - Trial view
        setText('licenseTrialSubtitle', 'licenseTrialSubtitle');
        setText('licenseUpgradeLink', 'licenseUpgradeLink');

        // Licentie - Expired view
        setText('licenseExpiredTitle', 'licenseExpiredTitle');
        setText('licenseExpiredSubtitle', 'licenseExpiredSubtitle');
        setText('licenseBenefitsLabel', 'licenseBenefitsLabel');
        setText('licenseBenefitsText', 'licenseBenefitsText');
        setText('licenseBuyLink', 'licenseBuyLink');
        setPlaceholder('licenseKeyInput', 'licenseKeyPlaceholder');

        // Licentie - Premium view
        setText('licensePremiumTitle', 'licensePremiumTitle');
        setText('premiumEmail', 'licensePremiumSubtitle');
        setText('manageSubscriptionText', 'manageSubscription');
        setText('manageSubscriptionTooltip', 'manageSubscriptionTooltip');

        // Debug panel
        setText('debugModeTitle', 'debugModeTitle');
        setText('debugTrial30', 'debugTrial30');
        setText('debugTrial3', 'debugTrial3');
        setText('debugExpired', 'debugExpired');
        setText('debugPremium', 'debugPremium');
        setText('debugReset', 'debugReset');
    }

    // -------------------------------
    // Centrale foutafhandeling
    // -------------------------------
    function handleError(error, context) {
        console.error(`[${context}] ${error.message}`, error);
        showConfirmationMessage(getMessage('errorOccurred'), 'red');
    }

    // -------------------------------
    // Proefperiode en UI-hulpfuncties
    // -------------------------------

    /**
     * Haalt de proefperiode status op
     */
    async function getTrialStatus() {
        if (trialStatus) return trialStatus;

        try {
            const response = await new Promise((resolve, reject) => {
                chrome.runtime.sendMessage({ action: 'checkTrialStatus' }, (response) => {
                    if (chrome.runtime.lastError) {
                        reject(chrome.runtime.lastError);
                    } else if (response) {
                        resolve(response);
                    } else {
                        reject(new Error('No response from background'));
                    }
                });
            });
            trialStatus = response;
            return response;
        } catch (error) {
            console.warn('[Popup] Background unavailable, checking storage directly:', error.message);
        }

        // Fallback: check storage direct
        try {
            const data = await chrome.storage.sync.get(['installDate', 'trialDays', 'licenseValid']);

            if (data.licenseValid === true) {
                trialStatus = { isActive: false, daysRemaining: 0, isExpired: false, hasLicense: true };
                return trialStatus;
            }

            const TRIAL_DAYS = data.trialDays || 30;
            const MS_PER_DAY = 24 * 60 * 60 * 1000;

            if (!data.installDate) {
                await chrome.storage.sync.set({ installDate: Date.now(), trialDays: TRIAL_DAYS });
                trialStatus = { isActive: true, daysRemaining: TRIAL_DAYS, isExpired: false, hasLicense: false };
                return trialStatus;
            }

            const daysSinceInstall = Math.floor((Date.now() - data.installDate) / MS_PER_DAY);
            const daysRemaining = Math.max(0, TRIAL_DAYS - daysSinceInstall);
            const isExpired = daysRemaining <= 0;

            trialStatus = {
                isActive: !isExpired,
                daysRemaining: daysRemaining,
                isExpired: isExpired,
                hasLicense: false
            };
            return trialStatus;
        } catch (storageError) {
            console.error('[Popup] Storage check failed:', storageError);
            return { isActive: true, daysRemaining: 30, isExpired: false, hasLicense: false };
        }
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

    /**
     * Update de licentie-UI gebaseerd op trial status
     */
    async function updateUIForTrialPeriod() {
        const status = await getTrialStatus();
        const hasAccess = status.hasLicense || status.isActive;
        const isExpiredWithoutLicense = !status.isActive && !status.hasLicense;

        // Checkbox status forceren bij verlopen trial
        if (backgroundSecurity) {
            backgroundSecurity.disabled = !hasAccess;

            // Forceer checkbox UIT bij verlopen trial zonder licentie
            if (isExpiredWithoutLicense) {
                backgroundSecurity.checked = false;
                // Ook opslaan in storage om consistentie te garanderen
                chrome.storage.sync.set({ backgroundSecurity: false });
            }
        }

        // Reset alle views
        if (licenseTrialView) licenseTrialView.style.display = 'none';
        if (licenseExpiredView) licenseExpiredView.style.display = 'none';
        if (licensePremiumView) licensePremiumView.style.display = 'none';

        if (status.hasLicense) {
            // Premium actief
            if (licenseStatusBox) licenseStatusBox.className = 'license-status-box premium';
            if (licensePremiumView) licensePremiumView.style.display = 'block';
            if (premiumBadge) premiumBadge.style.display = 'inline';

            // Toon email indien beschikbaar
            const data = await chrome.storage.sync.get(['licenseEmail']);
            if (premiumEmail && data.licenseEmail) {
                premiumEmail.textContent = data.licenseEmail;
            }
        } else if (status.isActive) {
            // Trial actief
            if (licenseStatusBox) licenseStatusBox.className = 'license-status-box trial';
            if (licenseTrialView) licenseTrialView.style.display = 'block';
            if (licenseTrialTitle) {
                licenseTrialTitle.textContent = getMessage('licenseTrialTitle', [status.daysRemaining.toString()]);
            }
            if (premiumBadge) premiumBadge.style.display = 'none';
        } else {
            // Trial verlopen - STRIKTE RESTRICTIES
            if (licenseStatusBox) licenseStatusBox.className = 'license-status-box expired';
            if (licenseExpiredView) licenseExpiredView.style.display = 'block';

            // Premium badge duidelijk zichtbaar om upgrade te stimuleren
            if (premiumBadge) {
                premiumBadge.style.display = 'inline';
                premiumBadge.style.color = '#dc2626'; // Rode kleur voor urgentie
                premiumBadge.style.fontWeight = 'bold';
            }
        }
    }

    // -------------------------------
    // Instellingen initialiseren
    // -------------------------------
    async function initializeSettings() {
        try {
            let result = await chrome.storage.sync.get(['backgroundSecurity', 'integratedProtection']);
            result = result || {};

            if (typeof result !== "object" || !("backgroundSecurity" in result) || !("integratedProtection" in result)) {
                result = { backgroundSecurity: false, integratedProtection: false };
            }

            if (backgroundSecurity) backgroundSecurity.checked = result.backgroundSecurity;
            if (integratedProtection) integratedProtection.checked = result.integratedProtection;

            await updateUIForTrialPeriod();
        } catch (error) {
            handleError(error, "initializeSettings");
        }
    }

    async function displayLastRuleUpdate() {
        try {
            const { lastRuleUpdate } = await chrome.storage.local.get('lastRuleUpdate');
            if (lastRuleUpdate && lastRuleUpdateDisplay) {
                const locale = chrome.i18n.getUILanguage() || 'en-US';
                lastRuleUpdateDisplay.innerHTML = getMessage("lastRuleUpdate") +
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
                lastRuleUpdateDisplay.textContent = getMessage("lastRuleUpdateNone");
            }
        } catch (error) {
            handleError(error, "displayLastRuleUpdate");
        }
    }

    // -------------------------------
    // Save Button Handler
    // -------------------------------
    if (saveButton) {
        saveButton.addEventListener('click', async function () {
            // Haal actuele trial status op voor beveiliging
            const status = await getTrialStatus();
            const isExpiredWithoutLicense = !status.isActive && !status.hasLicense;

            // Bepaal backgroundSecurity waarde met bescherming tegen manipulatie
            let backgroundSecurityValue = backgroundSecurity ? backgroundSecurity.checked : false;

            // BEVEILIGING: Forceer false bij verlopen trial zonder licentie
            // Dit voorkomt dat gebruikers via HTML manipulatie de beveiliging omzeilen
            if (isExpiredWithoutLicense && backgroundSecurityValue === true) {
                backgroundSecurityValue = false;
                console.warn('[Popup] Poging om backgroundSecurity in te schakelen zonder geldige licentie geblokkeerd');
            }

            const settings = {
                backgroundSecurity: backgroundSecurityValue,
                integratedProtection: integratedProtection ? integratedProtection.checked : false,
            };

            try {
                await chrome.storage.sync.set(settings);
                showConfirmationMessage(getMessage("settingsSaved"));
            } catch (error) {
                handleError(error, "saveSettings");
            }
        });
    }

    // -------------------------------
    // Lemon Squeezy Error Vertaling
    // -------------------------------

    /**
     * Vertaalt Lemon Squeezy API foutmeldingen via i18n
     */
    function translateLicenseError(errorMessage) {
        if (!errorMessage) return getMessage('licenseErrorUnknown');

        // Mapping van Lemon Squeezy errors naar i18n keys
        const errorKeyMap = {
            // Lemon Squeezy specifieke foutmeldingen
            'license key was not found': 'licenseErrorNotFound',
            'license key not found': 'licenseErrorNotFound',
            'has been disabled': 'licenseErrorDisabled',
            'has expired': 'licenseErrorExpired',
            'activation limit': 'licenseErrorActivationLimit',
            'instance not found': 'licenseErrorInstanceNotFound',
            'invalid': 'licenseErrorInvalid',
            // Generieke netwerkfouten
            'network': 'licenseErrorNetwork',
            'timeout': 'licenseErrorNetwork',
            'fetch': 'licenseErrorNetwork'
        };

        const lowerError = errorMessage.toLowerCase();

        // Zoek gedeeltelijke match (case-insensitive)
        for (const [pattern, key] of Object.entries(errorKeyMap)) {
            if (lowerError.includes(pattern.toLowerCase())) {
                const translated = getMessage(key);
                // Als i18n key niet bestaat, gebruik fallback
                return translated !== key ? translated : errorMessage;
            }
        }

        // Fallback: originele foutmelding
        return errorMessage;
    }

    // -------------------------------
    // Licentie Activatie Handler
    // -------------------------------
    if (activateLicenseBtn && licenseKeyInput) {
        activateLicenseBtn.addEventListener('click', async function () {
            const licenseCode = licenseKeyInput.value.trim();

            if (!licenseCode) {
                if (licenseErrorMsg) {
                    licenseErrorMsg.textContent = getMessage('licenseEmptyError');
                    licenseErrorMsg.style.display = 'block';
                }
                return;
            }

            // Loading state
            activateLicenseBtn.textContent = getMessage('licenseActivating');
            activateLicenseBtn.disabled = true;
            licenseKeyInput.disabled = true;
            if (licenseErrorMsg) licenseErrorMsg.style.display = 'none';

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

                activateLicenseBtn.textContent = getMessage('licenseActivateButton');
                activateLicenseBtn.disabled = false;
                licenseKeyInput.disabled = false;

                if (!response || !response.success) {
                    if (licenseErrorMsg) {
                        licenseErrorMsg.textContent = translateLicenseError(response?.error);
                        licenseErrorMsg.style.display = 'block';
                    }
                } else {
                    trialStatus = null;
                    showConfirmationMessage(getMessage('licenseActivatedSuccess'), 'green', 4000);
                    await updateUIForTrialPeriod();
                }
            } catch (error) {
                activateLicenseBtn.textContent = getMessage('licenseActivateButton');
                activateLicenseBtn.disabled = false;
                licenseKeyInput.disabled = false;
                if (licenseErrorMsg) {
                    licenseErrorMsg.textContent = getMessage('licenseConnectionError');
                    licenseErrorMsg.style.display = 'block';
                }
                console.error('[Popup] License validation error:', error);
            }
        });

        // Enter key support
        licenseKeyInput.addEventListener('keypress', function (e) {
            if (e.key === 'Enter') {
                activateLicenseBtn.click();
            }
        });
    }

    // -------------------------------
    // Initialisatie
    // -------------------------------
    (async function initializePopup() {
        loadTranslations();
        if (confirmationMessage) confirmationMessage.style.display = 'none';

        await initializeSettings();
        await displayLastRuleUpdate();
    })();
});

// Containerbreedte instellen
const container = document.querySelector('.container');
if (container) {
    container.style.width = "280px";
}

// =============================
// SECURITY: Debug Panel UITGESCHAKELD voor productie
// =============================
// Debug functionaliteit is verwijderd om security risico's te voorkomen.
// Gebruikers kunnen niet langer trial/premium status manipuleren.
// Voor development, gebruik een aparte development build met debug features.
