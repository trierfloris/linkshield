// =============================
// popup.js - Premium Business Card Edition
// =============================

document.addEventListener('DOMContentLoaded', function () {
    // Elements
    const statusCard = document.getElementById('statusCard');
    const statusIcon = document.getElementById('statusIcon');
    const statusTitle = document.getElementById('statusTitle');
    const statusSubText = document.getElementById('statusSubText');
    const premiumBadge = document.getElementById('premiumBadge');
    const trialProgress = document.getElementById('trialProgress');
    const ctaButton = document.getElementById('ctaButton');
    const ctaText = document.getElementById('ctaText');
    const ctaPrice = document.getElementById('ctaPrice');
    const divider = document.getElementById('divider');
    const licenseSection = document.getElementById('licenseSection');
    const licenseInput = document.getElementById('licenseInput');
    const activateBtn = document.getElementById('activateBtn');
    const activateBtnText = document.getElementById('activateBtnText');
    const spinner = document.getElementById('spinner');
    const licenseError = document.getElementById('licenseError');
    const premiumManagement = document.getElementById('premiumManagement');
    const premiumEmail = document.getElementById('premiumEmail');
    const manageBtn = document.getElementById('manageBtn');
    const manageBtnText = document.getElementById('manageBtnText');
    const transferBtn = document.getElementById('transferBtn');
    const transferBtnText = document.getElementById('transferBtnText');
    const deactivateConfirm = document.getElementById('deactivateConfirm');
    const deactivateText = document.getElementById('deactivateText');
    const cancelBtn = document.getElementById('cancelBtn');
    const confirmBtn = document.getElementById('confirmBtn');
    const sectionLabel = document.getElementById('sectionLabel');
    const toggle1Title = document.getElementById('toggle1Title');
    const toggle1Desc = document.getElementById('toggle1Desc');
    const toggle2Title = document.getElementById('toggle2Title');
    const toggle2Desc = document.getElementById('toggle2Desc');
    const backgroundSecurity = document.getElementById('backgroundSecurity');
    const integratedProtection = document.getElementById('integratedProtection');
    const toggle1Help = document.getElementById('toggle1Help');
    const toggle1Tooltip = document.getElementById('toggle1Tooltip');
    const tooltipTitle = document.getElementById('tooltipTitle');
    const tooltipFeature1 = document.getElementById('tooltipFeature1');
    const tooltipFeature2 = document.getElementById('tooltipFeature2');
    const tooltipFeature3 = document.getElementById('tooltipFeature3');
    const tooltipFeature4 = document.getElementById('tooltipFeature4');
    const tooltipFeature5 = document.getElementById('tooltipFeature5');
    const tooltipFeature6 = document.getElementById('tooltipFeature6');
    const tooltipFeature7 = document.getElementById('tooltipFeature7');
    const tooltipFeature8 = document.getElementById('tooltipFeature8');
    const tooltipFeature9 = document.getElementById('tooltipFeature9');
    const tooltipFeature10 = document.getElementById('tooltipFeature10');
    const tooltipFooter = document.getElementById('tooltipFooter');
    const premiumTag = document.getElementById('premiumTag');
    const liveBadge = document.getElementById('liveBadge');
    const footer = document.getElementById('footer');
    const toast = document.getElementById('toast');
    const licenseToggleLink = document.getElementById('licenseToggleLink');

    let trialStatus = null;
    let licenseExpanded = false;
    const TRIAL_DAYS = 30;

    // Icons
    const ICONS = {
        check: '<polyline points="20 6 9 17 4 12"/>',
        warning: '<path d="M10.29 3.86L1.82 18a2 2 0 0 0 1.71 3h16.94a2 2 0 0 0 1.71-3L13.71 3.86a2 2 0 0 0-3.42 0z"/><line x1="12" y1="9" x2="12" y2="13"/><line x1="12" y1="17" x2="12.01" y2="17"/>'
    };

    /**
     * Veilige i18n wrapper met null checks
     * @param {string} key - De i18n message key
     * @param {string} [fallback] - Optionele fallback waarde
     * @returns {string}
     */
    function msg(key, fallback) {
        try {
            if (typeof chrome !== 'undefined' && chrome.i18n && typeof chrome.i18n.getMessage === 'function') {
                const message = chrome.i18n.getMessage(key);
                return message || fallback || key;
            }
        } catch (e) {
            // Ignore - extension context might be invalidated
        }
        return fallback || key;
    }

    // Toast
    function showToast(message, duration = 2000) {
        toast.textContent = message;
        toast.classList.add('show');
        setTimeout(() => toast.classList.remove('show'), duration);
    }

    // Load translations
    function loadTranslations() {
        sectionLabel.textContent = msg('sectionProtection');
        toggle1Title.textContent = msg('backgroundAnalysisFeature');
        toggle1Desc.textContent = msg('backgroundAnalysisDescription');
        toggle2Title.textContent = msg('integratedProtectionFeature');
        toggle2Desc.textContent = msg('integratedProtectionDescription');
        toggle1Tooltip.textContent = msg('backgroundSecurityHelp');

        // Tooltip translations
        if (tooltipTitle) tooltipTitle.textContent = msg('tooltipTitle');
        if (tooltipFeature1) tooltipFeature1.childNodes[0].textContent = msg('tooltipFeature1');
        if (tooltipFeature2) tooltipFeature2.textContent = msg('tooltipFeature2');
        if (tooltipFeature3) tooltipFeature3.textContent = msg('tooltipFeature3');
        if (tooltipFeature4) tooltipFeature4.textContent = msg('tooltipFeature4');
        if (tooltipFeature5) tooltipFeature5.textContent = msg('tooltipFeature5');
        if (tooltipFeature6) tooltipFeature6.textContent = msg('tooltipFeature6');
        if (tooltipFeature7) tooltipFeature7.textContent = msg('tooltipFeature7');
        if (tooltipFeature8) {
            // Keep the NEW badge, only replace the text
            const newBadge = tooltipFeature8.querySelector('.new-badge');
            if (newBadge) {
                newBadge.textContent = msg('tooltipNewBadge');
                tooltipFeature8.firstChild.textContent = msg('tooltipFeature8') + ' ';
            } else {
                tooltipFeature8.textContent = msg('tooltipFeature8');
            }
        }
        if (tooltipFeature9) tooltipFeature9.textContent = msg('tooltipFeature9');
        if (tooltipFeature10) tooltipFeature10.textContent = msg('tooltipFeature10');
        if (tooltipFooter) tooltipFooter.textContent = msg('tooltipFooter');

        licenseInput.placeholder = msg('licenseKeyPlaceholder');
        activateBtnText.textContent = msg('licenseActivateShort');
        manageBtnText.textContent = msg('manageBtnText');
        transferBtnText.textContent = msg('transferBtnText');
        deactivateText.textContent = msg('licenseDeactivateConfirm');
        cancelBtn.textContent = msg('licenseDeactivateCancel');
        confirmBtn.textContent = msg('deactivateDeviceBtn');
    }

    // Get trial status
    async function getTrialStatus() {
        if (trialStatus) return trialStatus;

        try {
            const response = await new Promise((resolve, reject) => {
                chrome.runtime.sendMessage({ action: 'checkTrialStatus' }, (res) => {
                    if (chrome.runtime.lastError) reject(chrome.runtime.lastError);
                    else if (res) resolve(res);
                    else reject(new Error('No response'));
                });
            });
            trialStatus = response;
            return response;
        } catch (e) {
            console.warn('[Popup] Background unavailable:', e.message);
        }

        // Fallback
        try {
            const data = await chrome.storage.sync.get(['installDate', 'trialDays', 'licenseValid']);
            if (data.licenseValid === true) {
                trialStatus = { isActive: false, daysRemaining: 0, isExpired: false, hasLicense: true };
                return trialStatus;
            }
            const days = data.trialDays || TRIAL_DAYS;
            const MS_PER_DAY = 86400000;
            if (!data.installDate) {
                await chrome.storage.sync.set({ installDate: Date.now(), trialDays: days });
                trialStatus = { isActive: true, daysRemaining: days, isExpired: false, hasLicense: false };
                return trialStatus;
            }
            const daysSince = Math.floor((Date.now() - data.installDate) / MS_PER_DAY);
            const remaining = Math.max(0, days - daysSince);
            trialStatus = { isActive: remaining > 0, daysRemaining: remaining, isExpired: remaining <= 0, hasLicense: false };
            return trialStatus;
        } catch (e) {
            return { isActive: true, daysRemaining: TRIAL_DAYS, isExpired: false, hasLicense: false };
        }
    }

    // Update UI
    async function updateUI() {
        const status = await getTrialStatus();
        const hasAccess = status.hasLicense || status.isActive;

        // Toggle states
        backgroundSecurity.disabled = !hasAccess;

        if (status.hasLicense) {
            // === PREMIUM ===
            statusCard.className = 'status-card premium';
            statusIcon.innerHTML = ICONS.check;
            statusTitle.textContent = msg('statusProtected');
            statusSubText.textContent = msg('statusPremiumSub');

            // Hide help icon and PRO tag for premium users (they already have it)
            toggle1Help.style.display = 'none';
            premiumTag.classList.add('hidden');

            ctaButton.style.display = 'none';
            licenseToggleLink.classList.add('hidden');
            divider.classList.add('hidden');
            licenseSection.classList.remove('show');
            premiumManagement.classList.add('show');

            const data = await chrome.storage.sync.get(['licenseEmail']);
            premiumEmail.textContent = data.licenseEmail || '';

        } else if (status.isActive) {
            // === TRIAL ===
            statusCard.className = 'status-card trial';
            statusIcon.innerHTML = ICONS.check;
            statusTitle.textContent = msg('statusProtected');
            statusSubText.textContent = msg('statusTrialSub', [status.daysRemaining.toString()]);

            // Progress bar with dynamic color
            const progress = (status.daysRemaining / TRIAL_DAYS) * 100;
            trialProgress.style.width = progress + '%';

            // Change color based on days remaining: green > 5 days, orange <= 5 days
            if (status.daysRemaining <= 5) {
                trialProgress.style.background = 'linear-gradient(90deg, #f59e0b 0%, #fbbf24 100%)';
                statusCard.classList.add('urgent');
            } else {
                trialProgress.style.background = 'linear-gradient(90deg, #10b981 0%, #34d399 100%)';
                statusCard.classList.remove('urgent');
            }

            ctaButton.style.display = 'block';
            ctaButton.className = 'cta-button';
            ctaText.textContent = msg('ctaUpgradeText');
            ctaPrice.textContent = msg('ctaUpgradePrice');

            // Trial: compact view - hide license section by default, show toggle link
            licenseToggleLink.classList.remove('hidden');
            licenseToggleLink.textContent = msg('useLicenseKey') || 'Use license key';
            if (!licenseExpanded) {
                divider.classList.add('hidden');
                licenseSection.classList.remove('show');
            } else {
                divider.classList.remove('hidden');
                licenseSection.classList.add('show');
            }
            premiumManagement.classList.remove('show');

            // Show help icon and PRO tag for trial users to understand premium value
            toggle1Help.style.display = 'block';
            premiumTag.classList.remove('hidden');

        } else {
            // === EXPIRED ===
            statusCard.className = 'status-card expired';
            statusIcon.innerHTML = ICONS.warning;
            statusTitle.textContent = msg('statusExpired');
            statusSubText.textContent = msg('statusExpiredSub');

            trialProgress.style.width = '0%';

            ctaButton.style.display = 'block';
            ctaButton.className = 'cta-button red';
            ctaText.textContent = msg('ctaRenewText');
            ctaPrice.textContent = msg('ctaUpgradePrice');

            // Expired: show license section directly (more urgent to activate)
            licenseToggleLink.classList.add('hidden');
            divider.classList.remove('hidden');
            licenseSection.classList.add('show');
            premiumManagement.classList.remove('show');

            // Show help icon and PRO tag for expired users
            toggle1Help.style.display = 'block';
            premiumTag.classList.remove('hidden');

            backgroundSecurity.checked = false;
            await chrome.storage.sync.set({ backgroundSecurity: false });
        }
    }

    // Auto-save
    async function autoSave(key, value) {
        const status = await getTrialStatus();
        if (key === 'backgroundSecurity' && value && !(status.hasLicense || status.isActive)) {
            backgroundSecurity.checked = false;
            return;
        }
        try {
            await chrome.storage.sync.set({ [key]: value });
            showToast(msg('settingsSaved'));
        } catch (e) {
            showToast(msg('errorOccurred'));
        }
    }

    // Init settings
    async function initSettings() {
        try {
            const r = await chrome.storage.sync.get(['backgroundSecurity', 'integratedProtection']);
            backgroundSecurity.checked = r.backgroundSecurity || false;
            integratedProtection.checked = r.integratedProtection || false;
        } catch (e) {}
    }

    // Last update with dynamic Live badge
    async function displayLastUpdate() {
        try {
            const { lastRuleUpdate } = await chrome.storage.local.get('lastRuleUpdate');
            if (lastRuleUpdate) {
                const now = Date.now();
                const updateTime = new Date(lastRuleUpdate).getTime();
                const minutesAgo = Math.floor((now - updateTime) / 60000);

                // Show "Live" badge if updated within last 60 minutes
                if (minutesAgo <= 60) {
                    liveBadge.classList.add('show');
                    if (minutesAgo < 5) {
                        liveBadge.textContent = msg('liveNow') || 'Live';
                    } else {
                        liveBadge.textContent = msg('updatedMinAgo', [minutesAgo.toString()]) || `${minutesAgo}m ago`;
                    }
                } else {
                    liveBadge.classList.remove('show');
                }

                const d = new Intl.DateTimeFormat(chrome.i18n.getUILanguage() || 'en', {
                    day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit'
                }).format(new Date(lastRuleUpdate));
                footer.textContent = msg('lastRuleUpdate') + ' ' + d;
            }
        } catch (e) {}
    }

    // Error translation
    function translateError(err) {
        if (!err) return msg('licenseErrorUnknown');
        const l = err.toLowerCase();
        if (l.includes('not found')) return msg('licenseErrorNotFound');
        if (l.includes('disabled')) return msg('licenseErrorDisabled');
        if (l.includes('expired')) return msg('licenseErrorExpired');
        if (l.includes('activation limit')) return msg('licenseErrorActivationLimit');
        if (l.includes('network') || l.includes('fetch')) return msg('licenseErrorNetwork');
        return err;
    }

    // =============================
    // EVENT LISTENERS
    // =============================

    backgroundSecurity.addEventListener('change', () => autoSave('backgroundSecurity', backgroundSecurity.checked));
    integratedProtection.addEventListener('change', () => autoSave('integratedProtection', integratedProtection.checked));

    // License toggle link (expand/collapse license input in trial mode)
    licenseToggleLink.addEventListener('click', () => {
        licenseExpanded = !licenseExpanded;
        if (licenseExpanded) {
            divider.classList.remove('hidden');
            licenseSection.classList.add('show');
            licenseToggleLink.classList.add('hidden');
            licenseInput.focus();
        } else {
            divider.classList.add('hidden');
            licenseSection.classList.remove('show');
            licenseToggleLink.classList.remove('hidden');
        }
    });

    // License activation
    activateBtn.addEventListener('click', async () => {
        const code = licenseInput.value.trim();
        if (!code) {
            licenseError.textContent = msg('licenseEmptyError');
            licenseError.classList.add('show');
            return;
        }

        spinner.classList.add('show');
        activateBtnText.textContent = msg('licenseActivating');
        activateBtn.disabled = true;
        licenseInput.disabled = true;
        licenseError.classList.remove('show');

        try {
            const res = await new Promise((resolve, reject) => {
                chrome.runtime.sendMessage({ type: 'validateLicense', licenseKey: code }, (r) => {
                    if (chrome.runtime.lastError) reject(chrome.runtime.lastError);
                    else resolve(r);
                });
            });

            spinner.classList.remove('show');
            activateBtnText.textContent = msg('licenseActivateShort');
            activateBtn.disabled = false;
            licenseInput.disabled = false;

            if (!res || !res.success) {
                licenseError.textContent = translateError(res?.error);
                licenseError.classList.add('show');
            } else {
                trialStatus = null;
                showToast(msg('licenseActivatedSuccess'), 3000);
                await updateUI();
                // Trigger success glow animation
                statusCard.classList.add('success-glow');
                setTimeout(() => statusCard.classList.remove('success-glow'), 1500);
            }
        } catch (e) {
            spinner.classList.remove('show');
            activateBtnText.textContent = msg('licenseActivateShort');
            activateBtn.disabled = false;
            licenseInput.disabled = false;
            // Specific network error message
            licenseError.textContent = msg('licenseNetworkError');
            licenseError.classList.add('show');
        }
    });

    licenseInput.addEventListener('keypress', (e) => {
        if (e.key === 'Enter') activateBtn.click();
    });

    // Transfer/Deactivate
    transferBtn.addEventListener('click', () => {
        deactivateConfirm.classList.add('show');
        transferBtn.style.display = 'none';
    });

    cancelBtn.addEventListener('click', () => {
        deactivateConfirm.classList.remove('show');
        transferBtn.style.display = 'flex';
    });

    confirmBtn.addEventListener('click', async () => {
        confirmBtn.disabled = true;
        cancelBtn.disabled = true;
        confirmBtn.textContent = msg('licenseDeactivating');

        try {
            const res = await new Promise((resolve, reject) => {
                chrome.runtime.sendMessage({ type: 'deactivateLicense' }, (r) => {
                    if (chrome.runtime.lastError) reject(chrome.runtime.lastError);
                    else resolve(r);
                });
            });

            confirmBtn.disabled = false;
            cancelBtn.disabled = false;
            confirmBtn.textContent = msg('deactivateDeviceBtn');

            if (res && res.success) {
                trialStatus = null;
                showToast(msg('licenseDeactivatedSuccess'), 3000);
                await updateUI();
            } else {
                showToast(res?.error || msg('licenseErrorUnknown'));
            }

            deactivateConfirm.classList.remove('show');
            transferBtn.style.display = 'flex';
        } catch (e) {
            confirmBtn.disabled = false;
            cancelBtn.disabled = false;
            confirmBtn.textContent = msg('deactivateDeviceBtn');
            showToast(msg('licenseNetworkError'));
            deactivateConfirm.classList.remove('show');
            transferBtn.style.display = 'flex';
        }
    });

    // =============================
    // INIT
    // =============================
    (async () => {
        loadTranslations();
        await initSettings();
        await updateUI();
        await displayLastUpdate();
    })();
});

// Container
const c = document.querySelector('.container');
if (c) c.style.width = '280px';
