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
    const licenseSectionWrapper = document.getElementById('licenseSectionWrapper');
    const licenseSection = document.getElementById('licenseSection');
    const licenseInput = document.getElementById('licenseInput');
    const activateBtn = document.getElementById('activateBtn');
    const activateBtnText = document.getElementById('activateBtnText');
    const spinner = document.getElementById('spinner');
    const licenseError = document.getElementById('licenseError');
    const licenseToggleLink = document.getElementById('licenseToggleLink');
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
    const tooltipFeature11 = document.getElementById('tooltipFeature11');
    const tooltipFeature12 = document.getElementById('tooltipFeature12');
    const tooltipFeature13 = document.getElementById('tooltipFeature13');
    const tooltipFeature14 = document.getElementById('tooltipFeature14');
    const tooltipFeature15 = document.getElementById('tooltipFeature15');
    const tooltipFeature16 = document.getElementById('tooltipFeature16');
    const tooltipFooter = document.getElementById('tooltipFooter');
    const freeTag = document.getElementById('freeTag');
    const proTag = document.getElementById('proTag');
    const dbUpdateText = document.getElementById('dbUpdateText');
    const toast = document.getElementById('toast');

    // v8.4.0: Quota elements (now in status card)
    const quotaCard = document.getElementById('quotaCard');
    const quotaTitle = document.getElementById('quotaTitle');
    const quotaCount = document.getElementById('quotaCount');
    const quotaBarFill = document.getElementById('quotaBarFill');
    const quotaReset = document.getElementById('quotaReset');

    // v8.4.1: Threats today counter element
    const threatsToday = document.getElementById('threatsToday');
    const threatsTodayLabel = document.getElementById('threatsTodayLabel');

    let trialStatus = null;
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
    function msg(key, substitutions, fallback) {
        // Handle legacy calls: msg(key, fallback)
        if (typeof substitutions === 'string') {
            fallback = substitutions;
            substitutions = undefined;
        }
        try {
            if (typeof chrome !== 'undefined' && chrome.i18n && typeof chrome.i18n.getMessage === 'function') {
                const message = chrome.i18n.getMessage(key, substitutions);
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

    // v8.4.1: Fetch and display threats added today
    async function loadThreatsToday() {
        if (!threatsToday) return;

        try {
            // Check sessionStorage cache first
            const cached = sessionStorage.getItem('linkshield_threats_today');
            if (cached) {
                const data = JSON.parse(cached);
                // Cache valid for 1 hour
                if (Date.now() - data.timestamp < 3600000) {
                    displayThreatsCount(data.today, data.total);
                    return;
                }
            }

            // Fetch the URL list
            const response = await fetch('https://linkshield.nl/files/proces/all_urls.txt', {
                cache: 'no-cache'
            });
            if (!response.ok) throw new Error('Failed to fetch');

            const text = await response.text();
            const lines = text.trim().split('\n').filter(line => line.includes(','));

            // Get today's date in YYYY-MM-DD format
            const today = new Date().toISOString().split('T')[0];

            // Count URLs added today
            let todayCount = 0;
            for (const line of lines) {
                if (line.endsWith(today)) {
                    todayCount++;
                }
            }

            const totalCount = lines.length;

            // Cache the result
            sessionStorage.setItem('linkshield_threats_today', JSON.stringify({
                today: todayCount,
                total: totalCount,
                timestamp: Date.now()
            }));

            displayThreatsCount(todayCount, totalCount);
        } catch (e) {
            // On error, hide the counter silently
            threatsToday.classList.remove('show');
        }
    }

    function displayThreatsCount(todayCount, totalCount) {
        if (!threatsToday || !threatsTodayLabel) return;

        if (todayCount > 0) {
            threatsTodayLabel.textContent = msg('threatsTodayCount', [todayCount.toLocaleString()], `+${todayCount.toLocaleString()} ${msg('threatsTodayLabel', 'today')}`);
            threatsToday.classList.add('show');
        } else if (totalCount > 0) {
            threatsTodayLabel.textContent = msg('threatsTotalCount', [totalCount.toLocaleString()], `${totalCount.toLocaleString()} ${msg('threatsBlockedLabel', 'blocked')}`);
            threatsToday.classList.add('show');
        } else {
            threatsToday.classList.remove('show');
        }
    }

    // Load translations
    function loadTranslations() {
        sectionLabel.textContent = msg('sectionProtection');
        toggle1Title.textContent = msg('backgroundAnalysisFeature');
        toggle1Desc.textContent = msg('backgroundAnalysisDescription');
        toggle2Title.textContent = msg('integratedProtectionFeature');
        toggle2Desc.textContent = msg('integratedProtectionDescription');
        // v8.4.0: toggle1Tooltip removed from HTML (Automatic Protection is now FREE)
        if (toggle1Tooltip) toggle1Tooltip.textContent = msg('backgroundSecurityHelp');

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
        if (tooltipFeature11) tooltipFeature11.textContent = msg('tooltipFeature11');
        if (tooltipFeature12) tooltipFeature12.textContent = msg('tooltipFeature12');
        if (tooltipFeature13) {
            const newBadge = tooltipFeature13.querySelector('.new-badge');
            if (newBadge) {
                newBadge.textContent = msg('tooltipNewBadge');
                tooltipFeature13.firstChild.textContent = msg('tooltipFeature13') + ' ';
            } else {
                tooltipFeature13.textContent = msg('tooltipFeature13');
            }
        }
        if (tooltipFeature14) {
            tooltipFeature14.textContent = msg('tooltipFeature14');
        }
        if (tooltipFeature15) {
            tooltipFeature15.textContent = msg('tooltipFeature15');
        }
        if (tooltipFeature16) {
            const newBadge = tooltipFeature16.querySelector('.new-badge');
            if (newBadge) {
                newBadge.textContent = msg('tooltipNewBadge');
                tooltipFeature16.firstChild.textContent = msg('tooltipFeature16') + ' ';
            } else {
                tooltipFeature16.textContent = msg('tooltipFeature16');
            }
        }
        if (tooltipFooter) tooltipFooter.textContent = msg('tooltipFooter');

        licenseInput.placeholder = msg('licenseKeyPlaceholder');
        if (licenseToggleLink) licenseToggleLink.textContent = msg('licenseHaveKey', 'Already have a key?');
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

        // v8.4.0: Automatic Protection is ALWAYS FREE - never disable this toggle
        backgroundSecurity.disabled = false;

        // v8.4.0: Smart Link Scanning (integratedProtection) is now the PRO feature
        // It stays enabled during trial, and after trial it's limited by quota
        // The toggle itself remains enabled - quota handling is done in displayScanQuota()

        if (status.hasLicense) {
            // === PREMIUM ===
            statusCard.className = 'status-card premium';
            statusIcon.innerHTML = ICONS.check;
            statusTitle.textContent = msg('statusProtected');
            statusSubText.textContent = msg('statusPremiumSub');

            // Hide PRO tag for premium users (they already have unlimited access)
            if (proTag) proTag.classList.add('hidden');

            ctaButton.style.display = 'none';
            // Hide license section for premium users
            if (licenseSectionWrapper) licenseSectionWrapper.classList.add('hidden');
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

            // Trial: show license section
            if (licenseSectionWrapper) licenseSectionWrapper.classList.remove('hidden');
            premiumManagement.classList.remove('show');

            // Show PRO tag for trial users (they have unlimited but it's a preview)
            if (proTag) proTag.classList.remove('hidden');

        } else {
            // === EXPIRED (Free tier) ===
            statusCard.className = 'status-card expired';
            statusIcon.innerHTML = ICONS.warning;
            statusTitle.textContent = msg('statusExpired');
            statusSubText.textContent = msg('statusExpiredSub');

            trialProgress.style.width = '0%';

            ctaButton.style.display = 'block';
            ctaButton.className = 'cta-button red';
            ctaText.textContent = msg('ctaRenewText');
            ctaPrice.textContent = msg('ctaUpgradePrice');

            // Expired: show license section
            if (licenseSectionWrapper) licenseSectionWrapper.classList.remove('hidden');
            premiumManagement.classList.remove('show');

            // Show PRO tag for expired users (Smart Link Scanning has quota limits)
            if (proTag) proTag.classList.remove('hidden');

            // v8.4.0: Automatic Protection is FREE - keep it enabled!
            // Do NOT disable backgroundSecurity here
        }
    }

    // Auto-save
    async function autoSave(key, value) {
        // v8.4.0: backgroundSecurity (Automatic Protection) is always FREE - no restrictions
        // integratedProtection (Smart Link Scanning) can always be toggled by user
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
            // v8.4.0: Default to true (enabled) if not explicitly set
            // Automatic Protection is always free, so both should be ON by default
            backgroundSecurity.checked = r.backgroundSecurity ?? true;
            integratedProtection.checked = r.integratedProtection ?? true;
        } catch (e) {}
    }

    // Database update tooltip
    async function displayLastUpdate() {
        if (!dbUpdateText) return;
        try {
            const { lastRuleUpdate, ruleStats } = await chrome.storage.local.get(['lastRuleUpdate', 'ruleStats']);
            if (lastRuleUpdate) {
                const d = new Intl.DateTimeFormat(chrome.i18n.getUILanguage() || 'en', {
                    day: '2-digit', month: 'short', hour: '2-digit', minute: '2-digit'
                }).format(new Date(lastRuleUpdate));

                // v8.7.1: Show rule count on new line
                dbUpdateText.innerHTML = msg('lastRuleUpdate') + d;
                if (ruleStats && ruleStats.loadedAfterFiltering) {
                    dbUpdateText.innerHTML += `<br>${ruleStats.loadedAfterFiltering.toLocaleString()} ${msg('rulesLoaded', 'phishing sites blocked')}`;
                }
            } else {
                dbUpdateText.textContent = msg('lastRuleUpdate') + '–';
            }
        } catch (e) {}
    }

    // v8.4.0: Display scan quota in status card for free users
    async function displayScanQuota() {
        try {
            const response = await new Promise((resolve) => {
                chrome.runtime.sendMessage({ type: 'getScanQuota' }, (response) => {
                    if (chrome.runtime.lastError) {
                        resolve(null);
                    } else {
                        resolve(response);
                    }
                });
            });

            if (!response || response.isUnlimited) {
                // Premium or trial user - hide quota indicator
                if (quotaCard) quotaCard.classList.add('hidden');
                integratedProtection.disabled = false;
                return;
            }

            // Show quota indicator for free users
            if (quotaCard) quotaCard.classList.remove('hidden');

            // Update count
            if (quotaCount) quotaCount.textContent = `${response.count}/${response.limit}`;

            // Update progress bar
            const percentage = Math.min((response.count / response.limit) * 100, 100);
            if (quotaBarFill) quotaBarFill.style.width = `${percentage}%`;

            // Update styling based on usage
            if (quotaCard) {
                quotaCard.classList.remove('warning', 'critical');
                if (response.count >= response.limit) {
                    quotaCard.classList.add('critical');
                    // Disable Smart Link Scanning toggle when quota exceeded
                    integratedProtection.disabled = true;
                    integratedProtection.checked = false;
                    // v8.4.1: Also save to storage so content.js stops scanning
                    await chrome.storage.sync.set({ integratedProtection: false });
                } else {
                    if (percentage >= 75) {
                        quotaCard.classList.add('warning');
                    }
                    // Enable toggle
                    integratedProtection.disabled = false;
                    // Auto-enable Smart Link Scanning if it was disabled due to quota
                    const settings = await chrome.storage.sync.get('integratedProtection');
                    if (settings.integratedProtection === false) {
                        await chrome.storage.sync.set({ integratedProtection: true });
                        integratedProtection.checked = true;
                    }
                }
            }

            // Update reset time
            if (response.resetAt && quotaReset) {
                const resetDate = new Date(response.resetAt);
                const resetTime = resetDate.toLocaleTimeString(chrome.i18n.getUILanguage() || 'en', {
                    hour: '2-digit',
                    minute: '2-digit',
                    hour12: false,
                    timeZone: 'UTC'
                });
                quotaReset.textContent = msg('quotaResetsAt', [resetTime], `Resets at ${resetTime} UTC`);
            }

            // Update title
            if (quotaTitle) quotaTitle.textContent = msg('quotaDailyScans', 'Daily scans');

        } catch (e) {
            // On error, hide quota (fail-safe)
            if (quotaCard) quotaCard.classList.add('hidden');
            integratedProtection.disabled = false;
        }
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

    // License toggle link (expand input)
    if (licenseToggleLink) {
        licenseToggleLink.addEventListener('click', (e) => {
            e.preventDefault();
            licenseToggleLink.classList.add('hidden');
            if (licenseSection) {
                licenseSection.classList.add('show');
                licenseInput.focus();
            }
        });
    }

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
                // v8.4.0: Enable both protection features when license is activated
                await chrome.storage.sync.set({
                    backgroundSecurity: true,
                    integratedProtection: true
                });
                backgroundSecurity.checked = true;
                integratedProtection.checked = true;
                showToast(msg('licenseActivatedSuccess'), 3000);
                await updateUI();
                await displayScanQuota(); // Refresh quota display (will hide for premium)
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
        await displayScanQuota(); // v8.4.0: Show quota for free users
        loadThreatsToday(); // v8.4.1: Show threats added today (async, no await - non-blocking)
    })();

    // v8.4.0: Real-time quota updates via message from background.js
    // (storage.local.onChanged doesn't propagate from service worker to popup in MV3)
    chrome.runtime.onMessage.addListener((message) => {
        if (message.type === 'quotaUpdated' || message.type === 'quotaReset') {
            displayScanQuota();
        }
    });
});

// Container
const c = document.querySelector('.container');
if (c) c.style.width = '280px';
