/**
 * Test voor BUG-002 fix: Tab mismatch in dynamic.js
 *
 * Bug: currentSiteStatus is globaal (niet per tab), waardoor een warning
 * van tab A kan worden getoond wanneer je op het LinkShield icoon klikt in tab B.
 *
 * Fix: dynamic.js vergelijkt nu de hostname van de actieve tab met de hostname
 * in currentSiteStatus. Als ze niet overeenkomen, wordt de normale popup getoond.
 */

describe('BUG-002: Tab mismatch fix in dynamic.js', () => {
    // Helper functie die de hostname extractie simuleert
    function getHostname(url) {
        if (!url || typeof url !== 'string') return null;
        try {
            return new URL(url).hostname.toLowerCase();
        } catch (e) {
            return null;
        }
    }

    // Helper functie die de validatie logica simuleert
    function validateSiteStatus(status) {
        return status && typeof status === 'object' &&
            ('level' in status) && typeof status.level === 'string';
    }

    // Simuleert de beslissingslogica van dynamic.js
    function determineRedirect(activeUrl, currentSiteStatus) {
        // Skip speciale URLs
        if (activeUrl && (
            activeUrl.startsWith('chrome://') ||
            activeUrl.startsWith('chrome-extension://') ||
            activeUrl.startsWith('about:') ||
            activeUrl.startsWith('edge://') ||
            activeUrl.startsWith('moz-extension://')
        )) {
            return 'popup.html';
        }

        // Valideer status
        if (!validateSiteStatus(currentSiteStatus)) {
            return 'popup.html';
        }

        // Vergelijk hostnames
        const activeHostname = getHostname(activeUrl);
        const statusHostname = getHostname(currentSiteStatus.url);

        if (!activeHostname || !statusHostname || activeHostname !== statusHostname) {
            return 'popup.html';
        }

        // Status is voor de juiste tab
        const lvl = currentSiteStatus.level.trim().toLowerCase();
        switch (lvl) {
            case 'alert': return 'alert.html';
            case 'caution': return 'caution.html';
            default: return 'popup.html';
        }
    }

    describe('getHostname helper', () => {
        test('extracts hostname from valid URL', () => {
            expect(getHostname('https://mail.google.com/mail/u/0/')).toBe('mail.google.com');
            expect(getHostname('https://example.com')).toBe('example.com');
            expect(getHostname('http://sub.domain.org:8080/path')).toBe('sub.domain.org');
        });

        test('returns null for invalid input', () => {
            expect(getHostname(null)).toBeNull();
            expect(getHostname(undefined)).toBeNull();
            expect(getHostname('')).toBeNull();
            expect(getHostname('not-a-url')).toBeNull();
            expect(getHostname(123)).toBeNull();
        });

        test('normalizes hostname to lowercase', () => {
            expect(getHostname('https://GOOGLE.COM')).toBe('google.com');
            expect(getHostname('https://Mail.Google.Com')).toBe('mail.google.com');
        });
    });

    describe('Tab mismatch detection (BUG-002 core fix)', () => {
        test('CRITICAL: different hostnames should redirect to popup (not show wrong warning)', () => {
            // Scenario: Je bent op mail.google.com, maar status is van badsite.com
            const result = determineRedirect(
                'https://mail.google.com/mail/u/0/',
                { url: 'https://badsite.com/phishing', level: 'caution', reasons: ['suspicious'] }
            );
            expect(result).toBe('popup.html');
        });

        test('CRITICAL: same hostname should show the correct warning', () => {
            // Scenario: Je bent op badsite.com en status is ook van badsite.com
            const result = determineRedirect(
                'https://badsite.com/page',
                { url: 'https://badsite.com/phishing', level: 'caution', reasons: ['suspicious'] }
            );
            expect(result).toBe('caution.html');
        });

        test('same hostname with different paths should show warning', () => {
            // Paden kunnen verschillen, maar hostname moet matchen
            const result = determineRedirect(
                'https://example.com/page1',
                { url: 'https://example.com/page2', level: 'alert', reasons: ['phishing'] }
            );
            expect(result).toBe('alert.html');
        });

        test('same hostname with different protocols should show warning', () => {
            // HTTP vs HTTPS van dezelfde host
            const result = determineRedirect(
                'http://example.com',
                { url: 'https://example.com', level: 'caution', reasons: ['noHttps'] }
            );
            expect(result).toBe('caution.html');
        });

        test('subdomain mismatch should redirect to popup', () => {
            // mail.google.com !== www.google.com
            const result = determineRedirect(
                'https://mail.google.com',
                { url: 'https://www.google.com', level: 'caution', reasons: ['something'] }
            );
            expect(result).toBe('popup.html');
        });
    });

    describe('Special URL handling', () => {
        const cautionStatus = { url: 'https://test.com', level: 'caution', reasons: ['test'] };

        test('chrome:// URLs should redirect to popup', () => {
            expect(determineRedirect('chrome://settings', cautionStatus)).toBe('popup.html');
            expect(determineRedirect('chrome://extensions', cautionStatus)).toBe('popup.html');
        });

        test('chrome-extension:// URLs should redirect to popup', () => {
            expect(determineRedirect('chrome-extension://abc123/popup.html', cautionStatus)).toBe('popup.html');
        });

        test('about: URLs should redirect to popup', () => {
            expect(determineRedirect('about:blank', cautionStatus)).toBe('popup.html');
            expect(determineRedirect('about:newtab', cautionStatus)).toBe('popup.html');
        });

        test('edge:// URLs should redirect to popup', () => {
            expect(determineRedirect('edge://settings', cautionStatus)).toBe('popup.html');
        });

        test('moz-extension:// URLs should redirect to popup', () => {
            expect(determineRedirect('moz-extension://abc123/popup.html', cautionStatus)).toBe('popup.html');
        });
    });

    describe('Status validation', () => {
        test('invalid status should redirect to popup', () => {
            expect(determineRedirect('https://example.com', null)).toBe('popup.html');
            expect(determineRedirect('https://example.com', undefined)).toBe('popup.html');
            expect(determineRedirect('https://example.com', {})).toBe('popup.html');
            expect(determineRedirect('https://example.com', { url: 'test' })).toBe('popup.html');
            expect(determineRedirect('https://example.com', { level: 123 })).toBe('popup.html');
        });

        test('valid status with matching hostname should work', () => {
            expect(determineRedirect(
                'https://example.com',
                { url: 'https://example.com', level: 'safe', reasons: [] }
            )).toBe('popup.html'); // safe = popup

            expect(determineRedirect(
                'https://example.com',
                { url: 'https://example.com', level: 'caution', reasons: ['test'] }
            )).toBe('caution.html');

            expect(determineRedirect(
                'https://example.com',
                { url: 'https://example.com', level: 'alert', reasons: ['phishing'] }
            )).toBe('alert.html');
        });
    });

    describe('Edge cases', () => {
        test('null/undefined active URL should redirect to popup', () => {
            const status = { url: 'https://example.com', level: 'caution', reasons: ['test'] };
            expect(determineRedirect(null, status)).toBe('popup.html');
            expect(determineRedirect(undefined, status)).toBe('popup.html');
        });

        test('status with null URL should redirect to popup', () => {
            expect(determineRedirect(
                'https://example.com',
                { url: null, level: 'caution', reasons: ['test'] }
            )).toBe('popup.html');
        });

        test('level with extra whitespace should be handled', () => {
            expect(determineRedirect(
                'https://example.com',
                { url: 'https://example.com', level: '  caution  ', reasons: ['test'] }
            )).toBe('caution.html');
        });

        test('level with mixed case should be handled', () => {
            expect(determineRedirect(
                'https://example.com',
                { url: 'https://example.com', level: 'CAUTION', reasons: ['test'] }
            )).toBe('caution.html');

            expect(determineRedirect(
                'https://example.com',
                { url: 'https://example.com', level: 'Alert', reasons: ['test'] }
            )).toBe('alert.html');
        });

        test('unknown level should redirect to popup (safe fallback)', () => {
            expect(determineRedirect(
                'https://example.com',
                { url: 'https://example.com', level: 'unknown', reasons: ['test'] }
            )).toBe('popup.html');
        });
    });

    describe('Real-world scenarios that triggered the bug', () => {
        test('Scenario 1: Multiple tabs open, clicking icon on wrong tab', () => {
            // User has Tab A (phishing site) and Tab B (Gmail)
            // Status was set by Tab A, user clicks icon on Tab B
            const phishingStatus = {
                url: 'https://fake-bank-login.xyz',
                level: 'alert',
                reasons: ['phishing', 'suspiciousTLD']
            };

            // Should NOT show alert for Gmail
            expect(determineRedirect('https://mail.google.com', phishingStatus)).toBe('popup.html');
        });

        test('Scenario 2: Race condition - status from slower tab overwrites', () => {
            // Tab A starts check, Tab B starts check
            // Tab B finishes first (trusted domain, quick return)
            // Tab A finishes later (slower, has warnings)
            // User clicks icon on Tab B expecting safe, but sees Tab A's warning
            const slowTabStatus = {
                url: 'https://slow-suspicious-site.com',
                level: 'caution',
                reasons: ['suspiciousTLD', 'newDomain']
            };

            // Should NOT show caution for fast trusted site
            expect(determineRedirect('https://google.com', slowTabStatus)).toBe('popup.html');
        });

        test('Scenario 3: Trusted domain showing warning from other tab', () => {
            // The exact bug reported: mail.google.com showing caution with trustedDomain reason
            const mixedStatus = {
                url: 'https://some-other-site.com',
                level: 'caution',
                reasons: ['trustedDomain'] // Contradictory - this was the symptom
            };

            // mail.google.com should NOT see this warning
            expect(determineRedirect('https://mail.google.com/mail/u/0/', mixedStatus)).toBe('popup.html');
        });

        test('Scenario 4: Legitimate warning should still work', () => {
            // When status IS for the current tab, warning should show
            const legitimateWarning = {
                url: 'https://suspicious-site.xyz/login',
                level: 'alert',
                reasons: ['phishing', 'suspiciousTLD', 'brandImpersonation']
            };

            expect(determineRedirect('https://suspicious-site.xyz/login', legitimateWarning)).toBe('alert.html');
            expect(determineRedirect('https://suspicious-site.xyz/other-page', legitimateWarning)).toBe('alert.html');
        });
    });
});
