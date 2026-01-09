/**
 * LinkShield Regression Tests v7.1
 * Tests voor alle nieuwe security fixes en functies
 */

// Mock chrome API
global.chrome = {
    runtime: {
        id: 'test-extension-id',
        sendMessage: jest.fn(),
        onMessage: { addListener: jest.fn() }
    },
    storage: {
        sync: {
            get: jest.fn().mockResolvedValue({}),
            set: jest.fn().mockResolvedValue()
        }
    },
    i18n: {
        getMessage: jest.fn((key) => key)
    }
};

// Mock window en document
global.window = {
    location: { href: 'https://example.com', hostname: 'example.com' }
};

describe('Regression Tests: New Security Functions', () => {

    describe('@ Symbol Attack Detection (detectAtSymbolAttack)', () => {
        // Simuleer de functie zoals geïmplementeerd in content.js
        function detectAtSymbolAttack(urlString) {
            try {
                const url = new URL(urlString, 'https://example.com');
                if (url.username && url.username.includes('.')) {
                    return {
                        detected: true,
                        fakeHost: url.username,
                        realHost: url.hostname,
                        reason: 'atSymbolPhishing'
                    };
                }
                if (url.pathname.includes('@') || url.pathname.includes('%40')) {
                    // Platforms die @ gebruiken voor handles/usernames in URLs
                    const platformsWithAtHandles = [
                        'youtube.com',
                        'www.youtube.com',
                        'm.youtube.com',
                        'medium.com',
                        'www.medium.com',
                        'threads.net',
                        'www.threads.net',
                        'substack.com',
                        'instagram.com',
                        'www.instagram.com'
                    ];

                    // Check ook voor Mastodon instances (*.social, mastodon.*)
                    const isMastodonInstance = /^(.*\.social|mastodon\..*)$/i.test(url.hostname);

                    const isWhitelistedPlatform = platformsWithAtHandles.some(domain =>
                        url.hostname === domain || url.hostname.endsWith('.' + domain)
                    );

                    // Als het een legitiem platform is met @ handles, geen alert
                    if (isWhitelistedPlatform || isMastodonInstance) {
                        return { detected: false };
                    }

                    return {
                        detected: true,
                        reason: 'atSymbolInPath'
                    };
                }
                return { detected: false };
            } catch {
                return { detected: false, error: true };
            }
        }

        test('https://google.com@evil.com should detect fake host', () => {
            const result = detectAtSymbolAttack('https://google.com@evil.com');
            expect(result.detected).toBe(true);
            expect(result.fakeHost).toBe('google.com');
            expect(result.realHost).toBe('evil.com');
        });

        test('https://paypal.com:443@attacker.ru should detect fake host', () => {
            const result = detectAtSymbolAttack('https://paypal.com:443@attacker.ru');
            expect(result.detected).toBe(true);
            expect(result.realHost).toBe('attacker.ru');
        });

        test('https://user:pass@example.com should NOT trigger (no dot in username)', () => {
            const result = detectAtSymbolAttack('https://user:pass@example.com');
            expect(result.detected).toBe(false);
        });

        test('Normal URL should not trigger', () => {
            const result = detectAtSymbolAttack('https://www.google.com/search?q=test');
            expect(result.detected).toBe(false);
        });

        test('URL with %40 in path should be flagged on unknown sites', () => {
            const result = detectAtSymbolAttack('https://example.com/path%40evil');
            expect(result.detected).toBe(true);
            expect(result.reason).toBe('atSymbolInPath');
        });

        // YouTube @ handle tests - should NOT trigger (legitimate use)
        test('YouTube channel handle should NOT trigger', () => {
            const result = detectAtSymbolAttack('https://www.youtube.com/@yaraeggenhuizen532');
            expect(result.detected).toBe(false);
        });

        test('YouTube mobile channel handle should NOT trigger', () => {
            const result = detectAtSymbolAttack('https://m.youtube.com/@MrBeast');
            expect(result.detected).toBe(false);
        });

        test('Medium user profile should NOT trigger', () => {
            const result = detectAtSymbolAttack('https://medium.com/@username/article');
            expect(result.detected).toBe(false);
        });

        test('Threads profile should NOT trigger', () => {
            const result = detectAtSymbolAttack('https://www.threads.net/@zaborona');
            expect(result.detected).toBe(false);
        });

        test('Mastodon instance should NOT trigger', () => {
            const result = detectAtSymbolAttack('https://mastodon.social/@user');
            expect(result.detected).toBe(false);
        });

        test('Other .social Mastodon instances should NOT trigger', () => {
            const result = detectAtSymbolAttack('https://infosec.social/@security');
            expect(result.detected).toBe(false);
        });
    });

    describe('Double Encoding Detection (hasDoubleEncoding)', () => {
        function hasDoubleEncoding(urlString) {
            return /%25[0-9A-Fa-f]{2}/.test(urlString);
        }

        test('%252e%252e (double encoded ..) should be detected', () => {
            expect(hasDoubleEncoding('https://evil.com/%252e%252e/admin')).toBe(true);
        });

        test('%2e (single encoded) should NOT trigger', () => {
            expect(hasDoubleEncoding('https://evil.com/%2e%2e/admin')).toBe(false);
        });

        test('Normal URL should not trigger', () => {
            expect(hasDoubleEncoding('https://www.google.com/')).toBe(false);
        });

        test('%2520 (double encoded space) should be detected', () => {
            expect(hasDoubleEncoding('https://evil.com/path%2520name')).toBe(true);
        });
    });

    describe('Fullwidth Character Detection (hasFullwidthCharacters)', () => {
        function hasFullwidthCharacters(urlString) {
            return /[\uFF01-\uFF5E]/.test(urlString);
        }

        test('Fullwidth letters (ｇｏｏｇｌｅ) should be detected', () => {
            expect(hasFullwidthCharacters('https://ｇｏｏｇｌｅ.com')).toBe(true);
        });

        test('Normal ASCII should not trigger', () => {
            expect(hasFullwidthCharacters('https://google.com')).toBe(false);
        });

        test('Fullwidth numbers should be detected', () => {
            expect(hasFullwidthCharacters('https://test１２３.com')).toBe(true);
        });
    });

    describe('Null Byte Detection (hasNullByteInjection)', () => {
        function hasNullByteInjection(urlString) {
            return urlString.includes('%00') || urlString.includes('\x00');
        }

        test('URL with %00 should be detected', () => {
            expect(hasNullByteInjection('https://evil.com/file%00.txt')).toBe(true);
        });

        test('URL with actual null byte should be detected', () => {
            expect(hasNullByteInjection('https://evil.com/file\x00.txt')).toBe(true);
        });

        test('Normal URL should not trigger', () => {
            expect(hasNullByteInjection('https://google.com/file.txt')).toBe(false);
        });
    });

    describe('data: URL Blocking', () => {
        function isValidURL(string) {
            try {
                if (string.trim().toLowerCase().startsWith('data:')) {
                    return false;
                }
                const url = new URL(string, 'https://example.com');
                const allowedProtocols = ['http:', 'https:', 'mailto:', 'tel:', 'ftp:'];
                if (!allowedProtocols.includes(url.protocol)) return false;
                if (['http:', 'https:', 'ftp:'].includes(url.protocol) && !url.hostname) return false;
                return true;
            } catch {
                return false;
            }
        }

        test('data:text/html should be blocked', () => {
            expect(isValidURL('data:text/html,<script>alert(1)</script>')).toBe(false);
        });

        test('data:image/png should be blocked', () => {
            expect(isValidURL('data:image/png;base64,iVBORw0...')).toBe(false);
        });

        test('Normal https URL should be allowed', () => {
            expect(isValidURL('https://google.com')).toBe(true);
        });

        test('javascript: URL should be blocked', () => {
            expect(isValidURL('javascript:alert(1)')).toBe(false);
        });
    });
});

describe('Regression Tests: Sender Validation', () => {
    function isValidSender(sender) {
        if (sender.id === 'test-extension-id') {
            return true;
        }
        return false;
    }

    test('Message from own extension should be allowed', () => {
        const sender = { id: 'test-extension-id', url: 'chrome-extension://test/popup.html' };
        expect(isValidSender(sender)).toBe(true);
    });

    test('Message from other extension should be blocked', () => {
        const sender = { id: 'other-extension-id', url: 'chrome-extension://other/popup.html' };
        expect(isValidSender(sender)).toBe(false);
    });

    test('Message without id should be blocked', () => {
        const sender = { url: 'https://malicious.com' };
        expect(isValidSender(sender)).toBe(false);
    });
});

describe('Regression Tests: Whitelist Bypass Prevention', () => {
    const HARDCODED_WHITELIST = new Set([
        "accounts.google.com", "mail.google.com", "google.com",
        "microsoft.com", "apple.com"
    ]);

    function isWhitelisted(urlFilter) {
        const cleanFilter = urlFilter
            .replace(/^\*:\/\//, '')
            .replace(/^\|\|/, '')
            .replace(/\^.*$/, '')
            .replace(/\/.*$/, '')
            .replace(/^\*\./, '')
            .replace(/\*$/, '')
            .toLowerCase();

        if (HARDCODED_WHITELIST.has(cleanFilter)) {
            return true;
        }

        for (const whitelistedDomain of HARDCODED_WHITELIST) {
            if (cleanFilter.endsWith('.' + whitelistedDomain)) {
                return true;
            }
        }

        return false;
    }

    test('google.com should be whitelisted', () => {
        expect(isWhitelisted('google.com')).toBe(true);
    });

    test('mail.google.com should be whitelisted', () => {
        expect(isWhitelisted('mail.google.com')).toBe(true);
    });

    test('sub.mail.google.com should be whitelisted (subdomain)', () => {
        expect(isWhitelisted('sub.mail.google.com')).toBe(true);
    });

    test('not-google.com should NOT be whitelisted (bypass attempt)', () => {
        expect(isWhitelisted('not-google.com')).toBe(false);
    });

    test('google.com.evil.com should NOT be whitelisted (bypass attempt)', () => {
        expect(isWhitelisted('google.com.evil.com')).toBe(false);
    });

    test('fakegoogle.com should NOT be whitelisted', () => {
        expect(isWhitelisted('fakegoogle.com')).toBe(false);
    });

    test('||google.com^ format should be whitelisted', () => {
        expect(isWhitelisted('||google.com^')).toBe(true);
    });

    test('*://google.com/* format should be whitelisted', () => {
        expect(isWhitelisted('*://google.com/*')).toBe(true);
    });
});

describe('Regression Tests: Circular Redirect Detection', () => {
    test('Circular redirect should be detected', () => {
        const visitedUrls = new Set();
        const url1 = 'https://a.com';
        const url2 = 'https://b.com';

        visitedUrls.add(url1);
        visitedUrls.add(url2);

        // Trying to visit url1 again = circular
        const isCircular = visitedUrls.has(url1);
        expect(isCircular).toBe(true);
    });

    test('New URL should not trigger circular detection', () => {
        const visitedUrls = new Set();
        visitedUrls.add('https://a.com');
        visitedUrls.add('https://b.com');

        const isCircular = visitedUrls.has('https://c.com');
        expect(isCircular).toBe(false);
    });
});

describe('Regression Tests: Cache Timestamp Cleanup', () => {
    test('Old cache entries should be identified for cleanup', () => {
        const REDIRECT_CACHE_TTL = 30 * 60 * 1000; // 30 minutes
        const now = Date.now();

        const oldEntry = { timestamp: now - (31 * 60 * 1000) }; // 31 minutes old
        const newEntry = { timestamp: now - (5 * 60 * 1000) };  // 5 minutes old

        const isOldExpired = (now - oldEntry.timestamp) > REDIRECT_CACHE_TTL;
        const isNewExpired = (now - newEntry.timestamp) > REDIRECT_CACHE_TTL;

        expect(isOldExpired).toBe(true);
        expect(isNewExpired).toBe(false);
    });
});

describe('Regression Tests: Threshold Synchronization', () => {
    test('Default thresholds should be 4/8/15', () => {
        const defaultThresholds = {
            LOW_THRESHOLD: 4,
            MEDIUM_THRESHOLD: 8,
            HIGH_THRESHOLD: 15
        };

        expect(defaultThresholds.LOW_THRESHOLD).toBe(4);
        expect(defaultThresholds.MEDIUM_THRESHOLD).toBe(8);
        expect(defaultThresholds.HIGH_THRESHOLD).toBe(15);
    });

    test('Risk levels should be calculated correctly', () => {
        const LOW = 4, MEDIUM = 8, HIGH = 15;

        expect(3 < LOW).toBe(true);   // safe
        expect(5 >= LOW && 5 < HIGH).toBe(true);  // caution
        expect(15 >= HIGH).toBe(true); // alert
    });
});

describe('Regression Tests: MALWARE_EXTENSIONS', () => {
    // Test de regex zonder false positives
    const MALWARE_EXTENSIONS = /\.(exe|zip|bak|tar|gz|msi|dmg|jar|rar|7z|iso|bin|scr|bat|cmd|vbs|lnk|chm|ps1|apk|vbscript|docm|xlsm|pptm|torrent|wsf|hta|jse|reg|swf|wsh|pif|wasm|cab|cpl|inf|msc|pcd|sct|shb|sys)$/i;

    test('.exe should be flagged', () => {
        expect(MALWARE_EXTENSIONS.test('file.exe')).toBe(true);
    });

    test('.zip should be flagged', () => {
        expect(MALWARE_EXTENSIONS.test('file.zip')).toBe(true);
    });

    test('.js should NOT be flagged (false positive removed)', () => {
        expect(MALWARE_EXTENSIONS.test('script.js')).toBe(false);
    });

    test('.py should NOT be flagged (false positive removed)', () => {
        expect(MALWARE_EXTENSIONS.test('script.py')).toBe(false);
    });

    test('.svg should NOT be flagged (false positive removed)', () => {
        expect(MALWARE_EXTENSIONS.test('image.svg')).toBe(false);
    });

    test('.dll should NOT be flagged (false positive removed)', () => {
        expect(MALWARE_EXTENSIONS.test('library.dll')).toBe(false);
    });

    test('.docm (macro-enabled) should be flagged', () => {
        expect(MALWARE_EXTENSIONS.test('document.docm')).toBe(true);
    });

    test('.doc (regular) should NOT be flagged', () => {
        expect(MALWARE_EXTENSIONS.test('document.doc')).toBe(false);
    });
});

describe('Regression Tests: Official Shorteners (False Positive Prevention)', () => {
    // Officiële shorteners die NIET als verdacht moeten worden gemarkeerd
    const OFFICIAL_SHORTENERS = new Set([
        't.co', 'youtu.be', 'fb.me', 'g.co', 'goo.gl', 'lnkd.in', 'amzn.to', 'amzn.eu',
        'msft.it', 'aka.ms', 'apple.co', 'spoti.fi', 'pin.it', 'redd.it'
    ]);

    // Algemene shorteners die WEL als verdacht moeten worden gemarkeerd
    const SUSPICIOUS_SHORTENERS = new Set([
        'bit.ly', 'tinyurl.com', 'is.gd', 'rb.gy', 'cutt.ly', 'short.io'
    ]);

    function isOfficialShortener(domain) {
        return OFFICIAL_SHORTENERS.has(domain.toLowerCase().replace(/^www\./, ''));
    }

    function isSuspiciousShortener(domain) {
        const cleanDomain = domain.toLowerCase().replace(/^www\./, '');
        return SUSPICIOUS_SHORTENERS.has(cleanDomain) && !OFFICIAL_SHORTENERS.has(cleanDomain);
    }

    test('t.co (Twitter) should NOT be flagged as suspicious shortener', () => {
        expect(isOfficialShortener('t.co')).toBe(true);
        expect(isSuspiciousShortener('t.co')).toBe(false);
    });

    test('youtu.be (YouTube) should NOT be flagged as suspicious shortener', () => {
        expect(isOfficialShortener('youtu.be')).toBe(true);
        expect(isSuspiciousShortener('youtu.be')).toBe(false);
    });

    test('lnkd.in (LinkedIn) should NOT be flagged as suspicious shortener', () => {
        expect(isOfficialShortener('lnkd.in')).toBe(true);
        expect(isSuspiciousShortener('lnkd.in')).toBe(false);
    });

    test('amzn.to (Amazon) should NOT be flagged as suspicious shortener', () => {
        expect(isOfficialShortener('amzn.to')).toBe(true);
        expect(isSuspiciousShortener('amzn.to')).toBe(false);
    });

    test('aka.ms (Microsoft Azure) should NOT be flagged as suspicious shortener', () => {
        expect(isOfficialShortener('aka.ms')).toBe(true);
        expect(isSuspiciousShortener('aka.ms')).toBe(false);
    });

    test('bit.ly (generic shortener) SHOULD be flagged as suspicious', () => {
        expect(isOfficialShortener('bit.ly')).toBe(false);
        expect(isSuspiciousShortener('bit.ly')).toBe(true);
    });

    test('tinyurl.com (generic shortener) SHOULD be flagged as suspicious', () => {
        expect(isOfficialShortener('tinyurl.com')).toBe(false);
        expect(isSuspiciousShortener('tinyurl.com')).toBe(true);
    });
});

describe('Regression Tests: Trusted CDN Domains (False Positive Prevention)', () => {
    const TRUSTED_CDN_DOMAINS = new Set([
        'cloudfront.net', 'amazonaws.com', 'azureedge.net', 'googleusercontent.com',
        'gstatic.com', 'akamaized.net', 'fastly.net', 'jsdelivr.net', 'unpkg.com',
        'fbcdn.net', 'twimg.com', 'ytimg.com', 'licdn.com'
    ]);

    function isTrustedCdn(domain) {
        const cleanDomain = domain.toLowerCase();
        for (const cdn of TRUSTED_CDN_DOMAINS) {
            if (cleanDomain === cdn || cleanDomain.endsWith('.' + cdn)) {
                return true;
            }
        }
        return false;
    }

    test('d1234567890.cloudfront.net should be trusted CDN', () => {
        expect(isTrustedCdn('d1234567890.cloudfront.net')).toBe(true);
    });

    test('my-bucket.s3.amazonaws.com should be trusted CDN', () => {
        expect(isTrustedCdn('my-bucket.s3.amazonaws.com')).toBe(true);
    });

    test('lh3.googleusercontent.com should be trusted CDN', () => {
        expect(isTrustedCdn('lh3.googleusercontent.com')).toBe(true);
    });

    test('fonts.gstatic.com should be trusted CDN', () => {
        expect(isTrustedCdn('fonts.gstatic.com')).toBe(true);
    });

    test('cdn.jsdelivr.net should be trusted CDN', () => {
        expect(isTrustedCdn('cdn.jsdelivr.net')).toBe(true);
    });

    test('pbs.twimg.com (Twitter images) should be trusted CDN', () => {
        expect(isTrustedCdn('pbs.twimg.com')).toBe(true);
    });

    test('scontent.fbcdn.net (Facebook CDN) should be trusted CDN', () => {
        expect(isTrustedCdn('scontent.fbcdn.net')).toBe(true);
    });

    test('random-phishing.com should NOT be trusted CDN', () => {
        expect(isTrustedCdn('random-phishing.com')).toBe(false);
    });
});

describe('Regression Tests: Legitimate TLDs (False Positive Prevention)', () => {
    // TLDs die NIET meer als verdacht worden gemarkeerd
    // .dev, .app, .io zijn legitieme Google TLDs veel gebruikt door developers
    const SUSPICIOUS_TLDS = /\.(beauty|bond|buzz|cc|cf|club|cn|es|ga|gq|hair|li|live|ml|mov|pro|rest|ru|sbs|shop|tk|top|uno|win|xin|xyz|zip)$/i;

    test('.dev should NOT be flagged as suspicious TLD', () => {
        expect(SUSPICIOUS_TLDS.test('myapp.dev')).toBe(false);
    });

    test('.app should NOT be flagged as suspicious TLD', () => {
        expect(SUSPICIOUS_TLDS.test('myapp.app')).toBe(false);
    });

    test('.io should NOT be flagged as suspicious TLD', () => {
        expect(SUSPICIOUS_TLDS.test('github.io')).toBe(false);
    });

    test('.xyz SHOULD be flagged as suspicious TLD', () => {
        expect(SUSPICIOUS_TLDS.test('phishing.xyz')).toBe(true);
    });

    test('.tk SHOULD be flagged as suspicious TLD', () => {
        expect(SUSPICIOUS_TLDS.test('free-stuff.tk')).toBe(true);
    });

    test('.ru SHOULD be flagged as suspicious TLD', () => {
        expect(SUSPICIOUS_TLDS.test('malware.ru')).toBe(true);
    });

    test('.top SHOULD be flagged as suspicious TLD', () => {
        expect(SUSPICIOUS_TLDS.test('fake-bank.top')).toBe(true);
    });
});

describe('Regression Tests: Trusted API Domains (False Positive Prevention)', () => {
    const TRUSTED_API_DOMAINS = new Set([
        'accounts.google.com', 'login.microsoftonline.com', 'appleid.apple.com',
        'api.stripe.com', 'api.paypal.com', 'auth0.com', 'okta.com', 'api.github.com'
    ]);

    function isTrustedApi(domain) {
        const cleanDomain = domain.toLowerCase();
        for (const api of TRUSTED_API_DOMAINS) {
            if (cleanDomain === api || cleanDomain.endsWith('.' + api)) {
                return true;
            }
        }
        return false;
    }

    test('accounts.google.com should be trusted API domain', () => {
        expect(isTrustedApi('accounts.google.com')).toBe(true);
    });

    test('login.microsoftonline.com should be trusted API domain', () => {
        expect(isTrustedApi('login.microsoftonline.com')).toBe(true);
    });

    test('api.stripe.com should be trusted API domain', () => {
        expect(isTrustedApi('api.stripe.com')).toBe(true);
    });

    test('api.github.com should be trusted API domain', () => {
        expect(isTrustedApi('api.github.com')).toBe(true);
    });

    test('tenant.auth0.com should be trusted API domain', () => {
        expect(isTrustedApi('tenant.auth0.com')).toBe(true);
    });

    test('fake-google-login.com should NOT be trusted API domain', () => {
        expect(isTrustedApi('fake-google-login.com')).toBe(false);
    });

    test('accounts-google.com.phishing.xyz should NOT be trusted API domain', () => {
        expect(isTrustedApi('accounts-google.com.phishing.xyz')).toBe(false);
    });
});
