/**
 * Comprehensive Phishing Detection Test
 * Tests 100+ URLs based on real phishing patterns
 */

// Mock chrome API
global.chrome = {
    runtime: { id: 'test-extension-id' },
    storage: { sync: { get: jest.fn().mockResolvedValue({}), set: jest.fn() } },
    i18n: { getMessage: jest.fn((key) => key) }
};

describe('Comprehensive Phishing Detection Test', () => {
    const CONFIG = {
        SUSPICIOUS_TLDS: /\.(beauty|bond|buzz|cc|cf|club|cn|es|ga|gq|hair|li|live|ml|mov|pro|rest|ru|sbs|shop|tk|top|uno|win|xin|xyz|zip|autos|boats|cam|casa|cfd|click|cloud|cyou|desi|digital|fit|fun|gdn|gives|icu|lat|lol|mom|monster|nexus|observer|online|ooo|pics|quest|racing|realty|rodeo|site|skin|space|store|stream|surf|tech|today|vip|wang|webcam|website|work|world|wtf|yachts|ai|bot|chat|crypto|dao|data|dex|eth|gpt|link|llm|metaverse|nft|sol|token|wallet|web3)$/i,

        FREE_HOSTING_DOMAINS: [
            'vercel.app', 'netlify.app', 'pages.dev', 'workers.dev', 'herokuapp.com',
            'firebaseapp.com', 'web.app', 'github.io', 'gitlab.io', 'azurewebsites.net',
            'azurestaticapps.net', 'blob.core.windows.net', 'web.core.windows.net',
            's3.amazonaws.com', 'amplifyapp.com', 'webflow.io', 'framer.app',
            'canva.site', 'typedream.app', 'carrd.co', 'wixsite.com', 'weebly.com',
            'blogspot.com', 'sites.google.com', 'glitch.me', 'replit.dev'
        ],

        OFFICIAL_SHORTENERS: ['t.co', 'youtu.be', 'fb.me', 'g.co', 'goo.gl', 'lnkd.in', 'amzn.to', 'aka.ms'],

        SUSPICIOUS_SHORTENERS: ['bit.ly', 'tinyurl.com', 'is.gd', 'rb.gy', 'cutt.ly', 'short.io'],

        TRUSTED_CDN_DOMAINS: [
            'cloudfront.net', 'amazonaws.com', 'azureedge.net', 'googleusercontent.com',
            'gstatic.com', 'akamaized.net', 'fastly.net', 'jsdelivr.net', 'unpkg.com',
            'fbcdn.net', 'twimg.com', 'ytimg.com'
        ],

        PHISHING_KEYWORDS: ['login', 'verify', 'secure', 'account', 'update', 'confirm', 'bank', 'wallet', 'password', 'signin', 'auth'],
        CRYPTO_KEYWORDS: ['wallet', 'metamask', 'exodus', 'ledger', 'trezor', 'web3', 'connect', 'dapp', 'defi', 'swap', 'bridge', 'airdrop', 'mint', 'nft']
    };

    // Risk calculation function
    function calculateRisk(url) {
        let risk = 0;
        const reasons = [];

        try {
            const urlObj = new URL(url);
            const hostname = urlObj.hostname.toLowerCase();
            const fullUrl = url.toLowerCase();

            // Check trusted CDN - but still check for brand impersonation
            const brandKeywords = ['paypal', 'amazon', 'microsoft', 'google', 'apple', 'facebook', 'netflix', 'bank', 'ing', 'rabo', 'login', 'secure', 'verify'];
            for (const cdn of CONFIG.TRUSTED_CDN_DOMAINS) {
                if (hostname === cdn || hostname.endsWith('.' + cdn)) {
                    // Check if subdomain contains brand keywords (potential phishing on CDN)
                    const subdomain = hostname.replace('.' + cdn, '').replace(cdn, '');
                    for (const brand of brandKeywords) {
                        if (subdomain.toLowerCase().includes(brand)) {
                            risk += 6;
                            reasons.push('brandOnCDN');
                            return { risk, reasons };
                        }
                    }
                    // No brand impersonation detected - it's a legitimate CDN
                    return { risk: 0, reasons: ['trustedCDN'] };
                }
            }

            // 1. Suspicious TLD check
            if (CONFIG.SUSPICIOUS_TLDS.test(hostname)) {
                risk += 8;
                reasons.push('suspiciousTLD');
            }

            // 2. Free hosting check
            for (const domain of CONFIG.FREE_HOSTING_DOMAINS) {
                if (hostname === domain || hostname.endsWith('.' + domain)) {
                    risk += 5;
                    reasons.push('freeHosting');
                    break;
                }
            }

            // 3. Suspicious shorteners (not official ones)
            for (const shortener of CONFIG.SUSPICIOUS_SHORTENERS) {
                if (hostname === shortener) {
                    risk += 4;
                    reasons.push('suspiciousShortener');
                    break;
                }
            }

            // 4. Phishing keywords in URL
            for (const keyword of CONFIG.PHISHING_KEYWORDS) {
                if (fullUrl.includes(keyword)) {
                    risk += 2;
                    reasons.push('phishingKeyword');
                    break;
                }
            }

            // 5. Crypto keywords
            for (const keyword of CONFIG.CRYPTO_KEYWORDS) {
                if (fullUrl.includes(keyword)) {
                    risk += 4;
                    reasons.push('cryptoKeyword');
                    break;
                }
            }

            // 6. @ symbol attack
            if (urlObj.username && urlObj.username.includes('.')) {
                risk += 10;
                reasons.push('atSymbolAttack');
            }

            // 7. Double encoding
            if (/%25[0-9A-Fa-f]{2}/.test(url)) {
                risk += 6;
                reasons.push('doubleEncoding');
            }

            // 8. IP address
            if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
                risk += 5;
                reasons.push('ipAddress');
            }

            // 9. Random path (entropy check)
            const path = urlObj.pathname;
            if (path.length > 15 && /[a-zA-Z0-9]{15,}/.test(path)) {
                risk += 3;
                reasons.push('randomPath');
            }

            // 10. Homoglyphs (Cyrillic characters)
            if (/[\u0400-\u04FF]/.test(hostname)) {
                risk += 12;
                reasons.push('homoglyph');
            }

        } catch (e) {
            risk += 5;
            reasons.push('invalidURL');
        }

        return { risk, reasons };
    }

    // Phishing URLs test set (90 URLs)
    const phishingUrls = [
        // Suspicious TLDs (20)
        'https://secure-bank-login.xyz/verify',
        'https://paypal-update.top/account',
        'https://microsoft365-login.sbs/auth',
        'https://amazon-verify.cfd/secure',
        'https://netflix-billing.icu/update',
        'https://apple-id-verify.online/confirm',
        'https://google-security.site/alert',
        'https://facebook-recover.club/password',
        'https://instagram-verify.fun/login',
        'https://linkedin-secure.tech/signin',
        'https://twitter-auth.space/verify',
        'https://tiktok-verify.click/account',
        'https://snapchat-login.cam/auth',
        'https://whatsapp-update.monster/verify',
        'https://telegram-secure.quest/login',
        'https://discord-verify.surf/auth',
        'https://spotify-billing.stream/update',
        'https://dropbox-secure.digital/verify',
        'https://icloud-login.world/auth',
        'https://outlook-verify.today/secure',

        // Free hosting phishing (20)
        'https://paypal-secure-login.vercel.app/verify',
        'https://microsoft-365-auth.netlify.app/signin',
        'https://amazon-prime-update.pages.dev/billing',
        'https://apple-id-verify.herokuapp.com/confirm',
        'https://google-account-secure.firebaseapp.com/auth',
        'https://facebook-recover.web.app/password',
        'https://netflix-update.azurewebsites.net/billing',
        'https://bank-secure-login.blob.core.windows.net/verify',
        'https://paypal-confirm.s3.amazonaws.com/account',
        'https://instagram-auth.wixsite.com/verify',
        'https://linkedin-secure.weebly.com/login',
        'https://twitter-verify.blogspot.com/auth',
        'https://tiktok-login.sites.google.com/secure',
        'https://wallet-connect.glitch.me/dapp',
        'https://metamask-auth.replit.dev/web3',
        'https://exodus-wallet.typedream.app/connect',
        'https://ledger-secure.carrd.co/verify',
        'https://trezor-update.framer.app/auth',
        'https://coinbase-login.canva.site/wallet',
        'https://binance-verify.webflow.io/secure',

        // Crypto phishing (15)
        'https://metamask-wallet-connect.xyz/dapp',
        'https://exodus-secure-login.top/wallet',
        'https://ledger-live-update.sbs/verify',
        'https://trezor-bridge.cfd/connect',
        'https://phantom-wallet.icu/solana',
        'https://coinbase-auth.online/login',
        'https://binance-secure.site/verify',
        'https://kraken-login.tech/auth',
        'https://uniswap-connect.space/swap',
        'https://opensea-verify.click/nft',
        'https://web3-wallet-auth.vercel.app/connect',
        'https://defi-swap-secure.netlify.app/bridge',
        'https://nft-mint-free.pages.dev/claim',
        'https://airdrop-claim.herokuapp.com/token',
        'https://crypto-wallet.firebaseapp.com/auth',

        // Dutch brand impersonation (10)
        'https://ing-nl-login.xyz/bankieren',
        'https://rabobank-secure.top/inloggen',
        'https://abnamro-verify.sbs/mijn',
        'https://bunq-app-update.cfd/auth',
        'https://digid-verify.icu/inloggen',
        'https://belastingdienst-mijn.online/toeslagen',
        'https://postnl-track.site/pakket',
        'https://bol-com-order.tech/bestelling',
        'https://coolblue-korting.shop/aanbieding',
        'https://marktplaats-betaling.click/koop',

        // Suspicious URL shorteners (5)
        'https://bit.ly/3xPhish123',
        'https://tinyurl.com/fakepaypal',
        'https://is.gd/scamlink',
        'https://rb.gy/malware',
        'https://cutt.ly/phishing',

        // @ symbol attacks (5)
        'https://google.com@evil.xyz/login',
        'https://paypal.com@phish.top/verify',
        'https://microsoft.com@malware.sbs/auth',
        'https://amazon.com@scam.cfd/order',
        'https://apple.com@fake.icu/id',

        // Double encoding (3)
        'https://evil.xyz/%252e%252e/admin',
        'https://phish.top/path%2520encoded',
        'https://scam.sbs/%253Cscript%253E',

        // IP-based URLs (5)
        'https://192.168.1.1/paypal/login',
        'https://10.0.0.1/microsoft/auth',
        'https://172.16.0.1/amazon/verify',
        'https://192.0.2.1/bank/secure',
        'https://203.0.113.1/wallet/connect',

        // Mixed indicators (7)
        'https://secure-paypal.xyz/login?verify=true',
        'https://metamask-web3.vercel.app/wallet/connect',
        'https://ing-bank.herokuapp.com/login/verify',
        'https://microsoft-365.top/auth/signin',
        'https://amazon-prime.pages.dev/billing/update',
        'https://apple-icloud.netlify.app/password/reset',
        'https://google-drive.firebaseapp.com/auth/2fa'
    ];

    // Legitimate URLs (should NOT be flagged)
    const legitimateUrls = [
        'https://www.google.com/search?q=test',
        'https://www.microsoft.com/en-us/windows',
        'https://www.apple.com/iphone',
        'https://www.amazon.com/dp/B09V3KXJPB',
        'https://www.paypal.com/myaccount',
        'https://github.com/anthropics/claude',
        'https://stackoverflow.com/questions/12345',
        'https://www.youtube.com/watch?v=dQw4w9WgXcQ',
        'https://twitter.com/OpenAI',
        'https://www.linkedin.com/in/example',
        'https://www.netflix.com/browse',
        'https://www.spotify.com/account',
        'https://www.dropbox.com/home',
        'https://slack.com/workspace',
        'https://discord.com/channels',
        // Official shorteners (should NOT be flagged)
        'https://t.co/abc123',
        'https://youtu.be/dQw4w9WgXcQ',
        'https://lnkd.in/example',
        'https://amzn.to/product',
        'https://aka.ms/windows11',
        // CDN URLs (should NOT be flagged)
        'https://d1234567.cloudfront.net/image.jpg',
        'https://fonts.gstatic.com/s/roboto',
        'https://pbs.twimg.com/media/image.jpg',
        'https://scontent.fbcdn.net/image.jpg',
        'https://cdn.jsdelivr.net/npm/jquery'
    ];

    describe('Phishing URL Detection', () => {
        test.each(phishingUrls)('Should detect phishing: %s', (url) => {
            const { risk, reasons } = calculateRisk(url);
            expect(risk).toBeGreaterThanOrEqual(4);
        });
    });

    describe('Legitimate URL - No False Positives', () => {
        test.each(legitimateUrls)('Should NOT flag legitimate: %s', (url) => {
            const { risk, reasons } = calculateRisk(url);
            expect(risk).toBeLessThan(4);
        });
    });

    describe('Detection Coverage Summary', () => {
        test('Generate comprehensive report', () => {
            let phishDetected = 0;
            let phishMissed = 0;
            let falsePositives = 0;
            const missedUrls = [];
            const fpUrls = [];

            // Test phishing URLs
            for (const url of phishingUrls) {
                const { risk, reasons } = calculateRisk(url);
                if (risk >= 4) {
                    phishDetected++;
                } else {
                    phishMissed++;
                    missedUrls.push({ url, risk, reasons });
                }
            }

            // Test legitimate URLs
            for (const url of legitimateUrls) {
                const { risk, reasons } = calculateRisk(url);
                if (risk >= 4) {
                    falsePositives++;
                    fpUrls.push({ url, risk, reasons });
                }
            }

            const detectionRate = Math.round(phishDetected / phishingUrls.length * 100);
            const fpRate = Math.round(falsePositives / legitimateUrls.length * 100);

            console.log('\n' + '='.repeat(50));
            console.log('COMPREHENSIVE PHISHING DETECTION REPORT');
            console.log('='.repeat(50));
            console.log(`\nPhishing URLs tested: ${phishingUrls.length}`);
            console.log(`  Detected: ${phishDetected} (${detectionRate}%)`);
            console.log(`  Missed: ${phishMissed} (${100 - detectionRate}%)`);
            console.log(`\nLegitimate URLs tested: ${legitimateUrls.length}`);
            console.log(`  Correctly allowed: ${legitimateUrls.length - falsePositives}`);
            console.log(`  False positives: ${falsePositives} (${fpRate}%)`);
            console.log(`\nOVERALL SCORE: ${detectionRate - fpRate}/100`);

            if (missedUrls.length > 0) {
                console.log('\nMissed phishing URLs:');
                missedUrls.forEach(({ url, risk, reasons }) => {
                    console.log(`  ${url}`);
                    console.log(`    Risk: ${risk}, Reasons: ${reasons.join(', ') || 'none'}`);
                });
            }

            if (fpUrls.length > 0) {
                console.log('\nFalse positives:');
                fpUrls.forEach(({ url, risk, reasons }) => {
                    console.log(`  ${url}`);
                    console.log(`    Risk: ${risk}, Reasons: ${reasons.join(', ')}`);
                });
            }

            // Assertions
            expect(detectionRate).toBeGreaterThanOrEqual(95);
            expect(fpRate).toBe(0);
        });
    });
});
