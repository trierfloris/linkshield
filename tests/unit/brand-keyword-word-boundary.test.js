/**
 * Test voor v8.8.2: Word boundary check voor korte brand keywords
 *
 * Bug: "hostinger.com" werd gedetecteerd als ING Bank impersonation omdat
 * "ing" als substring voorkomt in "hostinger".
 *
 * Fix: Korte brand keywords (<=3 karakters) vereisen nu word boundaries.
 * Bijv. "ing" matcht wel "ing-bank.com" maar niet "hostinger.com"
 */

describe('v8.8.2: Brand keyword word boundary detection', () => {
    // Simuleert de brand detection logica uit content.js
    function detectBrandInDomain(hostname) {
        const brandPatterns = ['microsoft', 'paypal', 'apple', 'google', 'amazon', 'netflix',
            'facebook', 'instagram', 'whatsapp', 'coinbase', 'binance', 'metamask', 'chase',
            'wellsfargo', 'bankofamerica', 'citibank', 'hsbc', 'barclays', 'ing', 'rabobank',
            'abnamro', 'linkedin', 'twitter', 'dropbox', 'adobe', 'zoom', 'slack', 'spotify',
            'dhl', 'ups', 'sns', 'abn'];

        const parts = hostname.toLowerCase().split('.');
        const tld = parts.length >= 2 ? parts[parts.length - 1] : '';
        const baseDomain = parts.length >= 2 ? parts.slice(0, -1).join('.') : hostname;

        for (const brand of brandPatterns) {
            let brandMatched = false;

            // FIX v8.8.2: Word boundary check for short brands
            if (brand.length <= 3) {
                const wordBoundaryRegex = new RegExp(`(^|[^a-z])${brand}([^a-z]|$)`, 'i');
                brandMatched = wordBoundaryRegex.test(baseDomain);
            } else {
                brandMatched = baseDomain.includes(brand);
            }

            if (brandMatched) {
                // Check if it's the actual brand domain
                const brandDomain = brand + '.' + tld;
                const brandWithWww = 'www.' + brand + '.' + tld;
                if (hostname !== brandDomain && hostname !== brandWithWww &&
                    !hostname.endsWith('.' + brand + '.' + tld)) {
                    return { detected: true, brand };
                }
            }
        }

        return { detected: false, brand: null };
    }

    describe('FALSE POSITIVES that should NOT be detected (v8.8.2 fix)', () => {
        test('hostinger.com should NOT detect "ing" brand', () => {
            const result = detectBrandInDomain('www.hostinger.com');
            expect(result.detected).toBe(false);
        });

        test('hostinger.nl should NOT detect "ing" brand', () => {
            const result = detectBrandInDomain('hostinger.nl');
            expect(result.detected).toBe(false);
        });

        test('shopping.com should NOT detect "ing" brand', () => {
            const result = detectBrandInDomain('www.shopping.com');
            expect(result.detected).toBe(false);
        });

        test('booking.com should NOT detect "ing" brand', () => {
            const result = detectBrandInDomain('www.booking.com');
            expect(result.detected).toBe(false);
        });

        test('rings.com should NOT detect "ing" brand', () => {
            const result = detectBrandInDomain('rings.com');
            expect(result.detected).toBe(false);
        });

        test('groups.com should NOT detect "ups" brand', () => {
            const result = detectBrandInDomain('groups.com');
            expect(result.detected).toBe(false);
        });

        test('startups.io should NOT detect "ups" brand', () => {
            const result = detectBrandInDomain('startups.io');
            expect(result.detected).toBe(false);
        });

        test('cupshop.com should NOT detect "ups" brand', () => {
            const result = detectBrandInDomain('cupshop.com');
            expect(result.detected).toBe(false);
        });

        test('dhlgroup.com should NOT detect "dhl" brand', () => {
            // "dhl" is 3 chars, but it's at the start so word boundary should match
            // This is actually a legitimate concern - let's see
            const result = detectBrandInDomain('dhlgroup.com');
            // dhl at start, followed by "g" which is a letter, so no match
            expect(result.detected).toBe(false);
        });

        test('sns-news.com should detect "sns" brand (word boundary present)', () => {
            // "sns" followed by hyphen, which is a word boundary
            const result = detectBrandInDomain('sns-news.com');
            expect(result.detected).toBe(true);
            expect(result.brand).toBe('sns');
        });
    });

    describe('TRUE POSITIVES that SHOULD be detected', () => {
        test('ing-login.com should detect "ing" brand', () => {
            const result = detectBrandInDomain('ing-login.com');
            expect(result.detected).toBe(true);
            expect(result.brand).toBe('ing');
        });

        test('secure-ing.com should detect "ing" brand', () => {
            const result = detectBrandInDomain('secure-ing.com');
            expect(result.detected).toBe(true);
            expect(result.brand).toBe('ing');
        });

        test('ing.phishing.com should detect "ing" brand', () => {
            const result = detectBrandInDomain('ing.phishing.com');
            expect(result.detected).toBe(true);
            expect(result.brand).toBe('ing');
        });

        test('login-ing-bank.com should detect "ing" brand', () => {
            const result = detectBrandInDomain('login-ing-bank.com');
            expect(result.detected).toBe(true);
            expect(result.brand).toBe('ing');
        });

        test('ups-delivery.com should detect "ups" brand', () => {
            const result = detectBrandInDomain('ups-delivery.com');
            expect(result.detected).toBe(true);
            expect(result.brand).toBe('ups');
        });

        test('track-ups.net should detect "ups" brand', () => {
            const result = detectBrandInDomain('track-ups.net');
            expect(result.detected).toBe(true);
            expect(result.brand).toBe('ups');
        });

        test('dhl-tracking.com should detect "dhl" brand', () => {
            const result = detectBrandInDomain('dhl-tracking.com');
            expect(result.detected).toBe(true);
            expect(result.brand).toBe('dhl');
        });

        test('fake-dhl.com should detect "dhl" brand', () => {
            const result = detectBrandInDomain('fake-dhl.com');
            expect(result.detected).toBe(true);
            expect(result.brand).toBe('dhl');
        });
    });

    describe('Longer brands should still use substring matching', () => {
        test('microsoft-login.com should detect "microsoft" brand', () => {
            const result = detectBrandInDomain('microsoft-login.com');
            expect(result.detected).toBe(true);
            expect(result.brand).toBe('microsoft');
        });

        test('fakemicrosoft.com should detect "microsoft" brand', () => {
            const result = detectBrandInDomain('fakemicrosoft.com');
            expect(result.detected).toBe(true);
            expect(result.brand).toBe('microsoft');
        });

        test('paypal-verify.com should detect "paypal" brand', () => {
            const result = detectBrandInDomain('paypal-verify.com');
            expect(result.detected).toBe(true);
            expect(result.brand).toBe('paypal');
        });

        test('netflixlogin.com should detect "netflix" brand', () => {
            const result = detectBrandInDomain('netflixlogin.com');
            expect(result.detected).toBe(true);
            expect(result.brand).toBe('netflix');
        });
    });

    describe('Legitimate brand domains should NOT be flagged', () => {
        test('ing.nl should NOT be flagged (actual brand domain)', () => {
            const result = detectBrandInDomain('ing.nl');
            expect(result.detected).toBe(false);
        });

        test('www.ing.com should NOT be flagged', () => {
            const result = detectBrandInDomain('www.ing.com');
            expect(result.detected).toBe(false);
        });

        test('microsoft.com should NOT be flagged', () => {
            const result = detectBrandInDomain('microsoft.com');
            expect(result.detected).toBe(false);
        });

        test('www.paypal.com should NOT be flagged', () => {
            const result = detectBrandInDomain('www.paypal.com');
            expect(result.detected).toBe(false);
        });

        test('login.microsoft.com should NOT be flagged (subdomain of brand)', () => {
            const result = detectBrandInDomain('login.microsoft.com');
            expect(result.detected).toBe(false);
        });
    });

    describe('Edge cases', () => {
        test('ing123.com should detect "ing" (number is word boundary)', () => {
            const result = detectBrandInDomain('ing123.com');
            expect(result.detected).toBe(true);
            expect(result.brand).toBe('ing');
        });

        test('123ing.com should detect "ing" (number is word boundary)', () => {
            const result = detectBrandInDomain('123ing.com');
            expect(result.detected).toBe(true);
            expect(result.brand).toBe('ing');
        });

        test('ING-LOGIN.COM (uppercase) should detect "ing" brand', () => {
            const result = detectBrandInDomain('ING-LOGIN.COM');
            expect(result.detected).toBe(true);
            expect(result.brand).toBe('ing');
        });
    });
});
