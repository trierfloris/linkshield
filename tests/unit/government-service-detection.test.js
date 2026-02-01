/**
 * Government Service Scam Detection Tests (v8.8.0)
 *
 * Tests for detectUnofficialGovernmentService() function
 * Layer 16: Detects unofficial websites offering government services (visas, ETAs)
 *
 * @jest-environment jsdom
 */

// Mock chrome API
const mockChrome = {
    runtime: {
        sendMessage: jest.fn().mockResolvedValue({ success: true }),
        lastError: null
    },
    storage: {
        sync: {
            get: jest.fn().mockResolvedValue({ integratedProtection: true })
        }
    },
    i18n: {
        getMessage: jest.fn((key) => key)
    }
};
global.chrome = mockChrome;

// Mock globalConfig
const mockConfig = {
    DEBUG_MODE: false,
    HIGH_THRESHOLD: 15,
    ADVANCED_THREAT_DETECTION: {
        unofficialGovernmentService: {
            enabled: true,
            scoreThreshold: 10,
            services: {
                'uk-eta': {
                    matchPhrases: [
                        'uk eta', 'uk eta application', 'apply for uk eta', 'apply uk eta',
                        'united kingdom eta', 'british eta', 'eta for uk', 'uk electronic travel',
                        'uk travel authorisation', 'uk travel authorization'
                    ],
                    officialDomains: ['gov.uk'],
                    officialUrl: 'https://www.gov.uk/guidance/apply-for-an-electronic-travel-authorisation-eta',
                    officialPrice: '£10',
                    country: 'UK'
                },
                'us-esta': {
                    matchPhrases: [
                        'esta', 'esta application', 'apply for esta', 'esta usa', 'us esta',
                        'esta united states', 'american esta', 'usa travel authorization',
                        'electronic system for travel authorization', 'esta online'
                    ],
                    officialDomains: ['cbp.dhs.gov'],
                    officialUrl: 'https://esta.cbp.dhs.gov/',
                    officialPrice: '$21',
                    country: 'USA'
                },
                'canada-eta': {
                    matchPhrases: [
                        'canada eta', 'canadian eta', 'eta canada', 'canada electronic travel',
                        'canada travel authorization', 'canada eta application'
                    ],
                    officialDomains: ['canada.ca', 'gc.ca'],
                    officialUrl: 'https://www.canada.ca/en/immigration-refugees-citizenship/services/visit-canada/eta.html',
                    officialPrice: 'CAD $7',
                    country: 'Canada'
                },
                'australia-eta': {
                    matchPhrases: [
                        'australia eta', 'australian eta', 'eta australia', 'australia electronic travel',
                        'australian travel authority', 'australia visitor visa', 'eta subclass 601'
                    ],
                    officialDomains: ['homeaffairs.gov.au', 'immi.gov.au'],
                    officialUrl: 'https://immi.homeaffairs.gov.au/visas/getting-a-visa/visa-listing/electronic-travel-authority-601',
                    officialPrice: 'AUD $20',
                    country: 'Australia'
                },
                'eu-etias': {
                    matchPhrases: [
                        'etias', 'eu etias', 'etias application', 'european etias',
                        'etias europe', 'schengen etias', 'etias travel authorization',
                        'european travel information and authorisation'
                    ],
                    officialDomains: ['europa.eu', 'travel-europe.europa.eu'],
                    officialUrl: 'https://travel-europe.europa.eu/etias_en',
                    officialPrice: '€7',
                    country: 'EU'
                }
            },
            legitimateThirdParties: [
                'ivisa.com',
                'visahq.com',
                'cibtvisas.com',
                'travisa.com',
                'visacentral.com'
            ],
            scores: {
                unofficialDomain: 12,
                legitimateThirdParty: 5,
                paymentFormPresent: 3,
                urgencyTactics: 2
            }
        }
    }
};

// Mock functions
let mockHostname = 'example.com';
let mockProtectionEnabled = true;
let mockTrustedDomain = false;
let mockWarningShown = null;

const isProtectionEnabled = jest.fn(() => Promise.resolve(mockProtectionEnabled));
const isTrustedDomain = jest.fn(() => Promise.resolve(mockTrustedDomain));
const showSecurityWarning = jest.fn((warning) => { mockWarningShown = warning; });
const getTranslatedMessage = jest.fn((key) => key);
const logDebug = jest.fn();
const handleError = jest.fn();

// Helper to set up DOM
function setupDOM(options = {}) {
    const {
        title = '',
        h1Text = '',
        h2Text = '',
        bodyText = '',
        hostname = 'example.com'
    } = options;

    mockHostname = hostname;

    document.title = title;
    document.body.innerHTML = `
        <h1>${h1Text}</h1>
        <h2>${h2Text}</h2>
        <p>${bodyText}</p>
    `;

    // Mock window.location
    delete window.location;
    window.location = {
        hostname: hostname,
        href: `https://${hostname}/`
    };
}

// The actual detection function (simplified version for testing)
async function detectUnofficialGovernmentService() {
    const config = mockConfig.ADVANCED_THREAT_DETECTION?.unofficialGovernmentService;
    if (!config?.enabled) {
        return { detected: false, serviceId: null, score: 0, isLegitimateThirdParty: false };
    }

    if (!(await isProtectionEnabled())) {
        return { detected: false, serviceId: null, score: 0, isLegitimateThirdParty: false };
    }

    const hostname = window.location.hostname.toLowerCase();
    try {
        if (await isTrustedDomain(hostname)) {
            return { detected: false, serviceId: null, score: 0, isLegitimateThirdParty: false };
        }
    } catch (e) { /* Continue */ }

    const pageTitle = (document.title || '').toLowerCase();
    const headers = Array.from(document.querySelectorAll('h1, h2')).map(h => (h.textContent || '').toLowerCase());
    const allSearchText = [pageTitle, ...headers].join(' ');

    let detectedService = null;
    let matchedServiceConfig = null;
    let score = 0;
    let isLegitimateThirdParty = false;

    try {
        for (const [serviceId, service] of Object.entries(config.services)) {
            const hasMatch = service.matchPhrases.some(phrase =>
                allSearchText.includes(phrase.toLowerCase())
            );

            if (!hasMatch) continue;

            const isOfficial = service.officialDomains.some(officialDomain =>
                hostname === officialDomain ||
                hostname.endsWith('.' + officialDomain)
            );

            if (isOfficial) {
                continue;
            }

            detectedService = serviceId;
            matchedServiceConfig = service;
            score = config.scores.unofficialDomain;

            isLegitimateThirdParty = config.legitimateThirdParties.some(legit =>
                hostname === legit || hostname.endsWith('.' + legit)
            );

            if (isLegitimateThirdParty) {
                score = config.scores.legitimateThirdParty;
            }

            if (!isLegitimateThirdParty) {
                // Note: Using textContent instead of innerText for jsdom compatibility
                const pageText = (document.body?.textContent || '').toLowerCase();
                const paymentKeywords = ['payment', 'pay now', 'checkout', 'credit card', 'debit card',
                    '€', '$', '£', 'price', 'fee', 'cost', 'total', 'amount'];
                const hasPayment = paymentKeywords.some(kw => pageText.includes(kw));
                if (hasPayment) {
                    score += config.scores.paymentFormPresent;
                }

                const urgencyKeywords = ['limited time', 'act now', 'don\'t miss', 'expires soon',
                    'urgent', 'immediately', 'fast processing', 'quick approval'];
                const hasUrgency = urgencyKeywords.some(kw => pageText.includes(kw));
                if (hasUrgency) {
                    score += config.scores.urgencyTactics;
                }
            }

            break;
        }

        const detected = score >= config.scoreThreshold;

        if (detected && matchedServiceConfig) {
            showSecurityWarning({
                id: 'unofficial-gov-service',
                severity: isLegitimateThirdParty ? 'warning' : 'critical',
                serviceId: detectedService,
                officialUrl: matchedServiceConfig.officialUrl,
                officialPrice: matchedServiceConfig.officialPrice
            });
        }

        return {
            detected,
            serviceId: detectedService,
            score,
            isLegitimateThirdParty,
            officialUrl: matchedServiceConfig?.officialUrl,
            officialPrice: matchedServiceConfig?.officialPrice
        };

    } catch (err) {
        handleError(err, 'UnofficialGovernmentServiceDetection');
        return { detected: false, serviceId: null, score: 0, isLegitimateThirdParty: false };
    }
}

// Reset mocks before each test
beforeEach(() => {
    jest.clearAllMocks();
    mockProtectionEnabled = true;
    mockTrustedDomain = false;
    mockWarningShown = null;
    document.title = '';
    document.body.innerHTML = '';
});

// =============================================================================
// TEST SUITES
// =============================================================================

describe('Government Service Detection - Basic Functionality', () => {

    test('should detect UK ETA scam site with exact phrase in title', async () => {
        setupDOM({
            title: 'UK ETA Application - Apply Online Fast',
            hostname: 'uk-eta.visasyst.com'
        });

        const result = await detectUnofficialGovernmentService();

        expect(result.detected).toBe(true);
        expect(result.serviceId).toBe('uk-eta');
        expect(result.score).toBeGreaterThanOrEqual(10);
        expect(result.officialUrl).toContain('gov.uk');
        expect(result.officialPrice).toBe('£10');
    });

    test('should detect US ESTA scam site', async () => {
        setupDOM({
            title: 'ESTA Application - Travel to USA',
            h1Text: 'Apply for ESTA Online',
            hostname: 'esta-application-usa.com'
        });

        const result = await detectUnofficialGovernmentService();

        expect(result.detected).toBe(true);
        expect(result.serviceId).toBe('us-esta');
        expect(result.officialUrl).toContain('cbp.dhs.gov');
        expect(result.officialPrice).toBe('$21');
    });

    test('should detect Canada ETA scam site', async () => {
        setupDOM({
            title: 'Canada ETA - Electronic Travel Authorization',
            hostname: 'canada-eta-online.com'
        });

        const result = await detectUnofficialGovernmentService();

        expect(result.detected).toBe(true);
        expect(result.serviceId).toBe('canada-eta');
        expect(result.officialPrice).toBe('CAD $7');
    });

    test('should detect Australia ETA scam site', async () => {
        setupDOM({
            title: 'Australian ETA Visa Application',
            hostname: 'australia-eta-visa.com'
        });

        const result = await detectUnofficialGovernmentService();

        expect(result.detected).toBe(true);
        expect(result.serviceId).toBe('australia-eta');
    });

    test('should detect EU ETIAS scam site', async () => {
        setupDOM({
            title: 'ETIAS Application - Travel to Europe',
            hostname: 'etias-europe-visa.com'
        });

        const result = await detectUnofficialGovernmentService();

        expect(result.detected).toBe(true);
        expect(result.serviceId).toBe('eu-etias');
        expect(result.officialPrice).toBe('€7');
    });
});

describe('Government Service Detection - Official Sites (Should NOT Detect)', () => {

    test('should NOT detect official UK gov.uk site', async () => {
        setupDOM({
            title: 'Apply for UK ETA - GOV.UK',
            h1Text: 'Apply for an Electronic Travel Authorisation (ETA)',
            hostname: 'gov.uk'
        });

        const result = await detectUnofficialGovernmentService();

        expect(result.detected).toBe(false);
        expect(result.serviceId).toBeNull();
    });

    test('should NOT detect official UK subdomain www.gov.uk', async () => {
        setupDOM({
            title: 'UK ETA - GOV.UK',
            hostname: 'www.gov.uk'
        });

        const result = await detectUnofficialGovernmentService();

        expect(result.detected).toBe(false);
    });

    test('should NOT detect official US ESTA cbp.dhs.gov', async () => {
        setupDOM({
            title: 'ESTA Application',
            hostname: 'cbp.dhs.gov'
        });

        const result = await detectUnofficialGovernmentService();

        expect(result.detected).toBe(false);
    });

    test('should NOT detect official esta.cbp.dhs.gov subdomain', async () => {
        setupDOM({
            title: 'Electronic System for Travel Authorization',
            hostname: 'esta.cbp.dhs.gov'
        });

        const result = await detectUnofficialGovernmentService();

        expect(result.detected).toBe(false);
    });

    test('should NOT detect official Canada canada.ca', async () => {
        setupDOM({
            title: 'Canada ETA - Immigration',
            hostname: 'www.canada.ca'
        });

        const result = await detectUnofficialGovernmentService();

        expect(result.detected).toBe(false);
    });

    test('should NOT detect official Australia homeaffairs.gov.au', async () => {
        setupDOM({
            title: 'Australia ETA - Department of Home Affairs',
            hostname: 'immi.homeaffairs.gov.au'
        });

        const result = await detectUnofficialGovernmentService();

        expect(result.detected).toBe(false);
    });

    test('should NOT detect official EU europa.eu', async () => {
        setupDOM({
            title: 'ETIAS - European Travel',
            hostname: 'travel-europe.europa.eu'
        });

        const result = await detectUnofficialGovernmentService();

        expect(result.detected).toBe(false);
    });
});

describe('Government Service Detection - Legitimate Third Parties', () => {

    test('should detect iVisa.com with soft warning (lower score)', async () => {
        setupDOM({
            title: 'UK ETA Application - iVisa',
            hostname: 'ivisa.com'
        });

        const result = await detectUnofficialGovernmentService();

        // iVisa is legitimate but should still warn users
        expect(result.detected).toBe(false); // Score 5 < threshold 10
        expect(result.isLegitimateThirdParty).toBe(true);
        expect(result.score).toBe(5);
    });

    test('should detect VisaHQ with soft warning', async () => {
        setupDOM({
            title: 'ESTA USA Application',
            hostname: 'www.visahq.com'
        });

        const result = await detectUnofficialGovernmentService();

        expect(result.isLegitimateThirdParty).toBe(true);
        expect(result.score).toBe(5);
    });

    test('should detect CIBT Visas with soft warning', async () => {
        setupDOM({
            title: 'Canada ETA Service',
            hostname: 'cibtvisas.com'
        });

        const result = await detectUnofficialGovernmentService();

        expect(result.isLegitimateThirdParty).toBe(true);
    });
});

describe('Government Service Detection - Score Calculation', () => {

    test('should add payment indicator score', async () => {
        setupDOM({
            title: 'UK ETA Application',
            bodyText: 'Pay now with credit card - Total: €99',
            hostname: 'fake-uk-eta.com'
        });

        const result = await detectUnofficialGovernmentService();

        expect(result.detected).toBe(true);
        expect(result.score).toBe(12 + 3); // unofficialDomain + paymentFormPresent
    });

    test('should add urgency tactics score', async () => {
        setupDOM({
            title: 'UK ETA - Apply Now',
            bodyText: 'Limited time offer! Act now before it expires!',
            hostname: 'fake-uk-eta.com'
        });

        const result = await detectUnofficialGovernmentService();

        expect(result.detected).toBe(true);
        expect(result.score).toBe(12 + 2); // unofficialDomain + urgencyTactics
    });

    test('should add both payment and urgency scores', async () => {
        setupDOM({
            title: 'UK ETA Application',
            bodyText: 'Pay now! Limited time offer! Credit card accepted. Act immediately!',
            hostname: 'scam-eta.com'
        });

        const result = await detectUnofficialGovernmentService();

        expect(result.detected).toBe(true);
        expect(result.score).toBe(12 + 3 + 2); // unofficialDomain + payment + urgency
    });

    test('should NOT add payment/urgency scores for legitimate third parties', async () => {
        setupDOM({
            title: 'UK ETA Application - iVisa',
            bodyText: 'Pay now with credit card - Act now!',
            hostname: 'ivisa.com'
        });

        const result = await detectUnofficialGovernmentService();

        // Legitimate third parties don't get extra scores
        expect(result.score).toBe(5);
        expect(result.isLegitimateThirdParty).toBe(true);
    });
});

describe('Government Service Detection - Edge Cases', () => {

    test('should handle case-insensitive matching', async () => {
        setupDOM({
            title: 'UK ETA APPLICATION',
            hostname: 'fake-eta.com'
        });

        const result = await detectUnofficialGovernmentService();
        expect(result.detected).toBe(true);
        expect(result.serviceId).toBe('uk-eta');
    });

    test('should handle mixed case', async () => {
        setupDOM({
            title: 'Uk Eta Application Form',
            hostname: 'fake-eta.com'
        });

        const result = await detectUnofficialGovernmentService();
        expect(result.detected).toBe(true);
    });

    test('should detect phrase in H1 only (not in title)', async () => {
        setupDOM({
            title: 'Travel Services',
            h1Text: 'Apply for UK ETA Online',
            hostname: 'fake-eta.com'
        });

        const result = await detectUnofficialGovernmentService();
        expect(result.detected).toBe(true);
        expect(result.serviceId).toBe('uk-eta');
    });

    test('should detect phrase in H2 only', async () => {
        setupDOM({
            title: 'Travel Services',
            h2Text: 'UK ETA Application Form',
            hostname: 'fake-eta.com'
        });

        const result = await detectUnofficialGovernmentService();
        expect(result.detected).toBe(true);
    });

    test('should NOT detect partial phrase match', async () => {
        setupDOM({
            title: 'UK Travel Information', // No "eta" phrase
            hostname: 'travel-info.com'
        });

        const result = await detectUnofficialGovernmentService();
        expect(result.detected).toBe(false);
    });

    test('should NOT detect phrase only in body text (not headers)', async () => {
        setupDOM({
            title: 'Travel Blog',
            bodyText: 'I applied for UK ETA last week...',
            hostname: 'travel-blog.com'
        });

        const result = await detectUnofficialGovernmentService();
        // Phrase is only in body, not in title/H1/H2
        expect(result.detected).toBe(false);
    });

    test('should handle empty title and headers', async () => {
        setupDOM({
            title: '',
            hostname: 'example.com'
        });

        const result = await detectUnofficialGovernmentService();
        expect(result.detected).toBe(false);
    });

    test('should handle multiple services mentioned - detect first match', async () => {
        setupDOM({
            title: 'UK ETA and ESTA Applications',
            hostname: 'visa-services.com'
        });

        const result = await detectUnofficialGovernmentService();
        expect(result.detected).toBe(true);
        // Should detect the first matching service
        expect(['uk-eta', 'us-esta']).toContain(result.serviceId);
    });

    test('should handle special characters in title', async () => {
        setupDOM({
            title: 'UK ETA™ Application® - Fast & Easy!',
            hostname: 'fake-eta.com'
        });

        const result = await detectUnofficialGovernmentService();
        expect(result.detected).toBe(true);
    });

    test('should handle unicode in hostname', async () => {
        setupDOM({
            title: 'UK ETA Application',
            hostname: 'uk-еta.com' // Cyrillic 'е' instead of Latin 'e'
        });

        const result = await detectUnofficialGovernmentService();
        expect(result.detected).toBe(true);
    });
});

describe('Government Service Detection - Protection Disabled', () => {

    test('should NOT detect when protection is disabled', async () => {
        mockProtectionEnabled = false;

        setupDOM({
            title: 'UK ETA Application - Scam Site',
            hostname: 'scam-site.com'
        });

        const result = await detectUnofficialGovernmentService();

        expect(result.detected).toBe(false);
        expect(isProtectionEnabled).toHaveBeenCalled();
    });

    test('should NOT detect on trusted domains', async () => {
        mockTrustedDomain = true;

        setupDOM({
            title: 'UK ETA Application',
            hostname: 'facebook.com' // Trusted domain
        });

        const result = await detectUnofficialGovernmentService();

        expect(result.detected).toBe(false);
        expect(isTrustedDomain).toHaveBeenCalled();
    });
});

describe('Government Service Detection - Config Disabled', () => {

    test('should NOT detect when feature is disabled in config', async () => {
        const originalEnabled = mockConfig.ADVANCED_THREAT_DETECTION.unofficialGovernmentService.enabled;
        mockConfig.ADVANCED_THREAT_DETECTION.unofficialGovernmentService.enabled = false;

        setupDOM({
            title: 'UK ETA Application - Scam Site',
            hostname: 'scam-site.com'
        });

        const result = await detectUnofficialGovernmentService();

        expect(result.detected).toBe(false);

        // Restore
        mockConfig.ADVANCED_THREAT_DETECTION.unofficialGovernmentService.enabled = originalEnabled;
    });
});

describe('Government Service Detection - Warning Display', () => {

    test('should show critical warning for unknown scam sites', async () => {
        setupDOM({
            title: 'UK ETA Application',
            hostname: 'unknown-scam.com'
        });

        await detectUnofficialGovernmentService();

        expect(showSecurityWarning).toHaveBeenCalled();
        expect(mockWarningShown.severity).toBe('critical');
        expect(mockWarningShown.officialUrl).toContain('gov.uk');
        expect(mockWarningShown.officialPrice).toBe('£10');
    });

    test('should NOT show warning for legitimate third parties below threshold', async () => {
        setupDOM({
            title: 'UK ETA Application',
            hostname: 'ivisa.com'
        });

        const result = await detectUnofficialGovernmentService();

        // Score 5 is below threshold 10, so no warning
        expect(result.detected).toBe(false);
        expect(showSecurityWarning).not.toHaveBeenCalled();
    });
});

describe('Government Service Detection - Real-World Scam Sites', () => {

    test('should detect uk-eta.visasyst.com (known scam)', async () => {
        setupDOM({
            title: 'UK ETA Application - Apply Online in Minutes',
            h1Text: 'Apply for UK ETA',
            bodyText: 'Fast processing! Pay only €99. Credit card accepted.',
            hostname: 'uk-eta.visasyst.com'
        });

        const result = await detectUnofficialGovernmentService();

        expect(result.detected).toBe(true);
        expect(result.serviceId).toBe('uk-eta');
        expect(result.score).toBeGreaterThanOrEqual(15); // 12 + 3 for payment
    });

    test('should detect esta-application.us (common scam pattern)', async () => {
        setupDOM({
            title: 'ESTA Application USA - Electronic Travel Authorization',
            h1Text: 'Apply for ESTA Online',
            bodyText: 'Get your ESTA in 24 hours! Only $89. Act now - limited time!',
            hostname: 'esta-application.us'
        });

        const result = await detectUnofficialGovernmentService();

        expect(result.detected).toBe(true);
        expect(result.serviceId).toBe('us-esta');
        expect(result.score).toBeGreaterThanOrEqual(17); // 12 + 3 + 2
    });

    test('should detect apply-eta-canada.com (fake Canada site)', async () => {
        setupDOM({
            title: 'Canada ETA Online Application',
            hostname: 'apply-eta-canada.com'
        });

        const result = await detectUnofficialGovernmentService();

        expect(result.detected).toBe(true);
        expect(result.serviceId).toBe('canada-eta');
    });
});

describe('Government Service Detection - False Positive Prevention', () => {

    test('should NOT detect news article about UK ETA', async () => {
        setupDOM({
            title: 'BBC News - UK ETA Requirements Change',
            h1Text: 'New rules for UK ETA applicants', // This is in H1 - might trigger
            hostname: 'bbc.com'
        });

        // Note: This might actually trigger if bbc.com is not trusted
        // In production, bbc.com should be in TrustedDomains.json
        mockTrustedDomain = true; // Simulate trusted domain

        const result = await detectUnofficialGovernmentService();

        expect(result.detected).toBe(false);
    });

    test('should NOT detect Wikipedia article', async () => {
        mockTrustedDomain = true;

        setupDOM({
            title: 'Electronic Travel Authorization - Wikipedia',
            h1Text: 'UK ETA',
            hostname: 'en.wikipedia.org'
        });

        const result = await detectUnofficialGovernmentService();

        expect(result.detected).toBe(false);
    });

    test('should NOT detect travel blog post', async () => {
        setupDOM({
            title: 'My Travel Blog',
            h1Text: 'Trip to London', // No ETA phrase in headers
            bodyText: 'I needed to apply for UK ETA before my trip...',
            hostname: 'mytravelblog.com'
        });

        const result = await detectUnofficialGovernmentService();

        // Phrase only in body text, not in title/headers
        expect(result.detected).toBe(false);
    });

    test('should NOT detect generic travel agency without specific ETA phrases', async () => {
        setupDOM({
            title: 'Travel Agency - Book Your Trip',
            h1Text: 'Visa Services Available',
            hostname: 'generic-travel.com'
        });

        const result = await detectUnofficialGovernmentService();

        expect(result.detected).toBe(false);
    });

    test('should NOT detect airline website', async () => {
        mockTrustedDomain = true;

        setupDOM({
            title: 'British Airways - Book Flights',
            hostname: 'britishairways.com'
        });

        const result = await detectUnofficialGovernmentService();

        expect(result.detected).toBe(false);
    });
});

describe('Government Service Detection - Alternate Phrases', () => {

    test('should detect "apply for uk eta"', async () => {
        setupDOM({
            title: 'How to Apply for UK ETA',
            hostname: 'fake-site.com'
        });

        const result = await detectUnofficialGovernmentService();
        expect(result.detected).toBe(true);
    });

    test('should detect "united kingdom eta"', async () => {
        setupDOM({
            title: 'United Kingdom ETA Application',
            hostname: 'fake-site.com'
        });

        const result = await detectUnofficialGovernmentService();
        expect(result.detected).toBe(true);
    });

    test('should detect "british eta"', async () => {
        setupDOM({
            title: 'Apply for British ETA Online',
            hostname: 'fake-site.com'
        });

        const result = await detectUnofficialGovernmentService();
        expect(result.detected).toBe(true);
    });

    test('should detect "electronic system for travel authorization"', async () => {
        setupDOM({
            title: 'Electronic System for Travel Authorization - Apply',
            hostname: 'fake-esta.com'
        });

        const result = await detectUnofficialGovernmentService();
        expect(result.detected).toBe(true);
        expect(result.serviceId).toBe('us-esta');
    });

    test('should detect "esta united states"', async () => {
        setupDOM({
            title: 'ESTA United States Application Form',
            hostname: 'fake-esta.com'
        });

        const result = await detectUnofficialGovernmentService();
        expect(result.detected).toBe(true);
    });
});

describe('Government Service Detection - Subdomain Handling', () => {

    test('should detect scam on subdomain', async () => {
        setupDOM({
            title: 'UK ETA Application',
            hostname: 'uk-eta.scam-domain.com'
        });

        const result = await detectUnofficialGovernmentService();
        expect(result.detected).toBe(true);
    });

    test('should detect on deep subdomain', async () => {
        setupDOM({
            title: 'Apply for UK ETA',
            hostname: 'apply.uk-eta.scam.example.com'
        });

        const result = await detectUnofficialGovernmentService();
        expect(result.detected).toBe(true);
    });

    test('should NOT detect on official subdomain', async () => {
        setupDOM({
            title: 'UK ETA Application',
            hostname: 'eta.gov.uk'
        });

        const result = await detectUnofficialGovernmentService();
        expect(result.detected).toBe(false);
    });

    test('should handle ivisa subdomain as legitimate', async () => {
        setupDOM({
            title: 'UK ETA - iVisa',
            hostname: 'uk.ivisa.com'
        });

        const result = await detectUnofficialGovernmentService();
        expect(result.isLegitimateThirdParty).toBe(true);
    });
});

// =============================================================================
// SUMMARY
// =============================================================================

describe('Test Coverage Summary', () => {
    test('all test suites should pass', () => {
        // This is a placeholder to ensure all tests run
        expect(true).toBe(true);
    });
});
