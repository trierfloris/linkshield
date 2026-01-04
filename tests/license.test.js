/**
 * LinkShield License System Tests
 *
 * Test suite voor de Gumroad-licentie-integratie.
 * Test scenarios:
 *   - Succesvolle validatie (success: true)
 *   - Ongeldige licentiesleutel (success: false)
 *   - Verlopen/terugbetaalde licentie (refunded: true)
 *   - Storage synchronisatie
 *   - checkTrialStatus integratie met Premium status
 */

// =============================================================================
// MOCK SETUP - Chrome API en Fetch mocking
// =============================================================================

const GUMROAD_PRODUCT_ID = 'tsjqn';
const TRIAL_DAYS = 30;
const MS_PER_DAY = 24 * 60 * 60 * 1000;

// In-memory storage mock
let mockSyncStorage = {};
let mockLocalStorage = {};

// Mock chrome.storage.sync
const chrome = {
    storage: {
        sync: {
            get: jest.fn((keys) => {
                return Promise.resolve(
                    Array.isArray(keys)
                        ? keys.reduce((acc, key) => {
                            if (mockSyncStorage[key] !== undefined) {
                                acc[key] = mockSyncStorage[key];
                            }
                            return acc;
                        }, {})
                        : typeof keys === 'string'
                            ? { [keys]: mockSyncStorage[keys] }
                            : mockSyncStorage
                );
            }),
            set: jest.fn((data) => {
                Object.assign(mockSyncStorage, data);
                return Promise.resolve();
            }),
            remove: jest.fn((keys) => {
                const keysArray = Array.isArray(keys) ? keys : [keys];
                keysArray.forEach(key => delete mockSyncStorage[key]);
                return Promise.resolve();
            })
        },
        local: {
            get: jest.fn((keys) => {
                return Promise.resolve(
                    Array.isArray(keys)
                        ? keys.reduce((acc, key) => {
                            if (mockLocalStorage[key] !== undefined) {
                                acc[key] = mockLocalStorage[key];
                            }
                            return acc;
                        }, {})
                        : typeof keys === 'string'
                            ? { [keys]: mockLocalStorage[keys] }
                            : mockLocalStorage
                );
            }),
            set: jest.fn((data) => {
                Object.assign(mockLocalStorage, data);
                return Promise.resolve();
            })
        }
    },
    i18n: {
        getMessage: jest.fn((key) => key)
    }
};

// Global chrome object for tests
global.chrome = chrome;

// Mock fetch responses
let mockFetchResponse = null;

global.fetch = jest.fn(() => {
    if (mockFetchResponse) {
        return Promise.resolve({
            ok: true,
            json: () => Promise.resolve(mockFetchResponse)
        });
    }
    return Promise.reject(new Error('Network error'));
});

// =============================================================================
// LICENSE FUNCTIONS - Geëxtraheerd uit background.js voor testbaarheid
// =============================================================================

/**
 * Valideert een licentiesleutel tegen de Gumroad API
 */
async function validateLicenseKey(licenseKey) {
    try {
        const response = await fetch('https://api.gumroad.com/v2/licenses/verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: `product_id=${GUMROAD_PRODUCT_ID}&license_key=${encodeURIComponent(licenseKey)}`
        });

        const result = await response.json();

        // Check for refunded/chargebacked/disputed licenses
        if (result.success && result.purchase) {
            const purchase = result.purchase;

            // License is invalid if refunded, chargebacked, or disputed
            if (purchase.refunded || purchase.chargebacked || purchase.disputed) {
                await chrome.storage.sync.set({
                    licenseKey: '',
                    licenseValid: false,
                    licenseEmail: '',
                    licenseValidatedAt: Date.now(),
                    licenseRefunded: true
                });
                return {
                    success: false,
                    error: 'License has been refunded or revoked',
                    refunded: true
                };
            }
        }

        if (result.success) {
            await chrome.storage.sync.set({
                licenseKey: licenseKey,
                licenseValid: true,
                licenseEmail: result.purchase?.email || '',
                licenseValidatedAt: Date.now(),
                licenseRefunded: false
            });
            return { success: true, email: result.purchase?.email };
        } else {
            await chrome.storage.sync.set({
                licenseKey: '',
                licenseValid: false,
                licenseEmail: '',
                licenseValidatedAt: Date.now()
            });
            return { success: false, error: result.message || 'Invalid license key' };
        }
    } catch (error) {
        // On network error, don't invalidate existing license (fail-safe)
        return { success: false, error: 'Network error during validation' };
    }
}

/**
 * Hervalideert opgeslagen licentiesleutel op de achtergrond
 */
async function revalidateLicense() {
    try {
        const data = await chrome.storage.sync.get(['licenseKey', 'licenseValid']);

        if (!data.licenseKey || !data.licenseValid) {
            return { revalidated: false, reason: 'No valid license to revalidate' };
        }

        const response = await fetch('https://api.gumroad.com/v2/licenses/verify', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: `product_id=${GUMROAD_PRODUCT_ID}&license_key=${encodeURIComponent(data.licenseKey)}`
        });

        const result = await response.json();

        if (result.success) {
            // Check for refunded status during revalidation
            if (result.purchase?.refunded || result.purchase?.chargebacked) {
                await chrome.storage.sync.set({
                    licenseValid: false,
                    licenseValidatedAt: Date.now(),
                    licenseRefunded: true
                });
                return { revalidated: true, valid: false, refunded: true };
            }

            await chrome.storage.sync.set({
                licenseValid: true,
                licenseValidatedAt: Date.now()
            });
            return { revalidated: true, valid: true };
        } else {
            await chrome.storage.sync.set({
                licenseValid: false,
                licenseValidatedAt: Date.now()
            });
            return { revalidated: true, valid: false };
        }
    } catch (error) {
        // Network error - don't change license status (fail-safe)
        return { revalidated: false, reason: 'Network error', networkError: true };
    }
}

/**
 * Controleert de status van de proefperiode en licentie
 */
async function checkTrialStatus() {
    try {
        const data = await chrome.storage.sync.get(['installDate', 'trialDays', 'licenseKey', 'licenseValid']);

        // Als er een geldige licentie is, is de proefperiode niet relevant
        if (data.licenseValid === true) {
            return {
                isActive: false,
                daysRemaining: 0,
                isExpired: false,
                hasLicense: true
            };
        }

        // Als er geen installatiedatum is, stel deze nu in
        if (!data.installDate) {
            const now = Date.now();
            await chrome.storage.sync.set({ installDate: now, trialDays: TRIAL_DAYS });
            return {
                isActive: true,
                daysRemaining: TRIAL_DAYS,
                isExpired: false,
                hasLicense: false
            };
        }

        const installDate = data.installDate;
        const trialDays = data.trialDays || TRIAL_DAYS;
        const now = Date.now();
        const daysSinceInstall = Math.floor((now - installDate) / MS_PER_DAY);
        const daysRemaining = Math.max(0, trialDays - daysSinceInstall);
        const isExpired = daysRemaining <= 0;

        return {
            isActive: !isExpired,
            daysRemaining: daysRemaining,
            isExpired: isExpired,
            hasLicense: false
        };
    } catch (error) {
        return {
            isActive: true,
            daysRemaining: TRIAL_DAYS,
            isExpired: false,
            hasLicense: false
        };
    }
}

/**
 * Controleert of premium functies beschikbaar zijn
 */
async function isPremiumActive() {
    const status = await checkTrialStatus();
    return status.hasLicense || status.isActive;
}

// =============================================================================
// TEST SUITES
// =============================================================================

describe('LinkShield License System', () => {

    // Reset storage en mocks voor elke test
    beforeEach(() => {
        mockSyncStorage = {};
        mockLocalStorage = {};
        mockFetchResponse = null;
        jest.clearAllMocks();
    });

    describe('License Validation - Gumroad API Responses', () => {

        test('Successful validation (success: true) should store license as valid', async () => {
            // Mock succesvolle Gumroad response
            mockFetchResponse = {
                success: true,
                purchase: {
                    email: 'user@example.com',
                    license_key: 'VALID-LICENSE-KEY',
                    refunded: false,
                    chargebacked: false,
                    disputed: false
                }
            };

            const result = await validateLicenseKey('VALID-LICENSE-KEY');

            // Controleer return value
            expect(result.success).toBe(true);
            expect(result.email).toBe('user@example.com');

            // Controleer storage
            expect(mockSyncStorage.licenseValid).toBe(true);
            expect(mockSyncStorage.licenseKey).toBe('VALID-LICENSE-KEY');
            expect(mockSyncStorage.licenseEmail).toBe('user@example.com');
            expect(mockSyncStorage.licenseValidatedAt).toBeDefined();
        });

        test('Invalid license key (success: false) should store license as invalid', async () => {
            // Mock ongeldige Gumroad response
            mockFetchResponse = {
                success: false,
                message: 'That license does not exist for the provided product.'
            };

            const result = await validateLicenseKey('INVALID-KEY');

            // Controleer return value
            expect(result.success).toBe(false);
            expect(result.error).toContain('does not exist');

            // Controleer storage
            expect(mockSyncStorage.licenseValid).toBe(false);
            expect(mockSyncStorage.licenseKey).toBe('');
            expect(mockSyncStorage.licenseEmail).toBe('');
        });

        test('Refunded license (refunded: true) should invalidate license', async () => {
            // Mock terugbetaalde licentie
            mockFetchResponse = {
                success: true,
                purchase: {
                    email: 'user@example.com',
                    license_key: 'REFUNDED-KEY',
                    refunded: true,
                    chargebacked: false,
                    disputed: false
                }
            };

            const result = await validateLicenseKey('REFUNDED-KEY');

            // Controleer return value
            expect(result.success).toBe(false);
            expect(result.refunded).toBe(true);
            expect(result.error).toContain('refunded');

            // Controleer storage
            expect(mockSyncStorage.licenseValid).toBe(false);
            expect(mockSyncStorage.licenseRefunded).toBe(true);
        });

        test('Chargebacked license should invalidate license', async () => {
            // Mock chargeback
            mockFetchResponse = {
                success: true,
                purchase: {
                    email: 'user@example.com',
                    license_key: 'CHARGEBACK-KEY',
                    refunded: false,
                    chargebacked: true,
                    disputed: false
                }
            };

            const result = await validateLicenseKey('CHARGEBACK-KEY');

            expect(result.success).toBe(false);
            expect(result.refunded).toBe(true);
            expect(mockSyncStorage.licenseValid).toBe(false);
        });

        test('Network error should NOT invalidate existing valid license (fail-safe)', async () => {
            // Stel eerst een geldige licentie in
            mockSyncStorage = {
                licenseKey: 'EXISTING-VALID-KEY',
                licenseValid: true,
                licenseEmail: 'existing@example.com'
            };

            // Mock network error
            global.fetch = jest.fn(() => Promise.reject(new Error('Network error')));

            const result = await validateLicenseKey('NEW-KEY');

            // Validatie mislukt maar bestaande licentie blijft intact
            expect(result.success).toBe(false);
            expect(result.error).toContain('Network error');

            // Bestaande licentie NIET overschreven
            expect(mockSyncStorage.licenseValid).toBe(true);
            expect(mockSyncStorage.licenseKey).toBe('EXISTING-VALID-KEY');
        });

    });

    describe('License Revalidation - Background Check', () => {

        test('Revalidation of valid license should update timestamp', async () => {
            // Setup: bestaande geldige licentie
            mockSyncStorage = {
                licenseKey: 'VALID-KEY',
                licenseValid: true,
                licenseValidatedAt: Date.now() - 86400000 // 1 dag geleden
            };

            // Mock succesvolle revalidatie
            mockFetchResponse = {
                success: true,
                purchase: {
                    email: 'user@example.com',
                    refunded: false
                }
            };

            // Reset fetch mock
            global.fetch = jest.fn(() => Promise.resolve({
                ok: true,
                json: () => Promise.resolve(mockFetchResponse)
            }));

            const result = await revalidateLicense();

            expect(result.revalidated).toBe(true);
            expect(result.valid).toBe(true);
            expect(mockSyncStorage.licenseValid).toBe(true);
        });

        test('Revalidation should detect newly refunded license', async () => {
            // Setup: licentie was geldig maar is nu terugbetaald
            mockSyncStorage = {
                licenseKey: 'NOW-REFUNDED-KEY',
                licenseValid: true
            };

            mockFetchResponse = {
                success: true,
                purchase: {
                    email: 'user@example.com',
                    refunded: true
                }
            };

            global.fetch = jest.fn(() => Promise.resolve({
                ok: true,
                json: () => Promise.resolve(mockFetchResponse)
            }));

            const result = await revalidateLicense();

            expect(result.revalidated).toBe(true);
            expect(result.valid).toBe(false);
            expect(result.refunded).toBe(true);
            expect(mockSyncStorage.licenseValid).toBe(false);
        });

        test('Revalidation should skip if no license stored', async () => {
            mockSyncStorage = {};

            const result = await revalidateLicense();

            expect(result.revalidated).toBe(false);
            expect(result.reason).toContain('No valid license');
        });

        test('Network error during revalidation should NOT change license status', async () => {
            mockSyncStorage = {
                licenseKey: 'VALID-KEY',
                licenseValid: true
            };

            global.fetch = jest.fn(() => Promise.reject(new Error('Network error')));

            const result = await revalidateLicense();

            expect(result.revalidated).toBe(false);
            expect(result.networkError).toBe(true);
            // Licentie blijft geldig
            expect(mockSyncStorage.licenseValid).toBe(true);
        });

    });

    describe('Storage Synchronization - chrome.storage.sync', () => {

        test('Valid license should be stored with all required fields', async () => {
            mockFetchResponse = {
                success: true,
                purchase: {
                    email: 'test@linkshield.nl',
                    license_key: 'LS-PREMIUM-2024'
                }
            };

            global.fetch = jest.fn(() => Promise.resolve({
                ok: true,
                json: () => Promise.resolve(mockFetchResponse)
            }));

            await validateLicenseKey('LS-PREMIUM-2024');

            // Alle vereiste velden aanwezig
            expect(mockSyncStorage).toHaveProperty('licenseKey');
            expect(mockSyncStorage).toHaveProperty('licenseValid');
            expect(mockSyncStorage).toHaveProperty('licenseEmail');
            expect(mockSyncStorage).toHaveProperty('licenseValidatedAt');

            // Correcte waarden
            expect(mockSyncStorage.licenseKey).toBe('LS-PREMIUM-2024');
            expect(mockSyncStorage.licenseValid).toBe(true);
            expect(mockSyncStorage.licenseEmail).toBe('test@linkshield.nl');
            expect(typeof mockSyncStorage.licenseValidatedAt).toBe('number');
        });

        test('Invalid license should clear stored license data', async () => {
            // Start met geldige licentie
            mockSyncStorage = {
                licenseKey: 'OLD-VALID-KEY',
                licenseValid: true,
                licenseEmail: 'old@example.com'
            };

            mockFetchResponse = {
                success: false,
                message: 'Invalid license'
            };

            global.fetch = jest.fn(() => Promise.resolve({
                ok: true,
                json: () => Promise.resolve(mockFetchResponse)
            }));

            await validateLicenseKey('INVALID-KEY');

            expect(mockSyncStorage.licenseKey).toBe('');
            expect(mockSyncStorage.licenseValid).toBe(false);
            expect(mockSyncStorage.licenseEmail).toBe('');
        });

        test('Storage should persist across function calls', async () => {
            // Eerste validatie
            mockFetchResponse = {
                success: true,
                purchase: { email: 'persist@test.com' }
            };

            global.fetch = jest.fn(() => Promise.resolve({
                ok: true,
                json: () => Promise.resolve(mockFetchResponse)
            }));

            await validateLicenseKey('PERSIST-KEY');

            // Controleer dat storage behouden blijft
            const stored = await chrome.storage.sync.get(['licenseKey', 'licenseValid']);
            expect(stored.licenseValid).toBe(true);
            expect(stored.licenseKey).toBe('PERSIST-KEY');
        });

    });

    describe('UI Integration - checkTrialStatus with Premium', () => {

        test('checkTrialStatus should return hasLicense: true when license is valid', async () => {
            mockSyncStorage = {
                licenseValid: true,
                licenseKey: 'PREMIUM-KEY'
            };

            const status = await checkTrialStatus();

            expect(status.hasLicense).toBe(true);
            expect(status.isExpired).toBe(false);
            expect(status.isActive).toBe(false); // Trial niet actief want licentie geldig
        });

        test('checkTrialStatus should show trial when no license', async () => {
            const installDate = Date.now() - (10 * MS_PER_DAY); // 10 dagen geleden
            mockSyncStorage = {
                installDate: installDate,
                trialDays: 30,
                licenseValid: false
            };

            const status = await checkTrialStatus();

            expect(status.hasLicense).toBe(false);
            expect(status.isActive).toBe(true);
            expect(status.daysRemaining).toBe(20); // 30 - 10 = 20 dagen
            expect(status.isExpired).toBe(false);
        });

        test('checkTrialStatus should show expired when trial ended and no license', async () => {
            const installDate = Date.now() - (35 * MS_PER_DAY); // 35 dagen geleden
            mockSyncStorage = {
                installDate: installDate,
                trialDays: 30,
                licenseValid: false
            };

            const status = await checkTrialStatus();

            expect(status.hasLicense).toBe(false);
            expect(status.isActive).toBe(false);
            expect(status.daysRemaining).toBe(0);
            expect(status.isExpired).toBe(true);
        });

        test('isPremiumActive should return true with valid license', async () => {
            mockSyncStorage = {
                licenseValid: true
            };

            const isPremium = await isPremiumActive();
            expect(isPremium).toBe(true);
        });

        test('isPremiumActive should return true during active trial', async () => {
            mockSyncStorage = {
                installDate: Date.now() - (5 * MS_PER_DAY),
                trialDays: 30,
                licenseValid: false
            };

            const isPremium = await isPremiumActive();
            expect(isPremium).toBe(true);
        });

        test('isPremiumActive should return false after trial expired without license', async () => {
            mockSyncStorage = {
                installDate: Date.now() - (40 * MS_PER_DAY),
                trialDays: 30,
                licenseValid: false
            };

            const isPremium = await isPremiumActive();
            expect(isPremium).toBe(false);
        });

    });

    describe('Edge Cases and Security', () => {

        test('Empty license key should fail validation', async () => {
            mockFetchResponse = {
                success: false,
                message: 'License key is required'
            };

            global.fetch = jest.fn(() => Promise.resolve({
                ok: true,
                json: () => Promise.resolve(mockFetchResponse)
            }));

            const result = await validateLicenseKey('');

            expect(result.success).toBe(false);
        });

        test('License key with special characters should be URL encoded', async () => {
            mockFetchResponse = { success: true, purchase: { email: 'test@test.com' } };

            global.fetch = jest.fn(() => Promise.resolve({
                ok: true,
                json: () => Promise.resolve(mockFetchResponse)
            }));

            await validateLicenseKey('KEY+WITH/SPECIAL=CHARS&MORE');

            // Verify fetch was called with encoded key
            expect(global.fetch).toHaveBeenCalledWith(
                'https://api.gumroad.com/v2/licenses/verify',
                expect.objectContaining({
                    body: expect.stringContaining('KEY%2BWITH%2FSPECIAL%3DCHARS%26MORE')
                })
            );
        });

        test('Disputed license should be treated as invalid', async () => {
            mockFetchResponse = {
                success: true,
                purchase: {
                    email: 'user@example.com',
                    disputed: true,
                    refunded: false,
                    chargebacked: false
                }
            };

            global.fetch = jest.fn(() => Promise.resolve({
                ok: true,
                json: () => Promise.resolve(mockFetchResponse)
            }));

            const result = await validateLicenseKey('DISPUTED-KEY');

            expect(result.success).toBe(false);
            expect(mockSyncStorage.licenseValid).toBe(false);
        });

        test('Multiple rapid validations should not cause race conditions', async () => {
            mockFetchResponse = {
                success: true,
                purchase: { email: 'test@test.com' }
            };

            global.fetch = jest.fn(() => Promise.resolve({
                ok: true,
                json: () => Promise.resolve(mockFetchResponse)
            }));

            // Simuleer meerdere snelle validaties
            const results = await Promise.all([
                validateLicenseKey('KEY-1'),
                validateLicenseKey('KEY-2'),
                validateLicenseKey('KEY-3')
            ]);

            // Alle validaties moeten slagen
            results.forEach(result => {
                expect(result.success).toBe(true);
            });

            // Storage moet consistent zijn (laatste key wint)
            expect(mockSyncStorage.licenseValid).toBe(true);
        });

        test('Validation timestamp should be recent', async () => {
            mockFetchResponse = {
                success: true,
                purchase: { email: 'test@test.com' }
            };

            global.fetch = jest.fn(() => Promise.resolve({
                ok: true,
                json: () => Promise.resolve(mockFetchResponse)
            }));

            const before = Date.now();
            await validateLicenseKey('TIME-TEST-KEY');
            const after = Date.now();

            expect(mockSyncStorage.licenseValidatedAt).toBeGreaterThanOrEqual(before);
            expect(mockSyncStorage.licenseValidatedAt).toBeLessThanOrEqual(after);
        });

    });

    describe('Product ID Verification', () => {

        test('Should use correct Gumroad product ID (tsjqn)', async () => {
            mockFetchResponse = { success: true, purchase: { email: 'test@test.com' } };

            global.fetch = jest.fn(() => Promise.resolve({
                ok: true,
                json: () => Promise.resolve(mockFetchResponse)
            }));

            await validateLicenseKey('TEST-KEY');

            expect(global.fetch).toHaveBeenCalledWith(
                'https://api.gumroad.com/v2/licenses/verify',
                expect.objectContaining({
                    body: expect.stringContaining('product_id=tsjqn')
                })
            );
        });

    });

});

// =============================================================================
// INTEGRATION TEST - Full Flow Simulation
// =============================================================================

describe('License System - Full Integration Flow', () => {

    beforeEach(() => {
        mockSyncStorage = {};
        mockLocalStorage = {};
        jest.clearAllMocks();
    });

    test('Complete user journey: trial -> purchase -> premium', async () => {
        // Stap 1: Nieuwe installatie - trial start
        const installDate = Date.now();
        mockSyncStorage = {
            installDate: installDate,
            trialDays: 30,
            licenseValid: false
        };

        let status = await checkTrialStatus();
        expect(status.isActive).toBe(true);
        expect(status.hasLicense).toBe(false);
        expect(status.daysRemaining).toBe(30);

        // Stap 2: 15 dagen later - trial halverwege
        mockSyncStorage.installDate = Date.now() - (15 * MS_PER_DAY);
        status = await checkTrialStatus();
        expect(status.isActive).toBe(true);
        expect(status.daysRemaining).toBe(15);

        // Stap 3: Gebruiker koopt licentie
        mockFetchResponse = {
            success: true,
            purchase: {
                email: 'buyer@linkshield.nl',
                license_key: 'LS-2024-PREMIUM'
            }
        };

        global.fetch = jest.fn(() => Promise.resolve({
            ok: true,
            json: () => Promise.resolve(mockFetchResponse)
        }));

        const validateResult = await validateLicenseKey('LS-2024-PREMIUM');
        expect(validateResult.success).toBe(true);

        // Stap 4: Nu Premium - trial niet meer relevant
        status = await checkTrialStatus();
        expect(status.hasLicense).toBe(true);
        expect(status.isExpired).toBe(false);

        const isPremium = await isPremiumActive();
        expect(isPremium).toBe(true);
    });

    test('Refund scenario: premium -> refund -> trial expired -> blocked', async () => {
        // Setup: Gebruiker had premium, trial was al verlopen
        mockSyncStorage = {
            installDate: Date.now() - (60 * MS_PER_DAY), // 60 dagen geleden
            trialDays: 30,
            licenseKey: 'REFUND-TEST-KEY',
            licenseValid: true,
            licenseEmail: 'refunder@test.com'
        };

        // Premium is actief
        let isPremium = await isPremiumActive();
        expect(isPremium).toBe(true);

        // Dagelijkse revalidatie detecteert refund
        mockFetchResponse = {
            success: true,
            purchase: {
                email: 'refunder@test.com',
                refunded: true
            }
        };

        global.fetch = jest.fn(() => Promise.resolve({
            ok: true,
            json: () => Promise.resolve(mockFetchResponse)
        }));

        const revalidateResult = await revalidateLicense();
        expect(revalidateResult.refunded).toBe(true);
        expect(mockSyncStorage.licenseValid).toBe(false);

        // Nu geen premium meer en trial is ook verlopen
        isPremium = await isPremiumActive();
        expect(isPremium).toBe(false);

        const status = await checkTrialStatus();
        expect(status.hasLicense).toBe(false);
        expect(status.isExpired).toBe(true);
    });

});
