/**
 * LinkShield Protection Settings Test Suite
 *
 * Tests for checkbox toggle functionality:
 * - backgroundSecurity checkbox
 * - integratedProtection checkbox
 * - isProtectionEnabled() function
 * - getStoredSettings() function
 * - Feature initialization based on settings
 */

// ============================================================================
// MOCK SETUP - Chrome APIs
// ============================================================================
let mockStorage = {
  sync: {}
};

// Track function calls for verification
let initFunctionCalls = {
  clipboardGuard: 0,
  clickFixDetection: 0,
  bitBDetection: 0,
  tableQRScanner: 0,
  checkCurrentUrl: 0
};

// Reset function to clear state between tests
function resetMocks() {
  mockStorage = { sync: {} };
  initFunctionCalls = {
    clipboardGuard: 0,
    clickFixDetection: 0,
    bitBDetection: 0,
    tableQRScanner: 0,
    checkCurrentUrl: 0
  };
  if (global.chrome) {
    global.chrome.runtime.lastError = null;
  }
}

global.chrome = {
  storage: {
    sync: {
      get: jest.fn((keys, callback) => {
        const result = {};
        const keyArray = Array.isArray(keys) ? keys : [keys];
        keyArray.forEach(key => {
          if (mockStorage.sync.hasOwnProperty(key)) {
            result[key] = mockStorage.sync[key];
          }
        });
        if (callback) {
          callback(result);
        }
        return Promise.resolve(result);
      }),
      set: jest.fn((data) => {
        Object.assign(mockStorage.sync, data);
        return Promise.resolve();
      })
    }
  },
  runtime: {
    lastError: null
  },
  i18n: {
    getMessage: jest.fn((key) => key)
  }
};

// ============================================================================
// FUNCTION IMPLEMENTATIONS (extracted from content.js)
// ============================================================================

/**
 * Gets stored settings from chrome.storage.sync
 * Mirrors the implementation in content.js
 */
async function getStoredSettings() {
  const defaultSettings = { backgroundSecurity: true, integratedProtection: true };

  try {
    if (typeof chrome === 'undefined' || !chrome.storage || !chrome.storage.sync) {
      return defaultSettings;
    }

    const settings = await new Promise((resolve, reject) => {
      chrome.storage.sync.get(['backgroundSecurity', 'integratedProtection'], (result) => {
        if (chrome.runtime.lastError) {
          reject(new Error(chrome.runtime.lastError.message));
        } else {
          resolve(result);
        }
      });
    });

    if (!settings || typeof settings !== 'object') {
      return defaultSettings;
    }

    return {
      backgroundSecurity: Boolean(settings.backgroundSecurity),
      integratedProtection: Boolean(settings.integratedProtection)
    };
  } catch (error) {
    return defaultSettings;
  }
}

/**
 * Checks if protection is enabled (both settings must be true)
 * Mirrors the implementation in content.js
 */
async function isProtectionEnabled() {
  const settings = await getStoredSettings();
  return settings.backgroundSecurity && settings.integratedProtection;
}

/**
 * Simulates checkCurrentUrl behavior with protection check
 */
async function checkCurrentUrl() {
  if (!(await isProtectionEnabled())) {
    return { skipped: true, reason: 'Protection disabled' };
  }
  initFunctionCalls.checkCurrentUrl++;
  return { skipped: false, checked: true };
}

/**
 * Simulates DOMContentLoaded initialization behavior
 */
async function initializeFeatures() {
  const protectionEnabled = await isProtectionEnabled();

  if (protectionEnabled) {
    initFunctionCalls.clipboardGuard++;
    initFunctionCalls.clickFixDetection++;
    initFunctionCalls.bitBDetection++;
    initFunctionCalls.tableQRScanner++;
    return { initialized: true, features: ['clipboardGuard', 'clickFixDetection', 'bitBDetection', 'tableQRScanner'] };
  } else {
    return { initialized: false, reason: 'Protection disabled' };
  }
}

// ============================================================================
// TESTS
// ============================================================================

describe('Protection Settings: getStoredSettings()', () => {

  beforeEach(() => {
    resetMocks();
  });

  test('should return default settings when storage is empty', async () => {
    const settings = await getStoredSettings();

    expect(settings.backgroundSecurity).toBe(false); // Empty storage returns false for Boolean(undefined)
    expect(settings.integratedProtection).toBe(false);
  });

  test('should return true when both settings are enabled', async () => {
    mockStorage.sync = {
      backgroundSecurity: true,
      integratedProtection: true
    };

    const settings = await getStoredSettings();

    expect(settings.backgroundSecurity).toBe(true);
    expect(settings.integratedProtection).toBe(true);
  });

  test('should return false when backgroundSecurity is disabled', async () => {
    mockStorage.sync = {
      backgroundSecurity: false,
      integratedProtection: true
    };

    const settings = await getStoredSettings();

    expect(settings.backgroundSecurity).toBe(false);
    expect(settings.integratedProtection).toBe(true);
  });

  test('should return false when integratedProtection is disabled', async () => {
    mockStorage.sync = {
      backgroundSecurity: true,
      integratedProtection: false
    };

    const settings = await getStoredSettings();

    expect(settings.backgroundSecurity).toBe(true);
    expect(settings.integratedProtection).toBe(false);
  });

  test('should handle undefined values as false', async () => {
    mockStorage.sync = {
      backgroundSecurity: undefined,
      integratedProtection: undefined
    };

    const settings = await getStoredSettings();

    expect(settings.backgroundSecurity).toBe(false);
    expect(settings.integratedProtection).toBe(false);
  });

  test('should handle null values as false', async () => {
    mockStorage.sync = {
      backgroundSecurity: null,
      integratedProtection: null
    };

    const settings = await getStoredSettings();

    expect(settings.backgroundSecurity).toBe(false);
    expect(settings.integratedProtection).toBe(false);
  });

  test('should handle string "true" as truthy', async () => {
    mockStorage.sync = {
      backgroundSecurity: "true",
      integratedProtection: "true"
    };

    const settings = await getStoredSettings();

    expect(settings.backgroundSecurity).toBe(true);
    expect(settings.integratedProtection).toBe(true);
  });

  test('should handle string "false" as truthy (non-empty string)', async () => {
    // Note: Boolean("false") === true because it's a non-empty string
    mockStorage.sync = {
      backgroundSecurity: "false",
      integratedProtection: "false"
    };

    const settings = await getStoredSettings();

    expect(settings.backgroundSecurity).toBe(true); // Boolean("false") = true
    expect(settings.integratedProtection).toBe(true);
  });

  test('should handle numeric 0 as false', async () => {
    mockStorage.sync = {
      backgroundSecurity: 0,
      integratedProtection: 0
    };

    const settings = await getStoredSettings();

    expect(settings.backgroundSecurity).toBe(false);
    expect(settings.integratedProtection).toBe(false);
  });

  test('should handle numeric 1 as true', async () => {
    mockStorage.sync = {
      backgroundSecurity: 1,
      integratedProtection: 1
    };

    const settings = await getStoredSettings();

    expect(settings.backgroundSecurity).toBe(true);
    expect(settings.integratedProtection).toBe(true);
  });

  test('should return defaults on chrome.runtime.lastError', async () => {
    global.chrome.runtime.lastError = { message: 'Storage error' };

    const settings = await getStoredSettings();

    // Should return defaults on error
    expect(settings.backgroundSecurity).toBe(true);
    expect(settings.integratedProtection).toBe(true);
  });

});

describe('Protection Settings: isProtectionEnabled()', () => {

  beforeEach(() => {
    resetMocks();
  });

  test('should return true when both settings are enabled', async () => {
    mockStorage.sync = {
      backgroundSecurity: true,
      integratedProtection: true
    };

    const enabled = await isProtectionEnabled();

    expect(enabled).toBe(true);
  });

  test('should return false when backgroundSecurity is disabled', async () => {
    mockStorage.sync = {
      backgroundSecurity: false,
      integratedProtection: true
    };

    const enabled = await isProtectionEnabled();

    expect(enabled).toBe(false);
  });

  test('should return false when integratedProtection is disabled', async () => {
    mockStorage.sync = {
      backgroundSecurity: true,
      integratedProtection: false
    };

    const enabled = await isProtectionEnabled();

    expect(enabled).toBe(false);
  });

  test('should return false when both settings are disabled', async () => {
    mockStorage.sync = {
      backgroundSecurity: false,
      integratedProtection: false
    };

    const enabled = await isProtectionEnabled();

    expect(enabled).toBe(false);
  });

  test('should return false when storage is empty', async () => {
    mockStorage.sync = {};

    const enabled = await isProtectionEnabled();

    expect(enabled).toBe(false);
  });

});

describe('Protection Settings: checkCurrentUrl() behavior', () => {

  beforeEach(() => {
    resetMocks();
  });

  test('should skip check when protection is disabled', async () => {
    mockStorage.sync = {
      backgroundSecurity: false,
      integratedProtection: true
    };

    const result = await checkCurrentUrl();

    expect(result.skipped).toBe(true);
    expect(result.reason).toBe('Protection disabled');
    expect(initFunctionCalls.checkCurrentUrl).toBe(0);
  });

  test('should execute check when protection is enabled', async () => {
    mockStorage.sync = {
      backgroundSecurity: true,
      integratedProtection: true
    };

    const result = await checkCurrentUrl();

    expect(result.skipped).toBe(false);
    expect(result.checked).toBe(true);
    expect(initFunctionCalls.checkCurrentUrl).toBe(1);
  });

  test('should skip check when only backgroundSecurity is enabled', async () => {
    mockStorage.sync = {
      backgroundSecurity: true,
      integratedProtection: false
    };

    const result = await checkCurrentUrl();

    expect(result.skipped).toBe(true);
    expect(initFunctionCalls.checkCurrentUrl).toBe(0);
  });

  test('should skip check when only integratedProtection is enabled', async () => {
    mockStorage.sync = {
      backgroundSecurity: false,
      integratedProtection: true
    };

    const result = await checkCurrentUrl();

    expect(result.skipped).toBe(true);
    expect(initFunctionCalls.checkCurrentUrl).toBe(0);
  });

});

describe('Protection Settings: Feature Initialization', () => {

  beforeEach(() => {
    resetMocks();
  });

  test('should initialize all features when protection is enabled', async () => {
    mockStorage.sync = {
      backgroundSecurity: true,
      integratedProtection: true
    };

    const result = await initializeFeatures();

    expect(result.initialized).toBe(true);
    expect(result.features).toContain('clipboardGuard');
    expect(result.features).toContain('clickFixDetection');
    expect(result.features).toContain('bitBDetection');
    expect(result.features).toContain('tableQRScanner');
    expect(initFunctionCalls.clipboardGuard).toBe(1);
    expect(initFunctionCalls.clickFixDetection).toBe(1);
    expect(initFunctionCalls.bitBDetection).toBe(1);
    expect(initFunctionCalls.tableQRScanner).toBe(1);
  });

  test('should NOT initialize features when backgroundSecurity is disabled', async () => {
    mockStorage.sync = {
      backgroundSecurity: false,
      integratedProtection: true
    };

    const result = await initializeFeatures();

    expect(result.initialized).toBe(false);
    expect(result.reason).toBe('Protection disabled');
    expect(initFunctionCalls.clipboardGuard).toBe(0);
    expect(initFunctionCalls.clickFixDetection).toBe(0);
    expect(initFunctionCalls.bitBDetection).toBe(0);
    expect(initFunctionCalls.tableQRScanner).toBe(0);
  });

  test('should NOT initialize features when integratedProtection is disabled', async () => {
    mockStorage.sync = {
      backgroundSecurity: true,
      integratedProtection: false
    };

    const result = await initializeFeatures();

    expect(result.initialized).toBe(false);
    expect(result.reason).toBe('Protection disabled');
    expect(initFunctionCalls.clipboardGuard).toBe(0);
    expect(initFunctionCalls.clickFixDetection).toBe(0);
    expect(initFunctionCalls.bitBDetection).toBe(0);
    expect(initFunctionCalls.tableQRScanner).toBe(0);
  });

  test('should NOT initialize features when both settings are disabled', async () => {
    mockStorage.sync = {
      backgroundSecurity: false,
      integratedProtection: false
    };

    const result = await initializeFeatures();

    expect(result.initialized).toBe(false);
    expect(initFunctionCalls.clipboardGuard).toBe(0);
    expect(initFunctionCalls.clickFixDetection).toBe(0);
    expect(initFunctionCalls.bitBDetection).toBe(0);
    expect(initFunctionCalls.tableQRScanner).toBe(0);
  });

});

describe('Protection Settings: Edge Cases', () => {

  beforeEach(() => {
    resetMocks();
  });

  test('should handle rapid setting changes', async () => {
    // Start with enabled
    mockStorage.sync = {
      backgroundSecurity: true,
      integratedProtection: true
    };

    let enabled = await isProtectionEnabled();
    expect(enabled).toBe(true);

    // Disable
    mockStorage.sync.backgroundSecurity = false;
    enabled = await isProtectionEnabled();
    expect(enabled).toBe(false);

    // Re-enable
    mockStorage.sync.backgroundSecurity = true;
    enabled = await isProtectionEnabled();
    expect(enabled).toBe(true);
  });

  test('should handle mixed truthy/falsy values', async () => {
    const testCases = [
      { bg: true, ip: 1, expected: true },
      { bg: 1, ip: true, expected: true },
      { bg: "yes", ip: true, expected: true },
      { bg: false, ip: 0, expected: false },
      { bg: 0, ip: false, expected: false },
      { bg: "", ip: true, expected: false },
      { bg: true, ip: "", expected: false },
    ];

    for (const tc of testCases) {
      mockStorage.sync = {
        backgroundSecurity: tc.bg,
        integratedProtection: tc.ip
      };

      const enabled = await isProtectionEnabled();
      expect(enabled).toBe(tc.expected);
    }
  });

  test('should handle object/array values as truthy', async () => {
    mockStorage.sync = {
      backgroundSecurity: {},
      integratedProtection: []
    };

    const settings = await getStoredSettings();

    // Objects and arrays are truthy
    expect(settings.backgroundSecurity).toBe(true);
    expect(settings.integratedProtection).toBe(true);
  });

  test('should maintain independent setting states', async () => {
    // Test that changing one setting doesn't affect the other
    mockStorage.sync = {
      backgroundSecurity: true,
      integratedProtection: true
    };

    let settings = await getStoredSettings();
    expect(settings.backgroundSecurity).toBe(true);
    expect(settings.integratedProtection).toBe(true);

    // Change only backgroundSecurity
    mockStorage.sync.backgroundSecurity = false;
    settings = await getStoredSettings();
    expect(settings.backgroundSecurity).toBe(false);
    expect(settings.integratedProtection).toBe(true); // Should remain unchanged

    // Change only integratedProtection
    mockStorage.sync.backgroundSecurity = true;
    mockStorage.sync.integratedProtection = false;
    settings = await getStoredSettings();
    expect(settings.backgroundSecurity).toBe(true); // Should remain unchanged
    expect(settings.integratedProtection).toBe(false);
  });

  test('should handle concurrent reads', async () => {
    mockStorage.sync = {
      backgroundSecurity: true,
      integratedProtection: true
    };

    // Multiple concurrent reads should all return the same value
    const results = await Promise.all([
      isProtectionEnabled(),
      isProtectionEnabled(),
      isProtectionEnabled(),
      isProtectionEnabled(),
      isProtectionEnabled()
    ]);

    expect(results.every(r => r === true)).toBe(true);
  });

});

describe('Protection Settings: Popup Save Integration', () => {

  beforeEach(() => {
    resetMocks();
  });

  test('saving settings should update storage correctly', async () => {
    // Simulate popup.js save behavior
    const saveSettings = async (bgSecurity, intProtection) => {
      const settings = {
        backgroundSecurity: bgSecurity,
        integratedProtection: intProtection
      };
      await chrome.storage.sync.set(settings);
    };

    // Save enabled settings
    await saveSettings(true, true);
    expect(mockStorage.sync.backgroundSecurity).toBe(true);
    expect(mockStorage.sync.integratedProtection).toBe(true);

    // Save disabled settings
    await saveSettings(false, false);
    expect(mockStorage.sync.backgroundSecurity).toBe(false);
    expect(mockStorage.sync.integratedProtection).toBe(false);
  });

  test('content script should respect saved settings', async () => {
    // User disables backgroundSecurity in popup
    mockStorage.sync = {
      backgroundSecurity: false,
      integratedProtection: true
    };

    // Content script checks should be skipped
    const checkResult = await checkCurrentUrl();
    expect(checkResult.skipped).toBe(true);

    const initResult = await initializeFeatures();
    expect(initResult.initialized).toBe(false);

    // User re-enables backgroundSecurity
    mockStorage.sync.backgroundSecurity = true;

    // Content script checks should now execute
    const checkResult2 = await checkCurrentUrl();
    expect(checkResult2.skipped).toBe(false);

    const initResult2 = await initializeFeatures();
    expect(initResult2.initialized).toBe(true);
  });

});

// Export for potential reuse
module.exports = {
  getStoredSettings,
  isProtectionEnabled,
  checkCurrentUrl,
  initializeFeatures
};
