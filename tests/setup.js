/**
 * Jest Setup - Mock Chrome Extension APIs
 */

// Mock chrome.storage
const mockStorage = {
  sync: {
    data: {},
    get: jest.fn((keys, callback) => {
      if (typeof keys === 'function') {
        callback = keys;
        keys = null;
      }
      const result = {};
      if (keys === null) {
        Object.assign(result, mockStorage.sync.data);
      } else if (typeof keys === 'string') {
        result[keys] = mockStorage.sync.data[keys];
      } else if (Array.isArray(keys)) {
        keys.forEach(key => {
          result[key] = mockStorage.sync.data[key];
        });
      } else if (typeof keys === 'object') {
        Object.keys(keys).forEach(key => {
          result[key] = mockStorage.sync.data[key] !== undefined
            ? mockStorage.sync.data[key]
            : keys[key];
        });
      }
      if (callback) callback(result);
      return Promise.resolve(result);
    }),
    set: jest.fn((items, callback) => {
      Object.assign(mockStorage.sync.data, items);
      if (callback) callback();
      return Promise.resolve();
    }),
    remove: jest.fn((keys, callback) => {
      if (typeof keys === 'string') {
        delete mockStorage.sync.data[keys];
      } else if (Array.isArray(keys)) {
        keys.forEach(key => delete mockStorage.sync.data[key]);
      }
      if (callback) callback();
      return Promise.resolve();
    }),
    clear: jest.fn((callback) => {
      mockStorage.sync.data = {};
      if (callback) callback();
      return Promise.resolve();
    })
  },
  local: {
    data: {},
    get: jest.fn((keys, callback) => {
      if (typeof keys === 'function') {
        callback = keys;
        keys = null;
      }
      const result = {};
      if (keys === null) {
        Object.assign(result, mockStorage.local.data);
      } else if (typeof keys === 'string') {
        result[keys] = mockStorage.local.data[keys];
      } else if (Array.isArray(keys)) {
        keys.forEach(key => {
          result[key] = mockStorage.local.data[key];
        });
      }
      if (callback) callback(result);
      return Promise.resolve(result);
    }),
    set: jest.fn((items, callback) => {
      Object.assign(mockStorage.local.data, items);
      if (callback) callback();
      return Promise.resolve();
    }),
    remove: jest.fn((keys, callback) => {
      if (typeof keys === 'string') {
        delete mockStorage.local.data[keys];
      } else if (Array.isArray(keys)) {
        keys.forEach(key => delete mockStorage.local.data[key]);
      }
      if (callback) callback();
      return Promise.resolve();
    }),
    clear: jest.fn((callback) => {
      mockStorage.local.data = {};
      if (callback) callback();
      return Promise.resolve();
    })
  },
  onChanged: {
    addListener: jest.fn(),
    removeListener: jest.fn()
  }
};

// Mock chrome.runtime
const mockRuntime = {
  lastError: null,
  sendMessage: jest.fn((message, callback) => {
    if (callback) callback({});
    return Promise.resolve({});
  }),
  onMessage: {
    addListener: jest.fn(),
    removeListener: jest.fn()
  },
  onInstalled: {
    addListener: jest.fn()
  },
  onStartup: {
    addListener: jest.fn()
  },
  getURL: jest.fn(path => `chrome-extension://mock-id/${path}`)
};

// Mock chrome.i18n
const mockI18n = {
  getMessage: jest.fn((key, substitutions) => {
    return key;
  }),
  getUILanguage: jest.fn(() => 'en')
};

// Mock chrome.tabs
const mockTabs = {
  query: jest.fn((queryInfo, callback) => {
    if (callback) callback([{ id: 1, url: 'https://example.com' }]);
    return Promise.resolve([{ id: 1, url: 'https://example.com' }]);
  }),
  sendMessage: jest.fn(),
  onUpdated: {
    addListener: jest.fn()
  }
};

// Mock chrome.action (MV3)
const mockAction = {
  setIcon: jest.fn(),
  setBadgeText: jest.fn(),
  setBadgeBackgroundColor: jest.fn()
};

// Mock chrome.alarms
const mockAlarms = {
  create: jest.fn(),
  clear: jest.fn(),
  get: jest.fn((name, callback) => {
    if (callback) callback(null);
  }),
  onAlarm: {
    addListener: jest.fn()
  }
};

// Mock chrome.declarativeNetRequest
const mockDeclarativeNetRequest = {
  updateDynamicRules: jest.fn(() => Promise.resolve()),
  getDynamicRules: jest.fn(() => Promise.resolve([]))
};

// Assemble chrome object
global.chrome = {
  storage: mockStorage,
  runtime: mockRuntime,
  i18n: mockI18n,
  tabs: mockTabs,
  action: mockAction,
  alarms: mockAlarms,
  declarativeNetRequest: mockDeclarativeNetRequest
};

// Reset mocks before each test
beforeEach(() => {
  jest.clearAllMocks();
  mockStorage.sync.data = {};
  mockStorage.local.data = {};
  mockRuntime.lastError = null;
});

// Export for use in tests
module.exports = {
  mockStorage,
  mockRuntime,
  mockI18n,
  mockTabs,
  mockAction,
  mockAlarms,
  mockDeclarativeNetRequest
};
