/**
 * Jest Setup File - Mocks voor Chrome Extension APIs
 */

// Mock Chrome API
global.chrome = {
  i18n: {
    getMessage: jest.fn((key) => key),
    getUILanguage: jest.fn(() => 'en')
  },
  storage: {
    sync: {
      get: jest.fn(() => Promise.resolve({})),
      set: jest.fn(() => Promise.resolve())
    },
    local: {
      get: jest.fn(() => Promise.resolve({})),
      set: jest.fn(() => Promise.resolve())
    }
  },
  runtime: {
    sendMessage: jest.fn(),
    onMessage: {
      addListener: jest.fn()
    }
  }
};

// Mock window.location
delete global.window.location;
global.window.location = {
  href: 'https://example.com',
  hostname: 'example.com',
  protocol: 'https:',
  pathname: '/',
  search: '',
  hash: ''
};

// Mock trustedDomains (loaded from TrustedDomains.json)
global.window.trustedDomains = [
  'google.com',
  'youtube.com',
  'facebook.com',
  'amazon.com',
  'microsoft.com',
  'apple.com',
  'linkedin.com',
  'wikipedia.org',
  'twitter.com',
  'instagram.com'
];

// Mock safeDomains array
global.safeDomains = global.window.trustedDomains;

// Mock punycode
global.punycode = {
  toUnicode: jest.fn((str) => str),
  toASCII: jest.fn((str) => str)
};

// Mock console methods for cleaner test output
global.console = {
  ...console,
  log: jest.fn(),
  info: jest.fn(),
  warn: jest.fn(),
  error: jest.fn()
};
