/**
 * Jest Configuration for LinkShield Chrome Extension
 */

module.exports = {
  // Test environment
  testEnvironment: 'jsdom',

  // Setup files to run before tests
  setupFilesAfterEnv: ['<rootDir>/tests/setup.js'],

  // Test file patterns
  testMatch: [
    '<rootDir>/tests/**/*.test.js',
    '<rootDir>/tests/**/*.spec.js'
  ],

  // Exclude E2E tests
  testPathIgnorePatterns: [
    '/node_modules/',
    '<rootDir>/tests/e2e/'
  ],

  // Coverage configuration
  collectCoverageFrom: [
    'content.js',
    'background.js',
    'popup.js',
    'config.js',
    '!node_modules/**',
    '!tests/**'
  ],

  // Verbose output
  verbose: true,

  // Test timeout
  testTimeout: 10000
};
