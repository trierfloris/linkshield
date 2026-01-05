/**
 * Jest E2E Configuration for LinkShield Chrome Extension
 * Uses Puppeteer for browser-based testing
 */

module.exports = {
  // Use node environment for Puppeteer
  testEnvironment: 'node',

  // E2E test files
  testMatch: [
    '<rootDir>/tests/e2e/**/*.test.js',
    '<rootDir>/tests/e2e/**/*.spec.js'
  ],

  // Longer timeout for E2E tests
  testTimeout: 60000,

  // Verbose output
  verbose: true,

  // Setup/teardown for Puppeteer
  globalSetup: '<rootDir>/tests/e2e/setup.js',
  globalTeardown: '<rootDir>/tests/e2e/teardown.js'
};
