/**
 * Puppeteer Global Setup for LinkShield E2E Tests
 */

const puppeteer = require('puppeteer');
const path = require('path');
const fs = require('fs');

module.exports = async () => {
  console.log('\nSetting up Puppeteer for E2E tests...');

  const extensionPath = path.resolve(__dirname, '../..');

  // Verify extension path exists
  if (!fs.existsSync(path.join(extensionPath, 'manifest.json'))) {
    throw new Error(`Extension manifest not found at ${extensionPath}`);
  }

  // Launch browser with extension loaded
  const browser = await puppeteer.launch({
    headless: false, // Extensions require headed mode in Puppeteer
    args: [
      `--disable-extensions-except=${extensionPath}`,
      `--load-extension=${extensionPath}`,
      '--no-sandbox',
      '--disable-setuid-sandbox'
    ]
  });

  // Get the extension ID
  const targets = await browser.targets();
  const extensionTarget = targets.find(target =>
    target.type() === 'service_worker' &&
    target.url().includes('chrome-extension://')
  );

  if (extensionTarget) {
    const extensionUrl = extensionTarget.url();
    const extensionId = extensionUrl.split('//')[1].split('/')[0];
    global.__EXTENSION_ID__ = extensionId;
    console.log(`Extension loaded with ID: ${extensionId}`);
  }

  // Store browser for teardown
  global.__BROWSER__ = browser;

  console.log('Puppeteer setup complete.\n');
};
