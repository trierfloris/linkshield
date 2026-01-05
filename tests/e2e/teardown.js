/**
 * Puppeteer Global Teardown for LinkShield E2E Tests
 */

module.exports = async () => {
  console.log('\nTearing down Puppeteer...');

  if (global.__BROWSER__) {
    await global.__BROWSER__.close();
  }

  console.log('Puppeteer teardown complete.\n');
};
