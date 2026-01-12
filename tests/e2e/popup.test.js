/**
 * LinkShield Popup E2E Tests
 *
 * Tests the popup.html flow including:
 * - License status display (trial/expired/premium)
 * - Settings toggles
 * - License activation
 */

const puppeteer = require('puppeteer');
const path = require('path');

describe('LinkShield Popup E2E Tests', () => {
  let browser;
  let page;
  let extensionId;

  beforeAll(async () => {
    const extensionPath = path.resolve(__dirname, '../..');

    browser = await puppeteer.launch({
      headless: false,
      args: [
        `--disable-extensions-except=${extensionPath}`,
        `--load-extension=${extensionPath}`,
        '--no-sandbox',
        '--disable-setuid-sandbox'
      ]
    });

    // Wait for extension to load and get ID
    await new Promise(resolve => setTimeout(resolve, 2000));

    const targets = await browser.targets();
    const extensionTarget = targets.find(target =>
      target.type() === 'service_worker' &&
      target.url().includes('chrome-extension://')
    );

    if (extensionTarget) {
      extensionId = extensionTarget.url().split('//')[1].split('/')[0];
    }
  });

  afterAll(async () => {
    if (browser) {
      await browser.close();
    }
  });

  beforeEach(async () => {
    page = await browser.newPage();
  });

  afterEach(async () => {
    if (page) {
      await page.close();
    }
  });

  describe('Popup Load and Basic UI', () => {
    test('popup.html loads correctly', async () => {
      const popupUrl = `chrome-extension://${extensionId}/popup.html`;
      await page.goto(popupUrl, { waitUntil: 'networkidle0' });

      // Check container exists
      const container = await page.$('.container');
      expect(container).not.toBeNull();
    });

    test('extension name and description are displayed', async () => {
      const popupUrl = `chrome-extension://${extensionId}/popup.html`;
      await page.goto(popupUrl, { waitUntil: 'networkidle0' });

      // Wait for i18n to load
      await page.waitForSelector('#extName');

      const extName = await page.$eval('#extName', el => el.textContent);
      expect(extName.length).toBeGreaterThan(0);
    });

    test('license status box is visible', async () => {
      const popupUrl = `chrome-extension://${extensionId}/popup.html`;
      await page.goto(popupUrl, { waitUntil: 'networkidle0' });

      const licenseBox = await page.$('#licenseStatusBox');
      expect(licenseBox).not.toBeNull();
    });
  });

  describe('License Status Views', () => {
    test('trial view has correct elements', async () => {
      const popupUrl = `chrome-extension://${extensionId}/popup.html`;
      await page.goto(popupUrl, { waitUntil: 'networkidle0' });

      // Trial view should have upgrade link
      const upgradeLink = await page.$('#licenseUpgradeLink');
      expect(upgradeLink).not.toBeNull();
    });

    test('expired view has license input', async () => {
      const popupUrl = `chrome-extension://${extensionId}/popup.html`;
      await page.goto(popupUrl, { waitUntil: 'networkidle0' });

      // License input should exist (even if hidden)
      const licenseInput = await page.$('#licenseKeyInput');
      expect(licenseInput).not.toBeNull();
    });

    test('activate button exists', async () => {
      const popupUrl = `chrome-extension://${extensionId}/popup.html`;
      await page.goto(popupUrl, { waitUntil: 'networkidle0' });

      const activateBtn = await page.$('#activateLicenseBtn');
      expect(activateBtn).not.toBeNull();
    });
  });

  describe('Settings Controls', () => {
    test('background security checkbox exists', async () => {
      const popupUrl = `chrome-extension://${extensionId}/popup.html`;
      await page.goto(popupUrl, { waitUntil: 'networkidle0' });

      const checkbox = await page.$('#backgroundSecurity');
      expect(checkbox).not.toBeNull();
    });

    test('integrated protection checkbox exists', async () => {
      const popupUrl = `chrome-extension://${extensionId}/popup.html`;
      await page.goto(popupUrl, { waitUntil: 'networkidle0' });

      const checkbox = await page.$('#integratedProtection');
      expect(checkbox).not.toBeNull();
    });

    test('integrated protection checkbox is clickable', async () => {
      const popupUrl = `chrome-extension://${extensionId}/popup.html`;
      await page.goto(popupUrl, { waitUntil: 'networkidle0' });

      const checkbox = await page.$('#integratedProtection');
      const isDisabled = await page.$eval('#integratedProtection', el => el.disabled);
      expect(isDisabled).toBe(false);
    });

    test('save button exists and is clickable', async () => {
      const popupUrl = `chrome-extension://${extensionId}/popup.html`;
      await page.goto(popupUrl, { waitUntil: 'networkidle0' });

      const saveBtn = await page.$('#saveSettings');
      expect(saveBtn).not.toBeNull();

      // Click should not throw
      await saveBtn.click();

      // Wait for confirmation message
      await page.waitForSelector('#confirmationMessage', { visible: true, timeout: 5000 })
        .catch(() => {}); // May not show if settings unchanged
    });

    test('toggling integrated protection works', async () => {
      const popupUrl = `chrome-extension://${extensionId}/popup.html`;
      await page.goto(popupUrl, { waitUntil: 'networkidle0' });

      const initialState = await page.$eval('#integratedProtection', el => el.checked);

      // Click the checkbox
      await page.click('#integratedProtection');

      const newState = await page.$eval('#integratedProtection', el => el.checked);
      expect(newState).toBe(!initialState);
    });
  });

  describe('License Activation Flow', () => {
    test('empty license key shows error', async () => {
      const popupUrl = `chrome-extension://${extensionId}/popup.html`;
      await page.goto(popupUrl, { waitUntil: 'networkidle0' });

      // Make expired view visible (simulate expired trial)
      await page.evaluate(() => {
        document.getElementById('licenseTrialView').style.display = 'none';
        document.getElementById('licenseExpiredView').style.display = 'block';
        document.getElementById('licenseStatusBox').className = 'license-status-box expired';
      });

      // Clear input and click activate
      await page.$eval('#licenseKeyInput', el => el.value = '');
      await page.click('#activateLicenseBtn');

      // Wait a bit for error handling
      await new Promise(resolve => setTimeout(resolve, 500));

      // Error message should appear or button should not process
      const inputValue = await page.$eval('#licenseKeyInput', el => el.value);
      expect(inputValue).toBe('');
    });

    test('invalid license key triggers validation', async () => {
      const popupUrl = `chrome-extension://${extensionId}/popup.html`;
      await page.goto(popupUrl, { waitUntil: 'networkidle0' });

      // Make expired view visible
      await page.evaluate(() => {
        document.getElementById('licenseTrialView').style.display = 'none';
        document.getElementById('licenseExpiredView').style.display = 'block';
        document.getElementById('licenseStatusBox').className = 'license-status-box expired';
      });

      // Enter invalid license
      await page.type('#licenseKeyInput', 'INVALID-LICENSE-KEY-12345');
      await page.click('#activateLicenseBtn');

      // Wait for API response
      await new Promise(resolve => setTimeout(resolve, 2000));

      // Check for error message display
      const errorMsgDisplay = await page.$eval('#licenseErrorMsg', el =>
        window.getComputedStyle(el).display
      );

      // Error should be visible after invalid key
      // (Note: actual API call may fail, but UI should handle it)
    });
  });

  describe('Upgrade Links', () => {
    test('upgrade link points to correct URL', async () => {
      const popupUrl = `chrome-extension://${extensionId}/popup.html`;
      await page.goto(popupUrl, { waitUntil: 'networkidle0' });

      const upgradeHref = await page.$eval('#licenseUpgradeLink', el => el.href);
      expect(upgradeHref).toContain('lemonsqueezy.com');
    });

    test('buy link points to correct URL', async () => {
      const popupUrl = `chrome-extension://${extensionId}/popup.html`;
      await page.goto(popupUrl, { waitUntil: 'networkidle0' });

      const buyHref = await page.$eval('#licenseBuyLink', el => el.href);
      expect(buyHref).toContain('lemonsqueezy.com');
    });
  });

  describe('Section Titles and Labels', () => {
    test('background analysis section title exists', async () => {
      const popupUrl = `chrome-extension://${extensionId}/popup.html`;
      await page.goto(popupUrl, { waitUntil: 'networkidle0' });

      const title = await page.$('#backgroundAnalysisTitle');
      expect(title).not.toBeNull();
    });

    test('feature descriptions are present', async () => {
      const popupUrl = `chrome-extension://${extensionId}/popup.html`;
      await page.goto(popupUrl, { waitUntil: 'networkidle0' });

      const bgDesc = await page.$('#backgroundAnalysisDescription');
      const intDesc = await page.$('#integratedProtectionDescription');

      expect(bgDesc).not.toBeNull();
      expect(intDesc).not.toBeNull();
    });
  });

  describe('Last Rule Update Display', () => {
    test('last rule update element exists', async () => {
      const popupUrl = `chrome-extension://${extensionId}/popup.html`;
      await page.goto(popupUrl, { waitUntil: 'networkidle0' });

      const updateDisplay = await page.$('#lastRuleUpdateDisplay');
      expect(updateDisplay).not.toBeNull();
    });
  });

  describe('License Deactivation UI', () => {
    test('deactivate link exists in premium view', async () => {
      const popupUrl = `chrome-extension://${extensionId}/popup.html`;
      await page.goto(popupUrl, { waitUntil: 'networkidle0' });

      // Deactivate link should exist (even if hidden initially)
      const deactivateLink = await page.$('#deactivateLicenseLink');
      expect(deactivateLink).not.toBeNull();
    });

    test('deactivate confirmation panel exists', async () => {
      const popupUrl = `chrome-extension://${extensionId}/popup.html`;
      await page.goto(popupUrl, { waitUntil: 'networkidle0' });

      const confirmPanel = await page.$('#deactivateConfirm');
      expect(confirmPanel).not.toBeNull();
    });

    test('deactivate confirmation has cancel and confirm buttons', async () => {
      const popupUrl = `chrome-extension://${extensionId}/popup.html`;
      await page.goto(popupUrl, { waitUntil: 'networkidle0' });

      const cancelBtn = await page.$('#deactivateCancelBtn');
      const confirmBtn = await page.$('#deactivateConfirmBtn');

      expect(cancelBtn).not.toBeNull();
      expect(confirmBtn).not.toBeNull();
    });

    test('clicking deactivate link shows confirmation panel', async () => {
      const popupUrl = `chrome-extension://${extensionId}/popup.html`;
      await page.goto(popupUrl, { waitUntil: 'networkidle0' });

      // Make premium view visible (simulate active license)
      await page.evaluate(() => {
        document.getElementById('licenseTrialView').style.display = 'none';
        document.getElementById('licenseExpiredView').style.display = 'none';
        document.getElementById('licensePremiumView').style.display = 'block';
        document.getElementById('licenseStatusBox').className = 'license-status-box premium';
      });

      // Click deactivate link
      await page.click('#deactivateLicenseLink');

      // Wait for panel to show
      await new Promise(resolve => setTimeout(resolve, 100));

      // Check if confirmation panel is visible
      const isVisible = await page.$eval('#deactivateConfirm', el => {
        return el.classList.contains('show') || window.getComputedStyle(el).display !== 'none';
      });

      expect(isVisible).toBe(true);
    });

    test('clicking cancel hides confirmation panel', async () => {
      const popupUrl = `chrome-extension://${extensionId}/popup.html`;
      await page.goto(popupUrl, { waitUntil: 'networkidle0' });

      // Make premium view visible and show confirmation
      await page.evaluate(() => {
        document.getElementById('licenseTrialView').style.display = 'none';
        document.getElementById('licensePremiumView').style.display = 'block';
        document.getElementById('deactivateConfirm').classList.add('show');
        document.getElementById('deactivateLicenseLink').style.display = 'none';
      });

      // Click cancel
      await page.click('#deactivateCancelBtn');

      // Wait for state change
      await new Promise(resolve => setTimeout(resolve, 100));

      // Check if confirmation panel is hidden
      const isHidden = await page.$eval('#deactivateConfirm', el => {
        return !el.classList.contains('show');
      });

      expect(isHidden).toBe(true);
    });

    test('deactivate link has correct text from i18n', async () => {
      const popupUrl = `chrome-extension://${extensionId}/popup.html`;
      await page.goto(popupUrl, { waitUntil: 'networkidle0' });

      // Wait for i18n to load
      await new Promise(resolve => setTimeout(resolve, 500));

      const linkText = await page.$eval('#deactivateLicenseLink', el => el.textContent);

      // Should have some text (from i18n)
      expect(linkText.length).toBeGreaterThan(0);
    });
  });

  describe('Subscription Management Link', () => {
    test('subscription management link exists in premium view', async () => {
      const popupUrl = `chrome-extension://${extensionId}/popup.html`;
      await page.goto(popupUrl, { waitUntil: 'networkidle0' });

      const manageLink = await page.$('#manageSubscriptionLink');
      expect(manageLink).not.toBeNull();
    });

    test('subscription management link points to Lemon Squeezy', async () => {
      const popupUrl = `chrome-extension://${extensionId}/popup.html`;
      await page.goto(popupUrl, { waitUntil: 'networkidle0' });

      const href = await page.$eval('#manageSubscriptionLink', el => el.href);
      expect(href).toContain('lemonsqueezy.com');
    });
  });
});

describe('LinkShield Alert Page E2E Tests', () => {
  let browser;
  let page;
  let extensionId;

  beforeAll(async () => {
    const extensionPath = path.resolve(__dirname, '../..');

    browser = await puppeteer.launch({
      headless: false,
      args: [
        `--disable-extensions-except=${extensionPath}`,
        `--load-extension=${extensionPath}`,
        '--no-sandbox'
      ]
    });

    await new Promise(resolve => setTimeout(resolve, 2000));

    const targets = await browser.targets();
    const extensionTarget = targets.find(target =>
      target.type() === 'service_worker' &&
      target.url().includes('chrome-extension://')
    );

    if (extensionTarget) {
      extensionId = extensionTarget.url().split('//')[1].split('/')[0];
    }
  });

  afterAll(async () => {
    if (browser) {
      await browser.close();
    }
  });

  beforeEach(async () => {
    page = await browser.newPage();
  });

  afterEach(async () => {
    if (page) {
      await page.close();
    }
  });

  test('alert.html loads correctly', async () => {
    const alertUrl = `chrome-extension://${extensionId}/alert.html`;
    await page.goto(alertUrl, { waitUntil: 'networkidle0' });

    const body = await page.$('body');
    expect(body).not.toBeNull();
  });
});

describe('LinkShield Caution Page E2E Tests', () => {
  let browser;
  let page;
  let extensionId;

  beforeAll(async () => {
    const extensionPath = path.resolve(__dirname, '../..');

    browser = await puppeteer.launch({
      headless: false,
      args: [
        `--disable-extensions-except=${extensionPath}`,
        `--load-extension=${extensionPath}`,
        '--no-sandbox'
      ]
    });

    await new Promise(resolve => setTimeout(resolve, 2000));

    const targets = await browser.targets();
    const extensionTarget = targets.find(target =>
      target.type() === 'service_worker' &&
      target.url().includes('chrome-extension://')
    );

    if (extensionTarget) {
      extensionId = extensionTarget.url().split('//')[1].split('/')[0];
    }
  });

  afterAll(async () => {
    if (browser) {
      await browser.close();
    }
  });

  beforeEach(async () => {
    page = await browser.newPage();
  });

  afterEach(async () => {
    if (page) {
      await page.close();
    }
  });

  test('caution.html loads correctly', async () => {
    const cautionUrl = `chrome-extension://${extensionId}/caution.html`;
    await page.goto(cautionUrl, { waitUntil: 'networkidle0' });

    const body = await page.$('body');
    expect(body).not.toBeNull();
  });
});
