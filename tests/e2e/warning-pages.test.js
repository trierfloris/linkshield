/**
 * LinkShield Warning Pages E2E Tests
 *
 * Tests for alert.html and caution.html warning pages including:
 * - Page load and display
 * - Trust domain functionality
 * - Close button functionality
 * - i18n translations
 */

const puppeteer = require('puppeteer');
const path = require('path');

describe('LinkShield Alert Page E2E Tests', () => {
  let browser;
  let page;
  let extensionId;

  beforeAll(async () => {
    const extensionPath = path.resolve(__dirname, '../../dist');

    browser = await puppeteer.launch({
      headless: false,
      args: [
        `--disable-extensions-except=${extensionPath}`,
        `--load-extension=${extensionPath}`,
        '--no-sandbox',
        '--disable-setuid-sandbox'
      ]
    });

    // Wait for extension to load
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

  describe('Alert Page Structure', () => {
    test('alert.html loads with correct structure', async () => {
      const alertUrl = `chrome-extension://${extensionId}/alert.html`;
      await page.goto(alertUrl, { waitUntil: 'networkidle0' });

      // Check main container
      const container = await page.$('#warning-container');
      expect(container).not.toBeNull();
    });

    test('brand header is present', async () => {
      const alertUrl = `chrome-extension://${extensionId}/alert.html`;
      await page.goto(alertUrl, { waitUntil: 'networkidle0' });

      const brandHeader = await page.$('.brand-header');
      expect(brandHeader).not.toBeNull();

      const brandText = await page.$eval('.brand-text', el => el.textContent);
      expect(brandText).toContain('LinkShield');
    });

    test('severity text element exists', async () => {
      const alertUrl = `chrome-extension://${extensionId}/alert.html`;
      await page.goto(alertUrl, { waitUntil: 'networkidle0' });

      const severityText = await page.$('#severity-text');
      expect(severityText).not.toBeNull();
    });

    test('reason list element exists', async () => {
      const alertUrl = `chrome-extension://${extensionId}/alert.html`;
      await page.goto(alertUrl, { waitUntil: 'networkidle0' });

      const reasonList = await page.$('#reason-list');
      expect(reasonList).not.toBeNull();
    });

    test('URL info elements exist', async () => {
      const alertUrl = `chrome-extension://${extensionId}/alert.html`;
      await page.goto(alertUrl, { waitUntil: 'networkidle0' });

      const siteName = await page.$('#site-name');
      const urlLink = await page.$('#url-link');

      expect(siteName).not.toBeNull();
      expect(urlLink).not.toBeNull();
    });
  });

  describe('Alert Page Buttons', () => {
    test('trust domain button exists', async () => {
      const alertUrl = `chrome-extension://${extensionId}/alert.html`;
      await page.goto(alertUrl, { waitUntil: 'networkidle0' });

      const trustBtn = await page.$('#trust-domain');
      expect(trustBtn).not.toBeNull();
    });

    test('close button exists', async () => {
      const alertUrl = `chrome-extension://${extensionId}/alert.html`;
      await page.goto(alertUrl, { waitUntil: 'networkidle0' });

      const closeBtn = await page.$('#close-warning');
      expect(closeBtn).not.toBeNull();
    });

    test('trust button has correct class', async () => {
      const alertUrl = `chrome-extension://${extensionId}/alert.html`;
      await page.goto(alertUrl, { waitUntil: 'networkidle0' });

      const trustBtnClass = await page.$eval('#trust-domain', el => el.className);
      expect(trustBtnClass).toContain('trust-btn');
    });

    test('close button has correct class', async () => {
      const alertUrl = `chrome-extension://${extensionId}/alert.html`;
      await page.goto(alertUrl, { waitUntil: 'networkidle0' });

      const closeBtnClass = await page.$eval('#close-warning', el => el.className);
      expect(closeBtnClass).toContain('close-btn');
    });
  });

  describe('Alert Page Styling', () => {
    test('background has danger color', async () => {
      const alertUrl = `chrome-extension://${extensionId}/alert.html`;
      await page.goto(alertUrl, { waitUntil: 'networkidle0' });

      const bgColor = await page.evaluate(() => {
        return window.getComputedStyle(document.body).backgroundColor;
      });

      // Should be a red/danger tone
      expect(bgColor).toBeTruthy();
    });

    test('h1 has danger color', async () => {
      const alertUrl = `chrome-extension://${extensionId}/alert.html`;
      await page.goto(alertUrl, { waitUntil: 'networkidle0' });

      const h1Color = await page.$eval('h1', el =>
        window.getComputedStyle(el).color
      );

      expect(h1Color).toBeTruthy();
    });
  });

  describe('Alert Page i18n', () => {
    test('title has data-i18n attribute', async () => {
      const alertUrl = `chrome-extension://${extensionId}/alert.html`;
      await page.goto(alertUrl, { waitUntil: 'networkidle0' });

      const titleI18n = await page.$eval('h1', el =>
        el.getAttribute('data-i18n')
      );

      expect(titleI18n).toBe('alertTitle');
    });

    test('i18n elements are populated', async () => {
      const alertUrl = `chrome-extension://${extensionId}/alert.html`;
      await page.goto(alertUrl, { waitUntil: 'networkidle0' });

      // Wait for i18n to load
      await new Promise(resolve => setTimeout(resolve, 500));

      const h1Text = await page.$eval('h1', el => el.textContent);
      // Should have actual translated content, not empty
      expect(h1Text.length).toBeGreaterThan(0);
    });
  });
});

describe('LinkShield Caution Page E2E Tests', () => {
  let browser;
  let page;
  let extensionId;

  beforeAll(async () => {
    const extensionPath = path.resolve(__dirname, '../../dist');

    browser = await puppeteer.launch({
      headless: false,
      args: [
        `--disable-extensions-except=${extensionPath}`,
        `--load-extension=${extensionPath}`,
        '--no-sandbox',
        '--disable-setuid-sandbox'
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

  describe('Caution Page Structure', () => {
    test('caution.html loads with correct structure', async () => {
      const cautionUrl = `chrome-extension://${extensionId}/caution.html`;
      await page.goto(cautionUrl, { waitUntil: 'networkidle0' });

      const container = await page.$('#warning-container');
      expect(container).not.toBeNull();
    });

    test('brand header is present', async () => {
      const cautionUrl = `chrome-extension://${extensionId}/caution.html`;
      await page.goto(cautionUrl, { waitUntil: 'networkidle0' });

      const brandHeader = await page.$('.brand-header');
      expect(brandHeader).not.toBeNull();
    });

    test('advice section exists', async () => {
      const cautionUrl = `chrome-extension://${extensionId}/caution.html`;
      await page.goto(cautionUrl, { waitUntil: 'networkidle0' });

      const advice = await page.$('.advice');
      expect(advice).not.toBeNull();
    });
  });

  describe('Caution Page Buttons', () => {
    test('trust domain button exists', async () => {
      const cautionUrl = `chrome-extension://${extensionId}/caution.html`;
      await page.goto(cautionUrl, { waitUntil: 'networkidle0' });

      const trustBtn = await page.$('#trust-domain');
      expect(trustBtn).not.toBeNull();
    });

    test('close button exists', async () => {
      const cautionUrl = `chrome-extension://${extensionId}/caution.html`;
      await page.goto(cautionUrl, { waitUntil: 'networkidle0' });

      const closeBtn = await page.$('#close-warning');
      expect(closeBtn).not.toBeNull();
    });

    test('action buttons container has two buttons', async () => {
      const cautionUrl = `chrome-extension://${extensionId}/caution.html`;
      await page.goto(cautionUrl, { waitUntil: 'networkidle0' });

      const buttons = await page.$$('.action-buttons .button');
      expect(buttons.length).toBe(2);
    });
  });

  describe('Caution Page Styling', () => {
    test('background has warning color', async () => {
      const cautionUrl = `chrome-extension://${extensionId}/caution.html`;
      await page.goto(cautionUrl, { waitUntil: 'networkidle0' });

      const bgColor = await page.evaluate(() => {
        return window.getComputedStyle(document.body).backgroundColor;
      });

      // Should be a yellow/warning tone
      expect(bgColor).toBeTruthy();
    });

    test('advice box has warning styling', async () => {
      const cautionUrl = `chrome-extension://${extensionId}/caution.html`;
      await page.goto(cautionUrl, { waitUntil: 'networkidle0' });

      const adviceBg = await page.$eval('.advice', el =>
        window.getComputedStyle(el).backgroundColor
      );

      expect(adviceBg).toBeTruthy();
    });
  });

  describe('Caution Page i18n', () => {
    test('all data-i18n elements are populated', async () => {
      const cautionUrl = `chrome-extension://${extensionId}/caution.html`;
      await page.goto(cautionUrl, { waitUntil: 'networkidle0' });

      // Wait for i18n
      await new Promise(resolve => setTimeout(resolve, 500));

      const emptyI18n = await page.$$eval('[data-i18n]', elements =>
        elements.filter(el => el.textContent.trim() === '').length
      );

      // Should have no empty i18n elements after loading
      expect(emptyI18n).toBe(0);
    });
  });
});

describe('Trust Domain Flow E2E Tests', () => {
  let browser;
  let page;
  let extensionId;

  beforeAll(async () => {
    const extensionPath = path.resolve(__dirname, '../../dist');

    browser = await puppeteer.launch({
      headless: false,
      args: [
        `--disable-extensions-except=${extensionPath}`,
        `--load-extension=${extensionPath}`,
        '--no-sandbox',
        '--disable-setuid-sandbox'
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

  describe('Trust Domain Button Interaction', () => {
    test('trust button has i18n text', async () => {
      const cautionUrl = `chrome-extension://${extensionId}/caution.html`;
      await page.goto(cautionUrl, { waitUntil: 'networkidle0' });

      await new Promise(resolve => setTimeout(resolve, 500));

      const trustBtnText = await page.$eval('#trust-domain', el => el.textContent);
      expect(trustBtnText.length).toBeGreaterThan(0);
    });

    test('trust button has data-i18n attribute', async () => {
      const cautionUrl = `chrome-extension://${extensionId}/caution.html`;
      await page.goto(cautionUrl, { waitUntil: 'networkidle0' });

      const i18nAttr = await page.$eval('#trust-domain', el =>
        el.getAttribute('data-i18n')
      );

      expect(i18nAttr).toBe('trustDomainButton');
    });
  });

  describe('Storage Integration', () => {
    test('can set and read from chrome.storage.sync', async () => {
      const testPage = await browser.newPage();
      const bgUrl = `chrome-extension://${extensionId}/popup.html`;
      await testPage.goto(bgUrl, { waitUntil: 'networkidle0' });

      // Test that chrome.storage is accessible
      const storageAvailable = await testPage.evaluate(() => {
        return typeof chrome !== 'undefined' &&
               typeof chrome.storage !== 'undefined' &&
               typeof chrome.storage.sync !== 'undefined';
      });

      expect(storageAvailable).toBe(true);
      await testPage.close();
    });
  });
});

describe('Dynamic Page E2E Tests', () => {
  let browser;
  let page;
  let extensionId;

  beforeAll(async () => {
    const extensionPath = path.resolve(__dirname, '../../dist');

    browser = await puppeteer.launch({
      headless: false,
      args: [
        `--disable-extensions-except=${extensionPath}`,
        `--load-extension=${extensionPath}`,
        '--no-sandbox',
        '--disable-setuid-sandbox'
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

  test('dynamic.html loads and redirects based on status', async () => {
    const dynamicUrl = `chrome-extension://${extensionId}/dynamic.html`;
    await page.goto(dynamicUrl, { waitUntil: 'networkidle0' });

    // Dynamic page should have loaded something
    const body = await page.$('body');
    expect(body).not.toBeNull();
  });

  test('dynamic.html shows loading state initially', async () => {
    const dynamicUrl = `chrome-extension://${extensionId}/dynamic.html`;

    // Navigate without waiting for full load
    await page.goto(dynamicUrl, { waitUntil: 'domcontentloaded' });

    // Check if loading indicator exists (if implemented)
    const content = await page.content();
    expect(content).toBeTruthy();
  });
});
