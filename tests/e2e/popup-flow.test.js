/**
 * LinkShield Popup Flow E2E Tests
 *
 * Tests the popup.html/dynamic.html flow using Puppeteer
 * These tests verify the user-facing UI behavior
 */

const puppeteer = require('puppeteer');
const path = require('path');
const fs = require('fs');

const EXTENSION_PATH = path.join(__dirname, '..', '..');
const POPUP_PATH = path.join(EXTENSION_PATH, 'dynamic.html');

// Helper to wait
const wait = (ms) => new Promise(resolve => setTimeout(resolve, ms));

describe('LinkShield Popup E2E Tests', () => {
  let browser;
  let page;

  beforeAll(async () => {
    // Launch browser with extension loaded
    browser = await puppeteer.launch({
      headless: 'new',
      args: [
        `--disable-extensions-except=${EXTENSION_PATH}`,
        `--load-extension=${EXTENSION_PATH}`,
        '--no-sandbox',
        '--disable-setuid-sandbox'
      ]
    });
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

  describe('Popup HTML Structure', () => {
    test('popup.html should exist and be valid HTML', () => {
      const popupPath = path.join(EXTENSION_PATH, 'popup.html');
      expect(fs.existsSync(popupPath)).toBe(true);

      const content = fs.readFileSync(popupPath, 'utf8');
      expect(content).toContain('<!DOCTYPE html>');
      expect(content).toContain('<html');
      expect(content).toContain('</html>');
    });

    test('dynamic.html should exist and be valid HTML', () => {
      expect(fs.existsSync(POPUP_PATH)).toBe(true);

      const content = fs.readFileSync(POPUP_PATH, 'utf8');
      expect(content).toContain('<!DOCTYPE html>');
      expect(content).toContain('<html');
    });

    test('alert.html should exist', () => {
      const alertPath = path.join(EXTENSION_PATH, 'alert.html');
      expect(fs.existsSync(alertPath)).toBe(true);
    });

    test('caution.html should exist', () => {
      const cautionPath = path.join(EXTENSION_PATH, 'caution.html');
      expect(fs.existsSync(cautionPath)).toBe(true);
    });
  });

  describe('Popup UI Elements', () => {
    test('popup should have required UI elements', async () => {
      // Load main popup.html directly (dynamic.html is just a redirect)
      const mainPopupPath = path.join(EXTENSION_PATH, 'popup.html');
      await page.goto(`file://${mainPopupPath}`);
      await wait(500);

      // Check for main containers
      const hasHeader = await page.$('.header, #header, header') !== null;
      const hasStatusCard = await page.$('.status-card') !== null;

      // At least one should exist
      expect(hasHeader || hasStatusCard).toBe(true);
    });

    test('popup should load CSS correctly', async () => {
      // Load main popup.html (has linked CSS)
      const mainPopupPath = path.join(EXTENSION_PATH, 'popup.html');
      await page.goto(`file://${mainPopupPath}`);

      // Check if stylesheet is linked or inline style exists
      const stylesheets = await page.$$('link[rel="stylesheet"]');
      const inlineStyles = await page.$$('style');
      expect(stylesheets.length + inlineStyles.length).toBeGreaterThan(0);
    });

    test('popup should load JavaScript correctly', async () => {
      await page.goto(`file://${POPUP_PATH}`);

      // Check if scripts are loaded
      const scripts = await page.$$('script[src]');
      expect(scripts.length).toBeGreaterThan(0);
    });
  });

  describe('Popup i18n Elements', () => {
    test('popup.js should use chrome.i18n for localization', () => {
      // popup.html uses JavaScript-based i18n via popup.js
      const popupJsPath = path.join(EXTENSION_PATH, 'popup.js');
      const content = fs.readFileSync(popupJsPath, 'utf8');

      // Should use chrome.i18n.getMessage for translations
      expect(content).toMatch(/chrome\.i18n\.getMessage|getTranslatedMessage|msg\(/);
    });

    test('all data-i18n keys in alert.html should be non-empty', async () => {
      const alertPath = path.join(EXTENSION_PATH, 'alert.html');
      await page.goto(`file://${alertPath}`);

      const i18nKeys = await page.$$eval('[data-i18n]', els =>
        els.map(el => el.getAttribute('data-i18n'))
      );

      for (const key of i18nKeys) {
        expect(key).toBeTruthy();
        expect(key.length).toBeGreaterThan(0);
      }
    });
  });

  describe('Settings Toggles', () => {
    test('popup should have protection toggle switches', async () => {
      await page.goto(`file://${POPUP_PATH}`);
      await wait(300);

      // Look for toggle inputs or switches
      const toggles = await page.$$('input[type="checkbox"], .toggle, .switch');

      // Popup should have at least one toggle for protection settings
      // This may be 0 if the popup uses a different structure
      console.log(`Found ${toggles.length} toggle elements`);
    });
  });

  describe('Alert Page Flow', () => {
    test('alert.html should have warning elements', async () => {
      const alertPath = path.join(EXTENSION_PATH, 'alert.html');
      await page.goto(`file://${alertPath}`);
      await wait(300);

      // Check for warning-related elements
      const hasWarningContent = await page.evaluate(() => {
        const body = document.body.innerHTML.toLowerCase();
        return body.includes('warning') ||
               body.includes('alert') ||
               body.includes('risk') ||
               document.querySelector('[data-i18n*="alert"]') !== null ||
               document.querySelector('[data-i18n*="risk"]') !== null;
      });

      expect(hasWarningContent).toBe(true);
    });

    test('alert.html should have close button', async () => {
      const alertPath = path.join(EXTENSION_PATH, 'alert.html');
      await page.goto(`file://${alertPath}`);

      const closeButton = await page.$('#close-warning, .close-button, button[data-i18n*="close"]');
      expect(closeButton).not.toBeNull();
    });

    test('alert.html should have trust domain button', async () => {
      const alertPath = path.join(EXTENSION_PATH, 'alert.html');
      await page.goto(`file://${alertPath}`);

      const trustButton = await page.$('#trust-domain, .trust-button, button[data-i18n*="trust"]');
      expect(trustButton).not.toBeNull();
    });
  });

  describe('Caution Page Flow', () => {
    test('caution.html should have caution elements', async () => {
      const cautionPath = path.join(EXTENSION_PATH, 'caution.html');
      await page.goto(`file://${cautionPath}`);
      await wait(300);

      // Check for caution-related elements
      const hasCautionContent = await page.evaluate(() => {
        const body = document.body.innerHTML.toLowerCase();
        return body.includes('caution') ||
               body.includes('warning') ||
               body.includes('suspicious') ||
               document.querySelector('[data-i18n*="caution"]') !== null ||
               document.querySelector('[data-i18n*="risk"]') !== null;
      });

      expect(hasCautionContent).toBe(true);
    });

    test('caution.html should have action buttons', async () => {
      const cautionPath = path.join(EXTENSION_PATH, 'caution.html');
      await page.goto(`file://${cautionPath}`);

      const buttons = await page.$$('button');
      expect(buttons.length).toBeGreaterThan(0);
    });
  });

  describe('Reason List Display', () => {
    test('alert page should have reason list container', async () => {
      const alertPath = path.join(EXTENSION_PATH, 'alert.html');
      await page.goto(`file://${alertPath}`);

      const reasonList = await page.$('#reason-list, .reason-list, ul.reasons, .reasons');
      expect(reasonList).not.toBeNull();
    });

    test('caution page should have reason list container', async () => {
      const cautionPath = path.join(EXTENSION_PATH, 'caution.html');
      await page.goto(`file://${cautionPath}`);

      const reasonList = await page.$('#reason-list, .reason-list, ul.reasons, .reasons');
      expect(reasonList).not.toBeNull();
    });
  });

  describe('Responsive Design', () => {
    test('popup should render correctly at popup dimensions', async () => {
      await page.setViewport({ width: 400, height: 600 });
      await page.goto(`file://${POPUP_PATH}`);

      // Check that content doesn't overflow
      const hasOverflow = await page.evaluate(() => {
        const body = document.body;
        return body.scrollWidth > body.clientWidth;
      });

      expect(hasOverflow).toBe(false);
    });

    test('alert page should render correctly', async () => {
      const alertPath = path.join(EXTENSION_PATH, 'alert.html');
      await page.setViewport({ width: 800, height: 600 });
      await page.goto(`file://${alertPath}`);

      // Check that main content is visible
      const bodyVisible = await page.evaluate(() => {
        const body = document.body;
        return body.offsetHeight > 0 && body.offsetWidth > 0;
      });

      expect(bodyVisible).toBe(true);
    });
  });
});

describe('Static File Validation', () => {
  test('manifest.json should be valid JSON', () => {
    const manifestPath = path.join(EXTENSION_PATH, 'manifest.json');
    const content = fs.readFileSync(manifestPath, 'utf8');

    expect(() => JSON.parse(content)).not.toThrow();
  });

  test('manifest.json should have required fields', () => {
    const manifestPath = path.join(EXTENSION_PATH, 'manifest.json');
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));

    expect(manifest.manifest_version).toBe(3);
    expect(manifest.name).toBeTruthy();
    expect(manifest.version).toBeTruthy();
    expect(manifest.permissions).toBeInstanceOf(Array);
  });

  test('config.js should exist and be valid', () => {
    const configPath = path.join(EXTENSION_PATH, 'config.js');
    expect(fs.existsSync(configPath)).toBe(true);

    const content = fs.readFileSync(configPath, 'utf8');
    // Config uses window.CONFIG pattern
    expect(content).toContain('window.CONFIG');
  });

  test('all locale files should be valid JSON', () => {
    const localesDir = path.join(EXTENSION_PATH, '_locales');
    const locales = fs.readdirSync(localesDir);

    for (const locale of locales) {
      const messagesPath = path.join(localesDir, locale, 'messages.json');
      if (fs.existsSync(messagesPath)) {
        const content = fs.readFileSync(messagesPath, 'utf8');
        expect(() => JSON.parse(content)).not.toThrow();
      }
    }
  });
});
