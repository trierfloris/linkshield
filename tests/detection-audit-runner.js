/**
 * LinkShield Detection Audit Runner v2.0
 *
 * Correcte testmethodologie voor alle 10 security layers.
 *
 * VEREISTEN:
 * 1. npm install puppeteer (in tests folder)
 * 2. Start webserver: npx serve test-pages -p 8080
 * 3. Run: node detection-audit-runner.js
 *
 * BELANGRIJK:
 * - NIET headless (sommige tests vereisen echte rendering)
 * - Extensie moet geladen worden als unpacked
 * - Tests draaien op HTTP, niet file://
 */

const puppeteer = require('puppeteer');
const path = require('path');
const fs = require('fs');

// ============================================================================
// CONFIGURATIE
// ============================================================================

const CONFIG = {
  // Pad naar LinkShield extensie (parent directory)
  extensionPath: path.resolve(__dirname, '..'),

  // Test server URL
  testServerUrl: 'http://localhost:8080',

  // Pad naar test pagina's
  testPagesPath: 'detection-audit',

  // Headless mode - false voor QR en clipboard tests, true voor CI/CLI
  // Set via environment: HEADLESS=true node detection-audit-runner.js
  headless: process.env.HEADLESS === 'true' || process.env.CI === 'true',

  // Timeout per test (ms)
  testTimeout: 10000,

  // Wacht tijd na page load voor LinkShield initialization
  initDelay: 1500,

  // Verbose logging
  verbose: true
};

// ============================================================================
// TEST DEFINITIES
// ============================================================================

const LAYER_TESTS = [
  {
    layer: 1,
    name: 'Phishing URLs & Suspicious TLDs',
    file: 'layer1-phishing-urls.html',
    testMethod: 'hoverLinks',
    expectedDetections: ['Risk score', 'suspiciousTLD', 'phishing'],
    description: 'Link analyse triggert bij HOVER, niet page load'
  },
  {
    layer: 2,
    name: 'Unicode Lookalike Domains',
    file: 'layer2-unicode-lookalikes.html',
    testMethod: 'hoverLinks',
    expectedDetections: ['Punycode', 'Homoglyph', 'Cyrillic', 'mixed-script'],
    description: 'Homoglyph detectie bij link analyse'
  },
  {
    layer: 3,
    name: 'Fake Browser Windows (BitB)',
    file: 'layer3-fake-browser-windows.html',
    testMethod: 'waitForScan',
    expectedDetections: ['BitB', 'fake URL bar', 'window controls'],
    description: 'BitB scan na page load + MutationObserver'
  },
  {
    layer: 4,
    name: 'PowerShell/ClickFix',
    file: 'layer4-clickfix-powershell.html',
    testMethod: 'waitForScan',
    expectedDetections: ['ClickFix', 'PowerShell', 'command'],
    description: 'ClickFix scan van page content'
  },
  {
    layer: 5,
    name: 'Invisible Overlay Attacks',
    file: 'layer5-invisible-overlays.html',
    testMethod: 'waitForScan',
    expectedDetections: ['Visual Hijacking', 'pointer-events', 'z-index'],
    description: 'Visual hijacking proactive scan'
  },
  {
    layer: 6,
    name: 'Malicious QR Codes',
    file: 'layer6-malicious-qr-codes.html',
    testMethod: 'scrollToImages',
    expectedDetections: ['QR', 'malicious', 'javascript:'],
    description: 'QR scan vereist element in viewport (IntersectionObserver)'
  },
  {
    layer: 7,
    name: 'Dangerous Link Types',
    file: 'layer7-dangerous-links.html',
    testMethod: 'hoverLinks',
    expectedDetections: ['Dangerous scheme', 'javascript:', 'data:', 'blocked'],
    description: 'Immediate block bij dangerous URI schemes'
  },
  {
    layer: 8,
    name: 'Form Hijacking',
    file: 'layer8-form-hijacking.html',
    testMethod: 'triggerFormHijacking',
    expectedDetections: ['Form hijacking', 'action changed', 'external'],
    description: 'Detectie bij form action WIJZIGING + password focus'
  },
  {
    layer: 9,
    name: 'Clipboard Manipulation',
    file: 'layer9-clipboard-hijacking.html',
    testMethod: 'triggerClipboard',
    expectedDetections: ['Clipboard', 'hijacking', 'copy'],
    description: 'Vereist echte copy actie (Ctrl+C)'
  },
  {
    layer: 10,
    name: 'Shadow DOM Abuse',
    file: 'layer10-shadow-dom-abuse.html',
    testMethod: 'waitForScan',
    expectedDetections: ['Shadow DOM', 'shadowRoot', 'scanned'],
    description: 'Open Shadow DOM scanning (closed is niet mogelijk)'
  }
];

// ============================================================================
// HULPFUNCTIES
// ============================================================================

function log(message, type = 'info') {
  const timestamp = new Date().toISOString().split('T')[1].split('.')[0];
  const prefix = {
    info: '\x1b[36m[INFO]\x1b[0m',
    success: '\x1b[32m[PASS]\x1b[0m',
    fail: '\x1b[31m[FAIL]\x1b[0m',
    warn: '\x1b[33m[WARN]\x1b[0m',
    debug: '\x1b[90m[DEBUG]\x1b[0m'
  };
  console.log(`${timestamp} ${prefix[type] || prefix.info} ${message}`);
}

function sleep(ms) {
  return new Promise(resolve => setTimeout(resolve, ms));
}

// ============================================================================
// TEST METHODES
// ============================================================================

/**
 * Hover over alle links om analyse te triggeren
 */
async function hoverLinks(page, logs) {
  const links = await page.$$('a[href]');
  log(`  Hovering over ${links.length} links...`, 'debug');

  for (const link of links) {
    try {
      await link.hover();
      await sleep(150); // Wacht op tooltip/analyse
    } catch (e) {
      // Element might not be visible
    }
  }

  await sleep(500); // Extra wacht voor async analyse
}

/**
 * Wacht op automatische scan (BitB, ClickFix, Visual Hijacking)
 */
async function waitForScan(page, logs) {
  log(`  Waiting for automatic scan...`, 'debug');
  await sleep(2500); // LinkShield scans hebben delay
}

/**
 * Scroll naar images om IntersectionObserver te triggeren
 */
async function scrollToImages(page, logs) {
  const images = await page.$$('img');
  log(`  Scrolling to ${images.length} images for QR scan...`, 'debug');

  for (const img of images) {
    try {
      await img.scrollIntoViewIfNeeded();
      await sleep(300); // Wacht op IntersectionObserver
    } catch (e) {
      // Ignore
    }
  }

  await sleep(1000); // Extra wacht voor QR processing
}

/**
 * Trigger form hijacking detectie
 */
async function triggerFormHijacking(page, logs) {
  log(`  Triggering form hijacking detection...`, 'debug');

  // Wacht op de setTimeout in de test pagina die action wijzigt
  await sleep(1500);

  // Focus op password velden om JIT detectie te triggeren
  const passwordFields = await page.$$('input[type="password"]');
  for (const field of passwordFields) {
    try {
      await field.focus();
      await sleep(300); // Wacht op JIT check (microtask + 50ms + 200ms)
    } catch (e) {
      // Ignore
    }
  }

  await sleep(500);
}

/**
 * Trigger clipboard manipulatie detectie
 */
async function triggerClipboard(page, logs) {
  log(`  Triggering clipboard detection...`, 'debug');

  // De test pagina probeert automatisch naar clipboard te schrijven
  // Dit zou gedetecteerd moeten worden als "no user gesture"
  await sleep(1000);

  // Selecteer tekst en kopieer (echte user gesture)
  try {
    // Focus op de copy-target element
    const copyTarget = await page.$('#copy-target, .code-box');
    if (copyTarget) {
      await copyTarget.click({ clickCount: 3 }); // Select all text
      await sleep(100);

      // Simuleer Ctrl+C
      await page.keyboard.down('Control');
      await page.keyboard.press('KeyC');
      await page.keyboard.up('Control');
      await sleep(500);
    }
  } catch (e) {
    log(`  Clipboard interaction failed: ${e.message}`, 'warn');
  }
}

// ============================================================================
// HOOFD TEST RUNNER
// ============================================================================

async function runAudit() {
  log('='.repeat(70));
  log('LinkShield Detection Audit Runner v2.0');
  log('='.repeat(70));
  log(`Extension path: ${CONFIG.extensionPath}`);
  log(`Test server: ${CONFIG.testServerUrl}`);
  log('');

  // Check of extensie directory bestaat
  if (!fs.existsSync(path.join(CONFIG.extensionPath, 'manifest.json'))) {
    log(`Extension not found at ${CONFIG.extensionPath}`, 'fail');
    process.exit(1);
  }

  // Launch browser met extensie
  log('Launching Chrome with LinkShield extension...');

  let browser;
  try {
    const launchOptions = {
      headless: CONFIG.headless ? 'new' : false, // 'new' for better headless
      args: [
        `--disable-extensions-except=${CONFIG.extensionPath}`,
        `--load-extension=${CONFIG.extensionPath}`,
        '--no-sandbox',
        '--disable-setuid-sandbox',
        '--disable-dev-shm-usage',
        '--disable-web-security',
        '--allow-file-access-from-files',
        '--disable-gpu'
      ],
      defaultViewport: { width: 1280, height: 800 }
    };

    log(`Headless mode: ${CONFIG.headless ? 'YES (some tests may not work)' : 'NO (full browser)'}`, 'info');
    browser = await puppeteer.launch(launchOptions);
  } catch (e) {
    log(`Failed to launch browser: ${e.message}`, 'fail');
    process.exit(1);
  }

  log('Browser launched successfully', 'success');

  const results = {
    timestamp: new Date().toISOString(),
    totalTests: LAYER_TESTS.length,
    passed: 0,
    failed: 0,
    skipped: 0,
    layers: {}
  };

  // Run tests voor elke layer
  for (const test of LAYER_TESTS) {
    log('');
    log('-'.repeat(70));
    log(`Layer ${test.layer}: ${test.name}`);
    log(`Description: ${test.description}`);
    log('-'.repeat(70));

    const page = await browser.newPage();
    const consoleLogs = [];

    // Capture console logs
    page.on('console', msg => {
      const text = msg.text();
      consoleLogs.push(text);
      if (CONFIG.verbose && text.includes('[LinkShield]')) {
        log(`  Console: ${text.substring(0, 100)}`, 'debug');
      }
    });

    // Capture errors
    page.on('pageerror', err => {
      log(`  Page error: ${err.message}`, 'warn');
    });

    try {
      // Bepaal URL
      let testUrl;
      if (test.file) {
        testUrl = `${CONFIG.testServerUrl}/${CONFIG.testPagesPath}/${test.file}`;
      } else if (test.altFile) {
        testUrl = `${CONFIG.testServerUrl}/${test.altFile}`;
      } else {
        log(`No test file for layer ${test.layer}`, 'warn');
        results.skipped++;
        results.layers[test.layer] = { status: 'SKIPPED', reason: 'No test file' };
        await page.close();
        continue;
      }

      log(`Loading: ${testUrl}`);

      // Navigate naar test pagina
      await page.goto(testUrl, {
        waitUntil: 'domcontentloaded',
        timeout: CONFIG.testTimeout
      });

      // Wacht op LinkShield initialization
      await sleep(CONFIG.initDelay);

      // Voer layer-specifieke test methode uit
      const testMethods = {
        hoverLinks,
        waitForScan,
        scrollToImages,
        triggerFormHijacking,
        triggerClipboard
      };

      const method = testMethods[test.testMethod];
      if (method) {
        await method(page, consoleLogs);
      }

      // Analyseer resultaten
      const detected = test.expectedDetections.some(keyword =>
        consoleLogs.some(log => log.toLowerCase().includes(keyword.toLowerCase()))
      );

      // Check voor visuele indicators (data attributes, warnings)
      const visualDetection = await page.evaluate(() => {
        const warnings = document.querySelectorAll('[data-linkshield-warned="true"], [data-linkshield-level]');
        const warningDialogs = document.querySelectorAll('[id*="linkshield"], [class*="linkshield"]');
        const bodyAttrs = document.body.getAttribute('data-linkshield-form-hijack-detected') ||
                         document.body.getAttribute('data-linkshield-clipboard-detected');
        return {
          warningCount: warnings.length,
          dialogCount: warningDialogs.length,
          bodyDetection: !!bodyAttrs
        };
      });

      const hasVisualDetection = visualDetection.warningCount > 0 ||
                                  visualDetection.dialogCount > 0 ||
                                  visualDetection.bodyDetection;

      // Bepaal test resultaat
      const passed = detected || hasVisualDetection;

      if (passed) {
        log(`Layer ${test.layer}: DETECTED`, 'success');
        results.passed++;
        results.layers[test.layer] = {
          status: 'DETECTED',
          consoleDetection: detected,
          visualDetection: hasVisualDetection,
          details: visualDetection
        };
      } else {
        log(`Layer ${test.layer}: NOT DETECTED`, 'fail');
        results.failed++;
        results.layers[test.layer] = {
          status: 'NOT_DETECTED',
          consoleDetection: detected,
          visualDetection: hasVisualDetection,
          consoleLogs: consoleLogs.filter(l => l.includes('LinkShield')).slice(0, 10)
        };
      }

    } catch (error) {
      log(`Layer ${test.layer}: ERROR - ${error.message}`, 'fail');
      results.failed++;
      results.layers[test.layer] = {
        status: 'ERROR',
        error: error.message
      };
    }

    await page.close();
  }

  // Sluit browser
  await browser.close();

  // ============================================================================
  // RAPPORT
  // ============================================================================

  log('');
  log('='.repeat(70));
  log('AUDIT RESULTATEN');
  log('='.repeat(70));
  log('');

  // Tabel met resultaten
  console.log('| Layer | Feature                          | Status       |');
  console.log('|-------|----------------------------------|--------------|');

  for (const test of LAYER_TESTS) {
    const result = results.layers[test.layer];
    const status = result ? result.status : 'UNKNOWN';
    const statusIcon = status === 'DETECTED' ? '✅' : status === 'SKIPPED' ? '⏭️' : '❌';
    const paddedName = test.name.padEnd(32);
    const paddedStatus = `${statusIcon} ${status}`.padEnd(12);
    console.log(`| ${test.layer.toString().padEnd(5)} | ${paddedName} | ${paddedStatus} |`);
  }

  log('');
  log(`Total: ${results.passed}/${results.totalTests} passed (${Math.round(results.passed/results.totalTests*100)}%)`);
  log(`Passed: ${results.passed}, Failed: ${results.failed}, Skipped: ${results.skipped}`);

  // Sla resultaten op
  const reportPath = path.join(__dirname, 'detection-audit-results.json');
  fs.writeFileSync(reportPath, JSON.stringify(results, null, 2));
  log(`Results saved to: ${reportPath}`);

  // Exit code
  process.exit(results.failed > 0 ? 1 : 0);
}

// ============================================================================
// ENTRY POINT
// ============================================================================

// Check voor webserver
const http = require('http');

log('Checking if test server is running...');

const checkServer = http.get(`${CONFIG.testServerUrl}`, (res) => {
  log(`Test server is running (status: ${res.statusCode})`, 'success');
  runAudit().catch(err => {
    log(`Audit failed: ${err.message}`, 'fail');
    process.exit(1);
  });
});

checkServer.on('error', (err) => {
  log(`Test server not running at ${CONFIG.testServerUrl}`, 'fail');
  log('Start the server with: npx serve test-pages -p 8080', 'warn');
  process.exit(1);
});

checkServer.setTimeout(10000, () => {
  log('Server check timeout', 'fail');
  process.exit(1);
});
