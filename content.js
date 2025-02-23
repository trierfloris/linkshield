/**
 * Logt debug-informatie als DEBUG_MODE aanstaat.
 * @param {string} message - Het bericht om te loggen.
 * @param {...any} optionalParams - Optionele parameters.
 */
function logDebug(message, ...optionalParams) {
  if (globalConfig && globalConfig.DEBUG_MODE) {
    console.info(message, ...optionalParams);
  }
}

/**
 * Haalt een vertaling op voor een gegeven message key.
 * @param {string} messageKey
 * @returns {string}
 */
function getTranslatedMessage(messageKey) {
  return chrome.i18n.getMessage(messageKey);
}

/**
 * Logt een foutmelding.
 * @param {string} message - Het foutbericht.
 * @param {...any} optionalParams - Optionele parameters.
 */
function logError(message, ...optionalParams) {
  console.error(message, ...optionalParams);
}

/**
 * Centrale foutafhandelingsfunctie die een fout logt met context.
 * @param {Error} error - De fout.
 * @param {string} context - Contextuele informatie over waar de fout is opgetreden.
 */
function handleError(error, context) {
  logError(`[${context}] ${error.message}`, error);
}

// Global configuration
let globalConfig = null;

/**
 * Valideert en sanitize de configuratie.
 * @param {object} config
 * @returns {object}
 */
function validateConfig(config) {
  const validated = { ...config };
  if (typeof validated.DEBUG_MODE !== 'boolean') {
    validated.DEBUG_MODE = false;
  }
  if (!Array.isArray(validated.ALLOWED_PROTOCOLS)) {
    validated.ALLOWED_PROTOCOLS = ['https:', 'http:', 'mailto:', 'tel:'];
  }
  if (!(validated.SUSPICIOUS_TLDS instanceof RegExp)) {
    validated.SUSPICIOUS_TLDS = /(?:xyz|test)$/i;
  }
  return validated;
}

/**
 * Laadt de configuratie uit window.CONFIG en valideert deze.
 */
const defaultConfig = {
  DEBUG_MODE: false,
  ALLOWED_PROTOCOLS: ['https:', 'http:', 'mailto:', 'tel:'],
  SUSPICIOUS_TLDS: /(?:xyz|test)$/i,
  RISK_THRESHOLD: 5,
  MAX_SUBDOMAINS: 3,
  SHORTENED_URL_DOMAINS: ['bit.ly', 't.co', 'tinyurl.com'],
  PHISHING_KEYWORDS: new Set(['login', 'password', 'verify']),
  MALWARE_EXTENSIONS: /\.(exe|bat|sh)$/i
};

async function loadConfig() {
  try {
    if (window.CONFIG && typeof window.CONFIG === 'object') {
      globalConfig = validateConfig({ ...defaultConfig, ...window.CONFIG });
      logDebug("Configuration loaded successfully:", globalConfig);
    } else {
      throw new Error("window.CONFIG is not available or invalid.");
    }
  } catch (error) {
    handleError(error, "loadConfig");
    globalConfig = validateConfig(defaultConfig); // Fallback naar standaard
    logDebug("Using default configuration:", globalConfig);
  }
}

(async () => {
  await loadConfig();
})();

// Cache voor JSON-bestanden met expiratie
const jsonCache = {};
const CACHE_EXPIRATION_MS = 3600 * 1000; // 1 uur

async function fetchCachedJson(fileName) {
  const cached = jsonCache[fileName];
  const now = Date.now();
  if (cached && (now - cached.timestamp < CACHE_EXPIRATION_MS)) {
    return cached.data;
  }
  try {
    const url = (typeof chrome !== 'undefined' && chrome.runtime?.getURL)
      ? chrome.runtime.getURL(fileName)
      : fileName;
    const response = await fetch(url);
    if (!response.ok) throw new Error(`Error fetching ${fileName}: ${response.statusText}`);
    const json = await response.json();
    jsonCache[fileName] = { data: json, timestamp: now };
    return json;
  } catch (error) {
    handleError(error, "fetchCachedJson");
    return null;
  }
}

async function fetchJson(url) {
  try {
    const response = await fetch(url);
    if (!response.ok) throw new Error(`Error fetching ${url}: ${response.statusText}`);
    return await response.json();
  } catch (error) {
    handleError(error, "fetchJson");
    return null;
  }
}

let safeDomains = [];
let safeDomainsInitialized = false;

async function initializeSafeDomains() {
  try {
    const domains = await fetchCachedJson('TrustedDomains.json') || [];
    if (!Array.isArray(domains) || domains.some(domain => typeof domain !== 'string')) {
      throw new Error("Invalid format in TrustedDomains.json");
    }
    safeDomains = domains;
    safeDomainsInitialized = true;
    logDebug("Trusted domains loaded successfully:", safeDomains);
  } catch (error) {
    handleError(error, "initializeSafeDomains");
    safeDomains = [];
    safeDomainsInitialized = false;
  }
}

initializeSafeDomains();

let warningDiv = null;

function isChromeStorageSyncAvailable() {
  return typeof chrome !== 'undefined' &&
    typeof chrome.storage !== 'undefined' &&
    typeof chrome.storage.sync !== 'undefined';
}

async function isProtectionEnabled() {
  const settings = await getStoredSettings();
  return settings.backgroundSecurity && settings.integratedProtection;
}

async function getStoredSettings() {
  try {
    const settings = await new Promise((resolve) => {
      chrome.storage.sync.get(['backgroundSecurity', 'integratedProtection'], resolve);
    });
    if (!settings || typeof settings !== 'object') {
      throw new Error("Invalid settings structure.");
    }
    return {
      backgroundSecurity: Boolean(settings.backgroundSecurity),
      integratedProtection: Boolean(settings.integratedProtection)
    };
  } catch (error) {
    handleError(error, "getStoredSettings");
    return { backgroundSecurity: true, integratedProtection: true };
  }
}

let lastCheckedUrl = null;

function checkCurrentUrl() {
  const currentUrl = window.location.href;
  if (currentUrl !== lastCheckedUrl) {
    lastCheckedUrl = currentUrl;
    logDebug("[Content] URL changed to:", currentUrl);
    performSuspiciousChecks(currentUrl).then((result) => {
      logDebug("[Content] Check result:", result);
      console.log("Analysis result:", result);
      chrome.runtime.sendMessage({
        type: "checkResult",
        isSafe: result.isSafe,
        risk: result.risk,
        reasons: result.reasons,
        url: currentUrl
      });
    });
  }
}

function performSingleCheck(condition, riskWeight, reason, severity = "medium") {
  if (condition) {
    return { riskWeight, reason, severity };
  }
  return null;
}

function analyzeHighRisk(reasons) {
  const highRiskCount = Array.from(reasons).filter(reason => reason.includes("(high)")).length;
  if (highRiskCount >= 2) {
    return "Multiple critical high risks detected.";
  }
  return null;
}

function applyChecks(checks, reasons, totalRiskRef) {
  logDebug("Starting applyChecks: Current risk:", totalRiskRef.value);
  checks.forEach(({ condition, weight, reason, severity }) => {
    if (condition) {
      reasons.add(`${reason} (${severity})`);
      totalRiskRef.value += weight;
      logDebug(`✅ Risico toegevoegd: ${reason} (${severity}) | Huidige risicoscore: ${totalRiskRef.value}`);
    }
  });
  logDebug("Finished applyChecks: Final risk:", totalRiskRef.value);
}


async function applyDynamicChecks(dynamicChecks, url, reasons, totalRiskRef) {
  logDebug("Starting applyDynamicChecks: Current risk:", totalRiskRef.value);
  for (const { func, message, risk, severity } of dynamicChecks) {
    try {
      const result = await func(url);
      if (result) {
        reasons.add(`${message} (${severity})`);
        logDebug(`Before adding: Current risk=${totalRiskRef.value}, Adding=${risk}`);
        totalRiskRef.value += risk;
        logDebug(`After adding: Current risk=${totalRiskRef.value}`);
      }
    } catch (error) {
      handleError(error, `applyDynamicChecks (${message})`);
    }
  }
  logDebug("Finished applyDynamicChecks: Current risk:", totalRiskRef.value);
}

function createAnalysisResult(isSafe, reasons, risk) {
  logDebug("Generated analysis result:", { isSafe, reasons, risk });
  return { isSafe, reasons, risk };
}

// Controleer URL bij pagina-load
document.addEventListener('popstate', () => checkCurrentUrl());
window.addEventListener('hashchange', () => checkCurrentUrl());

const domainRegex = /^www\./;
const trailingSlashRegex = /\/$/;

function normalizeDomain(url) {
  try {
    if (!/^https?:\/\//i.test(url)) {
      url = `http://${sanitizeInput(url)}`;
    }
    const parsedUrl = new URL(url);
    let hostname = sanitizeInput(parsedUrl.hostname.toLowerCase());
    hostname = hostname.replace(domainRegex, "").replace(trailingSlashRegex, "");
    if (globalConfig?.SUSPICIOUS_TLDS?.test(hostname)) {
      logDebug(`Suspicious TLD detected: ${hostname}`);
    }
    return hostname;
  } catch (error) {
    handleError(error, "normalizeDomain");
    return null;
  }
}

async function initContentScript() {
  logDebug("Starting initialization of content script...");
await Promise.all([loadConfig(), initializeSafeDomains()]);  
const isEnabled = await isProtectionEnabled();
  if (!isEnabled) {
    logDebug("Protection is disabled. Skipping initialization.");
    return;
  }
  if (isSearchResultPage()) {
    logDebug("Setting up Google search protection...");
    setupGoogleSearchProtection();
  }
  logDebug("Checking links...");
  await checkLinks();
  logDebug("Initialization complete.");
}

let debounceTimer = null;
const checkedLinks = new Set();
const scannedLinks = new Set();

function debounce(func, delay = 250) {
  let timer;
  return (...args) => {
    clearTimeout(timer);
    timer = setTimeout(() => func(...args), delay);
  };
}

function setupGoogleSearchProtection() {
  logDebug("Google Search Protection started...");
  const searchContainer = document.querySelector('#search') || document.body;
  const observer = new MutationObserver(debounce((mutations) => {
    mutations.forEach(mutation => {
      mutation.addedNodes.forEach(node => {
        if (node.nodeType === Node.ELEMENT_NODE) {
          const newLinks = node.querySelectorAll('a');
          newLinks.forEach(link => {
            if (isValidURL(link.href)) classifyAndCheckLink(link);
          });
        }
      });
    });
  }, 150));
  observer.observe(searchContainer, { childList: true, subtree: true });
  debounceCheckGoogleSearchResults();
  injectWarningIconStyles();
}

function debounceCheckGoogleSearchResults() {
  clearTimeout(debounceTimer);
  debounceTimer = setTimeout(checkGoogleSearchResults, 150);
}

function checkGoogleSearchResults() {
  logDebug("Checking search results...");
  const searchResults = document.querySelectorAll('#search a:not(.fl)');
  searchResults.forEach(link => {
    if (!checkedLinks.has(link) && link.href && isValidURL(link.href)) {
      classifyAndCheckLink(link);
      checkedLinks.add(link);
    }
  });
}

async function checkForPhishingAds(link) {
  const url = sanitizeInput(link.href);
  const urlObj = new URL(url);
  const domain = normalizeDomain(url);
  if (!domain) return false;
  const checks = [
    {
      func: () => /^(crypto|coins|wallet|exchange|ico|airdrop)/i.test(domain),
      score: 5,
      message: "Warning: This appears to be a crypto-related phishing ad."
    },
    {
      func: () => /adclick|gclid|utm_source/i.test(sanitizeInput(urlObj.search)),
      score: 2,
      message: "Warning: Suspicious ad URL structure."
    },
    {
      func: () => globalConfig.SUSPICIOUS_TLDS.test(domain),
      score: 3,
      message: "Warning: This domain has a suspicious TLD."
    },
    {
      func: () => isHomoglyphAttack(domain),
      score: 4,
      message: "Warning: Possible homoglyph attack in ad URL."
    },
    {
      func: () => /^(amazon|google|microsoft|paypal)/i.test(domain),
      score: 5,
      message: "Warning: Potential misuse of brand name without official domain."
    }
  ];
  try {
    const results = checks.map(check => {
      const result = check.func();
      return result ? { score: check.score, message: check.message } : null;
    }).filter(result => result !== null);
    const totalRiskScore = results.reduce((sum, result) => sum + result.score, 0);
    const specificReasons = results.map(result => result.message);
    if (specificReasons.length > 0) {
      await warnLink(link, specificReasons); // Gebruik await
      const warningIcon = document.createElement("span");
      warningIcon.className = "phishing-warning-icon";
      warningIcon.textContent = "⚠️";
      warningIcon.style = "position: relative; top: 0; left: 5px; color: #ff0000;";
      link.insertAdjacentElement("afterend", warningIcon);
      link.style.border = "2px solid #ff0000";
      link.style.color = "#ff0000";
      link.title = `Warning: This ad may be unsafe. \n${specificReasons.join("\n")}`;
    }
  } catch (error) {
    handleError(error, "checkForPhishingAds");
    await warnLink(link, ["An error occurred while checking this link."]); // Gebruik await
  }
}


function classifyAndCheckLink(link) {
  if (link.closest('div[data-text-ad], .ads-visurl')) {
    checkForPhishingAds(link);
  } else {
    analyzeDomainAndUrl(link);
  }
}

async function warnLink(link, reasons, messageKey = null) {
  if (!link || !link.href || !isValidURL(link.href)) {
    logError("Invalid link provided to warnLink:", link);
    return;
  }

  // Get the current domain and the link's domain
  const currentDomain = normalizeDomain(window.location.href);
  const linkDomain = normalizeDomain(link.href);
  const isSameDomain = currentDomain && linkDomain && linkDomain.endsWith(currentDomain);

  // Calculate risk score asynchronously
  const riskResult = await calculateRiskScore(link.href);
  const isHighRisk = riskResult.score >= (globalConfig.RISK_THRESHOLD || 5);

  // Sanitize and prepare reasons for display
  const translatedReasons = Array.from(reasons)
    .map(reason => chrome.i18n.getMessage(reason) || `Translation missing for: ${reason}`)
    .join("\n");
  logDebug(`[warnLink] Marking link as suspicious: ${link.href}, Same domain: ${isSameDomain}, Reasons:`, translatedReasons);

  // Remove existing warnings to avoid duplicates
  const existingIcon = link.nextElementSibling;
  if (existingIcon && existingIcon.classList.contains('phishing-warning-icon')) {
    existingIcon.remove();
  }
  link.style.border = ''; // Reset any existing border
  link.style.color = ''; // Reset color

  // Create or update warning based on domain and risk
  const warningIcon = document.createElement('span');
  warningIcon.className = 'phishing-warning-icon';
  warningIcon.textContent = '⚠️';

  if (isSameDomain) {
    // Subtle warning for same-domain links: just an icon with a tooltip
    warningIcon.style.cssText = `
      font-size: 12px;
      color: #ff9800; /* Softer orange instead of red */
      vertical-align: middle;
      margin-left: 5px;
      cursor: help;
    `;
    warningIcon.title = translatedReasons; // Tooltip with details
  } else if (isHighRisk) {
    // More prominent warning for external or high-risk links
    warningIcon.style.cssText = `
      font-size: 16px;
      color: #ff0000;
      vertical-align: middle;
      margin-left: 5px;
      cursor: help;
    `;
    link.style.border = '1px dashed #ff0000'; // Dashed border instead of solid
    link.style.color = '#ff0000';
  } else {
    // Moderate warning for external low-risk links
    warningIcon.style.cssText = `
      font-size: 14px;
      color: #ff5722; /* Orange-red for moderate risk */
      vertical-align: middle;
      margin-left: 5px;
      cursor: help;
    `;
    link.style.border = '1px dotted #ff5722'; // Dotted border for low risk
  }

  link.title = translatedReasons; // Set tooltip on the link itself
  link.insertAdjacentElement('afterend', warningIcon);

  // Ensure warning styles are injected
  injectWarningIconStyles();
}

// Helper function to ensure warning styles are injected (updated for subtlety)
function injectWarningIconStyles() {
  if (!document.head.querySelector('#phishing-warning-styles')) {
    const style = document.createElement('style');
    style.id = 'phishing-warning-styles';
    style.textContent = `
      .phishing-warning-icon {
        position: relative;
        top: 0;
        left: 5px;
        transition: color 0.3s ease;
      }
      .phishing-warning-icon:hover {
        color: #d32f2f; /* Darker red on hover for emphasis */
      }
    `;
    document.head.appendChild(style);
  }
}
function sanitizeInput(input) {
  const tempDiv = document.createElement('div');
  tempDiv.textContent = input;
  return tempDiv.innerHTML;
}



async function analyzeDomainAndUrl(link) {
  const url = new URL(link.href);
  const hostname = url.hostname;
  const isInternalIp = (hostname) => {
    return (
      /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname) ||
      /^192\.168\.\d{1,3}\.\d{1,3}$/.test(hostname) ||
      /^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname) ||
      /^172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}$/.test(hostname)
    );
  };
  if (isInternalIp(hostname) || hostname.endsWith(".local") || hostname === "localhost") {
    logDebug(`Internal server detected: ${hostname}. Skipping checks.`);
    return;
  }
  if (globalConfig.SUSPICIOUS_TLDS.test(hostname) || !isHttps(link.href)) {
    const result = await performSuspiciousChecks(link.href);
    if (!result.isSafe || result.reasons.length > 0) {
      const primaryReason = result.reasons.length > 0 ? result.reasons[0] : "unknownWarning";
      logDebug(`[analyzeDomainAndUrl] Using messageKey: ${primaryReason}`);
      await warnLink(link, result.reasons, primaryReason); // Gebruik await
    }
  }
}

function ensureProtocol(url) {
  if (url.startsWith('tel:')) {
    return url;
  }
  if (!/^https?:\/\//i.test(url)) {
    return `http://${url}`;
  }
  return url;
}

function getAbsoluteUrl(relativeUrl) {
  try {
    return new URL(relativeUrl, window.location.href).href;
  } catch (error) {
    handleError(error, "getAbsoluteUrl");
    return relativeUrl;
  }
}

async function calculateRiskScore(url) {
  let score = 0;
  let reasons = [];
  try {
    const urlObj = new URL(url);
    const domain = normalizeDomain(url);
    if (!domain) return { score: -1, reasons: ["Invalid URL."] };
    const path = urlObj.pathname.toLowerCase();
    const addRisk = (points, reason, severity = "low") => {
      score += points;
      reasons.push(`${reason} (${severity})`);
    };
    if (urlObj.protocol !== 'https:') {
      addRisk(15, "URL uses HTTP instead of HTTPS", "medium");
    }
    if (isLoginPage() && urlObj.protocol !== 'https:') {
      addRisk(20, "Login page detected without HTTPS", "high");
    }
    const urlParts = sanitizeInput(url.toLowerCase()).split(/[\/?#]/);
    if (urlParts.some(word => globalConfig.PHISHING_KEYWORDS.has(word))) {
      addRisk(10, "URL contains phishing keywords", "high");
    }
    const ext = urlObj.pathname.toLowerCase().match(/\.[0-9a-z]+$/i);
    if (ext && globalConfig.MALWARE_EXTENSIONS.test(ext[0])) {
      addRisk(10, "URL points to a suspicious file type", "high");
    }
    if (/^(?:https?:\/\/)?(\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:\/|$)/.test(url)) {
      addRisk(10, "URL contains an IP address", "medium");
    }
    const shortenedUrlDomains = new Set(globalConfig.SHORTENED_URL_DOMAINS);
    if (shortenedUrlDomains.has(domain)) {
      addRisk(6, "URL shortener detected", "medium");
      try {
        const response = await fetch(url, { method: 'HEAD', redirect: 'follow' });
        const finalUrl = response.url;
        if (finalUrl && finalUrl !== url) {
          addRisk(10, `Shortened URL resolved to: ${finalUrl}`, "medium");
        }
      } catch (error) {
        addRisk(5, "Error resolving shortened URL", "low");
        handleError(error, "calculateRiskScore (shortened URL)");
      }
    }
    if (globalConfig.SUSPICIOUS_TLDS.test(domain)) {
      addRisk(15, "URL uses a suspicious top-level domain", "high");
    }
    const maxLength = globalConfig.MAX_URL_LENGTH || 2000;
    if (url.length > maxLength) {
      addRisk(5, "URL is unusually long", "low");
    }
    if (url.includes("@") && !url.toLowerCase().startsWith("mailto:")) {
      addRisk(4, "Email address in URL without 'mailto:' protocol", "medium");
    }
    if (/%[0-9A-Fa-f]{2}/.test(url)) {
      addRisk(3, "URL contains encoded characters", "low");
    }
    if (domain.split(".").length > 3) {
      addRisk(5, "URL has excessive subdomains", "medium");
    }
    if (/^(javascript|data):/.test(url) || /[a-f0-9]{32,}/.test(url)) {
      addRisk(10, "Possible Base64 or hexadecimal encoding in URL", "high");
    }
    logDebug(`Risk score for ${url}: ${score}. Reasons: ${reasons.join(', ')}`);
    return { score, reasons };
  } catch (error) {
    handleError(error, "calculateRiskScore");
    return { score: -1, reasons: ["Error calculating risk score."] };
  }
}

function isSearchResultPage() {
  const url = new URL(window.location.href);
  return url.hostname.includes("google.") && (url.pathname === "/search" || url.pathname === "/imgres");
}


function isLoginPage() {
  const result = document.querySelector('input[type="password"]') !== null;
  logDebug("Login Page Detected:", result);
  return result;
}

function isHttps(url) {
  try {
    if (globalConfig && Array.isArray(globalConfig.ALLOWED_PROTOCOLS)) {
      for (const protocol of globalConfig.ALLOWED_PROTOCOLS) {
        if (url.startsWith(protocol)) {
          logDebug(`Allowed protocol detected: ${protocol}`);
          return true;
        }
      }
    }
    const parsedUrl = new URL(url, window.location.href);
    const protocol = parsedUrl.protocol;
    if (protocol === 'https:') {
      return true;
    }
    if (protocol === 'http:') {
      logDebug(`Insecure protocol detected (HTTP): ${url}`);
      return false;
    }
    logDebug(`Unsupported protocol detected: ${protocol}`);
    return false;
  } catch (e) {
    handleError(e, "isHttps");
    return false;
  }
}

function isIpAddress(url) {
  return /^(https?:\/\/)?(\d{1,3}\.){3}\d{1,3}(:\d+)?(\/|$)/.test(url);
}

async function hasSuspiciousPattern(url) {
  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname.toLowerCase().normalize('NFC');
    const path = urlObj.pathname.toLowerCase().normalize('NFC');
    const query = urlObj.search.toLowerCase().normalize('NFC');

    // Snelle pre-check: alleen verder als URL verdacht lijkt
    if (hostname.length < 10 && path.length < 5 && query.length < 5) {
      return false; // Korte, eenvoudige URL's overslaan
    }

    const weightedPatterns = [
      { pattern: /\d{15,}/, weight: 3, description: "Long numeric sequences" },
      { pattern: /-{5,}/, weight: 2, description: "Multiple consecutive hyphens" },
      { pattern: /%[0-9A-Fa-f]{2}/, weight: 2, description: "Encoded characters" },
      { pattern: /[^a-zA-Z0-9.-]{3,}/, weight: 3, description: "Unusual characters" }
    ];

    let totalScore = 0;
    const detectedPatterns = [];
    weightedPatterns.forEach(({ pattern, weight, description }) => {
      if (pattern.test(hostname) || pattern.test(path) || pattern.test(query)) {
        totalScore += weight;
        detectedPatterns.push(description);
      }
    });

    if (totalScore >= 5) {
      logDebug(`Suspicious patterns in ${url}:`, detectedPatterns);
      return true;
    }
    return false;
  } catch (error) {
    handleError(error, "hasSuspiciousPattern");
    return false;
  }
}

function countMatches(pattern, ...strings) {
  return strings.reduce((count, str) => count + (str.match(pattern) || []).length, 0);
}

let trustedDownloadDomains = new Set();

async function isDownloadPage() {
  const links = document.querySelectorAll('a');
  let suspiciousLinkCount = 0;
  let contextLinkCount = 0;
  const totalLinkCount = links.length;
  for (const link of links) {
    try {
      const linkUrl = new URL(link.href, window.location.origin);
      const hostname = linkUrl.hostname;
      if (globalConfig.SUSPICIOUS_TLDS.test(hostname) && globalConfig.MALWARE_EXTENSIONS.test(linkUrl.pathname)) {
        suspiciousLinkCount++;
        if (isInDownloadContext(link)) {
          contextLinkCount++;
        }
        if (
          suspiciousLinkCount / totalLinkCount >= globalConfig.SUSPICION_THRESHOLD ||
          contextLinkCount >= 1
        ) {
          return true;
        }
      }
    } catch (error) {
      handleError(error, "isDownloadPage");
    }
  }
  return false;
}

function isInDownloadContext(link) {
  const downloadKeywords = new Set(["download", "install", "setup", "file", "update"]);
  let surroundingText = '';
  if (link.textContent) {
    surroundingText += link.textContent.toLowerCase() + ' ';
  }
  const parent = link.parentElement;
  if (parent) {
    surroundingText += parent.textContent.toLowerCase() + ' ';
  }
  return Array.from(downloadKeywords).some(keyword => surroundingText.includes(keyword));
}

const MAX_URL_LENGTH = 200;
const MAX_QUERY_LENGTH = 1000;
const MAX_PARAMETERS = 15;

function isUrlTooLong(url) {
  try {
    const urlObj = new URL(url);
    const queryParams = new URLSearchParams(urlObj.search);
    const totalLength = url.length;
    const queryLength = queryParams.toString().length;
    const paramCount = queryParams.size;
    logDebug(`Total Length: ${totalLength}, Query Length: ${queryLength}, Parameter Count: ${paramCount}`);
    return totalLength > MAX_URL_LENGTH &&
      queryLength > MAX_QUERY_LENGTH &&
      paramCount > MAX_PARAMETERS;
  } catch (error) {
    handleError(error, "isUrlTooLong");
    return false;
  }
}

function hasSuspiciousKeywords(url) {
  const weightedKeywords = [
    { keyword: "login", weight: 4 },
    { keyword: "secure", weight: 3 },
    { keyword: "verify", weight: 4 },
    { keyword: "password", weight: 4 },
    { keyword: "auth", weight: 3 },
    { keyword: "account", weight: 2 },
    { keyword: "billing", weight: 2 },
    { keyword: "invoice", weight: 2 },
    { keyword: "payment", weight: 3 },
    { keyword: "token", weight: 3 },
    { keyword: "session", weight: 2 },
    { keyword: "activate", weight: 3 },
    { keyword: "reset", weight: 4 },
  ];
  const patterns = [
    /\/(signin|reset-password|confirm|validate|secure-login|update-account|activate)/i,
    /[?&](action|step|verify|auth|reset|token|session)=/i,
    /(password-reset|confirm-email|verify-account|secure-payment|2fa-verification)/i,
  ];
  const legitimatePaths = [
    "/wp-login.php",
    "/admin/login",
    "/user/account",
    "/password-reset/valid",
    "/secure-payment/success"
  ];
  const legitimatePatterns = [
    /reset-password=valid/i,
    /verify-email=completed/i,
    /session-id=[a-z0-9]+/i
  ];
  const urlObj = new URL(url);
  const path = urlObj.pathname.toLowerCase();
  const search = urlObj.search.toLowerCase();
  if (legitimatePaths.includes(path) || legitimatePatterns.some(pattern => pattern.test(search))) {
    logDebug(`Legitimate context detected: ${url}`);
    return false;
  }
  const foundKeywords = weightedKeywords
    .map(({ keyword, weight }) => ({
      keyword,
      weight,
      matched: path.includes(keyword) || search.includes(keyword)
    }))
    .filter(item => item.matched);
  const totalScore = foundKeywords.reduce((sum, { weight }) => sum + weight, 0);
  const matchesPattern = patterns.some(pattern => pattern.test(path) || pattern.test(search));
  const isHighlySuspicious = totalScore >= 4 && matchesPattern;
  const isModeratelySuspicious = totalScore >= 3 && patterns.some(pattern => pattern.test(path) || pattern.test(search));
  logDebug(`Checked URL: ${url}`);
  logDebug(`Keywords found: ${JSON.stringify(foundKeywords)}`);
  logDebug(`Patterns matched: ${matchesPattern}`);
  return isHighlySuspicious || isModeratelySuspicious;
}

function hasSuspiciousUrlPattern(url) {
  const urlObj = new URL(url);
  const path = urlObj.pathname.toLowerCase();
  const search = urlObj.search.toLowerCase();
  const patterns = globalConfig.SUSPICIOUS_URL_PATTERNS || [];
  const matches = patterns.filter(pattern => pattern.test(path) || pattern.test(search));
  return matches.length >= 2;
}

async function hasSuspiciousIframes() {
  let trustedIframeDomains = [];
  try {
    trustedIframeDomains = await fetchCachedJson('trustedIframes.json');
  } catch (error) {
    handleError(error, "hasSuspiciousIframes");
    trustedIframeDomains = [];
  }
  const iframes = document.querySelectorAll("iframe");
  let suspiciousCount = 0;
  for (const iframe of iframes) {
    const src = iframe.getAttribute("src");
    if (!src) continue;
    let riskScore = 0;
    const reasons = [];
    try {
      const iframeURL = new URL(src, window.location.origin);
      const iframeDomain = iframeURL.hostname.toLowerCase();
      if (trustedIframeDomains.includes(iframeDomain)) continue;
      
      if (!iframeURL.protocol.startsWith("https")) {
        riskScore += 2;
        reasons.push(chrome.i18n.getMessage("noHttps"));
      }
      
      if (globalConfig.SUSPICIOUS_TLDS.test(iframeDomain)) {
        riskScore += 3;
        // Als je dynamische data wilt weergeven, kun je deze achter de vertaling plakken
        reasons.push(chrome.i18n.getMessage("suspiciousTLD") + " " + iframeDomain);
      }
      
      if (globalConfig.SUSPICIOUS_IFRAME_KEYWORDS && globalConfig.SUSPICIOUS_IFRAME_KEYWORDS.test(src)) {
        riskScore += 4;
        reasons.push(chrome.i18n.getMessage("suspiciousKeywords"));
      }
      
      const isHiddenOrSmall =
        iframe.offsetParent === null ||
        iframe.style.display === "none" ||
        iframe.style.visibility === "hidden" ||
        (parseInt(iframe.width, 10) < 10 && parseInt(iframe.height, 10) < 10);
      if (isHiddenOrSmall) {
        riskScore += 2;
        // Zorg dat je een vertaalde key "iframeHidden" toevoegt, anders gebruikt de fallback
        reasons.push(chrome.i18n.getMessage("iframeHidden") || "Iframe is hidden or too small.");
      }
      
      if (riskScore >= 7) {
        suspiciousCount++;
        logDebug(`Suspicious iframe detected: ${src}`);
        console.table(reasons);
      }
    } catch (error) {
      handleError(error, "hasSuspiciousIframes");
    }
  }
  return suspiciousCount > 0;
}

async function checkForSuspiciousExternalScripts() {
  let trustedScripts = [];
  let suspiciousScripts = [];
  try {
    trustedScripts = await fetchCachedJson('trustedScripts.json') || [];
  } catch (error) {
    handleError(error, "checkForSuspiciousExternalScripts");
    trustedScripts = []; // Fallback naar lege array
  }
  const suspiciousPatterns = globalConfig.SUSPICIOUS_SCRIPT_PATTERNS || [];
  const scripts = document.querySelectorAll("script[src]");
  for (const script of scripts) {
    const src = script.getAttribute("src");
    if (!src) continue;
    let riskScore = 0;
    const reasons = [];
    try {
      const scriptURL = new URL(src, window.location.origin);
      const scriptDomain = scriptURL.hostname.toLowerCase();
      // Controleer of trustedScripts een array is voordat .includes() wordt gebruikt
      if (Array.isArray(trustedScripts) && trustedScripts.includes(scriptDomain)) {
        continue;
      }
      if (!scriptURL.protocol.startsWith("https")) {
        riskScore += 2;
        reasons.push(chrome.i18n.getMessage("noHttps"));
      }
      if (suspiciousPatterns.some(pattern => pattern.test(src))) {
        riskScore += 4;
        reasons.push(chrome.i18n.getMessage("externalScripts"));
      }
      if (riskScore >= 7) {
        suspiciousScripts.push({
          src,
          riskScore,
          reasons
        });
      }
    } catch (error) {
      handleError(error, "checkForSuspiciousExternalScripts");
    }
  }
  suspiciousScripts.forEach(({ src, riskScore, reasons }) => {
    logDebug(`Suspicious script detected: ${src}, Risk Score: ${riskScore}`);
    console.table(reasons);
  });
  return suspiciousScripts.length > 0;
}

async function analyzeScriptContent(scriptUrl) {
  try {
    const response = await fetch(scriptUrl.href);
    if (!response.ok) {
      logDebug(`Unable to fetch script: ${scriptUrl.href} (Status: ${response.status})`);
      return false;
    }
    const scriptText = await response.text();
    const maliciousPatterns = [
      /eval\(.*\)/i,
      /document\.write\(.*\)/i,
      /atob\(.*\)/i,
      /location\.href\s*=\s*['"`]javascript:/i,
      /createElement\(["'`]script["'`]\)/i
    ];
    const hasMaliciousPatterns = maliciousPatterns.some(pattern => pattern.test(scriptText));
    if (hasMaliciousPatterns) {
      return true;
    }
    const isMinified = scriptText.replace(/\s/g, "").length > scriptText.length * 0.8;
    const hasNoSourceMap = !/\/\/\s*sourceMappingURL=/i.test(scriptText);
    if (isMinified && hasNoSourceMap) {
      return true;
    }
    logDebug(`Script is safe: ${scriptUrl.href}`);
    return false;
  } catch (error) {
    handleError(error, "analyzeScriptContent");
    if (error.message.includes("Failed to fetch")) {
      return false;
    }
    return true;
  }
}

async function checkScriptMinification(scriptUrl) {
  try {
    const response = await fetch(scriptUrl.href);
    const scriptText = await response.text();
    if (scriptText.replace(/\s/g, '').length > scriptText.length * 0.8) {
      if (!/\/\/#\s*sourceMappingURL=/i.test(scriptText)) {
        return true;
      }
    }
    return false;
  } catch (error) {
    handleError(error, "checkScriptMinification");
    return false;
  }
}

async function checkScriptObfuscation(scriptUrl) {
  try {
    const response = await fetch(scriptUrl.href);
    const scriptText = await response.text();
    const obfuscationPatterns = [
      /^\s*function\s*\(\s*\w*\s*,\s*\w*\s*,\s*\w*\s*,\s*\w*\s*,\s*\w*\s*\)/i,
      /\$[^A-Za-z0-9]/,
      /[a-zA-Z]{3,}\.[a-zA-Z]{3,}\(/,
      /[a-zA-Z]{4,}\s*=\s*\[[^]]+\]/,
    ];
    return obfuscationPatterns.some(pattern => pattern.test(scriptText));
  } catch (error) {
    handleError(error, "checkScriptObfuscation");
    return false;
  }
}

function isValidURL(string) {
  if (!string || typeof string !== 'string') {
    return false;
  }
  try {
    const url = new URL(string, window.location.href);
    const protocol = url.protocol;
    if (!globalConfig.ALLOWED_PROTOCOLS.includes(protocol)) {
      return false;
    }
    if ((protocol === 'http:' || protocol === 'https:') && !url.hostname) {
      return false;
    }
    return true;
  } catch (error) {
    return false;
  }
}

function ensureValidURL(string) {
  if (isValidURL(string)) {
    return string;
  }
  return 'https://linkshield.nl';
}

// Standaard homoglyph-mappings als fallback
const DEFAULT_HOMOGLYPHS = {
  'a': ['а', 'ä', 'α', 'ạ', 'å'],
  'b': ['Ь', 'β', 'ḅ'],
  'c': ['с', 'ç', 'ć'],
  'e': ['е', 'ë', 'ε', 'ẹ'],
  'i': ['і', 'ï', 'ι', 'ḯ'],
  'l': ['ӏ', 'ł', 'ḷ'],
  'o': ['о', 'ö', 'ο', 'ọ', 'ø'],
  'p': ['р', 'ρ', 'ṗ'],
  's': ['ѕ', 'ś', 'ṣ'],
  'u': ['υ', 'ü', 'µ', 'ṵ'],
  'v': ['ν', 'ṽ'],
  'w': ['ω', 'ẉ'],
  'x': ['х', 'χ'],
  'y': ['у', 'ÿ', 'γ'],
};

// Initialiseer homoglyph-set en regex éénmalig
const homoglyphConfig = globalConfig.HOMOGLYPHS || DEFAULT_HOMOGLYPHS;
const homoglyphSet = new Set(Object.values(homoglyphConfig).flat());
const homoglyphRegex = new RegExp(
  Object.values(homoglyphConfig)
    .map(variants => `(${variants.join('|')})`)
    .join('|'),
  'g'
);

/**
 * Controleert of een domein homoglyph-aanvallen bevat.
 * @param {string} domain - Het te controleren domein.
 * @returns {boolean} - True als een homoglyph-aanval wordt gedetecteerd, anders false.
 */
function isHomoglyphAttack(domain) {
  if (!domain || typeof domain !== 'string') {
    logError('Invalid domain input:', domain);
    return false;
  }

  try {
    const normalizedDomain = domain.toLowerCase().normalize('NFC');
    if (!homoglyphRegex.test(normalizedDomain)) {
      logDebug(`No homoglyphs detected in ${normalizedDomain}`);
      return false;
    }

    const homoglyphMap = new Map(Object.entries(homoglyphConfig));
    for (let i = 0; i < normalizedDomain.length; i++) {
      const char = normalizedDomain[i];
      if (homoglyphSet.has(char)) {
        let originalChar = null;
        for (const [key, variants] of homoglyphMap) {
          if (variants.includes(char)) {
            originalChar = key;
            break;
          }
        }

        if (originalChar) {
          const windowSize = 3;
          const start = Math.max(0, i - windowSize);
          const end = Math.min(normalizedDomain.length, i + windowSize + 1);
          const window = normalizedDomain.slice(start, end);

          if (!window.includes(originalChar)) {
            logDebug(`Homoglyph attack detected: ${char} (replacing ${originalChar}) in ${normalizedDomain}`);
            return true;
          }
        }
      }
    }

    const homoglyphCount = (normalizedDomain.match(homoglyphRegex) || []).length;
    if (homoglyphCount > 1) {
      logDebug(`Multiple homoglyphs detected in ${normalizedDomain}: ${homoglyphCount}`);
      return true;
    }

    return false;
  } catch (error) {
    handleError(error, 'isHomoglyphAttack');
    return false;
  }
}

function analyzeParts(checkString) {
  const parts = checkString.split(/[./?=#]/);
  for (let part of parts) {
    if (isPartSuspicious(part)) {
      return true;
    }
  }
  return false;
}

function isPartSuspicious(part) {
  const normalChars = part.split('').filter(char => !homoglyphSet.has(char)).join('');
  const homoglyphsUsed = part.split('').filter(char => homoglyphSet.has(char));
  if (homoglyphsUsed.length > normalChars.length) {
    return true;
  }
  if (/(www|login|mail|bank|secure|account)/i.test(part)) {
    for (let char of homoglyphsUsed) {
      for (let [normalChar, homoglyphVariants] of Object.entries(globalConfig.HOMOGLYPHS || {})) {
        if (homoglyphVariants.includes(char) && char !== normalChar) {
          return true;
        }
      }
    }
  }
  return false;
}

function getCheckString(domain, fullUrl) {
  const normalizedDomain = domain.toLowerCase().normalize('NFC');
  return fullUrl ? new URL(domain).hostname.toLowerCase().normalize('NFC') : normalizedDomain;
}

/* Aangepaste versie van content.js zodat deze overeenkomt met oud.js */

/* Aangepaste versie van content.js zodat deze overeenkomt met oud.js */

async function performSuspiciousChecks(url) {
  const isEnabled = await isProtectionEnabled();
  if (!isEnabled) {
    logDebug("Protection is disabled. Skipping checks for URL:", url);
    return { isSafe: true, reasons: [], risk: 0 };
  }
  const reasons = new Set();
  const totalRiskRef = { value: 0 };

  if (!globalConfig) {
  logError("❌ globalConfig is niet geladen! Kan geen checks uitvoeren.");
  return { isSafe: false, reasons: ["Configuratiefout"], risk: 10 };
}

await checkStaticConditions(url, reasons, totalRiskRef);
await checkDynamicConditions(url, reasons, totalRiskRef);

logDebug("🔍 Eindscore voor URL:", url, "| Risicoscore:", totalRiskRef.value);


  const isSafe = totalRiskRef.value < (globalConfig.RISK_THRESHOLD || 5);
  return createAnalysisResult(isSafe, Array.from(reasons), totalRiskRef.value);
}


function checkStaticConditions(url, reasons, totalRiskRef) {
  const urlObj = new URL(url);
  const domain = urlObj.hostname.toLowerCase();
  
  if (safeDomains.some(pattern => new RegExp(pattern).test(domain))) {
    logDebug(`Safe domain detected: ${domain}`);
    reasons.add("safeDomain");
    totalRiskRef.value = 0.1;
    return;
  }
  
  const allowedProtocols = ['ftp:', 'data:', 'javascript:'];
  if (allowedProtocols.includes(urlObj.protocol)) {
    logDebug(`Allowed protocol detected: ${urlObj.protocol}`);
    reasons.add("allowedProtocol");
    totalRiskRef.value = 0.1;
    return;
  }
  
  if (
    urlObj.protocol !== "https:" &&
    urlObj.protocol !== "mailto:" &&
    urlObj.protocol !== "tel:" &&
    !reasons.has("noHttps")
  ) {
    reasons.add("noHttps");
    totalRiskRef.value += 6.0;
  }
  
  const domainChecks = [
    { condition: globalConfig.SUSPICIOUS_TLDS.test(domain), weight: 6, reason: "suspiciousTLD" },
    { condition: /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/.test(domain), weight: 5, reason: "ipAsDomain" },
    { 
      condition: !isIpAddress(url) && domain.split(".").length > globalConfig.MAX_SUBDOMAINS, 
      weight: 5, 
      reason: "tooManySubdomains" 
    }
  ];
  
  domainChecks.forEach(({ condition, weight, reason }) => {
    if (condition && !reasons.has(reason)) {
      reasons.add(reason);
      totalRiskRef.value += weight;
    }
  });
}


async function checkDynamicConditions(url, reasons, totalRiskRef) {
  const dynamicChecks = [
    { func: isIpAddress, messageKey: "ipAsDomain", risk: 5 },
    { func: hasMultipleSubdomains, messageKey: "tooManySubdomains", risk: 5.0 },
    { func: hasSuspiciousKeywords, messageKey: "suspiciousKeywords", risk: 2.0 },
    { func: hasSuspiciousUrlPattern, messageKey: "suspiciousPattern", risk: 3.0 },
    { func: isShortenedUrl, messageKey: "shortenedUrl", risk: 4.0 },
    { func: isDownloadPage, messageKey: "downloadPage", risk: 3.5 },
    { func: isFreeHostingDomain, messageKey: "freeHosting", risk: 5 },
    { func: hasEncodedCharacters, messageKey: "encodedCharacters", risk: 3.0 },
    { func: hasBase64OrHex, messageKey: "base64OrHex", risk: 2.0 },
    { func: isHomoglyphAttack, messageKey: "homoglyphAttack", risk: 2.0 },
    { func: hasMetaRedirect, messageKey: "metaRedirect", risk: 4.0 },
    { func: isCryptoPhishingUrl, messageKey: "cryptoPhishing", risk: 5 },
    { func: checkForSuspiciousExternalScripts, messageKey: "externalScripts", risk: 4.0 },
    { func: hasSuspiciousIframes, messageKey: "suspiciousIframes", risk: 3.5 },
    { func: hasSuspiciousQueryParameters, messageKey: "suspiciousParams", risk: 2.5 },
    { func: hasMixedContent, messageKey: "mixedContent", risk: 2.0 },
    { func: hasUnusualPort, messageKey: "unusualPort", risk: 3.5 },
    { func: hasJavascriptScheme, messageKey: "javascriptScheme", risk: 4.0 },
    { func: usesUrlFragmentTrick, messageKey: "urlFragmentTrick", risk: 2.0 }
  ];
  for (const { func, messageKey, risk } of dynamicChecks) {
    try {
      const result = await func(url);
      if (result && !reasons.has(messageKey)) {
        reasons.add(messageKey);
        totalRiskRef.value += risk;
      }
    } catch (error) {
      handleError(error, `checkDynamicConditions (${messageKey})`);
      reasons.add(`error_${messageKey}`);
    }
  }
}
function addReason(map, reason, severity) {
  if (!map.has(reason)) {
    map.set(reason, severity);
  }
}

function addReasonIfNotExists(reasonsMap, reason, severity) {
  const normalizedReason = normalizeReason(reason, severity);
  if (!reasonsMap.has(normalizedReason)) {
    reasonsMap.set(normalizedReason, severity);
  }
}

function normalizeReason(reason, severity) {
  return `${reason} (${severity})`;
}

function addUniqueReason(reasonsMap, reason, severity) {
  const normalizedReason = normalizeReason(reason, severity);
  if (!reasonsMap.has(normalizedReason)) {
    reasonsMap.set(normalizedReason, severity);
  }
}

async function isLoginPageFromUrl(url) {
  try {
    const loginPatterns = globalConfig.LOGIN_PATTERNS || /(login|signin|authenticate)/i;
    if (loginPatterns.test(url)) {
      logDebug(`Login page detected based on URL pattern: ${url}`);
      return true;
    }
    const response = await fetch(url);
    const html = await response.text();
    const hasPasswordField = /<input[^>]*type=["']?password["']?/i.test(html);
    if (hasPasswordField) {
      logDebug(`Login page detected based on content: ${url}`);
      return true;
    }
    logDebug(`No login page detected: ${url}`);
    return false;
  } catch (error) {
    handleError(error, "isLoginPageFromUrl");
    return false;
  }
}

function mapRiskToSeverity(priorRisk) {
  if (priorRisk >= 0.7) return "high";
  if (priorRisk >= 0.4) return "medium";
  return "low";
}

function constructResult(isSafe, reasons, priorRisk) {
  try {
    if (typeof priorRisk !== "number" || isNaN(priorRisk)) {
      logError("priorRisk is not a valid number:", priorRisk);
      priorRisk = 1.0;
    }
    if (!Array.isArray(reasons)) {
      logError("reasons is not an array:", reasons);
      reasons = ["Unexpected error analyzing risks."];
    }
    logDebug("Construct Result:", { isSafe, reasons, priorRisk });
    return {
      isSafe: Boolean(isSafe),
      reasons: reasons.length > 0 ? reasons : ["No specific risks detected."],
      risk: priorRisk.toFixed(2),
    };
  } catch (error) {
    handleError(error, "constructResult");
    return {
      isSafe: false,
      reasons: ["Unexpected error in result construction."],
      risk: "1.00",
    };
  }
}

function calculateBayesianRisk(prior, evidenceRisk, evidence) {
  if (evidence === 0) return prior;
  const posterior = ((evidenceRisk ** 2) * prior) / (evidence + prior);
  return Math.min(posterior, 1);
}

function generateResult(isSafe, reasons, riskProbability, isExternal) {
  return {
    isSafe,
    reasons,
    riskProbability,
    isExternal,
  };
}

function checkSafeProtocol(url) {
  try {
    const protocol = new URL(url, window.location.href).protocol;
    return globalConfig.ALLOWED_PROTOCOLS.includes(protocol);
  } catch (e) {
    return false;
  }
}

function processSeverity(priorRisk, severity, risk, severityWeights, lowSeverityCount) {
  const weight = severityWeights[severity] || 1.0;
  if (severity === "low") {
    lowSeverityCount++;
    if (lowSeverityCount >= 2) {
      return updateRisk(priorRisk, risk * weight * 1.1, 0.05);
    } else {
      return updateRisk(priorRisk, risk * weight, 0.02);
    }
  }
  if (severity === "medium") {
    return updateRisk(priorRisk, risk * weight * 1.0, 0.05);
  }
  if (severity === "high") {
    return updateRisk(priorRisk, risk * weight * 1.3, 0.1);
  }
  return priorRisk;
}

function updateRisk(priorRisk, addedRisk, adjustmentFactor) {
  const adjustedRisk = priorRisk + addedRisk;
  const finalRisk = adjustedRisk + adjustmentFactor;
  return Math.min(finalRisk, 0.9);
}

function hasSuspiciousQueryParameters(url) {
  const suspiciousParams = /(token|auth|password|key|session|id|login|verify|secure|access)/i;
  try {
    const urlObj = new URL(url);
    for (const [key, value] of urlObj.searchParams) {
      if (suspiciousParams.test(key) || suspiciousParams.test(value)) {
        return true;
      }
    }
  } catch (error) {
    handleError(error, "hasSuspiciousQueryParameters");
  }
  return false;
}

function hasMixedContent(url) {
  try {
    const urlObj = new URL(url);
    return urlObj.protocol === "https:" && urlObj.href.includes("http://");
  } catch (error) {
    handleError(error, "hasMixedContent");
  }
  return false;
}

function hasUnusualPort(url) {
  const commonPorts = [80, 443];
  try {
    const urlObj = new URL(url);
    const port = urlObj.port ? parseInt(urlObj.port, 10) : (urlObj.protocol === "http:" ? 80 : 443);
    return !commonPorts.includes(port);
  } catch (error) {
    handleError(error, "hasUnusualPort");
  }
  return false;
}

function hasJavascriptScheme(url) {
  try {
    const urlObj = new URL(url);
    return urlObj.protocol === "javascript:";
  } catch (error) {
    handleError(error, "hasJavascriptScheme");
  }
  return false;
}

function usesUrlFragmentTrick(url) {
  try {
    const urlObj = new URL(url);
    return urlObj.hash && urlObj.hash.length > 10;
  } catch (error) {
    handleError(error, "usesUrlFragmentTrick");
  }
  return false;
}

function isSafeParameter(param, value) {
  const allowedParams = [
    'utm_source', 'utm_medium', 'utm_campaign', 'utm_term', 'utm_content',
    'fbclid', 'gclid', 'dclid', 'sclid', 'twclid',
    'referrer', 'source', 'campaign', 'session_id', 'visitor_id', 'ga_id',
    'q', 'query', 'search', 'keyword', 'kw',
    'product_id', 'sku', 'variant', 'category', 'price', 'currency',
    'page', 'page_id', 'section', 'lang', 'locale', 'country',
    'debug', 'cache_bypass', 'test',
    'user_id', 'session_token', 'affiliate_id', 'partner'
  ];
  return allowedParams.includes(param);
}

function hasMultipleSubdomains(url) {
  logDebug(`hasMultipleSubdomains called with url: ${url}`);
  try {
    logDebug(`Attempting to extract hostname from url: ${url}`);
    const hostname = new URL(url).hostname;
    logDebug(`Extracted hostname: ${hostname}`);
    
    // Controleer of het een IP-adres is en sla subdomein-check over
    const isIpAddress = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
    logDebug(`Is hostname an IP address? ${isIpAddress}`);
    if (isIpAddress) {
      logDebug(`Hostname is an IP address, returning false`);
      return false;
    }

    logDebug(`Splitting hostname into subdomains`);
    const subdomains = hostname.split('.').slice(0, -2);
    logDebug(`Subdomains: ${subdomains.join(', ')}`);
    const maxAllowedSubdomains = 2;
    const hasTooManySubdomains = subdomains.length > maxAllowedSubdomains;
    logDebug(`Number of subdomains: ${subdomains.length}, max allowed: ${maxAllowedSubdomains}, has too many: ${hasTooManySubdomains}`);
    return hasTooManySubdomains;
  } catch (error) {
    logDebug(`Error in hasMultipleSubdomains: ${error.message}`);
    handleError(error, "hasMultipleSubdomains");
    return false;
  }
}


async function isShortenedUrl(url) {
  try {
    if (!globalConfig || !Array.isArray(globalConfig.SHORTENED_URL_DOMAINS)) {
      logDebug("SHORTENED_URL_DOMAINS not loaded correctly!");
      return false;
    }
    const shortenedDomains = new Set(globalConfig.SHORTENED_URL_DOMAINS.map(d => d.toLowerCase().trim()));
    const domain = new URL(url).hostname.toLowerCase().replace(/^www\./, "");
    if (!shortenedDomains.has(domain)) {
      logDebug(`No shortener detected for: ${url}`);
      return false;
    }
    console.debug(`Detecting shortened URL: ${url}`);
    const finalUrl = await resolveShortenedUrlWithRetry(url);
    if (finalUrl === url) {
      logDebug(`Could not resolve shortened URL, assuming it is still shortened: ${url}`);
      return true;
    }
    logDebug(`Shortened URL resolved: ${url} → ${finalUrl}`);
    return true;
  } catch (error) {
    handleError(error, "isShortenedUrl");
    return false;
  }
}

async function resolveShortenedUrlWithRetry(url, retries = 3, delay = 1000) {
  for (let attempt = 1; attempt <= retries; attempt++) {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000);
    try {
      const response = await fetch(url, {
        method: 'HEAD',
        redirect: 'follow',
        signal: controller.signal,
        headers: { 'Accept': '*/*' }
      });
      clearTimeout(timeout);
      if (response.ok) return response.url;
      throw new Error(`Fetch failed: ${response.status}`);
    } catch (error) {
      clearTimeout(timeout);
      if (error.name === 'AbortError') {
        logError(`Request timed out for ${url} on attempt ${attempt}`);
      } else if (error.message.includes('network')) {
        logError(`Network error for ${url}: ${error.message}`);
      } else if (error.message.includes('CORS')) {
        logError(`CORS issue for ${url}: ${error.message}`);
      } else {
        handleError(error, `resolveShortenedUrlWithRetry (Attempt ${attempt})`);
      }
      if (attempt === retries) return url;
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
  return url;
}

function hasEncodedCharacters(url) {
  try {
    const urlObj = new URL(url);
    const path = urlObj.pathname;
    const query = urlObj.search;
    const encodedCharPattern = /%[0-9A-Fa-f]{2}/g;
    const pathEncodedCount = (path.match(encodedCharPattern) || []).length;
    const queryEncodedCount = (query.match(encodedCharPattern) || []).length;
    const totalEncodedCount = pathEncodedCount + queryEncodedCount;
    const minEncodedCount = 50;
    return totalEncodedCount > minEncodedCount && (path.length > 150 || query.length > 400);
  } catch (error) {
    handleError(error, "hasEncodedCharacters");
    return false;
  }
}

function hasBase64OrHex(url) {
  const base64Pattern = /(?:[A-Za-z0-9+/]{20,}(?:==|=)?)/g;
  const hexPattern = /\b[a-f0-9]{32,}\b/gi;
  const uuidPattern = /\b[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}\b/gi;
  try {
    const urlObj = new URL(url);
    const components = [
      urlObj.hostname,
      urlObj.pathname,
      urlObj.search,
      urlObj.hash,
    ];
    for (const component of components) {
      if (base64Pattern.test(component)) {
        logDebug(`Base64 pattern found in: ${component}`);
        return true;
      }
      if (hexPattern.test(component)) {
        logDebug(`Hexadecimal pattern found in: ${component}`);
        return true;
      }
      if (uuidPattern.test(component)) {
        logDebug(`UUID pattern found in: ${component}`);
        return true;
      }
    }
    return false;
  } catch (error) {
    handleError(error, "hasBase64OrHex");
    return false;
  }
}

function detectLoginPage(url) {
  try {
    const loginPatterns = /(login|signin|wp-login|authenticate|account)/i;
    const urlIndicatesLogin = loginPatterns.test(url);
    const hasPasswordField = !!document.querySelector('input[type="password"]');
    logDebug(`Login detection: URL indication: ${urlIndicatesLogin}, Password field: ${hasPasswordField}`);
    return urlIndicatesLogin || hasPasswordField;
  } catch (error) {
    logError("Error in detectLoginPage:", error);
    return false;
  }
}

function isFreeHostingDomain(url) {
  try {
    const parsedUrl = new URL(url);
    const domain = parsedUrl.hostname.toLowerCase();
    const freeHostingDomains = globalConfig.FREE_HOSTING_DOMAINS || [];
    const suspiciousKeywords = ['free', 'webhost', 'cheap', 'hosting', 'unlimited'];
    if (freeHostingDomains.some(host => domain.endsWith(host))) {
      return true;
    }
    if (suspiciousKeywords.some(keyword => domain.includes(keyword))) {
      return true;
    }
    if (/[-]{2,}/.test(domain) || domain.split('.').some(part => part.length > 25)) {
      return true;
    }
    return false;
  } catch (error) {
    handleError(error, "isFreeHostingDomain");
    return true;
  }
}

function generateLookalikeKeywords(baseKeywords) {
  const replacements = {
    "o": ["0", "°"],
    "i": ["1", "l", "!"],
    "e": ["3", "€"],
    "a": ["@", "4"],
    "s": ["$", "5", "z"],
    "t": ["7", "+"],
    "b": ["8"],
    "l": ["1", "|"],
    "c": ["ç", "k"]
  };
  const lookalikeKeywords = new Set();
  baseKeywords.forEach(keyword => {
    const chars = keyword.split("");
    const variations = new Set([keyword]);
    chars.forEach((char, index) => {
      if (replacements[char]) {
        replacements[char].forEach(replacement => {
          const newVariation = chars.slice(0, index).join("") + replacement + chars.slice(index + 1).join("");
          variations.add(newVariation);
        });
      }
    });
    variations.forEach(variation => {
      lookalikeKeywords.add(variation);
      lookalikeKeywords.add(`secure-${variation}`);
      lookalikeKeywords.add(`${variation}-login`);
      lookalikeKeywords.add(`${variation}-support`);
    });
  });
  return Array.from(lookalikeKeywords);
}

function isCryptoPhishingUrl(url) {
  const officialDomains = (globalConfig && globalConfig.CRYPTO_DOMAINS) || [];
  const cryptoDomains = officialDomains.map(domain => domain.split('.')[0]);
  const suspiciousPatterns = [
    /secure.*login/i,
    /wallet.*connect/i,
    /auth.*crypto/i,
    /locked.*account/i,
    new RegExp(`2fa.*(${cryptoDomains.join('|')})`, 'i'),
    /free.*crypto/i,
    /earn.*bitcoin/i,
    /airdrop.*crypto/i
  ];
  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname.toLowerCase();
    if (officialDomains.some(domain => hostname === domain || hostname.endsWith(`.${domain}`))) {
      logDebug(`Safe: Official domain detected (${hostname})`);
      return false;
    }
    if (officialDomains.some(domain =>
      hostname.includes(domain.replace('.com', '')) && hostname !== domain
    )) {
      logDebug(`Suspicious: Lookalike domain detected (${hostname})`);
      return true;
    }
    if (suspiciousPatterns.some(pattern => pattern.test(`${hostname}${urlObj.pathname}`))) {
      logDebug(`Suspicious: Suspicious patterns detected (${hostname})`);
      return true;
    }
    logDebug(`Safe: No suspicious characteristics found (${hostname})`);
    return false;
  } catch (error) {
    handleError(error, "isCryptoPhishingUrl");
    return false;
  }
}

function hasMetaRedirect() {
  const metaTag = document.querySelector("meta[http-equiv='refresh']");
  return Boolean(metaTag && /^\s*\d+\s*;\s*url=/i.test(metaTag.getAttribute("content")));
}

function isRightClickDisabled() {
  return document.body.oncontextmenu !== null || document.body.hasAttribute('oncontextmenu');
}

if (isChromeStorageSyncAvailable()) {
  logDebug("chrome.storage.sync is available.");
} else {
  logError("chrome.storage.sync is not available. Defaulting to empty settings.");
}

document.addEventListener('DOMContentLoaded', async () => {
  try {
    logDebug("🚀 Initializing content script...");
    await initContentScript();
    
    const currentUrl = window.location.href;
    logDebug(`🔍 Checking the current page: ${currentUrl}`);

    // Directe controle uitvoeren bij laden van de pagina
    performSuspiciousChecks(currentUrl)
      .then(result => {
        const isSafe = result.reasons.length === 0; // Voorkom false positives
        chrome.runtime.sendMessage({
          type: "checkResult",
          url: currentUrl,
          isSafe,
          risk: result.risk,
          reasons: result.reasons
        });
        logDebug(`✅ Check complete: isSafe=${isSafe}, risk=${result.risk}, reasons=${result.reasons.join(", ")}`);
      })
      .catch(error => handleError(error, "Initial URL Check"));

    let attempts = 0;
    const maxAttempts = 10;
    const checkInterval = 500;

    const interval = setInterval(async () => {
      attempts++;

      const isLogin = detectLoginPage(currentUrl);
      if (isLogin) {
        clearInterval(interval);
        chrome.runtime.sendMessage({
          type: "checkResult",
          url: currentUrl,
          isSafe: false,
          risk: 7, // Extra risico voor login-pagina's
          reasons: ["⚠️ Login page detected without HTTPS!"]
        });
        logDebug(`❌ Login page detected: ${currentUrl}`);
      }

      if (attempts >= maxAttempts) {
        clearInterval(interval);
        logDebug("🛑 Maximum login detection attempts reached.");
      }
    }, checkInterval);
  } catch (error) {
    handleError(error, "DOMContentLoaded");
  }
});



/**
 * Aangepaste versie van checkLinks() die overslaat als we op een Google zoekpagina zitten.
 */
function checkLinks() {
  // Als het een Google zoekpagina is, overslaan om te voorkomen dat google.com zelf gecontroleerd wordt.
  if (isSearchResultPage()) {
    logDebug("Google search page detected, skipping global link check.");
    return;
  }

  const currentDomain = new URL(window.location.href).hostname;
  const links = Array.from(document.querySelectorAll('a')).filter(link => {
    if (!link.href || !isValidURL(link.href)) return false;
    const linkDomain = new URL(link.href).hostname;
    return linkDomain.endsWith(currentDomain) && !scannedLinks.has(link.href);
  });
  links.forEach(link => {
    const href = link.href;
    scannedLinks.add(href);
    if (globalConfig.SUSPICIOUS_TLDS.test(new URL(href).hostname)) {
      chrome.runtime.sendMessage({
        type: 'checkResult',
        url: href,
        isSafe: false,
        risk: 0,
        reasons: [chrome.i18n.getMessage("suspiciousTLD")]
      });
      return;
    }
    if (!href.startsWith('https:')) {
      chrome.runtime.sendMessage({
        type: 'checkResult',
        url: href,
        isSafe: false,
        risk: 0,
        reasons: [chrome.i18n.getMessage("noHttps")]
      });
      return;
    }
    performSuspiciousChecks(href).then(({ isSafe, reasons, risk }) => {
      chrome.runtime.sendMessage({
        type: 'checkResult',
        url: href,
        isSafe,
        risk,
        reasons
      });
    });
  });
}

// In de initialisatie wordt checkLinks() alleen aangeroepen als we niet op een Google zoekpagina zitten.
getStoredSettings().then(settings => {
  if (settings.integratedProtection && !isSearchResultPage()) {
    checkLinks();
  }
});

function injectWarningStyles() {
  if (document.head.querySelector("#linkshield-warning-styles")) {
    console.debug("Warning styles already present, skipping.");
    return;
  }
  const style = document.createElement("style");
  style.id = "linkshield-warning-styles";
  style.textContent = `
    .linkshield-warning {
      display: inline-block !important;
      position: relative !important;
      top: 0 !important;
      left: 0 !important;
      background-color: #ff0000 !important;
      color: #ffffff !important;
      padding: 2px 5px !important;
      font-size: 12px !important;
      border-radius: 50% !important;
      margin-left: 5px !important;
      z-index: 1000 !important;
      cursor: pointer !important;
    }
    .suspicious-link {
      background-color: #ffebee !important;
      border-bottom: 2px solid #ff0000 !important;
    }
  `;
  document.head.appendChild(style);
}

function determineRiskSeverity(score) {
  if (score <= 10) {
    return "low";
  } else if (score <= 20) {
    return "medium";
  } else {
    return "high";
  }
}

(async function init() {
  try {
    // Extra initialisatiecode (indien nodig)
  } catch (error) {
    handleError(error, "init");
  }
})();

function unmarkLinksAsSuspicious(url) {
  document.querySelectorAll('a').forEach(link => {
    if (link.href === url) {
      link.classList.remove('suspicious-link');
      const warningIcon = link.nextElementSibling;
      if (warningIcon && warningIcon.classList.contains('linkshield-warning')) {
        warningIcon.remove();
      }
    }
  });
}

function showConfirmationMessage(message) {
  const confirmationMessage = document.createElement('div');
  confirmationMessage.textContent = message;
  confirmationMessage.style.cssText = `
    position: fixed;
    top: 20px;
    left: 50%;
    transform: translateX(-50%);
    background-color: #fff;
    border: 2px solid green;
    padding: 10px;
    z-index: 10001;
    box-shadow: 0 4px 10px rgba(0, 0, 0, 0.2);
    border-radius: 8px;
    max-width: 90%;
    width: 300px;
    text-align: center;
    font-family: 'Arial', sans-serif;
    color: #2c3e50;
    background-color: lightgreen;
  `;
  document.body.appendChild(confirmationMessage);
  setTimeout(() => confirmationMessage.remove(), 3000);
}

const observer = new MutationObserver(debounce((mutations) => {
  mutations.forEach(mutation => {
    mutation.addedNodes.forEach(node => {
      if (node.nodeType !== Node.ELEMENT_NODE) return;
      if (node.tagName === "A" && isValidURL(node.href)) {
        classifyAndCheckLink(node);
      } else {
        node.querySelectorAll('a').forEach(link => {
          if (isValidURL(link.href)) classifyAndCheckLink(link);
        });
      }
    });
  });
}, 250));
observer.observe(document.body, { childList: true, subtree: true });

document.addEventListener('mouseover', debounce((event) => {
  if (event.target.tagName === 'A') {
    unifiedCheckLinkSafety(event.target, 'mouseover', event);
  }
}, 250));

document.addEventListener('click', debounce((event) => {
  if (event.target.tagName === 'A') {
    unifiedCheckLinkSafety(event.target, 'click', event);
  }
}, 250));

const processedLinks = new Set();

async function unifiedCheckLinkSafety(link, eventType, event) {
  if (!link || !isValidURL(link.href)) return;
  const href = link.href;
  if (processedLinks.has(href)) return;
  processedLinks.add(href);
  setTimeout(() => processedLinks.delete(href), 2000);
  try {
    const { isSafe, reasons, risk } = await performSuspiciousChecks(href);
    chrome.runtime.sendMessage({
      type: 'checkResult',
      url: href,
      isSafe,
      risk,
      reasons
    });
    logDebug(`Checked link ${href} on ${eventType}: isSafe: ${isSafe}, risk: ${risk}, reasons:`, reasons);
    if (eventType === 'click') {
      const linkDomain = new URL(href).hostname;
      const currentDomain = new URL(window.location.href).hostname;
      if (!linkDomain.endsWith(currentDomain)) {
        if (!isSafe) {
          event.preventDefault();
        } else {
          event.preventDefault();
          window.location.href = href;
        }
      }
    }
  } catch (error) {
    handleError(error, "unifiedCheckLinkSafety");
  }
}

chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'testURL') {
    performSuspiciousChecks(message.url)
      .then((result) => {
        sendResponse({ isSafe: result.isSafe, reasons: result.reasons, risk: result.risk });
      })
      .catch((error) => {
        handleError(error, "chrome.runtime.onMessage");
        sendResponse({ isSafe: false, reasons: ["An error occurred."], risk: 0 });
      });
    return true;
  }
});