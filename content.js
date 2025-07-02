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

function isHiddenInput(el) {
  return el.tagName === 'INPUT' && el.type === 'hidden';
}

function isVisible(el) {
  const style = getComputedStyle(el);
  return (
    style.display !== 'none' &&
    style.visibility !== 'hidden' &&
    el.offsetParent !== null &&
    el.getAttribute('aria-hidden') !== 'true'
  );
}



/**
 * Zorgt ervoor dat de globale configuratie (`globalConfig`) beschikbaar en geldig is.
 * 
 * Deze functie wordt gebruikt als safeguard in functies die afhankelijk zijn van 
 * globale configuratie-instellingen zoals risico-drempels, toegestane protocollen, 
 * verdachte extensies, enz. 
 * 
 * Werking:
 * - Controleert of `globalConfig` beschikbaar is en gevuld.
 * - Zo niet, roept `loadConfig()` aan om de configuratie opnieuw te laden (asynchroon).
 * - Indien `globalConfig` daarna nog steeds niet beschikbaar is (bijv. door fetch-fout),
 *   wordt een fallbackconfiguratie gebruikt via `validateConfig(defaultConfig)`.
 * 
 * Belangrijk:
 * Deze functie voorkomt runtime-fouten bij vroege of onverwachte aanroepen van 
 * analysefuncties die `globalConfig` nodig hebben. Te gebruiken bovenin:
 *  - `warnLink()`
 *  - `performSuspiciousChecks()`
 *  - `analyzeDomainAndUrl()`
 *  - `checkCurrentUrl()`
 */
async function ensureConfigReady() {
  // Controleer of de globale configuratie beschikbaar en niet leeg is
  if (!globalConfig || Object.keys(globalConfig).length === 0) {
    logDebug("[Config] Config niet beschikbaar, opnieuw laden...");
    await loadConfig();

    // Als na het laden globalConfig nog steeds leeg is: fallback naar standaard
    if (!globalConfig || Object.keys(globalConfig).length === 0) {
      logError("[Config] Config nog steeds niet beschikbaar. Gebruik default fallback.");
      globalConfig = validateConfig(defaultConfig);
    }
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
let globalHomoglyphReverseMap = {};


// Shared constants for throttling and caching
const CHECK_INTERVAL_MS = 5000; // 5 seconds between checks
const CACHE_DURATION_MS = 3600 * 1000; // 1 hour cache expiration

const MAX_CACHE_SIZE = 1000;

const warnedDomainsInline = new Set()

if (!window.linkSafetyCache) {
  window.linkSafetyCache = new Map();
}
if (!window.linkRiskCache) {
  window.linkRiskCache = new Map();
}


// Throttle tracking variables (global scope for persistence)
let lastIframeCheck = 0;
let lastScriptCheck = 0;



/**
 * Hoofd-functie die alle subsector-helpers aanroept.
 * @param {object} config
 * @returns {object}
 */
function validateConfig(config) {
  const validated = { ...config };

  // 1. General settings
  validateGeneralSettings(validated);

  // 2. String-arrayvelden
  validateStringArrayField(validated, 'ALLOWED_PROTOCOLS', ['https:', 'http:', 'mailto:', 'tel:', 'ftp:']);
  validateRegexArrayField(validated, 'ALLOWED_PATHS', [
    /^\/home/i, /^\/products/i, /^\/about/i,
    /^\/contact/i, /^\/blog/i
  ]);
  validateRegexArrayField(validated, 'ALLOWED_QUERY_PARAMS', [
    /^utm_/i, /^ref$/i, /^source$/i,
    /^lang$/i, /^session$/i
  ]);

  validateStringArrayField(validated, 'CRYPTO_DOMAINS', [
    'binance.com', 'kraken.com', 'metamask.io', 'wallet-connect.org', 'coinbase.com',
    'bybit.com', 'okx.com', 'kucoin.com', 'hashkey.com', 'binance.us', 'raydium.io'
  ]);
  validateStringArrayField(validated, 'FREE_HOSTING_DOMAINS', [
    'sites.net', 'angelfire.com', 'geocities.ws', '000a.biz', '000webhostapp.com',
    'weebly.com', 'wixsite.com', 'freehosting.com', 'glitch.me', 'firebaseapp.com',
    'herokuapp.com', 'freehostia.com', 'netlify.app', 'webs.com', 'yolasite.com',
    'github.io', 'bravenet.com', 'zyro.com', 'altervista.org', 'tripod.com',
    'jimdo.com', 'ucoz.com', 'blogspot.com', 'square.site', 'pages.dev',
    'r2.dev', 'mybluehost.me', '000space.com', 'awardspace.com', 'byethost.com',
    'biz.nf', 'hyperphp.com', 'infinityfree.net', '50webs.com', 'tripod.lycos.com',
    'site123.me', 'webflow.io', 'strikingly.com', 'x10hosting.com',
    'freehostingnoads.net', '000freewebhost.com', 'mystrikingly.com',
    'sites.google.com', 'appspot.com', 'vercel.app', 'weeblysite.com',
    's3.amazonaws.com', 'bubbleapps.io', 'typedream.app', 'codeanyapp.com',
    'carrd.co', 'surge.sh', 'replit.dev', 'fly.dev', 'render.com', 'onrender.com'
  ]);
  validateStringArrayField(validated, 'TRUSTED_IFRAME_DOMAINS', ['youtube.com', 'vimeo.com', 'google.com']);
  validateStringArrayField(validated, 'legitimateDomains', [
    'microsoft.com', 'apple.com', 'google.com', 'linkedin.com', 'alibaba.com',
    'whatsapp.com', 'amazon.com', 'x.com', 'facebook.com', 'adobe.com'
  ]);

  // 3. Risicogewichten
  validateRiskWeights(validated);

  // 4. Compound TLD's
  validateStringArrayField(validated, 'COMPOUND_TLDS', [
    'co.uk', 'org.uk', 'gov.uk', 'ac.uk',
    'com.au', 'org.au',
    'co.nz'
  ]);

  // 5. Velden met RegExp of Set
  validateSetField(validated, 'DOWNLOAD_KEYWORDS', [
    'download','install','setup','file','update','patch','plugin','installer','software','driver',
    'execute','run','launch','tool','patcher','application','program','app','fix','crack',
    'keygen','serial','activation','license','trial','demo','zip','archive','compressed',
    'installer_package','upgrade','update_tool','free','fixer','repair','optimizer','restore',
    'reset','unlock','backup','configuration','config','module','library','framework','macro',
    'enable','torrent','seed','payload','exploit','dropper','loader','package','binary',
    'release','beta','mod','hack'
  ]);
  validateRegexOrSetPatternFields(validated);

  // 6. Suspicious-patternvelden
  validateSuspiciousPatterns(validated);

  return validated;
}

/* --- Helper 1: Algemene instellingen --- */
function validateGeneralSettings(cfg) {
  // DEBUG_MODE moet boolean zijn
  if (typeof cfg.DEBUG_MODE !== 'boolean') {
    cfg.DEBUG_MODE = false;
  }

  // MAX_SUBDOMAINS moet positief zijn
  if (typeof cfg.MAX_SUBDOMAINS !== 'number' || cfg.MAX_SUBDOMAINS < 0) {
    cfg.MAX_SUBDOMAINS = 3;
  }

  // CACHE_DURATION_MS moet > 0 zijn
  if (typeof cfg.CACHE_DURATION_MS !== 'number' || cfg.CACHE_DURATION_MS <= 0) {
    cfg.CACHE_DURATION_MS = 24 * 60 * 60 * 1000;
  }

  // SUSPICION_THRESHOLD tussen 0 en 1
  if (typeof cfg.SUSPICION_THRESHOLD !== 'number' || cfg.SUSPICION_THRESHOLD < 0 || cfg.SUSPICION_THRESHOLD > 1) {
    cfg.SUSPICION_THRESHOLD = 0.1;
  }

  // ==== Validatie voor de nieuwe risicodrempels ====
  if (typeof cfg.LOW_THRESHOLD !== 'number' || cfg.LOW_THRESHOLD < 0) {
    cfg.LOW_THRESHOLD = 3;
  }
  if (typeof cfg.MEDIUM_THRESHOLD !== 'number' || cfg.MEDIUM_THRESHOLD < cfg.LOW_THRESHOLD) {
    cfg.MEDIUM_THRESHOLD = cfg.LOW_THRESHOLD + 1;
  }
  if (typeof cfg.HIGH_THRESHOLD !== 'number' || cfg.HIGH_THRESHOLD < cfg.MEDIUM_THRESHOLD) {
    cfg.HIGH_THRESHOLD = cfg.MEDIUM_THRESHOLD + 1;
  }

  // Domain-age checks
  if (typeof cfg.DOMAIN_AGE_MIN_RISK !== 'number' || cfg.DOMAIN_AGE_MIN_RISK < 0) {
    cfg.DOMAIN_AGE_MIN_RISK = 5;
  }
  if (typeof cfg.YOUNG_DOMAIN_THRESHOLD_DAYS !== 'number' || cfg.YOUNG_DOMAIN_THRESHOLD_DAYS < 0) {
    cfg.YOUNG_DOMAIN_THRESHOLD_DAYS = 7;
  }
  if (typeof cfg.YOUNG_DOMAIN_RISK !== 'number' || cfg.YOUNG_DOMAIN_RISK < 0) {
    cfg.YOUNG_DOMAIN_RISK = 5;
  }

  // Nieuwe instelling: risico-gewicht voor “geen HTTPS”
  if (typeof cfg.PROTOCOL_RISK !== 'number' || cfg.PROTOCOL_RISK < 0) {
    // defaultConfig.PROTOCOL_RISK staat in je defaultConfig op bijv. 4
    cfg.PROTOCOL_RISK = defaultConfig.PROTOCOL_RISK;
  }
}


/* --- Helper 2: Array van strings --- */
function validateStringArrayField(cfg, field, defaultArray) {
  const val = cfg[field];
  if (!Array.isArray(val) || val.some(item => typeof item !== 'string')) {
    cfg[field] = defaultArray.slice();
  } else {
    cfg[field] = val
      .map(s => s.trim())
      .filter(s => s.length > 0);
  }
}

/* --- Helper 3: Array van RegExp --- */
function validateRegexArrayField(cfg, field, defaultRegexArray) {
  const val = cfg[field];
  if (!Array.isArray(val) || val.some(item => !(item instanceof RegExp))) {
    cfg[field] = defaultRegexArray.slice();
  }
}

/* --- Helper 4: Risicogewichten --- */
function validateRiskWeights(cfg) {
  const val = cfg.domainRiskWeights;
  const defaultWeights = {
    'microsoft.com': 10,
    'apple.com': 4,
    'google.com': 4,
    'linkedin.com': 3,
    'alibaba.com': 1,
    'whatsapp.com': 1,
    'amazon.com': 1,
    'x.com': 1,
    'facebook.com': 1,
    'adobe.com': 1
  };

  if (
    typeof val !== 'object' ||
    val === null ||
    Array.isArray(val) ||
    Object.values(val).some(w => typeof w !== 'number' || w < 0)
  ) {
    cfg.domainRiskWeights = { ...defaultWeights };
  }
}

/* --- Helper 5a: Set van strings --- */
function validateSetField(cfg, field, defaultArray) {
  const val = cfg[field];
  if (!(val instanceof Set)) {
    cfg[field] = new Set(defaultArray);
  } else {
    // Sanitiseer: houd alleen niet-lege strings
    cfg[field] = new Set(
      Array.from(val).filter(item => typeof item === 'string' && item.trim().length > 0)
    );
    if (cfg[field].size === 0) {
      cfg[field] = new Set(defaultArray);
    }
  }
}

/* --- Helper 5b: RegExp- en Set-patronen --- */
function validateRegexOrSetPatternFields(cfg) {
  const safeRegex = () => new RegExp('$^');

  // HOMOGLYPHS: object met array<string>
  const h = cfg.HOMOGLYPHS;
  const isValidHomoglyphs =
    typeof h === 'object' &&
    h !== null &&
    !Array.isArray(h) &&
    Object.values(h).every(
      arr => Array.isArray(arr) && arr.every(item => typeof item === 'string')
    );
  if (!isValidHomoglyphs) {
    cfg.HOMOGLYPHS = {
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
      'z': ['ž', 'ƶ', 'ź', 'ż', 'ẑ', 'ẓ', 'ẕ', 'ƹ', 'ɀ']
    };
  }

  // LOGIN_PATTERNS: RegExp
  if (!(cfg.LOGIN_PATTERNS instanceof RegExp)) {
    try {
      cfg.LOGIN_PATTERNS = new RegExp(
        '(login|account|auth|authenticate|signin|wp-login|sign-in|log-in|dashboard|portal|session|user|profile)',
        'i'
      );
    } catch (error) {
      logError(`Ongeldig RegExp-patroon voor LOGIN_PATTERNS: ${error.message}`);
      cfg.LOGIN_PATTERNS = safeRegex();
    }
  }

  // MALWARE_EXTENSIONS: RegExp
  if (!(cfg.MALWARE_EXTENSIONS instanceof RegExp)) {
    try {
      cfg.MALWARE_EXTENSIONS = new RegExp(
        '\\.(exe|zip|bak|tar|gz|msi|dmg|jar|rar|7z|iso|bin|scr|bat|cmd|sh|vbs|lnk|chm|ps2|apk|ps1|py|js|vbscript|dll|docm|xlsm|pptm|doc|xls|ppt|rtf|torrent|wsf|hta|jse|reg|swf|svg|lnk|chm)$',
        'i'
      );
    } catch (error) {
      logError(`Ongeldig RegExp-patroon voor MALWARE_EXTENSIONS: ${error.message}`);
      cfg.MALWARE_EXTENSIONS = safeRegex();
    }
  }

  // PHISHING_KEYWORDS: Set<string>
  const phishingSet = cfg.PHISHING_KEYWORDS;
  if (!(phishingSet instanceof Set)) {
    cfg.PHISHING_KEYWORDS = new Set([
      'login','password','verify','access','account','auth','blocked','bonus',
      'captcha','claim','click','credentials','free','gift','notification','pay',
      'pending','prize','recover','secure','signin','unlock','unusual','update',
      'urgent','validate','win'
    ]);
  }

  // SHORTENED_URL_DOMAINS: Set<string>
  const shortUrls = cfg.SHORTENED_URL_DOMAINS;
  if (!(shortUrls instanceof Set) || shortUrls.size === 0) {
    cfg.SHORTENED_URL_DOMAINS = new Set([
      'bit.ly','is.gd','tinyurl.com','goo.gl','t.co','ow.ly','shorturl.at','rb.gy',
      'adf.ly','bc.vc','cutt.ly','lnk.to','rebrand.ly','shorte.st','s.id','tiny.cc',
      'v.gd','zpr.io','clk.sh','soo.gd','u.to','x.co','1url.com','bl.ink',
      'clicky.me','dub.sh','kutt.it','lc.cx','linktr.ee','rb.gy','short.io',
      't.ly','tr.im','urlz.fr','vzturl.com','yourls.org','zi.ma','qr.ae'
    ]);
  }
  cfg.SHORTENED_URL_DOMAINS = new Set(
    Array.from(cfg.SHORTENED_URL_DOMAINS).filter(d => typeof d === 'string' && d.trim().length > 0)
  );
  logDebug(`Validated SHORTENED_URL_DOMAINS: ${Array.from(cfg.SHORTENED_URL_DOMAINS).join(', ')}`);
}

/* --- Helper 6: Suspicious-patternvelden --- */
function validateSuspiciousPatterns(cfg) {
  const safeRegex = () => new RegExp('$^');

  // Verhoogde totaalgewicht-drempel om false positives te verminderen
  cfg.SCRIPT_SUSPICION_THRESHOLD = cfg.SCRIPT_SUSPICION_THRESHOLD || 20;

  // SUSPICIOUS_EMAIL_PATTERNS (ongewijzigd)
  if (
    !Array.isArray(cfg.SUSPICIOUS_EMAIL_PATTERNS) ||
    cfg.SUSPICIOUS_EMAIL_PATTERNS.some(p => !(p instanceof RegExp))
  ) {
    cfg.SUSPICIOUS_EMAIL_PATTERNS = [
      /admin@.*\.xyz/i,
      /support@.*\.top/i,
      /noreply@.*\.info/i,
      /verify@.*\.site/i,
      /account@.*\.online/i
    ];
  }

  // SUSPICIOUS_SCRIPT_PATTERNS met strengere validatie
  if (
    !Array.isArray(cfg.SUSPICIOUS_SCRIPT_PATTERNS) ||
    cfg.SUSPICIOUS_SCRIPT_PATTERNS.some(entry => !(entry.regex instanceof RegExp))
  ) {
    cfg.SUSPICIOUS_SCRIPT_PATTERNS = [
      {
        regex: /\beval\s*\(\s*['"][^'"]{30,}['"]\s*\)/i,
        weight: 12,
        description: 'Dangerous eval of Function met zeer lange strings'
      },
      {
        regex: /\bnew\s+Function\s*\(\s*['"][^'"]{30,}['"](?:\s*,\s*['"][^'"]*['"])*\)/i,
        weight: 12,
        description: 'Dangerous Function constructor met zeer lange strings'
      },
      {
        regex: /\b(?:coinimp|cryptonight|webminer|miner\.js|crypto-jacking|keylogger|trojan|worm|ransomware)\b/i,
        weight: 12,
        description: 'Expliciete malware-/cryptomining-termen'
      },
      {
        regex: /\b(?:malicious|phish(?:ing)?|exploit(?:s)?|redirect(?:ing)?|inject(?:ion)?|clickjacking|backdoor|rootkit)\b/i,
        weight: 11,
        description: 'Malware- of phishing-termen'
      },
      {
        regex: /\b(?:document\.write\s*\(\s*['"][^'"]*javascript:|innerHTML\s*=\s*['"][^'"]*eval)/i,
        weight: 8,
        description: 'Verdachte DOM-manipulatie'
      },
      {
        regex: /\b(?:fetch\([^)]*\.wasm[^)]*eval|import\([^)]*\.wasm[^)]*javascript:)/i,
        weight: 7,
        description: 'WebAssembly-misbruik'
      },
      {
        regex: /\b(?:RTCPeerConnection\s*\(\s*{[^}]*stun:|RTCDataChannel\W*send\s*\(\s*['"][^'"]*eval)/i,
        weight: 6,
        description: 'WebRTC-aanvallen'
      }
    ];
  }

  // SUSPICIOUS_TLDS (ongewijzigd)
  if (!(cfg.SUSPICIOUS_TLDS instanceof RegExp)) {
    try {
      cfg.SUSPICIOUS_TLDS = new RegExp(
        "\\.(academy|accountant|...|zone)$", 'i'
      );
    } catch (err) {
      logError(`Ongeldig RegExp-patroon voor SUSPICIOUS_TLDS: ${err.message}`);
      cfg.SUSPICIOUS_TLDS = safeRegex();
    }
  }

  // SUSPICIOUS_URL_PATTERNS & TYPOSQUATTING_PATTERNS (ongewijzigd)
}



/* --- Helper 7: detectInteractiveControls --- */
function detectInteractiveControls(root = document) {
  const selector = `
    button, input[type="button"], input[type="submit"], 
    input[type="text"], input[type="email"], input[type="password"], input[type="search"],
    select, textarea, a[href],
    [role="button"], [role="link"],
    [onclick], [tabindex]:not([tabindex="-1"])
  `;

  let elements = Array.from(root.querySelectorAll(selector))
    .filter(el => isVisible(el) && !isHiddenInput(el));

  // Shadow DOM ondersteuning
  for (const el of root.querySelectorAll('*')) {
    if (el.shadowRoot) {
      elements = elements.concat(detectInteractiveControls(el.shadowRoot));
    }
  }

  return elements;
}


function startDynamicDetection(callback) {
  const observer = new MutationObserver(mutations => {
    for (const mutation of mutations) {
      mutation.addedNodes.forEach(node => {
        if (node.nodeType === Node.ELEMENT_NODE) {
          const controls = detectInteractiveControls(node);
          if (controls.length > 0) {
            callback(controls);
          }
        }
      });
    }
  });

  observer.observe(document.body, { childList: true, subtree: true });
}



/**
 * Laadt de configuratie uit window.CONFIG en valideert deze.
 */

const defaultConfig = {
  // **Algemene instellingen**
  CACHE_DURATION_MS: 24 * 60 * 60 * 1000, // 24 uur
  DEBUG_MODE: false,
  MAX_SUBDOMAINS: 3,
  RISK_THRESHOLD: 5,
  SUSPICION_THRESHOLD: 0.1,

  // ==== Risicodrempels voor gefaseerde analyse en UI-feedback ====
  LOW_THRESHOLD: 4,             // risico < 4 → safe (was 2)
  MEDIUM_THRESHOLD: 8,          // 4 ≤ risico < 8 → caution (was 5)
  HIGH_THRESHOLD: 15,           // risico ≥ 15 → alert (was 10)

  YOUNG_DOMAIN_THRESHOLD_DAYS: 14,  // Domeinen jonger dan 2 weken (blijft 14)
  DOMAIN_AGE_MIN_RISK: 5,           // Domeinleeftijd‐check vanaf 5 punten (was 3)
  YOUNG_DOMAIN_RISK: 5,             // Risico‐gewicht voor jonge domeinen (was 7)
  PROTOCOL_RISK: 4,

  // **Lijsten van toegestane waarden**
  ALLOWED_PROTOCOLS: ['https:', 'http:', 'mailto:', 'tel:', 'ftp:'],
  ALLOWED_PATHS: [
    /^\/home/i,
    /^\/products/i,
    /^\/about/i,
    /^\/contact/i,
    /^\/blog/i
  ],
  ALLOWED_QUERY_PARAMS: [
    /^utm_/i,
    /^ref$/i,
    /^source$/i,
    /^lang$/i,
    /^session$/i
  ],

  // **Vertrouwde domeinen**
  CRYPTO_DOMAINS: [
    'binance.com',
    'kraken.com',
    'metamask.io',
    'wallet-connect.org',
    'coinbase.com',
    'bybit.com',
    'okx.com',
    'kucoin.com',
    'hashkey.com',
    'binance.us',
    'raydium.io'
  ],
  FREE_HOSTING_DOMAINS: [
    'sites.net', 'angelfire.com', 'geocities.ws', '000a.biz', '000webhostapp.com', 'weebly.com', 'wixsite.com',
    'freehosting.com', 'glitch.me', 'firebaseapp.com', 'herokuapp.com', 'freehostia.com', 'netlify.app', 'webs.com',
    'yolasite.com', 'github.io', 'bravenet.com', 'zyro.com', 'altervista.org', 'tripod.com', 'jimdo.com', 'ucoz.com',
    'blogspot.com', 'square.site', 'pages.dev', 'r2.dev', 'mybluehost.me', '000space.com', 'awardspace.com',
    'byethost.com', 'biz.nf', 'hyperphp.com', 'infinityfree.net', '50webs.com', 'tripod.lycos.com', 'site123.me',
    'webflow.io', 'strikingly.com', 'x10hosting.com', 'freehostingnoads.net', '000freewebhost.com', 'mystrikingly.com',
    'sites.google.com', 'appspot.com', 'vercel.app', 'weeblysite.com', 's3.amazonaws.com', 'bubbleapps.io',
    'typedream.app', 'codeanyapp.com', 'carrd.co', 'surge.sh', 'replit.dev', 'fly.dev', 'render.com', 'onrender.com'
  ],
  TRUSTED_IFRAME_DOMAINS: ['youtube.com', 'vimeo.com', 'google.com'],
  legitimateDomains: [
    'microsoft.com', 'apple.com', 'google.com', 'linkedin.com', 'alibaba.com',
    'whatsapp.com', 'amazon.com', 'x.com', 'facebook.com', 'adobe.com'
  ],

  // **Risicogewichten**
  domainRiskWeights: {
    'microsoft.com': 10, 'apple.com': 4, 'google.com': 4, 'linkedin.com': 3, 'alibaba.com': 1,
    'whatsapp.com': 1, 'amazon.com': 1, 'x.com': 1, 'facebook.com': 1, 'adobe.com': 1
  },

  // **Regex-gebaseerde patronen**
  COMPOUND_TLDS: [
    'co.uk', 'org.uk', 'gov.uk', 'ac.uk',
    'com.au', 'org.au',
    'co.nz'
  ],
  DOWNLOAD_KEYWORDS: new Set([
    'download', 'install', 'setup', 'file', 'update', 'patch', 'plugin', 'installer', 'software', 'driver',
    'execute', 'run', 'launch', 'tool', 'patcher', 'application', 'program', 'app', 'fix', 'crack',
    'keygen', 'serial', 'activation', 'license', 'trial', 'demo', 'zip', 'archive', 'compressed',
    'installer_package', 'upgrade', 'update_tool', 'free', 'fixer', 'repair', 'optimizer', 'restore',
    'reset', 'unlock', 'backup', 'configuration', 'config', 'module', 'library', 'framework', 'macro',
    'enable', 'torrent', 'seed', 'payload', 'exploit', 'dropper', 'loader', 'package', 'binary',
    'release', 'beta', 'mod', 'hack'
  ]),
  HOMOGLYPHS: {
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
    'z': ['ž', 'ƶ', 'ź', 'ż', 'ẑ', 'ẓ', 'ẕ', 'ƹ', 'ɀ']
  },
  LOGIN_PATTERNS: /(login|account|auth|authenticate|signin|wp-login|sign-in|log-in|dashboard|portal|session|user|profile)/i,
  MALWARE_EXTENSIONS: /\.(exe|zip|bak|tar|gz|msi|dmg|jar|rar|7z|iso|bin|scr|bat|cmd|sh|vbs|lnk|chm|ps2|apk|ps1|py|js|vbscript|dll|docm|xlsm|pptm|doc|xls|ppt|rtf|torrent|wsf|hta|jse|reg|swf|svg|lnk|chm)$/i,
  PHISHING_KEYWORDS: new Set([
    'login', 'password', 'verify', 'access', 'account', 'auth', 'blocked', 'bonus', 'captcha', 'claim',
    'click', 'credentials', 'free', 'gift', 'notification', 'pay', 'pending', 'prize', 'recover',
    'secure', 'signin', 'unlock', 'unusual', 'update', 'urgent', 'validate', 'win'
  ]),
  SHORTENED_URL_DOMAINS: new Set(['bit.ly', 'is.gd', 'tinyurl.com', 'goo.gl', 't.co']),
  SUSPICIOUS_EMAIL_PATTERNS: [
    /admin@.*\.xyz/i,
    /support@.*\.top/i,
    /noreply@.*\.info/i,
    /verify@.*\.site/i,
    /account@.*\.online/i
  ],
  SUSPICIOUS_SCRIPT_PATTERNS: [
    { regex: new RegExp('(?:\\beval\\s*\\(\\s*[\'"].*[\'"][^)]*\\)|new\\s+Function\\s*\\(\\s*[\'"].*[\'"][^)]*\\)|base64_decode\\s*\\()', 'i'), weight: 8, description: 'Dangerous eval or Function with strings' },
    { regex: new RegExp('(?:coinimp|cryptonight|webminer|miner\\.js|crypto-jacking|keylogger|trojan|worm|ransomware|xss\\s*\\()', 'i'), weight: 10, description: 'Explicit malware terms' },
    { regex: new RegExp('(?:document\\.write\\s*\\(\\s*[\'"][^\'"]*javascript:|innerHTML\\s*=\\s*[\'"][^\'"]*eval)', 'i'), weight: 7, description: 'Suspicious DOM manipulation' },
    { regex: new RegExp('(?:fetch\\(.+\\.wasm[^)]*eval|import\\(.+\\.wasm[^)]*javascript:)', 'i'), weight: 6, description: 'WebAssembly misuse' },
    { regex: new RegExp('(?:malicious|phish|exploit|redirect|inject|clickjacking|backdoor|rootkit)', 'i'), weight: 9, description: 'Malware keywords' },
    { regex: new RegExp('(?:RTCPeerConnection\\s*\\(\\s*{[^}]*stun:|RTCDataChannel\\s*.\\s*send\\s*\\(\\s*[\'"][^\'"]*eval)', 'i'), weight: 6, description: 'WebRTC attacks' },
  ],
  SUSPICIOUS_TLDS: /\.(academy|accountant|accountants|agency|ap|app|art|asia|auto|bank|bar|beauty|bet|bid|bio|biz|blog|buzz|cam|capital|casa|casino|cfd|charity|cheap|church|city|claims|click|club|company|crispsalt|cyou|data|date|design|dev|digital|directory|download|email|energy|estate|events|exchange|expert|exposed|express|finance|fit|forsale|foundation|fun|games|gle|goog|gq|guide|guru|health|help|home|host|html|icu|ink|institute|investments|ip|jobs|life|limited|link|live|loan|lol|ltd|ly|mall|market|me|media|men|ml|mom|money|monster|mov|network|one|online|page|partners|party|php|pics|play|press|pro|promo|pw|quest|racing|rest|review|rocks|run|sbs|school|science|services|shop|shopping|site|software|solutions|space|store|stream|support|team|tech|tickets|to|today|tools|top|trade|trading|uno|ventures|vip|website|wiki|win|work|world|xin|xyz|zip|zone|co|cc|tv|name|team|live|stream|quest|sbs)$/i,
  SUSPICIOUS_URL_PATTERNS: [
    /\/(payment|invoice|billing|money|bank|secure|login|checkout|subscription|refund|delivery)\//i,
    /(Base64|hexadecimal|b64|encode|urlencode|obfuscate|crypt)/i,
    /\/(signup|register|confirmation|securepayment|order|tracking|verify-account|reset-password|oauth)\//i,
    /(?:\bsecurepay\b|\baccountverify\b|\bresetpassword\b|\bverifyemail\b|\bupdateinfo\b)/i,
    /(qr-code|qrcode|qr\.|generate-qr|scan|qrserver|qrcodes\.)/i,
    /(fake|clone|spoof|impersonate|fraud|scam|phish)/i,
    /[^a-zA-Z0-9]{2,}/,
    /(http[s]?:\/\/[^\/]+){2,}/i,
    /(qr-code|qrcode|qr\.|generate-qr|scan)/i
  ],
  TYPOSQUATTING_PATTERNS: [
    /g00gle/i,
    /paypa1/i,
    /micr0soft/i,
    /[0o][0o]/i,
    /1n/i,
    /vv/i,
    /rn$/i
  ]
};

// Voeg een vlag toe om te controleren of de configuratie al is geladen
let configLoaded = false;
let configPromise = null;
const maxConfigLoadAttempts = 5;

async function loadConfig() {
  if (configLoaded) {
    return configPromise;
  }
  if (configPromise) {
    return configPromise;
  }

  configPromise = (async () => {
    let attempt = 0;

    while (attempt < maxConfigLoadAttempts && !configLoaded) {
      attempt++;
      try {
        // — Stap 1: Probeer window.CONFIG —
        if (window.CONFIG && typeof window.CONFIG === 'object' && !Array.isArray(window.CONFIG)) {
          // Mergen én valideren van user‐config
          const merged = { 
            ...defaultConfig, 
            ...window.CONFIG 
          };
          try {
            globalConfig = validateConfig(merged);
            logDebug(`Configuration geladen uit window.CONFIG (poging ${attempt}):`, globalConfig);
            configLoaded = true;
            return globalConfig;
          } catch (validationError) {
            handleError(validationError, 'loadConfig: window.CONFIG ongeldig, fallback naar default');
            globalConfig = validateConfig(defaultConfig);
            configLoaded = true;
            return globalConfig;
          }
        }

        // — Stap 2: Probeer chrome.storage.sync —
        const stored = await new Promise((resolve, reject) => {
          chrome.storage.sync.get('CONFIG', (items) => {
            if (chrome.runtime.lastError) {
              reject(new Error(chrome.runtime.lastError.message));
            } else {
              resolve(items.CONFIG);
            }
          });
        });

        if (stored && typeof stored === 'object' && !Array.isArray(stored)) {
          const merged = { 
            ...defaultConfig, 
            ...stored 
          };
          try {
            globalConfig = validateConfig(merged);
            logDebug(`Configuration geladen uit chrome.storage (poging ${attempt}):`, globalConfig);
            configLoaded = true;
            return globalConfig;
          } catch (validationError) {
            handleError(validationError, 'loadConfig: chrome.storage.CONFIG ongeldig, fallback naar default');
            globalConfig = validateConfig(defaultConfig);
            configLoaded = true;
            return globalConfig;
          }
        }

        // — Stap 3: Noch window.CONFIG, noch chrome.storage leverde iets op —
        throw new Error('Geen geldige configuratie in window of chrome.storage');
      } catch (error) {
        handleError(error, `loadConfig: kon config niet laden (poging ${attempt})`);
        if (attempt < maxConfigLoadAttempts) {
          // Exponentiële backoff, max 10s
          const delay = Math.min(Math.pow(2, attempt) * 1000, 10000);
          logDebug(`Retry in ${delay / 1000} s… (poging ${attempt})`);
          await new Promise(res => setTimeout(res, delay));
        }
      }
    }

    // Na max pogingen: fallback naar default
    if (!configLoaded) {
      logDebug(`Max pogingen (${maxConfigLoadAttempts}) bereikt — gebruik defaultConfig.`);
      try {
        globalConfig = validateConfig(defaultConfig);
      } catch (fallbackError) {
        handleError(fallbackError, 'validateConfig(defaultConfig) faalde');
        globalConfig = defaultConfig;
      }
      configLoaded = true;
      return globalConfig;
    }
  })();

  return configPromise;
}




(async () => {
  await loadConfig();
})();


// Cache voor JSON-bestanden met expiratie
const jsonCache = {};

// Voeg dit toe direct na de declaratie van jsonCache
const CACHE_TTL_MS = 3600000; // TTL van 1 uur

function cleanupJsonCache() {
  const now = Date.now();
  for (const [key, entry] of Object.entries(jsonCache)) {
    if (now - entry.timestamp > CACHE_TTL_MS) {
      delete jsonCache[key];
      logDebug(`Cache entry '${key}' verwijderd omdat deze ouder is dan ${CACHE_TTL_MS / 1000} seconden.`);
    }
  }
}

// Start de cleanup op een interval (bijv. elke 1 uur)
setInterval(cleanupJsonCache, CACHE_TTL_MS);



async function fetchCachedJson(fileName) {
  const cached = jsonCache[fileName];
  const now = Date.now();
  if (cached && (now - cached.timestamp < CACHE_DURATION_MS)) {
    logDebug(`Cache hit for ${fileName}`);
    return cached.data;
  }

  try {
    if (!chrome.runtime || !chrome.runtime.getURL) {
      throw new Error("chrome.runtime is niet beschikbaar");
    }
    const url = chrome.runtime.getURL(fileName);
    logDebug(`Attempting to fetch ${fileName} from: ${url}`);

    const response = await fetch(url, {
      method: 'GET',
      cache: 'no-store'
    });

    logDebug(`Response status: ${response.status}, statusText: ${response.statusText}`);
    if (!response.ok) {
      throw new Error(`Fetch failed with status: ${response.status} - ${response.statusText}`);
    }

    const json = await response.json();
    if (!json || typeof json !== 'object') {
      throw new Error(`Invalid JSON format in ${fileName}`);
    }

    jsonCache[fileName] = { data: json, timestamp: now };
    logDebug(`Successfully fetched and cached ${fileName}`);
    return json;
  } catch (error) {
    handleError(error, `fetchCachedJson: Kon ${fileName} niet laden`);
    if (fileName === 'trustedIframes.json') {
      logDebug(`Falling back to default trusted iframes`);
      return ['youtube.com', 'vimeo.com', 'google.com'];
    } else if (fileName === 'trustedScripts.json') {
      logDebug(`Falling back to default trusted scripts`);
      return ['googleapis.com', 'cloudflare.com']; // Aanpassen aan jouw behoeften
    }
    return [];
  }
}


async function fetchJson(url) {
  try {
    const response = await fetch(url);
    if (!response.ok) throw new Error(`Error fetching ${url}: ${response.statusText}`);
    return await response.json();
  } catch (error) {
    handleError(error, `fetchJson: Kon ${url} niet laden`);
    return null;
  }
}


// Global cache voor RDAP-resultaten
const rdapCache = new Map();
const RDAP_CACHE_TTL_MS = 24 * 60 * 60 * 1000; // 1 dag TTL

// Functie om verlopen RDAP cache-entries te verwijderen
function cleanRdapCache() {
  const now = Date.now();
  for (const [key, entry] of rdapCache.entries()) {
    if (now - entry.timestamp > RDAP_CACHE_TTL_MS) {
      rdapCache.delete(key);
      logDebug(`RDAP cache entry '${key}' verwijderd omdat deze ouder is dan ${RDAP_CACHE_TTL_MS / (1000 * 60 * 60)} uur.`);
    }
  }
}
// Start periodieke schoonmaak
setInterval(cleanRdapCache, RDAP_CACHE_TTL_MS);


/**
 * Haalt de registratiedatum op via de RDAP.org aggregator (met CORS-headers).
 * Gebruikt een interne cache om dubbele aanroepen te voorkomen.
 * @param {string} domain — b.v. "example.com"
 * @returns {Promise<Date|null>}
 */
async function fetchDomainCreationDate(domain) {
  // Controleer eerst de cache
  const cachedEntry = rdapCache.get(domain);
  if (cachedEntry && (Date.now() - cachedEntry.timestamp < RDAP_CACHE_TTL_MS)) {
    logDebug(`RDAP cache hit voor ${domain}`);
    return cachedEntry.data;
  }

  try {
    const resp = await fetch(`https://rdap.org/domain/${domain}`, {
      redirect: 'follow',
      mode: 'cors',
      headers: { 'Accept': 'application/json' }
    });

    if (resp.status === 404) {
      logError(`RDAP.org kent geen data voor ${domain} (404)`);
      rdapCache.set(domain, { data: null, timestamp: Date.now() }); // Cache null-resultaat ook
      return null;
    }
    if (!resp.ok) {
      logError(`RDAP.org HTTP ${resp.status} voor ${domain}`);
      rdapCache.set(domain, { data: null, timestamp: Date.now() }); // Cache null-resultaat ook
      return null;
    }

    const data = await resp.json();
    const regEvent = Array.isArray(data.events)
      ? data.events.find(e => e.eventAction === 'registration')
      : null;

    const creationDate = regEvent && regEvent.eventDate
      ? new Date(regEvent.eventDate)
      : null;

    rdapCache.set(domain, { data: creationDate, timestamp: Date.now() }); // Cache het resultaat
    return creationDate;

  } catch (e) {
    logError(`RDAP.org fetch fout voor ${domain}:`, e);
    rdapCache.set(domain, { data: null, timestamp: Date.now() }); // Cache null bij fout
    return null;
  }
}




/**
 * Controleert of een domein jonger is dan de configureerbare drempel (standaard 7 dagen).
 * Indien ja, voegt een vertaald bericht toe met de exacte leeftijd in dagen en voegt risicopunten toe.
 *
 * @param {string} url — de volledige URL
 * @param {{ totalRiskRef: { value: number }, reasons: Set<string> }} ctx — context object met risicoreferentie en redenen
 * @returns {Promise<boolean>} — true als jong domein, anders false
 */
async function checkDomainAgeDynamic(url, ctx) {
  // Zorg dat de globale config geladen is
  await ensureConfigReady();

  // Gebruik de robuustere getRegistrableDomain die nu extractMainDomain aanroept
  const domain = getRegistrableDomain(url);
  if (!domain) {
    logDebug(`checkDomainAgeDynamic: Kon geen registreerbaar domein extraheren uit ${url}. Overslaan.`);
    return false;
  }

  // Haal de aanmaakdatum op via de gecachte functie
  const created = await fetchDomainCreationDate(domain);
  if (!created) {
    logDebug(`checkDomainAgeDynamic: Kon geen aanmaakdatum vinden voor domein ${domain}. Overslaan.`);
    return false;
  }

  const ageDays = (Date.now() - created.getTime()) / (1000 * 60 * 60 * 24);

  // Gebruik de correcte drempel uit globalConfig; validateConfig zorgt voor een fallback als deze ontbreekt
  const thresholdDays = globalConfig.YOUNG_DOMAIN_THRESHOLD_DAYS;
  const riskWeight = globalConfig.YOUNG_DOMAIN_RISK;

  if (ageDays < thresholdDays) {
    const ageFormatted = ageDays.toFixed(1);

    // Haal de vertaalde reden op, met de ageFormatted als parameter
    const reasonMsg = chrome.i18n.getMessage(
      'youngDomain',
      [ageFormatted]
    );
    ctx.reasons.add(reasonMsg);

    ctx.totalRiskRef.value += riskWeight;

    logDebug(`⚠️ Jong domein: ${domain}, ${ageFormatted} dagen oud. Risico toegevoegd: ${riskWeight}. Huidig totaalrisico: ${ctx.totalRiskRef.value}`);
    return true;
  }

  logDebug(`checkDomainAgeDynamic: Domein ${domain} is ${ageDays.toFixed(1)} dagen oud, ouder dan drempel (${thresholdDays} dagen). Geen risico toegevoegd.`);
  return false;
}


/**
 * Extraheert het registreerbare domein (bijv. "example.com" of "example.co.uk") uit een volledige URL.
 * Deze functie maakt gebruik van de robuustere `extractMainDomain` functie die rekening houdt met compound TLD's.
 *
 * @param {string} url - De volledige URL waaruit het registreerbare domein moet worden geëxtraheerd.
 * @returns {string|null} - Het registreerbare domein (SLD + TLD) of `null` als de URL ongeldig is.
 */
function getRegistrableDomain(url) {
  try {
    const hostname = new URL(url).hostname.toLowerCase();
    // Gebruik je eigen extractMainDomain functie voor robuuste extractie
    return extractMainDomain(hostname);
  } catch (e) {
    // Log de fout voor debugging, maar retourneer null om crashes te voorkomen
    handleError(e, `getRegistrableDomain: Failed to extract registrable domain from URL: ${url}`);
    return null;
  }
}



// Definieer cache en TTL bovenaan je script (buiten de functie)
const safeDomainsCache = {};
const SAFE_DOMAINS_TTL_MS = 3600 * 1000; // 1 uur TTL

let safeDomains = [];
let safeDomainsInitialized = false;

async function initializeSafeDomains() {
  const now = Date.now();
  const cached = safeDomainsCache['TrustedDomains'];

  // Controleer of er een geldige cache is
  if (cached && (now - cached.timestamp < SAFE_DOMAINS_TTL_MS)) {
    logDebug("Using cached safeDomains");
    safeDomains = cached.data;
    safeDomainsInitialized = true;
    return; // Gebruik de gecachte data en stop
  }

  try {
    const domains = await fetchCachedJson('TrustedDomains.json') || [];
    if (!Array.isArray(domains) || domains.some(domain => typeof domain !== 'string')) {
      throw new Error("Invalid format in TrustedDomains.json");
    }
    safeDomains = domains;
    safeDomainsInitialized = true;
    // Cache de nieuwe data
    safeDomainsCache['TrustedDomains'] = { data: domains, timestamp: now };
    logDebug("Trusted domains loaded successfully and cached:", safeDomains);
  } catch (error) {
    handleError(error, `initializeSafeDomains: Kon TrustedDomains.json niet laden of verwerken`);
    safeDomains = ['example.com', 'google.com']; // Hardcoded fallback
    safeDomainsInitialized = true;
    // Cache ook de fallback
    safeDomainsCache['TrustedDomains'] = { data: safeDomains, timestamp: now };
    logDebug("Fallback domains cached:", safeDomains);
  }
}

// Roep de functie aan bij initialisatie
initializeSafeDomains();

// Periodieke cache-schoonmaak (voeg dit toe aan je script)
setInterval(() => {
  const now = Date.now();
  for (const key in safeDomainsCache) {
    if (now - safeDomainsCache[key].timestamp > SAFE_DOMAINS_TTL_MS) {
      delete safeDomainsCache[key];
      logDebug(`SafeDomains cache entry '${key}' verwijderd wegens verlopen TTL`);
    }
  }
}, SAFE_DOMAINS_TTL_MS);
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
    handleError(error, `getStoredSettings: Kon instellingen niet ophalen uit chrome.storage.sync`);
    return { backgroundSecurity: true, integratedProtection: true };
  }
}



async function getFinalUrl(url) {
  try {
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), 5000);
    const response = await fetch(url, { 
      method: 'HEAD', 
      redirect: 'follow', 
      signal: controller.signal 
    });
    clearTimeout(timeoutId);
    return response.url || url; // Fallback naar originele URL
  } catch (error) {
    logError(`Fout bij ophalen uiteindelijke URL voor ${url}: ${error.message}`);
    return url; // Fallback naar originele URL bij fout
  }
}



function getMetaRefreshUrl() {
  const metaTag = document.querySelector('meta[http-equiv="refresh"]');
  if (metaTag) {
    const content = metaTag.getAttribute('content');
    const match = content.match(/url=(.+)/i);
    if (match) return match[1];
  }
  return null;
}


function performSingleCheck(condition, riskWeight, reason, severity = "medium") {
  if (condition) {
    return { riskWeight, reason, severity };
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
      handleError(error, `applyDynamicChecks: Fout bij uitvoeren van ${message} op URL ${url}`);
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
    if (!/^[a-z]+:\/\//i.test(url)) {
      url = `https://${url}`; // Standaard https toevoegen
    }
    const parsedUrl = new URL(url);
    if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
      return null; // Alleen http/https toestaan
    }
    let hostname = parsedUrl.hostname.toLowerCase();
    hostname = hostname.replace(/^www\./, "").replace(/\/$/, "");
    return hostname;
  } catch (error) {
    logError(`Fout bij normaliseren van URL ${url}: ${error.message}`);
    return null;
  }
}

/**
 * Normaliseert een string door homoglyphen te vervangen door hun Latijnse equivalenten
 * met behulp van een reverse mapping.
 * Bijvoorbeeld: 'а' (Cyrillisch) -> 'a' (Latijn), 'ö' -> 'o'.
 * @param {string} str - De string om te normaliseren.
 * @param {object} reverseMap - De reverse homoglyph-mapping (homoglyph -> Latijnse base).
 * @returns {string} - Het genormaliseerde domein.
 */
function normalizeToLatinBase(str, reverseMap) {
    if (!str) return '';
    let normalized = '';
    // Itereren over karakters, ook Unicode (daarom for...of)
    for (const char of str) {
        normalized += reverseMap[char] || char; // Als er een mapping is, gebruik die; anders, behoud het karakter
    }
    // Specifieke gevallen voor combinaties die niet door char-per-char mapping gaan
    normalized = normalized.replace(/rn/g, 'm').replace(/vv/g, 'w');
    return normalized;
}

async function initContentScript() {
  logDebug("Starting initialization of content script...");
  try {
    // Wacht op configuratie en veilige domeinen
    await Promise.all([loadConfig(), initializeSafeDomains()]);
    if (!globalConfig) {
      logError("globalConfig is niet geladen na loadConfig(). Gebruik standaardconfiguratie.");
      globalConfig = validateConfig(defaultConfig);
    }

    // Controleer of de bescherming is ingeschakeld
    const isEnabled = await isProtectionEnabled();
    if (!isEnabled) {
      logDebug("Protection is disabled. Skipping initialization.");
      return;
    }

    // Controleer of het een Google-zoekresultatenpagina is
    if (isSearchResultPage()) {
      logDebug("Setting up Google search protection...");
      setupGoogleSearchProtection();
    } else {
      logDebug("Checking links...");
      await checkLinks(); // Controleert hoofddomein en externe links
      // Geen extra 'alert'-bericht meer nodig
    }

    logDebug("Initialization complete.");
  } catch (error) {
    logError(`Error during initialization: ${error.message}`);
    throw error; // Optioneel: fout doorsluizen
  }
}

let debounceTimer = null;
const checkedLinks = new Set();
const scannedLinks = new Set();

function debounce(func, delay = 250) {
  let timer;
  return (...args) => {
    clearTimeout(timer);
    return new Promise((resolve) => {
      timer = setTimeout(async () => {
        const result = await func(...args);
        resolve(result);
      }, delay);
    });
  };
}

function setupGoogleSearchProtection() {
  logDebug("Google Search Protection started...");
  const searchContainer = document.querySelector('#search') || document.body;

  // Observer voor nieuwe resultaten
  const observer = new MutationObserver(debounce(() => {
    debounceCheckGoogleSearchResults();
  }, 300));

  observer.observe(searchContainer, { childList: true, subtree: true });

  // Initial run
  debounceCheckGoogleSearchResults();

  // Styles voor waarschuwingsiconen
  injectWarningIconStyles();
}


function debounceCheckGoogleSearchResults() {
  clearTimeout(debounceTimer);
  debounceTimer = setTimeout(checkGoogleSearchResults, 250);
}


/**
 * Controleert een link specifiek op kenmerken van phishing-advertenties.
 * Past visuele waarschuwingen toe via `warnLinkByLevel` indien verdacht.
 * @param {HTMLAnchorElement} link - Het HTML-ankerelement van de advertentie.
 */
async function checkForPhishingAds(link) {
  // Valideer de link href om fouten te voorkomen
  if (!link || !link.href || !isValidURL(link.href)) {
    logDebug(`Skipping checkForPhishingAds: Invalid or missing link href: ${link?.href || 'undefined'}`);
    return;
  }

  const url = link.href; // Gebruik link.href direct, sanitizeInput is niet nodig voor URL constructie.
  let urlObj;
  try {
    urlObj = new URL(url);
  } catch (error) {
    logError(`checkForPhishingAds: Ongeldige URL voor constructie: ${url}`, error);
    // Bij een constructiefout, converteer naar een "caution" of "alert" level
    warnLinkByLevel(link, { level: 'caution', risk: 5, reasons: ['invalidUrlFormat'] });
    return;
  }

  const domain = normalizeDomain(url);
  if (!domain) {
    logDebug(`checkForPhishingAds: Kon domein niet normaliseren voor URL: ${url}`);
    warnLinkByLevel(link, { level: 'caution', risk: 5, reasons: ['invalidDomain'] });
    return;
  }

  // Zorg dat globalConfig geladen is voor toegang tot HOMOGLYPHS en legitimateDomains
  await ensureConfigReady();

  // Definieer homoglyphMap en knownBrands - haal deze uit globalConfig
  const homoglyphMapEntries = globalConfig.HOMOGLYPHS || {};
  const homoglyphMap = {};
  for (const [latin, variants] of Object.entries(homoglyphMapEntries)) {
      if (Array.isArray(variants)) { // Belangrijk om te controleren of variants een array is
          for (const g of variants) {
              homoglyphMap[g] = latin;
          }
      }
  }
  const knownBrands = globalConfig.legitimateDomains || ['microsoft.com', 'apple.com', 'google.com'];

  // Definieer de specifieke checks voor advertenties, met scores
  const checks = [
    { func: () => /^(crypto|coins|wallet|exchange|ico|airdrop)/i.test(domain), score: 5, messageKey: "cryptoPhishingAd" },
    { func: () => /adclick|gclid|utm_source/i.test(urlObj.search), score: 2, messageKey: "suspiciousAdStructure" },
    // Zorg ervoor dat SUSPICIOUS_TLDS een RegExp is voordat je test
    { func: () => (globalConfig.SUSPICIOUS_TLDS instanceof RegExp) && globalConfig.SUSPICIOUS_TLDS.test(domain), score: 3, messageKey: "suspiciousAdTLD" },
    // isHomoglyphAttack voegt al redenen toe aan een Set, dus hier return we alleen true/false
    { func: async () => await isHomoglyphAttack(domain, homoglyphMap, knownBrands, extractTld(domain), new Set()), score: 4, messageKey: "homoglyphAdAttack" },
    { func: () => /^(amazon|google|microsoft|paypal)/i.test(domain) && !knownBrands.includes(domain), score: 5, messageKey: "brandMisuse" } // Controleer op misuse, niet legitiem gebruik
  ];

  try {
    const specificReasons = new Set(); // Gebruik een Set om unieke redenen te verzamelen
    let totalRiskScore = 0;

    for (const check of checks) {
      // Voer de functie uit; als het een Promise is, wacht dan
      const condition = await Promise.resolve(check.func());
      if (condition) {
        specificReasons.add(check.messageKey);
        totalRiskScore += check.score;
        logDebug(`[checkForPhishingAds] Reden toegevoegd: ${check.messageKey}, score: ${check.score}. Huidige risicoscore: ${totalRiskScore}`);
      }
    }

    if (specificReasons.size > 0) {
      // Bepaal het level op basis van de geaccumuleerde score en de globale drempels
      let level;
      if (totalRiskScore >= (globalConfig.HIGH_THRESHOLD || 12)) {
        level = 'alert';
      } else if (totalRiskScore >= (globalConfig.LOW_THRESHOLD || 3)) {
        level = 'caution';
      } else {
        level = 'safe'; // Kan ook 'safe' zijn als de score te laag is voor een waarschuwing
      }

      // Roep de nieuwe, universele waarschuwingsfunctie aan
      warnLinkByLevel(link, { level: level, risk: totalRiskScore, reasons: Array.from(specificReasons) });
      logDebug(`[checkForPhishingAds] Advertentie link ${url} gemarkeerd: Level=${level}, Risk=${totalRiskScore}, Redenen=${Array.from(specificReasons).join(', ')}`);
    } else {
      logDebug(`[checkForPhishingAds] Advertentie link ${url} veilig bevonden. Geen waarschuwing.`);
      warnLinkByLevel(link, { level: 'safe', risk: 0, reasons: [] }); // Zorg dat eventuele oude waarschuwingen worden verwijderd
    }

  } catch (error) {
    handleError(error, `checkForPhishingAds: Fout bij controleren van link ${link.href}`);
    // Bij een fout, converteer naar een "caution" level met een generieke foutreden
    warnLinkByLevel(link, { level: 'caution', risk: 5, reasons: ["fileCheckFailed"] }); // Gebruik "fileCheckFailed" of een meer generieke "analysisError"
  }
}



function classifyAndCheckLink(link) {
  if (!link || !link.href) {
    logDebug(`Skipping classification: Invalid or missing link: ${link || 'undefined'}`);
    return; // Sla volledig ongeldige links over
  }

  // Haal de href op, rekening houdend met SVGAnimatedString
  const href = link.href instanceof SVGAnimatedString ? link.href.baseVal : link.href;

  // Log voor debugging, inclusief type en SVG-status
  logDebug(`Classifying link: ${href || 'undefined'}, Type: ${typeof link.href}, Is SVG: ${link.ownerSVGElement ? 'yes' : 'no'}`);

  // Controleer of href een geldige URL is
  if (!isValidURL(href)) {
    logDebug(`Skipping classification: Invalid URL in link: ${href || 'undefined'}`);
    return;
  }

  if (link.closest('div[data-text-ad], .ads-visurl')) {
    checkForPhishingAds(link);
  } else {
    analyzeDomainAndUrl(link);
  }
}


/**
 * Toont een eenmalige introductiebanner als deze nog niet eerder is getoond.
 * @param {string} message De tekst van de introductiebanner.
 */
async function showIntroBannerOnce(message) {
  try {
    const result = await chrome.storage.sync.get('hasShownIntroBanner');
    if (!result.hasShownIntroBanner) {
      // Creëer de banner
      const banner = document.createElement('div');
      banner.id = 'linkshield-intro-banner';
      banner.style.cssText = `
        position: fixed;
        top: 10px;
        left: 50%;
        transform: translateX(-50%);
        background-color: #4CAF50; /* Groen */
        color: white;
        padding: 15px 20px;
        border-radius: 8px;
        box-shadow: 0 4px 8px rgba(0, 0, 0, 0.2);
        z-index: 99999;
        font-family: sans-serif;
        font-size: 16px;
        text-align: center;
        opacity: 0;
        transition: opacity 0.5s ease-in-out;
      `;
      banner.textContent = message;

      document.body.appendChild(banner);

      // Fade-in effect
      setTimeout(() => {
        banner.style.opacity = '1';
      }, 100);

      // Verdwijn na 10 seconden
      setTimeout(() => {
        banner.style.opacity = '0';
        banner.addEventListener('transitionend', () => banner.remove());
      }, 10000); // 10 seconden

      // Stel de vlag in Chrome Storage in
      await chrome.storage.sync.set({ hasShownIntroBanner: true });
      logDebug("Introductiebanner getoond en vlag opgeslagen.");
    }
  } catch (error) {
    handleError(error, "showIntroBannerOnce");
  }
}



/**
 * Plaatst een waarschuwing-icoon bij een link op basis van niveau en redenen,
 * en vertaalt de reden-keys via chrome.i18n.
 *
 * @param {HTMLAnchorElement} link
 * @param {{ level: 'safe'|'caution'|'alert', reasons: string[] }} options
 */
async function warnLinkByLevel(link, { level, reasons }) {
  // Verwijder oude styling/iconen
  clearWarning(link);
  injectWarningIconStyles();

  if (level === 'safe') {
    return;
  }

  // Vertaal de reden-keys (houd camelCase, vervang alleen ongeldige tekens)
  const translatedReasons = reasons.map(r => {
    const key = r.replace(/[^a-zA-Z0-9_]/g, '_');
    return chrome.i18n.getMessage(key) || r;
  });

  // Alert: direct rood icoon, geen extra logica
  if (level === 'alert') {
    addIcon(link, '❗️', 'high-risk-warning', translatedReasons);
    return;
  }

  // Caution: geel icoon pas bij hover/focus, met stay-open als je naar het icoon beweegt
  if (level === 'caution') {
    let hideTimeout;

    const show = () => {
      clearTimeout(hideTimeout);
      // Voeg het icoon maar één keer toe
      if (!link.querySelector('.phishing-warning-icon')) {
        addIcon(link, '⚠️', 'moderate-warning', translatedReasons);
        // Zodra het icoon er is, zorg dat hover over icoon ook 'show' blijft triggeren
        const icon = link.querySelector('.phishing-warning-icon');
        icon.addEventListener('mouseenter', show);
        icon.addEventListener('mouseleave', hide);
      }
    };

    const hide = () => {
      clearTimeout(hideTimeout);
      hideTimeout = setTimeout(() => clearWarning(link), 300);
    };

    link.addEventListener('mouseenter', show);
    link.addEventListener('focus',     show);
    link.addEventListener('mouseleave', hide);
    link.addEventListener('blur',       hide);
  }
}

function addIcon(link, symbol, cssClass, reasons) {
  if (link.dataset.linkshieldWarned === 'true') return;
  const icon = document.createElement('span');
  icon.className = `phishing-warning-icon ${cssClass}`;
  icon.textContent = symbol;
  icon.title = `Redenen:\n${reasons.join('\n')}`;
  link.appendChild(icon);
  link.dataset.linkshieldWarned = 'true';
}

function clearWarning(link) {
  delete link.dataset.linkshieldWarned;
  const old = link.querySelector('.phishing-warning-icon');
  if (old) old.remove();
  link.classList.remove('moderate-risk-link', 'high-risk-link');
}


function injectWarningIconStyles() {
    if (!document.head.querySelector('#phishing-warning-styles')) {
        const style = document.createElement('style');
        style.id = 'phishing-warning-styles';
        style.textContent = `
            .phishing-warning-icon {
                position: relative;
                vertical-align: middle;
                margin-left: 5px;
                cursor: help;
                transition: color 0.3s ease;
            }
            .subtle-warning {
                font-size: 12px;
                color: #ff9800; /* Softer orange */
            }
            .high-risk-warning {
                font-size: 16px;
                color: #ff0000;
            }
            .high-risk-link {
                border: 1px dashed #ff0000;
                color: #ff0000;
            }
            .moderate-warning {
                font-size: 14px;
                color: #ff5722; /* Orange-red */
            }
            .moderate-risk-link {
                border: 1px dotted #ff5722;
            }
            .phishing-warning-icon:hover {
                color: #d32f2f; /* Darker red on hover */
            }
            /* NIEUWE FALLBACK STIJLEN HIERONDER */
            .high-risk-link-fallback {
                outline: 2px dashed #ff0000 !important; /* Een zichtbare rand als fallback */
                outline-offset: 2px !important;
                box-shadow: 0 0 5px rgba(255, 0, 0, 0.5) !important; /* Optionele schaduw */
            }
            .moderate-risk-link-fallback {
                outline: 1px dotted #ff5722 !important;
                outline-offset: 1px !important;
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



/**
 * Analyseert het domein en de URL van een gegeven link om verdachte kenmerken te detecteren.
 * Roept de gelaagde detectielogica aan en de bijbehorende visuele waarschuwing.
 * @param {HTMLAnchorElement} link - Het HTML-ankerelement om te analyseren.
 */
async function analyzeDomainAndUrl(link) {
  await ensureConfigReady(); // Zorgt ervoor dat de globale configuratie geladen is

  // Log de input voor debugging, inclusief type en SVG-status.
  // We controleren nu ook direct op SVGAnimatedString om fouten te voorkomen met new URL().
  logDebug(`Analyzing link with href: ${link.href}, Type: ${typeof link.href}, Instance: ${link.href instanceof SVGAnimatedString ? 'SVGAnimatedString' : 'Other'}`);

  // Valideer de link en de href: sla volledig ongeldige links over.
  // Behandel ook SVGAnimatedString correct door de baseVal te gebruiken.
  let href;
  if (link && link.href) {
    href = link.href instanceof SVGAnimatedString ? link.href.baseVal : link.href;
  } else {
    logDebug(`Skipping analysis: Invalid or missing link or href: ${link?.href || 'undefined'}`);
    return;
  }

  // Controleer of de href een geldige URL is na mogelijke SVG-conversie.
  if (!isValidURL(href)) {
    logDebug(`Skipping analysis: Invalid URL in link: ${href}`);
    return;
  }

  try {
    const urlObj = new URL(href);
    const hostname = urlObj.hostname;

    // Sla checks over voor interne IP-adressen, .local, of localhost.
    const isInternalIp = (host) => {
      return (
        /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host) ||
        /^192\.168\.\d{1,3}\.\d{1,3}$/.test(host) ||
        /^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host) ||
        /^172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}$/.test(host)
      );
    };

    if (isInternalIp(hostname) || hostname.endsWith(".local") || hostname === "localhost") {
      logDebug(`Internal server detected for ${hostname}. Skipping checks.`);
      return;
    }

    // Voer de gelaagde verdachte controles uit op de link's href.
    const result = await performSuspiciousChecks(href);

    // Als het risiconiveau niet 'safe' is, roep dan de visuele waarschuwing aan.
    if (result.level !== 'safe') {
      warnLinkByLevel(link, result);
    } else {
      // Optioneel: als de link eerder gemarkeerd was en nu veilig is, verwijder dan de markering.
      // De `warnLinkByLevel` functie doet dit al als `level === 'safe'`.
      logDebug(`Link ${href} is veilig bevonden (level: ${result.level}, risk: ${result.risk}). Geen waarschuwing nodig.`);
    }

  } catch (error) {
    // Specifieke afhandeling voor URL-constructie fouten (die nu minder vaak zouden moeten voorkomen door isValidURL).
    if (error instanceof TypeError && error.message.includes('Failed to construct \'URL\'')) {
      handleError(error, `analyzeDomainAndUrl: Invalid URL (possibly malformed or SVGAnimatedString) in link ${href || 'undefined'}`);
    } else {
      // Algemene foutafhandeling.
      handleError(error, `analyzeDomainAndUrl: Error analyzing URL ${href || 'undefined'}`);
    }
    // Geen verdere verwerking bij een fout.
    return;
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
    handleError(error, `getAbsoluteUrl: Fout bij omzetten van relatieve URL ${relativeUrl}`);
    return relativeUrl;
  }
}

async function calculateRiskScore(url) {
  let score = 0;
  let reasons = [];

  const addRisk = (points, reasonKey, severity = "low") => {
    if (!reasons.includes(reasonKey)) {
      score += points;
      reasons.push(reasonKey);
    }
  };

  try {
    const urlObj = new URL(url);
    const domain = normalizeDomain(url);
    if (!domain) return { score: -1, reasons: ["invalidUrl"] };

    const path = urlObj.pathname.toLowerCase();
    const urlParts = sanitizeInput(url.toLowerCase()).split(/[\/?#]/);
    const ext = urlObj.pathname.toLowerCase().match(/\.[0-9a-z]+$/i);
    const maxLength = globalConfig.MAX_URL_LENGTH || 2000;

    // --- AANGEPASTE TRUSTED DOMAIN CHECK ---
    const fullHostname = urlObj.hostname.toLowerCase();
    const isTrusted = safeDomains.some(trustedDomain => {
        // Controleer op exacte match (bv. "facebook.com")
        // OF op een subdomein (bv. "business.facebook.com")
        return fullHostname === trustedDomain || fullHostname.endsWith(`.${trustedDomain}`);
    });
    
    // Als het domein vertrouwd is, direct stoppen met een lage score
    if (isTrusted) {
      logDebug(`Trusted domain ${domain}, risk calculation skipped.`);
      return { score: 0, reasons: ["trustedDomain"] };
    }
    // --- EINDE AANPASSING ---

    const domainParts = domain.split(".");
    const subdomain = domainParts.length > 2 ? domainParts.slice(0, -2).join(".") : "";

    // --- START AANGEPASTE RISICOSCORES ---

    // 1. HTTPS-controle
    if (urlObj.protocol !== 'https:') {
      // De gevaarlijkste situatie eerst: een inlogpagina zonder HTTPS
      if (isLoginPage(url)) {
        addRisk(15, "insecureLoginPage", "high"); // Was 20
      } else {
        // Algemene onveilige verbinding
        addRisk(4, "noHttps", "medium"); // Was 15 (aanzienlijk verlaagd)
      }
    }

    // 2. Phishing-trefwoorden (contextuele indicator)
    if (urlParts.some(word => globalConfig.PHISHING_KEYWORDS.has(word))) {
      addRisk(1.5, "suspiciousKeywords", "low"); // Was 10
    }

    // 3. BrandKeyword subdomein check (alleen als niet trusted)
    if (!isTrusted && /^(login|secure|auth|signin|verify|portal|account|access)\b/i.test(subdomain)) {
      addRisk(4, `brandKeyword:${subdomain}`, "medium"); // Was 5
    }

    // 4. Download-trefwoorden (contextuele indicator)
    if (urlParts.some(word => globalConfig.DOWNLOAD_KEYWORDS.has(word))) {
      addRisk(3, "downloadKeyword", "low"); // Was 8
    }

    // 5. Verdachte bestandsextensies (sterke indicator)
    if (ext && globalConfig.MALWARE_EXTENSIONS.test(ext[0])) {
      addRisk(10, "malwareExtension", "high"); // Was 12
    }

    // 6. IP-adres als domeinnaam (sterke technische indicator)
    if (/^(?:https?:\/\/)?(\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:\/|$)/.test(url)) {
      addRisk(8, "ipAsDomain", "high"); // Was 12, nu verfijnd
      // Check op ongebruikelijke poort als extra risico
      if (urlObj.port && !["80", "443"].includes(urlObj.port)) {
        addRisk(4, "unusualPort", "medium"); // Was 6
      }
    }

    // 7. Verkorte URL (contextuele indicator)
    if (globalConfig.SHORTENED_URL_DOMAINS.has(domain)) {
      addRisk(3, "shortenedUrl", "medium"); // Was 6
      try {
        const response = await fetch(url, { method: 'HEAD', redirect: 'follow' });
        const finalUrl = response.url;
        // Een redirect is inherent aan een shortener, dus we verwijderen de extra bestraffing
        if (finalUrl && finalUrl !== url) {
           logDebug(`Shortened URL ${url} resolved to ${finalUrl}`);
        }
      } catch (error) {
        addRisk(2, "shortenedUrlError", "low"); // Was 5
        handleError(error, `calculateRiskScore: Kon verkorte URL ${url} niet oplossen`);
      }
    }

    // 8. Verdachte TLD's (sterke technische indicator)
    if (globalConfig.SUSPICIOUS_TLDS.test(domain)) {
      addRisk(7, "suspiciousTLD", "high"); // Was 15
    }

    // 9. Ongewoon lange URL's (zwakke indicator)
    if (url.length > maxLength) {
      addRisk(1, "urlTooLong", "low"); // Was 8
    }

    // 10. Gecodeerde tekens (zwakke indicator)
    if (/%[0-9A-Fa-f]{2}/.test(url)) {
      addRisk(1, "encodedCharacters", "low"); // Was 6
    }

    // 11. Te veel subdomeinen (technische indicator)
    if (domain.split(".").length > (globalConfig.MAX_SUBDOMAINS || 3)) { // Gebruik MAX_SUBDOMAINS uit config
      addRisk(4, "tooManySubdomains", "medium"); // Was 5
    }

    // 12. Base64, hex of javascript-schema (sterke indicator)
    if (/^(javascript|data):/.test(url) || /[a-f0-9]{32,}/.test(url)) {
      addRisk(10, "base64OrHex", "high"); // Was 12
    }
    
    // --- EINDE AANGEPASTE RISICOSCORES ---

    logDebug(`Risk score for ${url}: ${score}. Reasons: ${reasons.join(', ')}`);
    return { score, reasons };

  } catch (error) {
    handleError(error, `calculateRiskScore: Fout bij risicoberekening voor URL ${url}`);
    return { score: -1, reasons: ["errorCalculatingRisk"] };
  }
}



function isSearchResultPage() {
  const url = new URL(window.location.href);
  return url.hostname.includes("google.") && (url.pathname === "/search" || url.pathname === "/imgres");
}


function detectLoginPage(url = window.location.href) {
  try {
    const loginPatterns = /(login|signin|wp-login|auth|authenticate)/i;
    const urlIndicatesLogin = loginPatterns.test(url);
    const hasPasswordField = !!document.querySelector('input[type="password"]');
    logDebug(`Login detection: URL indication: ${urlIndicatesLogin}, Password field: ${hasPasswordField}`);
    return urlIndicatesLogin || hasPasswordField;
  } catch (error) {
    handleError(error, `detectLoginPage: Fout bij detecteren van loginpagina voor URL ${url}`);
    return false;
  }
}

function isLoginPage(url = window.location.href) {
  try {
    // Controleer op wachtwoordveld
    let hasPasswordField = false;
    try {
      hasPasswordField = document.querySelector('input[type="password"]') !== null;
    } catch (error) {
      handleError(error, `isLoginPage: Error checking for password field on URL ${url}`);
    }

    // Controleer op login-patronen in tekst
    let hasLoginText = false;
    try {
      if (document.body) {
        const loginPatterns = /(login|signin|auth|authenticate|wp-login)/i;
        hasLoginText = document.body.textContent.match(loginPatterns) !== null;
      }
    } catch (error) {
      handleError(error, `isLoginPage: Error checking login text patterns on URL ${url}`);
    }

    // Controleer op login-patronen in URL
    let hasLoginInUrl = false;
    try {
      const loginPatterns = /(login|signin|auth|authenticate|wp-login)/i;
      hasLoginInUrl = loginPatterns.test(url);
    } catch (error) {
      handleError(error, `isLoginPage: Error checking URL patterns on URL ${url}`);
    }

    // Basisdetectie: is dit waarschijnlijk een login-pagina?
    const basicDetection = hasPasswordField || hasLoginText || hasLoginInUrl;

    // Als geen login-pagina wordt gedetecteerd, stoppen we hier
    if (!basicDetection) {
      return false;
    }

    // Diepere analyse van formulieren voor phishing-detectie
    let isSuspiciousLoginForm = false;
    try {
      const forms = document.querySelectorAll('form');
      forms.forEach(form => {
        const inputs = form.querySelectorAll('input');
        let hasPassword = false;
        let hasSuspiciousFields = false;
        let hasHiddenFields = false;
        let hasAutoCompleteOn = false;
        let actionDomain = null;

        // Controleer het action-attribuut van het formulier
        const action = form.getAttribute('action');
        if (action) {
          try {
            const actionUrl = new URL(action, window.location.href);
            actionDomain = actionUrl.hostname;
            if (actionDomain !== window.location.hostname) {
              isSuspiciousLoginForm = true; // Verdacht: ander domein
            }
          } catch (error) {
            handleError(error, `isLoginPage: Error parsing form action URL ${action}`);
          }
        }

        // Analyseer alle inputvelden in het formulier
        inputs.forEach(input => {
          const type = input.getAttribute('type');
          const name = input.getAttribute('name');
          const autocomplete = input.getAttribute('autocomplete');

          // Controleer wachtwoordvelden en autocomplete
          if (type === 'password') {
            hasPassword = true;
            if (autocomplete !== 'off') {
              hasAutoCompleteOn = true; // Verdacht: autocomplete aan
            }
          }

          // Controleer op verborgen velden
          if (type === 'hidden') {
            hasHiddenFields = true; // Verdacht: verborgen veld aanwezig
          }

          // Controleer op verdachte veldnamen
          if (name && /(creditcard|ccnumber|securitycode|ssn|dob)/i.test(name)) {
            hasSuspiciousFields = true; // Verdacht: niet-login-gerelateerd veld
          }
        });

        // Beoordeel of het formulier verdacht is
        if (hasPassword && (hasSuspiciousFields || hasHiddenFields || hasAutoCompleteOn || actionDomain !== window.location.hostname)) {
          isSuspiciousLoginForm = true;
        }
      });
    } catch (error) {
      handleError(error, `isLoginPage: Error analyzing forms on URL ${url}`);
    }

    // Controleer of de pagina via HTTPS wordt geserveerd
    let isHttpsSecure = true;
    try {
      if (window.location.protocol !== 'https:') {
        isHttpsSecure = false; // Verdacht: geen HTTPS
      }
    } catch (error) {
      handleError(error, `isLoginPage: Error checking HTTPS for URL ${url}`);
    }

    // Resultaat: login-pagina met verdachte kenmerken of geen HTTPS
    const result = basicDetection && (isSuspiciousLoginForm || !isHttpsSecure);
    logDebug("Login Page Analysis: Basic detection = ", basicDetection, ", Suspicious form = ", isSuspiciousLoginForm, ", HTTPS secure = ", isHttpsSecure, "Result = ", result);
    return result;
  } catch (error) {
    handleError(error, `isLoginPage: Unexpected error while detecting login page on URL ${url}. Details: ${error.message}`);
    return false;
  }
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
    handleError(e, `isHttps: Fout bij controleren van protocol voor URL ${url}`);
    return false;
  }
}

function isIpAddress(input) {
  if (!input || typeof input !== 'string') {
    logDebug(`Skipping IP check for invalid input: ${input || 'undefined'}`);
    return false;
  }

  const trimmed = input.trim().toLowerCase();

  // ❗ Voorkom crash bij incomplete of ongeldige schema's
  if (
    trimmed === '' ||
    trimmed === 'https://' ||
    trimmed === 'http://' ||
    trimmed.startsWith('mailto:') ||
    trimmed.startsWith('javascript:')
  ) {
    logDebug(`Skipping IP check for unsupported input: ${input}`);
    return false;
  }

  let hostname = input;
  try {
    if (input.includes('://')) {
      hostname = new URL(input).hostname;
    }

    const ipv4Pattern = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    if (ipv4Pattern.test(hostname)) {
      logDebug(`IPv4 address detected: ${hostname}`);
      return true;
    }

    const ipv6Pattern = /^(([0-9a-fA-F]{1,4}:){7,7}[0-9a-fA-F]{1,4}|... )$/; // jouw bestaande IPv6-regex
    if (ipv6Pattern.test(hostname)) {
      logDebug(`IPv6 address detected: ${hostname}`);
      return true;
    }

    logDebug(`No IP address detected for hostname: ${hostname}`);
    return false;
  } catch (error) {
    logDebug(`Fout bij controleren van IP-adres voor input ${input}: ${error.message}`);
    return false;
  }
}


const mxCache = {};
const MX_TTL_MS = 3600 * 1000; // 1 uur
const MAX_RETRIES = 2;
const RETRY_DELAY_MS = 1000;
const REQUEST_TIMEOUT_MS = 5000;

// Functie om verlopen cache-entries te verwijderen
function cleanMxCache() {
  const now = Date.now();
  for (const domain in mxCache) {
    if (now - mxCache[domain].timestamp >= MX_TTL_MS) {
      delete mxCache[domain];
      logDebug(`Verwijderd verlopen cache-entry voor ${domain}`);
    }
  }
}

// Periodieke schoonmaak van de cache (elke 10 minuten)
setInterval(cleanMxCache, 10 * 60 * 1000);

// Fetch met timeout
async function fetchWithTimeout(url, options = {}) {
  const controller = new AbortController();
  const timeoutId = setTimeout(() => controller.abort(), REQUEST_TIMEOUT_MS);
  try {
    const response = await fetch(url, { ...options, signal: controller.signal });
    clearTimeout(timeoutId);
    return response;
  } catch (error) {
    if (error.name === 'AbortError') {
      throw new Error('Request timeout');
    }
    throw error;
  }
}

// Retry-logica voor netwerkverzoeken
async function retryFetch(url, options = {}, retries = MAX_RETRIES) {
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      return await fetchWithTimeout(url, options);
    } catch (error) {
      if (attempt < retries) {
        logDebug(`Poging ${attempt} mislukt voor ${url}: ${error.message}. Probeer opnieuw...`);
        await new Promise(resolve => setTimeout(resolve, RETRY_DELAY_MS));
      } else {
        throw error;
      }
    }
  }
}



// Validatie van hostnamen
function isValidHostname(hostname) {
  return /^[a-zA-Z0-9.-]+$/.test(hostname) && hostname.includes('.');
}

const mxQueue = [];
let isProcessing = false;

async function processMxQueue() {
  if (isProcessing || mxQueue.length === 0) return;
  isProcessing = true;
  const { domain, resolve } = mxQueue.shift();
  try {
    const mxRecords = await getMxRecords(domain);
    resolve(mxRecords);
  } catch (error) {
    handleError(error, `MX-queue: Fout voor ${domain}`);
    resolve([]);
  }
  isProcessing = false;
  processMxQueue();
}

function queueMxCheck(domain) {
  return new Promise(resolve => {
    mxQueue.push({ domain, resolve });
    processMxQueue();
  });
}


async function getMxRecords(domain) {
  const now = Date.now();
  
  if (mxCache[domain] && (now - mxCache[domain].timestamp < MX_TTL_MS)) {
    logDebug(`MX-cache hit voor ${domain}:`, mxCache[domain].records);
    return mxCache[domain].records;
  }

  // Controleer vertrouwde domeinen
  const trustedDomains = window.trustedDomains || [];
  const isTrusted = trustedDomains.some(pattern => {
    const regex = new RegExp(pattern);
    return regex.test(domain) || domain.endsWith(pattern.replace(/\\\.com$/, '.com'));
  });

  if (isTrusted) {
    logDebug(`MX-check overgeslagen voor vertrouwd domein: ${domain}`);
    mxCache[domain] = { records: [], timestamp: now };
    return [];
  }

  let mxHosts = [];
  mxHosts = await tryGetMxRecords(domain);
  if (mxHosts.length === 0) {
    const parts = domain.split('.');
    if (parts.length > 2) {
      const parentDomain = parts.slice(-2).join('.');
      mxHosts = await tryGetMxRecords(parentDomain);
      logDebug(`Geen MX voor ${domain}, fallback naar ${parentDomain}:`, mxHosts);
    }
  }

  mxCache[domain] = { records: mxHosts, timestamp: now };
  if (mxHosts.length === 0) {
    logDebug(`Geen MX-records gevonden voor ${domain} via alle providers`);
  }
  return mxHosts;

  async function tryGetMxRecords(targetDomain) {
    const googleUrl = `https://dns.google/resolve?name=${targetDomain}&type=MX`;
    try {
      const response = await retryFetch(googleUrl);
      const json = await response.json();
      if (json.Status === 0 && json.Answer) {
        const hosts = json.Answer
          .map(r => r.data.split(' ')[1]?.replace(/\.$/, ''))
          .filter(host => host && isValidHostname(host));
        if (hosts.length > 0) {
          logDebug(`MX-records (Google) voor ${targetDomain}:`, hosts);
          return hosts;
        }
      }
      logDebug(`Geen geldige MX-records via Google voor ${targetDomain}`);
    } catch (error) {
      handleError(error, `Google DoH faalde voor ${targetDomain} - ${error.message}`);
    }

    const cloudflareUrl = `https://cloudflare-dns.com/dns-query?name=${targetDomain}&type=MX`;
    try {
      const response = await retryFetch(cloudflareUrl, {
        headers: { 'Accept': 'application/dns-json' }
      });
      const json = await response.json();
      if (json.Status === 0 && json.Answer) {
        const hosts = json.Answer
          .map(r => r.data.split(' ')[1]?.replace(/\.$/, ''))
          .filter(host => host && isValidHostname(host));
        if (hosts.length > 0) {
          logDebug(`MX-records (Cloudflare) voor ${targetDomain}:`, hosts);
          return hosts;
        }
      }
      logDebug(`Geen geldige MX-records via Cloudflare voor ${targetDomain}`);
    } catch (error) {
      handleError(error, `Cloudflare DoH faalde voor ${targetDomain} - ${error.message}`);
    }
    return [];
  }
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
    handleError(error, `hasSuspiciousPattern: Fout bij controleren van patronen in URL ${url}`);
    return false;
  }
}

function countMatches(pattern, ...strings) {
  return strings.reduce((count, str) => count + (str.match(pattern) || []).length, 0);
}

let trustedDownloadDomains = new Set();

function isDownloadPage(url) {
  try {
    const urlObj = new URL(url);
    const ext = urlObj.pathname.toLowerCase().match(/\.[0-9a-z]+$/i);
    if (ext && globalConfig.MALWARE_EXTENSIONS.test(ext[0])) {
      logDebug(`Download extension detected in URL: ${url}`);
      return true;
    }
    return false;
  } catch (error) {
    handleError(error, `isDownloadPage: Fout bij controleren van downloadpagina voor URL ${url}`);
    return false;
  }
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
    handleError(error, `isUrlTooLong: Fout bij controleren van URL-lengte voor ${url}`);
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


// Definieer de cache buiten de functie voor persistentie
const scriptFetchCache = new Map();
const SCRIPT_CACHE_TTL_MS = 3600000; // 1 uur TTL

async function analyzeScriptContent(scriptUrl) {
  try {
    const urlString = scriptUrl.href;
    const cached = scriptFetchCache.get(urlString);
    const now = Date.now();
    if (cached && now - cached.timestamp < SCRIPT_CACHE_TTL_MS) {
      logDebug(`Cache hit voor script fetch: ${urlString}`);
      return cached.result;
    }

    const response = await fetch(urlString);
    if (!response.ok) {
      logDebug(`Kan script niet ophalen: ${urlString} (Status: ${response.status})`);
      const result = { isSuspicious: false, matchedPatterns: [], totalWeight: 0 };
      scriptFetchCache.set(urlString, { result, timestamp: now });
      return result;
    }

    const scriptText = await response.text();

    // Overslaan kleine scripts
    if (scriptText.length < 2048) {
      logDebug(`Script te klein om verdacht te zijn: ${urlString} (${scriptText.length} bytes)`);
      const result = { isSuspicious: false, matchedPatterns: [], totalWeight: 0 };
      scriptFetchCache.set(urlString, { result, timestamp: now });
      return result;
    }

    // Controleer op bekende bibliotheken
    const knownLibraries = [
      /jQuery\s+v?[\d.]+/,
      /React(?:DOM)?\s+v?[\d.]+/,
      /angular[\d.]+/,
      /vue[\d.]+/,
      /bootstrap[\d.]+/,
      /lodash[\d.]+/,
      /moment\.js/,
      /axios[\d.]+/,
      /d3\s+v?[\d.]+/,
      /chart\.js/,
      /backbone[\d.]+/,
      /underscore[\d.]+/,
      /polyfill[\d.]+/,
      /sw[\d.]+/,
      /gtag/,
      /sentry\.io/,
    ];
    if (knownLibraries.some((pattern) => pattern.test(scriptText))) {
      logDebug(`Bekende bibliotheek gedetecteerd: ${urlString}`);
      const result = { isSuspicious: false, matchedPatterns: [], totalWeight: 0 };
      scriptFetchCache.set(urlString, { result, timestamp: now });
      return result;
    }

    // Controleer op verdachte patronen
    let totalWeight = 0;
    const matchedPatterns = [];

    const suspiciousPatterns = globalConfig?.SUSPICIOUS_SCRIPT_PATTERNS;
    if (Array.isArray(suspiciousPatterns)) {
      suspiciousPatterns.forEach(({ regex, weight, description }) => {
        if (regex && typeof regex.test === 'function' && regex.test(scriptText)) {
          totalWeight += weight;
          matchedPatterns.push(description);
        }
      });
    } else {
      logDebug("Waarschuwing: SUSPICIOUS_SCRIPT_PATTERNS is niet beschikbaar of geen array.");
    }

    // Drempels voor verdacht script
    const isMinified = scriptText.replace(/\s/g, '').length > scriptText.length * 0.8;
    const hasNoSourceMap = !/\/\/\s*sourceMappingURL=/i.test(scriptText);
    const hasExplicitMalware = totalWeight > 0;

    const isSuspicious = isMinified && hasNoSourceMap && hasExplicitMalware && totalWeight >= 12;
    const result = { isSuspicious, matchedPatterns, totalWeight };

    if (isSuspicious) {
      logDebug(`Verdacht script gedetecteerd: ${urlString}, Gewicht: ${totalWeight}, Patronen: ${matchedPatterns.join(', ')}`);
    } else {
      logDebug(`Script is veilig: ${urlString}, Gewicht: ${totalWeight}, Patronen: ${matchedPatterns.join(', ')}`);
    }

    scriptFetchCache.set(urlString, { result, timestamp: now });
    return result;

  } catch (error) {
    handleError(error, `analyzeScriptContent: Fout bij analyseren van script ${scriptUrl.href}`);
    const result = { isSuspicious: false, matchedPatterns: [], totalWeight: 0 };
    scriptFetchCache.set(scriptUrl.href, { result, timestamp: Date.now() });
    return result;
  }
}


// Optioneel: Periodieke cache-schoonmaak
setInterval(() => {
  const now = Date.now();
  for (const [url, { timestamp }] of scriptFetchCache) {
    if (now - timestamp >= SCRIPT_CACHE_TTL_MS) {
      scriptFetchCache.delete(url);
      logDebug(`Removed expired script cache entry for ${url}`);
    }
  }
}, SCRIPT_CACHE_TTL_MS);

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
   handleError(error, `checkScriptMinification: Fout bij controleren van scriptminificatie voor ${scriptUrl.href}`);
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
  try {
    const url = new URL(string, window.location.href);
    const protocol = url.protocol;
    const allowedProtocols = ['http:', 'https:', 'mailto:', 'tel:', 'ftp:'];
    if (!allowedProtocols.includes(protocol)) return false;
    if (['http:', 'https:', 'ftp:'].includes(protocol) && !url.hostname) return false;
    return true;
  } catch (error) {
    logDebug(`isValidURL: Ongeldige URL gedetecteerd: ${string}`);
    return false;
  }
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
 * Normaliseert een domein door homoglyphs te vervangen door hun Latijnse equivalenten.
 * @param {string} domain - Het te normaliseren domein.
 * @param {object} homoglyphMap - De homoglyph-mapping uit config.js.
 * @returns {string} - Het genormaliseerde domein.
 */
function normalizeWithHomoglyphs(str, homoglyphMap) {
  return str.replace(/./g, c => {
    const mapped = homoglyphMap[c] || c;
    if (mapped !== c) {
      logDebug(`Mapping ${c} (U+${c.codePointAt(0).toString(16)}) to ${mapped}`);
    }
    return mapped;
  });
}

/**
 * Extraheert het hoofddomein uit een volledig domein.
 * @param {string} domain - Het volledige domein.
 * @returns {string} - Het hoofddomein.
 */
function extractMainDomain(domain) {
  const parts = domain.toLowerCase().split('.');
  const tld = parts.slice(-1)[0];
  const compoundTlds = window.CONFIG.COMPOUND_TLDS || [];
  if (compoundTlds.some(ctld => domain.endsWith(ctld))) {
    return parts.slice(-3).join('.');
  }
  return parts.slice(-2).join('.');
}

/**
 * Bouwt de globale reverse homoglyph mapping op uit de HOMOGLYPHS configuratie.
 * Dit wordt gebruikt om homoglyphen (bijv. cyrillische 'а') terug te mappen naar hun
 * Latijnse basis (bijv. 'a').
 */
function buildGlobalHomoglyphReverseMap() {
    const homoglyphs = globalConfig.HOMOGLYPHS || {};
    const tempReverseMap = {};

    // Map Latijnse basiskarakters naar zichzelf en hun varianten naar de Latijnse basis
    for (const [latinBase, variants] of Object.entries(homoglyphs)) {
        tempReverseMap[latinBase] = latinBase; // 'a' mapt naar 'a'
        if (Array.isArray(variants)) {
            for (const variant of variants) {
                tempReverseMap[variant] = latinBase; // 'а' mapt naar 'a'
            }
        }
    }

    // VOEG HIER EXTRA SPECIFIEKE MAPPINGS TOE VOOR BEKENDE PROBLEMATISCHE UNICODE-TEKENS
    // die niet altijd correct worden gestript door normalize('NFD').replace(/\p{Diacritic}/gu, '')
    // of die specifieke homoglyphen zijn voor cijfers of andere letters
    tempReverseMap['rn'] = 'm'; // Typo
    tempReverseMap['vv'] = 'w'; // Typo
    tempReverseMap['0'] = 'o';  // Cijfer homoglyph
    tempReverseMap['1'] = 'l';  // Cijfer homoglyph
    tempReverseMap['3'] = 'e';
    tempReverseMap['4'] = 'a';
    tempReverseMap['5'] = 's';
    tempReverseMap['7'] = 't';
    tempReverseMap['8'] = 'b';
    tempReverseMap['9'] = 'g';
    tempReverseMap['2'] = 'z';
    tempReverseMap['6'] = 'b';

    // Specifieke Punycode/Homoglyph issues
    tempReverseMap['Ñ'] = 'n'; // Hoofdletter N met tilde (U+00D1)
    tempReverseMap['ñ'] = 'n'; // Kleine letter n met tilde (U+00F1) - deze was al in homoglyphs
    tempReverseMap['İ'] = 'i'; // Hoofdletter I met punt (U+0130) - Turks I
    tempReverseMap['ı'] = 'i'; // Kleine letter puntloze i (U+0131) - Turks i
    tempReverseMap['Ø'] = 'o'; // Hoofdletter O met schuine streep (U+00D8)
    tempReverseMap['ø'] = 'o'; // Kleine letter o met schuine streep (U+00F8)
    tempReverseMap['Œ'] = 'oe';// Latijnse ligature OE (U+0152)
    tempReverseMap['œ'] = 'oe';// Latijnse ligature oe (U+0153)
    tempReverseMap['ẞ'] = 'ss';// Duitse scherpe S (U+1E9E)
    tempReverseMap['ß'] = 'ss';// Duitse scherpe S (U+00DF)

    // Overige Cyrillische / Griekse homoglyphen die vaak voorkomen bij phishing
    tempReverseMap['а'] = 'a'; // Cyrillisch a
    tempReverseMap['с'] = 'c'; // Cyrillisch es
    tempReverseMap['е'] = 'e'; // Cyrillisch ie
    tempReverseMap['і'] = 'i'; // Cyrillisch i (dotless)
    tempReverseMap['κ'] = 'k'; // Grieks kappa
    tempReverseMap['м'] = 'm'; // Cyrillisch em
    tempReverseMap['о'] = 'o'; // Cyrillisch o
    tempReverseMap['р'] = 'p'; // Cyrillisch er
    tempReverseMap['ѕ'] = 's'; // Cyrillisch ze
    tempReverseMap['т'] = 't'; // Cyrillisch te
    tempReverseMap['у'] = 'y'; // Cyrillisch u
    tempReverseMap['х'] = 'x'; // Cyrillisch ha
    tempReverseMap['з'] = 'z'; // Cyrillisch ze (alternate)
    tempReverseMap['д'] = 'd'; // Cyrillisch de
    tempReverseMap['г'] = 'r'; // Cyrillisch ge (lowercase, seems like r)
    tempReverseMap['п'] = 'n'; // Cyrillisch pe
    tempReverseMap['б'] = 'b'; // Cyrillisch be
    tempReverseMap['ц'] = 'u'; // Cyrillisch tse
    tempReverseMap['э'] = 'e'; // Cyrillisch e
    tempReverseMap['ш'] = 'w'; // Cyrillisch sha
    tempReverseMap['ч'] = 'h'; // Cyrillisch che
    tempReverseMap['щ'] = 'sh'; // Cyrillisch shcha
    tempReverseMap['ъ'] = ''; // Hard sign (invisible/ignored)
    tempReverseMap['ь'] = ''; // Soft sign (invisible/ignored)

    // Grieks
    tempReverseMap['α'] = 'a'; // Alpha
    tempReverseMap['β'] = 'b'; // Beta
    tempReverseMap['ε'] = 'e'; // Epsilon
    tempReverseMap['η'] = 'n'; // Eta
    tempReverseMap['ι'] = 'i'; // Iota
    tempReverseMap['κ'] = 'k'; // Kappa
    tempReverseMap['μ'] = 'm'; // Mu
    tempReverseMap['ν'] = 'v'; // Nu
    tempReverseMap['ο'] = 'o'; // Omicron
    tempReverseMap['ρ'] = 'p'; // Rho
    tempReverseMap['τ'] = 't'; // Tau
    tempReverseMap['υ'] = 'u'; // Upsilon
    tempReverseMap['χ'] = 'x'; // Chi
    tempReverseMap['ψ'] = 'ps'; // Psi
    tempReverseMap['ω'] = 'w'; // Omega
    tempReverseMap['π'] = 'p'; // Pi (U+03C0) <-- Deze is belangrijk voor "πaypal.com"
    tempReverseMap['λ'] = 'l'; // Lambda (U+03BB)


    globalHomoglyphReverseMap = tempReverseMap;
    logDebug("Global homoglyph reverse map built with", Object.keys(globalHomoglyphReverseMap).length, "entries.");
}

/**
 * Controleert of een domein een homoglyph- of typosquatting-aanval is.
 * @param {string} domain             Het onbewerkte domein (zonder protocol).
 * @param {object} homoglyphMap       De mapping uit globalConfig.HOMOGLYPHS (nu alleen gebruikt voor `buildGlobalHomoglyphReverseMap`).
 * @param {string[]} knownBrands      Lijst met legitieme domeinen.
 * @param {string} tld                De TLD (bv. 'fr', 'de', 'co.uk').
 * @param {Set<string>} reasons       Set waarin de reden-tags worden toegevoegd.
 * @returns {Promise<boolean>}        True als een aanval is gedetecteerd, anders false.
 */
async function isHomoglyphAttack(domain, homoglyphMap, knownBrands, tld = '', reasons = new Set()) {
    // Zorg dat de globale config geladen is
    await ensureConfigReady();

    // Bouw de reverse map als deze nog niet is gebouwd
    if (Object.keys(globalHomoglyphReverseMap).length === 0) {
        buildGlobalHomoglyphReverseMap();
    }
    const reverseMap = globalHomoglyphReverseMap;

    // Basiskontrole
    if (!domain || typeof domain !== 'string') {
        logDebug('isHomoglyphAttack: Ongeldig domein:', domain);
        return false;
    }

    try {
        // 1) CLEANUP & NFC
        let cleanHostname = domain
            .toLowerCase()
            .replace(/^www\./, '')
            .normalize('NFC');
        logDebug(`Clean hostname: ${cleanHostname}`);

        
        // 2) WHITELIST-EXACT MATCH (op basis van Unicode-codepoints)
        const safeList = Array.isArray(globalConfig.legitimateDomains)
            ? globalConfig.legitimateDomains.map(d => d.toLowerCase().normalize('NFC'))
            : [];
        const cp = [...cleanHostname].map(c => c.codePointAt(0)).join();
        if (safeList.some(d =>
            [...d].map(c => c.codePointAt(0)).join() === cp
        )) {
            logDebug(`Whitelist: ${cleanHostname} is exact legitiem domein`);
            reasons.add('safeDomain');
            return false;
        }

        // 3) SUBDOMEINEN-CHECK
        // Correcte berekening van subdomeinen, rekening houdend met compound TLDs.
        const tldParts = tld.split('.');
        const actualSubCount = cleanHostname.split('.').length - (tldParts.length + 1); // +1 voor het SLD
        if (actualSubCount > (globalConfig.MAX_SUBDOMAINS || 3)) {
            logDebug(`Te veel subdomeinen in ${cleanHostname}: ${actualSubCount}`);
            reasons.add('tooManySubdomains');
        }

        // 4) PUNYCODE-DECODING
        let decodedDomain = cleanHostname;
        let isPunycode = false;
        if (cleanHostname.startsWith('xn--') && typeof punycode !== 'undefined' && punycode.toUnicode) {
            try {
                decodedDomain = punycode.toUnicode(cleanHostname)
                    .toLowerCase()
                    .normalize('NFC');
                isPunycode = true;
                logDebug(`Punycode decoded: ${cleanHostname} → ${decodedDomain}`);
            } catch (e) {
                logError(`Punycode faalde voor ${cleanHostname}: ${e.message}`);
                reasons.add('punycodeDecodingError');
            }
        }

        // 5) DIAKRITICA-STRIPPING
        // Dit is een standaard Unicode normalisatie stap.
        const strippedDomain = decodedDomain
            .normalize('NFD') // Normaliseert naar decomposed form (bijv. 'ö' -> 'o' + diacritisch teken)
            .replace(/\p{Diacritic}/gu, '') // Verwijdert alle diakritische tekens
            .normalize('NFC'); // Normaliseert terug naar canonical form
        logDebug(`Diacritics stripped: ${decodedDomain} → ${strippedDomain}`);

        // 6) GEMENGDE SCRIPTS-CHECK
        const scripts = getUnicodeScripts(strippedDomain); // Deze functie moet Unicode scripts identificeren
        const accentFriendlyTlds = ['fr','de','es','it']; // TLDs waar gemengde scripts minder verdacht zijn
        if (scripts.size > 1 && !accentFriendlyTlds.includes(tld.toLowerCase())) {
            logDebug(`Gemengde scripts in ${strippedDomain}: ${[...scripts].join(',')}`);
            reasons.add('mixedScripts');
        }

        // 7) SKELETON-NORMALISATIE (Kern van de homoglyph-detectie)
        // Gebruik de `normalizeToLatinBase` functie die de `globalHomoglyphReverseMap` gebruikt.
        const skeletonDomain = normalizeToLatinBase(strippedDomain, reverseMap);
        logDebug(`Skeleton domain: ${strippedDomain} → ${skeletonDomain}`);

        // 8) SUSPICIOUS PUNYCODE-NA NORMALISATIE
        // Controleert of een Punycode-domein, eenmaal gedecodeerd en geskeletoniseerd,
        // verdacht veel lijkt op een bekend merk.
        if (isPunycode && skeletonDomain !== cleanHostname) { // Vergelijk skeleton met *initiële* cleanHostname voor verandering
            for (const brand of safeList) {
                const brandMain = extractMainDomain(brand); // Zorg dat brandMain ook genormaliseerd is
                const dist = levenshteinDistance(skeletonDomain, brandMain);
                // Een kleine Levenshtein afstand na normalisatie van een Punycode is zeer verdacht.
                if (dist > 0 && dist <= 2) {
                    logDebug(`Suspicious punycode after skeleton: ${skeletonDomain} lijkt op ${brandMain}`);
                    reasons.add(`suspiciousPunycodeDecoding:${brandMain.replace(/\./g,'_')}`);
                    return true; // Hoog risico, direct return
                }
            }
        }

        // 9) EXTRACT MAIN DOMAIN (altijd op basis van skeletonDomain voor vergelijkingen)
        const mainDomain = extractMainDomain(skeletonDomain);
        logDebug(`Main domain for Levenshtein: ${skeletonDomain} → ${mainDomain}`);

        // 10) ACCENT-VRIENDELIJKE TLD? (voor logging, geen risico-add)
        if (
            tld && accentFriendlyTlds.includes(tld.toLowerCase()) &&
            scripts.size === 1 && scripts.has('Latin')
        ) {
            logDebug(`Accent-TLD ${tld} met alleen Latin; minder verdacht.`);
        }

        // 11) DIGIT-TYPOSQUATTING (specifiekere check)
        // Detecteert wanneer cijfers worden gebruikt om merknamen na te bootsen (bijv. g00gle.com)
        let digitTyposquattingDetected = false;
        // De `digitMap` is al geïntegreerd in `buildGlobalHomoglyphReverseMap`
        // We vergelijken de `strippedDomain` (zonder diakritica)
        // met de geskeletoniseerde versie (die cijfers naar letters omzet)
        const skeletonFromStrippedDigits = normalizeToLatinBase(strippedDomain, reverseMap);

        for (const brand of knownBrands) {
            const brandMain = extractMainDomain(brand.toLowerCase().normalize('NFC'));
            if (!brandMain) continue;

            const dist = levenshteinDistance(skeletonFromStrippedDigits, brandMain);
            const ratio = dist / Math.max(skeletonFromStrippedDigits.length, brandMain.length);

            // Als de afstand na cijfer-substitutie erg klein is, is het verdacht.
            // dist <= 1 is zeer sterk bewijs.
            // dist <= 2 met een lage relatieve ratio (bijv. < 0.1) kan ook verdacht zijn.
            if (dist > 0 && (dist <= 1 || (dist <= 2 && ratio < 0.1))) {
                // Alleen toevoegen als de originele domeinnaam daadwerkelijk een cijfer bevatte
                if (/\d/.test(cleanHostname)) { // Controleer of het origineel een cijfer had
                    logDebug(`Digit typosquatting: "${cleanHostname}" (stripped+mapped: "${skeletonFromStrippedDigits}") looks like "${brandMain}" (d=${dist}, r=${ratio.toFixed(3)})`);
                    reasons.add(`digitTyposquatting:${brandMain.replace(/\./g,'_')}`);
                    digitTyposquattingDetected = true;
                    // Geen break hier, om alle relevante matches te vinden.
                }
            }
        }
        if (digitTyposquattingDetected) {
            return true; // Hoog risico, direct return
        }


        // 12) ALGEMENE TYPOSQUATTING-PATRONEN
        // Dit zijn patronen die vaak duiden op typosquatting, naast homoglyphen.
        const patterns = globalConfig.TYPOSQUATTING_PATTERNS || [
            /g00gle/i, /paypa1/i, /micr0soft/i, // Specifieke, hardcoded typos
            /-\d+\b/, // bv. google-4.com (domein met suffix-cijfer)
            /[-.]login\b/i, // bv. microsoft.login.com (subdomein/path 'login')
            // OPMERKING: /^(?:[a-z0-9]+\.)+[a-z0-9]+\.[a-z]{2,}$/ is vaak gedekt door 'tooManySubdomains'
            /^[a-z0-9-]{1,63}\.[a-z]{2,}$/ // bv. weebly-9.com (generieke hostingsnamen met cijfers)
        ];

        for (const pat of patterns) {
            if (pat.test(skeletonDomain)) { // Test op de geskeletoniseerde versie
                for (const brand of knownBrands) {
                    const bm = extractMainDomain(brand.toLowerCase().normalize('NFC'));
                    if (tld && !bm.endsWith(`.${tld}`)) continue; // Optioneel: alleen vergelijken met merken met dezelfde TLD
                    const dist = levenshteinDistance(mainDomain, bm); // Vergelijk mainDomain (skeleton) met brandMain
                    const ratio = dist / Math.max(mainDomain.length, bm.length);

                    // Lage afstand is verdacht
                    if (dist > 0 && (dist <= 2 && ratio <= 0.2)) { // dist 1 of 2 met acceptabele ratio
                        logDebug(`Typosquatting patroon match: "${skeletonDomain}" (main: "${mainDomain}") → "${bm}" (d=${dist}, r=${ratio.toFixed(3)})`);
                        reasons.add(`typosquatting_${bm.replace(/\./g,'_')}`);
                        return true; // Hoog risico, direct return
                    }
                }
            }
        }

        // 13) GENERIEKE LEVENSHTEIN-CHECK (op geskeletoniseerde hoofddomein)
        // Dit is een catch-all voor domeinen die niet via specifieke patronen zijn gevangen,
        // maar wel een zeer lage Levenshtein-afstand hebben tot een bekend merk na normalisatie.
        let minDist = Infinity, closest = null;
        for (const brand of knownBrands) {
            const bm = extractMainDomain(brand.toLowerCase().normalize('NFC'));
            if (tld && !bm.endsWith(`.${tld}`)) continue;
            const d = levenshteinDistance(mainDomain, bm); // Vergelijk mainDomain (skeleton) met brandMain
            if (d > 0 && d <= 2 && d < minDist) { // Max 2 verschillen
                minDist = d; closest = bm;
            }
        }
        if (closest && !reasons.has('tooManySubdomains')) { // Voorkom dubbele flagging
            const ratio = minDist / Math.max(mainDomain.length, closest.length);
            // Pas de drempel aan: Punycode-domeinen zijn inherent verdachter, zelfs met lage ratios.
            // globalConfig.SUSPICION_THRESHOLD is een goede basis.
            const threshold = isPunycode ? 0.05 : (globalConfig.SUSPICION_THRESHOLD || 0.1); // Lagere threshold voor Punycode

            logDebug(`Levenshtein generiek: "${mainDomain}" vs "${closest}" → d=${minDist}, r=${ratio.toFixed(3)}, t=${threshold}`);
            // Conditie: 1 teken verschil is altijd verdacht, of ratio onder threshold.
            if (minDist === 1 || ratio <= threshold) {
                reasons.add(`similarToLegitimateDomain_${closest.replace(/\./g,'_')}`);
                return true; // Markeer als verdacht
            }
        }

        // 14) EINDOORDEEL: Retourneer true als er enige reden is gevonden.
        return reasons.size > 0;

    } catch (error) {
        logError(`isHomoglyphAttack error voor ${domain}: ${error.message}`);
        return false; // Bij een fout, retourneer false om overblokkering te voorkomen.
    }
}





/**
 * Haalt de Unicode-scripts van karakters in een string op.
 * @param {string} str - De te analyseren string.
 * @returns {Set<string>} - Set van Unicode-scriptnamen.
 */
function getUnicodeScripts(str) {
  const scripts = new Set();

  // Valideer invoer
  if (!str || typeof str !== 'string') {
    logDebug(`getUnicodeScripts: Ongeldige invoer: ${str}`);
    return scripts;
  }

  for (const char of str) {
    const codePoint = char.codePointAt(0);
    if (!Number.isInteger(codePoint)) {
      logDebug(`getUnicodeScripts: Ongeldig codepoint voor karakter: ${char}`);
      continue;
    }

    const script = getScriptForCodePoint(codePoint);
    if (script) {
      scripts.add(script);
      logDebug(`Character ${char} (U+${codePoint.toString(16).toUpperCase()}) mapped to script: ${script}`);
    } else {
      logDebug(`Character ${char} (U+${codePoint.toString(16).toUpperCase()}) heeft geen bekende script`);
    }
  }

  return scripts;
}

/**
 * Bepaalt de Unicode-script voor een gegeven codepoint.
 * @param {number} codePoint - Het Unicode-codepoint van een teken.
 * @returns {string|null}    De scriptnaam (bijv. 'Latin', 'Cyrillic', 'Greek', etc.),
 *                            of null bij ongeldig input.
 */
function getScriptForCodePoint(codePoint) {
  // 1) Input-validatie
  if (!Number.isInteger(codePoint) || codePoint < 0) {
    return null;
  }

  // 2) Ranges checken van meest voorkomende scripts
  if (codePoint <= 0x02FF) {
    // Basic Latin + Latin-1 + Latin Extended-A/B
    return 'Latin';
  }
  if (codePoint >= 0x0370 && codePoint <= 0x03FF) {
    return 'Greek';
  }
  if (codePoint >= 0x0400 && codePoint <= 0x04FF) {
    return 'Cyrillic';
  }
  if (codePoint >= 0x0530 && codePoint <= 0x058F) {
    return 'Armenian';
  }
  if (codePoint >= 0x0600 && codePoint <= 0x06FF) {
    return 'Arabic';
  }
  if (codePoint >= 0x3040 && codePoint <= 0x309F) {
    return 'Hiragana';
  }
  if (codePoint >= 0x30A0 && codePoint <= 0x30FF) {
    return 'Katakana';
  }
  if (codePoint >= 0x4E00 && codePoint <= 0x9FFF) {
    return 'Han';
  }
  // Interpunctie, spaties, zero-width etc.
  if (
    (codePoint >= 0x2000 && codePoint <= 0x206F) || 
    codePoint === 0x200B || codePoint === 0x200C || codePoint === 0x200D
  ) {
    return 'Common';
  }

  // 3) Fallback voor alle andere ranges
  return 'Unknown';
}


/**
 * Bepaalt verwachte scripts op basis van TLD.
 * @param {string} tld - De top-level domein (bijv. 'fr').
 * @returns {string[]} - Lijst van verwachte scripts.
 */
function getExpectedScriptForTld(tld) {
  const tldScriptMap = {
    'fr': ['Latin'],
    'ru': ['Cyrillic'],
    'cn': ['Han'],
    'jp': ['Hiragana', 'Katakana', 'Han'],
    'de': ['Latin'],
    // Voeg meer TLD's en scripts toe
  };
  return tldScriptMap[tld.toLowerCase()] || ['Latin'];
}

// Je bestaande Levenshtein-functie (ongewijzigd)
function levenshteinDistance(a, b) {
  const matrix = Array(b.length + 1).fill().map(() => Array(a.length + 1).fill(0));
  for (let i = 0; i <= a.length; i++) matrix[0][i] = i;
  for (let j = 0; j <= b.length; j++) matrix[j][0] = j;
  for (let j = 1; j <= b.length; j++) {
    for (let i = 1; i <= a.length; i++) {
      const indicator = a[i - 1] === b[j - 1] ? 0 : 1;
      matrix[j][i] = Math.min(
        matrix[j][i - 1] + 1,
        matrix[j - 1][i] + 1,
        matrix[j - 1][i - 1] + indicator
      );
    }
  }
  return matrix[b.length][a.length];
}



const nonHttpProtocols = ['mailto:', 'tel:'];


// -------------------------
// performSuspiciousChecks.js (gewone script-versie, géén modules)
// -------------------------

// Globaal cache-object voor performSuspiciousChecks
const linkRiskCache = new Map();


/**
 * Helper om resultaat in de cache op te slaan, inclusief timestamp.
 */
function storeInCache(url, result) {
    linkRiskCache.set(url, {
        timestamp: Date.now(),
        result
    });
}


/**
 * Voert een reeks gelaagde checks uit op een URL en retourneert het risiconiveau.
 * De checks zijn verdeeld in fasen: lokaal, licht netwerk/CPU, en diepe validatie.
 * @param {string} url - De URL die gecontroleerd moet worden.
 * @returns {Promise<{level: 'safe'|'caution'|'alert', risk: number, reasons: string[]}>}
 */
async function performSuspiciousChecks(url) {
  await ensureConfigReady();

  // 1) Cache lookup
  const cachedEntry = window.linkRiskCache.get(url);
  if (cachedEntry && Date.now() - cachedEntry.timestamp < CACHE_TTL_MS) {
    logDebug(`Cache hit voor verdachte controles: ${url}`);
    return cachedEntry.result;
  }

  // 2) Feature flag
  if (!await isProtectionEnabled()) {
    const fallback = { level: 'safe', risk: 0, reasons: [] };
    window.linkRiskCache.set(url, { result: fallback, timestamp: Date.now() });
    return fallback;
  }

  const reasons = new Set();
  const totalRiskRef = { value: 0 };

  // 3) URL parsing
  let urlObj;
  try {
    urlObj = new URL(url, window.location.href);
  } catch (err) {
    logError(`Ongeldige URL: ${url}`, err);
    const fallback = { level: 'safe', risk: 0, reasons: ['invalidUrl'] };
    window.linkRiskCache.set(url, { result: fallback, timestamp: Date.now() });
    return fallback;
  }

  // 4) Early exits voor niet-http(s) protocollen, met verbeterde javascript: handling
  const nonHttpProtocols = ['mailto:', 'tel:', 'ftp:', 'javascript:'];
  if (nonHttpProtocols.includes(urlObj.protocol)) {
    logDebug(`Niet-HTTP protocol gedetecteerd: ${urlObj.protocol}`);

    if (urlObj.protocol === 'javascript:') {
      const clean = url.trim().toLowerCase();
      // Alleen flaggen als het geen harmless shorthand is én er verdacht script in zit
      if (!harmlessJsProtocols.includes(clean) && hasJavascriptScheme(clean)) {
        reasons.add('javascriptScheme');
        totalRiskRef.value += 8;
        logDebug(`⚠️ Verdachte javascript link: ${url}`);
      }
      // anders geen waarschuwing
    } else {
      reasons.add('allowedProtocol');
    }

    const level = totalRiskRef.value >= globalConfig.LOW_THRESHOLD ? 'caution' : 'safe';
    const result = { level, risk: totalRiskRef.value, reasons: Array.from(reasons) };
    window.linkRiskCache.set(url, { result, timestamp: Date.now() });
    return result;
  }

  // 5) file: protocol
  if (urlObj.protocol === 'file:') {
    logDebug(`File protocol gedetecteerd: ${url}`);
    const result = { level: 'safe', risk: 0, reasons: ['fileProtocol'] };
    window.linkRiskCache.set(url, { result, timestamp: Date.now() });
    return result;
  }

  // 6) Invalid hostname
  if (!urlObj.hostname || urlObj.href === `${urlObj.protocol}//`) {
    logDebug(`Ongeldige hostname, overslaan: ${url}`);
    const result = { level: 'safe', risk: 0, reasons: ['invalidHostname'] };
    window.linkRiskCache.set(url, { result, timestamp: Date.now() });
    return result;
  }

  // 7) Whitelist check (trusted domains)
  if ((globalConfig.legitimateDomains || []).includes(urlObj.hostname)) {
    logDebug(`Trusted domain ${urlObj.hostname} gedetecteerd.`);
    const result = { level: 'safe', risk: 0, reasons: ['trustedDomain'] };
    window.linkRiskCache.set(url, { result, timestamp: Date.now() });
    return result;
  }

  // =================== HIER BEGINT DE SSL-SKIP FIX ===================
  const currentPageHostname = window.location.hostname;
  if (urlObj.hostname !== currentPageHostname) {
    try {
      const sslResult = await new Promise(resolve => {
        chrome.runtime.sendMessage(
          { action: 'checkSslLabs', domain: urlObj.hostname },
          resolve
        );
      });
      if (!sslResult.isValid) {
        reasons.add('sslValidationFailed');
        totalRiskRef.value += (globalConfig.PROTOCOL_RISK * 2);
        logDebug(`⚠️ SSL Labs check faalde voor extern domein ${urlObj.hostname}: ${sslResult.reason}`);
      } else {
        logDebug(`✅ SSL Labs check OK voor extern domein ${urlObj.hostname}: ${sslResult.reason}`);
      }
    } catch (e) {
      reasons.add('sslValidationFailed');
      totalRiskRef.value += (globalConfig.PROTOCOL_RISK * 2);
      logError(`Fout bij SSL Labs check voor extern domein ${urlObj.hostname}`, e);
    }
  } else {
    logDebug(`SSL Labs check overgeslagen voor intern domein: ${urlObj.hostname}`);
  }
  // =================== HIER EINDIGT DE SSL-SKIP FIX ===================

  // 9) Fase 1: snelle, lokale checks
  checkStaticConditions(url, reasons, totalRiskRef);

  // 10) Fase 2: middelzware, async checks
  await checkDynamicConditionsPhase2(url, reasons, totalRiskRef);

  // 11) Fase 3: diepe checks (domain-age, MX, login HTTPS)
  if (totalRiskRef.value >= globalConfig.DOMAIN_AGE_MIN_RISK) {
    await checkDomainAgeDynamic(url, { totalRiskRef, reasons });
  }
  if (detectLoginPage(url)) {
    try {
      let dom = urlObj.hostname.toLowerCase();
      if (dom.startsWith('xn--') && typeof punycode !== 'undefined') {
        dom = punycode.toUnicode(dom);
      }
      const mx = await queueMxCheck(dom);
      if (mx.length === 0) {
        reasons.add('loginPageNoMX');
        totalRiskRef.value += 12;
      }
    } catch (e) {
      handleError(e, 'performSuspiciousChecks MX');
    }
    if (urlObj.hostname === window.location.hostname && urlObj.protocol !== 'https:') {
      reasons.add('insecureLoginPage');
      totalRiskRef.value += 15;
      logDebug(`⚠️ Insecure loginpagina zonder HTTPS: ${url}`);
    }
  }

  // 12) Bepaal final level en cache
  const finalLevel = totalRiskRef.value >= globalConfig.HIGH_THRESHOLD
    ? 'alert'
    : (totalRiskRef.value >= globalConfig.LOW_THRESHOLD ? 'caution' : 'safe');
  const finalResult = {
    level: finalLevel,
    risk: Number(totalRiskRef.value.toFixed(1)),
    reasons: Array.from(reasons)
  };
  window.linkRiskCache.set(url, { result: finalResult, timestamp: Date.now() });
  logDebug(`Resultaat voor ${url}:`, finalResult);
  return finalResult;
}




/**
 * Scant alle iframes op de pagina en retourneert een lijst met i18n-reden-keys voor verdachte iframes.
 * Werkt met de SUSPICIOUS_IFRAME_PATTERNS en TRUSTED_IFRAME_DOMAINS uit window.CONFIG, en optioneel
 * met host-specifieke uitzonderingen via CONFIG.HOST_IFRAME_EXCEPTIONS.
 *
 * @returns {Promise<string[]>} Een array van unieke reden-keys.
 */
async function hasSuspiciousIframes() {
  await ensureConfigReady();
  const config = window.CONFIG || {};

  // Globale patronen en whitelists
  const patterns        = config.SUSPICIOUS_IFRAME_PATTERNS || [];
  const trustedDomains  = config.TRUSTED_IFRAME_DOMAINS   || [];
  const hostExceptionsConfig = config.HOST_IFRAME_EXCEPTIONS || {};
  const currentHost     = window.location.hostname;

  // Host-specifieke uitzonderingen (regex strings uit config omgezet naar RegExp)
  const hostExceptions = (hostExceptionsConfig[currentHost] || [])
    .map(str => new RegExp(str, 'i'));

  const iframes = Array.from(document.getElementsByTagName('iframe'))
    .filter(iframe => iframe.src || iframe.srcdoc);
  const detected = new Set();

  for (const iframe of iframes) {
    const src = iframe.src || '';

    // 1) Iframe zonder src maar met verdachte attributen
    if (!src) {
      const style = getComputedStyle(iframe);
      const isTiny = parseInt(style.width) < 2 && parseInt(style.height) < 2;
      if ((iframe.hasAttribute('onload') || iframe.hasAttribute('onerror')) && isTiny) {
        detected.add('suspiciousIframeHidden');
      }
      continue;
    }

    // 2) URL-parsing en validatie
    let urlObj;
    try {
      urlObj = new URL(src, window.location.origin);
    } catch (err) {
      detected.add('invalidIframeSrc');
      logError(`hasSuspiciousIframes: Ongeldige src: ${src}`);
      continue;
    }
    const hostname = urlObj.hostname.replace(/^www\./, '').toLowerCase();

    // 3) Globale domein-whitelist
    if (trustedDomains.some(d => {
      d = d.toLowerCase();
      return hostname === d || hostname.endsWith(`.${d}`);
    })) {
      logDebug(`hasSuspiciousIframes: Vertrouwd domein, overslaan: ${src}`);
      continue;
    }

    // 4) Host-specifieke uitzonderingen
    if (hostExceptions.some(rx => rx.test(src))) {
      logDebug(`hasSuspiciousIframes: Host-exceptie, overslaan: ${src}`);
      continue;
    }

    // 5) Aanvullende signalen
    const style  = getComputedStyle(iframe);
    const rect   = iframe.getBoundingClientRect();
    const isHidden = style.display === 'none'
                  || style.visibility === 'hidden'
                  || style.opacity === '0';
    const isSmall  = rect.width  < 100
                  && rect.height < 100;

    // 6) Strengere regex: boundaries en negatieve look-arounds
    for (const { name, pattern } of patterns) {
      if (!(pattern instanceof RegExp)) continue;
      const strict = new RegExp(
        `(?:^|\\b)(?:${pattern.source})(?:\\b|$)`,
        pattern.flags
      );
      if (strict.test(src) && (isHidden || isSmall)) {
        detected.add(name);
        logDebug(`hasSuspiciousIframes: Verdacht (${name}): ${src}`);
        break;
      }
    }
  }

  logDebug(`hasSuspiciousIframes: Gedetecteerde redenen: ${[...detected].join(', ')}`);
  return [...detected];
}



/**
 * Controleert externe scripts op verdachte kenmerken met een focus op inhoudsanalyse
 * en minder nadruk op zwakke, contextuele signalen om false positives te verminderen.
 * @returns {Promise<string[]>} Een array van reden-keys voor daadwerkelijk verdachte scripts.
 */
async function checkForSuspiciousExternalScripts() {
  const MAX_SCRIPTS_TO_CHECK = 20;
  const scripts = Array.from(document.getElementsByTagName('script'))
    .filter(s => s.src)
    .slice(0, MAX_SCRIPTS_TO_CHECK);

  // --- VERBETERING 1: Configuratie en whitelists eenmalig ophalen ---
  let trustedDomains = [];
  try {
    const json = await fetchCachedJson('trustedScripts.json');
    if (Array.isArray(json)) {
      trustedDomains = json
        .filter(d => typeof d === 'string' && /^[a-zA-Z0-9.-]+$/.test(d))
        .map(d => d.toLowerCase());
    }
  } catch (err) {
    handleError(err, 'checkForSuspiciousExternalScripts: fout laden trustedScripts.json');
  }

  const builtinTrusted = [
    'google.com', 'www.google.com', 'google.be', 'www.google.be',
    'accounts.google.com', 'search.google.com', 'www.gstatic.com',
    'translate.google.com', 'support.google.com', 'apis.google.com',
    'googleapis.com', 'cloudflare.com', 'cdnjs.cloudflare.com', 'jsdelivr.net', 'unpkg.com',
    'code.jquery.com', 'bootstrapcdn.com', 'ajax.googleapis.com', 'static.cloudflareinsights.com',
    'polyfill.io', 'googletagmanager.com', 'analytics.google.com',
  ];
  const trustedScripts = new Set([...builtinTrusted, ...trustedDomains]);

  // Aanbeveling: Maak deze lijst in de configuratie veel kleiner!
  const safeTLDs = new Set(['com', 'net', 'org', 'edu', 'gov', 'be', 'nl', 'io', 'app', 'dev', 'tech', 'cloud', 'info']);

  const allDetectedReasons = new Set();
  const currentPageHostname = window.location.hostname;

  for (const script of scripts) {
    const src = script.src;
    if (!src) continue;

    try {
      const urlObj = new URL(src);

      // --- VERBETERING X: Overslaan niet-HTTP(S)-scripts ---
      if (urlObj.protocol !== 'http:' && urlObj.protocol !== 'https:') {
        logDebug(`⚪️ Overslaan niet-HTTP(S)-script: ${src}`);
        continue;
      }

      const hostname = urlObj.hostname.toLowerCase();

      // --- VERBETERING 2: Interne scripts direct overslaan ---
      if (hostname === currentPageHostname) {
        logDebug(`🔵 Intern script overgeslagen: ${src}`);
        continue;
      }

      // --- Whitelist check (vertrouwde externe domeinen) ---
      if (trustedScripts.has(hostname) || Array.from(trustedScripts).some(d => hostname.endsWith(`.${d}`))) {
        logDebug(`🟢 Vertrouwd extern script: ${src}`);
        continue;
      }
      
      // --- Heuristische checks voor overslaan (async, defer, module) ---
      if (script.hasAttribute('defer') || script.hasAttribute('async') || script.getAttribute('type') === 'module') {
        logDebug(`🟢 Modern script (defer/async/module) overgeslagen: ${src}`);
        continue;
      }

      // --- VERBETERING 3: Contextuele risico's verzamelen i.p.v. direct bestraffen ---
      let contextualRisk = 0;
      const contextReasons = [];

      // Mixed content
      if (urlObj.protocol === 'http:' && window.location.protocol === 'https:') {
        contextualRisk += 6;
        contextReasons.push('mixedContent');
        logDebug(`[Context] ⚠️ mixedContent: ${src}`);
      }

      // Verdachte TLD
      if (globalConfig?.SUSPICIOUS_TLDS instanceof RegExp) {
        const tld = hostname.split('.').pop();
        if (globalConfig.SUSPICIOUS_TLDS.test(tld) && !safeTLDs.has(tld)) {
          contextualRisk += 1;
          contextReasons.push('suspiciousTLD');
          logDebug(`[Context] 🤏 Verdachte TLD (.${tld}): ${src}`);
        }
      }

      // IP-adres als domein
      if (/^\d+\.\d+\.\d+\.\d+$/.test(hostname)) {
        contextualRisk += 3;
        contextReasons.push('ipAsDomain');
        logDebug(`[Context] ⚠️ IP-domein: ${src}`);
      }

      // --- VERBETERING 4: Focus op de inhoudsanalyse ---
      const contentResult = await analyzeScriptContent(urlObj);
      if (contentResult.isSuspicious) {
        const totalRisk = contentResult.totalWeight + contextualRisk;
        logDebug(`[Analyse] Inhoud verdacht (gewicht ${contentResult.totalWeight}), context risico (${contextualRisk}). Totaal: ${totalRisk}`);

        if (totalRisk >= (globalConfig?.SCRIPT_RISK_THRESHOLD || 10)) {
          logDebug(`❌ Verdacht script gedetecteerd (score ${totalRisk}): ${src}`);
          contentResult.matchedPatterns.forEach(reason => allDetectedReasons.add(reason));
          contextReasons.forEach(reason => allDetectedReasons.add(reason));
        } else {
          logDebug(`✔️ Inhoud wel verdacht, maar totale score (${totalRisk}) is onder de drempel.`);
        }
      } else {
        logDebug(`✔️ Inhoudsanalyse OK voor script: ${src}`);
      }

    } catch (err) {
      logError(`checkForSuspiciousExternalScripts: fout bij ${src}: ${err.message}`);
      allDetectedReasons.add('scriptAnalysisError');
    }
  }

  logDebug(`🔍 Totaal gedetecteerde redenen voor verdachte scripts: ${[...allDetectedReasons].join(', ')}`);
  return [...allDetectedReasons];
}












// Optionele periodieke cache-schoonmaak (voeg dit toe aan je script)
setInterval(() => {
  const now = Date.now();
  for (const [url, { timestamp }] of linkRiskCache) {
    if (now - timestamp >= CACHE_TTL_MS) {
      linkRiskCache.delete(url);
      logDebug(`Removed expired cache entry for ${url}`);
    }
  }
}, CACHE_TTL_MS);

/**
 * Voert “statische” controles uit op een URL, wijzigt `reasons` en `totalRiskRef.value`.
 * - Punycode + NFC-normalisatie
 * - Whitelist-check vóór alle andere checks
 * - HTTPS-controle (noHttps) in fase 1
 * - Compound-TLD-ondersteuning bij subdomeinen
 * - Adaptieve relatieve Levenshtein-drempel (≤ 0.1 of 0.2)
 * - Extra statische checks: urlTooLong, encodedCharacters, unusualPort, ipAsDomain, suspiciousTLD
 *
 * @param {string} url
 * @param {Set<string>} reasons
 * @param {{ value: number }} totalRiskRef
 */
function checkStaticConditions(url, reasons, totalRiskRef) {
  let urlObj;
  try {
    urlObj = new URL(url, window.location.href);
  } catch (err) {
    logError(`checkStaticConditions: Ongeldige URL: ${url}`);
    return;
  }

  // 1) Punycode-decoding & NFC-normalisatie
  let rawHost = urlObj.hostname.toLowerCase();
  if (rawHost.startsWith('xn--') && typeof punycode !== 'undefined' && punycode.toUnicode) {
    try {
      rawHost = punycode.toUnicode(rawHost);
      logDebug(`Static: Punycode decoded: ${urlObj.hostname} → ${rawHost}`);
    } catch (e) {
      logError(`Static: Kon Punycode niet decoderen voor ${urlObj.hostname}: ${e.message}`);
    }
  }
  const hostNFC = rawHost.normalize('NFC');

  // 2) Whitelist vóór alle checks
  const allSafe = new Set([
    ...(window.trustedDomains || []),
    ...(globalConfig.legitimateDomains || [])
  ].map(d => d.toLowerCase().replace(/^www\./, '')));
  const checkDomain = hostNFC.replace(/^www\./, '');
  if (allSafe.has(checkDomain)) {
    logDebug(`Static: ✅ ${checkDomain} is expliciet veilig (whitelist).`);
    reasons.add('safeDomain');
    totalRiskRef.value = 0;
    return;
  }

  const proto = urlObj.protocol;

  // 3) Verzamel subdomein-informatie m.b.v. compound TLDs
  const parts = hostNFC.split('.');
  let tldLen = 1;
  for (const ctld of (globalConfig.COMPOUND_TLDS || [])) {
    if (hostNFC === ctld || hostNFC.endsWith(`.${ctld}`)) {
      tldLen = ctld.split('.').length;
      break;
    }
  }
  const subCount = parts.length - tldLen - 1;

  // 4) Overzicht van alle statische checks INCLUSIEF HTTPS
  const staticChecks = [
    // HTTPS-controle
    {
      condition: proto === 'http:',
      weight: globalConfig.PROTOCOL_RISK,
      reason: 'noHttps'
    },
    // Verdachte TLD's
    {
      condition: (globalConfig.SUSPICIOUS_TLDS instanceof RegExp)
        ? globalConfig.SUSPICIOUS_TLDS.test(hostNFC)
        : false,
      weight: 7,
      reason: 'suspiciousTLD'
    },
    // IP-adres als domeinnaam
    {
      condition: /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/.test(hostNFC),
      weight: 8,
      reason: 'ipAsDomain'
    },
    // Te veel subdomeinen
    {
      condition: !isIpAddress(hostNFC) && subCount > (globalConfig.MAX_SUBDOMAINS || 3),
      weight: 4,
      reason: 'tooManySubdomains'
    },
    // Ongewoon lange URL's
    {
      condition: url.length > (globalConfig.MAX_URL_LENGTH || 2000),
      weight: 1,
      reason: 'urlTooLong'
    },
    // Gecodeerde tekens
    {
      condition: hasEncodedCharacters(url),
      weight: 1,
      reason: 'encodedCharacters'
    },
    // Ongebruikelijke poort
    {
      condition: hasUnusualPort(url),
      weight: 5,
      reason: 'unusualPort'
    }
  ];

  for (const { condition, weight, reason } of staticChecks) {
    if (condition && !reasons.has(reason)) {
      logDebug(`Static: ${reason} gedetecteerd op ${hostNFC}`);
      reasons.add(reason);
      totalRiskRef.value += weight;
    }
  }

  // 5) Adaptieve Levenshtein-check tegen legitieme domeinen
  if (
    Array.isArray(globalConfig.legitimateDomains) &&
    typeof globalConfig.domainRiskWeights === 'object'
  ) {
    for (const legit of globalConfig.legitimateDomains) {
      const base = extractMainDomain(legit.toLowerCase().normalize('NFC'));
      const dist = levenshteinDistance(hostNFC, base);
      if (dist > 0 && dist <= 2) {
        const maxLen = Math.max(hostNFC.length, base.length);
        const ratio = dist / maxLen;
        const thr = (base.length <= 6)
          ? 0.2
          : (globalConfig.SUSPICION_THRESHOLD || 0.1);
        logDebug(`Static Levenshtein: ${hostNFC} vs ${base} → d=${dist}, r=${ratio.toFixed(2)}, t=${thr}`);
        if (ratio <= thr) {
          const wt = globalConfig.domainRiskWeights[base] || 1;
          const key = `similarToLegitimateDomain:${base}`;
          if (!reasons.has(key)) {
            logDebug(`Static: ${key} (weight=${wt})`);
            reasons.add(key);
            totalRiskRef.value += wt;
          }
          break;
        }
      }
    }
  }
}



/**
 * Voert snelle, lokale checks uit op een URL zonder netwerkverkeer.
 * Wijzigt `reasons` en `totalRiskRef.value` direct.
 * @param {string} url - De volledige URL.
 * @param {Set<string>} reasons - Set waarin reason-tags worden toegevoegd.
 * @param {{ value: number }} totalRiskRef - Object dat de cumulatieve risicoscore bijhoudt.
 */
function applyStaticChecks(url, reasons, totalRiskRef) {
    let urlObj;
    try {
        urlObj = new URL(url, window.location.href);
    } catch (err) {
        logError(`applyStaticChecks: Ongeldige URL: ${url}`);
        reasons.add('invalidUrl');
        totalRiskRef.value += 0.5; // Een minimaal risico voor ongeldige URL's
        return;
    }

    const rawHost = urlObj.hostname.toLowerCase();
    let hostNFC = rawHost; // Start met rawHost, normalisatie gebeurt later
    let isPunycode = false;

    // Decode punycode indien nodig
    if (rawHost.startsWith('xn--') && typeof punycode !== 'undefined') {
        try {
            hostNFC = punycode.toUnicode(rawHost);
            logDebug(`Static: Punycode decoded: ${rawHost} → ${hostNFC}`);
            isPunycode = true;
        } catch (e) {
            logError(`Static: Kon Punycode niet decoderen voor ${rawHost}: ${e.message}`);
            reasons.add('punycodeDecodingError');
            totalRiskRef.value += 2;
        }
    }
    // Normaliseer naar NFC voor consistente vergelijkingen
    hostNFC = hostNFC.normalize('NFC');

    // --- GEFIXTE WHITELIST-LOGICA ---
    const allSafe = Array.from(new Set([
        ...(window.trustedDomains || []),
        ...(globalConfig.legitimateDomains || [])
    ]))
    .map(d => d.toLowerCase().replace(/^www\./, ''));

    // Check op exact match of subdomein-match
    const checkDomainRaw = rawHost.replace(/^www\./, '');
    const checkDomainDecoded = hostNFC.replace(/^www\./, '');
    const isWhitelisted = allSafe.some(d =>
        checkDomainRaw === d || checkDomainRaw.endsWith(`.${d}`) ||
        checkDomainDecoded === d || checkDomainDecoded.endsWith(`.${d}`)
    );

    if (isWhitelisted) {
        logDebug(`Static: ✅ Domein "${checkDomainRaw}" of "${checkDomainDecoded}" is (sub)domein van whitelist. Skip verdere checks.`);
        reasons.add('safeDomain');
        totalRiskRef.value = 0; // Geen risico voor whitelisted domeinen
        return;
    }
    // --- Einde GEFIXTE WHITELIST-LOGICA ---

    // Bepaal aantal subdomeinen, met ondersteuning voor compound TLDs
    const parts = hostNFC.split('.');
    let tldLen = 1;
    for (const ctld of (globalConfig.COMPOUND_TLDS || [])) {
        if (hostNFC === ctld || hostNFC.endsWith(`.${ctld}`)) {
            tldLen = ctld.split('.').length;
            break;
        }
    }
    const subdomainCount = parts.length - (tldLen + 1);

    // De overige statische checks
    const staticChecks = [
        {
            condition: (globalConfig.SUSPICIOUS_TLDS instanceof RegExp)
                       && globalConfig.SUSPICIOUS_TLDS.test(hostNFC),
            weight: 6,
            reason: 'suspiciousTLD'
        },
        {
            condition: /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/.test(hostNFC),
            weight: 5,
            reason: 'ipAsDomain'
        },
        {
            condition: subdomainCount > (globalConfig.MAX_SUBDOMAINS || 3),
            weight: 5,
            reason: 'tooManySubdomains'
        },
        {
            condition: (globalConfig.TYPOSQUATTING_PATTERNS || []).some(pat => pat.test(hostNFC)),
            weight: 3,
            reason: 'typosquattingPattern'
        },
        {
            condition: url.length > (globalConfig.MAX_URL_LENGTH || 2000),
            weight: 2,
            reason: 'urlTooLong'
        },
        {
            condition: /%[0-9A-Fa-f]{2}/.test(url) && !hasEncodedCharactersExclusion(url),
            weight: 2,
            reason: 'encodedCharacters'
        }
    ];

    staticChecks.forEach(({ condition, weight, reason }) => {
        if (condition && !reasons.has(reason)) {
            logDebug(`Static: ${reason} gedetecteerd op ${hostNFC}`);
            reasons.add(reason);
            totalRiskRef.value += weight;
        }
    });

    // Uitsluiting voor enkel %20 in pad
    function hasEncodedCharactersExclusion(u) {
        const o = new URL(u);
        const enc = /%[0-9A-Fa-f]{2}/g;
        const pathMatches = (o.pathname.match(enc) || []);
        const queryMatches = (o.search.match(enc)   || []);
        const uniq = new Set([...pathMatches, ...queryMatches]);
        return uniq.size === 1 && uniq.has('%20')
               && pathMatches.length > 0 && queryMatches.length === 0;
    }

    // Levenshtein-check tegen legitieme domeinen
    if (Array.isArray(globalConfig.legitimateDomains)
        && typeof globalConfig.domainRiskWeights === 'object') {
        const simpHost = hostNFC.replace(/[-.]/g, '');
        for (const legit of globalConfig.legitimateDomains) {
            const simpLegit = legit.toLowerCase().replace(/^www\./, '').replace(/[-.]/g, '');
            const dist = levenshteinDistance(simpHost, simpLegit);
            if (dist > 0 && dist <= 2) {
                const ratio = dist / Math.max(simpHost.length, simpLegit.length);
                const thr = (simpLegit.length <= 6) ? 0.2 : (globalConfig.SUSPICION_THRESHOLD || 0.1);
                if (ratio <= thr) {
                    const wt = globalConfig.domainRiskWeights[legit] || 1;
                    const tag = `similarToLegitimateDomain:${legit.replace(/\./g,'_')}`;
                    if (!reasons.has(tag)) {
                        logDebug(`Static (Lev): ${tag} (weight=${wt})`);
                        reasons.add(tag);
                        totalRiskRef.value += wt;
                    }
                    break;
                }
            }
        }
    }

    logDebug(`Einde applyStaticChecks: Risico ${totalRiskRef.value}, Redenen: ${[...reasons].join(', ')}`);
}




/**
 * Voert middelzware checks uit (licht netwerk/CPU, DOM-analyse) op een URL.
 * Wordt alleen uitgevoerd als de statische checks al een basisrisico hebben gedetecteerd.
 * @param {string} url - De volledige URL.
 * @param {Set<string>} reasons - Set waarin reason-tags worden toegevoegd.
 * @param {{ value: number }} totalRiskRef - Object dat de cumulatieve risicoscore bijhoudt.
 */
async function applyMediumChecks(url, reasons, totalRiskRef) {
  const urlObj = new URL(url);
  const domainOnly = urlObj.hostname.toLowerCase();
  const tld = extractTld(domainOnly); // Gebruik je eigen extractTld functie

  // Bouw homoglyphMap en knownBrands vanuit globalConfig
  const homoglyphMapEntries = globalConfig.HOMOGLYPHS || {};
  const homoglyphMap = {};
  for (const [latin, variants] of Object.entries(homoglyphMapEntries)) {
    if (Array.isArray(variants)) { // Check if variants is an array
      for (const g of variants) {
        homoglyphMap[g] = latin;
      }
    }
  }
  const knownBrands = Array.isArray(globalConfig.legitimateDomains)
    ? globalConfig.legitimateDomains.map(d => d.toLowerCase())
    : [];

  // Lijst van checks voor de middelzware fase
  const mediumChecks = [
    // isHomoglyphAttack kan network calls doen (bijv. voor punycode, hoewel we die al eerder decodeerden),
    // dus past hier goed. Het voegt zelf al redenen toe aan de 'reasons' Set.
    {
    func: async () => {
      // maak een eigen Set voor deze check
      const localReasons = new Set();
      const attack = await isHomoglyphAttack(domainOnly, homoglyphMap, knownBrands, tld, localReasons);
      if (attack) {
        reasons.add('homoglyphAttack');
        // eventueel: localReasons.forEach(r => reasons.add(r));
      }
      return attack;
    },
    messageKey: 'homoglyphAttack',
    risk: 10
  },
    { func: async () => await isShortenedUrl(url), messageKey: 'shortenedUrl', risk: 4.0 },
    { func: async () => await isDownloadPage(url), messageKey: 'downloadPage', risk: 3.5 },
    { func: async () => await hasSuspiciousQueryParameters(url), messageKey: 'suspiciousParams', risk: 2.5 },
    { func: async () => await hasMixedContent(url), messageKey: 'mixedContent', risk: 2.0 },
    { func: async () => await hasUnusualPort(url), messageKey: 'unusualPort', risk: 5 },
    { func: async () => await hasJavascriptScheme(url), messageKey: 'javascriptScheme', risk: 4.0 },
    { func: async () => await usesUrlFragmentTrick(url), messageKey: 'urlFragmentTrick', risk: 2.0 },
    { func: async () => await isCryptoPhishingUrl(url), messageKey: 'cryptoPhishing', risk: 10.0 },
    { func: async () => await isFreeHostingDomain(url), messageKey: 'freeHosting', risk: 5 },
    { func: async () => await hasSuspiciousKeywords(url), messageKey: 'suspiciousKeywords', risk: 2.0 },
    { func: async () => await hasSuspiciousUrlPattern(url), messageKey: 'suspiciousPattern', risk: 3.0 },
    // Scripts en Iframes checks zijn vaak iets zwaarder door DOM-traversal / head requests
    // Deze retourneren al arrays van redenen.
    { func: async () => await hasSuspiciousIframes(), messageKey: 'suspiciousIframes', risk: 3.5 },
    { func: async () => await checkForSuspiciousExternalScripts(), messageKey: 'suspiciousScripts', risk: 4.0 },
  ];

  for (const { func, messageKey, risk } of mediumChecks) {
    try {
      const result = await func();
      let triggered = false;
      let specificReasons = [];

      if (Array.isArray(result)) {
        if (result.length > 0) {
          triggered = true;
          specificReasons = result;
        }
      } else {
        triggered = Boolean(result);
      }

      // Voeg alleen de risicopunten en redenen toe als de check niet al een reden heeft toegevoegd
      // of als de check zelf een array van specifieke redenen retourneert.
      if (triggered) {
        if (specificReasons.length > 0) {
          specificReasons.forEach(r => reasons.add(r));
        } else if (!reasons.has(messageKey)) { // Voeg alleen toe als de reden nog niet bestaat
          reasons.add(messageKey);
        }
        totalRiskRef.value += risk;
        logDebug(`Fase 2: Toegevoegd ${messageKey} (risico ${risk}) voor ${url}. Huidig risico: ${totalRiskRef.value}.`);
      }
    } catch (e) {
      handleError(e, `applyMediumChecks (${messageKey})`);
      reasons.add(`error_${messageKey}`); // Voeg een foutreden toe
    }
  }
}

/**
 * Voert middelzware checks uit (licht netwerk/CPU, DOM-analyse) op een URL.
 * Wordt alleen uitgevoerd als de statische checks al een basisrisico hebben gedetecteerd.
 * @param {string} url - De volledige URL.
 * @param {Set<string>} reasons - Set waarin reason-tags worden toegevoegd.
 * @param {{ value: number }} totalRiskRef - Object dat de cumulatieve risicoscore bijhoudt.
 */
async function checkDynamicConditionsPhase2(url, reasons, totalRiskRef) {
  const urlObj = new URL(url);
  const domainOnly = urlObj.hostname.toLowerCase();
  const tld = domainOnly.split('.').pop().toLowerCase();

  // Hergebruik de homoglyphMap en knownBrands
  const homoglyphMapEntries = globalConfig.HOMOGLYPHS || {};
  const homoglyphMap = {};
  for (const [latin, variants] of Object.entries(homoglyphMapEntries)) {
    // Voeg een controle toe om er zeker van te zijn dat variants een array is
    if (Array.isArray(variants)) {
        for (const g of variants) {
            homoglyphMap[g] = latin;
        }
    }
  }
  const knownBrands = Array.isArray(globalConfig.legitimateDomains)
    ? globalConfig.legitimateDomains.map(d => d.toLowerCase())
    : [];

  // De lijst met dynamische checks en hun aangepaste risicoscores
  const dynamicChecksPhase2 = [
    // --- 'Red Flag' Indicatoren ---
    {
      func: async () => {
        const localReasons = new Set();
        const attack = await isHomoglyphAttack(domainOnly, homoglyphMap, knownBrands, tld, localReasons);
        if (attack) {
          reasons.add('homoglyphAttack');
          // Voeg eventueel de specifiekere redenen van de aanval toe
          localReasons.forEach(r => reasons.add(r));
        }
        return attack;
      },
      messageKey: 'homoglyphAttack',
      risk: 10 // Blijft 10. Dit is een zeer sterke indicator.
    },
    { 
      func: () => isCryptoPhishingUrl(url), 
      messageKey: 'cryptoPhishing', 
      risk: 10.0 // Blijft 10. Crypto phishing is een hoog-risico categorie.
    },
    // --- Technische Indicatoren ---
    
    { 
      func: () => checkForSuspiciousExternalScripts(), 
      messageKey: 'suspiciousScripts', 
      risk: 5.0 // Was 4.0. De aanwezigheid van verdachte scripts is een belangrijk signaal.
    },
    { 
      func: () => hasSuspiciousIframes(), 
      messageKey: 'suspiciousIframes', 
      risk: 5.0 // Was 3.5. Hetzelfde als scripts; dit is een significant risico.
    },
    // --- Contextuele Indicatoren ---
    { 
      func: () => isFreeHostingDomain(url), 
      messageKey: 'freeHosting', 
      risk: 4 // Was 5. Verlaagd, maar blijft een belangrijke contextuele factor.
    },
    { 
      func: () => isShortenedUrl(url), 
      messageKey: 'shortenedUrl', 
      risk: 3.0 // Was 4.0. Verlaagd omdat legitiem gebruik veel voorkomt.
    },
    { 
      func: () => isDownloadPage(url), 
      messageKey: 'downloadPage', 
      risk: 3.0 // Was 3.5. Licht verlaagd.
    },
    { 
      func: () => hasSuspiciousUrlPattern(url), 
      messageKey: 'suspiciousPattern', 
      risk: 3.0 // Blijft 3.0. Een goede indicator voor ongebruikelijke URL-structuren.
    },
    { 
      func: () => hasSuspiciousQueryParameters(url), 
      messageKey: 'suspiciousParams', 
      risk: 2.0 // Was 2.5. Verlaagd, context is hier erg belangrijk.
    },
    { 
      func: () => hasMixedContent(url), 
      messageKey: 'mixedContent', 
      risk: 2.0 // Blijft 2.0.
    },
    { 
      func: () => hasSuspiciousKeywords(url), 
      messageKey: 'suspiciousKeywords', 
      risk: 1.5 // Was 2.0. Verlaagd, dit is een van de zwakste indicatoren.
    },
    { 
      func: () => usesUrlFragmentTrick(url), 
      messageKey: 'urlFragmentTrick', 
      risk: 1.0 // Was 2.0. Dit is een zeer zwakke indicator op zichzelf.
    }
  ];

  for (const { func, messageKey, risk } of dynamicChecksPhase2) {
    try {
      const result = await func();
      let triggered = false;
      let specificReasons = [];

      if (Array.isArray(result)) {
        // Functies die een array van redenen teruggeven (bijv. scripts/iframes)
        if (result.length > 0) {
          triggered = true;
          specificReasons = result;
        }
      } else {
        // Functies die een boolean teruggeven
        triggered = Boolean(result);
      }

      if (triggered) {
        if (specificReasons.length > 0) {
          specificReasons.forEach(r => reasons.add(r));
        } else {
          reasons.add(messageKey); // Voeg de algemene reden toe
        }
        totalRiskRef.value += risk;
        logDebug(`Fase 2: Toegevoegd ${messageKey} (risico ${risk}) voor ${url}. Huidig risico: ${totalRiskRef.value}`);
      }
    } catch (e) {
      handleError(e, `checkDynamicConditionsPhase2 (${messageKey})`);
      reasons.add(`error_${messageKey}`); // Voeg een foutreden toe
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
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 5000); // 5 seconden timeout
    const loginPatterns = globalConfig.LOGIN_PATTERNS || /(login|signin|authenticate)/i;
    if (loginPatterns.test(url)) {
      logDebug(`Login page detected based on URL pattern: ${url}`);
      return true;
    }
    const response = await fetch(url, { signal: controller.signal });
    clearTimeout(timeout);
    const html = await response.text();
    const hasPasswordField = /<input[^>]*type=["']?password["']?/i.test(html);
    if (hasPasswordField) {
      logDebug(`Login page detected based on content: ${url}`);
      return true;
    }
    logDebug(`No login page detected: ${url}`);
    return false;
  } catch (error) {
    handleError(error, `isLoginPageFromUrl: Fout bij controleren van loginpagina voor URL ${url}`);
    return false;
  }
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
    handleError(error, `constructResult: Fout bij construeren van resultaat met risico ${priorRisk}`);
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
        if (!isSafeParameter(key, value)) {
          return true;
        }
      }
    }
    return false;
  } catch (error) {
    handleError(error, `hasSuspiciousQueryParameters: Fout bij controleren van queryparameters voor URL ${url}`);
    return false; // Terugvallen op default false bij fout
  }
}

function hasMixedContent(url) {
  try {
    const urlObj = new URL(url);
    return urlObj.protocol === "https:" && urlObj.href.includes("http://");
  } catch (error) {
    handleError(error, `hasMixedContent: Fout bij controleren van gemengde inhoud voor URL ${url}`);
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

// Bovenaan in content.js, na de andere helperfuncties
const harmlessJsProtocols = [
  'javascript:void(0);',
  'javascript:void(0)',
  'javascript:;',
  'javascript:'
];

function hasJavascriptScheme(url) {
  // Haal de code achter 'javascript:' op en check op gevaarlijke calls
  const code = url.slice('javascript:'.length).trim();
  return /\b(eval|Function|document\.write|innerHTML=|location\.|window\.)\b/.test(code);
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
    
    const isIpAddress = /^(\d{1,3}\.){3}\d{1,3}$/.test(hostname);
    logDebug(`Is hostname an IP address? ${isIpAddress}`);
    if (isIpAddress) {
      logDebug(`Hostname is an IP address, returning false`);
      return false;
    }

    logDebug(`Splitting hostname into subdomains`);
    const subdomains = hostname.split('.').slice(0, -2);
    logDebug(`Subdomains: ${subdomains.join(', ')}`);
    const maxAllowedSubdomains = globalConfig.MAX_SUBDOMAINS || 3;
    const hasTooManySubdomains = subdomains.length > maxAllowedSubdomains;
    logDebug(`Number of subdomains: ${subdomains.length}, max allowed: ${maxAllowedSubdomains}, has too many: ${hasTooManySubdomains}`);
    return hasTooManySubdomains;
  } catch (error) {
    logDebug(`Error in hasMultipleSubdomains: ${error.message}`);
    handleError(error, "hasMultipleSubdomains");
    return false;
  }
}


// Definieer de cache buiten de functie om persistentie te garanderen
const shortenedUrlCache = new Map();


async function isShortenedUrl(url) {
  try {
    if (shortenedUrlCache.has(url)) {
      logDebug(`Cache hit voor URL: ${url}`);
      return shortenedUrlCache.get(url);
    }

    const shortenedDomains = globalConfig.SHORTENED_URL_DOMAINS;
    const domain = new URL(url).hostname.toLowerCase().replace(/^www\./, "");
    logDebug(`Checking domain ${domain} against SHORTENED_URL_DOMAINS: ${Array.from(shortenedDomains).join(', ')}`);

    const isShortened = shortenedDomains.has(domain);
    logDebug(`Shortener check for ${url}: ${isShortened ? 'Detected' : 'Not detected'}`);

    if (shortenedUrlCache.size >= MAX_CACHE_SIZE) {
      shortenedUrlCache.clear();
      logDebug("Cache limiet bereikt, cache gereset.");
    }
    shortenedUrlCache.set(url, isShortened);
    return isShortened;
  } catch (error) {
    handleError(error, `isShortenedUrl: Fout bij controleren van verkorte URL ${url}`);
    shortenedUrlCache.set(url, true); // Conservatief: assume shortened bij fout
    return true;
  }
}

async function resolveShortenedUrlWithRetry(url, retries = 3, delay = 1000) {
  for (let attempt = 1; attempt <= retries; attempt++) {
    try {
      const response = await fetch(url, {
        method: 'HEAD',
        redirect: 'follow',
        mode: 'no-cors', // Voorkom CORS-blokkering
      });
      return response.url || url; // Fallback naar originele URL als no-cors geen redirect geeft
    } catch (error) {
      if (attempt === retries) return url;
      await new Promise(resolve => setTimeout(resolve, delay));
    }
  }
  return url;
}

// ----------------------------------------------------
// AANGEPASTE hasEncodedCharacters FUNCTIE
// ----------------------------------------------------
function hasEncodedCharacters(url) {
    try {
        const urlObj = new URL(url);
        const path = urlObj.pathname;
        const query = urlObj.search;
        const encodedCharPattern = /%[0-9A-Fa-f]{2}/g;

        const pathEncodedMatches = path.match(encodedCharPattern) || [];
        const queryEncodedMatches = query.match(encodedCharPattern) || [];

        // Geen verdachtheid als de enige encoding spaties (%20) zijn in het pad
        // en er geen andere verdachte elementen zijn.
        // We willen alleen waarschuwen als het een complexere of ongebruikelijke encoding betreft.
        
        // Tel het aantal verschillende gecodeerde tekens.
        const uniqueEncodedChars = new Set([...pathEncodedMatches, ...queryEncodedMatches]);

        // Uitzondering: %20 (spatie) in het pad is vaak legitiem, vooral voor bestandsnamen
        if (uniqueEncodedChars.size === 1 && uniqueEncodedChars.has('%20') && pathEncodedMatches.length > 0 && queryEncodedMatches.length === 0) {
            logDebug(`Legitieme URL-encoding (%20) gedetecteerd in pad: ${url}`);
            return false;
        }

        // Als er meer dan één type encoding is, of als het in de query staat (potentieel verdachter)
        // of als het niet alleen %20 is, markeer het dan als verdacht.
        if (uniqueEncodedChars.size > 0) {
             // Controleer op dubbele encoding (bijv. %2520) - zeer verdacht
            if (/%25[0-9A-Fa-f]{2}/i.test(url)) {
                logDebug(`Dubbele URL-encoding gedetecteerd in ${url}`);
                return true;
            }

            // Controleer op lange, opeenvolgende reeksen van encoded tekens (kan obfuscation zijn)
            if (/%[0-9A-Fa-f]{2}(?:%[0-9A-Fa-f]{2}){5,}/i.test(url)) { // 6 of meer opvolgende encoded chars
                 logDebug(`Lange reeks encoded karakters gedetecteerd in ${url}`);
                 return true;
            }

            logDebug(`Verdachte URL-encoding gedetecteerd in ${url}: ${Array.from(uniqueEncodedChars).join(', ')}`);
            return true;
        }
        
        logDebug(`Geen verdachte URL-encoding gedetecteerd in ${url}`);
        return false;

    } catch (error) {
        handleError(error, `hasEncodedCharacters: Fout bij controleren van gecodeerde tekens voor URL ${url}`);
        return false; // Bij fout, val terug op 'niet verdacht'
    }
}
function hasBase64OrHex(url) {
  const base64Pattern = /^(?:[A-Za-z0-9+/]{4})*(?:[A-Za-z0-9+/]{2}==|[A-Za-z0-9+/]{3}=)?$/;
  const hexPattern = /\b[a-f0-9]{16,}\b/i; // Verhoogd naar 16 tekens voor Hex
  const minLengthThreshold = 12; // Strengere drempel
  const allowedProtocols = globalConfig?.ALLOWED_PROTOCOLS || ['https:', 'http:', 'ftp:'];

  try {
    const urlObj = new URL(url);
    const protocol = urlObj.protocol;

    // Skip niet-relevante protocollen
    if (!allowedProtocols.includes(protocol)) {
      logDebug(`Skipping Base64/Hex check for non-relevant protocol: ${url}`);
      return false;
    }

    const components = [
      urlObj.pathname.slice(1),
      urlObj.search.slice(1),
      urlObj.hash.slice(1),
    ].filter(Boolean);

    for (const component of components) {
      if (component.length < minLengthThreshold) continue;

      const segments = component.split(/[/?#&=]+/).filter(seg => seg.length >= minLengthThreshold);
      for (const segment of segments) {
        // Base64: vereis decodeerbare inhoud met verdachte kenmerken
        if (base64Pattern.test(segment)) {
          try {
            const decoded = atob(segment.replace(/=+$/, ''));
            const suspiciousContent = /script|eval|javascript|onload|onclick/i.test(decoded);
            if (suspiciousContent) {
              logDebug(`Valid Base64 with suspicious content detected in ${url}: ${segment} -> ${decoded}`);
              return true;
            }
          } catch (e) {
            logDebug(`Base64 matched but invalid decoding: ${segment} in ${url}`);
          }
        }

        // Hex: alleen lange reeksen met context
        const hexMatches = segment.match(hexPattern);
        if (hexMatches && hexMatches.some(match => match.length >= minLengthThreshold)) {
          const hasSuspiciousContext = /script|js|exec|load|data/i.test(component);
          if (hasSuspiciousContext) {
            logDebug(`Suspicious Hex detected in ${url}: ${hexMatches.join(', ')}`);
            return true;
          }
        }
      }
    }
    logDebug(`No suspicious Base64 or Hex detected in ${url}`);
    return false;
  } catch (error) {
    handleError(error, `hasBase64OrHex: Error checking Base64/Hex for URL ${url}`);
    return false;
  }
}

// Definieer de cache buiten de functie voor persistentie
const loginPageCache = new Map();
const LOGIN_CACHE_TTL_MS = 3600000; // 1 uur TTL

function detectLoginPage(url) {
  try {
    const cached = loginPageCache.get(url);
    const now = Date.now();
    if (cached && (now - cached.timestamp < LOGIN_CACHE_TTL_MS)) {
      logDebug(`Cache hit for login detection: ${url}`);
      return cached.result;
    }

    const loginPatterns = /(login|signin|wp-login|authenticate|account)/i;
    const urlIndicatesLogin = loginPatterns.test(url);
    const hasPasswordField = !!document.querySelector('input[type="password"]');
    logDebug(`Login detection for ${url}: URL indication: ${urlIndicatesLogin}, Password field: ${hasPasswordField}`);
    const result = urlIndicatesLogin || hasPasswordField;

    loginPageCache.set(url, { result, timestamp: now });
    logDebug(`Cached login detection result for ${url}: ${result}`);

    return result;
  } catch (error) {
    handleError(error, `detectLoginPage: Fout bij detecteren van loginpagina voor URL ${url}`);
    return false;
  }
}

// Optioneel: Periodieke cache-schoonmaak
setInterval(() => {
  const now = Date.now();
  for (const [url, { timestamp }] of loginPageCache) {
    if (now - timestamp >= LOGIN_CACHE_TTL_MS) {
      loginPageCache.delete(url);
      logDebug(`Removed expired login cache entry for ${url}`);
    }
  }
}, LOGIN_CACHE_TTL_MS);

/**
 * Controleert of een URL afkomstig is van een gratis-hostingdienst.
 *
 * @param {string} url   De volledige URL-string om te controleren.
 * @returns {Promise<boolean>}  true als de URL van gratis hosting lijkt, anders false.
 */
async function isFreeHostingDomain(url) {
  try {
    const parsedUrl = new URL(url);
    let domain = parsedUrl.hostname.toLowerCase();

    // Decode Punycode indien nodig
    if (domain.startsWith('xn--') && typeof punycode !== 'undefined' && punycode.toUnicode) {
      domain = punycode.toUnicode(domain);
      logDebug(`Checking free hosting voor gede­codeerd domein: ${domain}`);
    }

    // Splits hostname in labels
    const parts = domain.split('.');
    if (parts.length < 2) {
      // Geen geldig domein om verder te checken
      return false;
    }

    // Bepaal de TLD (laatste label) en SLD (voorlaatste label)
    const tld = parts[parts.length - 1];
    let sld = parts[parts.length - 2];

    // Haal globale lijst op (uit config.js)
    const freeHostingDomains = globalConfig.FREE_HOSTING_DOMAINS || [];

    // 1) Directe match of suffix-match: “domein” is exact in de lijst, of eindigt op “.entry”
    for (const entry of freeHostingDomains) {
      if (domain === entry || domain.endsWith('.' + entry)) {
        logDebug(`Gratis hosting gedetecteerd via directe suffix-match: ${entry}`);
        return true;
      }
    }

    // 2) Strip “-<cijfers>” achter SLD (bijv. “weebly-9” → “weebly”) en check opnieuw
    //    Dit dekt gevallen zoals “weebly-9.com” → “weebly.com”
    const strippedSld = sld.replace(/-\d+$/, '');
    const reconstructed = strippedSld + '.' + tld;
    if (freeHostingDomains.includes(reconstructed)) {
      logDebug(`Gratis hosting gedetecteerd via gestript SLD (“${sld}” → “${strippedSld}”): ${reconstructed}`);
      return true;
    }

    // 3) Verdachte trefwoorden in de volledige hostname (nu uitgebreid met bekende platform-namen)
    const suspiciousKeywords = [
      'free', 'webhost', 'cheap', 'hosting', 'tumblr', 'blogspot', 'blogger', 'weebly', 'wixsite'
    ];
    if (suspiciousKeywords.some(keyword => domain.includes(keyword))) {
      logDebug(`Verdacht hostingkeyword in ${domain}`);
      return true;
    }

    // 4) Meer dan één opeenvolgend koppelteken (soms duidt op auto-genereerde subdomeinen)
    if (/[-]{2,}/.test(domain)) {
      logDebug(`Meerdere opeenvolgende koppeltekens in ${domain}`);
      return true;
    }

    // 5) Een onderdeel (label) langer dan 25 tekens (kennelijk een gratis-hosting subdomein)
    if (parts.some(part => part.length > 25)) {
      logDebug(`Lang domeinonderdeel in ${domain}`);
      return true;
    }

    return false;
  } catch (error) {
    logError(`Fout bij free hosting-check voor ${url}: ${error.message}`);
    return false;
  }
}



/**
 * Checks the safety of a link upon user interaction (mouseover, click).
 * It calls the layered detection logic (`performSuspiciousChecks`) and manages visual warnings.
 *
 * @param {HTMLAnchorElement} link - The HTML anchor element being checked.
 * @param {string} eventType - The type of event ('mouseover', 'click', etc.).
 * @param {Event} event - The DOM event object.
 * @returns {Promise<{level: 'safe'|'caution'|'alert', risk: number, reasons: string[]}|void>}
 */
async function unifiedCheckLinkSafety(link, eventType, event) {
  // 1) Protection disabled?
  if (!(await isProtectionEnabled())) {
    logDebug('Protection disabled, skipping unifiedCheckLinkSafety');
    return;
  }

  // ───────────────────────────────────────────────────────────────────────
  // Step 1: Validate input and extract href
  // ───────────────────────────────────────────────────────────────────────
  let href;
  if (link && link.href) {
    // Handle SVGAnimatedString if the href comes from an SVG element
    href = link.href instanceof SVGAnimatedString ? link.href.baseVal : link.href;
  } else {
    logDebug(`Skipping unifiedCheckLinkSafety: Invalid or missing link or href: ${link?.href || 'undefined'}`);
    return;
  }

  // Basic URL validity check
  if (!isValidURL(href)) {
    logDebug(`Skipping unifiedCheckLinkSafety: Invalid URL in link: ${href}`);
    // Optionally, you could still warn the user about an invalid URL format
    warnLinkByLevel(link, { level: 'caution', risk: 1, reasons: ['invalidUrlFormat'] });
    return;
  }

  logDebug(`Checking URL in unifiedCheckLinkSafety: ${href}`);

  // ───────────────────────────────────────────────────────────────────────
  // Step 2: Deduplication (using window.processedLinks to avoid redundant checks)
  // ───────────────────────────────────────────────────────────────────────
  if (!window.processedLinks) {
    window.processedLinks = new Set();
  }
  // This deduplication is for the _immediate_ period to prevent rapid re-checking.
  // The `link.dataset.linkshieldWarned` flag handles persistent visual deduplication.
  if (window.processedLinks.has(href)) {
    logDebug(`Skipping duplicate unifiedCheckLinkSafety for ${href}`);
    // If already processed recently, just return the cached result if available.
    // Otherwise, we might still want to trigger warnLinkByLevel later if needed.
    return;
  }
  window.processedLinks.add(href);
  // Clear from recent cache after a short period (e.g., 2 seconds)
  setTimeout(() => window.processedLinks.delete(href), 2000);


  try {
    const urlObj = new URL(href);
    const hostname = urlObj.hostname;

    // Skip checks for internal IP addresses, .local, or localhost.
    const isInternalIp = (host) => {
      return (
        /^127\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host) ||
        /^192\.168\.\d{1,3}\.\d{1,3}$/.test(host) ||
        /^10\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(host) ||
        /^172\.(1[6-9]|2[0-9]|3[0-1])\.\d{1,3}\.\d{1,3}$/.test(host)
      );
    };
    if (isInternalIp(hostname) || hostname.endsWith(".local") || hostname === "localhost") {
      logDebug(`Internal server detected for ${hostname}. Skipping checks.`);
      return;
    }

    // ─────────────────────────────────────────────────────────────────────
    // Step 3: Perform the full, layered suspicious checks ONE time
    // This is the core logic now, replacing redundant checks in this function.
    // ─────────────────────────────────────────────────────────────────────
    const analysisResult = await performSuspiciousChecks(href);

    // ─────────────────────────────────────────────────────────────────────
    // Step 4: Apply visual warning based on analysis result
    // ─────────────────────────────────────────────────────────────────────
    warnLinkByLevel(link, analysisResult);

    
    // Return the analysis result for potential further use (e.g., caching in event handlers)
    return analysisResult;

  } catch (error) {
    handleError(error, `unifiedCheckLinkSafety: Error checking link ${href} on event ${eventType}`);
    // In case of an unexpected error, return a conservative 'caution' result
    const errorResult = { level: 'caution', risk: 5, reasons: ["unifiedCheckError"] };
    // And also ensure a visual warning is shown for the error
    warnLinkByLevel(link, errorResult);
    return errorResult;
  }
}




/**
 * Controleert of een URL wijst naar een mogelijke crypto-phishing site.
 *
 * @param {string} url  De volledige URL die gecontroleerd moet worden.
 * @returns {boolean}   True als het verdacht is voor crypto-phishing, anders false.
 */
function isCryptoPhishingUrl(url) {
  const officialDomains = (globalConfig && globalConfig.CRYPTO_DOMAINS) || [];
  // Haal van elk officieel domein alleen de merknaam (het eerste deel vóór de eerste punt)
  const cryptoBrands = officialDomains.map(domain => domain.split('.')[0].toLowerCase());
  const cryptoKeywords = [
    'crypto', 'bitcoin', 'btc', 'eth', 'ether', 'wallet', 'coin', 'token',
    'blockchain', 'ledger', 'exchange', 'airdrop'
  ];

  // Strengere patronen die een crypto-context vereisen (bijv. “secure-wallet”, “airdrop-crypto”)
  const suspiciousPatterns = [
    /^(?:secure|auth|verify|2fa|locked)-?(?:wallet|crypto|coin|exchange|token|account)$/i,
    /wallet[-_]?connect/i,
    /crypto[-_]?auth/i,
    /(?:free|earn|claim|bonus)[-_]?(?:crypto|bitcoin|btc|eth|coin)/i,
    /airdrop[-_]?(?:crypto|coin|token)/i,
    new RegExp(`(?:2fa|verify)[-_]?(?:${cryptoBrands.join('|')})`, 'i')
  ];

  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname.toLowerCase();
    const fullPath = (hostname + urlObj.pathname).toLowerCase();

    // 1) Controleer of het een officieel domein is (exact of subdomein)
    if (officialDomains.some(domain => hostname === domain || hostname.endsWith(`.${domain}`))) {
      logDebug(`Safe: Official crypto domain detected (${hostname})`);
      return false;
    }

    // 2) Controleer op “lookalike” (afstand ≤ 3) met een van de officiële domeinen
    const isLookalike = officialDomains.some(domain => {
      const brand = domain.split('.')[0];
      const distance = levenshteinDistance(hostname, domain);
      return hostname.includes(brand) && hostname !== domain && distance <= 3;
    });
    if (isLookalike) {
      logDebug(`Suspicious: Lookalike crypto domain detected (${hostname})`);
      return true;
    }

    // 3) Controleer of het merk (“coinbase”, “binance”, etc.) voorkomt in de hostname, met extra cijfers/tekens 
    //    Dit dekt gevallen zoals “fakecoinbase-46.com” of “binance123.net”
    for (const brand of cryptoBrands) {
      // Bouw een regex: merknaam gevolgd door een scheidingsteken of cijfers
      const brandPattern = new RegExp(`${brand}(?:[.-]?\\d+)`, 'i');
      if (brandPattern.test(hostname)) {
        logDebug(`Suspicious: Brand + digits detected in hostname (${hostname}) matches brand ${brand}`);
        return true;
      }
    }

    // 4) Controleer op crypto-specifieke patronen EN keywords in pad/hostnaam
    const hasCryptoKeyword = cryptoKeywords.some(keyword => fullPath.includes(keyword));
    const matchesPattern = suspiciousPatterns.some(pattern => pattern.test(fullPath));
    if (matchesPattern && hasCryptoKeyword) {
      logDebug(`Suspicious: Crypto phishing pattern detected in (${fullPath})`);
      return true;
    }

    logDebug(`Safe: No crypto phishing characteristics found (${hostname})`);
    return false;
  } catch (error) {
    handleError(error, `isCryptoPhishingUrl: Error checking crypto phishing for URL ${url}`);
    // Conservatieve fallback bij ongeldige URL
    return false;
  }
}



function hasMetaRedirect() {
  const metaTag = document.querySelector("meta[http-equiv='refresh']");
  return Boolean(metaTag && /^\s*\d+\s*;\s*url=/i.test(metaTag.getAttribute("content")));
}


function markAsDetected(el) {
  el.classList.add('linkshield-detected');
}


function checkControl(el) {
  const tag = el.tagName.toUpperCase();
  const role = el.getAttribute('role');
  const href = el.getAttribute('href');
  const type = el.getAttribute('type');

  const isClickable =
    href?.startsWith('http') ||
    typeof el.onclick === 'function' ||
    tag === 'BUTTON' ||
    (tag === 'INPUT' && type === 'submit') ||
    role === 'button';

  if (isClickable) {
    el.classList.add('linkshield-detected');
    logDebug('✅ Element herkend als interactief:', el);
  }
}






document.addEventListener('DOMContentLoaded', async () => {
  try {
    logDebug("🚀 Initializing content script...");
    await initContentScript(); // Wacht op configuratie en veilige domeinen

    const currentUrl = window.location.href;
    logDebug(`🔍 Checking the current page: ${currentUrl}`);

    // --- 1. Pagina-brede checks ---
    const reasonsForPage = new Set();
    let pageRisk = 0;

    // 1a. Mixed content iframes
    if (window.location.protocol === 'https:') {
      const iframes = Array.from(document.getElementsByTagName('iframe')).filter(f => f.src);
      for (const iframe of iframes) {
        try {
          const u = new URL(iframe.src);
          if (u.protocol === 'http:') {
            reasonsForPage.add('mixedContentIframe');
            pageRisk += 10;
            logDebug(`⚠️ Mixed content iframe: ${iframe.src}`);
            break;
          }
        } catch (e) {
          logError(`Fout bij mixed-content check iframe: ${iframe.src}`, e);
        }
      }
    }

    // 1b. Verdachte iframes
    const suspiciousIframes = await hasSuspiciousIframes();
    if (suspiciousIframes.length) {
      // we voegen alleen de raw reason toe, zonder 'iframe:'-prefix
      suspiciousIframes.forEach(r => reasonsForPage.add(r));
      pageRisk += 5.0;
      logDebug(`⚠️ Verdachte iframes: ${suspiciousIframes.join(', ')}`);
    }

    // 1c. Verdachte scripts
    const suspiciousScripts = await checkForSuspiciousExternalScripts();
    if (suspiciousScripts.length) {
      // we voegen alleen de raw reason toe, zonder 'script:'-prefix
      suspiciousScripts.forEach(r => reasonsForPage.add(r));
      pageRisk += 5.0;
      logDebug(`⚠️ Verdachte scripts: ${suspiciousScripts.join(', ')}`);
    }

    // 1d. Loginpagina-checks
    if (detectLoginPage(currentUrl)) {
      logDebug(`🔐 Loginpagina gedetecteerd: ${currentUrl}`);
      try {
        const u = new URL(currentUrl);
        let dom = u.hostname.toLowerCase();
        if (dom.startsWith('xn--') && typeof punycode !== 'undefined') {
          dom = punycode.toUnicode(dom);
        }
        const mx = await queueMxCheck(dom);
        if (!mx.length) {
          reasonsForPage.add('loginPageNoMX');
          pageRisk += 12;
          logDebug(`⚠️ Geen MX-records voor loginpagina: ${dom}`);
        }
      } catch (e) {
        handleError(e, 'Loginpagina MX-check mislukt');
      }
      if (new URL(currentUrl).protocol !== 'https:') {
        reasonsForPage.add('insecureLoginPage');
        pageRisk += 15;
        logDebug(`⚠️ Loginpagina niet via HTTPS: ${currentUrl}`);
      }
    }

    // 1e. Interactieve controls (visueel, geen berichten)
    const initialControls = detectInteractiveControls();
    logDebug(`[UI] ${initialControls.length} interactieve elementen gevonden`);
    startDynamicDetection(controls => {
      controls.forEach(el => {
        if (el.tagName === 'A' && el.href) classifyAndCheckLink(el);
      });
    });

    // --- 2. URL-specifieke checks ---
    const urlResult = await performSuspiciousChecks(currentUrl);

    // --- 3. Combineer alle redenen en bereken totaalrisico ---
    const allReasons = new Set([
      ...urlResult.reasons,
      ...reasonsForPage
    ]);
    const totalRisk = parseFloat(urlResult.risk) + pageRisk;

    // --- 4. Bepaal eindniveau ---
    let finalLevel;
    if (totalRisk >= globalConfig.HIGH_THRESHOLD) {
      finalLevel = 'alert';
    } else if (totalRisk >= globalConfig.LOW_THRESHOLD) {
      finalLevel = 'caution';
    } else {
      finalLevel = 'safe';
    }

    // --- 5. ÉÉN bericht sturen naar background.js ---
    chrome.runtime.sendMessage({
      action: 'checkResult',
      url: currentUrl,
      level: finalLevel,
      isSafe: finalLevel === 'safe',
      risk: totalRisk.toFixed(1),
      reasons: Array.from(allReasons)
    });
    logDebug(`✅ Check compleet: level=${finalLevel}, risk=${totalRisk.toFixed(1)}, reasons=${Array.from(allReasons).join(', ')}`);

    // --- 6. Externe links scannen (zonder extra berichten) ---
    await checkLinks();

  } catch (error) {
    handleError(error, `DOMContentLoaded unified`);
    chrome.runtime.sendMessage({
      action: 'checkResult',
      url: window.location.href,
      level: 'alert',
      isSafe: false,
      risk: 99,
      reasons: ['initializationError']
    });
  }
});







// 1) checkLinks stuurt nu géén berichten meer, maar returned alleen of er verdachte externe links zijn
async function checkLinks() {
  if (isSearchResultPage()) {
    logDebug("Zoekresultatenpagina gedetecteerd, linkcontrole wordt overgeslagen.");
    return false;
  }

  const currentUrl = window.location.href;
  let currentDomain;
  try {
    currentDomain = new URL(currentUrl).hostname.toLowerCase();
    logDebug(`Hoofddomein van de pagina: ${currentDomain}`);
  } catch (error) {
    logError(`Kon hoofddomein niet bepalen uit ${currentUrl}:`, error);
    return false;
  }

  const MAX_LINKS_TO_SCAN = 500;
  const allAnchors = Array.from(document.querySelectorAll('a'));
  const links = allAnchors
    .filter(link => link.href && isValidURL(link.href) && !scannedLinks.has(link.href))
    .slice(0, MAX_LINKS_TO_SCAN);

  if (links.length === 0) {
    logDebug("Geen nieuwe links om te controleren.");
    return false;
  }

  const checks = links.map(async link => {
    const href = link.href;
    scannedLinks.add(href);

    let urlObj;
    try {
      urlObj = new URL(href);
    } catch {
      return false;
    }

    const domain = urlObj.hostname.toLowerCase();
    if (isSameDomain(domain, currentDomain)) return false;

    const result = await performSuspiciousChecks(href);
    if (result.level !== 'safe') {
      warnLinkByLevel(link, result);
      logDebug(`Verdachte externe link: ${href} → level=${result.level}`);
      return true;
    }
    return false;
  });

  const results = await Promise.all(checks);
  return results.some(r => r === true);
}


// 2) checkCurrentUrl stuurt nu precies één bericht, incl. de uitkomst van checkLinks()
let lastCheckedUrl = null;

async function checkCurrentUrl() {
  await ensureConfigReady();

  try {
    const currentUrl = window.location.href;
    if (currentUrl === lastCheckedUrl) return;
    lastCheckedUrl = currentUrl;
    logDebug("[Content] URL changed to:", currentUrl);

    // Volg meta-refresh of echte redirects
    const metaRefresh = getMetaRefreshUrl();
    const finalUrl = metaRefresh
      ? (logDebug("[Content] Meta-refresh URL:", metaRefresh), metaRefresh)
      : await getFinalUrl(currentUrl);
    logDebug("[Content] Final URL after redirects:", finalUrl);

    // 1) Paginacheck
    const pageResult = await performSuspiciousChecks(finalUrl);
    logDebug("[Content] Page check result:", pageResult);

    // Valideer level
    let level = pageResult.level;
    if (!['safe', 'caution', 'alert'].includes(level)) {
      logError(`[checkCurrentUrl] Ongeldig level "${level}", fallback naar "safe".`);
      level = 'safe';
    }

    // 2) Externe links
    const hasBadLinks = await checkLinks();
    if (hasBadLinks && level === 'safe') {
      level = 'caution';
      logDebug("[Content] Externe links verdacht, level opgehoogd naar 'caution'");
    }

    // 3) ÉÉN bericht sturen naar background.js
    chrome.runtime.sendMessage({
      action: 'checkResult',
      url: finalUrl,
      level,
      isSafe: level === 'safe',
      risk: pageResult.risk,
      reasons: pageResult.reasons
    });
    logDebug(`✅ checkCurrentUrl complete: level=${level}, risk=${pageResult.risk}, reasons=${pageResult.reasons.join(', ')}`);

  } catch (err) {
    handleError(err, "checkCurrentUrl");
    chrome.runtime.sendMessage({
      action: 'checkResult',
      url: window.location.href,
      level: 'alert',
      isSafe: false,
      risk: 99,
      reasons: ['checkCurrentUrlError', err.message]
    });
  }
}






// Helperfunctie om te controleren of domeinen hetzelfde zijn (inclusief subdomeinen)
function isSameDomain(linkDomain, currentDomain) {
  return linkDomain === currentDomain || linkDomain.endsWith(`.${currentDomain}`);
}

// Eenvoudige URL-validatie
function isValidURL(url) {
  try {
    new URL(url);
    return true;
  } catch {
    return false;
  }
}

// In de initialisatie wordt checkLinks() alleen aangeroepen als we niet op een Google-zoekpagina zitten
getStoredSettings().then(settings => {
  if (settings.integratedProtection && !isSearchResultPage()) {
    checkLinks();
  }
});
function injectWarningStyles() {
  if (document.head.querySelector("#linkshield-warning-styles")) {
    logDebug("Warning styles already present, skipping.");
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


(async function init() {
  try {
    // Extra initialisatiecode (indien nodig)
  } catch (error) {
    handleError(error, `init: Fout bij algemene initialisatie`);
  }
})();



const observer = new MutationObserver(debounce(async (mutations) => {
  if (!(await isProtectionEnabled())) return; // Stop als bescherming uitstaat

  let scriptsAdded = false;
  let iframesAdded = false;
  let linksAdded = false;

  mutations.forEach(mutation => {
    mutation.addedNodes.forEach(node => {
      // Alleen element-nodes zijn relevant
      if (node.nodeType !== Node.ELEMENT_NODE) return;

      // Detecteer toegevoegde scripts en iframes
      if (node.tagName === "SCRIPT" && node.src) {
        scriptsAdded = true;
      } else if (node.tagName === "IFRAME" && node.src) {
        iframesAdded = true;
      }

      // Detecteer links die zijn toegevoegd
      // Directe <a> tags
      if (node.tagName === "A" && isValidURL(node.href)) {
        linksAdded = true;
        classifyAndCheckLink(node); // Controleer direct de nieuwe link
      } else {
        // Links binnen nieuw toegevoegde elementen (bijv. een nieuwe div met links erin)
        node.querySelectorAll('a').forEach(link => {
          if (isValidURL(link.href)) {
            linksAdded = true;
            classifyAndCheckLink(link); // Controleer direct de nieuwe link
          }
        });
      }
    });
  });

  // Als er scripts of iframes zijn toegevoegd, hercontroleer de paginabrede status.
  // We roepen de paginabrede logica die al in DOMContentLoaded staat opnieuw aan.
  if (scriptsAdded || iframesAdded) {
    logDebug("Dynamische content gedetecteerd (scripts/iframes). Hercontroleer paginabrede risico's.");
    // Roep de paginabrede controleroutine aan die nu in DOMContentLoaded staat.
    // Dit is een simpele aanroep; de details van het verzamelen en verzenden liggen daar.
    // Let op: 'window.location.href' wordt hier gebruikt, omdat we de huidige pagina opnieuw evalueren.
    const currentUrl = window.location.href;
    
    const reasonsForPageUpdate = new Set();
    let pageRiskUpdate = 0;

    // Hercontroleer mixed content iframes
    if (window.location.protocol === 'https:') {
      const iframes = Array.from(document.getElementsByTagName('iframe')).filter(i => i.src);
      for (const iframe of iframes) {
        try {
          const iframeUrlObj = new URL(iframe.src);
          if (iframeUrlObj.protocol === 'http:') {
            reasonsForPageUpdate.add('mixedContent');
            pageRiskUpdate += 10;
            break;
          }
        } catch (e) { /* Negeer foute URLs */ }
      }
    }

    // Hercontroleer verdachte iframes
    const suspiciousIframesReasons = await hasSuspiciousIframes();
    if (suspiciousIframesReasons.length > 0) {
        suspiciousIframesReasons.forEach(reason => reasonsForPageUpdate.add(reason));
        pageRiskUpdate += 3.5; // Risicopunt voor de aanwezigheid van verdachte iframes
    }

    // Hercontroleer verdachte externe scripts
    const suspiciousScriptReasons = await checkForSuspiciousExternalScripts();
    if (suspiciousScriptReasons.length > 0) {
        suspiciousScriptReasons.forEach(reason => reasonsForPageUpdate.add(reason));
        pageRiskUpdate += 4.0; // Risicopunt voor de aanwezigheid van verdachte scripts
    }

    // Stuur een update-bericht naar het achtergrondscript voor de paginastatus
    chrome.runtime.sendMessage({
      type: "updatePageStatus", // Nieuw type bericht voor paginastatus updates
      url: currentUrl,
      reasons: Array.from(reasonsForPageUpdate),
      risk: pageRiskUpdate
    });
  }

  // Specifieke afhandeling voor Google zoekresultaten
  if (linksAdded && isSearchResultPage()) {
    debounceCheckGoogleSearchResults();
  }
}, 500)); // Debounce om te voorkomen dat het te vaak afvuurt

observer.observe(document.documentElement, { childList: true, subtree: true });

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


/**
 * Extraheert de top-level domein (TLD) uit een hostname, inclusief samengestelde TLD's (bijv. .co.uk).
 * @param {string} hostname  De hostname (bijv. www.example.co.uk).
 * @returns {string}         De TLD (bijv. co.uk, com).
 */
function extractTld(hostname) {
  if (!hostname || typeof hostname !== 'string') {
    logDebug(`extractTld: Invalid hostname: ${hostname}`);
    return '';
  }

  // Lijst van bekende samengestelde TLD's (vereenvoudigd)
  const compoundTlds = [
    'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'com.au', 'org.au',
    'co.jp', 'go.jp', 'ne.jp', 'or.jp', 'co.kr', 're.kr',
    'co.nz', 'org.nz', 'gov.br', 'com.br', 'org.br',
  ];

  // Splits hostname in onderdelen
  const parts = hostname.toLowerCase().split('.');

  // Controleer op samengestelde TLD's (bijv. .co.uk)
  if (parts.length >= 3) {
    const potentialCompound = parts.slice(-2).join('.');
    if (compoundTlds.includes(potentialCompound)) {
      return potentialCompound;
    }
  }

  // Gebruik de laatste onderdeel als TLD als geen samengestelde TLD wordt gevonden
  return parts.length > 1 ? parts[parts.length - 1] : '';
}

function checkGoogleSearchResults() {
  logDebug("Checking search results...");

  // Specifieke selector voor organische resultaten
  const results = document.querySelectorAll('#search .yuRUbf > a');

  results.forEach(link => {
    if (checkedLinks.has(link)) return;

    const href = link.getAttribute('href');
    // Sla Google-redirects en zoek-pagina-links over
    if (!href || href.startsWith('/url?') || href.includes('google.com/search')) return;

    // Valideer met URL API
    try {
      new URL(href);
    } catch {
      return;
    }

    // Plan de phishing/SSL-check in idle-time
    if ('requestIdleCallback' in window) {
      requestIdleCallback(() => {
        classifyAndCheckLink(link);
        checkedLinks.add(link);
      }, { timeout: 2000 });
    } else {
      setTimeout(() => {
        classifyAndCheckLink(link);
        checkedLinks.add(link);
      }, 0);
    }
  });
}



chrome.runtime.onMessage.addListener((message, sender, sendResponse) => {
  if (message.action === 'testURL') {
    performSuspiciousChecks(message.url)
      .then((result) => {
        sendResponse({ isSafe: result.isSafe, reasons: result.reasons, risk: result.risk });
      })
      .catch((error) => {
        handleError(error, `chrome.runtime.onMessage: Fout bij testen van URL ${message.url}`);
        sendResponse({ isSafe: false, reasons: ["An error occurred."], risk: 0 });
      });
    return true;
  }
});
