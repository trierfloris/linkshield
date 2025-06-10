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
  if (typeof cfg.DEBUG_MODE !== 'boolean') {
    cfg.DEBUG_MODE = false;
  }
  if (typeof cfg.RISK_THRESHOLD !== 'number' || cfg.RISK_THRESHOLD < 0) {
    cfg.RISK_THRESHOLD = 5;
  }
  if (typeof cfg.MAX_SUBDOMAINS !== 'number' || cfg.MAX_SUBDOMAINS < 0) {
    cfg.MAX_SUBDOMAINS = 3;
  }
  if (typeof cfg.CACHE_DURATION_MS !== 'number' || cfg.CACHE_DURATION_MS <= 0) {
    cfg.CACHE_DURATION_MS = 24 * 60 * 60 * 1000;
  }
  if (typeof cfg.SUSPICION_THRESHOLD !== 'number' || cfg.SUSPICION_THRESHOLD < 0 || cfg.SUSPICION_THRESHOLD > 1) {
    cfg.SUSPICION_THRESHOLD = 0.1;
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

  // SUSPICIOUS_EMAIL_PATTERNS
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

  // SUSPICIOUS_SCRIPT_PATTERNS
  if (
    !Array.isArray(cfg.SUSPICIOUS_SCRIPT_PATTERNS) ||
    cfg.SUSPICIOUS_SCRIPT_PATTERNS.some(entry => !(entry.regex instanceof RegExp))
  ) {
    const scriptPatterns = [
      {
        pattern: '(?:\\beval\\s*\\(\\s*[\'"].*[\'"][^)]*\\)|new\\s+Function\\s*\\(\\s*[\'"].*[\'"][^)]*\\)|base64_decode\\s*\\()',
        weight: 8,
        description: 'Dangerous eval of Function met strings'
      },
      {
        pattern: '(?:coinimp|cryptonight|webminer|miner\\.js|crypto-jacking|keylogger|trojan|worm|ransomware|xss\\s*\\()',
        weight: 10,
        description: 'Expliciete malware-termen'
      },
      {
        pattern: '(?:document\\.write\\s*\\(\\s*[\'"][^\'"]*javascript:|innerHTML\\s*=\\s*[\'"][^\'"]*eval)',
        weight: 7,
        description: 'Verdachte DOM-manipulatie'
      },
      {
        pattern: '(?:fetch\\(.+\\.wasm[^)]*eval|import\\(.+\\.wasm[^)]*javascript:)',
        weight: 6,
        description: 'WebAssembly-misbruik'
      },
      {
        pattern: '(?:malicious|phish|exploit|redirect|inject|clickjacking|backdoor|rootkit)',
        weight: 9,
        description: 'Malware- of phishing-termen'
      },
      {
        pattern: '(?:RTCPeerConnection\\s*\\(\\s*{[^}]*stun:|RTCDataChannel\\s*.\\s*send\\s*\\(\\s*[\'"][^\'"]*eval)',
        weight: 6,
        description: 'WebRTC-aanvallen'
      }
    ];
    cfg.SUSPICIOUS_SCRIPT_PATTERNS = scriptPatterns.map(({ pattern, weight, description }) => {
      try {
        return { regex: new RegExp(pattern, 'i'), weight, description };
      } catch (err) {
        logError(`Ongeldig RegExp-patroon voor SUSPICIOUS_SCRIPT_PATTERNS (“${pattern}”): ${err.message}`);
        return { regex: safeRegex(), weight, description };
      }
    });
  }

  // SUSPICIOUS_TLDS
  if (!(cfg.SUSPICIOUS_TLDS instanceof RegExp)) {
    try {
      cfg.SUSPICIOUS_TLDS = new RegExp(
        '\\.(academy|accountant|accountants|agency|ap|app|art|asia|auto|bank|bar|beauty|bet|bid|bio|biz|blog|buzz|cam|capital|casa|casino|cfd|charity|cheap|church|city|claims|click|club|company|crispsalt|cyou|data|date|design|dev|digital|directory|download|email|energy|estate|events|exchange|expert|exposed|express|finance|fit|forsale|foundation|fun|games|gle|goog|gq|guide|guru|health|help|home|host|html|icu|ink|institute|investments|ip|jobs|life|limited|link|live|loan|lol|ltd|ly|mall|market|me|media|men|ml|mom|money|monster|mov|network|one|online|page|partners|party|php|pics|play|press|pro|promo|pw|quest|racing|rest|review|rocks|run|sbs|school|science|services|shop|shopping|site|software|solutions|space|store|stream|support|team|tech|tickets|to|today|tools|top|trade|trading|uno|ventures|vip|website|wiki|win|work|world|xin|xyz|zip|zone|co|cc|tv|name|team|live|stream|quest|sbs)$',
        'i'
      );
    } catch (err) {
      logError(`Ongeldig RegExp-patroon voor SUSPICIOUS_TLDS: ${err.message}`);
      cfg.SUSPICIOUS_TLDS = safeRegex();
    }
  }

  // SUSPICIOUS_URL_PATTERNS
  if (
    !Array.isArray(cfg.SUSPICIOUS_URL_PATTERNS) ||
    cfg.SUSPICIOUS_URL_PATTERNS.some(p => !(p instanceof RegExp))
  ) {
    const patterns = [
      '\\/(payment|invoice|billing|money|bank|secure|login|checkout|subscription|refund|delivery)\\/',
      '(Base64|hexadecimal|b64|encode|urlencode|obfuscate|crypt)',
      '\\/(signup|register|confirmation|securepayment|order|tracking|verify-account|reset-password|oauth)\\/',
      '(?:\\bsecurepay\\b|\\baccountverify\\b|\\bresetpassword\\b|\\bverifyemail\\b|\\bupdateinfo\\b)',
      '(qr-code|qrcode|qr\\.|generate-qr|scan|qrserver|qrcodes\\.)',
      '(fake|clone|spoof|impersonate|fraud|scam|phish)',
      '[^a-zA-Z0-9]{2,}',
      '(http[s]?:\\/\\/[^\\/]+){2,}',
      '(qr-code|qrcode|qr\\.|generate-qr|scan)'
    ];

    cfg.SUSPICIOUS_URL_PATTERNS = patterns.map(pat => {
      try {
        return new RegExp(pat, 'i');
      } catch (err) {
        logError(`Ongeldig RegExp-patroon voor SUSPICIOUS_URL_PATTERNS (“${pat}”): ${err.message}`);
        return safeRegex();
      }
    }).filter(re => re instanceof RegExp);

    if (cfg.SUSPICIOUS_URL_PATTERNS.length === 0) {
      cfg.SUSPICIOUS_URL_PATTERNS = [safeRegex()];
    }
  }

  // TYPOSQUATTING_PATTERNS
  if (
    !Array.isArray(cfg.TYPOSQUATTING_PATTERNS) ||
    cfg.TYPOSQUATTING_PATTERNS.some(p => !(p instanceof RegExp))
  ) {
    cfg.TYPOSQUATTING_PATTERNS = [
      /g00gle/i,
      /paypa1/i,
      /micr0soft/i,
      /[0o][0o]/i,
      /1n/i,
      /vv/i,
      /rn$/i
    ];
  }
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
          let merged = { ...defaultConfig, ...window.CONFIG };
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
        let stored = await new Promise((resolve, reject) => {
          chrome.storage.sync.get('CONFIG', (items) => {
            if (chrome.runtime.lastError) {
              reject(new Error(chrome.runtime.lastError.message));
            } else {
              resolve(items.CONFIG);
            }
          });
        });

        if (stored && typeof stored === 'object' && !Array.isArray(stored)) {
          let merged = { ...defaultConfig, ...stored };
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

let lastCheckedUrl = null;

async function checkCurrentUrl() {
  await ensureConfigReady()
   try {
    const currentUrl = window.location.href;
    if (currentUrl !== lastCheckedUrl) {
      lastCheckedUrl = currentUrl;
      logDebug("[Content] URL changed to:", currentUrl);

      // Controleer op meta-refresh URL
      const metaRefreshUrl = getMetaRefreshUrl();
      let finalUrl;

      if (metaRefreshUrl) {
        finalUrl = metaRefreshUrl;
        logDebug("[Content] Meta-refresh URL detected:", finalUrl);
      } else {
        // Haal de uiteindelijke URL op na HTTP-redirects
        finalUrl = await getFinalUrl(currentUrl);
        logDebug("[Content] Final URL after redirects:", finalUrl);
      }

      // Voer de check uit op de uiteindelijke URL
      const result = await performSuspiciousChecks(finalUrl);
      logDebug("[Content] Check result:", result);
      logDebug("Analysis result:", result);

      chrome.runtime.sendMessage({
        type: "checkResult",
        isSafe: result.isSafe,
        risk: result.risk,
        reasons: result.reasons,
        url: finalUrl // Gebruik de uiteindelijke URL in het bericht
      });
    }
  } catch (error) {
    handleError(error, "checkCurrentUrl");
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

function levenshteinDistance(a, b) {
  if (a.length === 0) return b.length;
  if (b.length === 0) return a.length;

  const matrix = [];

  for (let i = 0; i <= b.length; i++) {
    matrix[i] = [i];
  }

  for (let j = 0; j <= a.length; j++) {
    matrix[0][j] = j;
  }

  for (let i = 1; i <= b.length; i++) {
    for (let j = 1; j <= a.length; j++) {
      if (b[i - 1] === a[j - 1]) {
        matrix[i][j] = matrix[i - 1][j - 1];
      } else {
        matrix[i][j] = 1 + Math.min(matrix[i - 1][j], matrix[i][j - 1], matrix[i - 1][j - 1]);
      }
    }
  }

  return matrix[b.length][a.length];
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
  const observer = new MutationObserver(async (mutations) => {
    // Debounced call naar checkForSuspiciousExternalScripts
    await checkForSuspiciousExternalScripts();

    mutations.forEach(mutation => {
      mutation.addedNodes.forEach(node => {
        if (node.nodeType !== Node.ELEMENT_NODE) return;
        const newLinks = node.querySelectorAll('a');
        newLinks.forEach(link => {
          if (isValidURL(link.href)) classifyAndCheckLink(link);
        });
      });
    });
  });
  observer.observe(searchContainer, { childList: true, subtree: true });
  debounceCheckGoogleSearchResults();
  injectWarningIconStyles();
}

function debounceCheckGoogleSearchResults() {
  clearTimeout(debounceTimer);
  debounceTimer = setTimeout(checkGoogleSearchResults, 250);
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

  // Definieer homoglyphMap en knownBrands
  const homoglyphMap = globalConfig.HOMOGLYPHS || DEFAULT_HOMOGLYPHS;
  const knownBrands = globalConfig.legitimateDomains || ['microsoft.com', 'apple.com', 'google.com'];

  const checks = [
    { func: () => /^(crypto|coins|wallet|exchange|ico|airdrop)/i.test(domain),    score: 5, messageKey: "cryptoPhishingAd" },
    { func: () => /adclick|gclid|utm_source/i.test(sanitizeInput(urlObj.search)), score: 2, messageKey: "suspiciousAdStructure" },
    { func: () => globalConfig.SUSPICIOUS_TLDS.test(domain),                      score: 3, messageKey: "suspiciousAdTLD" },
    { func: async () => await isHomoglyphAttack(domain, homoglyphMap, knownBrands), score: 4, messageKey: "homoglyphAdAttack" },
    { func: () => /^(amazon|google|microsoft|paypal)/i.test(domain),               score: 5, messageKey: "brandMisuse" }
  ];

  try {
    const results = [];
    for (const check of checks) {
      const condition = await check.func();
      if (condition) {
        results.push({ score: check.score, messageKey: check.messageKey });
      }
    }

    const totalRiskScore  = results.reduce((sum, r) => sum + r.score, 0);
    const specificReasons = results.map(r => r.messageKey);

    if (specificReasons.length > 0) {
      await warnLink(link, specificReasons);
      const warningIcon = document.createElement("span");
      warningIcon.className = "phishing-warning-icon";
      warningIcon.textContent = "⚠️";
      warningIcon.style = "position: relative; top: 0; left: 5px; color: #ff0000;";
      link.insertAdjacentElement("afterend", warningIcon);
      link.style.border = "2px solid #ff0000";
      link.style.color = "#ff0000";
      link.title = chrome.i18n.getMessage("alertMessage") +
                   "\n" +
                   specificReasons
                     .map(key => chrome.i18n.getMessage(key))
                     .join("\n");
    }
  } catch (error) {
    handleError(error, `checkForPhishingAds: Fout bij controleren van link ${link.href}`);
    await warnLink(link, ["fileCheckFailed"]);
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


async function warnLink(link, reasons) {
    await ensureConfigReady();
    if (!link || !link.href || !isValidURL(link.href)) {
        logDebug("Invalid link provided to warnLink:", link);
        return;
    }

    const url = link.href;
    const hostname = new URL(url).hostname;

    // We gebruiken `warnedDomainsInline` om te voorkomen dat we TE VEEL meldingen krijgen
    // voor hetzelfde type probleem op dezelfde pagina, maar we willen wel elk unieke link markeren.
    // De check die `warnedDomainsInline` gebruikt, moet alleen de *melding* voorkomen, niet het icoon.
    // Dit betekent dat de `warnLink` functie ALTIJD een icoon moet proberen toe te voegen als de link onveilig is,
    // en `warnedDomainsInline` is meer voor de notificaties die via `chrome.runtime.sendMessage` gaan.

    // Voor nu: we gaan ervan uit dat `warnLink` wordt aangeroepen wanneer we een VISUELE markering willen.
    // We kunnen hier een simpele `link.dataset.linkshieldWarned = true;` toevoegen om te voorkomen
    // dat we meerdere iconen aan DEZELFDE LINK toevoegen, zonder te rommelen met domeinnamen.
    if (link.dataset.linkshieldWarned) {
        logDebug(`⚠️ Link (${url}) is al visueel gemarkeerd. Overslaan.`);
        return;
    }


    const riskResult = await performSuspiciousChecks(url);
    const isHighRisk = riskResult.risk >= (globalConfig.RISK_THRESHOLD || 5);

    // Verwijder eventuele oude iconen, dit is nog steeds nuttig bij dynamische updates
    const existingIcon = link.querySelector('.phishing-warning-icon'); // Zoek binnen de link
    if (existingIcon) {
        logDebug(`[warnLink] Removing existing icon inside link for ${url}`);
        existingIcon.remove();
    }
    link.style.border = ''; // Verwijder eerdere styling
    link.style.color = '';

    if (!isHighRisk && riskResult.reasons.length === 0) {
        logDebug(`[warnLink] Link ${url} is safe or not high risk, no icon needed.`);
        return;
    }

    // Toon de introductiebanner
    const introMessage = chrome.i18n.getMessage("introBannerMessage") || "LinkShield is actief en markeert verdachte links met ⚠️. Beweeg de muis over het icoon om te zien waarom een link verdacht is.";
    showIntroBannerOnce(introMessage);


    const warningIcon = document.createElement('span');
    warningIcon.className = 'phishing-warning-icon';
    warningIcon.textContent = '⚠️';

    const translatedReasons = riskResult.reasons.map(reason => {
        const key = reason.replace(/[:\.]/g, '_');
        const msg = chrome.i18n.getMessage(key);
        return msg || reason;
    }).join('\n');

    const tooltipText = `${chrome.i18n.getMessage("reasonLabel") || "Waarom?"}:\n${translatedReasons}`;
    logDebug(`[warnLink] Tooltip text:`, tooltipText);

    warningIcon.title = tooltipText; // Tooltip op het icoon
    link.title = tooltipText; // Tooltip op de link zelf (voor betere toegankelijkheid)

    if (isHighRisk) {
        warningIcon.className += ' high-risk-warning';
        link.className += ' high-risk-link';
    } else {
        warningIcon.className += ' moderate-warning';
        link.className += ' moderate-risk-link';
    }

    logDebug(`[warnLink] Attempting to append icon inside link for: ${url}. Link element:`, link);
    try {
        // Kernwijziging: Voeg het icoon TOE AAN het link-element, in plaats van ernaast.
        link.appendChild(warningIcon);
        link.dataset.linkshieldWarned = 'true'; // Markeer dit element om dubbele iconen te voorkomen
        logDebug(`[warnLink] Successfully appended icon inside link for ${url}. Link content:`, link.innerHTML);
    } catch (e) {
        logError(`[warnLink] Failed to append icon inside link for ${url}: ${e.message}`, e);
        // Fallback: Als toevoegen aan de link mislukt (bijv. door SVG of specifieke DOM-beperkingen)
        // val terug op de styling van de link zelf.
        link.classList.add(isHighRisk ? 'high-risk-link-fallback' : 'moderate-risk-link-fallback');
        logDebug(`[warnLink] Applied fallback styling to link element for ${url}.`);
    }

    injectWarningIconStyles(); // Zorgt dat de CSS-regels in de DOM zijn
}

// Set om bij te houden welke domeinen al een waarschuwing hebben gekregen op deze pagina
const warnedDomainsInline = new Set();

async function warnLink(link, reasons) {
  await ensureConfigReady();
  if (!link || !link.href || !isValidURL(link.href)) {
    logDebug("Invalid link provided to warnLink:", link);
    return;
  }

  const url = link.href;
  const hostname = new URL(url).hostname;

  // Toon slechts één waarschuwing per domein per pagina
  if (warnedDomainsInline.has(hostname)) {
    logDebug(`⚠️ Waarschuwing voor ${hostname} is al getoond op deze pagina. Overslaan.`);
    return;
  }
  warnedDomainsInline.add(hostname);

  const riskResult = await performSuspiciousChecks(url);
  const isHighRisk = riskResult.risk >= (globalConfig.RISK_THRESHOLD || 5);

  // Verwijder eventuele oude icoontjes
  const existingIcon = link.nextElementSibling;
  if (existingIcon && existingIcon.classList.contains('phishing-warning-icon')) {
    existingIcon.remove();
  }
  link.style.border = '';
  link.style.color = '';

  if (!isHighRisk && riskResult.reasons.length === 0) {
    return; // niets tonen als veilig
  }

  // --- Integratie van showIntroBannerOnce ---
  // Toon de introductiebanner wanneer een link voor het eerst als verdacht wordt gemarkeerd.
  // Zorg ervoor dat 'introBannerMessage' is gedefinieerd in je messages.json voor i18n.
  const introMessage = chrome.i18n.getMessage("introBannerMessage") || "LinkShield is actief en markeert verdachte links met ⚠️. Beweeg de muis over het icoon om te zien waarom een link verdacht is.";
  await showIntroBannerOnce(introMessage);
  // --- Einde integratie ---

  const warningIcon = document.createElement('span');
  warningIcon.className = 'phishing-warning-icon';
  warningIcon.textContent = '⚠️';

  // **HIER** doen we de omzetting naar underscores:
  const translatedReasons = riskResult.reasons.map(reason => {
    // zet telkens ":" en "." om naar "_"
    const key = reason.replace(/[:\.]/g, '_');
    const msg = chrome.i18n.getMessage(key);
    // fallback: als er geen vertaling is, laat gewoon de originele reason zien (snel debuggen)
    return msg || reason;
  }).join('\n');

  const tooltipText = `${chrome.i18n.getMessage("reasonLabel") || "Waarom?"}:\n${translatedReasons}`;
  logDebug(`[warnLink] Tooltip text:`, tooltipText);

  warningIcon.title = tooltipText;
  link.title = tooltipText;

  if (isHighRisk) {
    warningIcon.className += ' high-risk-warning';
    link.className += ' high-risk-link';
  } else {
    warningIcon.className += ' moderate-warning';
    link.className += ' moderate-risk-link';
  }

  logDebug(`[warnLink] Marking external link as suspicious: ${url}, Risk: ${riskResult.risk}, Translated Reasons:`, translatedReasons);
  link.insertAdjacentElement('afterend', warningIcon);
  injectWarningIconStyles();
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



async function analyzeDomainAndUrl(link) {
  await ensureConfigReady();
  // Log de input voor debugging
  logDebug(`Analyzing link with href: ${link.href}, Type: ${typeof link.href}, Instance: ${link.href instanceof SVGAnimatedString ? 'SVGAnimatedString' : 'Other'}`);
  
  if (!link || !link.href || !isValidURL(link.href)) {
    logDebug(`Skipping analysis: Invalid or missing URL in link: ${link.href || 'undefined'}`);
    return; // Skip processing if the URL is invalid
  }

  try {
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
        await warnLink(link, result.reasons, primaryReason);
      }
    }
  } catch (error) {
    // Controleer expliciet of de fout een TypeError is en handel het af
    if (error instanceof TypeError && error.message.includes('Failed to construct \'URL\'')) {
      handleError(error, `analyzeDomainAndUrl: Ongeldige URL (mogelijk SVGAniatedString) in link ${link.href || 'undefined'}`);
    } else {
      handleError(error, `analyzeDomainAndUrl: Fout bij analyseren van URL ${link.href || 'undefined'}`);
    }
    return; // Skip verdere verwerking bij een ongeldige URL
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

    // ✅ Trusted domain check
    const fullHostname = urlObj.hostname; // login.mailchimp.com
const isTrusted = safeDomains.some(pattern => {
  try {
    const regex = new RegExp(pattern);
    return regex.test(fullHostname);
  } catch (e) {
    return false;
  }
});


    // ✅ Extract subdomain (bijv. 'login' in login.mailchimp.com)
    const domainParts = domain.split(".");
    const subdomain = domainParts.length > 2 ? domainParts.slice(0, -2).join(".") : "";

    // 1. HTTPS-controle
    if (urlObj.protocol !== 'https:') {
      addRisk(15, "noHttps", "high");
      if (document.readyState !== 'complete') {
        await new Promise(resolve => document.addEventListener('DOMContentLoaded', resolve, { once: true }));
      }
      if (isLoginPage(url)) {
        addRisk(20, "insecureLoginPage", "high");
      }
    }

    // 2. Phishing-trefwoorden
    if (urlParts.some(word => globalConfig.PHISHING_KEYWORDS.has(word))) {
      addRisk(10, "suspiciousKeywords", "high");
    }

    // ✅ 2b. BrandKeyword subdomein check (alleen als niet trusted)
    if (!isTrusted && /^(login|secure|auth|signin|verify|portal|account|access)\b/i.test(subdomain)) {
      addRisk(5, `brandKeyword:${subdomain}`, "medium");
    }

    // 3. Download-trefwoorden
    if (urlParts.some(word => globalConfig.DOWNLOAD_KEYWORDS.has(word))) {
      addRisk(8, "downloadKeyword", "medium");
    }

    // 4. Verdachte bestandsextensies
    if (ext && globalConfig.MALWARE_EXTENSIONS.test(ext[0])) {
      addRisk(12, "malwareExtension", "high");
    }

    // 5. IP-adres als domeinnaam
    if (/^(?:https?:\/\/)?(\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:\/|$)/.test(url)) {
      addRisk(12, "ipAsDomain", "high");
      if (urlObj.port && !["80", "443"].includes(urlObj.port)) {
        addRisk(6, "unusualPort", "high");
      }
    }

    // 6. Verkorte URL
    if (globalConfig.SHORTENED_URL_DOMAINS.has(domain)) {
      addRisk(6, "shortenedUrl", "medium");
      try {
        const response = await fetch(url, { method: 'HEAD', redirect: 'follow' });
        const finalUrl = response.url;
        if (finalUrl && finalUrl !== url) {
          addRisk(10, "redirectedShortenedUrl", "medium");
        }
      } catch (error) {
        addRisk(5, "shortenedUrlError", "low");
        handleError(error, `calculateRiskScore: Kon verkorte URL ${url} niet oplossen`);
      }
    }

    // 7. Verdachte TLD's
    if (globalConfig.SUSPICIOUS_TLDS.test(domain)) {
      addRisk(15, "suspiciousTLD", "high");
    }

    // 8. Ongewoon lange URL's
    if (url.length > maxLength) {
      addRisk(8, "urlFragmentTrick", "medium");
    }

    // 9. Gecodeerde tekens
    if (/%[0-9A-Fa-f]{2}/.test(url)) {
      addRisk(6, "encodedCharacters", "medium");
    }

    // 10. Te veel subdomeinen
    if (domain.split(".").length > 3) {
      addRisk(5, "tooManySubdomains", "medium");
    }

    // 11. Base64 of hexadecimale strings
    if (/^(javascript|data):/.test(url) || /[a-f0-9]{32,}/.test(url)) {
      addRisk(12, "base64OrHex", "high");
    }

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

function hasSuspiciousIframes() {
  const iframes = Array.from(document.getElementsByTagName('iframe')).filter(iframe => iframe.src);
  const detectedReasonStrings = new Set(); // Gebruik een Set om dubbele redenen te voorkomen
  const trustedDomains = globalConfig?.TRUSTED_IFRAME_DOMAINS || ['youtube.com', 'vimeo.com', 'google.com'];

  for (const iframe of iframes) {
    const src = iframe.src;
    if (!src) continue;

    try {
      const urlObj = new URL(src);
      const hostname = urlObj.hostname.toLowerCase();
      const protocol = urlObj.protocol;

      // Skip vertrouwde domeinen
      if (trustedDomains.some(domain => hostname === domain || hostname.endsWith(`.${domain}`))) {
        logDebug(`Safe iframe detected: ${src}`); // Debugging-log voor veilige iframes blijft handig
        continue;
      }

      // 1. Controle op verdachte trefwoorden (NIEUW - vereist SUSPICIOUS_IFRAME_KEYWORDS in globalConfig)
      // Voeg dit alleen toe als het een RegExp is, anders kan het crashen.
      if (globalConfig?.SUSPICIOUS_IFRAME_KEYWORDS instanceof RegExp && globalConfig.SUSPICIOUS_IFRAME_KEYWORDS.test(src)) {
        detectedReasonStrings.add('suspiciousIframeKeyword');
        logDebug(`Suspicious iframe (suspicious keyword): ${src}`);
      }

      // 2. Mixed content detectie
      // De browser blokkeert dit sowieso, maar we willen het detecteren voor rapportage
      if (protocol === 'http:' && window.location.protocol === 'https:') {
        detectedReasonStrings.add('mixedContent');
        logDebug(`Suspicious iframe (mixed content): ${src}`);
      }

      // 3. Verdachte TLD's
      if (globalConfig?.SUSPICIOUS_TLDS instanceof RegExp && globalConfig.SUSPICIOUS_TLDS.test(hostname)) {
        detectedReasonStrings.add('suspiciousTLD');
        logDebug(`Suspicious iframe (suspicious TLD): ${src}`);
      }

      // 4. Verborgen iframes (en met verdachte attributen)
      const style = window.getComputedStyle(iframe);
      const isHidden = style.display === 'none' || style.visibility === 'hidden' ||
                       (parseInt(style.width) === 0 && parseInt(style.height) === 0);
      const hasSuspiciousAttributes = iframe.hasAttribute('onload') ||
                                      iframe.hasAttribute('onerror') ||
                                      iframe.src.startsWith('javascript:');

      if (isHidden && hasSuspiciousAttributes) {
        detectedReasonStrings.add('iframeHidden');
        logDebug(`Suspicious iframe (hidden with suspicious attributes): ${src}`);
      }

    } catch (error) {
      detectedReasonStrings.add('invalidIframeSrc'); // Voeg een generieke reden toe voor fouten
      logError(`hasSuspiciousIframes: Error analyzing iframe ${src}: ${error.message}`);
    }
  }

  // logDebug(`Suspicious iframes detected (raw reasons): ${Array.from(detectedReasonStrings).join(', ')}`);
  return Array.from(detectedReasonStrings); // Retourneer de array met unieke reden-strings
}


async function checkForSuspiciousExternalScripts() {
  const MAX_SCRIPTS_TO_CHECK = 20; // Beperk tot 20 scripts om prestaties te verbeteren
  const scripts = Array.from(document.getElementsByTagName('script'))
    .filter(script => script.src)
    .slice(0, MAX_SCRIPTS_TO_CHECK);

  // Gebruik een Set om unieke reden-strings te verzamelen
  const detectedReasonStrings = new Set();

  // Laad vertrouwde domeinen uit trustedScripts.json en combineer met config
  let trustedDomains = [];
  try {
    trustedDomains = await fetchCachedJson('trustedScripts.json');
    if (!Array.isArray(trustedDomains)) {
      logDebug('trustedScripts.json is geen array, gebruik lege lijst');
      trustedDomains = [];
    } else {
      trustedDomains = [...new Set(trustedDomains.filter(domain =>
        typeof domain === 'string' && /^[a-zA-Z0-9.-]+$/.test(domain) && domain.includes('.')
      ))];
    }
  } catch (error) {
    handleError(error, 'checkForSuspiciousExternalScripts: Fout bij laden trustedScripts.json');
    trustedDomains = [];
  }

  // Combineer JSON-domeinen met uitgebreide TRUSTED_SCRIPTS uit globalConfig
  const trustedScripts = new Set([
    ...(globalConfig?.TRUSTED_SCRIPTS || [
      'googleapis.com',
      'cloudflare.com',
      'cdnjs.cloudflare.com',
      'jsdelivr.net',
      'unpkg.com',
      'code.jquery.com',
      'bootstrapcdn.com',
      'ajax.googleapis.com',
      'static.cloudflareinsights.com',
      'polyfill.io',
      'googletagmanager.com',
      'analytics.google.com',
    ]),
    ...trustedDomains,
  ]);

  const freeHostingDomains = new Set(
    (globalConfig?.FREE_HOSTING_DOMAINS || []).filter(domain => !trustedScripts.has(domain))
  );
  const modernTlds = ['app', 'dev', 'tech', 'io', 'cloud'];

  for (const script of scripts) {
    const src = script.src;
    if (!src) continue;

    let riskScoreForThisScript = 0; // Lokale risicoscore voor dit specifieke script

    try {
      const urlObj = new URL(src);
      const hostname = urlObj.hostname.toLowerCase();
      const protocol = urlObj.protocol;

      // Sla vertrouwde scripts, educatieve, non-profit en overheidsdomeinen over
      if (
        trustedScripts.has(hostname) ||
        Array.from(trustedScripts).some((domain) => hostname === domain || hostname.endsWith(`.${domain}`)) ||
        hostname.endsWith('.edu') ||
        hostname.endsWith('.org') ||
        hostname.endsWith('.gov')
      ) {
        logDebug(`Veilig script gedetecteerd: ${src} (vertrouwd domein)`);
        continue;
      }

      // Controleer scriptattributen (defer/async/module, minder risico)
      const isDeferred = script.hasAttribute('defer') || script.hasAttribute('async');
      const isTypeModule = script.getAttribute('type') === 'module';
      if (isDeferred || isTypeModule) {
        logDebug(`Veilig script gedetecteerd: ${src} (defer/async/module)`);
        continue;
      }

      // Controleer scriptgrootte (kleine scripts overslaan)
      let isSmallScript = false;
      try {
        const headResponse = await fetch(src, { method: 'HEAD' });
        const contentLength = headResponse.headers.get('content-length');
        if (contentLength && parseInt(contentLength, 10) < 2048) {
          logDebug(`Klein script gedetecteerd (<2KB): ${src}`);
          isSmallScript = true;
        }
      } catch (headError) {
        logDebug(`Kon scriptgrootte niet ophalen voor ${src}: ${headError.message}`);
      }

      if (isSmallScript) {
        logDebug(`Analyse overgeslagen voor klein script: ${src}`);
        continue;
      }

      // Prioriteer niet-CDN paden (verlaag risico)
      if (/cdn|static|assets|lib|vendor/i.test(src)) {
        logDebug(`Script lijkt CDN-inhoud: ${src}, lagere prioriteit`);
        riskScoreForThisScript -= 2; // Verlaag risicoscore voor waarschijnlijke CDN’s
      }

      // Mixed content detectie (voor dit specifieke script)
      if (protocol === 'http:' && window.location.protocol === 'https:') {
        detectedReasonStrings.add('mixedContent');
        riskScoreForThisScript += 6; // Draag bij aan de lokale risicoscore voor dit script
        logDebug(`Verdacht script (mixed content): ${src}`);
      }

      // Verdachte TLD’s (voor dit specifieke script)
      const tld = hostname.split('.').pop();
      if (
        globalConfig?.SUSPICIOUS_TLDS instanceof RegExp &&
        globalConfig.SUSPICIOUS_TLDS.test(hostname) &&
        !trustedScripts.has(hostname) &&
        !modernTlds.includes(tld)
      ) {
        detectedReasonStrings.add('suspiciousTLD');
        riskScoreForThisScript += 2;
        logDebug(`Verdacht script (verdachte TLD): ${src}`);
      }

      // IP-adressen (voor dit specifieke script)
      if (/^\d+\.\d+\.\d+\.\d+$/.test(hostname)) {
        detectedReasonStrings.add('ipAsDomain');
        riskScoreForThisScript += 3;
        logDebug(`Verdacht script (IP als domein): ${src}`);
      }

      // Gratis hosting (voor dit specifieke script)
      if (freeHostingDomains.has(hostname) && !/cdn|static|assets/i.test(src)) {
        detectedReasonStrings.add('freeHosting');
        riskScoreForThisScript += 2;
        logDebug(`Verdacht script (gratis hosting): ${src}`);
      }

      // Controleer scriptinhoud
      const contentResult = await analyzeScriptContent(urlObj);
      if (contentResult.isSuspicious) {
        detectedReasonStrings.add('suspiciousScriptContent'); // Voeg de algemene reden toe
        riskScoreForThisScript += contentResult.totalWeight / 2; // Schaal gewicht naar risicoscore
        logDebug(`Verdacht script (inhoudsanalyse): ${src}, Gewicht: ${contentResult.totalWeight}, Patronen: ${contentResult.matchedPatterns.join(', ')}`);
      }

      // Als het script significant verdacht is (boven drempel), log het dan
      // De uiteindelijke totale 'pageRisk' wordt in DOMContentLoaded berekend.
      if (riskScoreForThisScript >= 8) {
        logDebug(`Verdacht script (individueel) gedetecteerd: ${src}, Score: ${riskScoreForThisScript}`);
        // Let op: Verwijder de chrome.runtime.sendMessage hier, dit wordt door DOMContentLoaded afgehandeld
      } else {
        logDebug(`Script ${src} onder verdenkingsdrempel: ${riskScoreForThisScript}`);
      }

    } catch (error) {
      logError(`checkForSuspiciousExternalScripts: Fout bij analyseren script ${src}: ${error.message}`);
      // Voeg een generieke foutreden toe als er een probleem is bij het analyseren van een script
      detectedReasonStrings.add('scriptAnalysisError');
    }
  }

  logDebug(`Verdachte externe scripts gedetecteerd (Totaal redenen): ${Array.from(detectedReasonStrings).join(', ')}`);
  return Array.from(detectedReasonStrings); // Retourneer een array van unieke reden-strings
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

        // 2) VERKORTE URL-CHECK
        const shortenedUrlDomains = new Set(globalConfig.SHORTENED_URL_DOMAINS || [
            'bit.ly','is.gd','tinyurl.com','goo.gl','t.co','ow.ly',
            'shorturl.at','rb.gy','adf.ly','bc.vc','cutt.ly','lnk.to',
            'rebrand.ly','shorte.st','s.id','tiny.cc','v.gd','zpr.io',
            'clk.sh','soo.gd','u.to','x.co','1url.com','bl.ink',
            'clicky.me','dub.sh','kutt.it','lc.cx','linktr.ee','short.io',
            't.ly','tr.im','urlz.fr','vzturl.com','yourls.org',
            'zi.ma','qr.ae'
        ]);
        if (shortenedUrlDomains.has(cleanHostname)) {
            logDebug(`Verkorte URL gedetecteerd: ${cleanHostname}`);
            reasons.add('shortenedUrl');
            return true;
        }

        // 3) WHITELIST-EXACT MATCH (op basis van Unicode-codepoints)
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

        // 4) SUBDOMEINEN-CHECK
        // Correcte berekening van subdomeinen, rekening houdend met compound TLDs.
        const tldParts = tld.split('.');
        const actualSubCount = cleanHostname.split('.').length - (tldParts.length + 1); // +1 voor het SLD
        if (actualSubCount > (globalConfig.MAX_SUBDOMAINS || 3)) {
            logDebug(`Te veel subdomeinen in ${cleanHostname}: ${actualSubCount}`);
            reasons.add('tooManySubdomains');
        }

        // 5) PUNYCODE-DECODING
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

        // 6) DIAKRITICA-STRIPPING
        // Dit is een standaard Unicode normalisatie stap.
        const strippedDomain = decodedDomain
            .normalize('NFD') // Normaliseert naar decomposed form (bijv. 'ö' -> 'o' + diacritisch teken)
            .replace(/\p{Diacritic}/gu, '') // Verwijdert alle diakritische tekens
            .normalize('NFC'); // Normaliseert terug naar canonical form
        logDebug(`Diacritics stripped: ${decodedDomain} → ${strippedDomain}`);

        // 7) GEMENGDE SCRIPTS-CHECK
        const scripts = getUnicodeScripts(strippedDomain); // Deze functie moet Unicode scripts identificeren
        const accentFriendlyTlds = ['fr','de','es','it']; // TLDs waar gemengde scripts minder verdacht zijn
        if (scripts.size > 1 && !accentFriendlyTlds.includes(tld.toLowerCase())) {
            logDebug(`Gemengde scripts in ${strippedDomain}: ${[...scripts].join(',')}`);
            reasons.add('mixedScripts');
        }

        // 8) SKELETON-NORMALISATIE (Kern van de homoglyph-detectie)
        // Gebruik de `normalizeToLatinBase` functie die de `globalHomoglyphReverseMap` gebruikt.
        const skeletonDomain = normalizeToLatinBase(strippedDomain, reverseMap);
        logDebug(`Skeleton domain: ${strippedDomain} → ${skeletonDomain}`);

        // 9) SUSPICIOUS PUNYCODE-NA NORMALISATIE
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

        // 10) EXTRACT MAIN DOMAIN (altijd op basis van skeletonDomain voor vergelijkingen)
        const mainDomain = extractMainDomain(skeletonDomain);
        logDebug(`Main domain for Levenshtein: ${skeletonDomain} → ${mainDomain}`);

        // 11) ACCENT-VRIENDELIJKE TLD? (voor logging, geen risico-add)
        if (
            tld && accentFriendlyTlds.includes(tld.toLowerCase()) &&
            scripts.size === 1 && scripts.has('Latin')
        ) {
            logDebug(`Accent-TLD ${tld} met alleen Latin; minder verdacht.`);
        }

        // 12) DIGIT-TYPOSQUATTING (specifiekere check)
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


        // 13) ALGEMENE TYPOSQUATTING-PATRONEN
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

        // 14) GENERIEKE LEVENSHTEIN-CHECK (op geskeletoniseerde hoofddomein)
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

        // 15) EINDOORDEEL: Retourneer true als er enige reden is gevonden.
        return reasons.size > 0;

    } catch (error) {
        logError(`isHomoglyphAttack error voor ${domain}: ${error.message}`);
        return false; // Bij een fout, retourneer false om overblokkering te voorkomen.
    }
}






/**
 * Bepaalt de Unicode-script voor een gegeven codepoint.
 * @param {number} codePoint  Het Unicode-codepoint van een teken.
 * @returns {string|null}     De scriptnaam (bijv. 'Latin', 'Cyrillic') of null als onbekend.
 */
function getScriptForCodePoint(codePoint) {
  if (!Number.isInteger(codePoint) || codePoint < 0) {
    return null;
  }

  // Unicode-script ranges (vereenvoudigd)
  if (codePoint >= 0x0000 && codePoint <= 0x007F) return 'Latin'; // Basic Latin
  if (codePoint >= 0x0080 && codePoint <= 0x00FF) return 'Latin'; // Latin-1 Supplement
  if (codePoint >= 0x0100 && codePoint <= 0x017F) return 'Latin'; // Latin Extended-A
  if (codePoint >= 0x0180 && codePoint <= 0x024F) return 'Latin'; // Latin Extended-B
  if (codePoint >= 0x0400 && codePoint <= 0x04FF) return 'Cyrillic';
  if (codePoint >= 0x2000 && codePoint <= 0x206F) return 'Common'; // General Punctuation
  if (codePoint >= 0x3000 && codePoint <= 0x303F) return 'Common'; // CJK Symbols and Punctuation

  return null; // Onbekende scripts
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
 * Bepaalt de Unicode-script voor een codepoint (vereenvoudigde implementatie).
 * @param {number} codePoint - De Unicode-codepoint.
 * @returns {string|null} - De scriptnaam of null.
 */
function getScriptForCodePoint(codePoint) {
  // Uitgebreidere mapping gebaseerd op Unicode-scriptcategorieën
  if (codePoint >= 0x0000 && codePoint <= 0x007F) return 'Latin'; // Basis Latijn (ASCII)
  if (codePoint >= 0x00A0 && codePoint <= 0x02FF) return 'Latin'; // Latijnse uitbreidingen (incl. é, Ñ)
  if (codePoint >= 0x0370 && codePoint <= 0x03FF) return 'Greek'; // Grieks
  if (codePoint >= 0x0400 && codePoint <= 0x04FF) return 'Cyrillic'; // Cyrillisch (incl. о)
  if (codePoint >= 0x0530 && codePoint <= 0x058F) return 'Armenian'; // Armeens
  if (codePoint >= 0x0600 && codePoint <= 0x06FF) return 'Arabic'; // Arabisch
  if (codePoint >= 0x4E00 && codePoint <= 0x9FFF) return 'Han'; // Chinees
  if (codePoint >= 0x3040 && codePoint <= 0x309F) return 'Hiragana'; // Japans Hiragana
  if (codePoint >= 0x30A0 && codePoint <= 0x30FF) return 'Katakana'; // Japans Katakana
  if (codePoint === 0x200B || codePoint === 0x200C || codePoint === 0x200D) return 'Common'; // Zero-width karakters
  return 'Unknown'; // Onbekende scripts worden gemarkeerd voor debugging
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
 * Voert een reeks checks uit op een URL en retourneert { isSafe, reasons, risk }.
 *
 * @param {string} url
 * @returns {Promise<{isSafe: boolean, reasons: string[], risk: number}>}
 */
async function performSuspiciousChecks(url) {
  try {
    await ensureConfigReady();

    const cachedEntry = window.linkRiskCache.get(url);
    if (cachedEntry && Date.now() - cachedEntry.timestamp < CACHE_TTL_MS) {
      logDebug(`Cache hit voor verdachte controles: ${url}`);
      return cachedEntry.result;
    }

    const isEnabled = await isProtectionEnabled();
    if (!isEnabled) {
      const fallback = { isSafe: true, reasons: [], risk: 0 };
      window.linkRiskCache.set(url, { result: fallback, timestamp: Date.now() });
      return fallback;
    }

    const reasonsSet = new Set();
    const totalRiskRef = { value: 0 }; // Gebruik een object om de waarde via referentie te wijzigen
    let urlObj;

    if (!url || typeof url !== 'string' || url.trim() === '') {
      logDebug(`Overslaan verdachte controles voor ongeldige URL: ${url || 'undefined'}`);
      const fallback = { isSafe: true, reasons: ['invalidUrl'], risk: 0 };
      window.linkRiskCache.set(url, { result: fallback, timestamp: Date.now() });
      return fallback;
    }

    try {
      urlObj = new URL(url, window.location.href);
    } catch (err) {
      logError(`Ongeldige URL: ${url}`, err);
      const fallback = { isSafe: true, reasons: ['invalidUrl'], risk: 0 };
      window.linkRiskCache.set(url, { result: fallback, timestamp: Date.now() });
      return fallback;
    }

    const nonHttpProtocols = ['mailto:', 'tel:', 'ftp:', 'javascript:'];
    if (nonHttpProtocols.includes(urlObj.protocol)) {
      logDebug(`Niet-HTTP protocol gedetecteerd: ${urlObj.protocol}`);
      if (['mailto:', 'tel:', 'ftp:'].includes(urlObj.protocol)) {
        reasonsSet.add('allowedProtocol');
        totalRiskRef.value = 0.1;
      } else if (urlObj.protocol === 'javascript:') {
        reasonsSet.add('javascriptScheme');
        totalRiskRef.value += 5;
      }
      const result = {
        isSafe: totalRiskRef.value < (globalConfig.RISK_THRESHOLD || 5),
        reasons: Array.from(reasonsSet),
        risk: totalRiskRef.value,
      };
      window.linkRiskCache.set(url, { result, timestamp: Date.now() });
      return result;
    }

    if (urlObj.protocol === 'file:') {
      logDebug(`File protocol gedetecteerd, minimale controles uitvoeren: ${url}`);
      const result = { isSafe: true, reasons: ['fileProtocol'], risk: 0 };
      window.linkRiskCache.set(url, { result, timestamp: Date.now() });
      return result;
    }

    if (!urlObj.hostname || urlObj.href === urlObj.protocol + '//') {
      logDebug(`Overslaan verdachte controles voor URL met ongeldige hostname: ${url}`);
      const result = { isSafe: true, reasons: ['invalidHostname'], risk: 0 };
      window.linkRiskCache.set(url, { result, timestamp: Date.now() });
      return result;
    }

    let domain = urlObj.hostname.toLowerCase();
    let decodedDomain = domain;
    if (domain.startsWith('xn--') && typeof punycode !== 'undefined' && punycode.toUnicode) {
      try {
        logDebug(`Raw Punycode: ${domain}`);
        decodedDomain = punycode.toUnicode(domain);
        logDebug(
          `Gedecodeerd domein: ${decodedDomain} (codepoints: ${[...decodedDomain]
            .map((c) => c.codePointAt(0).toString(16))
            .join(', ')})`
        );
      } catch (e) {
        logError(`Kon Punycode niet decoderen voor ${domain}: ${e.message}`);
      }
    } else if (domain.startsWith('xn--')) {
      logDebug(`Punycode decodering overgeslagen voor ${domain}: punycode bibliotheek niet beschikbaar`);
    }

    let normalizedDomain = '';
    if (decodedDomain) {
      try {
        normalizedDomain = normalizeDomain(`https://${decodedDomain}`);
      } catch (e) {
        logError(`Fout bij normaliseren van domein ${decodedDomain}: ${e.message}`);
        const fallback = { isSafe: true, reasons: ['invalidDomain'], risk: 0 };
        window.linkRiskCache.set(url, { result: fallback, timestamp: Date.now() });
        return fallback;
      }
    }

    const allSafeDomains = new Set([
      ...(window.trustedDomains || []),
      ...(globalConfig.legitimateDomains || [])
    ].map(d => {
      return d.toLowerCase().replace(/\\\./g, '.').replace(/\$$/, '').replace(/^www\./, '');
    }));

    const domainToCheck = urlObj.hostname.toLowerCase().replace(/^www\./, '');
    const decodedDomainToCheck = decodedDomain.toLowerCase().replace(/^www\./, '');

    const isWhitelisted = Array.from(allSafeDomains).some(safeDomain =>
      domainToCheck === safeDomain || domainToCheck.endsWith(`.${safeDomain}`) ||
      decodedDomainToCheck === safeDomain || decodedDomainToCheck.endsWith(`.${safeDomain}`)
    );

    if (isWhitelisted) {
      logDebug(`Static: ✅ Domein ${urlObj.hostname} is expliciet veilig (whitelist). Skip verdere checks.`);
      const result = { isSafe: true, reasons: ['safeDomain'], risk: 0 };
      window.linkRiskCache.set(url, { result, timestamp: Date.now() });
      return result;
    }

    const isHttpProtocol = ['http:', 'https:'].includes(urlObj.protocol);

    // Voeg meteen 'noHttps' toe bij HTTP‐pagina's
    if (urlObj.protocol === 'http:') {
      reasonsSet.add('noHttps');
      totalRiskRef.value += 15;
    }

    const homoglyphMap = {};
    for (const [latin, glyphs] of Object.entries(globalConfig.HOMOGLYPHS || {})) {
      for (const g of glyphs) {
        homoglyphMap[g] = latin;
      }
    }
    logDebug('Homoglyph map gebouwd:', Object.keys(homoglyphMap));

    const knownBrands = globalConfig.legitimateDomains || [];

    const tld = decodedDomain.split('.').pop();
    const trustedTlds = ['fr', 'de', 'es', 'it'];
    if (tld && trustedTlds.includes(tld.toLowerCase())) {
      totalRiskRef.value = Math.max(0, totalRiskRef.value - 5);
      reasonsSet.add('trustedTld');
      logDebug(`Verminderd risico voor vertrouwde TLD: ${tld}`);
    }

    const hostNFC = decodedDomain.normalize('NFC');
    const staticChecks = [
      {
        condition: (globalConfig.SUSPICIOUS_TLDS instanceof RegExp)
          ? globalConfig.SUSPICIOUS_TLDS.test(hostNFC)
          : false,
        weight: 6,
        reason: 'suspiciousTLD'
      },
      {
        condition: /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/.test(hostNFC),
        weight: 5,
        reason: 'ipAsDomain'
      },
      {
        condition: !isIpAddress(hostNFC) && (hostNFC.split('.').length - (tld.includes('.') ? tld.split('.').length + 1 : 2)) > (globalConfig.MAX_SUBDOMINENS || 3),
        weight: 5,
        reason: 'tooManySubdomains'
      }
    ];
    staticChecks.forEach(({ condition, weight, reason }) => {
      if (condition && !reasonsSet.has(reason)) {
        logDebug(`Static: ${reason} gedetecteerd op ${hostNFC}`);
        reasonsSet.add(reason);
        totalRiskRef.value += weight;
      }
    });

    if (isHttpProtocol && isIpAddress(urlObj.hostname)) {
      reasonsSet.add('ipAsDomain');
      totalRiskRef.value += 5;
      logDebug(`IP-adres gedetecteerd voor hostname: ${urlObj.hostname}`);
    }

    const numSub = decodedDomain.split('.').length - 2;
    if (numSub > globalConfig.MAX_SUBDOMAINS) {
      reasonsSet.add('tooManySubdomains');
      totalRiskRef.value += 5;
    }

    if (isHttpProtocol) {
      const scripts = getUnicodeScripts(decodedDomain);
      const expectedScript = getExpectedScriptForTld(tld);
      const isScriptConsistent =
        scripts.size === 1 && expectedScript.includes(Array.from(scripts)[0]);

      if (scripts.size > 1) {
        reasonsSet.add('mixedScripts');
        totalRiskRef.value += 13;
        logDebug(
          `Gemengde scripts gedetecteerd: ${decodedDomain}, scripts: ${Array.from(
            scripts
          ).join(', ')}`
        );

        const mainDomain = extractMainDomain(
          normalizeWithHomoglyphs(
            decodedDomain.toLowerCase().normalize('NFC'),
            homoglyphMap
          )
        );
        let minDistance = Infinity;
        let closestBrand = null;
        for (const brand of knownBrands) {
          const brandMain = extractMainDomain(brand.toLowerCase().normalize('NFC'));
          const d = levenshteinDistance(mainDomain, brandMain);
          if (d < minDistance) {
            minDistance = d;
            closestBrand = brandMain;
          }
        }
        if (closestBrand && minDistance > 0) {
          const maxLen = Math.max(mainDomain.length, closestBrand.length);
          const relRatio = minDistance / maxLen;

          const similarityThreshold = Math.max(0.15, Math.min(0.3, 2 / maxLen));
          if (relRatio <= similarityThreshold || minDistance <= 1) {
            logDebug(
              `Homoglyph attack: ${decodedDomain} (norm: ${mainDomain}) lijkt op ${closestBrand} (afstand=${minDistance}, norm=${relRatio})`
            );
            reasonsSet.add(`homoglyphAttack:${closestBrand}`);
            totalRiskRef.value += 11;
            if (globalConfig.domainRiskWeights[closestBrand]) {
              totalRiskRef.value += globalConfig.domainRiskWeights[closestBrand];
            }
          }
        }
      } else {
        const normalizedForTypos = normalizeWithHomoglyphs(
          decodedDomain.toLowerCase().normalize('NFC'),
          homoglyphMap
        );
        if (
          globalConfig.TYPOSQUATTING_PATTERNS.some((pat) =>
            pat.test(normalizedForTypos)
          )
        ) {
          let minDistance = Infinity;
          let closestBrand = null;
          const mainDomain = extractMainDomain(normalizedForTypos);
          for (const brand of knownBrands) {
            const brandMain = extractMainDomain(brand.toLowerCase().normalize('NFC'));
            const d = levenshteinDistance(mainDomain, brandMain);
            if (d < minDistance) {
              minDistance = d;
              closestBrand = brandMain;
            }
          }
          if (closestBrand && minDistance > 0) {
            const maxLen = Math.max(mainDomain.length, closestBrand.length);
            const relRatio = minDistance / maxLen;
            const typosquattingThreshold = Math.max(0.2, Math.min(0.4, 3 / maxLen));
            if (relRatio <= typosquattingThreshold || minDistance <= 2) {
              logDebug(
                `Typosquatting gedetecteerd: ${normalizedForTypos} lijkt op ${closestBrand} (afstand=${minDistance}, norm=${relRatio})`
              );
              reasonsSet.add(`typosquattingAttack:${closestBrand}`);
              totalRiskRef.value += 4;
              if (globalConfig.domainRiskWeights[closestBrand]) {
                totalRiskRef.value += globalConfig.domainRiskWeights[closestBrand];
              }
            }
          }
        } else {
          const mainDomain = extractMainDomain(decodedDomain);
          let minDistance = Infinity;
          let closestBrand = null;
          for (const brand of knownBrands) {
            const brandMain = extractMainDomain(brand.toLowerCase().normalize('NFC'));
            const d = levenshteinDistance(mainDomain, brandMain);
            if (d < minDistance) {
              minDistance = d;
              closestBrand = brandMain;
            }
          }
          if (closestBrand && minDistance > 0) {
            const maxLen = Math.max(mainDomain.length, closestBrand.length);
            const relRatio = minDistance / maxLen;

            logDebug(`DEBUG SIMILARITY CHECK:`);
            logDebug(`  Main Domain (decoded): "${decodedDomain}" (Length: ${decodedDomain.length})`);
            logDebug(`  Main Domain (extracted): "${mainDomain}" (Length: ${mainDomain.length})`);
            logDebug(`  Closest Brand: "${closestBrand}" (Length: ${closestBrand.length})`);
            logDebug(`  Min Distance: ${minDistance}`);
            logDebug(`  Max Length (for ratio): ${maxLen}`);
            logDebug(`  Relative Ratio (relRatio): ${relRatio.toFixed(3)}`);

            const VERY_LOW_REL_RATIO_THRESHOLD = 0.05;

            if (minDistance === 1 || (minDistance === 2 && relRatio < VERY_LOW_REL_RATIO_THRESHOLD)) {
              logDebug(
                `Domain ${decodedDomain} IS VERGELIJKBAAR met ${closestBrand} (afstand=${minDistance}, genorm=${relRatio.toFixed(3)})`
              );
              reasonsSet.add(`similarToLegitimateDomain:${closestBrand}`);
              totalRiskRef.value += 6;
              if (globalConfig.domainRiskWeights[closestBrand]) {
                totalRiskRef.value += globalConfig.domainRiskWeights[closestBrand];
              }
            } else {
              logDebug(
                `Domain ${decodedDomain} IS NIET VERGELIJKBAAR met ${closestBrand} (afstand=${minDistance}, genorm=${relRatio.toFixed(3)}, drempel=${VERY_LOW_REL_RATIO_THRESHOLD})`
              );
            }
          }
        }
      }
    }

    if (
      domain.startsWith('xn--') &&
      typeof punycode !== 'undefined' &&
      punycode.toUnicode
    ) {
      const decoded = punycode.toUnicode(domain);
      const codepoints = [...decoded].map((c) =>
        c.codePointAt(0).toString(16)
      );
      logDebug(
        `Gedecodeerd domein: ${decoded} (codepoints: ${codepoints.join(', ')})`
      );
      const unexpectedLatin = decoded.match(/[\u00C0-\u02AF]/);
      if (unexpectedLatin) {
        let minDistance = Infinity;
        let closestBrand = null;
        for (const brand of knownBrands) {
          const dist = levenshteinDistance(decoded, brand);
          if (dist < minDistance) {
            minDistance = dist;
            closestBrand = brand;
          }
        }
        if (closestBrand && minDistance > 0) {
          const maxLen = Math.max(decoded.length, closestBrand.length);
          const relRatio = minDistance / maxLen;
          const punycodeSimilarityThreshold = Math.min(0.2, 1 / maxLen);
          if (relRatio <= punycodeSimilarityThreshold || minDistance <= 1) {
            reasonsSet.add(`suspiciousPunycodeDecoding:${closestBrand}`);
            totalRiskRef.value += 5;
            logDebug(
              `Verdachte Punycode decodering: ${decoded} bevat onverwachte Latijnse karakters, lijkt op ${closestBrand}`
            );
          }
        }
      }
    }

    const dynamicChecks = [
      { func: hasBase64OrHex, messageKey: 'base64OrHex', risk: 2.0 },
      { func: isShortenedUrl, messageKey: 'shortenedUrl', risk: 4.0 },
      { func: hasEncodedCharacters, messageKey: 'encodedCharacters', risk: 3.0 },
      { func: hasUnusualPort, messageKey: 'unusualPort', risk: 5 },
      { func: hasSuspiciousKeywords, messageKey: 'suspiciousKeywords', risk: 3.0 },
      { func: hasSuspiciousPattern, messageKey: 'suspiciousPattern', risk: 4.0 },
      { func: isDownloadPage, messageKey: 'downloadPage', risk: 5.0 },
      { func: usesUrlFragmentTrick, messageKey: 'urlFragmentTrick', risk: 3.0 },
      { func: isCryptoPhishingUrl, messageKey: 'cryptoPhishing', risk: 10.0 },
      { func: isFreeHostingDomain, messageKey: 'freeHosting', risk: 5 },
      { func: hasSuspiciousQueryParameters, messageKey: 'suspiciousParams', risk: 2.5 },
      { func: hasMixedContent, messageKey: 'mixedContent', risk: 2.0 },
      { func: hasUnusualPort, messageKey: 'unusualPort', risk: 5 },
      { func: hasJavascriptScheme, messageKey: 'javascriptScheme', risk: 4.0 },
      { func: usesUrlFragmentTrick, messageKey: 'urlFragmentTrick', risk: 2.0 },
      { func: hasMultipleSubdomains, messageKey: 'tooManySubdomains', risk: 5.0 }, // Toegevoegd hier
    ];

    for (const { func, messageKey, risk } of dynamicChecks) {
      try {
        const result = await func(url); // Pass the url to functions that need it
        if (result === true) {
          reasonsSet.add(messageKey);
          totalRiskRef.value += risk;
          logDebug(`Toegevoegd ${messageKey} met risico ${risk} voor ${url}`);
        } else if (Array.isArray(result) && result.length > 0) {
          // Dit is voor functies die een array van redenen teruggeven (zoals hasSuspiciousIframes of checkForSuspiciousExternalScripts)
          result.forEach(r => reasonsSet.add(r)); // Voeg de individuele redenen toe
          totalRiskRef.value += risk; // Voeg het risico voor deze categorie toe
          logDebug(`Toegevoegd ${messageKey} met risico ${risk} voor ${url}, specifieke redenen: ${result.join(', ')}`);
        }
      } catch (e) {
        handleError(e, `performSuspiciousChecks (${messageKey})`);
      }
    }

    if (isHttpProtocol && detectLoginPage(url)) {
      try {
        const mxDomain = normalizeWithHomoglyphs(
          decodedDomain.toLowerCase().normalize('NFC'),
          homoglyphMap
        );
        const mxRecords = await queueMxCheck(mxDomain);
        if (!mxRecords.length) {
          reasonsSet.add('loginPageNoMX');
          totalRiskRef.value += 12;
          logDebug(`Login pagina zonder MX-records gedetecteerd: ${mxDomain}`);
        } else {
          logDebug(`MX-records gevonden voor login pagina ${mxDomain}:`, mxRecords);
        }
      } catch (e) {
        handleError(e, `performSuspiciousChecks: MX-controle mislukt voor ${decodedDomain}`);
      }
    }

    if (isHttpProtocol) {
      const currentPageDomain = normalizeDomain(window.location.href);
      const isCurrent = decodedDomain === currentPageDomain;
      const isHttp = urlObj.protocol === 'http:';
      // SSL-check altijd uitvoeren als de pagina HTTP is en het de huidige pagina betreft
      const shouldCheckSsl = isCurrent && isHttp;
      logDebug(
        `SSL-controle beslissing voor ${decodedDomain || 'geen domein'}: isCurrentPageDomain=${isCurrent}, isHttp=${isHttp}, risk=${totalRiskRef.value}, shouldCheckSsl=${shouldCheckSsl}`
      );
      if (shouldCheckSsl) {
        try {
          const sslResult = await Promise.race([
            new Promise((resolve, reject) => {
              chrome.runtime.sendMessage({ action: 'checkSslLabs', domain: decodedDomain }, (response) => {
                if (chrome.runtime.lastError) reject(new Error(chrome.runtime.lastError.message));
                else resolve(response);
              });
            }),
            new Promise((_, reject) => setTimeout(() => reject(new Error('SSL controle timeout')), 10000)),
          ]);
          if (!sslResult.isValid) {
            reasonsSet.add('sslValidationFailed');
            totalRiskRef.value += 10;
            logDebug(`SSL-controle mislukt voor ${decodedDomain}: ${sslResult.reason}`);
          } else {
            logDebug(`SSL-controle geslaagd voor ${decodedDomain}: ${sslResult.reason}`);
          }
        } catch (e) {
          handleError(e, `performSuspiciousChecks: SSL-controle mislukt voor ${decodedDomain}`);
        }
      }
    }

    const finalIsSafe = totalRiskRef.value < (globalConfig.RISK_THRESHOLD || 5);
    const finalResult = {
      isSafe: finalIsSafe,
      reasons: Array.from(reasonsSet),
      risk: totalRiskRef.value,
    };
    window.linkRiskCache.set(url, { result: finalResult, timestamp: Date.now() });
    logDebug(`Cached resultaat voor ${url}:`, finalResult);
    return finalResult;
  } catch (err) {
    handleError(err, `performSuspiciousChecks: Fout bij controleren URL ${url}`);
    return { isSafe: true, reasons: [], risk: 0 };
  }
}

// Functies die een array van strings moeten retourneren in plaats van een boolean
// ---
// `hasSuspiciousIframes()` functie
// ---
async function hasSuspiciousIframes() {
  const iframes = Array.from(document.getElementsByTagName('iframe')).filter(iframe => iframe.src);
  const detectedReasonStrings = new Set();
  const trustedDomains = globalConfig?.TRUSTED_IFRAME_DOMAINS || ['youtube.com', 'vimeo.com', 'google.com'];

  for (const iframe of iframes) {
    const src = iframe.src;
    if (!src) continue;

    try {
      const urlObj = new URL(src);
      const hostname = urlObj.hostname.toLowerCase();
      const protocol = urlObj.protocol;

      if (trustedDomains.some(domain => hostname === domain || hostname.endsWith(`.${domain}`))) {
        logDebug(`Safe iframe detected: ${src}`);
        continue;
      }

      if (globalConfig?.SUSPICIOUS_IFRAME_KEYWORDS instanceof RegExp && globalConfig.SUSPICIOUS_IFRAME_KEYWORDS.test(src)) {
        detectedReasonStrings.add('suspiciousIframeKeyword');
        logDebug(`Suspicious iframe (suspicious keyword): ${src}`);
      }

      if (protocol === 'http:' && window.location.protocol === 'https:') {
        detectedReasonStrings.add('mixedContent');
        logDebug(`Suspicious iframe (mixed content): ${src}`);
      }

      if (globalConfig?.SUSPICIOUS_TLDS instanceof RegExp && globalConfig.SUSPICIOUS_TLDS.test(hostname)) {
        detectedReasonStrings.add('suspiciousTLD');
        logDebug(`Suspicious iframe (suspicious TLD): ${src}`);
      }

      const style = window.getComputedStyle(iframe);
      const isHidden = style.display === 'none' || style.visibility === 'hidden' || (parseInt(style.width) === 0 && parseInt(style.height) === 0);
      const hasSuspiciousAttributes = iframe.hasAttribute('onload') || iframe.hasAttribute('onerror') || iframe.src.startsWith('javascript:');

      if (isHidden && hasSuspiciousAttributes) {
        detectedReasonStrings.add('iframeHidden');
        logDebug(`Suspicious iframe (hidden with suspicious attributes): ${src}`);
      }
    } catch (error) {
      detectedReasonStrings.add('invalidIframeSrc');
      logError(`hasSuspiciousIframes: Error analyzing iframe ${src}: ${error.message}`);
    }
  }
  logDebug(`Suspicious iframes detected (raw reasons): ${Array.from(detectedReasonStrings).join(', ')}`);
  return Array.from(detectedReasonStrings);
}

// ---
// `checkForSuspiciousExternalScripts()` functie
// ---
async function checkForSuspiciousExternalScripts() {
  const MAX_SCRIPTS_TO_CHECK = 20;
  const scripts = Array.from(document.getElementsByTagName('script'))
    .filter(script => script.src)
    .slice(0, MAX_SCRIPTS_TO_CHECK);

  const detectedReasonStrings = new Set();

  let trustedDomains = [];
  try {
    trustedDomains = await fetchCachedJson('trustedScripts.json');
    if (!Array.isArray(trustedDomains)) {
      logDebug('trustedScripts.json is geen array, gebruik lege lijst');
      trustedDomains = [];
    } else {
      trustedDomains = [...new Set(trustedDomains.filter(domain =>
        typeof domain === 'string' && /^[a-zA-Z0-9.-]+$/.test(domain) && domain.includes('.')
      ))];
    }
  } catch (error) {
    handleError(error, 'checkForSuspiciousExternalScripts: Fout bij laden trustedScripts.json');
    trustedDomains = [];
  }

  const trustedScripts = new Set([
    ...(globalConfig?.TRUSTED_SCRIPTS || [
      'googleapis.com', 'cloudflare.com', 'cdnjs.cloudflare.com', 'jsdelivr.net', 'unpkg.com',
      'code.jquery.com', 'bootstrapcdn.com', 'ajax.googleapis.com', 'static.cloudflareinsights.com',
      'polyfill.io', 'googletagmanager.com', 'analytics.google.com',
    ]),
    ...trustedDomains,
  ]);

  const freeHostingDomains = new Set(
    (globalConfig?.FREE_HOSTING_DOMAINS || []).filter(domain => !trustedScripts.has(domain))
  );
  const modernTlds = ['app', 'dev', 'tech', 'io', 'cloud'];

  for (const script of scripts) {
    const src = script.src;
    if (!src) continue;

    let riskScoreForThisScript = 0;

    try {
      const urlObj = new URL(src);
      const hostname = urlObj.hostname.toLowerCase();
      const protocol = urlObj.protocol;

      if (
        trustedScripts.has(hostname) ||
        Array.from(trustedScripts).some((domain) => hostname === domain || hostname.endsWith(`.${domain}`)) ||
        hostname.endsWith('.edu') || hostname.endsWith('.org') || hostname.endsWith('.gov')
      ) {
        logDebug(`Veilig script gedetecteerd: ${src} (vertrouwd domein)`);
        continue;
      }

      const isDeferred = script.hasAttribute('defer') || script.hasAttribute('async');
      const isTypeModule = script.getAttribute('type') === 'module';
      if (isDeferred || isTypeModule) {
        logDebug(`Veilig script gedetecteerd: ${src} (defer/async/module)`);
        continue;
      }

      let isSmallScript = false;
      try {
        const headResponse = await fetch(src, { method: 'HEAD' });
        const contentLength = headResponse.headers.get('content-length');
        if (contentLength && parseInt(contentLength, 10) < 2048) {
          logDebug(`Klein script gedetecteerd (<2KB): ${src}`);
          isSmallScript = true;
        }
      } catch (headError) {
        logDebug(`Kon scriptgrootte niet ophalen voor ${src}: ${headError.message}`);
      }

      if (isSmallScript) {
        logDebug(`Analyse overgeslagen voor klein script: ${src}`);
        continue;
      }

      if (/cdn|static|assets|lib|vendor/i.test(src)) {
        logDebug(`Script lijkt CDN-inhoud: ${src}, lagere prioriteit`);
        riskScoreForThisScript -= 2;
      }

      if (protocol === 'http:' && window.location.protocol === 'https:') {
        detectedReasonStrings.add('mixedContent');
        riskScoreForThisScript += 6;
        logDebug(`Verdacht script (mixed content): ${src}`);
      }

      const tld = hostname.split('.').pop();
      if (
        globalConfig?.SUSPICIOUS_TLDS instanceof RegExp &&
        globalConfig.SUSPICIOUS_TLDS.test(hostname) &&
        !trustedScripts.has(hostname) &&
        !modernTlds.includes(tld)
      ) {
        detectedReasonStrings.add('suspiciousTLD');
        riskScoreForThisScript += 2;
        logDebug(`Verdacht script (verdachte TLD): ${src}`);
      }

      if (/^\d+\.\d+\.\d+\.\d+$/.test(hostname)) {
        detectedReasonStrings.add('ipAsDomain');
        riskScoreForThisScript += 3;
        logDebug(`Verdacht script (IP als domein): ${src}`);
      }

      if (freeHostingDomains.has(hostname) && !/cdn|static|assets/i.test(src)) {
        detectedReasonStrings.add('freeHosting');
        riskScoreForThisScript += 2;
        logDebug(`Verdacht script (gratis hosting): ${src}`);
      }

      const contentResult = await analyzeScriptContent(urlObj);
      if (contentResult.isSuspicious) {
        detectedReasonStrings.add('suspiciousScriptContent');
        riskScoreForThisScript += contentResult.totalWeight / 2;
        logDebug(`Verdacht script (inhoudsanalyse): ${src}, Gewicht: ${contentResult.totalWeight}, Patronen: ${contentResult.matchedPatterns.join(', ')}`);
      }

      if (riskScoreForThisScript >= 8) {
        logDebug(`Verdacht script (individueel) gedetecteerd: ${src}, Score: ${riskScoreForThisScript}`);
      } else {
        logDebug(`Script ${src} onder verdenkingsdrempel: ${riskScoreForThisScript}`);
      }
    } catch (error) {
      logError(`checkForSuspiciousExternalScripts: Fout bij analyseren script ${src}: ${error.message}`);
      detectedReasonStrings.add('scriptAnalysisError');
    }
  }
  logDebug(`Verdachte externe scripts gedetecteerd (Totaal redenen): ${Array.from(detectedReasonStrings).join(', ')}`);
  return Array.from(detectedReasonStrings);
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
 * Verbeteringen t.o.v. de oude versie:
 * - Punycode + NFC-normalisatie
 * - Adaptieve relatieve Levenshtein-drempel (≤ 0.1 of 0.2)
 * - Compound-TLD-ondersteuning bij subdomeinen
 * @param {string} url          De volledige URL (inclusief protocol).
 * @param {Set<string>} reasons    Set waarin reason-tags worden toegevoegd.
 * @param {{ value: number }} totalRiskRef  Object dat de cumulatieve risicoscore bijhoudt.
 */
function checkStaticConditions(url, reasons, totalRiskRef) {
  let urlObj;
  try {
    urlObj = new URL(url, window.location.href);
  } catch (err) {
    logError(`checkStaticConditions: Ongeldige URL: ${url}`);
    return;
  }

  // 1) Punycode-decoding & Unicode NFC-normalisatie
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

  // --- Start van de GEFIXTE WHITELIST-LOGICA in checkStaticConditions ---
  const allSafeDomains = new Set([
    ...(window.trustedDomains || []),
    ...(globalConfig.legitimateDomains || [])
  ].map(d => d.toLowerCase().replace(/^www\./, '').replace(/\\\.com$/, '.com')));

  const domainToCheck = urlObj.hostname.toLowerCase().replace(/^www\./, '');
  const decodedDomainToCheck = hostNFC.toLowerCase().replace(/^www\./, '');

  if (allSafeDomains.has(domainToCheck) || allSafeDomains.has(decodedDomainToCheck)) {
    logDebug(`Static: ✅ Domein ${domainToCheck} of ${decodedDomainToCheck} is expliciet veilig (whitelist). Skip verdere statische checks.`);
    reasons.add('safeDomain');
    totalRiskRef.value = 0.1;
    return;
  }
  // --- Einde van de GEFIXTE WHITELIST-LOGICA ---


  // 3) Allowed protocols (ftp:, data:, javascript:) → skip zware checks
  const proto = urlObj.protocol;
  const allowedProtocols = ['ftp:', 'data:', 'javascript:'];
  if (allowedProtocols.includes(proto)) {
    logDebug(`Static: Allowed protocol ${proto} gedetecteerd voor ${url}`);
    reasons.add('allowedProtocol');
    totalRiskRef.value = 0.1;
  }

  // 4) HTTPS-controle
  if (
    !['https:', 'mailto:', 'tel:'].includes(proto) &&
    !reasons.has('noHttps')
  ) {
    if (proto !== 'https:') {
      logDebug(`Static: geen HTTPS voor ${url} (protocol=${proto})`);
      reasons.add('noHttps');
      totalRiskRef.value += 6.0;
    }
  }

  // 5) Bereken subdomein-aantal m.b.v. compound TLDs
  const parts = hostNFC.split('.');
  let tldLength = 1;
  const compoundTLDs = Array.isArray(globalConfig.COMPOUND_TLDS) ?
    globalConfig.COMPOUND_TLDS :
    [];
  compoundTLDs.forEach(ctld => {
    if (hostNFC === ctld || hostNFC.endsWith(`.${ctld}`)) {
      tldLength = ctld.split('.').length;
    }
  });
  const subdomainCount = parts.length - tldLength;

  // 6) Statische domeinchecks
  const staticChecks = [{
      // OPLOSSING: Controleren of het een RegExp-object is
      condition: (globalConfig.SUSPICIOUS_TLDS instanceof RegExp) ? 
        globalConfig.SUSPICIOUS_TLDS.test(hostNFC) :
        false,
      weight: 6,
      reason: 'suspiciousTLD'
    },
    {
      condition: /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/.test(hostNFC),
      weight: 5,
      reason: 'ipAsDomain'
    },
    {
      condition: !isIpAddress(hostNFC) && subdomainCount > (globalConfig.MAX_SUBDOMAINS || 3),
      weight: 5,
      reason: 'tooManySubdomains'
    }
  ];
  staticChecks.forEach(({
    condition,
    weight,
    reason
  }) => {
    if (condition && !reasons.has(reason)) {
      logDebug(`Static: ${reason} gedetecteerd op ${hostNFC}`);
      reasons.add(reason);
      totalRiskRef.value += weight;
    }
  });

  // 7) Adaptieve Levenshtein-check tov legitimateDomains
  if (
    Array.isArray(globalConfig.legitimateDomains) &&
    typeof globalConfig.domainRiskWeights === 'object'
  ) {
    for (const legit of globalConfig.legitimateDomains) {
      const legitMain = extractMainDomain(legit.toLowerCase().normalize('NFC'));
      const dist = levenshteinDistance(hostNFC, legitMain);
      if (dist > 0 && dist <= 2) {
        const maxLen = Math.max(hostNFC.length, legitMain.length);
        const relRatio = dist / maxLen;
        const threshold = (legitMain.length <= 6) ?
          0.2 :
          (globalConfig.SUSPICION_THRESHOLD || 0.1);

        logDebug(
          `Static Levenshtein: ${hostNFC} vs ${legitMain} → afstand=${dist}, ratio=${relRatio.toFixed(3)}, drempel=${threshold}`
        );
        if (relRatio <= threshold) {
          const weight = globalConfig.domainRiskWeights[legitMain] || 1;
          if (!reasons.has(`similarToLegitimateDomain:${legitMain}`)) {
            logDebug(`Static: similarToLegitimateDomain:${legitMain} (gewicht=${weight})`);
            reasons.add(`similarToLegitimateDomain:${legitMain}`);
            totalRiskRef.value += weight;
          }
          break;
        }
      }
    }
  }
}


async function checkDynamicConditions(url, reasons, totalRiskRef) {
  // Zorg dat de URL valide is
  let urlObj;
  try {
    urlObj = new URL(url);
  } catch (e) {
    handleError(e, `checkDynamicConditions: Ongeldige URL: ${url}`);
    return;
  }

  const isHttpProtocol = ['http:', 'https:'].includes(urlObj.protocol);
  const domainOnly = urlObj.hostname.toLowerCase();

  // Bouw homoglyphMap en knownBrands vanuit globalConfig
  const homoglyphMapEntries = globalConfig.HOMOGLYPHS || {};
  const homoglyphMap = {};
  for (const [latin, variants] of Object.entries(homoglyphMapEntries)) {
    for (const variant of variants) {
      homoglyphMap[variant] = latin;
    }
  }
  const knownBrands = Array.isArray(globalConfig.legitimateDomains)
    ? globalConfig.legitimateDomains.map(d => d.toLowerCase())
    : [];
  const tld = domainOnly.split('.').pop().toLowerCase();

  // Zet een lijst van “dynamische” checks op, waarbij we voor elke functie
  // een pijler (‘func’) definiëren die een boolean of array teruggeeft
  const dynamicChecks = [
    { func: () => isIpAddress(url),                               messageKey: "ipAsDomain",       risk: 5    },
    { func: () => hasMultipleSubdomains(url),                     messageKey: "tooManySubdomains", risk: 5.0  },
    { func: () => hasSuspiciousKeywords(url),                      messageKey: "suspiciousKeywords", risk: 2.0  },
    { func: () => hasSuspiciousUrlPattern(url),                    messageKey: "suspiciousPattern",  risk: 3.0  },
    { func: () => isShortenedUrl(url),                             messageKey: "shortenedUrl",       risk: 4.0  },
    // Alleen HTTP(S)-checks als het HTTP(S) is:
    ...(isHttpProtocol ? [
      { func: () => isDownloadPage(url),                            messageKey: "downloadPage",    risk: 3.5  },
      { func: () => checkForSuspiciousExternalScripts(),            messageKey: "externalScripts", risk: 4.0  },
      { func: () => hasMetaRedirect(),                              messageKey: "metaRedirect",    risk: 4.0  },
    ] : []),
    { func: () => isFreeHostingDomain(url),                        messageKey: "freeHosting",       risk: 5    },
    { func: () => hasEncodedCharacters(url),                        messageKey: "encodedCharacters", risk: 3.0  },
    { func: () => hasBase64OrHex(url),                             messageKey: "base64OrHex",      risk: 2.0  },
    // ↓ asynchrone aanroep van isHomoglyphAttack ↓
    {
      func: async () => {
        return await isHomoglyphAttack(domainOnly, homoglyphMap, knownBrands, tld);
      },
      messageKey: "homoglyphAttack",
      risk: 2.0
    },
    { func: () => isCryptoPhishingUrl(url),                        messageKey: "cryptoPhishing",    risk: 5    },
    { func: () => hasSuspiciousQueryParameters(url),               messageKey: "suspiciousParams",  risk: 2.5  },
    { func: () => hasMixedContent(url),                            messageKey: "mixedContent",     risk: 2.0  },
    { func: () => hasUnusualPort(url),                             messageKey: "unusualPort",      risk: 5    },
    { func: () => hasJavascriptScheme(url),                         messageKey: "javascriptScheme", risk: 4.0  },
    { func: () => usesUrlFragmentTrick(url),                        messageKey: "urlFragmentTrick", risk: 2.0  }
  ];

  for (const { func, messageKey, risk } of dynamicChecks) {
    try {
      // De functie kan een boolean of een array teruggeven
      const result = await func();
      const triggered = Array.isArray(result) ? result.length > 0 : Boolean(result);

      if (triggered && !reasons.has(messageKey)) {
        reasons.add(messageKey);
        totalRiskRef.value += risk;
        logDebug(`Added reason '${messageKey}' with risk ${risk} for ${url}`);
      }
    } catch (error) {
      // Bij een fout voeg een error-tag toe
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
 * Controleert de veiligheid van een link bij interacties zoals muisbewegingen of klikken.
 * Voert verdachte controles uit en beheert caching van resultaten.
 *
 * @param {HTMLAnchorElement} link    De link die wordt gecontroleerd.
 * @param {string} eventType          Het type event ('mouseover', 'click', etc.).
 * @param {Event} event               Het DOM-event-object.
 * @returns {Promise<{isSafe: boolean, risk: number, reasons: string[]}|void>}
 */
async function unifiedCheckLinkSafety(link, eventType, event) {
    // 1) Bescherming uitgeschakeld?
    if (!(await isProtectionEnabled())) {
        logDebug('Protection disabled, skipping unifiedCheckLinkSafety');
        return;
    }

    // ───────────────────────────────────────────────────────────────────────
    // Stap 1: Valideer invoer
    // ───────────────────────────────────────────────────────────────────────
    if (!link || !link.href || !isValidURL(link.href)) {
        logDebug(`Skipping unifiedCheckLinkSafety: Invalid or missing URL: ${link?.href || 'undefined'}`);
        return;
    }
    if (link.ownerSVGElement || link.href instanceof SVGAnimatedString) {
        const hrefValue = link.href instanceof SVGAnimatedString ? link.href.baseVal : link.href;
        logDebug(`Skipping SVG link: ${hrefValue || 'undefined'} (ownerSVGElement: ${!!link.ownerSVGElement}, SVGAnimatedString: ${link.href instanceof SVGAnimatedString})`);
        return;
    }

    const href = link.href;
    logDebug(`Checking URL in unifiedCheckLinkSafety: ${href}`);

    // ───────────────────────────────────────────────────────────────────────
    // Stap 2: Deduplicatie
    // ───────────────────────────────────────────────────────────────────────
    if (!window.processedLinks) {
        window.processedLinks = new Set();
    }
    // Voeg toe aan de set en plan verwijdering, om duplicaten voor een korte periode te voorkomen.
    if (window.processedLinks.has(href)) {
        logDebug(`Skipping duplicate check for ${href}`);
        return;
    }
    window.processedLinks.add(href);
    setTimeout(() => window.processedLinks.delete(href), 2000); // Verwijder na 2 seconden om herhaling toe te staan indien nodig

    try {
        // ─────────────────────────────────────────────────────────────────────
        // Stap 3: Bepaal hostname, check whitelist, en cache-beheer
        // ─────────────────────────────────────────────────────────────────────
        const urlObj = new URL(href);
        const hostname = urlObj.hostname.toLowerCase();
        const isPunycode = hostname.startsWith('xn--');
        const cacheKey = href.toLowerCase();

        if (!window.linkSafetyCache) {
            window.linkSafetyCache = new Map();
        }
        const cache = window.linkSafetyCache;

        // Haal 'legitimateDomains' op uit globalConfig
        const rawWhitelist = globalConfig.legitimateDomains || [];
        const whitelist = rawWhitelist.map(rgxStr =>
            rgxStr.replace(/\\\./g, '.').replace(/\$$/, '').toLowerCase()
        );

        // **Whitelist check:** Als het domein exact of als subdomein op de whitelist staat, markeer als veilig.
        if (whitelist.some(domainClean => hostname === domainClean || hostname.endsWith(`.${domainClean}`))) {
            logDebug(`Static: ✅ Domein "${hostname}" valt onder whitelist. Skip verdere checks.`);
            const safeResult = { isSafe: true, risk: 0, reasons: ['safeDomain'] };

            cache.set(cacheKey, safeResult);
            if (cache.size > MAX_CACHE_SIZE) {
                const firstKey = cache.keys().next().value;
                cache.delete(firstKey);
            }

            chrome.runtime.sendMessage({
                type: 'checkResult',
                url: href,
                isSafe: true,
                risk: 0,
                reasons: ['safeDomain'],
            });
            return safeResult;
        }

        // **Cache invalidatie:** Ongeldig de cache voor potentieel verdachte domeinen (punycode of domeinen met cijfers)
        // Cijfers in hostnamen worden hier als een indicatie van potentiële verandering/typosquatting gezien,
        // wat de cache minder betrouwbaar maakt voor die specifieke URL's.
        if (isPunycode || /\d/.test(hostname)) {
            logDebug(`Cache invalidated for ${href} due to ${isPunycode ? 'Punycode' : 'digits in hostname'}`);
            cache.delete(cacheKey);
        }

        // **Cache hit check:** Controleer de cache nadat potentiële invalidatie heeft plaatsgevonden.
        if (cache.has(cacheKey)) {
            const cachedResult = cache.get(cacheKey);
            logDebug(`Cache hit for ${href}: isSafe=${cachedResult.isSafe}, risk=${cachedResult.risk}, reasons=${cachedResult.reasons.join(', ')}`);
            chrome.runtime.sendMessage({
                type: 'checkResult',
                url: href,
                isSafe: cachedResult.isSafe,
                risk: cachedResult.risk,
                reasons: cachedResult.reasons,
            });
            return cachedResult;
        }

        // Initialiseer risico-variabelen
        const reasons = new Set();
        let isSafe = true;
        let risk = 0;

        // ─────────────────────────────────────────────────────────────────────
        // Stap 4: Homoglyph- en Typosquatting-controle (inclusief cijfer-gerelateerde)
        // De `isHomoglyphAttack` functie is nu verantwoordelijk voor het toevoegen van
        // redenen zoals 'digitHomoglyph' of 'typosquatting' als contextueel verdacht.
        // ─────────────────────────────────────────────────────────────────────
        const tld = extractTld(hostname);
        const homoglyphResult = await isHomoglyphAttack(
            hostname,
            globalConfig.HOMOGLYPHS,
            globalConfig.legitimateDomains,
            tld,
            reasons // Redenen worden direct aan deze Set toegevoegd door isHomoglyphAttack
        );
        if (homoglyphResult) {
            isSafe = false;
            risk += 10; // Basisrisico voor een gedetecteerde homoglyph/typosquatting aanval
        }

        // **Crypto-phishing check:** Specifieke check voor crypto-gerelateerde phishing.
        if (await isCryptoPhishingUrl(href)) {
             logDebug(`Crypto phishing detected for ${hostname}`);
             reasons.add('cryptoPhishing');
             isSafe = false;
             risk += 15; // Hoog risico voor crypto-phishing
        }

        // ─────────────────────────────────────────────────────────────────────
        // Stap 5a: Free hosting check
        // ─────────────────────────────────────────────────────────────────────
        const freeHosting = await isFreeHostingDomain(href);
        if (freeHosting) {
            logDebug(`Free hosting detected for ${hostname}`);
            reasons.add('freeHosting');
            isSafe = false;
            risk += 5;
        }

        // ─────────────────────────────────────────────────────────────────────
        // Stap 5b: Algemene verdachte controles via `performSuspiciousChecks`
        // Deze functie voegt algemene risico's toe zoals verdachte TLD's, IP als domein, etc.
        // ─────────────────────────────────────────────────────────────────────
        const checkResult = await performSuspiciousChecks(href);
        checkResult.reasons.forEach(reason => reasons.add(reason)); // Voeg alle redenen toe
        risk = Math.max(risk, checkResult.risk); // Neem het hoogste risico van alle checks
        isSafe = risk < (globalConfig.RISK_THRESHOLD || 5); // Herbereken `isSafe`

        // ─────────────────────────────────────────────────────────────────────
        // Stap 6: Controle verdachte normalisatie (bijv. van Unicode naar Latijnse tekens)
        // Hier wordt de correcte `normalizeToLatinBase` gebruikt.
        // ─────────────────────────────────────────────────────────────────────
        // Zorg ervoor dat `globalHomoglyphReverseMap` is gebouwd (wordt in DOMContentLoaded gedaan)
        if (Object.keys(globalHomoglyphReverseMap).length === 0) {
            buildGlobalHomoglyphReverseMap(); // Fallback, mocht het eerder mis zijn gegaan
        }
        const normalizedDomainForWhitelistCheck = normalizeToLatinBase(hostname, globalHomoglyphReverseMap);
        // Als het genormaliseerde domein verschilt van het origineel en op de whitelist staat,
        // duidt dit op een mogelijke poging tot misleiding.
        if (normalizedDomainForWhitelistCheck !== hostname && whitelist.includes(normalizedDomainForWhitelistCheck)) {
             logDebug(`Suspicious normalization for whitelist: ${hostname} → ${normalizedDomainForWhitelistCheck}`);
             reasons.add('suspiciousNormalization');
             isSafe = false;
             risk += 8;
         }

        // ─────────────────────────────────────────────────────────────────────
        // Stap 7: Cache en rapporteer het uiteindelijke resultaat
        // ─────────────────────────────────────────────────────────────────────
        const finalResult = { isSafe, risk, reasons: [...reasons] };
        cache.set(cacheKey, finalResult); // Sla het resultaat op in de cache

        // Beperk de cachegrootte
        if (cache.size > MAX_CACHE_SIZE) {
            const firstKey = cache.keys().next().value;
            cache.delete(firstKey);
        }

        // **BELANGRIJKE TOEVOEGING: Roep warnLink() hier aan als de link onveilig is!**
        if (!isSafe) {
            await warnLink(link, reasons); // Roep warnLink aan met de originele link-element
        }

        // Stuur het resultaat naar de achtergrondpagina (of andere luisteraars)
        chrome.runtime.sendMessage({
            type: 'checkResult',
            url: href,
            isSafe,
            risk,
            reasons: [...reasons],
        });
        logDebug(`Checked link ${href} on ${eventType}: isSafe: ${isSafe}, risk: ${risk}, reasons: ${[...reasons].join(', ')}`);

        // ─────────────────────────────────────────────────────────────────────
        // Stap 8: Klikverwerking met gebruikersfeedback
        // ─────────────────────────────────────────────────────────────────────
        if (eventType === 'click' && (href.startsWith('http://') || href.startsWith('https://'))) {
            try {
                const linkDomain = urlObj.hostname;
                const currentDomain = new URL(window.location.href).hostname;

                if (!linkDomain.endsWith(currentDomain)) {
                    event.preventDefault();

                    if (isSafe) {
                        window.location.href = href;
                    } else {
                        const warningMessage = `Warning: The link ${href} is potentially unsafe (reasons: ${[...reasons].join(', ')}). Proceed with caution?`;
                        if (confirm(warningMessage)) {
                            window.location.href = href;
                        }
                        logDebug(`Blocked unsafe link ${href} on click, user notified.`);
                    }
                }
            } catch (e) {
                logError(`Error in domain comparison for ${href}: ${e.message}`);
            }
        } else if (eventType === 'click') {
            logDebug(`Non-http(s) link skipped for click handling: ${href}`);
        }

        return finalResult;
    } catch (error) {
        logError(`unifiedCheckLinkSafety: Error checking link ${href} on event ${eventType}: ${error.message}`);
        handleError(error);
        logError(`[unifiedCheckLinkSafety] Error fallback for ${href}. Returning conservative safe result.`);
        return { isSafe: true, reasons: [], risk: 0 };
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


document.addEventListener('DOMContentLoaded', async () => {
    try {
        logDebug("🚀 Initializing content script...");
        await initContentScript(); // Zorgt voor initiële configuratie en laadt trusted domains.

        const currentUrl = window.location.href;
        logDebug(`🔍 Checking the current page: ${currentUrl}`);

        const reasonsForPage = new Set();
        let pageRisk = 0;

        // --- Paginabrede controles hier uitvoeren ---

        // 1. Controleer op mixed content iframes
        if (window.location.protocol === 'https:') {
            const iframes = Array.from(document.getElementsByTagName('iframe')).filter(iframe => iframe.src);
            for (const iframe of iframes) {
                try {
                    const iframeUrlObj = new URL(iframe.src);
                    if (iframeUrlObj.protocol === 'http:') {
                        reasonsForPage.add('mixedContent');
                        pageRisk += 10; // Voeg het risico voor de PAGINA toe
                        logDebug(`⚠️ Mixed content iframe gedetecteerd op pagina: ${iframe.src}`);
                        break; // Eén keer toevoegen is voldoende voor de pagina
                    }
                } catch (e) {
                    logError(`Fout bij analyseren iframe src voor mixed content: ${iframe.src}`, e);
                }
            }
        }

        // 2. Controleer op verdachte iframes (bijv. verborgen, met scripts, etc.)
        // Deze functie retourneert nu een array van strings (redenen).
        const suspiciousIframesReasons = await hasSuspiciousIframes(); // Zorg dat deze functie de correcte output levert (array van strings)
        if (suspiciousIframesReasons.length > 0) {
            suspiciousIframesReasons.forEach(reason => reasonsForPage.add(reason)); // Voeg enkel de reden-string toe
            pageRisk += 3.5; // Voeg een algemeen risico toe voor verdachte iframes op de pagina
            logDebug(`⚠️ Verdachte iframes op pagina:`, suspiciousIframesReasons);
        }

        // 3. Controleer op verdachte externe scripts
        // Deze functie retourneert nu een array van strings (redenen).
        const suspiciousScriptReasons = await checkForSuspiciousExternalScripts(); // Zorg dat deze functie de correcte output levert (array van strings)
        if (suspiciousScriptReasons.length > 0) {
            suspiciousScriptReasons.forEach(reason => reasonsForPage.add(reason)); // Voeg enkel de reden-string toe
            pageRisk += 4.0; // Voeg een algemeen risico toe voor verdachte scripts op de pagina
            logDebug(`⚠️ Verdachte scripts op pagina:`, suspiciousScriptReasons);
        }

        // 4. Controleer of de hoofd-URL een loginpagina is en of deze zonder MX-records is
        const isLoginOnPage = detectLoginPage(currentUrl); // Controleer de hoofd-URL
        if (isLoginOnPage) {
            logDebug(`Login pagina gedetecteerd op hoofdpagina: ${currentUrl}`);
            // Voer MX-check uit voor de hoofd-URL (alleen relevant als het een loginpagina is)
            try {
                const urlObjForMx = new URL(currentUrl);
                let domainForMx = urlObjForMx.hostname.toLowerCase();
                if (domainForMx.startsWith('xn--') && typeof punycode !== 'undefined' && punycode.toUnicode) {
                    try {
                        domainForMx = punycode.toUnicode(domainForMx);
                    } catch (e) {
                        logError(`Kon Punycode niet decoderen voor MX check: ${domainForMx}`, e);
                    }
                }
                const mxRecords = await queueMxCheck(domainForMx);
                if (mxRecords.length === 0) {
                    reasonsForPage.add('loginPageNoMX');
                    pageRisk += 12; // Hoog risico voor loginpagina zonder MX
                    logDebug(`⚠️ Login pagina op hoofdpagina zonder MX-records gedetecteerd: ${domainForMx}`);
                }
            } catch (error) {
                handleError(error, `DOMContentLoaded: MX-controle hoofdpagina mislukt voor ${currentUrl}`);
            }

            // Voeg insecureLoginPage alleen toe als het HTTP is
            // Belangrijk: Hier wordt de `urlObj` van de `DOMContentLoaded` scope gebruikt.
            // Zorg ervoor dat `urlObj` hier correct is gedefinieerd of haal het opnieuw op.
            const currentUrlObj = new URL(currentUrl);
            if (currentUrlObj.protocol !== 'https:') {
                reasonsForPage.add('insecureLoginPage');
                pageRisk += 20; // Zeer hoog risico voor HTTP loginpagina
                logDebug(`⚠️ Insecure login pagina op hoofdpagina: ${currentUrl}`);
            }
        }

        // --- DEBUG LOG START ---
        // Log de paginabrede redenen en risico voordat ze worden gecombineerd met de link-specifieke checks
        logDebug(`[DOMContentLoaded] Initial page-wide reasons collected:`, Array.from(reasonsForPage));
        logDebug(`[DOMContentLoaded] Initial page-wide risk:`, pageRisk);
        // --- DEBUG LOG END ---


        // Voer de reguliere performSuspiciousChecks uit op de hoofd-URL
        // Deze functie bevat nu NIET de paginabrede checks (mixedContent, suspiciousIframes, externalScripts, MX-check voor links, etc.)
        const mainUrlAnalysisResult = await performSuspiciousChecks(currentUrl);

        // --- DEBUG LOG START ---
        // Log het resultaat van performSuspiciousChecks voor de hoofd-URL
        logDebug(`[DOMContentLoaded] Result from performSuspiciousChecks for main URL:`, mainUrlAnalysisResult);
        // --- DEBUG LOG END ---


        // Combineer de paginabrede redenen en risico's met de redenen van de hoofd-URL
        mainUrlAnalysisResult.reasons = [...new Set([...mainUrlAnalysisResult.reasons, ...reasonsForPage])];
        mainUrlAnalysisResult.risk = mainUrlAnalysisResult.risk + pageRisk;

        // Herbereken isSafe op basis van het gecombineerde risico
        mainUrlAnalysisResult.isSafe = mainUrlAnalysisResult.risk < (globalConfig.RISK_THRESHOLD || 5);

        // --- DEBUG LOG START ---
        // Log het gecombineerde, uiteindelijke resultaat dat wordt verzonden
        logDebug(`[DOMContentLoaded] Sending final combined checkResult for page:`, {
            type: "checkResult",
            url: currentUrl,
            isSafe: mainUrlAnalysisResult.isSafe,
            risk: mainUrlAnalysisResult.risk,
            reasons: mainUrlAnalysisResult.reasons
        });
        // --- DEBUG LOG END ---

        // Verstuur het gecombineerde resultaat voor de pagina
        chrome.runtime.sendMessage({
            type: "checkResult",
            url: currentUrl,
            isSafe: mainUrlAnalysisResult.isSafe,
            risk: mainUrlAnalysisResult.risk,
            reasons: mainUrlAnalysisResult.reasons
        });
        logDebug(`✅ Hoofdpagina check compleet: isSafe=${mainUrlAnalysisResult.isSafe}, risk=${mainUrlAnalysisResult.risk}, reasons=${Array.from(mainUrlAnalysisResult.reasons).join(", ")}`);


        // Controleer vervolgens alle externe links op de pagina
        await checkLinks(); // Deze roept performSuspiciousChecks() aan voor individuele links

    } catch (error) {
        handleError(error, `DOMContentLoaded: Fout bij initialiseren van content script voor pagina ${window.location.href}`);
    }
});


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

  const mainUrlCheck = await performSuspiciousChecks(currentUrl);
  chrome.runtime.sendMessage({
    type: 'checkResult',
    url: currentUrl,
    isSafe: mainUrlCheck.isSafe,
    risk: mainUrlCheck.risk,
    reasons: mainUrlCheck.reasons
  });

  const MAX_LINKS_TO_SCAN = 500; // Verlaagd voor betere prestatie
  const links = Array.from(document.querySelectorAll('a'))
    .filter(link => link.href && isValidURL(link.href) && !scannedLinks.has(link.href))
    .slice(0, MAX_LINKS_TO_SCAN);

  const totalLinks = document.querySelectorAll('a').length;
  if (totalLinks > MAX_LINKS_TO_SCAN) {
    logDebug(`Aantal links (${totalLinks}) overschrijdt limiet (${MAX_LINKS_TO_SCAN}), alleen eerste ${MAX_LINKS_TO_SCAN} worden gecontroleerd.`);
  }

  if (links.length === 0) {
    logDebug(`Geen links om te controleren. Resultaat gebaseerd op hoofdpagina: ${mainUrlCheck.isSafe}`);
    return !mainUrlCheck.isSafe;
  }

  const linkChecks = links.map(async (link) => {
    const href = link.href;
    scannedLinks.add(href);

    let urlObj;
    try {
      urlObj = new URL(href);
    } catch (error) {
      logError(`Ongeldige URL gedetecteerd: ${href}`, error);
      return { href, isSuspicious: false };
    }

    const linkDomain = urlObj.hostname.toLowerCase();
    if (isSameDomain(linkDomain, currentDomain)) {
      logDebug(`Link ${href} behoort tot hoofddomein ${currentDomain}, geen visuele waarschuwing.`);
      return { href, isSuspicious: false };
    }

    const protocol = urlObj.protocol;
    const isHttpProtocol = ['http:', 'https:'].includes(protocol);

    const addWarning = async (reasons) => {
      await warnLink(link, reasons);
      logDebug(`Externe link ${href} gemarkeerd als verdacht. Redenen: ${reasons.join(', ')}`);
      return true;
    };

    if (!isHttpProtocol) {
      logDebug(`Skipping HTTPS/TLD checks for non-HTTP protocol: ${href}`);
      return { href, isSuspicious: false };
    }

    if (globalConfig.SUSPICIOUS_TLDS.test(linkDomain)) {
      return { href, isSuspicious: await addWarning(["suspiciousTLD"]) };
    }

    if (protocol !== 'https:') {
      return { href, isSuspicious: await addWarning(["noHttps"]) };
    }

    const { isSafe, reasons, risk } = await performSuspiciousChecks(href);
    if (!isSafe) {
      return { href, isSuspicious: await addWarning(reasons) };
    }

    logDebug(`Externe link ${href} is veilig. Redenen: ${reasons.length > 0 ? reasons.join(', ') : 'geen'}`);
    return { href, isSuspicious: false };
  });

  const results = await Promise.all(linkChecks);
  const hasSuspiciousExternalLinks = results.some(result => result.isSuspicious);
  const finalResult = hasSuspiciousExternalLinks || !mainUrlCheck.isSafe;

  logDebug(`Eindresultaat checkLinks: ${finalResult}. Hoofdpagina veilig: ${mainUrlCheck.isSafe}, Verdachte externe links: ${hasSuspiciousExternalLinks}`);
  return finalResult;
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


/**
 * Controleert de veiligheid van een link bij interacties zoals muisbewegingen of klikken.
 * Voert verdachte controles uit en beheert caching van resultaten.
 *
 * @param {HTMLAnchorElement} link    De link die wordt gecontroleerd.
 * @param {string} eventType          Het type event ('mouseover', 'click', etc.).
 * @param {Event} event               Het DOM-event-object.
 * @returns {Promise<{isSafe: boolean, risk: number, reasons: string[]}|void>}
 */
async function unifiedCheckLinkSafety(link, eventType, event) {
    // 1) Bescherming uitgeschakeld?
    if (!(await isProtectionEnabled())) {
        logDebug('Protection disabled, skipping unifiedCheckLinkSafety');
        return;
    }

    // ───────────────────────────────────────────────────────────────────────
    // Stap 1: Valideer invoer
    // ───────────────────────────────────────────────────────────────────────
    if (!link || !link.href || !isValidURL(link.href)) {
        logDebug(`Skipping unifiedCheckLinkSafety: Invalid or missing URL: ${link?.href || 'undefined'}`);
        return;
    }
    if (link.ownerSVGElement || link.href instanceof SVGAnimatedString) {
        const hrefValue = link.href instanceof SVGAnimatedString ? link.href.baseVal : link.href;
        logDebug(`Skipping SVG link: ${hrefValue || 'undefined'} (ownerSVGElement: ${!!link.ownerSVGElement}, SVGAnimatedString: ${link.href instanceof SVGAnimatedString})`);
        return;
    }

    const href = link.href;
    logDebug(`Checking URL in unifiedCheckLinkSafety: ${href}`);

    // ───────────────────────────────────────────────────────────────────────
    // Stap 2: Deduplicatie
    // ───────────────────────────────────────────────────────────────────────
    if (!window.processedLinks) {
        window.processedLinks = new Set();
    }
    // Voeg toe aan de set en plan verwijdering, om duplicaten voor een korte periode te voorkomen.
    if (window.processedLinks.has(href)) {
        logDebug(`Skipping duplicate check for ${href}`);
        return;
    }
    window.processedLinks.add(href);
    setTimeout(() => window.processedLinks.delete(href), 2000); // Verwijder na 2 seconden om herhaling toe te staan indien nodig

    try {
        // ─────────────────────────────────────────────────────────────────────
        // Stap 3: Bepaal hostname, check whitelist, en cache-beheer
        // ─────────────────────────────────────────────────────────────────────
        const urlObj = new URL(href);
        const hostname = urlObj.hostname.toLowerCase();
        const isPunycode = hostname.startsWith('xn--');
        const cacheKey = href.toLowerCase();

        if (!window.linkSafetyCache) {
            window.linkSafetyCache = new Map();
        }
        const cache = window.linkSafetyCache;

        // Haal 'legitimateDomains' op uit globalConfig
        const rawWhitelist = globalConfig.legitimateDomains || [];
        const whitelist = rawWhitelist.map(rgxStr =>
            rgxStr.replace(/\\\./g, '.').replace(/\$$/, '').toLowerCase()
        );

        // **Whitelist check:** Als het domein exact of als subdomein op de whitelist staat, markeer als veilig.
        if (whitelist.some(domainClean => hostname === domainClean || hostname.endsWith(`.${domainClean}`))) {
            logDebug(`Static: ✅ Domein "${hostname}" valt onder whitelist. Skip verdere checks.`);
            const safeResult = { isSafe: true, risk: 0, reasons: ['safeDomain'] };

            cache.set(cacheKey, safeResult);
            if (cache.size > MAX_CACHE_SIZE) {
                const firstKey = cache.keys().next().value;
                cache.delete(firstKey);
            }

            chrome.runtime.sendMessage({
                type: 'checkResult',
                url: href,
                isSafe: true,
                risk: 0,
                reasons: ['safeDomain'],
            });
            return safeResult;
        }

        // **Cache invalidatie:** Ongeldig de cache voor potentieel verdachte domeinen (punycode of domeinen met cijfers)
        // Cijfers in hostnamen worden hier als een indicatie van potentiële verandering/typosquatting gezien,
        // wat de cache minder betrouwbaar maakt voor die specifieke URL's.
        if (isPunycode || /\d/.test(hostname)) {
            logDebug(`Cache invalidated for ${href} due to ${isPunycode ? 'Punycode' : 'digits in hostname'}`);
            cache.delete(cacheKey);
        }

        // **Cache hit check:** Controleer de cache nadat potentiële invalidatie heeft plaatsgevonden.
        if (cache.has(cacheKey)) {
            const cachedResult = cache.get(cacheKey);
            logDebug(`Cache hit for ${href}: isSafe=${cachedResult.isSafe}, risk=${cachedResult.risk}, reasons=${cachedResult.reasons.join(', ')}`);
            chrome.runtime.sendMessage({
                type: 'checkResult',
                url: href,
                isSafe: cachedResult.isSafe,
                risk: cachedResult.risk,
                reasons: cachedResult.reasons,
            });
            return cachedResult;
        }

        // Initialiseer risico-variabelen
        const reasons = new Set();
        let isSafe = true;
        let risk = 0;

        // ─────────────────────────────────────────────────────────────────────
        // Stap 4: Homoglyph- en Typosquatting-controle (inclusief cijfer-gerelateerde)
        // De `isHomoglyphAttack` functie is nu verantwoordelijk voor het toevoegen van
        // redenen zoals 'digitHomoglyph' of 'typosquatting' als contextueel verdacht.
        // ─────────────────────────────────────────────────────────────────────
        const tld = extractTld(hostname);
        const homoglyphResult = await isHomoglyphAttack(
            hostname,
            globalConfig.HOMOGLYPHS,
            globalConfig.legitimateDomains,
            tld,
            reasons // Redenen worden direct aan deze Set toegevoegd door isHomoglyphAttack
        );
        if (homoglyphResult) {
            isSafe = false;
            risk += 10; // Basisrisico voor een gedetecteerde homoglyph/typosquatting aanval
        }

        // **Crypto-phishing check:** Specifieke check voor crypto-gerelateerde phishing.
        if (await isCryptoPhishingUrl(href)) {
             logDebug(`Crypto phishing detected for ${hostname}`);
             reasons.add('cryptoPhishing');
             isSafe = false;
             risk += 15; // Hoog risico voor crypto-phishing
        }

        // ─────────────────────────────────────────────────────────────────────
        // Stap 5a: Free hosting check
        // ─────────────────────────────────────────────────────────────────────
        const freeHosting = await isFreeHostingDomain(href);
        if (freeHosting) {
            logDebug(`Free hosting detected for ${hostname}`);
            reasons.add('freeHosting');
            isSafe = false;
            risk += 5;
        }

        // ─────────────────────────────────────────────────────────────────────
        // Stap 5b: Algemene verdachte controles via `performSuspiciousChecks`
        // Deze functie voegt algemene risico's toe zoals verdachte TLD's, IP als domein, etc.
        // ─────────────────────────────────────────────────────────────────────
        const checkResult = await performSuspiciousChecks(href);
        checkResult.reasons.forEach(reason => reasons.add(reason)); // Voeg alle redenen toe
        risk = Math.max(risk, checkResult.risk); // Neem het hoogste risico van alle checks
        isSafe = risk < (globalConfig.RISK_THRESHOLD || 5); // Herbereken `isSafe`

        // ─────────────────────────────────────────────────────────────────────
        // Stap 6: Controle verdachte normalisatie (bijv. van Unicode naar Latijnse tekens)
        // ─────────────────────────────────────────────────────────────────────
        const normalizedDomain = normalizeWithHomoglyphs(hostname, {
            ...globalConfig.HOMOGLYPHS,
            'rn': 'm',
            'vv': 'w',
        });
        // Als het genormaliseerde domein verschilt van het origineel en op de whitelist staat,
        // duidt dit op een mogelijke poging tot misleiding.
        if (normalizedDomain !== hostname && whitelist.includes(normalizedDomain)) {
            logDebug(`Suspicious normalization: ${hostname} → ${normalizedDomain}`);
            reasons.add('suspiciousNormalization');
            isSafe = false;
            risk += 8;
        }

        // ─────────────────────────────────────────────────────────────────────
        // Stap 7: Cache en rapporteer het uiteindelijke resultaat
        // ─────────────────────────────────────────────────────────────────────
        const finalResult = { isSafe, risk, reasons: [...reasons] };
        cache.set(cacheKey, finalResult); // Sla het resultaat op in de cache

        // Beperk de cachegrootte
        if (cache.size > MAX_CACHE_SIZE) {
            const firstKey = cache.keys().next().value;
            cache.delete(firstKey);
        }

        // Stuur het resultaat naar de achtergrondpagina (of andere luisteraars)
        chrome.runtime.sendMessage({
            type: 'checkResult',
            url: href,
            isSafe,
            risk,
            reasons: [...reasons],
        });
        logDebug(`Checked link ${href} on ${eventType}: isSafe: ${isSafe}, risk: ${risk}, reasons: ${[...reasons].join(', ')}`);

        // ─────────────────────────────────────────────────────────────────────
        // Stap 8: Klikverwerking met gebruikersfeedback (voor externe, potentieel onveilige links)
        // ─────────────────────────────────────────────────────────────────────
        // Alleen HTTP/HTTPS links behandelen
        if (eventType === 'click' && (href.startsWith('http://') || href.startsWith('https://'))) {
            try {
                const linkDomain = urlObj.hostname;
                const currentDomain = new URL(window.location.href).hostname;

                // Als het een externe link is (niet hetzelfde domein of subdomein)
                if (!linkDomain.endsWith(currentDomain)) {
                    event.preventDefault(); // Voorkom standaard navigatie direct

                    if (isSafe) {
                        // Als veilig, navigeer dan alsnog
                        window.location.href = href;
                    } else {
                        // Als onveilig, toon een waarschuwing en vraag om bevestiging
                        const warningMessage = `Warning: The link ${href} is potentially unsafe (reasons: ${[...reasons].join(', ')}). Proceed with caution?`;
                        if (confirm(warningMessage)) {
                            window.location.href = href;
                        }
                        logDebug(`Blocked unsafe link ${href} on click, user notified.`);
                    }
                }
            } catch (e) {
                logError(`Error in domain comparison for ${href}: ${e.message}`);
            }
        } else if (eventType === 'click') {
            logDebug(`Non-http(s) link skipped for click handling: ${href}`);
        }

        return finalResult; // Retourneer het resultaat van de check
    } catch (error) {
        logError(`unifiedCheckLinkSafety: Error checking link ${href} on event ${eventType}: ${error.message}`);
        handleError(error); // Log de fout via de centrale foutafhandeling
        logError(`[unifiedCheckLinkSafety] Error fallback for ${href}. Returning conservative safe result.`);
        // Bij een onverwachte fout, retourneer een 'veilig' resultaat om te voorkomen dat legitieme links geblokkeerd worden
        return { isSafe: true, reasons: [], risk: 0 };
    }
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
