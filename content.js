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


// Shared constants for throttling and caching
const CHECK_INTERVAL_MS = 5000; // 5 seconds between checks
const CACHE_DURATION_MS = 3600 * 1000; // 1 hour cache expiration

// Throttle tracking variables (global scope for persistence)
let lastIframeCheck = 0;
let lastScriptCheck = 0;



/**
 * Valideert en sanitize de configuratie.
 * @param {object} config
 * @returns {object}
 */
function validateConfig(config) {
  const validated = { ...config };

  // Basic type checks and defaults
  if (typeof validated.DEBUG_MODE !== 'boolean') {
    validated.DEBUG_MODE = false;
  }
  if (!Array.isArray(validated.ALLOWED_PROTOCOLS)) {
    validated.ALLOWED_PROTOCOLS = ['https:', 'http:', 'mailto:', 'tel:', 'ftp:'];
  }

  // SUSPICIOUS_TLDS met try/catch
  if (!(validated.SUSPICIOUS_TLDS instanceof RegExp)) {
    try {
      validated.SUSPICIOUS_TLDS = new RegExp(
        '\\.(academy|accountant|accountants|agency|ap|app|art|asia|auto|bank|bar|beauty|bet|bid|bio|biz|blog|buzz|cam|capital|casa|casino|cfd|charity|cheap|church|city|claims|click|club|company|crispsalt|cyou|data|date|design|dev|digital|directory|download|email|energy|estate|events|exchange|expert|exposed|express|finance|fit|forsale|foundation|fun|games|gle|goog|gq|guide|guru|health|help|home|host|html|icu|ink|institute|investments|ip|jobs|life|limited|link|live|loan|lol|ltd|ly|mall|market|me|media|men|ml|mom|money|monster|mov|network|one|online|page|partners|party|php|pics|play|press|pro|promo|pw|quest|racing|rest|review|rocks|run|sbs|school|science|services|shop|shopping|site|software|solutions|space|store|stream|support|team|tech|tickets|to|today|tools|top|trade|trading|uno|ventures|vip|website|wiki|win|work|world|xin|xyz|zip|zone|co|cc|tv|name|team|live|stream|quest|sbs)$',
        'i'
      );
    } catch (error) {
      logError(`Ongeldig RegExp-patroon voor SUSPICIOUS_TLDS: ${error.message}`);
      validated.SUSPICIOUS_TLDS = /.*/; // Fallback naar veilige RegExp
    }
  }

  // MALWARE_EXTENSIONS met try/catch
  if (!(validated.MALWARE_EXTENSIONS instanceof RegExp)) {
    try {
      validated.MALWARE_EXTENSIONS = new RegExp(
        '\\.(exe|zip|bak|tar|gz|msi|dmg|jar|rar|7z|iso|bin|scr|bat|cmd|sh|vbs|lnk|chm|ps2|apk|ps1|py|js|vbscript|dll|docm|xlsm|pptm|doc|xls|ppt|rtf|torrent|wsf|hta|jse|reg|swf|svg|lnk|chm)$',
        'i'
      );
    } catch (error) {
      logError(`Ongeldig RegExp-patroon voor MALWARE_EXTENSIONS: ${error.message}`);
      validated.MALWARE_EXTENSIONS = /.*/; // Fallback naar veilige RegExp
    }
  }

  // Convert SHORTENED_URL_DOMAINS to a Set if it's an array or not a Set
  if (!validated.SHORTENED_URL_DOMAINS || !(validated.SHORTENED_URL_DOMAINS instanceof Set)) {
    validated.SHORTENED_URL_DOMAINS = new Set(validated.SHORTENED_URL_DOMAINS || ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co']);
  }

  // PHISHING_KEYWORDS
  if (!(validated.PHISHING_KEYWORDS instanceof Set)) {
    validated.PHISHING_KEYWORDS = new Set(validated.PHISHING_KEYWORDS || ['login', 'password', 'verify', 'access', 'account', 'auth', 'blocked', 'bonus', 'captcha', 'claim', 'click', 'credentials', 'free', 'gift', 'notification', 'pay', 'pending', 'prize', 'recover', 'secure', 'signin', 'unlock', 'unusual', 'update', 'urgent', 'validate', 'win']);
  }

  // DOWNLOAD_KEYWORDS
  if (!(validated.DOWNLOAD_KEYWORDS instanceof Set)) {
    validated.DOWNLOAD_KEYWORDS = new Set(validated.DOWNLOAD_KEYWORDS || ['download', 'install', 'setup', 'file', 'update', 'patch', 'plugin', 'installer', 'software', 'driver', 'execute', 'run', 'launch', 'tool', 'patcher', 'application', 'program', 'app', 'fix', 'crack', 'keygen', 'serial', 'activation', 'license', 'trial', 'demo', 'zip', 'archive', 'compressed', 'installer_package', 'upgrade', 'update_tool', 'free', 'fixer', 'repair', 'optimizer', 'restore', 'reset', 'unlock', 'backup', 'configuration', 'config', 'module', 'library', 'framework', 'macro', 'enable', 'torrent', 'seed', 'payload', 'exploit', 'dropper', 'loader', 'package', 'binary', 'release', 'beta', 'mod', 'hack']);
  }

  // Numerieke instellingen
  if (typeof validated.RISK_THRESHOLD !== 'number' || validated.RISK_THRESHOLD < 0) {
    validated.RISK_THRESHOLD = 5;
  }
  if (typeof validated.MAX_SUBDOMAINS !== 'number' || validated.MAX_SUBDOMAINS < 0) {
    validated.MAX_SUBDOMAINS = 3;
  }
  if (typeof validated.CACHE_DURATION_MS !== 'number' || validated.CACHE_DURATION_MS <= 0) {
    validated.CACHE_DURATION_MS = 24 * 60 * 60 * 1000; // 24 uur
  }
  if (typeof validated.SUSPICION_THRESHOLD !== 'number' || validated.SUSPICION_THRESHOLD < 0 || validated.SUSPICION_THRESHOLD > 1) {
    validated.SUSPICION_THRESHOLD = 0.1;
  }

  // TRUSTED_IFRAME_DOMAINS
  if (!Array.isArray(validated.TRUSTED_IFRAME_DOMAINS) || validated.TRUSTED_IFRAME_DOMAINS.some(domain => typeof domain !== 'string')) {
    validated.TRUSTED_IFRAME_DOMAINS = ['youtube.com', 'vimeo.com', 'google.com'];
  }

  // LOGIN_PATTERNS met try/catch
  if (!(validated.LOGIN_PATTERNS instanceof RegExp)) {
    try {
      validated.LOGIN_PATTERNS = new RegExp(
        '(login|account|auth|authenticate|signin|wp-login|sign-in|log-in|dashboard|portal|session|user|profile|dashboard|portal|session|user|profile)',
        'i'
      );
    } catch (error) {
      logError(`Ongeldig RegExp-patroon voor LOGIN_PATTERNS: ${error.message}`);
      validated.LOGIN_PATTERNS = /.*/; // Fallback naar veilige RegExp
    }
  }

  // FREE_HOSTING_DOMAINS
  if (!Array.isArray(validated.FREE_HOSTING_DOMAINS) || validated.FREE_HOSTING_DOMAINS.some(domain => typeof domain !== 'string')) {
    validated.FREE_HOSTING_DOMAINS = [
      'sites.net', 'angelfire.com', 'geocities.ws', '000a.biz', '000webhostapp.com', 'weebly.com', 'wixsite.com', 
      'freehosting.com', 'glitch.me', 'firebaseapp.com', 'herokuapp.com', 'freehostia.com', 'netlify.app', 'webs.com', 
      'yolasite.com', 'github.io', 'bravenet.com', 'zyro.com', 'altervista.org', 'tripod.com', 'jimdo.com', 'ucoz.com', 
      'blogspot.com', 'square.site', 'pages.dev', 'r2.dev', 'mybluehost.me', '000space.com', 'awardspace.com', 
      'byethost.com', 'biz.nf', 'hyperphp.com', 'infinityfree.net', '50webs.com', 'tripod.lycos.com', 'site123.me', 
      'webflow.io', 'strikingly.com', 'x10hosting.com', 'freehostingnoads.net', '000freewebhost.com', 'mystrikingly.com', 
      'sites.google.com', 'appspot.com', 'vercel.app', 'weeblysite.com', 's3.amazonaws.com', 'bubbleapps.io', 
      'typedream.app', 'codeanyapp.com', 'carrd.co', 'surge.sh', 'replit.dev', 'fly.dev', 'render.com', 'onrender.com',
      'netlify.app', 'vercel.app'
    ];
  }

  // CRYPTO_DOMAINS
  if (!Array.isArray(validated.CRYPTO_DOMAINS) || validated.CRYPTO_DOMAINS.some(domain => typeof domain !== 'string')) {
    validated.CRYPTO_DOMAINS = [
      "binance.com", "kraken.com", "metamask.io", "wallet-connect.org", "coinbase.com", "bybit.com", "okx.com", 
      "kucoin.com", "hashkey.com", "binance.us", "raydium.io"
    ];
  }

  // HOMOGLYPHS
  if (typeof validated.HOMOGLYPHS !== 'object' || validated.HOMOGLYPHS === null) {
    validated.HOMOGLYPHS = {
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

  // SUSPICIOUS_URL_PATTERNS met try/catch
  if (!Array.isArray(validated.SUSPICIOUS_URL_PATTERNS) || validated.SUSPICIOUS_URL_PATTERNS.some(p => !(p instanceof RegExp))) {
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
    validated.SUSPICIOUS_URL_PATTERNS = patterns.map(pattern => {
      try {
        return new RegExp(pattern, 'i');
      } catch (error) {
        logError(`Ongeldig RegExp-patroon voor SUSPICIOUS_URL_PATTERNS: ${pattern}. Fout: ${error.message}`);
        return null;
      }
    }).filter(regex => regex !== null);
    if (validated.SUSPICIOUS_URL_PATTERNS.length === 0) {
      validated.SUSPICIOUS_URL_PATTERNS = [/.*/]; // Fallback naar veilige RegExp
    }
  }

  // legitimateDomains
  if (!Array.isArray(validated.legitimateDomains) || validated.legitimateDomains.some(domain => typeof domain !== 'string')) {
    validated.legitimateDomains = [
      'microsoft.com', 'apple.com', 'google.com', 'linkedin.com', 'alibaba.com',
      'whatsapp.com', 'amazon.com', 'x.com', 'facebook.com', 'adobe.com'
    ];
  }

if (!Array.isArray(validated.COMPOUND_TLDS)) {
  validated.COMPOUND_TLDS = [
    'co.uk', 'org.uk', 'gov.uk', 'ac.uk',
    'com.au', 'org.au',
    'co.nz'
  ];
}

  // domainRiskWeights
  if (typeof validated.domainRiskWeights !== 'object' || validated.domainRiskWeights === null) {
    validated.domainRiskWeights = {
      'microsoft.com': 10, 'apple.com': 4, 'google.com': 4, 'linkedin.com': 3, 'alibaba.com': 1,
      'whatsapp.com': 1, 'amazon.com': 1, 'x.com': 1, 'facebook.com': 1, 'adobe.com': 1
    };
  }

  // SUSPICIOUS_SCRIPT_PATTERNS met try/catch
  if (!Array.isArray(validated.SUSPICIOUS_SCRIPT_PATTERNS) || validated.SUSPICIOUS_SCRIPT_PATTERNS.some(p => !(p instanceof RegExp))) {
    const scriptPatterns = [
      '(?:base64_decode|base64_encode|rot13|hex|md5|sha1|sha256|xor|hash|eval64|obfuscate)',
      '(?:document\\.write|eval|Function|setTimeout|setInterval|atob|btoa|escape|unescape|innerHTML|outerHTML|appendChild|insertBefore|replaceChild|removeChild|location\\.href|window\\.location|localStorage|sessionStorage|XMLHttpRequest|fetch|WebSocket|prototype\\.call|Object\\.defineProperty|new Function)',
      '(?:download|execute|payload|install|load|unpack|update|patch|plugin|setup|plugin\\.js|install\\.js|update\\.js|loader\\.js|miner\\.js|coinimp|cryptonight|wasm)',
      '(?:iframe|srcdoc|data:text\\/html|javascript:|onload|onerror|onclick|onsubmit|onmouseover|onfocus|onblur|onchange|onscroll|onkeydown|onkeyup|onkeypress)',
      '(?:malicious|unsafe|tracker|adserver|spy|hack|exploit|virus|malware|phish|redirect|inject|clickjacking|xss|keylogger|trojan|worm|ransomware|payload|obfuscated|obfuscate|backdoor|rootkit|sqlinjection|sqli|bufferoverflow|overflow|csrf|cryptojacking|mining)',
      '(RTCPeerConnection|RTCDataChannel|mozRTCPeerConnection|webkitRTCPeerConnection|iceCandidate|peerconnection|stun:|turn:)',
      '(navigator\\.geolocation|navigator\\.permissions|navigator\\.mediaDevices|Clipboard|ServiceWorker|PushManager|WebAssembly)',
      '\\.(php|asp|cgi|exe|bin|dll|dat|py|sh|vb|vbs|cmd|bat|pl|ps1|psm1|jar|class|js|jsp|aspx|cfm|rb|ts|mjs|apk|swift|go|lua|wasm)$',
      'script|eval',
      '(RTCPeerConnection|RTCDataChannel|mozRTCPeerConnection|webkitRTCPeerConnection|iceCandidate)'
    ];
    validated.SUSPICIOUS_SCRIPT_PATTERNS = scriptPatterns.map(pattern => {
      try {
        return new RegExp(pattern, 'i');
      } catch (error) {
        logError(`Ongeldig RegExp-patroon voor SUSPICIOUS_SCRIPT_PATTERNS: ${pattern}. Fout: ${error.message}`);
        return null;
      }
    }).filter(regex => regex !== null);
    if (validated.SUSPICIOUS_SCRIPT_PATTERNS.length === 0) {
      validated.SUSPICIOUS_SCRIPT_PATTERNS = [/.*/]; // Fallback naar veilige RegExp
    }
  }

  return validated;
}


/**
 * Laadt de configuratie uit window.CONFIG en valideert deze.
 */
const defaultConfig = {
  DEBUG_MODE: false,
  ALLOWED_PROTOCOLS: ['https:', 'http:', 'mailto:', 'tel:', 'ftp:'], // Match window.CONFIG
  SUSPICIOUS_TLDS: /\.(academy|accountant|accountants|agency|ap|app|art|asia|auto|bank|bar|beauty|bet|bid|bio|biz|blog|buzz|cam|capital|casa|casino|cfd|charity|cheap|church|city|claims|click|club|company|crispsalt|cyou|data|date|design|dev|digital|directory|download|email|energy|estate|events|exchange|expert|exposed|express|finance|fit|forsale|foundation|fun|games|gle|goog|gq|guide|guru|health|help|home|host|html|icu|ink|institute|investments|ip|jobs|life|limited|link|live|loan|lol|ltd|ly|mall|market|me|media|men|ml|mom|money|monster|mov|network|one|online|page|partners|party|php|pics|play|press|pro|promo|pw|quest|racing|rest|review|rocks|run|sbs|school|science|services|shop|shopping|site|software|solutions|space|store|stream|support|team|tech|tickets|to|today|tools|top|trade|trading|uno|ventures|vip|website|wiki|win|work|world|xin|xyz|zip|zone|co|cc|tv|name|team|live|stream|quest|sbs)$/i,
  MALWARE_EXTENSIONS: /\.(exe|zip|bak|tar|gz|msi|dmg|jar|rar|7z|iso|bin|scr|bat|cmd|sh|vbs|lnk|chm|ps2|apk|ps1|py|js|vbscript|dll|docm|xlsm|pptm|doc|xls|ppt|rtf|torrent|wsf|hta|jse|reg|swf|svg|lnk|chm)$/i,
  SHORTENED_URL_DOMAINS: new Set(['bit.ly', 'tinyurl.com', 'goo.gl', 't.co']),
  PHISHING_KEYWORDS: new Set(['login', 'password', 'verify', 'access', 'account', 'auth', 'blocked', 'bonus', 'captcha', 'claim', 'click', 'credentials', 'free', 'gift', 'notification', 'pay', 'pending', 'prize', 'recover', 'secure', 'signin', 'unlock', 'unusual', 'update', 'urgent', 'validate', 'win']),
  DOWNLOAD_KEYWORDS: new Set(['download', 'install', 'setup', 'file', 'update', 'patch', 'plugin', 'installer', 'software', 'driver', 'execute', 'run', 'launch', 'tool', 'patcher', 'application', 'program', 'app', 'fix', 'crack', 'keygen', 'serial', 'activation', 'license', 'trial', 'demo', 'zip', 'archive', 'compressed', 'installer_package', 'upgrade', 'update_tool', 'free', 'fixer', 'repair', 'optimizer', 'restore', 'reset', 'unlock', 'backup', 'configuration', 'config', 'module', 'library', 'framework', 'macro', 'enable', 'torrent', 'seed', 'payload', 'exploit', 'dropper', 'loader', 'package', 'binary', 'release', 'beta', 'mod', 'hack']),
  RISK_THRESHOLD: 5,
  MAX_SUBDOMAINS: 3,
  CACHE_DURATION_MS: 24 * 60 * 60 * 1000, // 24 hours
  SUSPICION_THRESHOLD: 0.1,
  TRUSTED_IFRAME_DOMAINS: ['youtube.com', 'vimeo.com', 'google.com'],
  LOGIN_PATTERNS: /(login|account|auth|authenticate|signin|wp-login|sign-in|log-in|dashboard|portal|session|user|profile|dashboard|portal|session|user|profile)/i,
  FREE_HOSTING_DOMAINS: [
    'sites.net', 'angelfire.com', 'geocities.ws', '000a.biz', '000webhostapp.com', 'weebly.com', 'wixsite.com', 
    'freehosting.com', 'glitch.me', 'firebaseapp.com', 'herokuapp.com', 'freehostia.com', 'netlify.app', 'webs.com', 
    'yolasite.com', 'github.io', 'bravenet.com', 'zyro.com', 'altervista.org', 'tripod.com', 'jimdo.com', 'ucoz.com', 
    'blogspot.com', 'square.site', 'pages.dev', 'r2.dev', 'mybluehost.me', '000space.com', 'awardspace.com', 
    'byethost.com', 'biz.nf', 'hyperphp.com', 'infinityfree.net', '50webs.com', 'tripod.lycos.com', 'site123.me', 
    'webflow.io', 'strikingly.com', 'x10hosting.com', 'freehostingnoads.net', '000freewebhost.com', 'mystrikingly.com', 
    'sites.google.com', 'appspot.com', 'vercel.app', 'weeblysite.com', 's3.amazonaws.com', 'bubbleapps.io', 
    'typedream.app', 'codeanyapp.com', 'carrd.co', 'surge.sh', 'replit.dev', 'fly.dev', 'render.com', 'onrender.com',
    'netlify.app', 'vercel.app'
  ],
  CRYPTO_DOMAINS: [
    "binance.com", "kraken.com", "metamask.io", "wallet-connect.org", "coinbase.com", "bybit.com", "okx.com", 
      "kucoin.com", "hashkey.com", "binance.us", "raydium.io"
  ],
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
  SUSPICIOUS_SCRIPT_PATTERNS: [
    /(?:base64_decode|base64_encode|rot13|hex|md5|sha1|sha256|xor|hash|eval64|obfuscate)/i,
    /(?:document\.write|eval|Function|setTimeout|setInterval|atob|btoa|escape|unescape|innerHTML|outerHTML|appendChild|insertBefore|replaceChild|removeChild|location\.href|window\.location|localStorage|sessionStorage|XMLHttpRequest|fetch|WebSocket|prototype\.call|Object\.defineProperty|new Function)/i,
    /(?:download|execute|payload|install|load|unpack|update|patch|plugin|setup|plugin\.js|install\.js|update\.js|loader\.js|miner\.js|coinimp|cryptonight|wasm)/i,
    /(?:iframe|srcdoc|data:text\/html|javascript:|onload|onerror|onclick|onsubmit|onmouseover|onfocus|onblur|onchange|onscroll|onkeydown|onkeyup|onkeypress)/i,
    /(?:malicious|unsafe|tracker|adserver|spy|hack|exploit|virus|malware|phish|redirect|inject|clickjacking|xss|keylogger|trojan|worm|ransomware|payload|obfuscated|obfuscate|backdoor|rootkit|sqlinjection|sqli|bufferoverflow|overflow|csrf|cryptojacking|mining)/i,
    /(RTCPeerConnection|RTCDataChannel|mozRTCPeerConnection|webkitRTCPeerConnection|iceCandidate|peerconnection|stun:|turn:)/i,
    /(navigator\.geolocation|navigator\.permissions|navigator\.mediaDevices|Clipboard|ServiceWorker|PushManager|WebAssembly)/i,
    /\.(php|asp|cgi|exe|bin|dll|dat|py|sh|vb|vbs|cmd|bat|pl|ps1|psm1|jar|class|js|jsp|aspx|cfm|rb|ts|mjs|apk|swift|go|lua|wasm)$/i,
    /script|eval/i,
    /(RTCPeerConnection|RTCDataChannel|mozRTCPeerConnection|webkitRTCPeerConnection|iceCandidate)/i
  ],
legitimateDomains: [
    'microsoft.com',
    'apple.com',
    'google.com',
    'linkedin.com',
    'alibaba.com',
    'whatsapp.com',
    'amazon.com',
    'x.com',
    'facebook.com',
    'adobe.com'
  ],
  domainRiskWeights: {
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
  },
};

// Voeg een vlag toe om te controleren of de configuratie al is geladen
const maxConfigLoadAttempts = 3;
let configLoadAttempts = 0;
let configLoaded = false;

async function loadConfig() {
  if (configLoaded || configLoadAttempts >= maxConfigLoadAttempts) return;

  const attempt = configLoadAttempts + 1;
  configLoadAttempts++;

  try {
    if (window.CONFIG && typeof window.CONFIG === 'object') {
      globalConfig = validateConfig({ ...defaultConfig, ...window.CONFIG });
      logDebug("Configuration loaded successfully:", globalConfig);
      configLoaded = true;
    } else {
      throw new Error("window.CONFIG is not available or invalid.");
    }
  } catch (error) {
    handleError(error, `loadConfig: Kon configuratie niet laden (poging ${attempt})`);

    if (configLoadAttempts < maxConfigLoadAttempts) {
      const delay = Math.pow(2, attempt) * 1000; // Exponentiële backoff: 1s, 2s, 4s
      logDebug(`Config load failed, retrying in ${delay / 1000} seconden... (poging ${attempt})`);
      setTimeout(loadConfig, delay);
    } else {
      globalConfig = validateConfig(defaultConfig);
      logDebug("Using default configuration after failed attempts:", globalConfig);
      configLoaded = true; // Voorkom verdere pogingen
    }
  }
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
    handleError(error, `initializeSafeDomains: Kon TrustedDomains.json niet laden of verwerken`);
    safeDomains = ['example.com', 'google.com']; // Hardcoded fallback
    safeDomainsInitialized = true;
  }
}

initializeSafeDomains();


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

function checkCurrentUrl() {
  const currentUrl = window.location.href;
  if (currentUrl !== lastCheckedUrl) {
    lastCheckedUrl = currentUrl;
    logDebug("[Content] URL changed to:", currentUrl);
    performSuspiciousChecks(currentUrl).then((result) => {
      logDebug("[Content] Check result:", result);
      logDebug("Analysis result:", result);
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
    // Controleer of de URL al een protocol heeft (bijv. http://, mailto:)
    if (/^[a-z]+:\/\//i.test(url)) {
      const parsedUrl = new URL(url);
      // Alleen http en https hebben een relevant domein
      if (!['http:', 'https:'].includes(parsedUrl.protocol)) {
        return null; // Bijv. mailto: heeft geen domein
      }
      let hostname = parsedUrl.hostname.toLowerCase();
      hostname = hostname.replace(/^www\./, "").replace(/\/$/, "");
      return hostname;
    } else {
      // Relatieve URL: los op ten opzichte van de huidige pagina
      const absoluteUrl = new URL(url, window.location.href);
      let hostname = absoluteUrl.hostname.toLowerCase();
      hostname = hostname.replace(/^www\./, "").replace(/\/$/, "");
      return hostname;
    }
  } catch (error) {
    handleError(error, `normalizeDomain: Fout bij normaliseren van URL ${url}`);
    return null;
  }
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
    const checks = [
        { func: () => /^(crypto|coins|wallet|exchange|ico|airdrop)/i.test(domain), score: 5, messageKey: "cryptoPhishingAd" },
        { func: () => /adclick|gclid|utm_source/i.test(sanitizeInput(urlObj.search)), score: 2, messageKey: "suspiciousAdStructure" },
        { func: () => globalConfig.SUSPICIOUS_TLDS.test(domain), score: 3, messageKey: "suspiciousAdTLD" },
        { func: () => isHomoglyphAttack(domain), score: 4, messageKey: "homoglyphAdAttack" },
        { func: () => /^(amazon|google|microsoft|paypal)/i.test(domain), score: 5, messageKey: "brandMisuse" }
    ];
    try {
        const results = checks.map(check => {
            const result = check.func();
            return result ? { score: check.score, messageKey: check.messageKey } : null;
        }).filter(result => result !== null);
        const totalRiskScore = results.reduce((sum, result) => sum + result.score, 0);
        const specificReasons = results.map(result => result.messageKey);
        if (specificReasons.length > 0) {
            await warnLink(link, specificReasons);
            const warningIcon = document.createElement("span");
            warningIcon.className = "phishing-warning-icon";
            warningIcon.textContent = "⚠️";
            warningIcon.style = "position: relative; top: 0; left: 5px; color: #ff0000;";
            link.insertAdjacentElement("afterend", warningIcon);
            link.style.border = "2px solid #ff0000";
            link.style.color = "#ff0000";
            link.title = chrome.i18n.getMessage("alertMessage") + "\n" + specificReasons.map(key => chrome.i18n.getMessage(key)).join("\n");
        }
    } catch (error) {
        handleError(error, `checkForPhishingAds: Fout bij controleren van link ${link.href}`);
        await warnLink(link, ["fileCheckFailed"]); // Gebruik een bestaande key
    }
}

function classifyAndCheckLink(link) {
  if (!link || !link.href) {
    logDebug(`Skipping classification: Invalid or missing link: ${link || 'undefined'}`);
    return; // Sla volledig ongeldige links over
  }

  // Controleer expliciet of het een SVG-element is en sla het over
  if (link.ownerSVGElement) {
    logDebug(`Skipping SVG link: ${link.href || 'undefined'}, Type: ${typeof link.href}`);
    return; // Sla alle SVG-links over, ongeacht de href
  }

  // Controleer of href een geldige URL is
  if (!isValidURL(link.href)) {
    logDebug(`Skipping classification: Invalid URL in link: ${link.href || 'undefined'}`);
    return;
  }

  if (link.closest('div[data-text-ad], .ads-visurl')) {
    checkForPhishingAds(link);
  } else {
    analyzeDomainAndUrl(link);
  }
}

async function warnLink(link, reasons) {
  if (!link || !link.href || !isValidURL(link.href)) {
    logDebug("Invalid link provided to warnLink:", link);
    return;
  }

  const url = link.href;
  const riskResult = await performSuspiciousChecks(url); // Gebruikt cache
  const isHighRisk = riskResult.risk >= (globalConfig.RISK_THRESHOLD || 5);

  // Verwijder bestaande waarschuwingsiconen
  const existingIcon = link.nextElementSibling;
  if (existingIcon && existingIcon.classList.contains('phishing-warning-icon')) {
    existingIcon.remove();
  }
  link.style.border = '';
  link.style.color = '';

  if (!isHighRisk && riskResult.reasons.length === 0) {
    return; // Geen waarschuwing als veilig
  }

  const warningIcon = document.createElement('span');
  warningIcon.className = 'phishing-warning-icon';
  warningIcon.textContent = '⚠️';

  const translatedReasons = riskResult.reasons.map(reason => {
    const translated = chrome.i18n.getMessage(reason) || reason;
    logDebug(`Vertaling voor reason '${reason}':`, translated);
    return translated;
  }).join("\n");

  const tooltipText = `${chrome.i18n.getMessage("reasonLabel") || "Why?"}:\n${translatedReasons}`;
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
            reasons.push(reasonKey); // Gebruik alleen de key, geen formatted string
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

        // 2. Phishing keywords
        if (urlParts.some(word => globalConfig.PHISHING_KEYWORDS.has(word))) {
            addRisk(10, "suspiciousKeywords", "high");
        }

        // 3. Verdachte bestandsextensies
        if (ext && globalConfig.MALWARE_EXTENSIONS.test(ext[0])) {
            addRisk(12, "downloadPage", "high"); // "downloadPage" lijkt passend
        }

        // 4. IP-adres als domeinnaam + ongebruikelijke poort
        if (/^(?:https?:\/\/)?(\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:\/|$)/.test(url)) {
            addRisk(12, "ipAsDomain", "high");
            if (urlObj.port && !["80", "443"].includes(urlObj.port)) {
                addRisk(6, "unusualPort", "high");
            }
        }

        // 5. Verkorte URL-detectie
        if (globalConfig.SHORTENED_URL_DOMAINS.has(domain)) {
            addRisk(6, "shortenedUrl", "medium");
            try {
                const response = await fetch(url, { method: 'HEAD', redirect: 'follow' });
                const finalUrl = response.url;
                if (finalUrl && finalUrl !== url) {
                    addRisk(10, "shortenedUrl", "medium"); // Hergebruik key, geen dynamische tekst
                }
            } catch (error) {
                addRisk(5, "shortenedUrl", "low"); // Fallback bij fout
                handleError(error, `calculateRiskScore: Kon verkorte URL ${url} niet oplossen`);
            }
        }

        // 6. Verdachte TLD's
        if (globalConfig.SUSPICIOUS_TLDS.test(domain)) {
            addRisk(15, "suspiciousTLD", "high");
        }

        // 7. Ongewoon lange URL's
        if (url.length > maxLength) {
            addRisk(8, "urlFragmentTrick", "medium"); // Geen exacte match, maar dichtbij
        }

        // 8. Gecodeerde tekens
        if (/%[0-9A-Fa-f]{2}/.test(url)) {
            addRisk(6, "encodedCharacters", "medium");
        }

        // 9. Overmatig gebruik van subdomeinen
        if (domain.split(".").length > 3) {
            addRisk(5, "tooManySubdomains", "medium");
        }

        // 10. Base64 of hexadecimale encoding
        if (/^(javascript|data):/.test(url) || /[a-f0-9]{32,}/.test(url)) {
            addRisk(12, "base64OrHex", "high");
        }

        logDebug(`Risk score for ${url}: ${score}. Reasons: ${reasons.join(', ')}`);
        return { score, reasons };

    } catch (error) {
        handleError(error, `calculateRiskScore: Fout bij risicoberekening voor URL ${url}`);
        return { score: -1, reasons: ["Error calculating risk score."] };
    }
}


function isSearchResultPage() {
  const url = new URL(window.location.href);
  return url.hostname.includes("google.") && (url.pathname === "/search" || url.pathname === "/imgres");
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
  const suspiciousReasons = [];
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
        logDebug(`Safe iframe detected: ${src}`);
        continue;
      }

      // Mixed content detectie (ongewijzigd)
      if (protocol === 'http:' && window.location.protocol === 'https:') {
        suspiciousReasons.push({ reason: 'mixedContent', risk: 10, src });
        logDebug(`Suspicious iframe (mixed content): ${src}`);
      }

      // Verdachte TLDs (ongewijzigd)
      if (globalConfig.SUSPICIOUS_TLDS.test(hostname)) {
        suspiciousReasons.push({ reason: 'suspiciousTLD', risk: 6, src });
        logDebug(`Suspicious iframe (suspicious TLD): ${src}`);
      }

      // Verborgen iframes: specifieker maken
      const style = window.getComputedStyle(iframe);
      const isHidden = style.display === 'none' || style.visibility === 'hidden' || 
                       (parseInt(style.width) === 0 && parseInt(style.height) === 0);
      const hasSuspiciousAttributes = iframe.hasAttribute('onload') || iframe.hasAttribute('onerror') || 
                                      iframe.src.startsWith('javascript:');
      if (isHidden && hasSuspiciousAttributes) { // Alleen verdacht met kwaadaardige kenmerken
        suspiciousReasons.push({ reason: 'iframeHidden', risk: 3, src });
        logDebug(`Suspicious iframe (hidden with suspicious attributes): ${src}`);
      }

      // Base64/Hex check later apart behandeld
    } catch (error) {
      handleError(error, `hasSuspiciousIframes: Error analyzing iframe ${src}`);
    }
  }

  if (suspiciousReasons.length > 0) {
    logDebug(`Suspicious iframes detected: ${JSON.stringify(suspiciousReasons)}`);
    return suspiciousReasons;
  }

  logDebug('No suspicious iframes found');
  return [];
}

function checkForSuspiciousExternalScripts() {
  const scripts = Array.from(document.getElementsByTagName('script')).filter(script => script.src);
  const suspiciousReasons = [];
  const trustedScripts = globalConfig?.TRUSTED_SCRIPTS || new Set(['googleapis.com', 'cloudflare.com', 'cdnjs.cloudflare.com']);
  const freeHostingDomains = Array.isArray(globalConfig?.FREE_HOSTING_DOMAINS) 
    ? new Set(globalConfig.FREE_HOSTING_DOMAINS) 
    : new Set();

  for (const script of scripts) {
    const src = script.src;
    if (!src) continue;

    try {
      const urlObj = new URL(src);
      const hostname = urlObj.hostname.toLowerCase();
      const protocol = urlObj.protocol;

      // Skip vertrouwde scripts en populaire CDN’s
      if (trustedScripts.has(hostname) || hostname.endsWith('.edu') || hostname.endsWith('.org')) {
        logDebug(`Safe script detected: ${src}`);
        continue;
      }

      // Mixed content detectie
      if (protocol === 'http:' && window.location.protocol === 'https:') {
        suspiciousReasons.push({ reason: 'mixedContent', risk: 10, src });
        logDebug(`Suspicious script (mixed content): ${src}`);
      }

      // Verdachte TLDs alleen als niet vertrouwd
      if (globalConfig?.SUSPICIOUS_TLDS?.test(hostname) && !trustedScripts.has(hostname)) {
        suspiciousReasons.push({ reason: 'suspiciousTLD', risk: 6, src });
        logDebug(`Suspicious script (suspicious TLD): ${src}`);
      }

      // IP-adressen
      if (/^\d+\.\d+\.\d+\.\d+$/.test(hostname)) {
        suspiciousReasons.push({ reason: 'ipAsDomain', risk: 5, src });
        logDebug(`Suspicious script (IP as domain): ${src}`);
      }

      // Gratis hosting: specifieker maken
      if (freeHostingDomains.has(hostname) && !/cdn|static|assets/i.test(src)) {
        suspiciousReasons.push({ reason: 'freeHosting', risk: 5, src });
        logDebug(`Suspicious script (free hosting): ${src}`);
      }

      // Base64/Hex: apart behandeld
    } catch (error) {
      handleError(error, `checkForSuspiciousExternalScripts: Error analyzing script ${src}`);
    }
  }

  if (suspiciousReasons.length > 0) {
    logDebug(`Suspicious external scripts detected: ${JSON.stringify(suspiciousReasons)}`);
    return suspiciousReasons;
  }

  logDebug('No suspicious external scripts found');
  return [];
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
    handleError(error, `analyzeScriptContent: Fout bij analyseren van script ${scriptUrl.href}`);
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
 * Controleert of een domein homoglyph-aanvallen bevat.
 * @param {string} domain - Het te controleren domein.
 * @returns {boolean} - True als een homoglyph-aanval wordt gedetecteerd, anders false.
 */
function isHomoglyphAttack(domain) {
  // Controleer of de invoer geldig is (niet null, undefined, geen string, of leeg)
  if (!domain || typeof domain !== 'string' || domain.trim() === '') {
    logError('Ongeldige domeininvoer:', domain);
    return false;
  }

  try {
    // Normaliseer de domeinnaam naar kleine letters en NFC-formaat
    const normalizedDomain = domain.toLowerCase().normalize('NFC');
    
    // Snelle controle: als er geen homoglyphs zijn, stoppen we hier
    if (!homoglyphRegex.test(normalizedDomain)) {
      logDebug(`Geen homoglyphs gedetecteerd in ${normalizedDomain}`);
      return false;
    }

    // Converteer homoglyphConfig naar een Map voor efficiënte lookups
    const homoglyphMap = new Map(Object.entries(homoglyphConfig));
    // Maak een set van alle karakters in de domeinnaam voor snelle controle
    const domainChars = new Set(normalizedDomain);

    // Controleer elk karakter in de domeinnaam
    for (let i = 0; i < normalizedDomain.length; i++) {
      const char = normalizedDomain[i];
      if (homoglyphSet.has(char)) {
        let originalChar = null;
        // Zoek het originele karakter dat overeenkomt met de homoglyph
        for (const [key, variants] of homoglyphMap) {
          if (variants.includes(char)) {
            originalChar = key;
            break;
          }
        }

        // Als het originele karakter niet in de domeinnaam voorkomt, is het een aanval
        if (originalChar && !domainChars.has(originalChar)) {
          logDebug(`Homoglyph-aanval gedetecteerd: ${char} (vervangt ${originalChar}) in ${normalizedDomain}`);
          return true;
        }
      }
    }

    // Controleer op meerdere homoglyphs als extra beveiliging
    const homoglyphCount = (normalizedDomain.match(homoglyphRegex) || []).length;
    if (homoglyphCount > 1) {
      logDebug(`Meerdere homoglyphs gedetecteerd in ${normalizedDomain}: ${homoglyphCount}`);
      return true;
    }

    logDebug(`Geen homoglyph-aanval gedetecteerd in ${normalizedDomain}`);
    return false;
  } catch (error) {
    handleError(error, `isHomoglyphAttack: Fout bij controleren van homoglyph-aanval op domein ${domain}`);
    return false;
  }
}

const nonHttpProtocols = ['mailto:', 'tel:'];

// Cache-definitie buiten de functie met TTL en groottebeheer

const MAX_CACHE_SIZE = 1000; // Maximaal 1000 items in cache
const linkRiskCache = new Map();

function storeInCache(url, result) {
  if (linkRiskCache.size >= MAX_CACHE_SIZE) {
    const oldestKey = linkRiskCache.keys().next().value;
    linkRiskCache.delete(oldestKey);
    logDebug(`Cache size exceeded (${MAX_CACHE_SIZE}), removed oldest entry: ${oldestKey}`);
  }
  linkRiskCache.set(url, { result, timestamp: Date.now() });
  logDebug(`Cached result for ${url}:`, result);
}

async function performSuspiciousChecks(url) {
  const cached = linkRiskCache.get(url);
  if (cached && (Date.now() - cached.timestamp < CACHE_TTL_MS)) {
    logDebug(`Cache hit for suspicious checks: ${url}`);
    return cached.result;
  }

  const isEnabled = await isProtectionEnabled();
  if (!isEnabled) {
    const result = { isSafe: true, reasons: [], risk: 0 };
    storeInCache(url, result);
    return result;
  }

  const reasons = new Set();
  const totalRiskRef = { value: 0 };
  const urlObj = new URL(url);
  const isHttpProtocol = ['http:', 'https:'].includes(urlObj.protocol);

  // Safe domain check
  const domain = normalizeDomain(url); // Gebruik normalizeDomain voor consistente validatie
  const isSafeDomain = safeDomains.some(pattern => new RegExp(pattern).test(domain || ''));

  if (isSafeDomain && domain) {
    reasons.add("safeDomain");
    totalRiskRef.value = 0.1;
    logDebug(`Safe domain detected: ${domain}`);
  }

  if (!isHttpProtocol) {
    logDebug(`Skipping HTTP-specific checks for non-HTTP protocol: ${urlObj.protocol}`);
    if (['mailto:', 'tel:', 'ftp:', 'javascript:'].includes(urlObj.protocol)) {
      reasons.add("allowedProtocol");
      totalRiskRef.value += 0.1;
    }
    if (urlObj.protocol === 'javascript:') {
      reasons.add("javascriptScheme");
      totalRiskRef.value += 5;
    }
  } else if (urlObj.protocol !== 'https:' && domain) {
    reasons.add("noHttps");
    totalRiskRef.value += 15;
    if (isLoginPage(url)) {
      reasons.add("insecureLoginPage");
      totalRiskRef.value += 20;
    }
  }

  // Fast-track voor safeDomain
  if (isSafeDomain && totalRiskRef.value < 10 && domain) {
    logDebug(`Safe domain fast-track applied for ${url}`);
    const result = createAnalysisResult(true, ["safeDomain"], 0.1);
    storeInCache(url, result);
    return result;
  }

  // Statische condities (bestaande functie)
  await checkStaticConditions(url, reasons, totalRiskRef);

  // Extra statische checks
  if (/^\d+\.\d+\.\d+\.\d+$/.test(urlObj.hostname) && domain) {
    reasons.add("ipAsDomain");
    totalRiskRef.value += 5;
  }
  const subdomains = (domain || '').split('.').length - 2;
  if (subdomains > globalConfig.MAX_SUBDOMAINS && !isSafeDomain && domain) {
    reasons.add("tooManySubdomains");
    totalRiskRef.value += 5;
  }
  if (domain && isHomoglyphAttack(domain) && !isSafeDomain) { // Gebruik genormaliseerd domain
    reasons.add("homoglyphAttack");
    totalRiskRef.value += 10;
  }

  // Dynamische condities met jouw bestaande functies
  const dynamicChecks = [
    { func: hasBase64OrHex, messageKey: "base64OrHex", risk: 2.0 },
    { func: isShortenedUrl, messageKey: "shortenedUrl", risk: 4.0 },
    { func: hasEncodedCharacters, messageKey: "encodedCharacters", risk: 3.0 },
    { func: hasUnusualPort, messageKey: "unusualPort", risk: 3.0 },
    { func: hasSuspiciousKeywords, messageKey: "suspiciousKeywords", risk: 3.0 },
    { func: hasSuspiciousPattern, messageKey: "suspiciousPattern", risk: 4.0 },
    { func: isDownloadPage, messageKey: "downloadPage", risk: 5.0 },
    { func: usesUrlFragmentTrick, messageKey: "urlFragmentTrick", risk: 3.0 },
    { func: isCryptoPhishingUrl, messageKey: "cryptoPhishing", risk: 10.0 },
    ...(isHttpProtocol ? [
      { func: checkForSuspiciousExternalScripts, messageKey: "externalScripts", risk: 4.0 },
      { func: hasSuspiciousIframes, messageKey: "suspiciousIframes", risk: 3.5 },
    ] : []),
  ];

  for (const { func, messageKey, risk } of dynamicChecks) {
    try {
      const result = await func(url);
      if (func === hasBase64OrHex || func === isShortenedUrl || func === hasEncodedCharacters || 
          func === hasUnusualPort || func === hasSuspiciousKeywords || func === hasSuspiciousPattern || 
          func === isDownloadPage || func === usesUrlFragmentTrick || func === isCryptoPhishingUrl) {
        if (result === true && domain) {
          reasons.add(messageKey);
          totalRiskRef.value += risk;
          logDebug(`Added ${messageKey} with risk ${risk} for ${url}`);
        }
      } else {
        if (result && Array.isArray(result) && result.length > 0 && domain) {
          result.forEach(({ reason, risk: subRisk }) => reasons.add(reason));
          totalRiskRef.value += risk;
          logDebug(`Added ${messageKey} with risk ${risk} for ${url}, reasons: ${result.map(r => r.reason).join(', ')}`);
        }
      }
    } catch (error) {
      handleError(error, `performSuspiciousChecks (${messageKey})`);
    }
  }

  // Laatste safeDomain override
  if (isSafeDomain && totalRiskRef.value < 10 && domain) {
    logDebug(`Safe domain override applied for ${url}`);
    totalRiskRef.value = 0.1;
    reasons.clear();
    reasons.add("safeDomain");
  }

  const isSafe = totalRiskRef.value < (globalConfig.RISK_THRESHOLD || 5);
  const result = createAnalysisResult(isSafe, Array.from(reasons), totalRiskRef.value);
  storeInCache(url, result);
  return result;
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

function checkStaticConditions(url, reasons, totalRiskRef) {
  const urlObj = new URL(url);
  const domain = urlObj.hostname.toLowerCase();

  if (safeDomains.some(pattern => new RegExp(pattern).test(domain))) {
    logDebug(`Safe domain detected: ${domain}`);
    reasons.add("safeDomain");
    totalRiskRef.value = 0.1;
  }

  const allowedProtocols = ['ftp:', 'data:', 'javascript:'];
  if (allowedProtocols.includes(urlObj.protocol)) {
    logDebug(`Allowed protocol detected: ${urlObj.protocol}`);
    reasons.add("allowedProtocol");
    totalRiskRef.value = 0.1;
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

  // Bereken het aantal subdomeinen met compound TLD-ondersteuning
  const compoundTLDs = globalConfig.COMPOUND_TLDS || [];
  let effectiveSubdomains = domain.split(".");
  let tldLength = 1; // Standaard TLD-lengte (bijv. .com)
  compoundTLDs.forEach(compoundTLD => {
    if (domain.endsWith(`.${compoundTLD}`) || domain === compoundTLD) {
      tldLength = compoundTLD.split(".").length; // Bijv. 2 voor .co.uk
    }
  });
  const subdomainCount = effectiveSubdomains.length - tldLength;

  const domainChecks = [
    { condition: globalConfig.SUSPICIOUS_TLDS.test(domain), weight: 6, reason: "suspiciousTLD" },
    { condition: /^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$/.test(domain), weight: 5, reason: "ipAsDomain" },
    { 
      condition: !isIpAddress(url) && subdomainCount > globalConfig.MAX_SUBDOMAINS, 
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

  if (globalConfig.legitimateDomains && globalConfig.domainRiskWeights) {
    for (const legitDomain of globalConfig.legitimateDomains) {
      const distance = levenshteinDistance(domain, legitDomain);
      if (distance > 0 && distance <= 2) { // Vergelijkbaar maar niet identiek
        const riskWeight = globalConfig.domainRiskWeights[legitDomain] || 1;
        reasons.add(`similarToLegitimateDomain: ${legitDomain}`);
        totalRiskRef.value += riskWeight;
        logDebug(`Domein ${domain} lijkt op ${legitDomain} met afstand ${distance}, risicogewicht ${riskWeight}`);
        break; // Stop na de eerste match
      }
    }
  }
}

async function checkDynamicConditions(url, reasons, totalRiskRef) {
  const urlObj = new URL(url);
  const isHttpProtocol = ['http:', 'https:'].includes(urlObj.protocol);

  const dynamicChecks = [
    { func: isIpAddress, messageKey: "ipAsDomain", risk: 5 },
    { func: hasMultipleSubdomains, messageKey: "tooManySubdomains", risk: 5.0 },
    { func: hasSuspiciousKeywords, messageKey: "suspiciousKeywords", risk: 2.0 },
    { func: hasSuspiciousUrlPattern, messageKey: "suspiciousPattern", risk: 3.0 },
    { func: isShortenedUrl, messageKey: "shortenedUrl", risk: 4.0 },
    ...(isHttpProtocol ? [
      { func: isDownloadPage, messageKey: "downloadPage", risk: 3.5 },
      { func: checkForSuspiciousExternalScripts, messageKey: "externalScripts", risk: 4.0 },
      { func: hasMetaRedirect, messageKey: "metaRedirect", risk: 4.0 },
      // Verwijder hasSuspiciousIframes uit dynamicChecks, want het zit nu in performSuspiciousChecks
    ] : []),
    { func: isFreeHostingDomain, messageKey: "freeHosting", risk: 5 },
    { func: hasEncodedCharacters, messageKey: "encodedCharacters", risk: 3.0 },
    { func: hasBase64OrHex, messageKey: "base64OrHex", risk: 2.0 },
    { func: isHomoglyphAttack, messageKey: "homoglyphAttack", risk: 2.0 },
    { func: isCryptoPhishingUrl, messageKey: "cryptoPhishing", risk: 5 },
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
        logDebug(`Added reason '${messageKey}' with risk ${risk} for ${url}`);
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

    if (!shortenedDomains.has(domain)) {
      logDebug(`No shortener detected for: ${url}`);
      shortenedUrlCache.set(url, false);
      return false;
    }

    logDebug(`Detecting shortened URL: ${url}`);
    const finalUrl = await resolveShortenedUrlWithRetry(url);
    const result = finalUrl === url || shortenedDomains.has(domain); // Vertrouw op domein als fetch faalt

    if (shortenedUrlCache.size >= MAX_CACHE_SIZE) {
      shortenedUrlCache.clear();
      logDebug("Cache limiet bereikt, cache gereset.");
    }
    shortenedUrlCache.set(url, result);
    return result;
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

function hasEncodedCharacters(url) {
  try {
    const urlObj = new URL(url);
    const path = urlObj.pathname;
    const query = urlObj.search;
    const encodedCharPattern = /%[0-9A-Fa-f]{2}/g;
    const totalEncodedCount = (path.match(encodedCharPattern) || []).length + (query.match(encodedCharPattern) || []).length;
    return totalEncodedCount > 0; // Detecteer zelfs één encoded karakter
  } catch (error) {
    handleError(error, `hasEncodedCharacters: Fout bij controleren van gecodeerde tekens voor URL ${url}`);
    return false;
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

function detectLoginPage(url) {
  try {
    const loginPatterns = /(login|signin|wp-login|authenticate|account)/i;
    const urlIndicatesLogin = loginPatterns.test(url);
    const hasPasswordField = !!document.querySelector('input[type="password"]');
    logDebug(`Login detection: URL indication: ${urlIndicatesLogin}, Password field: ${hasPasswordField}`);
    return urlIndicatesLogin || hasPasswordField;
  } catch (error) {
    handleError(error, `detectLoginPage: Fout bij detecteren van loginpagina voor URL ${url}`);
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
    handleError(error, `isFreeHostingDomain: Fout bij controleren van gratis hostingdomein voor URL ${url}`);
    return true;
  }
}


function isCryptoPhishingUrl(url) {
  const officialDomains = (globalConfig && globalConfig.CRYPTO_DOMAINS) || [];
  const cryptoBrands = officialDomains.map(domain => domain.split('.')[0].toLowerCase());
  const cryptoKeywords = [
    'crypto', 'bitcoin', 'btc', 'eth', 'ether', 'wallet', 'coin', 'token', 'blockchain', 'ledger', 'exchange', 'airdrop'
  ];

  // Strengere patronen die een crypto-context vereisen
  const suspiciousPatterns = [
    /^(?:secure|auth|verify|2fa|locked)-?(?:wallet|crypto|coin|exchange|token|account)$/i, // Bijv. secure-wallet, auth-token
    /wallet[-_]?connect/i, // wallet-connect of wallet_connect
    /crypto[-_]?auth/i,    // crypto-auth of crypto_auth
    /(?:free|earn|claim|bonus)[-_]?(?:crypto|bitcoin|btc|eth|coin)/i, // free-crypto, earn-bitcoin
    /airdrop[-_]?(?:crypto|coin|token)/i, // airdrop-crypto
    new RegExp(`(?:2fa|verify)[-_]?(?:${cryptoBrands.join('|')})`, 'i'), // 2fa-binance, verify-kraken
  ];

  try {
    const urlObj = new URL(url);
    const hostname = urlObj.hostname.toLowerCase();
    const fullPath = `${hostname}${urlObj.pathname}`.toLowerCase();

    // Controleer of het een officieel domein is
    if (officialDomains.some(domain => hostname === domain || hostname.endsWith(`.${domain}`))) {
      logDebug(`Safe: Official crypto domain detected (${hostname})`);
      return false;
    }

    // Controleer op lookalike-domeinen (met minimale gelijkenis-drempel)
    const isLookalike = officialDomains.some(domain => {
      const brand = domain.split('.')[0];
      const distance = levenshteinDistance(hostname, domain);
      return hostname.includes(brand) && hostname !== domain && distance <= 3; // Max 3 tekens verschil
    });
    if (isLookalike) {
      logDebug(`Suspicious: Lookalike crypto domain detected (${hostname})`);
      return true;
    }

    // Controleer op crypto-specifieke patronen EN keywords
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
    return false; // Conservatieve fallback bij ongeldige URL
  }
}

function hasMetaRedirect() {
  const metaTag = document.querySelector("meta[http-equiv='refresh']");
  return Boolean(metaTag && /^\s*\d+\s*;\s*url=/i.test(metaTag.getAttribute("content")));
}


document.addEventListener('DOMContentLoaded', async () => {
  try {
    logDebug("🚀 Initializing content script...");
    await initContentScript();

    const currentUrl = window.location.href;
    logDebug(`🔍 Checking the current page: ${currentUrl}`);

    // Controleer of het een login-pagina is
    const isLogin = detectLoginPage(currentUrl);
    if (isLogin) {
      chrome.runtime.sendMessage({
        type: "checkResult",
        url: currentUrl,
        isSafe: false,
        risk: 7,
        reasons: ["insecureLoginPage"]
      });
      logDebug(`❌ Login page detected: ${currentUrl}`);
    } else {
      // Directe controle uitvoeren bij laden van de pagina als het geen login-pagina is
      const result = await performSuspiciousChecks(currentUrl);
      const isSafe = result.reasons.length === 0; // Voorkom false positives
      chrome.runtime.sendMessage({
        type: "checkResult",
        url: currentUrl,
        isSafe,
        risk: result.risk,
        reasons: result.reasons
      });
      logDebug(`✅ Check complete: isSafe=${isSafe}, risk=${result.risk}, reasons=${result.reasons.join(", ")}`);
    }
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
    currentDomain = new URL(currentUrl).hostname;
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

  const MAX_LINKS_TO_SCAN = 1000;
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

    const linkDomain = urlObj.hostname;
    if (linkDomain === currentDomain || linkDomain.endsWith(`.${currentDomain}`)) {
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
  if (!(await isProtectionEnabled())) return;
  mutations.forEach(mutation => {
    mutation.addedNodes.forEach(node => {
      if (node.nodeType !== Node.ELEMENT_NODE) return;
      if (node.tagName === "SCRIPT") {
        checkForSuspiciousExternalScripts();
      } else if (node.tagName === "IFRAME") {
        hasSuspiciousIframes();
      } else if (node.tagName === "A" && isValidURL(node.href)) {
        classifyAndCheckLink(node);
      } else {
        node.querySelectorAll('a').forEach(link => {
          if (isValidURL(link.href)) classifyAndCheckLink(link);
        });
      }
    });
  });
}, 500));

setInterval(async () => {
  if (!(await isProtectionEnabled())) return;
  await checkForSuspiciousExternalScripts();
  await hasSuspiciousIframes();
}, 5000);


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
  if (!(await isProtectionEnabled())) return;

  // Controleer of link en href bestaan en geldig zijn
  if (!link || !link.href || !isValidURL(link.href)) {
    logDebug(`Skipping unifiedCheckLinkSafety: Invalid or missing URL in link: ${link.href || 'undefined'}`);
    return;
  }

  // Extra controle voor SVG-links
  if (link.ownerSVGElement || link.href instanceof SVGAnimatedString) {
    const hrefValue = link.href instanceof SVGAnimatedString ? link.href.baseVal : link.href;
    logDebug(`Skipping SVG link: ${hrefValue || 'undefined'} (ownerSVGElement: ${!!link.ownerSVGElement}, SVGAnimatedString: ${link.href instanceof SVGAnimatedString})`);
    return;
  }

  const href = link.href;
  if (processedLinks.has(href)) return; // Sla eerder verwerkte links over
  processedLinks.add(href);
  setTimeout(() => processedLinks.delete(href), 2000); // Verwijder na 2 seconden

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
          event.preventDefault(); // Blokkeer klik als de link niet veilig is
        } else {
          event.preventDefault();
          window.location.href = href; // Ga door als veilig
        }
      }
    }
  } catch (error) {
    handleError(error, `unifiedCheckLinkSafety: Fout bij controleren van link ${href} op event ${eventType}`);
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