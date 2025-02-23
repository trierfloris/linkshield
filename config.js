window.CONFIG = {
    // Suspicious Top-Level Domains (TLDs)
    SUSPICIOUS_TLDS: /\.(academy|accountant|accountants|agency|ap|app|art|asia|auto|bank|bar|beauty|bet|bid|bio|biz|blog|buzz|cam|capital|casa|casino|cfd|charity|cheap|church|city|claims|click|club|company|crispsalt|cyou|data|date|design|dev|digital|directory|download|email|energy|estate|events|exchange|expert|exposed|express|finance|fit|forsale|foundation|fun|games|gle|goog|gq|guide|guru|health|help|home|host|html|icu|ink|institute|investments|ip|jobs|life|limited|link|live|loan|lol|ltd|ly|mall|market|me|media|men|ml|mom|money|monster|mov|network|one|online|page|partners|party|php|pics|play|press|pro|promo|pw|quest|racing|rest|review|rocks|run|sbs|school|science|services|shop|shopping|site|software|solutions|space|store|stream|support|team|tech|tickets|to|today|tools|top|trade|trading|uno|ventures|vip|website|wiki|win|work|world|xin|xyz|zip|zone|co|cc|tv|name|team|live|stream)$/i,

    DEBUG_MODE: false, // Zet op true voor debugging, false voor productie

    // Allowed URL Protocols
    ALLOWED_PROTOCOLS: ['http:', 'https:', 'mailto:', 'tel:', 'ftp:'],

    // Suspicious File Extensions (Uitgebreid met macro-bestanden en meer)
    MALWARE_EXTENSIONS: /\.(exe|zip|bak|tar|gz|msi|dmg|jar|rar|7z|iso|bin|scr|bat|cmd|sh|vbs|lnk|chm|ps2|apk|ps1|py|js|vbscript|dll|docm|xlsm|pptm|doc|xls|ppt|rtf|torrent|wsf|hta|jse|reg|swf|svg)$/i,

    // Keywords for Suspicious Downloads (Uitgebreid)
    DOWNLOAD_KEYWORDS: new Set([
        "download", "install", "setup", "file", "update", "patch", "plugin", 
        "installer", "software", "driver", "execute", "run", "launch", "tool",
        "patcher", "application", "program", "app", "fix", "crack", "keygen",
        "serial", "activation", "license", "trial", "demo", "zip", "archive",
        "compressed", "installer_package", "upgrade", "update_tool", "free",
        "fixer", "repair", "optimizer", "restore", "reset", "unlock", 
        "backup", "configuration", "config", "module", "library", "framework",
        "macro", "enable", "torrent", "seed", "payload", "exploit", "dropper",
        "loader", "package", "binary", "release", "beta", "mod", "hack"
    ]),

    // Phishing Keywords (Uitgebreid)
    PHISHING_KEYWORDS: new Set([
        "access", "account", "auth", "blocked", "bonus", "captcha", "claim", "click", "credentials", "free", "gift",
        "login", "notification", "pay", "pending", "prize", "recover", "secure", "signin", "unlock", "unusual",
        "update", "urgent", "validate", "verify", "win", "password", "bank", "security", "alert", "suspended",
        "confirm", "identity", "renew", "subscription", "billing", "refund", "delivery", "tracking", "survey",
        "reward", "promo", "deal", "offer", "urgent-action", "reset", "phishing", "scan", "qr", "qrcode"
    ]),

    // Suspicious Keywords for Iframes (Uitgebreid)
    SUSPICIOUS_IFRAME_KEYWORDS: /(malicious|phish|track|adserver|spy|exploit|redirect|inject|unsafe|popup|banner|ads|clickjacking|overlay|hidden|cloak)/i,

    // Cache Duration (in milliseconds)
    CACHE_DURATION_MS: 24 * 60 * 60 * 1000, // 24 hours

    // Default Thresholds
    SUSPICION_THRESHOLD: 0.1, // 10% of links must be suspicious

    // Trusted Iframe Domains
    TRUSTED_IFRAME_DOMAINS: ['youtube.com', 'vimeo.com', 'google.com'],

    // Login Patterns (Uitgebreid)
    LOGIN_PATTERNS: /(login|account|auth|authenticate|signin|wp-login|sign-in|log-in|dashboard|portal|session|user|profile)/i,

    // Free Hosting Domains (Uitgebreid)
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

    // Shortened URL Domains (Uitgebreid)
    SHORTENED_URL_DOMAINS: [
        "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly", "su.pr", "tiny.cc", "x.co", "rebrand.ly",
        "mcaf.ee", "po.st", "adf.ly", "cutt.ly", "qrco.de", "yourls.org", "shrtco.de", "chilp.it", "clck.ru", "rb.gy",
        "shorturl.at", "lnkd.in", "shorte.st", "cli.re", "surl.li", "tny.im", "zi.ma", "t1p.de", "urlz.fr", "did.li",
        "v.ht", "short.cm", "bit.do", "t.ly", "4gp.me", "linktr.ee", "tiny.ie", "1url.com", "hyperurl.co", "lnk.to",
        "snip.ly", "flip.to", "adcrun.ch", "short.to", "t.co.uk", "kutt.it", "flic.kr", "qr.net", "trk.li", "smll.co",
        "xurl.es", "xup.pl", "b.link", "x.gd", "n9.cl", "zi.pe", "qr.ae", "0rz.tw", "qqc.co", "h6y.eu",
        "fw.to", "lnk2.me", "shurl.net", "mrk.to", "clk.im", "u.to", "ezurl.cc", "fur.ly", "v.gd", "2ty.cc", "sh.ky",
        "s.coop", "cutt.us", "bitly.com", "q.gs", "i.cut", "s.id", "linklyhq.com", "slkt.io", "pp.gg", "short.url",
        "zpr.io", "me.qr", "short.io", "dub.co", "cl.ly", "bl.ink", "go.ly", "soo.gd", "jmp.sh", "u.nu"
    ],

    // Suspicious URL Patterns (Uitgebreid met QR-codes en meer)
    SUSPICIOUS_URL_PATTERNS: [
        /\/(payment|invoice|billing|money|bank|secure|login|checkout|subscription|refund|delivery)\//i,
        /(Base64|hexadecimal|b64|encode|urlencode|obfuscate|crypt)/i,
        /\/(signup|register|confirmation|securepayment|order|tracking|verify-account|reset-password|oauth)\//i,
        /(?:\bsecurepay\b|\baccountverify\b|\bresetpassword\b|\bverifyemail\b|\bupdateinfo\b)/i,
        /(qr-code|qrcode|qr\.|generate-qr|scan|qrserver|qrcodes\.)/i, // QR-code detectie
        /(fake|clone|spoof|impersonate|fraud|scam|phish)/i, // Typosquatting en fraudepatronen
        /[^a-zA-Z0-9]{2,}/, // Verdachte niet-alfanumerieke reeksen (bijv. "--" of "==")
        /(http[s]?:\/\/[^\/]+){2,}/i // Meerdere redirects in URL
    ],

    // Suspicious Script Patterns (Uitgebreid met WebRTC en meer)
    SUSPICIOUS_SCRIPT_PATTERNS: [
        /(?:base64_decode|base64_encode|rot13|hex|md5|sha1|sha256|xor|hash|eval64|obfuscate)/i,
        /(?:document\.write|eval|Function|setTimeout|setInterval|atob|btoa|escape|unescape|innerHTML|outerHTML|appendChild|insertBefore|replaceChild|removeChild|location\.href|window\.location|localStorage|sessionStorage|XMLHttpRequest|fetch|WebSocket|prototype\.call|Object\.defineProperty|new Function)/i,
        /(?:download|execute|payload|install|load|unpack|update|patch|plugin|setup|plugin\.js|install\.js|update\.js|loader\.js|miner\.js|coinimp|cryptonight|wasm)/i,
        /(?:iframe|srcdoc|data:text\/html|javascript:|onload|onerror|onclick|onsubmit|onmouseover|onfocus|onblur|onchange|onscroll|onkeydown|onkeyup|onkeypress)/i,
        /(?:malicious|unsafe|tracker|adserver|spy|hack|exploit|virus|malware|phish|redirect|inject|clickjacking|xss|keylogger|trojan|worm|ransomware|payload|obfuscated|obfuscate|backdoor|rootkit|sqlinjection|sqli|bufferoverflow|overflow|csrf|cryptojacking|mining)/i,
        /(RTCPeerConnection|RTCDataChannel|mozRTCPeerConnection|webkitRTCPeerConnection|iceCandidate|peerconnection|stun:|turn:)/i, // WebRTC detectie
        /(navigator\.geolocation|navigator\.permissions|navigator\.mediaDevices|Clipboard|ServiceWorker|PushManager|WebAssembly)/i, // Verdachte API-aanroepen
        /\.(php|asp|cgi|exe|bin|dll|dat|py|sh|vb|vbs|cmd|bat|pl|ps1|psm1|jar|class|js|jsp|aspx|cfm|rb|ts|mjs|apk|swift|go|lua|wasm)$/i,
        /script|eval/i
    ],

    ALLOWED_PATHS: [/\/products\/|\/account\/billing\/|\/plans\/|\/support\/|\/docs\//i],
    ALLOWED_QUERY_PARAMS: [/eventId|referrer|utm_|lang|theme/i],

    // Crypto Domains (Uitgebreid)
    CRYPTO_DOMAINS: [
        "binance.com", "kraken.com", "metamask.io", "wallet-connect.org", "coinbase.com", "bybit.com", "okx.com", 
        "kucoin.com", "hashkey.com", "binance.us", "global.hashkey.com", "bitget.com", "gate.io", "huobi.com", "bingx.com", 
        "bitfinex.com", "luno.com", "backpack.exchange", "woox.io", "mexc.com", "bitmart.com", "lbank.com", "coinw.com", 
        "crypto.com", "p2pb2b.com", "bitunix.com", "bigone.com", "azbit.com", "pionex.com", "coinstore.com", "coinex.com", 
        "exchange.fastex.com", "dex-trade.com", "links.bitstamp.net", "gemini.com", "phemex.com", "exmo.com", "bitkub.com", 
        "arkm.com", "bitso.com", "deribit.com", "bitcastle.io", "bitopro.com", "xeggex.com", "coins.ph", "bitcointry.com", 
        "emirex.com", "upbit.com", "digifinex.com", "bithumb.com", "xt.com", "toobit.com", "latoken.com", "bvox.com", 
        "weex.com", "ascendex.com", "biconomy.com", "hibt.com", "bitrue.com", "bitvavo.com", "btse.com", 
        "exchange.pointpay.io", "qmall.io", "bitflyer.com", "coincheck.com", "paribu.com", "slex.io", "bitbank.cc", 
        "bitdelta.com", "blofin.com", "kanga.exchange", "korbit.co.kr", "trade.cex.io", "nonkyc.io", "tokenize.exchange", 
        "foxbit.com.br", "independentreserve.com", "coindcx.com", "bitmex.com", "app.uniswap.org", "hotcoin.com", 
        "fameex.com", "tapbit.com", "deepcoin.com", "bydfi.com", "trubit.com", "pancakeswap.finance", "app.cetus.zone", 
        "coin.z.com", "bitci.com.tr", "fmfw.io", "bitstorage.finance", "ledger.com", "trezor.io", "ellipal.com", 
        "safepal.io", "shapeshift.com", "shiftcrypto.ch", "coldcardwallet.com", "dcentwallet.com", "secuxtech.com", 
        "gridplus.io", "coingecko.com", "coinmarketcap.com", "cryptoslate.com", "theblock.co", "decrypt.co", "coindesk.com", 
        "bitcoin.org", "messari.io", "cryptocompare.com", "glassnode.com", "tradingview.com", "bitinfocharts.com", 
        "blockchain.com", "etherscan.io", "phantom.app", "trustwallet.com", "keplr.app", "cosmostation.io", "solflare.com",
        "opensea.io", "rarible.com", "sushi.com", "curve.fi", "balancer.fi", "1inch.io", "raydium.io"
    ],

    // Homoglyphs Mapping (Ongewijzigd, maar kan worden uitgebreid met meer Unicode-tekens)
    HOMOGLYPHS: {
        'a': ['а', 'α', 'ⱥ', 'ä', 'å', 'á', 'à', 'â', 'ã', 'ā', 'ă', 'ǎ', 'ȁ', 'ȃ', 'ǻ', 'ª'],
        'e': ['е', 'ε', 'ë', 'ē', 'ĕ', 'ė', 'ę', 'ě', 'ê', 'è', 'é', 'ȅ', 'ȇ', '€', 'ɛ'],
        'o': ['ο', 'о', 'ö', 'ó', 'ò', 'ô', 'õ', 'ō', 'ŏ', 'ő', 'ø', 'ǒ', 'ȍ', 'ȏ', 'º'],
        'i': ['і', 'í', 'ì', 'î', 'ï', 'ī', 'ĭ', 'į', 'ǐ', 'ɨ', 'ı', '¡'],
        's': ['ѕ', 'ß', '$', 'ś', 'ŝ', 'ş', 'š', '§', 'ʃ'],
        'c': ['с', 'ç', '¢', 'ć', 'ĉ', 'ċ', 'č', '©', 'ȼ', 'ƈ'],
        'd': ['ԁ', 'đ', 'ď', 'ḋ', 'ḍ', 'ḏ', 'ḑ', 'ḓ', 'ɖ'],
        'g': ['ɡ', 'ġ', 'ğ', 'ĝ', 'ǧ', 'ģ', 'ǥ', 'ɢ'],
        'h': ['һ', 'ħ', 'ĥ', 'ḥ', 'ḧ', 'ḩ', 'ḫ', 'ɦ'],
        'k': ['κ', 'ќ', 'ḱ', 'ǩ', 'ķ', 'ḳ', 'ḵ', 'ƙ'],
        'l': ['ӏ', 'Ɩ', 'ĺ', 'ļ', 'ľ', 'ŀ', 'ł', 'Ɨ', 'ǀ'],
        'n': ['п', 'ñ', 'ń', 'ņ', 'ň', 'ŉ', 'ŋ', 'ṅ', 'ṇ', 'ṉ', 'ƞ'],
        'p': ['р', 'ƿ', 'ṕ', 'ṗ', 'ƥ', '℗'],
        't': ['τ', 'т', 'ţ', 'ť', 'ŧ', 'ṭ', 'ṯ', 'ṱ', 'ƭ', '†'],
        'u': ['υ', 'ц', 'ü', 'ú', 'ù', 'û', 'ū', 'ŭ', 'ů', 'ű', 'ų', 'ǔ', 'ȕ', 'ȗ', 'µ'],
        'x': ['х', '×', 'ẋ', 'ẍ', 'χ'],
        'y': ['у', 'ý', 'ÿ', 'ŷ', 'ȳ', '¥', 'ƴ', 'ɏ'],
        'z': ['ž', 'ƶ', 'ź', 'ż', 'ẑ', 'ẓ', 'ẕ', 'ƹ', 'ɀ']
    },

    // Nieuwe Detectie: Verdachte E-mailpatronen
    SUSPICIOUS_EMAIL_PATTERNS: [
        /noreply@.*\.(xyz|top|club|online|site)/i, // Verdachte noreply-domeinen
        /(support|admin|security|billing)@.*\.(co|cc|info|biz)/i, // Veelgebruikte phishing-adressen
        /[^@]+@[^@]+\.[a-z]{2,}$/i, // Algemene e-mailcheck (combineer met andere indicatoren)
        /\b(free|win|urgent|verify|login)@.*$/i // Phishing-trefwoorden in e-mailadres
    ],

    // Nieuwe Detectie: Typosquatting Indicatoren
    TYPOSQUATTING_PATTERNS: [
        /(g00gle|go0gle|goggle|paypa1|paypall|faceb00k|facbook|tw1tter|twiiter|amaz0n|amzon|micr0soft|micsoft)/i, // Bekende merken met fouten
        /(.)\1{2,}/, // Herhalende tekens (bijv. "goooogle")
        /xn--/, // IDN-domeinen (punycode, vaak gebruikt voor homoglyphs)
        /\d{1,2}[a-z]{2,}/i // Nummer-lettercombinaties (bijv. "bank123")
    ]
};