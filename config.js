window.CONFIG = {
    // Verdachte Top-Level Domeinen (TLD’s)
    SUSPICIOUS_TLDS: /\.(academy|accountant|accountants|agency|ap|app|art|asia|auto|bank|bar|beauty|bet|bid|bio|biz|blog|buzz|cam|capital|casa|casino|cfd|charity|cheap|church|city|claims|click|club|company|crispsalt|cyou|data|date|design|dev|digital|directory|download|email|energy|estate|events|exchange|expert|exposed|express|finance|fit|forsale|foundation|fun|games|gle|goog|gq|guide|guru|health|help|home|host|html|icu|ink|institute|investments|ip|jobs|life|limited|link|live|loan|lol|ltd|ly|mall|market|me|media|men|ml|mom|money|monster|mov|network|one|online|page|partners|party|php|pics|play|press|pro|promo|pw|quest|racing|rest|review|rocks|run|sbs|school|science|services|shop|shopping|site|software|solutions|space|store|stream|support|team|tech|tickets|to|today|tools|top|trade|trading|uno|ventures|vip|website|wiki|win|work|world|xin|xyz|zip|zone|co|cc|tv|name|team|live|stream|quest|sbs|lat|click|monster|bond|cyou|store|crypto|wallet|quantum|nft|web3|metaverse|ai|vr|dao|health|green|privacy|smart)$/i,

    // Debug Modus
    DEBUG_MODE: false, // Zet op true voor debugging, false voor productie

    // Toegestane URL Protocollen
    ALLOWED_PROTOCOLS: ['http:', 'https:', 'mailto:', 'tel:', 'ftp:'],

    // Verdachte Bestandsextensies
    MALWARE_EXTENSIONS: /\.(exe|zip|bak|tar|gz|msi|dmg|jar|rar|7z|iso|bin|scr|bat|cmd|sh|vbs|lnk|chm|ps2|apk|ps1|py|js|vbscript|dll|docm|xlsm|pptm|doc|xls|ppt|rtf|torrent|wsf|hta|jse|reg|swf|svg|lnk|chm|wsh|pif|wasm)$/i,

    // Trefwoorden voor Verdachte Downloads
    DOWNLOAD_KEYWORDS: new Set([
        "download", "install", "setup", "file", "update", "patch", "plugin", 
        "installer", "software", "driver", "execute", "run", "launch", "tool",
        "patcher", "application", "program", "app", "fix", "crack", "keygen",
        "serial", "activation", "license", "trial", "demo", "zip", "archive",
        "compressed", "installer_package", "upgrade", "update_tool", "free",
        "fixer", "repair", "optimizer", "restore", "reset", "unlock", 
        "backup", "configuration", "config", "module", "library", "framework",
        "macro", "enable", "torrent", "seed", "payload", "exploit", "dropper",
        "loader", "package", "binary", "release", "beta", "mod", "hack",
        "crack", "keygen", "serial", "unlocker", "generator", "premium",
        "ai", "quantum", "crypto", "wallet", "blockchain", "ledger", "metaverse", 
        "deepfake", "nft", "web3", "ar", "chatbot", "voice", "biometric", "zero-trust",
        "colleague", "team", "meeting", "urgent-call", "generated", "synthetic", "prompt", 
        "telehealth", "healthcare", "prescription", "patient",
        "model", "train", "inference", "simulate", "dynamic", "privacy", "secure-chat", 
        "federated", "anonymous", "green", "eco", "sustainable", "carbon",
        "adaptive", "personalize", "targeted", "behavior", "profile", "social", "data", 
        "custom", "smart", "city", "iot", "urban" // Nieuwe trefwoorden
    ]),

    // Phishing Trefwoorden
    PHISHING_KEYWORDS: new Set([
        "access", "account", "auth", "blocked", "bonus", "captcha", "claim", "click", "credentials", "free", "gift",
        "login", "notification", "pay", "pending", "prize", "recover", "secure", "signin", "unlock", "unusual",
        "update", "urgent", "validate", "verify", "win", "password", "bank", "security", "alert", "suspended",
        "confirm", "identity", "renew", "subscription", "billing", "refund", "delivery", "tracking", "survey",
        "reward", "promo", "deal", "offer", "urgent-action", "reset", "phishing", "scan", "qr", "qrcode",
        "urgent", "confirm", "alert", "suspended", "billing", "invoice", "2fa", "mfa", "otp", "verification",
        "authenticator", "token", "code", "ai", "quantum", "crypto", "wallet", "blockchain", "ledger", "metaverse", 
        "deepfake", "nft", "web3", "ar", "chatbot", "voice", "biometric", "zero-trust",
        "colleague", "team", "meeting", "urgent-call", "generated", "synthetic", "prompt", 
        "telehealth", "healthcare", "prescription", "patient",
        "model", "train", "inference", "simulate", "dynamic", "privacy", "secure-chat", 
        "federated", "anonymous", "green", "eco", "sustainable", "carbon",
        "adaptive", "personalize", "targeted", "behavior", "profile", "social", "data", 
        "custom", "smart", "city", "iot", "urban" // Nieuwe trefwoorden
    ]),

    // Verdachte Iframe Trefwoorden
    SUSPICIOUS_IFRAME_KEYWORDS: /(malicious|phish|track|adserver|spy|exploit|redirect|inject|unsafe|popup|banner|ads|clickjacking|overlay|hidden|cloak|fake-login|overlay-login)/i,

    // Cache Duur (in milliseconden)
    CACHE_DURATION_MS: 24 * 60 * 60 * 1000, // 24 uur

    // Standaard Drempelwaarden
    SUSPICION_THRESHOLD: 0.1, // 10% van de links moet verdacht zijn

    // Vertrouwde Iframe Domeinen
    TRUSTED_IFRAME_DOMAINS: ['youtube.com', 'vimeo.com', 'google.com'],

    // Inlogpatronen
    LOGIN_PATTERNS: /(login|account|auth|authenticate|signin|wp-login|sign-in|log-in|dashboard|portal|session|user|profile)/i,

    // Gratis Hosting Domeinen
    FREE_HOSTING_DOMAINS: [
        'sites.net', 'angelfire.com', 'geocities.ws', '000a.biz', '000webhostapp.com', 'weebly.com', 'wixsite.com', 
        'freehosting.com', 'glitch.me', 'firebaseapp.com', 'herokuapp.com', 'freehostia.com', 'netlify.app', 'webs.com', 
        'yolasite.com', 'github.io', 'bravenet.com', 'zyro.com', 'altervista.org', 'tripod.com', 'jimdo.com', 'ucoz.com', 
        'blogspot.com', 'square.site', 'pages.dev', 'r2.dev', 'mybluehost.me', '000space.com', 'awardspace.com', 
        'byethost.com', 'biz.nf', 'hyperphp.com', 'infinityfree.net', '50webs.com', 'tripod.lycos.com', 'site123.me', 
        'webflow.io', 'strikingly.com', 'x10hosting.com', 'freehostingnoads.net', '000freewebhost.com', 'mystrikingly.com', 
        'sites.google.com', 'appspot.com', 'vercel.app', 'weeblysite.com', 's3.amazonaws.com', 'bubbleapps.io', 
        'typedream.app', 'codeanyapp.com', 'carrd.co', 'surge.sh', 'replit.dev', 'fly.dev', 'render.com', 'onrender.com',
        'netlify.app', 'vercel.app', 'fly.io', 'workers.dev'
    ],

    // Verkorte URL Domeinen
    SHORTENED_URL_DOMAINS: [
        "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly", "su.pr", "tiny.cc", "x.co", "rebrand.ly",
        "mcaf.ee", "po.st", "adf.ly", "cutt.ly", "qrco.de", "yourls.org", "shrtco.de", "chilp.it", "clck.ru", "rb.gy",
        "shorturl.at", "lnkd.in", "shorte.st", "cli.re", "surl.li", "tny.im", "zi.ma", "t1p.de", "urlz.fr", "did.li",
        "v.ht", "short.cm", "bit.do", "t.ly", "4gp.me", "linktr.ee", "tiny.ie", "1url.com", "hyperurl.co", "lnk.to",
        "snip.ly", "flip.to", "adcrun.ch", "short.to", "t.co.uk", "kutt.it", "flic.kr", "qr.net", "trk.li", "smll.co",
        "xurl.es", "xup.pl", "b.link", "x.gd", "n9.cl", "zi.pe", "qr.ae", "0rz.tw", "qqc.co", "h6y.eu",
        "fw.to", "lnk2.me", "shurl.net", "mrk.to", "clk.im", "u.to", "ezurl.cc", "fur.ly", "v.gd", "2ty.cc", "sh.ky",
        "s.coop", "cutt.us", "bitly.com", "q.gs", "i.cut", "s.id", "linklyhq.com", "slkt.io", "pp.gg", "short.url",
        "zpr.io", "me.qr", "short.io", "dub.co", "cl.ly", "bl.ink", "go.ly", "soo.gd", "jmp.sh", "u.nu", "t2m.io", "short.link",
        "tiny.one", "short.link", "shr.link", "linkly.me" // Nieuwe shortener toegevoegd
    ],

    // Verdachte URL Patronen
    SUSPICIOUS_URL_PATTERNS: [
        /\/(payment|invoice|billing|money|bank|secure|login|checkout|subscription|refund|delivery|2fa|mfa|ai|quantum|crypto|wallet|blockchain|ledger|metaverse|deepfake|nft|web3|ar|chatbot|voice|biometric|zero-trust|telehealth|healthcare|prescription|patient|meeting|call|model|privacy|secure-chat|green|eco|sustainable|adaptive|personalize|targeted|social|smart|city|iot)\//i,
        /(Base64|hexadecimal|b64|encode|urlencode|obfuscate|crypt)/i,
        /\/(signup|register|confirmation|securepayment|order|tracking|verify-account|reset-password|oauth)\//i,
        /(?:\bsecurepay\b|\baccountverify\b|\bresetpassword\b|\bverifyemail\b|\bupdateinfo\b)/i,
        /(qr-code|qrcode|qr\.|generate-qr|scan|qrserver|qrcodes\.)/i,
        /(fake|clone|spoof|impersonate|fraud|scam|phish)/i,
        /[^a-zA-Z0-9]{2,}/,
        /(http[s]?:\/\/[^\/]+){2,}/i,
        /\/(chat|ai|machine-learning|quantum|crypto|wallet|blockchain|ledger|metaverse|deepfake|face-swap|nft|web3|ar|chatbot|voice|biometric|zero-trust|telehealth|healthcare|prescription|patient|meeting|call|model|privacy|secure-chat|green|eco|sustainable|adaptive|personalize|targeted|social|smart|city|iot)\//i // Nieuwe detectie voor AI, microtargeting, en smart cities
    ],

    // Verdachte Script Patronen
   SUSPICIOUS_SCRIPT_PATTERNS: [
  /(?:\beval\s*\(\s*['"][^'"]*['"]\s*\)|new\s+Function\s*\(\s*['"][^'"]*['"]\s*\)|base64_decode\s*\()/i,
  /(?:coinimp|cryptonight|webminer|miner\.js|crypto-jacking|keylogger|trojan|worm|ransomware|xss\s*\()/i,
  /(?:document\.write\s*\(\s*['"][^'"]*javascript:|innerHTML\s*=\s*['"][^'"]*eval)/i,
  /(?:fetch\(.+\.wasm[^)]*eval|import\(.+\.wasm[^)]*javascript:)/i,
  /(?:malicious|phish|exploit|redirect|inject|clickjacking|backdoor|rootkit)/i,
  /(?:RTCPeerConnection\s*\(\s*{[^}]*stun:|RTCDataChannel\s*.\s*send\s*\(\s*['"][^'"]*eval)/i,
],

    // Toegestane Paden en Query Parameters
    ALLOWED_PATHS: [/\/products\/|\/account\/billing\/|\/plans\/|\/support\/|\/docs\//i],
    ALLOWED_QUERY_PARAMS: [/eventId|referrer|utm_|lang|theme/i],

    // Crypto Domeinen
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

    // Homoglyphs Mapping
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

    // Verdachte E-mailpatronen
    SUSPICIOUS_EMAIL_PATTERNS: [
        /noreply@.*\.(xyz|top|club|online|site)/i,
        /(support|admin|security|billing)@.*\.(co|cc|info|biz)/i,
        /[^@]+@[^@]+\.[a-z]{2,}$/i,
        /\b(free|win|urgent|verify|login)@.*$/i,
        /ai-support@.*$/i, // Detectie voor AI-gerelateerde phishing-e-mails
        /verify-biometric@.*$/i, // Detectie voor biometrische phishing-e-mails
        /telehealth@.*$/i, // Detectie voor health tech-phishing
        /meeting@.*$/i, // Detectie voor nepvergaderingen
        /privacy@.*$/i, // Detectie voor privacygerichte phishing
        /green@.*$/i, // Detectie voor duurzaamheidsgerichte phishing
        /smart@.*$/i, // Nieuwe detectie voor smart city-phishing
        /social@.*$/i // Nieuwe detectie voor microtargeting-phishing
    ],

    // Typosquatting Patronen
    TYPOSQUATTING_PATTERNS: [
        /(g00gle|go0gle|goggle|gooogle|paypa1|paypall|faceb00k|facbook|tw1tter|twiiter|amaz0n|amzon|amazzon|micr0soft|micsoft|metavers|nftsale|webthree|g0ogle|m1crosoft|amazn|chatb0t)/i,
        /(.)\1{2,}/,
        /xn--/,
        /\d{1,2}[a-z]{2,}/i
    ],

    // Legitieme Domeinen (uitgebreid)
    legitimateDomains: [
        'microsoft.com', 'apple.com', 'google.com', 'linkedin.com', 'alibaba.com',
        'whatsapp.com', 'amazon.com', 'x.com', 'facebook.com', 'adobe.com',
        'paypal.com', 'netflix.com', 'instagram.com', 'outlook.com', 'dropbox.com',
        'opensea.io', 'decentraland.org', 'chat.openai.com', 'auth0.com', 
        'teladoc.com', 'zoom.us', 'signal.org', 'ecosia.org', 
        'smartcityexpo.com' // Nieuwe toevoeging voor smart city-platform
    ],

    COMPOUND_TLDS: [
        'co.uk', 'org.uk', 'gov.uk', 'ac.uk',
        'com.au', 'org.au',
        'co.nz'
    ],

    // Domein Risicogewichten (verfijnd met recente data)
    domainRiskWeights: {
        'microsoft.com': 10,  // Hoog risico: vaak nagebootst in phishing (bijv. Office 365 scams)
        'paypal.com': 8,      // Veel gebruikt in betaalphishing
        'outlook.com': 7,     // Veel voorkomende e-mailphishing
        'apple.com': 6,       // Regelmatige iCloud-phishing
        'google.com': 5,      // Gmail en Google Drive scams
        'linkedin.com': 4,    // Professionele netwerkphishing
        'chat.openai.com': 4, // AI-dienst, populair doelwit voor phishing
        'amazon.com': 3,      // Webshop- en bezorgscams
        'facebook.com': 3,    // Social media phishing
        'instagram.com': 3,   // Accountovername-pogingen
        'opensea.io': 3,      // NFT-marktplaats, populair doelwit voor phishing
        'auth0.com': 3,       // Authenticatieplatform, potentieel risico
        'teladoc.com': 3,     // Health tech-platform, opkomend phishing-doel
        'zoom.us': 3,         // Vergaderplatform, risico op real-time phishing
        'signal.org': 3,      // Privacyplatform, potentieel spoofing-doel
        'netflix.com': 2,     // Abonnementsphishing
        'whatsapp.com': 2,    // Berichtenscams
        'x.com': 2,           // Opkomend risico door populariteit
        'decentraland.org': 2,// Metaverse-platform, potentieel risico
        'ecosia.org': 2,      // Duurzaamheidsplatform, potentieel risico
        'smartcityexpo.com': 2, // Smart city-platform, potentieel risico
        'alibaba.com': 1,     // Minder frequent doelwit
        'adobe.com': 1,       // Lage frequentie
        'dropbox.com': 1      // Lage frequentie, maar potentieel risico
    }
};