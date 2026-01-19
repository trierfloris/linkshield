window.CONFIG = {
    // =============================================================================
    // LINKSHIELD CONFIG - Geüpdatet voor 2026
    // Laatste update: 2026-01-18
    // =============================================================================

    // =============================================================================
    // SCAN QUOTA SETTINGS (v8.4.0)
    // Gratis gebruikers: max 20 unieke domeinen per dag
    // Premium/Trial gebruikers: unlimited
    // =============================================================================
    DAILY_SCAN_QUOTA: 20,           // Max unieke domeinen per dag voor gratis users
    QUOTA_RESET_HOUR_UTC: 0,        // Reset om middernacht UTC

    // Verdachte Top-Level Domeinen (TLD's)
    // Uitgebreid met nieuwe TLD's die in 2025-2026 veel voor phishing worden gebruikt
    // NOTE: .dev, .app, .io VERWIJDERD - dit zijn legitieme Google TLDs gebruikt door developers
    // SECURITY FIX v8.1.1: Vervangen door Set voor O(1) lookup en ReDoS preventie
    SUSPICIOUS_TLDS_SET: new Set([
        // Originele verdachte TLD's
        'beauty', 'bond', 'buzz', 'cc', 'cf', 'club', 'cn', 'es', 'ga', 'gq',
        'hair', 'li', 'live', 'ml', 'mov', 'pro', 'rest', 'ru', 'sbs', 'shop', 'tk',
        'top', 'uno', 'win', 'xin', 'xyz', 'zip',
        // Nieuwe TLD's 2025-2026 (veel misbruikt voor phishing)
        'autos', 'boats', 'cam', 'casa', 'cfd', 'click', 'cloud', 'cyou', 'desi',
        'digital', 'fit', 'fun', 'gdn', 'gives', 'icu', 'lat', 'lol', 'mom', 'monster',
        'nexus', 'observer', 'online', 'ooo', 'pics', 'quest', 'racing', 'realty',
        'rodeo', 'site', 'skin', 'space', 'store', 'stream', 'surf', 'tech',
        'today', 'vip', 'wang', 'webcam', 'website', 'work', 'world', 'wtf', 'yachts',
        // AI/Tech gerelateerde TLD's (hoog risico in 2026)
        'ai', 'bot', 'chat', 'crypto', 'dao', 'data', 'dex', 'eth', 'gpt', 'link', 'llm',
        'metaverse', 'nft', 'sol', 'token', 'wallet', 'web3'
    ]),

    /**
     * SECURITY FIX v8.1.1: Set-based TLD check (O(1) lookup, ReDoS-safe)
     * Gebruik: CONFIG.isSuspiciousTLD('xyz') of CONFIG.SUSPICIOUS_TLDS.test('.xyz')
     * @param {string} tld - De TLD om te checken (zonder punt)
     * @returns {boolean} - true als de TLD verdacht is
     */
    isSuspiciousTLD: function(tld) {
        if (!tld || typeof tld !== 'string') return false;
        return this.SUSPICIOUS_TLDS_SET.has(tld.toLowerCase().replace(/^\./, ''));
    },

    // Legacy regex voor backwards compatibility (statisch, geen dynamische constructie)
    // Kan verwijderd worden na volledige migratie naar isSuspiciousTLD()
    SUSPICIOUS_TLDS: /\.(beauty|bond|buzz|cc|cf|club|cn|es|ga|gq|hair|li|live|ml|mov|pro|rest|ru|sbs|shop|tk|top|uno|win|xin|xyz|zip|autos|boats|cam|casa|cfd|click|cloud|cyou|desi|digital|fit|fun|gdn|gives|icu|lat|lol|mom|monster|nexus|observer|online|ooo|pics|quest|racing|realty|rodeo|site|skin|space|store|stream|surf|tech|today|vip|wang|webcam|website|work|world|wtf|yachts|ai|bot|chat|crypto|dao|data|dex|eth|gpt|link|llm|metaverse|nft|sol|token|wallet|web3)$/i,

    // ==== Risicodrempels voor gefaseerde analyse en UI-feedback ====
    LOW_THRESHOLD: 4,      //  risico < 4 → safe
    MEDIUM_THRESHOLD: 8,     //  4 ≤ risico < 8 → caution
    HIGH_THRESHOLD: 15,    //  risico ≥ 15 → alert
    SCRIPT_RISK_THRESHOLD: 10,  // drempel voor inhoudsanalyse van externe scripts

    YOUNG_DOMAIN_THRESHOLD_DAYS: 7, // Domeinen jonger dan 1 week (blijft 7)
    DOMAIN_AGE_MIN_RISK: 5,        // Domeinleeftijd‐check vanaf 5 punten (was 3)
    YOUNG_DOMAIN_RISK: 5,          // Risico‐gewicht voor jonge domeinen (was 7)
    PROTOCOL_RISK: 4,

    // Debug Modus
    DEBUG_MODE: false, // Zet op true voor debugging, false voor productie

    // AUDIT MODE (v8.1.0): Voor functionele tests
    // Wanneer true: ELKE externe link wordt als HIGH RISK gemarkeerd
    // Dit maakt het mogelijk om visuele bescherming (overlays, z-index) te testen
    // op willekeurige sites zonder echte phishing-domeinen te gebruiken
    // WAARSCHUWING: Alleen voor testen - zet op false voor productie!
    TEST_MODE: false,
    TEST_MODE_RISK_SCORE: 25, // Score die wordt toegekend in test mode

    // Toegestane URL Protocollen
    ALLOWED_PROTOCOLS: ['http:', 'https:', 'mailto:', 'tel:', 'ftp:'],

    // Verdachte Bestandsextensies
    // Verfijnd om false positives te vermijden:
    // - .js, .py, .svg, .dll VERWIJDERD (te veel legitieme resources)
    // - Focus op echte executables en macro-enabled documenten
    MALWARE_EXTENSIONS: /\.(exe|zip|bak|tar|gz|msi|dmg|jar|rar|7z|iso|bin|scr|bat|cmd|vbs|lnk|chm|ps1|apk|vbscript|docm|xlsm|pptm|torrent|wsf|hta|jse|reg|swf|wsh|pif|wasm|cab|cpl|inf|msc|pcd|sct|shb|sys)$/i,

    // Trefwoorden voor Verdachte Downloads
    // Ontdubbeld voor betere prestaties.
    DOWNLOAD_KEYWORDS: new Set([
        "download", "install", "setup", "file", "update", "patch", "plugin", "installer", "software", "driver", "execute", "run", "launch", "tool", "patcher", "application", "program", "app", "fix", "crack", "keygen", "serial", "activation", "license", "trial", "demo", "zip", "archive", "compressed", "installer_package", "upgrade", "update_tool", "free", "fixer", "repair", "optimizer", "restore", "reset", "unlock", "backup", "configuration", "config", "module", "library", "framework", "macro", "enable", "torrent", "seed", "payload", "exploit", "dropper", "loader", "package", "binary", "release", "beta", "mod", "hack", "unlocker", "generator", "premium", "ai", "quantum", "crypto", "wallet", "blockchain", "ledger", "metaverse", "deepfake", "nft", "web3", "ar", "chatbot", "voice", "biometric", "zero-trust", "colleague", "team", "meeting", "urgent-call", "generated", "synthetic", "prompt", "telehealth", "healthcare", "prescription", "patient", "model", "train", "inference", "simulate", "dynamic", "privacy", "secure-chat", "federated", "anonymous", "green", "eco", "sustainable", "carbon", "adaptive", "personalize", "targeted", "behavior", "profile", "social", "data", "custom", "smart", "city", "iot", "urban", "mutate", "evolve", "variant", "polymorphic", "interactive", "live", "stream", "avatar", "edge", "distributed", "cdn", "fog", "track", "monitor", "analytics", "behavioral", "assistant", "bot", "support", "guide", "6g", "ultra", "network", "connectivity", "voice-clone", "speech", "vishing", "callbot", "hologram", "holo", "ar-interface", "spatial", "quantum-secure", "post-quantum", "qkd", "bci", "neural", "brainwave", "neuro", "emotion", "sentiment", "affective", "psychometric", "zkp", "zero-knowledge", "proof"
    ]),

    // Phishing Trefwoorden
    // Ontdubbeld voor betere prestaties.
    PHISHING_KEYWORDS: new Set([
        "access", "account", "auth", "blocked", "bonus", "captcha", "claim", "click", "credentials", "free", "gift", "login", "notification", "pay", "pending", "prize", "recover", "secure", "signin", "unlock", "unusual", "update", "urgent", "validate", "verify", "win", "password", "bank", "security", "alert", "suspended", "confirm", "identity", "renew", "subscription", "billing", "refund", "delivery", "tracking", "survey", "reward", "promo", "deal", "offer", "urgent-action", "reset", "phishing", "scan", "qr", "qrcode", "invoice", "2fa", "mfa", "otp", "verification", "authenticator", "token", "code", "ai", "quantum", "crypto", "wallet", "blockchain", "ledger", "metaverse", "deepfake", "nft", "web3", "ar", "chatbot", "voice", "biometric", "zero-trust", "colleague", "team", "meeting", "urgent-call", "generated", "synthetic", "prompt", "telehealth", "healthcare", "prescription", "patient", "model", "train", "inference", "simulate", "dynamic", "privacy", "secure-chat", "federated", "anonymous", "green", "eco", "sustainable", "carbon", "adaptive", "personalize", "targeted", "behavior", "profile", "social", "data", "custom", "smart", "city", "iot", "urban", "mutate", "evolve", "variant", "polymorphic", "interactive", "live", "stream", "avatar", "edge", "distributed", "cdn", "fog", "track", "monitor", "analytics", "behavioral", "assistant", "bot", "support", "guide", "6g", "ultra", "network", "connectivity", "voice-clone", "speech", "vishing", "callbot", "hologram", "holo", "ar-interface", "spatial", "quantum-secure", "post-quantum", "qkd", "bci", "neural", "brainwave", "neuro", "emotion", "sentiment", "affective", "psychometric", "zkp", "zero-knowledge", "proof"
    ]),

    // Verdachte Iframe Patronen
    SUSPICIOUS_IFRAME_PATTERNS: [{
        name: 'suspiciousIframeAdComponent',
        pattern: /(adserver|banner|ads|doubleclick|pubmatic)/i,
        reason: 'Een advertentiecomponent van een derde partij is gedetecteerd.'
    }, {
        name: 'suspiciousIframeTracking',
        pattern: /(track|spy|analytics)/i,
        reason: 'Een trackingelement dat uw activiteit kan volgen, is gevonden.'
    }, {
        name: 'suspiciousIframeMalicious',
        pattern: /(malicious|phish|exploit|inject|clickjacking|fake-login)/i,
        reason: 'Een potentieel schadelijk element (zoals phishing of een exploit) is gevonden.'
    }, {
        name: 'suspiciousIframeHidden',
        check: (iframe) => {
            const style = window.getComputedStyle(iframe);
            const isHidden = style.display === 'none' || style.visibility === 'hidden' || style.opacity === '0' || parseInt(style.width) < 2 || parseInt(style.height) < 2;
            const hasSuspiciousAttributes = iframe.hasAttribute('onload') || iframe.src.startsWith('javascript:');
            return isHidden && hasSuspiciousAttributes;
        },
        reason: 'Een verdacht, verborgen element is gedetecteerd.'
    }],

    // Cache Duur (in milliseconden)
    CACHE_DURATION_MS: 24 * 60 * 60 * 1000, // 24 uur

    // Standaard Drempelwaarden
    SUSPICION_THRESHOLD: 0.1, // 10% van de links moet verdacht zijn

    // Domeinen waarvan we weten dat ze legitieme embeds/advertenties leveren
    // SECURITY NOTE: Google Docs/Drive/Forms verwijderd - worden veel misbruikt voor phishing
    TRUSTED_IFRAME_DOMAINS: [
        // Video platforms
        'youtube.com', 'www.youtube.com', 'youtu.be', 'vimeo.com', 'player.vimeo.com',
        'dailymotion.com', 'www.dailymotion.com', 'twitch.tv', 'player.twitch.tv',
        // Audio platforms
        'soundcloud.com', 'w.soundcloud.com', 'spotify.com', 'open.spotify.com',
        // Maps (alleen embed)
        'maps.google.com', 'www.google.com/maps', 'openstreetmap.org', 'www.openstreetmap.org',
        // Google Calendar (relatief veilig voor embeds)
        'calendar.google.com',
        // Social media (alleen officiële embeds)
        'platform.twitter.com', 'platform.linkedin.com', 'assets.pinterest.com',
        'embed.tiktok.com', 'facebook.net',
        // Payment providers (gevalideerde checkout flows)
        'js.stripe.com', 'checkout.stripe.com', 'checkoutshopper-live.adyen.com',
        // Chat widgets
        'widget.intercom.io', 'crisp.chat', 'webchat.livechatinc.com', 'js.zendesk.com',
        // Dev tools (sandbox)
        'gist.github.com', 'codesandbox.io', 'stackblitz.com', 'embed.replit.com',
        // Advertising (analytics/tracking)
        'fls.doubleclick.net', 'cm.g.doubleclick.net', 'googleadservices.com',
        'googlesyndication.com', 'adservice.google.com', 'ads.pubmatic.com',
        'hb.pubmatic.com', 'ads.rubiconproject.com', 'secure.adnxs.com',
        'adsafeprotected.com', 'segment.com', 'bat.bing.com',
        // Trust & consent
        'widget.trustpilot.com', 'consent.cookiebot.com', 'consentcdn.cookiebot.com'
    ],

    // Inlogpatronen
    LOGIN_PATTERNS: /(login|account|auth|authenticate|signin|wp-login|sign-in|log-in|dashboard|portal|session|user|profile)/i,

    // Gratis Hosting Domeinen (uitgebreid 2026 - veel misbruikt door AI phishing kits)
    FREE_HOSTING_DOMAINS: [
        // Klassieke gratis hosting
        'sites.net', 'angelfire.com', 'geocities.ws', '000a.biz', '000webhostapp.com', 'weebly.com',
        'wixsite.com', 'freehosting.com', 'glitch.me', 'freehostia.com', 'webs.com', 'yolasite.com',
        'bravenet.com', 'zyro.com', 'altervista.org', 'tripod.com', 'jimdo.com', 'ucoz.com',
        'blogspot.com', 'square.site', 'mybluehost.me', '000space.com', 'awardspace.com',
        'byethost.com', 'biz.nf', 'hyperphp.com', 'infinityfree.net', '50webs.com',
        'tripod.lycos.com', 'site123.me', 'strikingly.com', 'x10hosting.com',
        'freehostingnoads.net', '000freewebhost.com', 'mystrikingly.com', 'weeblysite.com',
        // Moderne cloud/serverless hosting (veel misbruikt voor AI-phishing in 2026)
        'vercel.app', 'netlify.app', 'pages.dev', 'workers.dev', 'r2.dev',
        'herokuapp.com', 'fly.dev', 'fly.io', 'render.com', 'onrender.com',
        'railway.app', 'deno.dev', 'val.run', 'val.town',
        // Firebase/Google Cloud
        'firebaseapp.com', 'web.app', 'firebaseio.com', 'cloudfunctions.net',
        'appspot.com', 'sites.google.com',
        // GitHub/GitLab/Azure
        'github.io', 'gitlab.io', 'azurewebsites.net', 'azurestaticapps.net',
        'blob.core.windows.net', 'privatelink.blob.core.windows.net', // Azure Blob Storage (veel misbruikt voor phishing met geldige TLS)
        'web.core.windows.net', // Azure Static Website hosting (PhishTank 2026-01)
        // AWS
        's3.amazonaws.com', 'amplifyapp.com', 'execute-api.amazonaws.com',
        // Andere moderne platforms
        'webflow.io', 'framer.website', 'framer.app', 'framercanvas.com', // framer.app toegevoegd (PhishTank 2026-01)
        'canva.site', // Canva Sites (PhishTank 2026-01)
        'bubbleapps.io', 'typedream.app', 'codeanyapp.com', 'carrd.co',
        'surge.sh', 'replit.dev', 'repl.co',
        // Edge/CDN platforms
        'edgecompute.app', 'durable.co', 'liveblocks.io',
        // AI/ML hosting platforms (veel misbruikt voor AI-gegenereerde phishing in 2026)
        'huggingface.co', 'hf.space', 'spaces.huggingface.co', 'gradio.app',
        'streamlit.app', 'replicate.com'
    ],

    // Verkorte URL Domeinen (algemene shorteners - mogelijk verdacht)
    SHORTENED_URL_DOMAINS: [
        "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly", "su.pr", "tiny.cc", "x.co", "rebrand.ly", "mcaf.ee", "po.st", "adf.ly", "cutt.ly", "qrco.de", "yourls.org", "shrtco.de", "chilp.it", "clck.ru", "rb.gy", "shorturl.at", "shorte.st", "cli.re", "surl.li", "tny.im", "zi.ma", "t1p.de", "urlz.fr", "did.li", "v.ht", "short.cm", "bit.do", "t.ly", "4gp.me", "linktr.ee", "tiny.ie", "1url.com", "hyperurl.co", "lnk.to", "snip.ly", "flip.to", "adcrun.ch", "short.to", "t.co.uk", "kutt.it", "flic.kr", "qr.net", "trk.li", "smll.co", "xurl.es", "xup.pl", "b.link", "x.gd", "n9.cl", "zi.pe", "qr.ae", "0rz.tw", "qqc.co", "h6y.eu", "fw.to", "lnk2.me", "shurl.net", "mrk.to", "clk.im", "u.to", "ezurl.cc", "fur.ly", "v.gd", "2ty.cc", "sh.ky", "s.coop", "cutt.us", "bitly.com", "q.gs", "i.cut", "s.id", "linklyhq.com", "slkt.io", "pp.gg", "short.url", "zpr.io", "me.qr", "short.io", "dub.co", "cl.ly", "bl.ink", "go.ly", "soo.gd", "jmp.sh", "u.nu", "t2m.io", "short.link", "tiny.one", "shr.link", "linkly.me", "cut.link", "shorty.ai", "link.ai", "tiny.ai", "cut.ai"
    ],

    // Officiële URL shorteners van bekende bedrijven - NIET verdacht markeren
    // Dit zijn shorteners die eigendom zijn van grote tech-bedrijven en veilig worden beheerd
    OFFICIAL_SHORTENERS: [
        "t.co",       // Twitter/X - officiële shortener
        "youtu.be",   // YouTube/Google - officiële shortener
        "fb.me",      // Facebook/Meta - officiële shortener
        "g.co",       // Google - officiële shortener
        "goo.gl",     // Google - legacy shortener (nog in gebruik)
        "lnkd.in",    // LinkedIn - officiële shortener
        "amzn.to",    // Amazon - officiële shortener
        "amzn.eu",    // Amazon EU - officiële shortener
        "msft.it",    // Microsoft - officiële shortener
        "aka.ms",     // Microsoft Azure - officiële shortener
        "apple.co",   // Apple - officiële shortener
        "spoti.fi",   // Spotify - officiële shortener
        "pin.it",     // Pinterest - officiële shortener
        "redd.it",    // Reddit - officiële shortener
        "vimeo.com",  // Vimeo - officiële links
        "twitch.tv"   // Twitch - officiële links
    ],

    // Vertrouwde CDN domeinen - legitieme content delivery networks
    // Deze domeinen worden gebruikt door bedrijven voor hosting van assets
    // en moeten niet automatisch als verdacht worden gemarkeerd
    TRUSTED_CDN_DOMAINS: [
        // AWS CDN en hosting
        "cloudfront.net",        // AWS CloudFront CDN
        "amazonaws.com",         // AWS S3, API Gateway, etc.
        "awsstatic.com",         // AWS static assets
        // Microsoft Azure CDN en hosting
        "azureedge.net",         // Azure CDN
        "azure.com",             // Azure services
        "msecnd.net",            // Microsoft CDN
        "aspnetcdn.com",         // ASP.NET CDN
        // Google Cloud CDN
        "googleusercontent.com", // Google user content
        "gstatic.com",           // Google static content
        "googleapis.com",        // Google APIs
        "ggpht.com",             // Google Photos
        // Cloudflare
        "cloudflare.com",        // Cloudflare services
        "cloudflareinsights.com",// Cloudflare analytics
        // Andere grote CDNs
        "akamaized.net",         // Akamai CDN
        "akamaihd.net",          // Akamai HD
        "fastly.net",            // Fastly CDN
        "edgecastcdn.net",       // Verizon/Edgecast CDN
        "stackpathcdn.com",      // StackPath CDN
        "jsdelivr.net",          // jsDelivr open source CDN
        "unpkg.com",             // npm CDN
        "cdnjs.cloudflare.com",  // Cloudflare CDNJS
        // Social media CDNs
        "fbcdn.net",             // Facebook CDN
        "twimg.com",             // Twitter images
        "pinimg.com",            // Pinterest images
        "ytimg.com",             // YouTube thumbnails
        "licdn.com"              // LinkedIn CDN
    ],

    // Vertrouwde API domeinen - legitieme API endpoints
    // OAuth, authenticatie en API services van bekende providers
    TRUSTED_API_DOMAINS: [
        // OAuth providers
        "accounts.google.com",
        "oauth.google.com",
        "login.microsoftonline.com",
        "login.live.com",
        "appleid.apple.com",
        "api.twitter.com",
        "api.x.com",
        "graph.facebook.com",
        "api.linkedin.com",
        "api.github.com",
        "oauth.reddit.com",
        // Payment APIs
        "api.stripe.com",
        "api.paypal.com",
        "checkout.stripe.com",
        // Authentication services
        "auth0.com",
        "okta.com",
        "login.okta.com",
        // Andere APIs
        "api.spotify.com",
        "api.twitch.tv",
        "api.dropbox.com",
        "api.slack.com"
    ],

SUSPICIOUS_URL_PATTERNS: [
  // 1. Hoog risico: oplichtings-/phishing-termen
  /\b(?:fake|clone|spoof|impersonate|fraud|scam|phish)\b/i,

  // 2. Middel risico: hype-technologieën die vaak misbruikt worden
  /\b(?:quantum|blockchain|nft|web3|metaverse|deepfake)\b/i,

  // 3. Financiële acties in het pad
  /\/(?:payment|billing|checkout|refund|subscription|invoice)\//i,

  // 4. Authenticatie-/accountflows
  /\/(?:login|secure(?:pay|chat)?|2fa|mfa|verify(?:-account|email)|reset-password)\//i,

  // 5. Tracking en analytics
  /\/(?:track|monitor|analytics)\//i,

  // 6. Encodering/obfuscatie keywords
  /(Base64|hexadecimal|b64|encode|urlencode|obfuscate|crypt)/i,

  // 7. QR-code gerelateerde paden
  /(qr-code|qrcode|qr\.|generate-qr|scan|qrserver|qrcodes\.)/i
],


    // Verdachte Script Patronen
    SUSPICIOUS_SCRIPT_PATTERNS: [
        /(?:\beval\s*\(\s*['"][^'"]*['"]\s*\)|new\s+Function\s*\(\s*['"][^'"]*['"]\s*\)|base64_decode\s*\()/i,
        /(?:coinimp|cryptonight|webminer|miner\.js|crypto-jacking|keylogger|trojan|worm|ransomware|xss\s*\()/i,
        /(?:document\.write\s*\(\s*['"][^'"]*javascript:|innerHTML\s*=\s*['"][^'"]*eval)/i,
        /(?:fetch\(.+\.wasm[^)]*eval|import\(.+\.wasm[^)]*javascript:)/i,
        /(?:malicious|phish|exploit|redirect|inject|clickjacking|backdoor|rootkit)/i,
        /(?:RTCPeerConnection\s*\(\s*{[^}]*stun:|RTCDataChannel\s*.\s*send\s*\(\s*['"][^'"]*eval)/i,
        /(RTCSessionDescription|RTCIceCandidate)/i,
        /(WebTransport)/i,
        /(quic-transport|http3)/i,
        /(serverless|lambda|cloudfunction)/i,
        /(WebGL|Three\.js)/i,
        /(ipfs|decentralized|dweb)/i,
        /(federated-learning|distributed-ai|edge-ai)/i,
        /(WebGPU)/i
    ],

    // Toegestane Paden en Query Parameters
    ALLOWED_PATHS: [/\/products\/|\/account\/billing\/|\/plans\/|\/support\/|\/docs\//i],
    ALLOWED_QUERY_PARAMS: [/eventId|referrer|utm_|lang|theme/i],

    // Crypto Domeinen
    CRYPTO_DOMAINS: [
        "binance.com", "kraken.com", "metamask.io", "wallet-connect.org", "coinbase.com", "bybit.com", "okx.com", "kucoin.com", "hashkey.com", "binance.us", "global.hashkey.com", "bitget.com", "gate.io", "huobi.com", "bingx.com", "bitfinex.com", "luno.com", "backpack.exchange", "woox.io", "mexc.com", "bitmart.com", "lbank.com", "coinw.com", "crypto.com", "p2pb2b.com", "bitunix.com", "bigone.com", "azbit.com", "pionex.com", "coinstore.com", "coinex.com", "exchange.fastex.com", "dex-trade.com", "links.bitstamp.net", "gemini.com", "phemex.com", "exmo.com", "bitkub.com", "arkm.com", "bitso.com", "deribit.com", "bitcastle.io", "bitopro.com", "xeggex.com", "coins.ph", "bitcointry.com", "emirex.com", "upbit.com", "digifinex.com", "bithumb.com", "xt.com", "toobit.com", "latoken.com", "bvox.com", "weex.com", "ascendex.com", "biconomy.com", "hibt.com", "bitrue.com", "bitvavo.com", "btse.com", "exchange.pointpay.io", "qmall.io", "bitflyer.com", "coincheck.com", "paribu.com", "slex.io", "bitbank.cc", "bitdelta.com", "blofin.com", "kanga.exchange", "korbit.co.kr", "trade.cex.io", "nonkyc.io", "tokenize.exchange", "foxbit.com.br", "independentreserve.com", "coindcx.com", "bitmex.com", "app.uniswap.org", "hotcoin.com", "fameex.com", "tapbit.com", "deepcoin.com", "bydfi.com", "trubit.com", "pancakeswap.finance", "app.cetus.zone", "coin.z.com", "bitci.com.tr", "fmfw.io", "bitstorage.finance", "ledger.com", "trezor.io", "ellipal.com", "safepal.io", "shapeshift.com", "shiftcrypto.ch", "coldcardwallet.com", "dcentwallet.com", "secuxtech.com", "gridplus.io", "coingecko.com", "coinmarketcap.com", "cryptoslate.com", "theblock.co", "decrypt.co", "coindesk.com", "bitcoin.org", "messari.io", "cryptocompare.com", "glassnode.com", "tradingview.com", "bitinfocharts.com", "blockchain.com", "etherscan.io", "phantom.app", "trustwallet.com", "keplr.app", "cosmostation.io", "solflare.com", "opensea.io", "rarible.com", "sushi.com", "curve.fi", "balancer.fi", "1inch.io", "raydium.io"
    ],

    // Homoglyphs Mapping - Uitgebreid voor 2026
    // Bevat Unicode confusables, Cyrillisch, Grieks, en speciale tekens
    HOMOGLYPHS: {
        // Basis letters met Cyrillische en Griekse varianten
        'a': ['а', 'α', 'ⱥ', 'ä', 'å', 'á', 'à', 'â', 'ã', 'ā', 'ă', 'ǎ', 'ȁ', 'ȃ', 'ǻ', 'ª', 'ɑ', 'ạ', 'ả', 'ấ', 'ầ', 'ẩ', 'ẫ', 'ậ', 'ắ', 'ằ', 'ẳ', 'ẵ', 'ặ'],
        'b': ['Ь', 'ь', 'Ƅ', 'ƅ', 'ɓ', 'ḃ', 'ḅ', 'ḇ', 'ß'],
        'c': ['с', 'ç', '¢', 'ć', 'ĉ', 'ċ', 'č', '©', 'ȼ', 'ƈ', 'ḉ', 'ꮯ', 'ⅽ'],
        'd': ['ԁ', 'đ', 'ď', 'ḋ', 'ḍ', 'ḏ', 'ḑ', 'ḓ', 'ɖ', 'ⅾ', 'ꓒ'],
        'e': ['е', 'ε', 'ë', 'ē', 'ĕ', 'ė', 'ę', 'ě', 'ê', 'è', 'é', 'ȅ', 'ȇ', '€', 'ɛ', 'ẹ', 'ẻ', 'ẽ', 'ế', 'ề', 'ể', 'ễ', 'ệ', 'ⅇ'],
        'f': ['ſ', 'ƒ', 'ḟ', 'ꬵ'],
        'g': ['ɡ', 'ġ', 'ğ', 'ĝ', 'ǧ', 'ģ', 'ǥ', 'ɢ', 'ḡ', 'ꮐ'],
        'h': ['һ', 'ħ', 'ĥ', 'ḥ', 'ḧ', 'ḩ', 'ḫ', 'ɦ', 'ⱨ', 'ꜧ'],
        'i': ['і', 'í', 'ì', 'î', 'ï', 'ī', 'ĭ', 'į', 'ǐ', 'ɨ', 'ı', '¡', 'ị', 'ỉ', 'ĩ', 'ⅰ', 'ⅼ', '১', '۱', 'ⵏ'],
        'j': ['ј', 'ʝ', 'ɉ', 'ĵ', 'ǰ'],
        'k': ['κ', 'ќ', 'ḱ', 'ǩ', 'ķ', 'ḳ', 'ḵ', 'ƙ', 'ⱪ', 'ꝁ'],
        'l': ['ӏ', 'Ɩ', 'ĺ', 'ļ', 'ľ', 'ŀ', 'ł', 'Ɨ', 'ǀ', 'ⅼ', 'ⅰ', '|', 'ꓲ', 'ꮮ'],
        'm': ['м', 'ṁ', 'ṃ', 'ⅿ', 'ꮇ', 'ɱ'],
        'n': ['п', 'ñ', 'ń', 'ņ', 'ň', 'ŉ', 'ŋ', 'ṅ', 'ṇ', 'ṉ', 'ƞ', 'ꞑ', 'ꮑ'],
        'o': ['ο', 'о', 'ö', 'ó', 'ò', 'ô', 'õ', 'ō', 'ŏ', 'ő', 'ø', 'ǒ', 'ȍ', 'ȏ', 'º', '0', 'ọ', 'ỏ', 'ố', 'ồ', 'ổ', 'ỗ', 'ộ', 'ớ', 'ờ', 'ở', 'ỡ', 'ợ', 'ꮎ', 'ⲟ'],
        'p': ['р', 'ƿ', 'ṕ', 'ṗ', 'ƥ', '℗', 'ⲣ', 'ꮲ'],
        'q': ['ԛ', 'ɋ', 'ꝗ', 'ꝙ'],
        'r': ['г', 'ŕ', 'ŗ', 'ř', 'ṙ', 'ṛ', 'ṝ', 'ṟ', 'ɍ', 'ꞧ', 'ꮁ'],
        's': ['ѕ', 'ß', '$', 'ś', 'ŝ', 'ş', 'š', '§', 'ʃ', 'ṡ', 'ṣ', 'ꮪ', 'Ȿ'],
        't': ['τ', 'т', 'ţ', 'ť', 'ŧ', 'ṭ', 'ṯ', 'ṱ', 'ƭ', '†', 'ⱦ', 'ꮦ'],
        'u': ['υ', 'ц', 'ü', 'ú', 'ù', 'û', 'ū', 'ŭ', 'ů', 'ű', 'ų', 'ǔ', 'ȕ', 'ȗ', 'µ', 'ụ', 'ủ', 'ứ', 'ừ', 'ử', 'ữ', 'ự', 'ꮜ'],
        'v': ['ν', 'ѵ', 'ṽ', 'ṿ', 'ⅴ', 'ꮩ', 'ⱱ'],
        'w': ['ω', 'ẁ', 'ẃ', 'ẅ', 'ẇ', 'ẉ', 'ⱳ', 'ꮃ'],
        'x': ['х', '×', 'ẋ', 'ẍ', 'χ', 'ⅹ', 'ꭓ', 'ꮖ'],
        'y': ['у', 'ý', 'ÿ', 'ŷ', 'ȳ', '¥', 'ƴ', 'ɏ', 'ỳ', 'ỵ', 'ỷ', 'ỹ', 'ꮍ'],
        'z': ['ž', 'ƶ', 'ź', 'ż', 'ẑ', 'ẓ', 'ẕ', 'ƹ', 'ɀ', 'ⱬ', 'ꮓ'],
        // Cijfers (vaak gebruikt in l33t-speak phishing)
        '0': ['ο', 'о', 'О', 'O', 'Ο', '〇', '०', '٠', '۰', 'ⲟ', 'ꮎ'],
        '1': ['l', 'I', 'i', '|', 'ⅰ', 'ⅼ', 'ӏ', '١', '۱', 'ꓲ'],
        '3': ['Ʒ', 'ʒ', 'Ȝ', 'ȝ', 'з', 'З', '�765', 'ⳍ'],
        '4': ['Ꮞ', 'ч', 'Ч'],
        '5': ['Ƽ', 'ƽ', 'Ѕ', 'ѕ'],
        '6': ['б', 'Ꮾ', 'ꮾ', 'ⳓ'],
        '8': ['Ȣ', 'ȣ', '�765', 'ⲑ'],
        '9': ['ɋ', 'ꝙ', 'ⳋ']
    },

    // Homoglyph combinaties - 2026 technieken
    // Detecteert combinaties zoals 'rn' -> 'm', 'cl' -> 'd', etc.
    HOMOGLYPH_COMBINATIONS: {
        'rn': 'm',
        'cl': 'd',
        'vv': 'w',
        'nn': 'm',
        'ri': 'n',
        'ii': 'u',
        'ln': 'in',
        'lm': 'im'
    },

    // Verdachte E-mailpatronen
    SUSPICIOUS_EMAIL_PATTERNS: [
        /noreply@.*\.(xyz|top|club|online|site)/i,
        /(support|admin|security|billing)@.*\.(co|cc|info|biz)/i,
        /[^@]+@[^@]+\.[a-z]{2,}$/i,
        /\b(free|win|urgent|verify|login)@.*$/i,
        /ai-support@.*$/i, /verify-biometric@.*$/i, /telehealth@.*$/i, /meeting@.*$/i, /privacy@.*$/i, /green@.*$/i, /smart@.*$/i, /social@.*$/i, /edge@.*$/i, /live@.*$/i, /assistant@.*$/i, /6g@.*$/i, /voice@.*$/i, /holo@.*$/i, /quantum@.*$/i, /bci@.*$/i, /neuro@.*$/i, /zkp@.*$/i
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
        'microsoft.com', 'apple.com', 'google.com', 'linkedin.com', 'alibaba.com', 'whatsapp.com', 'amazon.com', 'x.com', 'facebook.com', 'adobe.com', 'paypal.com', 'netflix.com', 'instagram.com', 'outlook.com', 'opensea.io', 'decentraland.org', 'chat.openai.com', 'auth0.com', 'teladoc.com', 'zoom.us', 'signal.org', 'ecosia.org', 'smartcityexpo.com', 'cloudflare.com', 'nokia.com', 'idquantique.com', 'neuralink.com',
        // Nederlandse banken en financiële instellingen (veelgebruikt in phishing)
        'ing.nl', 'ing.com', 'rabobank.nl', 'abnamro.nl', 'sns.nl', 'bunq.com', 'triodos.nl', 'asn.nl', 'knab.nl', 'regiobank.nl', 'volksbank.nl',
        // Overheid en uitkeringen (veelgebruikt in phishing)
        'digid.nl', 'mijnoverheid.nl', 'belastingdienst.nl', 'duo.nl', 'uwv.nl', 'svb.nl', 'toeslagen.nl',
        // Telecom en utilities
        'kpn.nl', 'vodafone.nl', 't-mobile.nl', 'ziggo.nl', 'tele2.nl',
        // E-commerce
        'bol.com', 'coolblue.nl', 'zalando.nl', 'marktplaats.nl', 'thuisbezorgd.nl',
        // Post en bezorging
        'postnl.nl', 'dhl.nl', 'ups.com', 'fedex.com'
    ],

    // Bekende merknamen (kort) voor substring-detectie in homoglyph-aanvallen
    BRAND_KEYWORDS: [
        'ing', 'rabo', 'abnamro', 'abn', 'sns', 'bunq', 'digid', 'belasting', 'overheid',
        'paypal', 'amazon', 'google', 'microsoft', 'apple', 'facebook', 'netflix', 'instagram',
        'whatsapp', 'linkedin', 'twitter', 'postnl', 'dhl', 'ups'
    ],

    // Legitieme merkdomeinen (whitelist voor brand subdomain check)
    LEGITIMATE_BRAND_DOMAINS: [
        // Nederlandse banken
        'ing.nl', 'ing.com', 'ingwb.com',
        'rabobank.nl', 'rabobank.com',
        'abnamro.nl', 'abnamro.com',
        'sns.nl', 'snsbank.nl',
        'bunq.com',
        'triodos.nl', 'triodos.com',
        'knab.nl',
        // Overheid
        'digid.nl', 'mijnoverheid.nl',
        'belastingdienst.nl',
        // Internationale merken
        'paypal.com', 'paypal.nl',
        'amazon.com', 'amazon.nl', 'amazon.de',
        'google.com', 'google.nl',
        'microsoft.com',
        'apple.com',
        'facebook.com',
        'netflix.com',
        'instagram.com',
        'whatsapp.com',
        'linkedin.com',
        'twitter.com', 'x.com',
        // Bezorging
        'postnl.nl', 'postnl.com',
        'dhl.nl', 'dhl.com',
        'ups.com', 'ups.nl'
    ],

    // Crypto wallet address patterns voor clipboard hijacking detectie
    CRYPTO_ADDRESS_PATTERNS: {
        bitcoin: /^(bc1|[13])[a-zA-HJ-NP-Z0-9]{25,39}$/,
        ethereum: /^0x[a-fA-F0-9]{40}$/,
        solana: /^[1-9A-HJ-NP-Za-km-z]{32,44}$/,
        // Generieke pattern voor detectie in clipboard content
        any: /(bc1|0x[a-fA-F0-9]{40}|[13][a-zA-HJ-NP-Z0-9]{25,39}|[1-9A-HJ-NP-Za-km-z]{32,44})/
    },

    // ClickFix Attack Detection (PowerShell/Command injection via fake CAPTCHA - +517% toename in 2025)
    CLICKFIX_PATTERNS: {
        // PowerShell execution patterns
        powershell: [
            /powershell\s*[\-\/]e(nc(odedcommand)?)?/i,           // powershell -e, -enc, -encodedcommand
            /powershell\s*[\-\/]w(indowstyle)?\s*h(idden)?/i,     // powershell -w hidden
            /powershell\s*[\-\/]nop(rofile)?/i,                   // powershell -noprofile
            /powershell\s*[\-\/]ep\s*bypass/i,                    // powershell -ep bypass
            /Invoke-Expression/i,                                  // IEX
            /IEX\s*[\(\$]/i,                                       // IEX( or IEX$
            /Invoke-WebRequest/i,                                  // Download cradle
            /Invoke-RestMethod/i,                                  // Download cradle
            /\[System\.Net\.WebClient\]/i,                        // .NET download
            /DownloadString\s*\(/i,                               // DownloadString()
            /DownloadFile\s*\(/i,                                 // DownloadFile()
            /Start-Process/i,                                      // Process execution
            /Set-ExecutionPolicy\s*(Bypass|Unrestricted)/i,       // Execution policy bypass
            /\-exec\s*bypass/i                                     // -exec bypass
        ],
        // CMD/Windows command patterns
        cmd: [
            /cmd\s*\/c/i,                                          // cmd /c
            /cmd\s*\/k/i,                                          // cmd /k
            /mshta\s+(http|vbscript)/i,                           // MSHTA attacks
            /certutil\s*[\-\/]urlcache/i,                         // Certutil download
            /bitsadmin\s*\/transfer/i,                            // BITS download
            /regsvr32\s*\/s\s*\/n\s*\/u/i                         // Regsvr32 bypass
        ],
        // Fake UI patterns that trick users into running commands
        fakeUI: [
            /press\s*(win(dows)?|⊞)\s*\+\s*r/i,                   // "Press Win+R"
            /open\s*(run|terminal|cmd|powershell)/i,              // "Open Run dialog"
            /paste\s*(and\s*)?(press\s*)?(enter|run)/i,           // "Paste and press Enter"
            /copy\s*(this|the)?\s*(code|command|script)/i,        // "Copy this code"
            /ctrl\s*\+\s*v.*enter/i,                              // "Ctrl+V then Enter"
            /right[\-\s]?click.*paste/i                           // "Right-click and paste"
        ]
    },

    // Browser-in-the-Browser (BitB) Attack Detection
    // Detecteert nep browser popups die OAuth/SSO logins simuleren
    //
    // DETECTIE LOGICA (v2.0):
    // Alert wordt alleen getriggerd als:
    // 1. Fake URL bar aanwezig (sterke indicator alleen) OF
    // 2. Login form + window controls OF
    // 3. Login form + OAuth branding OF
    // 4. Login form + window chrome + padlock (warning) OF
    // 5. Window controls + window chrome + padlock (warning)
    //
    // Same-domain login forms worden automatisch genegeerd (legitieme logins)
    BITB_DETECTION: {
        // Fake URL bar patterns - bekende OAuth/login URLs die in nep vensters verschijnen
        fakeUrlBarPatterns: [
            /^https?:\/\/(accounts\.google\.com|myaccount\.google\.com)/i,
            /^https?:\/\/(login\.microsoftonline\.com|login\.microsoft\.com|login\.live\.com)/i,
            /^https?:\/\/(appleid\.apple\.com|idmsa\.apple\.com)/i,
            /^https?:\/\/(www\.facebook\.com\/login|facebook\.com\/login)/i,
            /^https?:\/\/(twitter\.com\/login|x\.com\/login)/i,
            /^https?:\/\/(github\.com\/login|github\.com\/session)/i,
            /^https?:\/\/(.*\.okta\.com)/i,
            /^https?:\/\/(.*\.auth0\.com)/i,
            /^https?:\/\/(accounts\.zoho\.com|accounts\.zoho\.eu)/i,
            /^https?:\/\/(login\.yahoo\.com|login\.aol\.com)/i
        ],

        // OAuth provider branding keywords (case-insensitive matching)
        oauthBranding: [
            'sign in with google', 'continue with google', 'google sign-in', 'inloggen met google',
            'sign in with microsoft', 'continue with microsoft', 'microsoft sign-in',
            'sign in with apple', 'continue with apple', 'apple sign-in',
            'sign in with facebook', 'continue with facebook', 'log in with facebook',
            'sign in with twitter', 'sign in with x', 'continue with x',
            'sign in with github', 'continue with github',
            'single sign-on', 'sso login', 'federated login',
            'sign in with okta', 'sign in with auth0'
        ],

        // Window control indicators (CSS classes en tekst patterns)
        windowControlIndicators: {
            // macOS traffic light buttons
            trafficLights: /[●○◯].*[●○◯].*[●○◯]|[🔴🟡🟢]|•\s*•\s*•/,
            // Close button characters
            closeButtons: /[×✕✖✗⨉]|&times;/,
            // Window control classes
            controlClasses: /\b(close|minimize|maximize|window-control|btn-close|modal-close|title-?bar|window-?header|traffic-?light)\b/i
        },

        // DEPRECATED: domainWhitelist is no longer used here.
        // All trusted domains are now centrally managed in TrustedDomains.json
        // The isTrustedDomain() function in content.js checks this list for ALL scans
        // (ClickFix, BitB, risk analysis, etc.)

        // Score thresholds voor alert levels
        thresholds: {
            log: 6,       // Alleen loggen, geen waarschuwing
            warning: 10,  // Lichte waarschuwing tonen
            critical: 16  // Kritieke waarschuwing - zeer waarschijnlijk BitB
        },

        // Risk scores per indicator type
        scores: {
            fakeUrlBar: 10,           // URL tekst van OAuth provider in overlay
            windowControls: 6,        // Nep window controls (close/min/max)
            loginFormInOverlay: 5,    // Login form in fixed overlay
            oauthBrandingWithForm: 6, // OAuth branding + login form
            padlockIcon: 3,           // Fake security/lock icon
            windowChromeStyle: 3,     // OS-achtige window styling
            iframeInModal: 2          // iframe binnen modal
        }
    },

    COMPOUND_TLDS: [
        'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'com.au', 'org.au', 'co.nz'
    ],

    // Domein Risicogewichten (verfijnd met recente data)
    domainRiskWeights: {
        'microsoft.com': 10, 'paypal.com': 8, 'outlook.com': 7, 'apple.com': 6, 'google.com': 5, 'linkedin.com': 4, 'chat.openai.com': 4, 'amazon.com': 3, 'facebook.com': 3, 'instagram.com': 3, 'opensea.io': 3, 'auth0.com': 3, 'teladoc.com': 3, 'zoom.us': 3, 'signal.org': 3, 'cloudflare.com': 3, 'nokia.com': 3, 'idquantique.com': 3, 'neuralink.com': 3, 'netflix.com': 2, 'whatsapp.com': 2, 'x.com': 2, 'decentraland.org': 2, 'ecosia.org': 2, 'smartcityexpo.com': 2, 'alibaba.com': 1, 'adobe.com': 1, 'dropbox.com': 1
    },

    // WebTransport/HTTP3 Monitoring - Detecteert misbruik van moderne protocols voor C2/exfiltration
    WEBTRANSPORT_MONITORING: {
        enabled: true,

        // Verdachte endpoint patronen
        suspiciousEndpoints: [
            /^https?:\/\/\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/i,  // Direct IP address
            /^https?:\/\/[^\/]+:\d{5,}/i,                        // High port numbers (10000+)
            /^https?:\/\/[^\/]+\.onion/i,                        // Tor hidden services
            /^https?:\/\/[a-z0-9]{32,}\.[^\/]+/i,                // Random subdomain (C2 indicator)
            /^https?:\/\/[^\/]+\.(tk|ml|ga|cf|gq)\//i,           // Free TLDs often used for C2
        ],

        // Bekende legitieme WebTransport endpoints (whitelist)
        trustedEndpoints: [
            /^https:\/\/[^\/]*\.google\.com/i,
            /^https:\/\/[^\/]*\.googleapis\.com/i,
            /^https:\/\/[^\/]*\.cloudflare\.com/i,
            /^https:\/\/[^\/]*\.fastly\.com/i,
            /^https:\/\/[^\/]*\.akamai\.com/i,
            /^https:\/\/[^\/]*\.microsoft\.com/i,
            /^https:\/\/[^\/]*\.azure\.com/i,
            /^https:\/\/[^\/]*\.amazonaws\.com/i,
            /^https:\/\/[^\/]*\.facebook\.com/i,
            /^https:\/\/[^\/]*\.meta\.com/i,
        ],

        // Gedragsdrempels
        thresholds: {
            maxConnectionsPerMinute: 10,      // Meer = verdacht
            maxDatagramsPerSecond: 100,       // Bulk data = verdacht
            maxStreamsPerConnection: 50,      // Veel streams = C2 indicator
            connectionTrackingWindowMs: 300000, // 5 minuten tracking window
        },

        // Risk scores per indicator type
        scores: {
            directIP: 8,           // Direct IP connection
            highPort: 4,           // Unusual port number
            randomSubdomain: 6,    // Random C2-like subdomain
            freeTLD: 5,            // Free TLD endpoint
            nrdEndpoint: 10,       // Newly registered domain endpoint
            highConnectionRate: 5, // Too many connections
            highDatagramRate: 6,   // Bulk data transfer
            obfuscatedUrl: 7,      // Base64/encoded URL components
            invalidUrl: 5,         // Malformed URL
        }
    }
};