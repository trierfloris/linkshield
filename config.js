window.CONFIG = {
    // Verdachte Top-Level Domeinen (TLD’s)
    // Opgeschoond en ontdubbeld voor betere prestaties en onderhoud.
    SUSPICIOUS_TLDS: new RegExp('\\.(' + Array.from(new Set([
        'academy', 'accountant', 'accountants', 'agency', 'ap', 'app', 'art', 'asia', 'auto', 'bar', 'beauty', 'bet', 'bid', 'bio', 'biz', 'blog', 'buzz', 'cam', 'capital', 'casa', 'casino', 'cfd', 'charity', 'cheap', 'church', 'city', 'claims', 'click', 'club', 'company', 'crispsalt', 'cyou', 'data', 'date', 'design', 'dev', 'digital', 'directory', 'download', 'email', 'energy', 'estate', 'events', 'exchange', 'expert', 'exposed', 'express', 'finance', 'fit', 'forsale', 'foundation', 'fun', 'games', 'gle', 'goog', 'gq', 'guide', 'guru', 'health', 'help', 'home', 'host', 'html', 'icu', 'ink', 'institute', 'investments', 'ip', 'jobs', 'life', 'limited', 'link', 'live', 'loan', 'lol', 'ltd', 'ly', 'mall', 'market', 'me', 'media', 'men', 'ml', 'mom', 'money', 'monster', 'mov', 'network', 'one', 'online', 'page', 'partners', 'party', 'php', 'pics', 'play', 'press', 'pro', 'promo', 'pw', 'quest', 'racing', 'rest', 'review', 'rocks', 'run', 'sbs', 'school', 'science', 'services', 'shop', 'shopping', 'site', 'software', 'solutions', 'space', 'store', 'stream', 'support', 'team', 'tech', 'tickets', 'to', 'today', 'tools', 'top', 'trade', 'trading', 'uno', 'ventures', 'vip', 'website', 'wiki', 'win', 'work', 'world', 'xin', 'xyz', 'zip', 'zone', 'co', 'cc', 'tv', 'name', 'lat', 'bond', 'crypto', 'wallet', 'quantum', 'nft', 'web3', 'metaverse', 'vr', 'dao', 'green', 'privacy', 'smart', 'edge', 'connect', 'holo', 'neuro'
    ])).join('|') + ')$', 'i'),

    // ==== Risicodrempels voor gefaseerde analyse en UI-feedback ====
    LOW_THRESHOLD: 4,      //  risico < 4 → safe
    MEDIUM_THRESHOLD: 8,     //  4 ≤ risico < 8 → caution
    HIGH_THRESHOLD: 15,    //  risico ≥ 15 → alert
    SCRIPT_RISK_THRESHOLD: 10,  // drempel voor inhoudsanalyse van externe scripts

    YOUNG_DOMAIN_THRESHOLD_DAYS: 14, // Domeinen jonger dan 2 weken (blijft 14)
    DOMAIN_AGE_MIN_RISK: 5,        // Domeinleeftijd‐check vanaf 5 punten (was 3)
    YOUNG_DOMAIN_RISK: 5,          // Risico‐gewicht voor jonge domeinen (was 7)
    PROTOCOL_RISK: 4,

    // Debug Modus
    DEBUG_MODE: false, // Zet op true voor debugging, false voor productie

    // Toegestane URL Protocollen
    ALLOWED_PROTOCOLS: ['http:', 'https:', 'mailto:', 'tel:', 'ftp:'],

    // Verdachte Bestandsextensies
    // Verfijnd om false positives op .js, .py, en .dll te vermijden.
    MALWARE_EXTENSIONS: /\.(exe|zip|bak|tar|gz|msi|dmg|jar|rar|7z|iso|bin|scr|bat|cmd|sh|vbs|lnk|chm|ps2|apk|ps1|vbscript|docm|xlsm|pptm|doc|xls|ppt|rtf|torrent|wsf|hta|jse|reg|swf|svg|wsh|pif|wasm)$/i,

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
    TRUSTED_IFRAME_DOMAINS: [
        'youtube.com', 'www.youtube.com', 'youtu.be', 'vimeo.com', 'player.vimeo.com', 'dailymotion.com', 'www.dailymotion.com', 'twitch.tv', 'player.twitch.tv', 'soundcloud.com', 'w.soundcloud.com', 'spotify.com', 'open.spotify.com', 'maps.google.com', 'www.google.com/maps', 'docs.google.com', 'drive.google.com', 'calendar.google.com', 'forms.google.com', 'openstreetmap.org', 'www.openstreetmap.org', 'facebook.com', 'www.facebook.com', 'facebook.net', 'instagram.com', 'www.instagram.com', 'twitter.com', 'www.twitter.com', 'platform.twitter.com', 'linkedin.com', 'www.linkedin.com', 'platform.linkedin.com', 'pinterest.com', 'assets.pinterest.com', 'tiktok.com', 'embed.tiktok.com', 'paypal.com', 'www.paypal.com', 'stripe.com', 'js.stripe.com', 'checkout.stripe.com', 'adyen.com', 'checkoutshopper-live.adyen.com', 'discord.com', 'discordapp.com', 'slack.com', 'app.slack.com', 'intercom.io', 'widget.intercom.io', 'crisp.chat', 'webchat.livechatinc.com', 'js.zendesk.com', 'gist.github.com', 'codesandbox.io', 'stackblitz.com', 'repl.it', 'embed.replit.com', 'doubleclick.net', 'fls.doubleclick.net', 'googleadservices.com', 'googlesyndication.com', 'adservice.google.com', 'ads.pubmatic.com', 'hb.pubmatic.com', 'ads.rubiconproject.com', 'ads.adnxs.com', 'secure.adnxs.com', 'servedby.flashtalking.com', 'ads.yahoo.com', 'ads.openx.net', 'a.openx.net', 'indexexchange.com', 'sync.crwdcntrl.net', 'ads.coinzilla.com', 'adsafeprotected.com', 'segment.com', 'analytics.twitter.com', 'analytics.tiktok.com', 'bat.bing.com', 'cm.g.doubleclick.net', 'widget.buqer.com', 'widget.trustpilot.com', 'consent.cookiebot.com', 'consentcdn.cookiebot.com'
    ],

    // Inlogpatronen
    LOGIN_PATTERNS: /(login|account|auth|authenticate|signin|wp-login|sign-in|log-in|dashboard|portal|session|user|profile)/i,

    // Gratis Hosting Domeinen
    FREE_HOSTING_DOMAINS: [
        'sites.net', 'angelfire.com', 'geocities.ws', '000a.biz', '000webhostapp.com', 'weebly.com', 'wixsite.com', 'freehosting.com', 'glitch.me', 'firebaseapp.com', 'herokuapp.com', 'freehostia.com', 'netlify.app', 'webs.com', 'yolasite.com', 'github.io', 'bravenet.com', 'zyro.com', 'altervista.org', 'tripod.com', 'jimdo.com', 'ucoz.com', 'blogspot.com', 'square.site', 'pages.dev', 'r2.dev', 'mybluehost.me', '000space.com', 'awardspace.com', 'byethost.com', 'biz.nf', 'hyperphp.com', 'infinityfree.net', '50webs.com', 'tripod.lycos.com', 'site123.me', 'webflow.io', 'strikingly.com', 'x10hosting.com', 'freehostingnoads.net', '000freewebhost.com', 'mystrikingly.com', 'sites.google.com', 'appspot.com', 'vercel.app', 'weeblysite.com', 's3.amazonaws.com', 'bubbleapps.io', 'typedream.app', 'codeanyapp.com', 'carrd.co', 'surge.sh', 'replit.dev', 'fly.dev', 'render.com', 'onrender.com', 'fly.io', 'workers.dev'
    ],

    // Verkorte URL Domeinen
    SHORTENED_URL_DOMAINS: [
        "bit.ly", "tinyurl.com", "goo.gl", "t.co", "ow.ly", "is.gd", "buff.ly", "su.pr", "tiny.cc", "x.co", "rebrand.ly", "mcaf.ee", "po.st", "adf.ly", "cutt.ly", "qrco.de", "yourls.org", "shrtco.de", "chilp.it", "clck.ru", "rb.gy", "shorturl.at", "lnkd.in", "shorte.st", "cli.re", "surl.li", "tny.im", "zi.ma", "t1p.de", "urlz.fr", "did.li", "v.ht", "short.cm", "bit.do", "t.ly", "4gp.me", "linktr.ee", "tiny.ie", "1url.com", "hyperurl.co", "lnk.to", "snip.ly", "flip.to", "adcrun.ch", "short.to", "t.co.uk", "kutt.it", "flic.kr", "qr.net", "trk.li", "smll.co", "xurl.es", "xup.pl", "b.link", "x.gd", "n9.cl", "zi.pe", "qr.ae", "0rz.tw", "qqc.co", "h6y.eu", "fw.to", "lnk2.me", "shurl.net", "mrk.to", "clk.im", "u.to", "ezurl.cc", "fur.ly", "v.gd", "2ty.cc", "sh.ky", "s.coop", "cutt.us", "bitly.com", "q.gs", "i.cut", "s.id", "linklyhq.com", "slkt.io", "pp.gg", "short.url", "zpr.io", "me.qr", "short.io", "dub.co", "cl.ly", "bl.ink", "go.ly", "soo.gd", "jmp.sh", "u.nu", "t2m.io", "short.link", "tiny.one", "shr.link", "linkly.me", "cut.link", "shorty.ai", "link.ai", "tiny.ai", "cut.ai"
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

    // Homoglyphs Mapping
    HOMOGLYPHS: {
        'a': ['а', 'α', 'ⱥ', 'ä', 'å', 'á', 'à', 'â', 'ã', 'ā', 'ă', 'ǎ', 'ȁ', 'ȃ', 'ǻ', 'ª'], 'e': ['е', 'ε', 'ë', 'ē', 'ĕ', 'ė', 'ę', 'ě', 'ê', 'è', 'é', 'ȅ', 'ȇ', '€', 'ɛ'], 'o': ['ο', 'о', 'ö', 'ó', 'ò', 'ô', 'õ', 'ō', 'ŏ', 'ő', 'ø', 'ǒ', 'ȍ', 'ȏ', 'º'], 'i': ['і', 'í', 'ì', 'î', 'ï', 'ī', 'ĭ', 'į', 'ǐ', 'ɨ', 'ı', '¡'], 's': ['ѕ', 'ß', '$', 'ś', 'ŝ', 'ş', 'š', '§', 'ʃ'], 'c': ['с', 'ç', '¢', 'ć', 'ĉ', 'ċ', 'č', '©', 'ȼ', 'ƈ'], 'd': ['ԁ', 'đ', 'ď', 'ḋ', 'ḍ', 'ḏ', 'ḑ', 'ḓ', 'ɖ'], 'g': ['ɡ', 'ġ', 'ğ', 'ĝ', 'ǧ', 'ģ', 'ǥ', 'ɢ'], 'h': ['һ', 'ħ', 'ĥ', 'ḥ', 'ḧ', 'ḩ', 'ḫ', 'ɦ'], 'k': ['κ', 'ќ', 'ḱ', 'ǩ', 'ķ', 'ḳ', 'ḵ', 'ƙ'], 'l': ['ӏ', 'Ɩ', 'ĺ', 'ļ', 'ľ', 'ŀ', 'ł', 'Ɨ', 'ǀ'], 'n': ['п', 'ñ', 'ń', 'ņ', 'ň', 'ŉ', 'ŋ', 'ṅ', 'ṇ', 'ṉ', 'ƞ'], 'p': ['р', 'ƿ', 'ṕ', 'ṗ', 'ƥ', '℗'], 't': ['τ', 'т', 'ţ', 'ť', 'ŧ', 'ṭ', 'ṯ', 'ṱ', 'ƭ', '†'], 'u': ['υ', 'ц', 'ü', 'ú', 'ù', 'û', 'ū', 'ŭ', 'ů', 'ű', 'ų', 'ǔ', 'ȕ', 'ȗ', 'µ'], 'x': ['х', '×', 'ẋ', 'ẍ', 'χ'], 'y': ['у', 'ý', 'ÿ', 'ŷ', 'ȳ', '¥', 'ƴ', 'ɏ'], 'z': ['ž', 'ƶ', 'ź', 'ż', 'ẑ', 'ẓ', 'ẕ', 'ƹ', 'ɀ']
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
        'microsoft.com', 'apple.com', 'google.com', 'linkedin.com', 'alibaba.com', 'whatsapp.com', 'amazon.com', 'x.com', 'facebook.com', 'adobe.com', 'paypal.com', 'netflix.com', 'instagram.com', 'outlook.com', 'opensea.io', 'decentraland.org', 'chat.openai.com', 'auth0.com', 'teladoc.com', 'zoom.us', 'signal.org', 'ecosia.org', 'smartcityexpo.com', 'cloudflare.com', 'nokia.com', 'idquantique.com', 'neuralink.com'
    ],

    COMPOUND_TLDS: [
        'co.uk', 'org.uk', 'gov.uk', 'ac.uk', 'com.au', 'org.au', 'co.nz'
    ],

    // Domein Risicogewichten (verfijnd met recente data)
    domainRiskWeights: {
        'microsoft.com': 10, 'paypal.com': 8, 'outlook.com': 7, 'apple.com': 6, 'google.com': 5, 'linkedin.com': 4, 'chat.openai.com': 4, 'amazon.com': 3, 'facebook.com': 3, 'instagram.com': 3, 'opensea.io': 3, 'auth0.com': 3, 'teladoc.com': 3, 'zoom.us': 3, 'signal.org': 3, 'cloudflare.com': 3, 'nokia.com': 3, 'idquantique.com': 3, 'neuralink.com': 3, 'netflix.com': 2, 'whatsapp.com': 2, 'x.com': 2, 'decentraland.org': 2, 'ecosia.org': 2, 'smartcityexpo.com': 2, 'alibaba.com': 1, 'adobe.com': 1, 'dropbox.com': 1
    }
};