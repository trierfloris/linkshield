/**
 * Add v8.8.0 i18n keys for enhanced Unicode and ASCII lookalike detection
 */

const fs = require('fs');
const path = require('path');

const localesDir = path.join(__dirname, '..', '_locales');

const newKeys = {
    "mathematicalAlphanumericsDetected": {
        "en": { "message": "Mathematical symbol lookalikes detected", "description": "" },
        "nl": { "message": "Wiskundige symbool-lookalikes gedetecteerd", "description": "" },
        "de": { "message": "Mathematische Symbolähnlichkeiten erkannt", "description": "" },
        "fr": { "message": "Symboles mathématiques ressemblants détectés", "description": "" },
        "es": { "message": "Símbolos matemáticos similares detectados", "description": "" }
    },
    "fullwidthCharactersDetected": {
        "en": { "message": "Fullwidth characters detected in URL", "description": "" },
        "nl": { "message": "Fullwidth-tekens gedetecteerd in URL", "description": "" },
        "de": { "message": "Vollbreite Zeichen in URL erkannt", "description": "" },
        "fr": { "message": "Caractères pleine largeur détectés", "description": "" },
        "es": { "message": "Caracteres de ancho completo detectados", "description": "" }
    },
    "greekLettersDetected": {
        "en": { "message": "Greek letter substitution detected", "description": "" },
        "nl": { "message": "Griekse lettervervanging gedetecteerd", "description": "" },
        "de": { "message": "Griechische Buchstabenersetzung erkannt", "description": "" },
        "fr": { "message": "Substitution de lettres grecques détectée", "description": "" },
        "es": { "message": "Sustitución de letras griegas detectada", "description": "" }
    },
    "cyrillicCharactersDetected": {
        "en": { "message": "Cyrillic character substitution detected", "description": "" },
        "nl": { "message": "Cyrillische tekens gedetecteerd", "description": "" },
        "de": { "message": "Kyrillische Zeichen erkannt", "description": "" },
        "fr": { "message": "Caractères cyrilliques détectés", "description": "" },
        "es": { "message": "Caracteres cirílicos detectados", "description": "" }
    },
    "cherokeeCharactersDetected": {
        "en": { "message": "Cherokee character lookalikes detected", "description": "" },
        "nl": { "message": "Cherokee tekens gedetecteerd", "description": "" },
        "de": { "message": "Cherokee-Zeichen erkannt", "description": "" },
        "fr": { "message": "Caractères Cherokee détectés", "description": "" },
        "es": { "message": "Caracteres Cherokee detectados", "description": "" }
    },
    "scriptSymbolsDetected": {
        "en": { "message": "Script symbol lookalikes detected", "description": "" },
        "nl": { "message": "Script-symbolen gedetecteerd", "description": "" },
        "de": { "message": "Skript-Symbole erkannt", "description": "" },
        "fr": { "message": "Symboles de script détectés", "description": "" },
        "es": { "message": "Símbolos de script detectados", "description": "" }
    },
    "asciiLookalikePaypal": {
        "en": { "message": "Possible PayPal impersonation (1 vs l)", "description": "" },
        "nl": { "message": "Mogelijke PayPal-imitatie (1 vs l)", "description": "" },
        "de": { "message": "Mögliche PayPal-Imitation (1 vs l)", "description": "" },
        "fr": { "message": "Possible usurpation PayPal (1 vs l)", "description": "" },
        "es": { "message": "Posible suplantación de PayPal (1 vs l)", "description": "" }
    },
    "asciiLookalikeAmazon": {
        "en": { "message": "Possible Amazon impersonation (rn vs m)", "description": "" },
        "nl": { "message": "Mogelijke Amazon-imitatie (rn vs m)", "description": "" },
        "de": { "message": "Mögliche Amazon-Imitation (rn vs m)", "description": "" },
        "fr": { "message": "Possible usurpation Amazon (rn vs m)", "description": "" },
        "es": { "message": "Posible suplantación de Amazon (rn vs m)", "description": "" }
    },
    "asciiLookalikeMicrosoft": {
        "en": { "message": "Possible Microsoft impersonation (0 vs o)", "description": "" },
        "nl": { "message": "Mogelijke Microsoft-imitatie (0 vs o)", "description": "" },
        "de": { "message": "Mögliche Microsoft-Imitation (0 vs o)", "description": "" },
        "fr": { "message": "Possible usurpation Microsoft (0 vs o)", "description": "" },
        "es": { "message": "Posible suplantación de Microsoft (0 vs o)", "description": "" }
    },
    "asciiLookalikeGoogle": {
        "en": { "message": "Possible Google impersonation (0 vs o)", "description": "" },
        "nl": { "message": "Mogelijke Google-imitatie (0 vs o)", "description": "" },
        "de": { "message": "Mögliche Google-Imitation (0 vs o)", "description": "" },
        "fr": { "message": "Possible usurpation Google (0 vs o)", "description": "" },
        "es": { "message": "Posible suplantación de Google (0 vs o)", "description": "" }
    },
    "asciiLookalikeTwitter": {
        "en": { "message": "Possible Twitter impersonation (l vs i)", "description": "" },
        "nl": { "message": "Mogelijke Twitter-imitatie (l vs i)", "description": "" },
        "de": { "message": "Mögliche Twitter-Imitation (l vs i)", "description": "" },
        "fr": { "message": "Possible usurpation Twitter (l vs i)", "description": "" },
        "es": { "message": "Posible suplantación de Twitter (l vs i)", "description": "" }
    },
    "asciiLookalikeFacebook": {
        "en": { "message": "Possible Facebook impersonation (0 vs o)", "description": "" },
        "nl": { "message": "Mogelijke Facebook-imitatie (0 vs o)", "description": "" },
        "de": { "message": "Mögliche Facebook-Imitation (0 vs o)", "description": "" },
        "fr": { "message": "Possible usurpation Facebook (0 vs o)", "description": "" },
        "es": { "message": "Posible suplantación de Facebook (0 vs o)", "description": "" }
    },
    "asciiLookalikeApple": {
        "en": { "message": "Possible Apple impersonation (1 vs l)", "description": "" },
        "nl": { "message": "Mogelijke Apple-imitatie (1 vs l)", "description": "" },
        "de": { "message": "Mögliche Apple-Imitation (1 vs l)", "description": "" },
        "fr": { "message": "Possible usurpation Apple (1 vs l)", "description": "" },
        "es": { "message": "Posible suplantación de Apple (1 vs l)", "description": "" }
    },
    "asciiLookalikeWww": {
        "en": { "message": "Suspicious WWW substitution (vvv vs w)", "description": "" },
        "nl": { "message": "Verdachte WWW-vervanging (vvv vs w)", "description": "" },
        "de": { "message": "Verdächtige WWW-Ersetzung (vvv vs w)", "description": "" },
        "fr": { "message": "Substitution WWW suspecte (vvv vs w)", "description": "" },
        "es": { "message": "Sustitución WWW sospechosa (vvv vs w)", "description": "" }
    },
    "brandImpersonation": {
        "en": { "message": "Possible brand impersonation attempt", "description": "" },
        "nl": { "message": "Mogelijke merkimitatie-poging", "description": "" },
        "de": { "message": "Möglicher Markenimitationsversuch", "description": "" },
        "fr": { "message": "Tentative possible d'usurpation de marque", "description": "" },
        "es": { "message": "Posible intento de suplantación de marca", "description": "" }
    }
};

// Process each locale
const locales = fs.readdirSync(localesDir).filter(f =>
    fs.statSync(path.join(localesDir, f)).isDirectory()
);

let updated = 0;

locales.forEach(locale => {
    const messagesPath = path.join(localesDir, locale, 'messages.json');

    if (!fs.existsSync(messagesPath)) return;

    try {
        let content = fs.readFileSync(messagesPath, 'utf8');
        let messages = JSON.parse(content);
        let changed = false;

        for (const [key, translations] of Object.entries(newKeys)) {
            if (!messages[key]) {
                // Use locale-specific translation or fallback to English
                const translation = translations[locale] || translations['en'];
                messages[key] = translation;
                changed = true;
            }
        }

        if (changed) {
            fs.writeFileSync(messagesPath, JSON.stringify(messages, null, 2), 'utf8');
            updated++;
            console.log(`OK: ${locale}`);
        }
    } catch (e) {
        console.error(`ERROR: ${locale} - ${e.message}`);
    }
});

console.log(`\nDONE: Updated ${updated} locales with v8.8.0 i18n keys`);
