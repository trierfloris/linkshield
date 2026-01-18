# LinkShield Detection Audit v2.0

## Snelle Start

```bash
# 1. Installeer dependencies (eenmalig)
cd tests
npm install puppeteer

# 2. Start webserver (terminal 1)
npx serve test-pages -p 8080

# 3. Run audit (terminal 2)
node detection-audit-runner.js
```

## Vereisten

- Node.js 18+
- Chrome browser (wordt automatisch door Puppeteer gebruikt)
- LinkShield extensie in parent directory

## Belangrijke Configuratie

### NIET Headless Mode
De test runner gebruikt `headless: false` omdat:
- QR code scanning vereist echte canvas rendering
- Clipboard tests vereisen echte user gesture context
- Sommige MutationObservers werken anders in headless

### HTTP Server Vereist
Tests draaien op `http://localhost:8080`, niet `file://` omdat:
- Chrome extensies hebben beperkte toegang tot file:// URLs
- Cross-origin policies werken anders op file://
- Sommige APIs (clipboard, fetch) zijn geblokkeerd op file://

## Test Methodologie per Layer

| Layer | Trigger | Wat wordt getest |
|-------|---------|------------------|
| 1 | **Hover** over links | TLD check, phishing keywords |
| 2 | **Hover** over links | Punycode, Cyrillisch, homoglyphs |
| 3 | **Auto** (2s delay) | Overlay + fake URL bar detectie |
| 4 | **Auto** (2s delay) | PowerShell/CMD patterns in page |
| 5 | **Auto** (1s delay) | z-index + pointer-events scan |
| 6 | **Scroll** naar images | IntersectionObserver QR scan |
| 7 | **Hover** over links | javascript:, data:, blob: schemes |
| 8 | **Focus** password + **wacht** | MutationObserver action change |
| 9 | **Ctrl+C** simulatie | Copy event hijacking |
| 10 | **Auto** (1s delay) | Shadow DOM recursive scan |

## Verwachte Resultaten

```
| Layer | Feature                          | Status       |
|-------|----------------------------------|--------------|
| 1     | Phishing URLs & Suspicious TLDs  | ✅ DETECTED  |
| 2     | Unicode Lookalike Domains        | ✅ DETECTED  |
| 3     | Fake Browser Windows (BitB)      | ✅ DETECTED  |
| 4     | PowerShell/ClickFix              | ✅ DETECTED  |
| 5     | Invisible Overlay Attacks        | ✅ DETECTED  |
| 6     | Malicious QR Codes               | ✅ DETECTED  |
| 7     | Dangerous Link Types             | ✅ DETECTED  |
| 8     | Form Hijacking                   | ✅ DETECTED  |
| 9     | Clipboard Manipulation           | ✅ DETECTED  |
| 10    | Shadow DOM Abuse                 | ✅ DETECTED  |

Total: 10/10 passed (100%)
```

## Bekende Beperkingen

### Closed Shadow DOM (Layer 10)
- `mode: 'closed'` Shadow DOM is BY DESIGN niet toegankelijk
- Dit is een browser security feature, niet een LinkShield bug
- Test alleen open Shadow DOM

### Clipboard (Layer 9)
- `navigator.clipboard.writeText()` zonder user gesture wordt geblokkeerd door browser
- Test detecteert of LinkShield de POGING detecteert
- In echte aanvallen wordt dit gecombineerd met social engineering

### QR Codes (Layer 6)
- Vereist dat image in viewport is (IntersectionObserver)
- jsQR library moet geladen zijn
- Headless mode kan canvas rendering issues hebben

## Handmatige Verificatie

Als automatische tests falen, verifieer handmatig:

### Layer 1 & 2 - Links
1. Open `http://localhost:8080/detection-audit/layer1-phishing-urls.html`
2. **Hover** over een rode link
3. Check: verschijnt tooltip/warning?
4. Check console: `[LinkShield] Risk score`

### Layer 8 - Form Hijacking
1. Open `http://localhost:8080/detection-audit/layer8-form-hijacking.html`
2. Wacht 2 seconden (form action wordt gewijzigd)
3. Klik in password veld
4. Check: verschijnt form hijacking warning?

### Layer 9 - Clipboard
1. Open `http://localhost:8080/detection-audit/layer9-clipboard-hijacking.html`
2. Selecteer tekst in het groene vak
3. Druk Ctrl+C
4. Check: verschijnt clipboard warning?

## Debug Mode

Voeg toe aan `config.js` voor extra logging:
```javascript
DEBUG_MODE: true,
```

Dan zie je in console:
- `[LinkShield]` prefixed logs
- Risk scores per link
- Detection triggers

## Troubleshooting

### "Test server not running"
```bash
# Start server in tests folder
cd tests
npx serve test-pages -p 8080
```

### "Extension not found"
- Check of `manifest.json` in parent directory staat
- Check pad in `CONFIG.extensionPath`

### "0 detections"
1. Is `DEBUG_MODE: true` in config.js?
2. Draait de extensie? Check chrome://extensions
3. Is de test pagina niet op trusted domain?

### Headless mode issues
```javascript
// In detection-audit-runner.js
headless: false, // MOET false zijn
```

## Output

Na succesvolle run:
- Console toont tabel met resultaten
- `detection-audit-results.json` bevat gedetailleerde data
