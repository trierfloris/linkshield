# LinkShield

A Chrome extension that protects users against phishing attacks, malicious URLs, and deceptive websites.

## Features

- **Phishing Detection** - Analyzes URLs and page content for common phishing indicators
- **Browser-in-Browser (BitB) Attack Detection** - Detects fake browser windows used in advanced phishing attacks
- **IDN Homograph Attack Protection** - Identifies deceptive Unicode characters in domain names (e.g., pаypal.com using Cyrillic 'а')
- **QR Code Scanning** - Scans QR codes on pages for malicious URLs
- **SSL Certificate Validation** - Verifies SSL certificates via SSL Labs API
- **Trusted Domains Whitelist** - Mark legitimate domains as trusted to prevent false positives
- **Real-time Protection** - Continuous monitoring with visual status indicators

## Supported Languages

LinkShield is available in 24 languages:

Arabic, Chinese, Czech, Dutch, English, French, German, Greek, Hindi, Hungarian, Indonesian, Italian, Japanese, Korean, Polish, Portuguese, Portuguese (Brazil), Romanian, Russian, Spanish, Thai, Turkish, Ukrainian, Vietnamese

## Installation

### From Chrome Web Store
*(Coming soon)*

### Manual Installation (Developer Mode)

1. Download or clone this repository
2. Open Chrome and navigate to `chrome://extensions/`
3. Enable **Developer mode** (toggle in top right)
4. Click **Load unpacked**
5. Select the `dist` folder from this repository

## Project Structure

```
LinkShield/
├── dist/                    # Extension files (load this folder in Chrome)
│   ├── manifest.json        # Extension manifest (Manifest V3)
│   ├── background.js        # Service worker
│   ├── content.js           # Content script for page analysis
│   ├── config.js            # Configuration settings
│   ├── popup.html           # Main popup UI
│   ├── alert.html           # High-risk warning page
│   ├── caution.html         # Medium-risk warning page
│   ├── _locales/            # Internationalization files
│   └── icons/               # Extension icons
├── tests/                   # Jest test files
├── package.json             # Node.js dependencies (for testing)
└── README.md
```

## How It Works

LinkShield uses multiple detection methods:

1. **URL Analysis** - Checks for suspicious patterns, known phishing indicators, and deceptive domain names
2. **Page Content Analysis** - Scans forms, scripts, and page structure for phishing characteristics
3. **Visual Indicators** - Extension icon changes color based on threat level:
   - 🟢 Green: Safe
   - 🟡 Yellow: Caution (potential risk)
   - 🔴 Red: Alert (high risk)
   - ⚫ Grey: Unable to analyze

## Privacy

- All analysis is performed locally in your browser
- No browsing data is sent to external servers (except for optional SSL Labs certificate verification)
- Trusted domains are stored locally using Chrome's storage API

## Development

### Prerequisites

- Node.js (for running tests)
- Chrome browser

### Running Tests

```bash
npm install
npm test
```

### Test Coverage

```bash
npm run test:coverage
```

## Third-Party Libraries

- [jsQR](https://github.com/cozmo/jsQR) - QR code detection and decoding
- [Punycode.js](https://github.com/mathiasbynens/punycode.js) - Unicode/Punycode conversion for IDN handling

## License

This project is proprietary software. All rights reserved.

## Support

For bug reports and feature requests, please open an issue on GitHub.

---

*LinkShield - Protecting your browsing experience*
