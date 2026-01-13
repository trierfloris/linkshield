const fs = require('fs');
const path = require('path');

const bgPath = path.join(__dirname, '..', 'background.js');
let content = fs.readFileSync(bgPath, 'utf8');
content = content.replace(/\r\n/g, '\n');

const oldCase = `            case 'protection_preserved':
                title = chrome.i18n.getMessage('failSafePreservedTitle') || 'Protection Active';
                message = chrome.i18n.getMessage('failSafePreservedMessage') ||
                    'Your protection rules are preserved. Please verify your license when possible.';
                break;
            default:`;

const newCase = `            case 'protection_preserved':
                title = chrome.i18n.getMessage('failSafePreservedTitle') || 'Protection Active';
                message = chrome.i18n.getMessage('failSafePreservedMessage') ||
                    'Your protection rules are preserved. Please verify your license when possible.';
                break;
            case 'fresh_install_failsafe':
                title = chrome.i18n.getMessage('failSafeFreshInstallTitle') || 'Protection Enabled';
                message = chrome.i18n.getMessage('failSafeFreshInstallMessage') ||
                    'LinkShield protection is active. Please verify your license when possible.';
                break;
            default:`;

if (content.includes(oldCase)) {
    content = content.replace(oldCase, newCase);
    content = content.replace(/\n/g, '\r\n');
    fs.writeFileSync(bgPath, content, 'utf8');
    console.log('SUCCESS: Added fresh_install_failsafe case');
} else {
    console.log('ERROR: Case pattern not found');
}
