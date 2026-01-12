/**
 * WebTransport/HTTP3 Monitoring Test Suite
 * Tests detection of suspicious WebTransport usage patterns
 */

const fs = require('fs');
const path = require('path');

// Load config
const configPath = path.join(__dirname, '..', 'config.js');
const configContent = fs.readFileSync(configPath, 'utf8');

// Extract CONFIG object
const configMatch = configContent.match(/window\.CONFIG\s*=\s*(\{[\s\S]*\});?\s*$/);
let CONFIG;
if (configMatch) {
    eval('CONFIG = ' + configMatch[1]);
}

// Mock chrome API
global.chrome = {
    i18n: {
        getMessage: jest.fn((key) => key)
    },
    runtime: {
        sendMessage: jest.fn(() => Promise.resolve({}))
    }
};

// Mock globalConfig
global.globalConfig = CONFIG;

// Import functions from content.js (simulated since we can't directly import)
// We'll test the logic directly

/**
 * Simulated analyzeWebTransportEndpoint function
 */
function analyzeWebTransportEndpoint(url) {
    const config = CONFIG?.WEBTRANSPORT_MONITORING;
    if (!config?.enabled) return { score: 0, reasons: [], isTrusted: false };

    const scores = config.scores;
    let score = 0;
    const reasons = [];

    try {
        const parsedUrl = new URL(url);
        const hostname = parsedUrl.hostname;
        const port = parsedUrl.port;

        // Check trusted endpoints first
        for (const pattern of config.trustedEndpoints || []) {
            if (pattern.test(url)) {
                return { score: 0, reasons: [], isTrusted: true };
            }
        }

        // Direct IP address
        if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$/.test(hostname)) {
            score += scores.directIP;
            reasons.push('webTransportDirectIP');
        }

        // High port number (10000+)
        if (port && parseInt(port) >= 10000) {
            score += scores.highPort;
            reasons.push('webTransportHighPort');
        }

        // Random C2-like subdomain (32+ random chars)
        const subdomainMatch = hostname.match(/^([a-z0-9]+)\./i);
        if (subdomainMatch && subdomainMatch[1].length >= 32 && /^[a-z0-9]+$/i.test(subdomainMatch[1])) {
            score += scores.randomSubdomain;
            reasons.push('webTransportRandomSubdomain');
        }

        // Free TLD
        if (/\.(tk|ml|ga|cf|gq)$/i.test(hostname)) {
            score += scores.freeTLD;
            reasons.push('webTransportFreeTLD');
        }

        // Base64 in URL - check each path segment individually
        const pathSegments = parsedUrl.pathname.split('/').filter(s => s.length > 0);
        const queryParams = parsedUrl.search ? parsedUrl.search.slice(1).split('&') : [];
        const allSegments = [...pathSegments, ...queryParams];
        const base64Pattern = /^[A-Za-z0-9+\/=]{20,}$/;

        for (const segment of allSegments) {
            if (base64Pattern.test(segment)) {
                try {
                    atob(segment);
                    score += scores.obfuscatedUrl;
                    reasons.push('webTransportObfuscatedUrl');
                    break; // Only add once
                } catch {
                    // Not valid base64, continue
                }
            }
        }

        // Double encoding
        if (/%25[0-9A-Fa-f]{2}/.test(url)) {
            score += scores.obfuscatedUrl;
            reasons.push('webTransportObfuscatedUrl');
        }

    } catch (e) {
        score += scores.invalidUrl || 5;
        reasons.push('webTransportInvalidUrl');
    }

    return { score, reasons, isTrusted: false };
}

describe('WebTransport Monitoring', () => {

    describe('Configuration', () => {
        it('should have WEBTRANSPORT_MONITORING config defined', () => {
            expect(CONFIG.WEBTRANSPORT_MONITORING).toBeDefined();
        });

        it('should be enabled by default', () => {
            expect(CONFIG.WEBTRANSPORT_MONITORING.enabled).toBe(true);
        });

        it('should have suspicious endpoint patterns', () => {
            expect(CONFIG.WEBTRANSPORT_MONITORING.suspiciousEndpoints).toBeDefined();
            expect(CONFIG.WEBTRANSPORT_MONITORING.suspiciousEndpoints.length).toBeGreaterThan(0);
        });

        it('should have trusted endpoint patterns', () => {
            expect(CONFIG.WEBTRANSPORT_MONITORING.trustedEndpoints).toBeDefined();
            expect(CONFIG.WEBTRANSPORT_MONITORING.trustedEndpoints.length).toBeGreaterThan(0);
        });

        it('should have threshold configuration', () => {
            expect(CONFIG.WEBTRANSPORT_MONITORING.thresholds).toBeDefined();
            expect(CONFIG.WEBTRANSPORT_MONITORING.thresholds.maxConnectionsPerMinute).toBeGreaterThan(0);
            expect(CONFIG.WEBTRANSPORT_MONITORING.thresholds.maxDatagramsPerSecond).toBeGreaterThan(0);
        });

        it('should have score configuration', () => {
            expect(CONFIG.WEBTRANSPORT_MONITORING.scores).toBeDefined();
            expect(CONFIG.WEBTRANSPORT_MONITORING.scores.directIP).toBeGreaterThan(0);
            expect(CONFIG.WEBTRANSPORT_MONITORING.scores.randomSubdomain).toBeGreaterThan(0);
        });
    });

    describe('Endpoint Analysis - Suspicious Patterns', () => {

        it('should flag direct IP address endpoints', () => {
            const result = analyzeWebTransportEndpoint('https://192.168.1.1:4433/ws');
            expect(result.score).toBeGreaterThan(0);
            expect(result.reasons).toContain('webTransportDirectIP');
        });

        it('should flag public IP address endpoints', () => {
            const result = analyzeWebTransportEndpoint('https://45.33.32.156:443/connect');
            expect(result.score).toBeGreaterThan(0);
            expect(result.reasons).toContain('webTransportDirectIP');
        });

        it('should flag high port numbers (10000+)', () => {
            const result = analyzeWebTransportEndpoint('https://evil.com:54321/');
            expect(result.reasons).toContain('webTransportHighPort');
        });

        it('should flag very high port numbers (65000+)', () => {
            const result = analyzeWebTransportEndpoint('https://c2.example.com:65432/beacon');
            expect(result.reasons).toContain('webTransportHighPort');
        });

        it('should flag random C2-like subdomains (32+ chars)', () => {
            const result = analyzeWebTransportEndpoint('https://a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8.evil.com/');
            expect(result.reasons).toContain('webTransportRandomSubdomain');
        });

        it('should flag hex-encoded subdomain patterns', () => {
            const result = analyzeWebTransportEndpoint('https://deadbeefcafebabedeadbeefcafebabedeadbeef.malware.net/');
            expect(result.reasons).toContain('webTransportRandomSubdomain');
        });

        it('should flag free TLD endpoints (.tk)', () => {
            const result = analyzeWebTransportEndpoint('https://malware.tk/connect');
            expect(result.reasons).toContain('webTransportFreeTLD');
        });

        it('should flag free TLD endpoints (.ml)', () => {
            const result = analyzeWebTransportEndpoint('https://c2server.ml/beacon');
            expect(result.reasons).toContain('webTransportFreeTLD');
        });

        it('should flag free TLD endpoints (.ga)', () => {
            const result = analyzeWebTransportEndpoint('https://phishing.ga/stream');
            expect(result.reasons).toContain('webTransportFreeTLD');
        });

        it('should flag base64 encoded URL components', () => {
            const result = analyzeWebTransportEndpoint('https://example.com/connect/YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=');
            expect(result.reasons).toContain('webTransportObfuscatedUrl');
        });

        it('should flag double-encoded URLs', () => {
            const result = analyzeWebTransportEndpoint('https://example.com/path%252Fmalicious');
            expect(result.reasons).toContain('webTransportObfuscatedUrl');
        });

        it('should flag invalid URLs', () => {
            const result = analyzeWebTransportEndpoint('not-a-valid-url');
            expect(result.reasons).toContain('webTransportInvalidUrl');
        });

        it('should combine multiple risk factors', () => {
            // IP + high port = multiple risks
            const result = analyzeWebTransportEndpoint('https://10.0.0.1:55555/');
            expect(result.score).toBeGreaterThanOrEqual(
                CONFIG.WEBTRANSPORT_MONITORING.scores.directIP +
                CONFIG.WEBTRANSPORT_MONITORING.scores.highPort
            );
        });
    });

    describe('Endpoint Analysis - Trusted Patterns (Whitelist)', () => {

        it('should trust Google endpoints', () => {
            const result = analyzeWebTransportEndpoint('https://quic.googleapis.com/experimental');
            expect(result.isTrusted).toBe(true);
            expect(result.score).toBe(0);
        });

        it('should trust Cloudflare endpoints', () => {
            const result = analyzeWebTransportEndpoint('https://speed.cloudflare.com/webtransport');
            expect(result.isTrusted).toBe(true);
            expect(result.score).toBe(0);
        });

        it('should trust Microsoft endpoints', () => {
            const result = analyzeWebTransportEndpoint('https://teams.microsoft.com/stream');
            expect(result.isTrusted).toBe(true);
            expect(result.score).toBe(0);
        });

        it('should trust Amazon endpoints', () => {
            const result = analyzeWebTransportEndpoint('https://kinesis.amazonaws.com/connect');
            expect(result.isTrusted).toBe(true);
            expect(result.score).toBe(0);
        });

        it('should trust Facebook/Meta endpoints', () => {
            const result = analyzeWebTransportEndpoint('https://live.facebook.com/stream');
            expect(result.isTrusted).toBe(true);
            expect(result.score).toBe(0);
        });
    });

    describe('Endpoint Analysis - Legitimate Use Cases (No False Positives)', () => {

        it('should allow normal domain with standard port', () => {
            const result = analyzeWebTransportEndpoint('https://gameserver.example.com/connect');
            // Should not be trusted (not in whitelist) but score should be 0
            expect(result.score).toBe(0);
            expect(result.isTrusted).toBe(false);
        });

        it('should allow .com domains', () => {
            const result = analyzeWebTransportEndpoint('https://streaming.service.com/websocket');
            expect(result.reasons).not.toContain('webTransportFreeTLD');
        });

        it('should allow .io domains', () => {
            const result = analyzeWebTransportEndpoint('https://realtime.socket.io/connect');
            expect(result.reasons).not.toContain('webTransportFreeTLD');
        });

        it('should allow short subdomains', () => {
            const result = analyzeWebTransportEndpoint('https://api.example.com/stream');
            expect(result.reasons).not.toContain('webTransportRandomSubdomain');
        });

        it('should allow port 443', () => {
            const result = analyzeWebTransportEndpoint('https://example.com:443/connect');
            expect(result.reasons).not.toContain('webTransportHighPort');
        });

        it('should allow port 8443', () => {
            const result = analyzeWebTransportEndpoint('https://example.com:8443/connect');
            expect(result.reasons).not.toContain('webTransportHighPort');
        });
    });

    describe('Score Thresholds', () => {

        it('direct IP should score 8', () => {
            expect(CONFIG.WEBTRANSPORT_MONITORING.scores.directIP).toBe(8);
        });

        it('high port should score 4', () => {
            expect(CONFIG.WEBTRANSPORT_MONITORING.scores.highPort).toBe(4);
        });

        it('random subdomain should score 6', () => {
            expect(CONFIG.WEBTRANSPORT_MONITORING.scores.randomSubdomain).toBe(6);
        });

        it('free TLD should score 5', () => {
            expect(CONFIG.WEBTRANSPORT_MONITORING.scores.freeTLD).toBe(5);
        });

        it('obfuscated URL should score 7', () => {
            expect(CONFIG.WEBTRANSPORT_MONITORING.scores.obfuscatedUrl).toBe(7);
        });

        it('combined IP + high port should trigger warning (score >= 10)', () => {
            const result = analyzeWebTransportEndpoint('https://192.168.1.1:54321/');
            expect(result.score).toBeGreaterThanOrEqual(10);
        });
    });

    describe('Rate Limiting Thresholds', () => {

        it('max connections per minute should be 10', () => {
            expect(CONFIG.WEBTRANSPORT_MONITORING.thresholds.maxConnectionsPerMinute).toBe(10);
        });

        it('max datagrams per second should be 100', () => {
            expect(CONFIG.WEBTRANSPORT_MONITORING.thresholds.maxDatagramsPerSecond).toBe(100);
        });

        it('max streams per connection should be 50', () => {
            expect(CONFIG.WEBTRANSPORT_MONITORING.thresholds.maxStreamsPerConnection).toBe(50);
        });

        it('connection tracking window should be 5 minutes', () => {
            expect(CONFIG.WEBTRANSPORT_MONITORING.thresholds.connectionTrackingWindowMs).toBe(300000);
        });
    });

    describe('i18n Keys', () => {
        const messagesPath = path.join(__dirname, '..', '_locales', 'en', 'messages.json');
        const messages = JSON.parse(fs.readFileSync(messagesPath, 'utf8'));

        it('should have webTransportWarningTitle key', () => {
            expect(messages.webTransportWarningTitle).toBeDefined();
            expect(messages.webTransportWarningTitle.message).toBeTruthy();
        });

        it('should have webTransportWarningMessage key', () => {
            expect(messages.webTransportWarningMessage).toBeDefined();
            expect(messages.webTransportWarningMessage.message).toBeTruthy();
        });

        it('should have webTransportDirectIP key', () => {
            expect(messages.webTransportDirectIP).toBeDefined();
            expect(messages.webTransportDirectIP.message).toBeTruthy();
        });

        it('should have webTransportRandomSubdomain key', () => {
            expect(messages.webTransportRandomSubdomain).toBeDefined();
            expect(messages.webTransportRandomSubdomain.message).toBeTruthy();
        });

        it('should have webTransportHighConnectionRate key', () => {
            expect(messages.webTransportHighConnectionRate).toBeDefined();
            expect(messages.webTransportHighConnectionRate.message).toBeTruthy();
        });
    });

    describe('Real-World C2 Pattern Detection', () => {

        it('should detect Cobalt Strike-like beaconing pattern', () => {
            // Cobalt Strike often uses random subdomains
            const result = analyzeWebTransportEndpoint('https://ab12cd34ef56gh78ij90kl12mn34op56.teamserver.net:50050/');
            expect(result.score).toBeGreaterThan(0);
        });

        it('should detect fast-flux DNS-like pattern', () => {
            const result = analyzeWebTransportEndpoint('https://1a2b3c4d5e6f7g8h9i0j1k2l3m4n5o6p.botnet.tk/');
            expect(result.score).toBeGreaterThanOrEqual(10); // Random subdomain + free TLD
        });

        it('should detect data exfiltration endpoint pattern', () => {
            // Direct IP + high port + base64 path
            const result = analyzeWebTransportEndpoint('https://45.33.32.156:60000/exfil/YmFzZTY0ZW5jb2RlZGRhdGFoZXJl');
            expect(result.score).toBeGreaterThanOrEqual(15);
        });
    });

    describe('Summary Statistics', () => {
        it('should generate summary', () => {
            const suspiciousTests = [
                'https://192.168.1.1:4433/ws',
                'https://evil.com:54321/',
                'https://a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6q7r8.evil.com/',
                'https://malware.tk/connect',
                'https://example.com/connect/YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo='
            ];

            const legitimateTests = [
                'https://quic.googleapis.com/experimental',
                'https://speed.cloudflare.com/webtransport',
                'https://streaming.service.com/websocket'
            ];

            let suspiciousDetected = 0;
            let legitimateAllowed = 0;

            for (const url of suspiciousTests) {
                const result = analyzeWebTransportEndpoint(url);
                if (result.score > 0) suspiciousDetected++;
            }

            for (const url of legitimateTests) {
                const result = analyzeWebTransportEndpoint(url);
                if (result.score === 0 || result.isTrusted) legitimateAllowed++;
            }

            console.log('\n========================================');
            console.log('WEBTRANSPORT DETECTION TEST SUMMARY');
            console.log('========================================');
            console.log(`Suspicious endpoints tested: ${suspiciousTests.length}`);
            console.log(`  Detected: ${suspiciousDetected} (${(suspiciousDetected/suspiciousTests.length*100).toFixed(0)}%)`);
            console.log(`Legitimate endpoints tested: ${legitimateTests.length}`);
            console.log(`  Allowed: ${legitimateAllowed} (${(legitimateAllowed/legitimateTests.length*100).toFixed(0)}%)`);
            console.log('========================================\n');

            expect(suspiciousDetected).toBe(suspiciousTests.length);
            expect(legitimateAllowed).toBe(legitimateTests.length);
        });
    });
});
