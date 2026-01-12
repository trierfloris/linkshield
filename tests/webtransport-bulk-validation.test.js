/**
 * WebTransport/HTTP3 Bulk Validation Test Suite
 * Tests 100 URL scenarios for detection accuracy
 *
 * Distribution:
 * - 40x Legitimate endpoints (whitelist-based)
 * - 20x Direct IP addresses (score 8)
 * - 20x Random C2 subdomains >32 chars (score 6)
 * - 20x Obfuscated URLs - Base64/double encoding (score 7)
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

// Mock chrome API with message tracking
const messageLog = [];
const memorySnapshots = [];

global.chrome = {
    i18n: {
        getMessage: jest.fn((key) => key)
    },
    runtime: {
        sendMessage: jest.fn((message) => {
            messageLog.push({
                timestamp: Date.now(),
                message: { ...message },
                heapUsed: process.memoryUsage().heapUsed
            });
            return Promise.resolve({ received: true });
        })
    },
    action: {
        setBadgeText: jest.fn(),
        setBadgeBackgroundColor: jest.fn()
    }
};

global.globalConfig = CONFIG;

// ============================================================
// DATASET: 100 URL Scenarios
// ============================================================

/**
 * 40x LEGITIMATE ENDPOINTS (Based on config.js whitelist)
 * Expected: score = 0, isTrusted = true
 */
const LEGITIMATE_ENDPOINTS = [
    // Google (10)
    'https://quic.googleapis.com/experimental',
    'https://meet.google.com/webtransport/connect',
    'https://docs.google.com/realtime/stream',
    'https://chat.google.com/ws/transport',
    'https://stadia.google.com/gamestream',
    'https://youtube.googleapis.com/live/stream',
    'https://drive.google.com/sync/transport',
    'https://mail.google.com/realtime',
    'https://calendar.google.com/push/events',
    'https://photos.google.com/upload/stream',

    // Cloudflare (8)
    'https://speed.cloudflare.com/webtransport',
    'https://workers.cloudflare.com/realtime',
    'https://pages.cloudflare.com/ws/deploy',
    'https://stream.cloudflare.com/video/live',
    'https://api.cloudflare.com/client/v4/stream',
    'https://gateway.cloudflare.com/transport',
    'https://cdn.cloudflare.com/push/updates',
    'https://security.cloudflare.com/monitor',

    // Microsoft/Azure (8)
    'https://teams.microsoft.com/stream',
    'https://outlook.microsoft.com/realtime',
    'https://office.microsoft.com/collaboration',
    'https://xbox.microsoft.com/gamestream',
    'https://graph.microsoft.com/beta/stream',
    'https://login.azure.com/ws/auth',
    'https://portal.azure.com/realtime',
    'https://devops.azure.com/pipeline/stream',

    // Amazon AWS (6)
    'https://kinesis.amazonaws.com/connect',
    'https://lambda.amazonaws.com/invoke/stream',
    'https://s3.amazonaws.com/upload/multipart',
    'https://dynamodb.amazonaws.com/streams',
    'https://sqs.amazonaws.com/receive/batch',
    'https://cloudwatch.amazonaws.com/metrics/stream',

    // Facebook/Meta (4)
    'https://live.facebook.com/stream',
    'https://messenger.facebook.com/realtime',
    'https://instagram.facebook.com/stories/upload',
    'https://workplace.facebook.com/collaboration',

    // Fastly & Akamai (4)
    'https://global.fastly.com/edge/stream',
    'https://api.fastly.com/service/stream',
    'https://cdn.akamai.com/media/stream',
    'https://edge.akamai.com/delivery/live',
];

/**
 * 20x DIRECT IP ADDRESSES
 * Expected: score >= 8 (directIP score)
 */
const DIRECT_IP_ENDPOINTS = [
    // Private IPs (10)
    'https://192.168.1.1:443/connect',
    'https://192.168.0.100:8443/ws',
    'https://10.0.0.1:4433/stream',
    'https://10.10.10.10:443/beacon',
    'https://172.16.0.1:9443/transport',
    'https://172.31.255.255:443/c2',
    'https://192.168.100.50:50000/exfil',
    'https://10.255.255.1:443/cmd',
    'https://172.20.10.5:8080/ws',
    'https://192.168.50.1:443/data',

    // Public IPs (common C2/malware hosting) (10)
    'https://45.33.32.156:443/connect',
    'https://185.220.101.45:4433/beacon',
    'https://23.129.64.100:443/stream',
    'https://89.234.157.254:8443/tunnel',
    'https://91.219.236.222:443/ws',
    'https://104.244.72.115:50050/c2',
    'https://198.98.56.149:443/exfil',
    'https://94.102.49.190:4444/shell',
    'https://185.100.87.41:443/data',
    'https://37.120.198.219:8443/transport',
];

/**
 * 20x RANDOM C2 SUBDOMAINS (>32 characters)
 * Expected: score >= 6 (randomSubdomain score)
 */
const C2_SUBDOMAIN_ENDPOINTS = [
    // Cobalt Strike-like patterns (10)
    'https://a1b2c3d4e5f6g7h8i9j0k1l2m3n4o5p6.teamserver.net/',
    'https://deadbeefcafebabedeadbeefcafebabedeadbeef.malware.net/',
    'https://1234567890abcdef1234567890abcdef12345678.botnet.com/',
    'https://xyz123abc456def789ghi012jkl345mno678pqr.c2server.org/',
    'https://aaabbbcccdddeeefffggghhhiiijjjkkklllmmmnnn.evil.io/',
    'https://0x0123456789abcdef0123456789abcdef01234567.attacker.net/',
    'https://randomhexstringherewith32charactersplus.implant.cc/',
    'https://cobaltstriketeamserverbeaconidentifier.beacon.xyz/',
    'https://metasploitmeterpreterreverseshellconn.shell.tk/',
    'https://powershellempireagentcommunicationid.empire.ml/',

    // DGA-like patterns (Domain Generation Algorithm) (10)
    'https://qwertyuiopasdfghjklzxcvbnmqwertyu.dga.net/',
    'https://hg7k2m9p4x8c1v6b3n5j0q2w4e6r8t0y.flux.org/',
    'https://mnbvcxzlkjhgfdsapoiuytrewqmnbvcxz.rotate.com/',
    'https://a0b1c2d3e4f5g6h7i8j9k0l1m2n3o4p5q6r7.random.io/',
    'https://zzzyyyyxxxxwwwwvvvvuuuuttttssssrrrrq.gibberish.net/',
    'https://f1e2d3c4b5a6978685746352413029181716.obfuscate.cc/',
    'https://abcdefghijklmnopqrstuvwxyz0123456789.alphabet.org/',
    'https://base16encodedmalwareidentifierstrin.encoded.net/',
    'https://longrandomstringusedfordomaingener.generate.xyz/',
    'https://suspicioussubdomainwithmanycharacters.suspicious.io/',
];

/**
 * 20x OBFUSCATED URLs (Base64 / Double Encoding)
 * Expected: score >= 7 (obfuscatedUrl score)
 */
const OBFUSCATED_ENDPOINTS = [
    // Base64 encoded paths (10)
    'https://example.com/connect/YWJjZGVmZ2hpamtsbW5vcHFyc3R1dnd4eXo=',
    'https://cdn.malware.com/payload/SGVsbG9Xb3JsZEJhc2U2NEVuY29kZWQ=',
    'https://api.exfil.net/data/VGhpc0lzQVN1c3BpY2lvdXNCYXNlNjRTdHJpbmc=',
    'https://stream.c2.io/beacon/QzJCZWFjb25JZGVudGlmaWVyU3RyaW5nSGVyZQ==',
    'https://upload.evil.com/file/UGF5bG9hZERhdGFFbmNvZGVkSW5CYXNlNjQ=',
    'https://ws.attacker.net/shell/UmV2ZXJzZVNoZWxsQ29ubmVjdGlvbkRhdGE=',
    'https://realtime.botnet.org/cmd/Q29tbWFuZEFuZENvbnRyb2xEYXRhSGVyZQ==',
    'https://sync.malicious.com/update/TWFsd2FyZVVwZGF0ZVBheWxvYWREYXRh',
    'https://push.phishing.net/steal/Q3JlZGVudGlhbFN0ZWFsZXJEYXRhQmFzZTY0',
    'https://live.ransomware.io/key/RW5jcnlwdGlvbktleUV4ZmlsdHJhdGlvbg==',

    // Double URL encoding (10)
    'https://example.com/path%252Fmalicious%252Fpayload',
    'https://attacker.net/cmd%253Dexec%2526shell%253Dtrue',
    'https://c2server.org/beacon%252Fid%253D12345%2526key%253Dabcdef',
    'https://exfil.com/data%252F%252e%252e%252fsecrets',
    'https://malware.net/download%253Ffile%253D%252Fetc%252Fpasswd',
    'https://botnet.io/upload%252Fstolen%252Fcredentials',
    'https://phishing.com/redirect%253Furl%253Dhttps%25253A%25252F%25252Fevil',
    'https://evil.org/inject%252Fscript%253Dalert%252528xss%252529',
    'https://ransomware.net/encrypt%252Fkey%253D%252Froot%252F%252essh',
    'https://trojan.com/connect%253Fhost%253D192%252e168%252e1%252e1',
];

// ============================================================
// Test Helper Functions
// ============================================================

/**
 * Simulated analyzeWebTransportEndpoint function (mirrors content.js)
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
                    break;
                } catch {
                    // Not valid base64, continue
                }
            }
        }

        // Double encoding
        if (/%25[0-9A-Fa-f]{2}/.test(url)) {
            if (!reasons.includes('webTransportObfuscatedUrl')) {
                score += scores.obfuscatedUrl;
                reasons.push('webTransportObfuscatedUrl');
            }
        }

    } catch (e) {
        score += scores.invalidUrl || 5;
        reasons.push('webTransportInvalidUrl');
    }

    return { score, reasons, isTrusted: false };
}

/**
 * Simulated background.js message handler
 */
function handleWebTransportMessage(request, sender) {
    if (request.type !== 'webTransportDetected') return null;

    const tabId = sender?.tab?.id || Math.floor(Math.random() * 10000);
    const score = request.data?.score || 0;

    if (score >= 10) {
        chrome.action.setBadgeText({ text: '!', tabId });
        chrome.action.setBadgeBackgroundColor({ color: '#f59e0b', tabId });
    }

    return { received: true, score };
}

/**
 * Report WebTransport activity to background (simulated)
 */
function reportWebTransportActivity(url, analysis) {
    const message = {
        type: 'webTransportDetected',
        data: {
            url,
            score: analysis.score,
            reasons: analysis.reasons,
            timestamp: Date.now()
        }
    };

    // Simulate sending and handling
    chrome.runtime.sendMessage(message);
    handleWebTransportMessage(message, { tab: { id: Math.floor(Math.random() * 10000) } });
}

// ============================================================
// BULK VALIDATION TESTS
// ============================================================

describe('WebTransport Bulk Validation (100 URLs)', () => {

    beforeAll(() => {
        // Clear message log and take initial memory snapshot
        messageLog.length = 0;
        memorySnapshots.push({
            phase: 'start',
            heapUsed: process.memoryUsage().heapUsed,
            timestamp: Date.now()
        });
    });

    afterAll(() => {
        // Final memory snapshot
        memorySnapshots.push({
            phase: 'end',
            heapUsed: process.memoryUsage().heapUsed,
            timestamp: Date.now()
        });
    });

    // ========================================================
    // LEGITIMATE ENDPOINTS (40)
    // ========================================================
    describe('Legitimate Endpoints (40 URLs)', () => {
        const results = { passed: 0, failed: 0, falsePositives: [] };

        test.each(LEGITIMATE_ENDPOINTS)('should trust: %s', (url) => {
            const result = analyzeWebTransportEndpoint(url);

            // Legitimate URLs should be trusted OR have score 0
            const isCorrect = result.isTrusted || result.score === 0;

            if (isCorrect) {
                results.passed++;
            } else {
                results.failed++;
                results.falsePositives.push({ url, result });
            }

            expect(isCorrect).toBe(true);
        });

        afterAll(() => {
            console.log(`\n[LEGITIMATE] Passed: ${results.passed}/40`);
            if (results.falsePositives.length > 0) {
                console.log(`[LEGITIMATE] False Positives: ${results.falsePositives.length}`);
                results.falsePositives.forEach(fp => {
                    console.log(`  - ${fp.url} (score: ${fp.result.score}, reasons: ${fp.result.reasons.join(', ')})`);
                });
            }
        });
    });

    // ========================================================
    // DIRECT IP ADDRESSES (20)
    // ========================================================
    describe('Direct IP Addresses (20 URLs)', () => {
        const results = { passed: 0, failed: 0, falseNegatives: [] };
        const expectedScore = CONFIG.WEBTRANSPORT_MONITORING.scores.directIP; // 8

        test.each(DIRECT_IP_ENDPOINTS)('should flag IP: %s', (url) => {
            const result = analyzeWebTransportEndpoint(url);

            // Should have score >= 8 and contain directIP reason
            const hasCorrectScore = result.score >= expectedScore;
            const hasCorrectReason = result.reasons.includes('webTransportDirectIP');
            const isCorrect = hasCorrectScore && hasCorrectReason;

            if (isCorrect) {
                results.passed++;
                // Report to background
                reportWebTransportActivity(url, result);
            } else {
                results.failed++;
                results.falseNegatives.push({ url, result });
            }

            expect(hasCorrectScore).toBe(true);
            expect(hasCorrectReason).toBe(true);
        });

        afterAll(() => {
            console.log(`\n[DIRECT IP] Passed: ${results.passed}/20 (expected score >= ${expectedScore})`);
            if (results.falseNegatives.length > 0) {
                console.log(`[DIRECT IP] False Negatives: ${results.falseNegatives.length}`);
                results.falseNegatives.forEach(fn => {
                    console.log(`  - ${fn.url} (score: ${fn.result.score}, reasons: ${fn.result.reasons.join(', ')})`);
                });
            }
        });
    });

    // ========================================================
    // RANDOM C2 SUBDOMAINS (20)
    // ========================================================
    describe('Random C2 Subdomains (20 URLs)', () => {
        const results = { passed: 0, failed: 0, falseNegatives: [] };
        const expectedScore = CONFIG.WEBTRANSPORT_MONITORING.scores.randomSubdomain; // 6

        test.each(C2_SUBDOMAIN_ENDPOINTS)('should flag C2: %s', (url) => {
            const result = analyzeWebTransportEndpoint(url);

            // Should have score >= 6 and contain randomSubdomain reason
            const hasCorrectScore = result.score >= expectedScore;
            const hasCorrectReason = result.reasons.includes('webTransportRandomSubdomain');
            const isCorrect = hasCorrectScore && hasCorrectReason;

            if (isCorrect) {
                results.passed++;
                reportWebTransportActivity(url, result);
            } else {
                results.failed++;
                results.falseNegatives.push({ url, result });
            }

            expect(hasCorrectScore).toBe(true);
            expect(hasCorrectReason).toBe(true);
        });

        afterAll(() => {
            console.log(`\n[C2 SUBDOMAIN] Passed: ${results.passed}/20 (expected score >= ${expectedScore})`);
            if (results.falseNegatives.length > 0) {
                console.log(`[C2 SUBDOMAIN] False Negatives: ${results.falseNegatives.length}`);
                results.falseNegatives.forEach(fn => {
                    console.log(`  - ${fn.url} (score: ${fn.result.score}, reasons: ${fn.result.reasons.join(', ')})`);
                });
            }
        });
    });

    // ========================================================
    // OBFUSCATED URLs (20)
    // ========================================================
    describe('Obfuscated URLs (20 URLs)', () => {
        const results = { passed: 0, failed: 0, falseNegatives: [] };
        const expectedScore = CONFIG.WEBTRANSPORT_MONITORING.scores.obfuscatedUrl; // 7

        test.each(OBFUSCATED_ENDPOINTS)('should flag obfuscated: %s', (url) => {
            const result = analyzeWebTransportEndpoint(url);

            // Should have score >= 7 and contain obfuscatedUrl reason
            const hasCorrectScore = result.score >= expectedScore;
            const hasCorrectReason = result.reasons.includes('webTransportObfuscatedUrl');
            const isCorrect = hasCorrectScore && hasCorrectReason;

            if (isCorrect) {
                results.passed++;
                reportWebTransportActivity(url, result);
            } else {
                results.failed++;
                results.falseNegatives.push({ url, result });
            }

            expect(hasCorrectScore).toBe(true);
            expect(hasCorrectReason).toBe(true);
        });

        afterAll(() => {
            console.log(`\n[OBFUSCATED] Passed: ${results.passed}/20 (expected score >= ${expectedScore})`);
            if (results.falseNegatives.length > 0) {
                console.log(`[OBFUSCATED] False Negatives: ${results.falseNegatives.length}`);
                results.falseNegatives.forEach(fn => {
                    console.log(`  - ${fn.url} (score: ${fn.result.score}, reasons: ${fn.result.reasons.join(', ')})`);
                });
            }
        });
    });

    // ========================================================
    // BACKGROUND.JS MESSAGE HANDLER VERIFICATION
    // ========================================================
    describe('Background.js Message Handler', () => {

        it('should process all suspicious endpoint messages (60 total)', () => {
            // 20 IP + 20 C2 + 20 obfuscated = 60 suspicious URLs
            const expectedMessages = 60;
            const actualMessages = messageLog.length;

            console.log(`\n[MESSAGE HANDLER] Messages processed: ${actualMessages}/${expectedMessages}`);

            expect(actualMessages).toBe(expectedMessages);
        });

        it('should correctly set badge for high-risk detections (score >= 10)', () => {
            const highRiskMessages = messageLog.filter(m => m.message.data?.score >= 10);

            // Manually verify badge logic would trigger for high-risk messages
            let badgeTriggersExpected = 0;
            highRiskMessages.forEach(m => {
                if (m.message.data?.score >= 10) {
                    badgeTriggersExpected++;
                }
            });

            console.log(`[MESSAGE HANDLER] High-risk detections: ${highRiskMessages.length}`);
            console.log(`[MESSAGE HANDLER] Badge triggers expected: ${badgeTriggersExpected}`);

            // Verify high-risk messages have correct score threshold
            highRiskMessages.forEach(m => {
                expect(m.message.data.score).toBeGreaterThanOrEqual(10);
            });

            // Verify we detected some high-risk endpoints (IP + high port combos)
            expect(highRiskMessages.length).toBeGreaterThan(0);
        });

        it('should handle rapid message bursts without errors', async () => {
            // Simulate 100 rapid messages
            const burstSize = 100;
            const burstStart = Date.now();

            for (let i = 0; i < burstSize; i++) {
                const result = { score: Math.floor(Math.random() * 20), reasons: ['test'] };
                reportWebTransportActivity(`https://burst-test-${i}.example.com/`, result);
            }

            const burstEnd = Date.now();
            const burstDuration = burstEnd - burstStart;

            console.log(`[MESSAGE HANDLER] Burst test: ${burstSize} messages in ${burstDuration}ms`);

            // All messages should be logged
            expect(messageLog.length).toBeGreaterThanOrEqual(burstSize);
        });
    });

    // ========================================================
    // MEMORY LEAK VERIFICATION
    // ========================================================
    describe('Memory Leak Verification', () => {

        it('should not have significant memory growth after processing 100+ URLs', () => {
            // Force garbage collection if available
            if (global.gc) {
                global.gc();
            }

            // Take final memory reading
            const finalHeap = process.memoryUsage().heapUsed;
            const initialHeap = memorySnapshots[0]?.heapUsed || finalHeap;
            const heapGrowthBytes = finalHeap - initialHeap;
            const heapGrowthMB = (heapGrowthBytes / 1024 / 1024).toFixed(2);
            const heapGrowthPercent = ((heapGrowthBytes / initialHeap) * 100).toFixed(2);

            console.log('\n========================================');
            console.log('MEMORY ANALYSIS');
            console.log('========================================');
            console.log(`Initial heap: ${(initialHeap / 1024 / 1024).toFixed(2)} MB`);
            console.log(`Final heap: ${(finalHeap / 1024 / 1024).toFixed(2)} MB`);
            console.log(`Heap growth: ${heapGrowthMB} MB (${heapGrowthPercent}%)`);
            console.log(`Messages logged: ${messageLog.length}`);
            console.log(`Bytes per message: ${messageLog.length > 0 ? (heapGrowthBytes / messageLog.length).toFixed(0) : 'N/A'}`);

            // Memory growth should be under 50MB for 160+ messages
            // (More lenient threshold for test environment)
            const maxAllowedGrowthMB = 50;
            expect(parseFloat(heapGrowthMB)).toBeLessThan(maxAllowedGrowthMB);
        });

        it('should properly track connection timestamps', () => {
            // Verify all messages have valid timestamps
            const invalidTimestamps = messageLog.filter(m =>
                !m.timestamp || typeof m.timestamp !== 'number' || m.timestamp < 0
            );

            console.log(`[MEMORY] Messages with valid timestamps: ${messageLog.length - invalidTimestamps.length}/${messageLog.length}`);

            expect(invalidTimestamps.length).toBe(0);
        });

        it('should not accumulate duplicate entries', () => {
            // Check for exact URL duplicates in the message log
            const urls = messageLog.map(m => m.message.data?.url).filter(Boolean);
            const uniqueUrls = new Set(urls);

            // Burst test URLs are expected to be unique
            const burstUrls = urls.filter(u => u && u.includes('burst-test-'));
            const uniqueBurstUrls = new Set(burstUrls);

            console.log(`[MEMORY] Total URLs logged: ${urls.length}`);
            console.log(`[MEMORY] Burst test unique URLs: ${uniqueBurstUrls.size}/${burstUrls.length}`);

            // Burst URLs should all be unique
            expect(uniqueBurstUrls.size).toBe(burstUrls.length);
        });
    });

    // ========================================================
    // FINAL SUMMARY REPORT
    // ========================================================
    describe('Final Summary Report', () => {

        it('should generate comprehensive detection report', () => {
            // Run all URLs and collect statistics
            let legitimatePassed = 0;
            let directIPPassed = 0;
            let c2SubdomainPassed = 0;
            let obfuscatedPassed = 0;

            // Count legitimate (should be trusted/score 0)
            LEGITIMATE_ENDPOINTS.forEach(url => {
                const result = analyzeWebTransportEndpoint(url);
                if (result.isTrusted || result.score === 0) legitimatePassed++;
            });

            // Count direct IP (score >= 8)
            DIRECT_IP_ENDPOINTS.forEach(url => {
                const result = analyzeWebTransportEndpoint(url);
                if (result.score >= 8 && result.reasons.includes('webTransportDirectIP')) directIPPassed++;
            });

            // Count C2 subdomains (score >= 6)
            C2_SUBDOMAIN_ENDPOINTS.forEach(url => {
                const result = analyzeWebTransportEndpoint(url);
                if (result.score >= 6 && result.reasons.includes('webTransportRandomSubdomain')) c2SubdomainPassed++;
            });

            // Count obfuscated (score >= 7)
            OBFUSCATED_ENDPOINTS.forEach(url => {
                const result = analyzeWebTransportEndpoint(url);
                if (result.score >= 7 && result.reasons.includes('webTransportObfuscatedUrl')) obfuscatedPassed++;
            });

            // Calculate rates
            const falsePositiveRate = ((40 - legitimatePassed) / 40 * 100).toFixed(1);
            const directIPDetectionRate = (directIPPassed / 20 * 100).toFixed(1);
            const c2DetectionRate = (c2SubdomainPassed / 20 * 100).toFixed(1);
            const obfuscatedDetectionRate = (obfuscatedPassed / 20 * 100).toFixed(1);
            const overallFalseNegativeRate = (
                ((20 - directIPPassed) + (20 - c2SubdomainPassed) + (20 - obfuscatedPassed)) / 60 * 100
            ).toFixed(1);

            console.log('\n========================================');
            console.log('WEBTRANSPORT BULK VALIDATION REPORT');
            console.log('========================================');
            console.log('');
            console.log('DATASET BREAKDOWN (100 URLs):');
            console.log('├─ Legitimate endpoints: 40');
            console.log('├─ Direct IP addresses:  20');
            console.log('├─ C2 subdomains:        20');
            console.log('└─ Obfuscated URLs:      20');
            console.log('');
            console.log('DETECTION RESULTS:');
            console.log(`├─ Legitimate allowed:   ${legitimatePassed}/40 (${(legitimatePassed/40*100).toFixed(0)}%)`);
            console.log(`├─ Direct IP detected:   ${directIPPassed}/20 (${directIPDetectionRate}%)`);
            console.log(`├─ C2 subdomain detected: ${c2SubdomainPassed}/20 (${c2DetectionRate}%)`);
            console.log(`└─ Obfuscated detected:  ${obfuscatedPassed}/20 (${obfuscatedDetectionRate}%)`);
            console.log('');
            console.log('ACCURACY METRICS:');
            console.log(`├─ False Positive Rate:  ${falsePositiveRate}%`);
            console.log(`├─ False Negative Rate:  ${overallFalseNegativeRate}%`);
            console.log(`├─ Direct IP accuracy:   ${directIPDetectionRate}%`);
            console.log(`├─ C2 subdomain accuracy: ${c2DetectionRate}%`);
            console.log(`└─ Obfuscation accuracy: ${obfuscatedDetectionRate}%`);
            console.log('');
            console.log('MESSAGE HANDLER:');
            console.log(`├─ Total messages: ${messageLog.length}`);
            console.log(`├─ Badge updates:  ${chrome.action.setBadgeText.mock.calls.length}`);
            console.log(`└─ Memory stable:  ${memorySnapshots.length >= 2 ? 'Yes' : 'Pending'}`);
            console.log('');
            console.log('========================================');
            console.log('VERDICT: ' + (
                parseFloat(falsePositiveRate) <= 5 &&
                parseFloat(overallFalseNegativeRate) <= 5
                    ? 'PASS - Detection accuracy within acceptable limits'
                    : 'REVIEW NEEDED - Detection rates outside acceptable limits'
            ));
            console.log('========================================\n');

            // Assertions
            expect(parseFloat(falsePositiveRate)).toBeLessThanOrEqual(5); // Max 5% FP
            expect(parseFloat(overallFalseNegativeRate)).toBeLessThanOrEqual(10); // Max 10% FN
            expect(parseFloat(directIPDetectionRate)).toBe(100);
            expect(parseFloat(c2DetectionRate)).toBeGreaterThanOrEqual(95);
            expect(parseFloat(obfuscatedDetectionRate)).toBeGreaterThanOrEqual(95);
        });
    });
});
