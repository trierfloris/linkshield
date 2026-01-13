const fs = require('fs');
const path = require('path');

const contentPath = path.join(__dirname, '..', 'content.js');
let content = fs.readFileSync(contentPath, 'utf8');
content = content.replace(/\r\n/g, '\n');

// Replace the progressive scanning function with optimized version
const oldSection = `/**
 * PERFORMANCE FIX v8.2.0: Progressive scanning with viewport priority
 * Target: <3 seconds for 5000 links (was 11 seconds in v8.1.0 audit)
 *
 * Strategy:
 * 1. Viewport-first: Scan visible links immediately
 * 2. Batched processing: Process off-screen links in batches of 100
 * 3. requestIdleCallback: Use idle time for background work
 * 4. Early termination: Skip already-scanned links fast
 */
function scheduleFullPageScan() {
  const BATCH_SIZE = 100; // SECURITY FIX v8.2.0: Increased from 50 to 100 for better performance
  const BATCH_DELAY = 0; // ms between batches (0 = requestIdleCallback handles timing)`;

const newSection = `/**
 * PERFORMANCE FIX v8.6.0: Optimized progressive scanning
 * Target: <10 seconds for 5000 links
 *
 * Strategy:
 * 1. Viewport-first: Scan visible links immediately (blocking)
 * 2. Batched processing: Process off-screen links in batches of 200
 * 3. requestIdleCallback: Use idle time for background work
 * 4. Early termination: Skip already-scanned links via WeakSet
 * 5. Deferred classification: Skip heavy checks for simple URLs
 */

// WeakSet for O(1) "already scanned" lookup (faster than dataset attribute)
const scannedLinksSet = new WeakSet();

function scheduleFullPageScan() {
  const BATCH_SIZE = 200; // PERFORMANCE FIX v8.6.0: Increased from 100 to 200
  const BATCH_DELAY = 0; // ms between batches (0 = requestIdleCallback handles timing)`;

if (content.includes(oldSection)) {
    content = content.replace(oldSection, newSection);
    console.log('SUCCESS: Updated batch size to 200');
} else {
    console.log('ERROR: Pattern for batch size not found');
}

// Update the scanLink function to use WeakSet
const oldScanLink = `  /**
   * Scan a single link
   * SECURITY FIX v8.4.0: Added immediateUriSecurityCheck for data/javascript URI blocking
   */
  const scanLink = (link) => {
    if (link.dataset.linkshieldScanned) return false;`;

const newScanLink = `  /**
   * Scan a single link
   * PERFORMANCE FIX v8.6.0: Uses WeakSet for O(1) lookup + dataset for persistence
   */
  const scanLink = (link) => {
    // Fast WeakSet check first (O(1) vs O(n) for dataset)
    if (scannedLinksSet.has(link)) return false;
    if (link.dataset.linkshieldScanned) {
      scannedLinksSet.add(link); // Sync WeakSet with dataset
      return false;
    }`;

if (content.includes(oldScanLink)) {
    content = content.replace(oldScanLink, newScanLink);
    console.log('SUCCESS: Added WeakSet optimization');
} else {
    console.log('ERROR: Pattern for scanLink not found');
}

// Add WeakSet update when marking as scanned
const oldMarkScanned = `          classifyAndCheckLink(link);
          link.dataset.linkshieldScanned = 'true';
          return true;`;

const newMarkScanned = `          classifyAndCheckLink(link);
          link.dataset.linkshieldScanned = 'true';
          scannedLinksSet.add(link); // PERFORMANCE FIX v8.6.0: Keep WeakSet in sync
          return true;`;

// This pattern occurs multiple times, so we need to be careful
// Only replace in the scheduleFullPageScan context
if (content.includes(oldMarkScanned)) {
    // Replace only the first occurrence (inside scheduleFullPageScan)
    content = content.replace(oldMarkScanned, newMarkScanned);
    console.log('SUCCESS: Updated scanned marking');
} else {
    console.log('WARNING: Mark scanned pattern not found');
}

// Also update the requestIdleCallback timeout for faster startup
const oldTimeout = `requestIdleCallback(performScan, { timeout: 2000 });`;
const newTimeout = `requestIdleCallback(performScan, { timeout: 500 }); // PERFORMANCE FIX v8.6.0: Reduced from 2000ms`;

if (content.includes(oldTimeout)) {
    content = content.replace(oldTimeout, newTimeout);
    console.log('SUCCESS: Reduced initial timeout');
} else {
    console.log('WARNING: Timeout pattern not found');
}

// Update batch processing timeout
const oldBatchTimeout = `requestIdleCallback(() => processBatch(links, endIndex, callback), { timeout: 100 });`;
const newBatchTimeout = `requestIdleCallback(() => processBatch(links, endIndex, callback), { timeout: 50 }); // PERFORMANCE FIX v8.6.0: Faster batching`;

if (content.includes(oldBatchTimeout)) {
    content = content.replace(oldBatchTimeout, newBatchTimeout);
    console.log('SUCCESS: Reduced batch timeout');
} else {
    console.log('WARNING: Batch timeout pattern not found');
}

content = content.replace(/\n/g, '\r\n');
fs.writeFileSync(contentPath, content, 'utf8');
console.log('DONE: Performance optimizations applied');
