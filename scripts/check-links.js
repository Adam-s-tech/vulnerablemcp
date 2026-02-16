const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');

const vulnsPath = path.join(__dirname, '..', 'data', 'vulnerabilities.json');
const data = JSON.parse(fs.readFileSync(vulnsPath, 'utf8'));

const CONCURRENCY = 5;
const TIMEOUT_MS = 15000;
const USER_AGENT = 'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) VulnMCP-LinkChecker/1.0';

// ── Extract all URLs ────────────────────────────────────────────────
function extractAllUrls(entries) {
  const urls = [];
  for (const entry of entries) {
    if (entry.url) {
      urls.push({ url: entry.url, source: `${entry.id} (primary url)` });
    }
    if (Array.isArray(entry.references)) {
      for (const ref of entry.references) {
        if (ref.url) {
          urls.push({ url: ref.url, source: `${entry.id} -> ref "${ref.title}"` });
        }
      }
    }
    if (Array.isArray(entry.cveIds)) {
      for (const cve of entry.cveIds) {
        urls.push({
          url: `https://nvd.nist.gov/vuln/detail/${cve}`,
          source: `${entry.id} -> CVE ${cve} (NVD lookup)`,
          isCveCheck: true,
          cveId: cve,
        });
      }
    }
  }
  return urls;
}

// ── HTTP check ──────────────────────────────────────────────────────
function checkUrl(url) {
  return new Promise((resolve) => {
    const start = Date.now();
    const proto = url.startsWith('https') ? https : http;

    const req = proto.get(
      url,
      {
        timeout: TIMEOUT_MS,
        headers: {
          'User-Agent': USER_AGENT,
          Accept: 'text/html,application/xhtml+xml,*/*',
        },
        // Don't follow redirects automatically so we can report them
      },
      (res) => {
        // Consume response to free socket
        res.resume();
        const elapsed = Date.now() - start;
        resolve({
          url,
          status: res.statusCode,
          elapsed,
          redirect: res.headers.location || null,
          ok: res.statusCode >= 200 && res.statusCode < 400,
        });
      }
    );

    req.on('timeout', () => {
      req.destroy();
      resolve({ url, status: 'TIMEOUT', elapsed: Date.now() - start, ok: false });
    });

    req.on('error', (err) => {
      resolve({
        url,
        status: 'ERROR',
        error: err.code || err.message,
        elapsed: Date.now() - start,
        ok: false,
      });
    });
  });
}

// ── Run checks with concurrency limiter ─────────────────────────────
async function runWithConcurrency(tasks, limit) {
  const results = [];
  let idx = 0;

  async function worker() {
    while (idx < tasks.length) {
      const i = idx++;
      results[i] = await tasks[i]();
    }
  }

  const workers = Array.from({ length: Math.min(limit, tasks.length) }, () => worker());
  await Promise.all(workers);
  return results;
}

// ── Consistency checks ──────────────────────────────────────────────
function runConsistencyChecks(entries) {
  const issues = [];

  // Check for duplicate primary URLs
  const primaryUrls = new Map();
  for (const entry of entries) {
    if (primaryUrls.has(entry.url)) {
      issues.push(
        `DUPLICATE PRIMARY URL: "${entry.id}" and "${primaryUrls.get(entry.url)}" share the same url: ${entry.url}`
      );
    } else {
      primaryUrls.set(entry.url, entry.id);
    }
  }

  // Check for duplicate IDs
  const ids = new Map();
  for (const entry of entries) {
    if (ids.has(entry.id)) {
      issues.push(`DUPLICATE ID: "${entry.id}" appears more than once`);
    } else {
      ids.set(entry.id, true);
    }
  }

  // Check date ordering (should be chronological or at least valid)
  for (const entry of entries) {
    const d = new Date(entry.date);
    if (isNaN(d.getTime())) {
      issues.push(`INVALID DATE: "${entry.id}" has unparseable date "${entry.date}"`);
    } else if (d > new Date()) {
      issues.push(`FUTURE DATE: "${entry.id}" date ${entry.date} is in the future`);
    }
  }

  // Check CVE ID format
  for (const entry of entries) {
    if (Array.isArray(entry.cveIds)) {
      for (const cve of entry.cveIds) {
        if (!/^CVE-\d{4}-\d{4,}$/.test(cve)) {
          issues.push(`INVALID CVE FORMAT: "${entry.id}" has malformed CVE ID "${cve}"`);
        }
      }
    }
  }

  // Check that reference URLs don't have obvious duplicates within the same entry
  for (const entry of entries) {
    if (Array.isArray(entry.references)) {
      const refUrls = new Set();
      for (const ref of entry.references) {
        if (refUrls.has(ref.url)) {
          issues.push(`DUPLICATE REF URL: "${entry.id}" has duplicate reference url: ${ref.url}`);
        }
        refUrls.add(ref.url);
      }
    }
  }

  // Check that primary URL is reachable via references (optional, informational)
  for (const entry of entries) {
    if (Array.isArray(entry.references) && entry.references.length > 0) {
      const refUrls = new Set(entry.references.map((r) => r.url));
      if (!refUrls.has(entry.url)) {
        // This is informational, not necessarily wrong
      }
    }
  }

  return issues;
}

// ── Main ────────────────────────────────────────────────────────────
async function main() {
  console.log(`\n${'='.repeat(70)}`);
  console.log('  VULNERABILITY DATABASE LINK CHECKER & CONSISTENCY AUDIT');
  console.log(`${'='.repeat(70)}\n`);
  console.log(`Loaded ${data.length} vulnerability entries\n`);

  // Phase 1: Consistency checks (offline)
  console.log('── Phase 1: Consistency Checks ──────────────────────────\n');
  const issues = runConsistencyChecks(data);
  if (issues.length === 0) {
    console.log('  All consistency checks passed.\n');
  } else {
    for (const issue of issues) {
      console.log(`  ⚠  ${issue}`);
    }
    console.log('');
  }

  // Phase 2: Extract and deduplicate URLs
  const allUrlEntries = extractAllUrls(data);
  const uniqueUrls = new Map();
  for (const entry of allUrlEntries) {
    if (!uniqueUrls.has(entry.url)) {
      uniqueUrls.set(entry.url, []);
    }
    uniqueUrls.get(entry.url).push(entry.source);
  }

  console.log(`── Phase 2: Link Check (${uniqueUrls.size} unique URLs) ────────────────\n`);
  console.log(`  Concurrency: ${CONCURRENCY} | Timeout: ${TIMEOUT_MS}ms\n`);

  const urlList = [...uniqueUrls.keys()];
  const tasks = urlList.map((url) => () => checkUrl(url));
  const results = await runWithConcurrency(tasks, CONCURRENCY);

  // Categorize results
  const ok = [];
  const redirects = [];
  const broken = [];

  for (const result of results) {
    const sources = uniqueUrls.get(result.url);
    const enriched = { ...result, sources };

    if (result.ok) {
      if (result.status >= 300 && result.status < 400) {
        redirects.push(enriched);
      } else {
        ok.push(enriched);
      }
    } else {
      broken.push(enriched);
    }
  }

  // Report OK
  console.log(`  ✓ ${ok.length} URLs returned 2xx (OK)`);

  // Report redirects
  if (redirects.length > 0) {
    console.log(`\n  → ${redirects.length} URLs returned redirects:\n`);
    for (const r of redirects) {
      console.log(`    ${r.status} ${r.url}`);
      console.log(`       → ${r.redirect}`);
      console.log(`       Used by: ${r.sources.join(', ')}`);
    }
  }

  // Report broken
  if (broken.length > 0) {
    console.log(`\n  ✗ ${broken.length} URLs are BROKEN:\n`);
    for (const r of broken) {
      const detail = r.error ? `${r.status} (${r.error})` : `HTTP ${r.status}`;
      console.log(`    ${detail}: ${r.url}`);
      console.log(`       Used by: ${r.sources.join(', ')}`);
    }
  }

  // Summary
  console.log(`\n${'─'.repeat(70)}`);
  console.log('  SUMMARY');
  console.log(`${'─'.repeat(70)}`);
  console.log(`  Total entries:       ${data.length}`);
  console.log(`  Total unique URLs:   ${uniqueUrls.size}`);
  console.log(`  OK (2xx):            ${ok.length}`);
  console.log(`  Redirects (3xx):     ${redirects.length}`);
  console.log(`  Broken:              ${broken.length}`);
  console.log(`  Consistency issues:  ${issues.length}`);
  console.log(`${'─'.repeat(70)}\n`);

  // Exit code
  if (broken.length > 0 || issues.length > 0) {
    process.exit(1);
  }
}

main().catch((err) => {
  console.error('Fatal error:', err);
  process.exit(2);
});
