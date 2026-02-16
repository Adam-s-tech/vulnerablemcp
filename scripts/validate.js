const fs = require('fs');
const path = require('path');

const dataDir = path.join(__dirname, '..', 'data');
const vulnsPath = path.join(dataDir, 'vulnerabilities.json');
const taxonomyPath = path.join(dataDir, 'taxonomy.json');

function validate() {
  // Load taxonomy
  let taxonomy;
  try {
    taxonomy = JSON.parse(fs.readFileSync(taxonomyPath, 'utf8'));
  } catch (e) {
    console.error('Failed to load taxonomy.json:', e.message);
    process.exit(1);
  }

  const validSeverities = new Set(taxonomy.severities.map(s => s.id));
  const validCategories = new Set(taxonomy.categories.map(c => c.id));
  const validTags = new Set(taxonomy.tags.map(t => t.id));
  const validExploitability = new Set(taxonomy.exploitability.map(e => e.id));
  const validComponents = new Set(taxonomy.affectedComponents.map(c => c.id));
  const validPrevalence = new Set(taxonomy.prevalence.map(p => p.id));
  const validCisco = new Set(taxonomy.ciscoObjectives.map(o => o.id));

  // Load vulnerabilities
  const raw = fs.readFileSync(vulnsPath, 'utf8');
  let data;
  try {
    data = JSON.parse(raw);
  } catch (e) {
    console.error('Invalid JSON in vulnerabilities.json:', e.message);
    process.exit(1);
  }

  if (!Array.isArray(data)) {
    console.error('Root element must be an array');
    process.exit(1);
  }

  const ids = new Set();
  let errors = 0;
  let warnings = 0;

  function err(prefix, msg) {
    console.error(`  ERROR ${prefix}: ${msg}`);
    errors++;
  }

  function warn(prefix, msg) {
    console.warn(`  WARN  ${prefix}: ${msg}`);
    warnings++;
  }

  data.forEach((entry, i) => {
    const prefix = `[${i}] "${entry.title || entry.id || 'untitled'}"`;

    // Required string fields
    for (const field of ['id', 'title', 'description', 'reportedBy', 'url']) {
      if (!entry[field] || typeof entry[field] !== 'string') {
        err(prefix, `missing or invalid "${field}"`);
      }
    }

    // Unique ID
    if (entry.id) {
      if (ids.has(entry.id)) {
        err(prefix, `duplicate id "${entry.id}"`);
      } else {
        ids.add(entry.id);
      }
    }

    // Date format
    if (!entry.date || !/^\d{4}-\d{2}-\d{2}$/.test(entry.date)) {
      err(prefix, `invalid date "${entry.date}" (must be YYYY-MM-DD)`);
    }

    // URL format
    if (entry.url && typeof entry.url === 'string' && !entry.url.startsWith('http')) {
      err(prefix, `invalid url "${entry.url}" (must start with http)`);
    }

    // Severity (taxonomy reference)
    if (!validSeverities.has(entry.severity)) {
      err(prefix, `invalid severity "${entry.severity}" (valid: ${[...validSeverities].join(', ')})`);
    }

    // Category (taxonomy reference)
    if (!validCategories.has(entry.category)) {
      err(prefix, `invalid category "${entry.category}" (valid: ${[...validCategories].join(', ')})`);
    }

    // Tags (taxonomy references)
    if (!Array.isArray(entry.tags) || entry.tags.length === 0) {
      err(prefix, '"tags" must be a non-empty array');
    } else {
      entry.tags.forEach(tag => {
        if (!validTags.has(tag)) {
          err(prefix, `unknown tag "${tag}" (not in taxonomy)`);
        }
      });
    }

    // Impact score (1-10)
    if (typeof entry.impactScore !== 'number' || entry.impactScore < 1 || entry.impactScore > 10) {
      err(prefix, `impactScore must be a number between 1 and 10 (got ${entry.impactScore})`);
    }

    // Exploitability (taxonomy reference)
    if (!validExploitability.has(entry.exploitability)) {
      err(prefix, `invalid exploitability "${entry.exploitability}" (valid: ${[...validExploitability].join(', ')})`);
    }

    // Affected components (taxonomy references)
    if (!Array.isArray(entry.affectedComponents) || entry.affectedComponents.length === 0) {
      err(prefix, '"affectedComponents" must be a non-empty array');
    } else {
      entry.affectedComponents.forEach(comp => {
        if (!validComponents.has(comp)) {
          err(prefix, `unknown affectedComponent "${comp}" (not in taxonomy)`);
        }
      });
    }

    // Prevalence (taxonomy reference)
    if (!validPrevalence.has(entry.prevalence)) {
      err(prefix, `invalid prevalence "${entry.prevalence}" (valid: ${[...validPrevalence].join(', ')})`);
    }

    // Cisco objectives (taxonomy references, can be empty)
    if (!Array.isArray(entry.ciscoObjectives)) {
      err(prefix, '"ciscoObjectives" must be an array');
    } else {
      entry.ciscoObjectives.forEach(obj => {
        if (!validCisco.has(obj)) {
          err(prefix, `unknown ciscoObjective "${obj}" (not in taxonomy)`);
        }
      });
    }

    // Enrichment fields (warnings for missing, not errors)
    for (const field of ['who', 'where', 'when', 'how', 'impact', 'mitigation']) {
      if (!entry[field] || typeof entry[field] !== 'string') {
        warn(prefix, `missing enrichment field "${field}"`);
      }
    }

    // Alternative names (optional array)
    if (entry.alternativeNames && !Array.isArray(entry.alternativeNames)) {
      err(prefix, '"alternativeNames" must be an array if provided');
    }

    // CVE IDs (optional array)
    if (entry.cveIds && !Array.isArray(entry.cveIds)) {
      err(prefix, '"cveIds" must be an array if provided');
    }

    // References (optional array of objects)
    if (entry.references) {
      if (!Array.isArray(entry.references)) {
        err(prefix, '"references" must be an array if provided');
      } else {
        entry.references.forEach((ref, j) => {
          if (!ref.title || !ref.url) {
            err(prefix, `references[${j}] must have "title" and "url"`);
          }
        });
      }
    }
  });

  console.log('');
  if (errors > 0) {
    console.error(`Validation FAILED: ${errors} error(s), ${warnings} warning(s) across ${data.length} entries.`);
    process.exit(1);
  }

  if (warnings > 0) {
    console.log(`Validated ${data.length} vulnerabilities with ${warnings} warning(s). No errors.`);
  } else {
    console.log(`Validated ${data.length} vulnerabilities. All entries are valid and fully enriched.`);
  }
}

validate();
