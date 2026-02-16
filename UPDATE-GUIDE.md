# Vulnerability Update Guide

## Adding a New Vulnerability

### 1. Edit the JSON data file

Open `data/vulnerabilities.json` and add a new entry to the array:

```json
{
  "id": "unique-slug-for-the-vulnerability",
  "title": "Vulnerability Title",
  "alternativeNames": ["Other Name for This Vuln"],
  "severity": "critical",
  "category": "prompt-injection",
  "impactScore": 8,
  "exploitability": "easy",
  "affectedComponents": ["server"],
  "prevalence": "emerging",
  "reportedBy": "Researcher or Organization Name",
  "date": "2025-07-01",
  "tags": ["prompt-injection", "data-exfiltration"],
  "ciscoObjectives": ["goal-hijacking", "data-privacy-violation"],
  "url": "https://example.com/vulnerability-details",
  "cveIds": ["CVE-2025-12345"],
  "description": "Brief summary of the vulnerability.",
  "who": "Who is affected and who discovered it.",
  "where": "Where the vulnerability exists in the MCP architecture.",
  "when": "When it was discovered and relevant timeline.",
  "how": "Technical details of how the attack works.",
  "impact": "What damage can result from exploitation.",
  "mitigation": "Recommended steps to prevent or reduce risk.",
  "references": [
    { "title": "Original Research", "url": "https://example.com/writeup" }
  ]
}
```

### 2. Validate your entry

```bash
npm run validate
```

This checks all entries against `data/taxonomy.json` and verifies:
- All required fields are present and correctly typed
- `severity` is one of: critical, high, medium, low, info
- `category` is one of: prompt-injection, input-validation, authentication, session-management, integrity, trust-model, credential-management, network-security
- `exploitability` is one of: trivial, easy, moderate, difficult, theoretical
- `affectedComponents` values are valid: client, server, protocol, ecosystem
- `prevalence` is one of: widespread, common, emerging, rare
- `tags` and `ciscoObjectives` reference valid taxonomy entries
- `impactScore` is between 1 and 10
- `date` is in YYYY-MM-DD format
- `id` is unique across all entries
- URLs start with `http`
- Enrichment fields (who, where, when, how, impact, mitigation) are present

### 3. Check links (optional but recommended)

```bash
npm run check-links
```

This fetches every URL in the database and reports broken links, redirects, duplicate URLs, and consistency issues.

### 4. Build and preview

```bash
npm run build    # Generate site in dist/
npm run dev      # Build + start local server at http://localhost:3000
```

### 5. Submit

```bash
git add data/vulnerabilities.json
git commit -m "Add vulnerability: Your Vulnerability Title"
git push origin main
```

The site will auto-deploy via GitHub Actions within a few minutes.

## Field Reference

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `id` | string | yes | Unique kebab-case slug (e.g., `tool-poisoning-attacks`) |
| `title` | string | yes | Display title |
| `alternativeNames` | string[] | no | Other names for this vulnerability |
| `severity` | string | yes | critical, high, medium, low, or info |
| `category` | string | yes | Category from taxonomy (e.g., prompt-injection, input-validation) |
| `impactScore` | number | yes | 1-10 scale |
| `exploitability` | string | yes | trivial, easy, moderate, difficult, or theoretical |
| `affectedComponents` | string[] | yes | client, server, protocol, and/or ecosystem |
| `prevalence` | string | yes | widespread, common, emerging, or rare |
| `reportedBy` | string | yes | Who discovered/reported it |
| `date` | string | yes | ISO format: YYYY-MM-DD (publication/disclosure date) |
| `tags` | string[] | yes | Tags from taxonomy (see `data/taxonomy.json`) |
| `ciscoObjectives` | string[] | yes | Cisco security objectives (can be empty array) |
| `url` | string | yes | Link to the original writeup or advisory |
| `cveIds` | string[] | no | Associated CVE identifiers (can be empty array) |
| `description` | string | yes | Brief summary of the vulnerability |
| `who` | string | recommended | Who is affected and who discovered it |
| `where` | string | recommended | Where the vulnerability exists |
| `when` | string | recommended | Discovery and disclosure timeline |
| `how` | string | recommended | Technical attack details |
| `impact` | string | recommended | Consequences of exploitation |
| `mitigation` | string | recommended | Defensive recommendations |
| `references` | object[] | no | Array of `{ "title": "...", "url": "..." }` |

## Troubleshooting

- **Validation fails**: Check the error message -- it tells you exactly which field and entry has the issue. All categorical values must match `data/taxonomy.json`.
- **Build fails**: Make sure `npm install` has been run and `data/vulnerabilities.json` is valid JSON.
- **Missing images on ETDI page**: Ensure PNG files are in `assets/images/` (they get copied to `dist/` during build).
- **Unknown tag/category**: Check `data/taxonomy.json` for the full list of valid values.

## Architecture

- `data/vulnerabilities.json` is the single source of truth for vulnerability data
- `data/taxonomy.json` defines all valid controlled vocabularies
- `build.js` reads both JSON files, extracts content from `src/content/security.html` and `src/content/etdi-security.html`, and renders EJS templates into `dist/`
- Templates in `src/templates/partials/` are shared across all pages
- GitHub Actions automatically builds and deploys on push to `main`
