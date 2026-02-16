# The Vulnerable MCP Project

A comprehensive database of [Model Context Protocol (MCP)](https://modelcontextprotocol.io/) vulnerabilities, security research, and exploits.

**Live site:** [https://vulnerablemcp.info](https://vulnerablemcp.info)

## Quick Start

```bash
npm install          # Install dependencies
npm run build        # Build the site to dist/
npm run dev          # Build + start local dev server on port 3000
```

## Adding a New Vulnerability

1. Open `data/vulnerabilities.json`
2. Add a new entry following the v2 schema:

```json
{
  "id": "your-vulnerability-slug",
  "title": "Vulnerability Title",
  "alternativeNames": ["Other Name"],
  "severity": "critical",
  "category": "prompt-injection",
  "impactScore": 8,
  "exploitability": "easy",
  "affectedComponents": ["server"],
  "prevalence": "emerging",
  "reportedBy": "Researcher or Organization",
  "date": "2025-07-01",
  "tags": ["prompt-injection", "data-exfiltration"],
  "ciscoObjectives": ["goal-hijacking"],
  "url": "https://example.com/vulnerability-writeup",
  "cveIds": ["CVE-2025-12345"],
  "description": "Brief summary of the vulnerability.",
  "who": "Who is affected and who discovered it.",
  "where": "Where the vulnerability exists.",
  "when": "When it was discovered.",
  "how": "How the attack works.",
  "impact": "What damage can result.",
  "mitigation": "Recommended defenses.",
  "references": [
    { "title": "Original Research", "url": "https://example.com/writeup" }
  ]
}
```

3. Run `npm run validate` to check your entry against the taxonomy
4. Run `npm run build` to preview locally
5. Submit a pull request -- the site auto-deploys on merge to `main`

All categorical fields (`severity`, `category`, `tags`, `exploitability`, `affectedComponents`, `prevalence`, `ciscoObjectives`) are validated against `data/taxonomy.json`.

## Project Structure

```
vulnerablemcp/
├── data/
│   ├── vulnerabilities.json      # Vulnerability database (edit this!)
│   └── taxonomy.json             # Controlled vocabularies for categories, tags, etc.
├── src/templates/
│   ├── partials/                  # Shared HTML partials (head, header, footer)
│   └── pages/                    # Page templates (index, about, stats, taxonomy, etc.)
├── assets/
│   ├── css/style.css             # Shared stylesheet
│   ├── js/main.js                # Client-side JavaScript (search, filters, theme)
│   └── images/                   # Diagrams and images (ETDI, architecture)
├── scripts/
│   ├── validate.js               # JSON schema + taxonomy validation
│   └── check-links.js            # URL liveness + consistency checker
├── build.js                      # Build script (EJS + data -> static HTML)
├── server.js                     # Local dev server (serves dist/)
├── .github/workflows/
│   └── deploy.yml                # Auto-deploy to GitHub Pages on push to main
└── dist/                         # Built output (git-ignored)
```

## How It Works

1. **Data** lives in `data/vulnerabilities.json` (structured, validated JSON)
2. **Taxonomy** in `data/taxonomy.json` defines all valid categories, tags, and controlled vocabularies
3. **Content** sources in `src/content/` (security.html, etdi-security.html) provide rich page content extracted during build
4. **Templates** use [EJS](https://ejs.co/) with shared partials for consistent layout
5. **Build** (`node build.js`) renders templates + data into static HTML in `dist/`
6. **Deploy** happens automatically via GitHub Actions on push to `main`

## Scripts

| Command | Description |
|---------|-------------|
| `npm run build` | Build the site to `dist/` |
| `npm run validate` | Validate `data/vulnerabilities.json` against taxonomy |
| `npm run check-links` | Check all URLs for liveness and run consistency checks |
| `npm run dev` | Build + start local server on port 3000 |

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for details. You can:

- **Report vulnerabilities** via the [web form](https://vulnerablemcp.info/report.html) or GitHub Issues
- **Add vulnerabilities** by editing `data/vulnerabilities.json` and submitting a PR
- **Improve the site** by editing templates in `src/templates/`

## License

All rights reserved. See repository for details.

## Author

[Vineeth Sai](https://vineethsai.com) - [GitHub](https://github.com/vineethsai) - [LinkedIn](https://www.linkedin.com/in/vineethsai/)
