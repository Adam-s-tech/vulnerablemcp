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
2. Add a new entry to the array:

```json
{
  "id": "your-vulnerability-slug",
  "title": "Vulnerability Title",
  "severity": "high",
  "category": "security",
  "reportedBy": "Researcher or Organization",
  "date": "2025-07-01",
  "tags": ["Tag1", "Tag2", "Tag3"],
  "url": "https://example.com/vulnerability-writeup",
  "description": "Description of the vulnerability and its impact."
}
```

3. Run `npm run validate` to check your entry
4. Run `npm run build` to preview locally
5. Submit a pull request -- the site auto-deploys on merge to `main`

### Field Reference

| Field | Type | Required | Notes |
|-------|------|----------|-------|
| `id` | string | yes | Unique slug (e.g., `tool-poisoning-attacks`) |
| `title` | string | yes | Display title |
| `severity` | string | yes | `high`, `medium`, `low`, or `info` |
| `category` | string | yes | `security` or `implementation` |
| `reportedBy` | string | yes | Who discovered/reported it |
| `date` | string | yes | ISO format: `YYYY-MM-DD` |
| `tags` | string[] | yes | Array of descriptive tags |
| `url` | string | yes | Link to the original writeup |
| `description` | string | yes | Detailed description (supports `\n` for paragraphs) |

## Project Structure

```
vulnerablemcp/
├── data/
│   └── vulnerabilities.json     # Vulnerability database (edit this!)
├── src/templates/
│   ├── partials/                 # Shared HTML partials (head, header, footer)
│   └── pages/                   # Page templates (index, about, security, etc.)
├── assets/
│   ├── css/style.css            # Shared stylesheet
│   └── js/main.js               # Client-side JavaScript
├── scripts/
│   ├── validate.js              # JSON schema validation
│   └── migrate-md-to-json.js    # Migration tool (markdown -> JSON)
├── build.js                     # Build script (EJS -> HTML)
├── server.js                    # Local dev server
├── .github/workflows/
│   └── deploy.yml               # Auto-deploy to GitHub Pages
└── dist/                        # Built output (git-ignored)
```

## How It Works

1. **Data** lives in `data/vulnerabilities.json` (structured, validated JSON)
2. **Templates** use [EJS](https://ejs.co/) with shared partials for consistent header/footer/nav
3. **Build** (`node build.js`) renders templates + data into static HTML in `dist/`
4. **Deploy** happens automatically via GitHub Actions on push to `main`

## Scripts

| Command | Description |
|---------|-------------|
| `npm run build` | Build the site to `dist/` |
| `npm run validate` | Validate `data/vulnerabilities.json` |
| `npm run dev` | Build + start local server on port 3000 |
| `npm run migrate` | Convert legacy `vulnerabilities.md` to JSON |

## Contributing

We welcome contributions! You can:

- **Add vulnerabilities** by editing `data/vulnerabilities.json` and submitting a PR
- **Improve the site** by editing templates in `src/templates/`
- **Report issues** via [GitHub Issues](https://github.com/vineethsai/vulnerablemcp/issues)

## License

All rights reserved. See repository for details.

## Author

[Vineeth Sai](https://vineethsai.com) - [GitHub](https://github.com/vineethsai) - [LinkedIn](https://www.linkedin.com/in/vineethsai/)
