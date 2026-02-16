# Vulnerability Update Guide

## Adding a New Vulnerability

### 1. Edit the JSON data file

Open `data/vulnerabilities.json` and add a new entry to the array:

```json
{
  "id": "unique-slug-for-the-vulnerability",
  "title": "Vulnerability Title",
  "severity": "high",
  "category": "security",
  "reportedBy": "Researcher or Organization Name",
  "date": "2025-07-01",
  "tags": ["Tag1", "Tag2", "Tag3"],
  "url": "https://example.com/vulnerability-details",
  "description": "Description of the vulnerability. Use \\n for paragraph breaks."
}
```

### 2. Validate your entry

```bash
npm run validate
```

This checks:
- All required fields are present
- Date format is `YYYY-MM-DD`
- Severity is one of: `high`, `medium`, `low`, `info`
- Category is one of: `security`, `implementation`
- IDs are unique
- URLs start with `http`

### 3. Build and preview

```bash
npm run build    # Generate site in dist/
npm run dev      # Build + start local server at http://localhost:3000
```

### 4. Submit

```bash
git add data/vulnerabilities.json
git commit -m "Add vulnerability: Your Vulnerability Title"
git push origin main
```

The site will auto-deploy via GitHub Actions within a few minutes.

## Field Reference

| Field | Format | Example |
|-------|--------|---------|
| `id` | kebab-case slug | `tool-poisoning-attacks` |
| `title` | Free text | `Tool Poisoning Attacks` |
| `severity` | `high` / `medium` / `low` / `info` | `high` |
| `category` | `security` / `implementation` | `security` |
| `reportedBy` | Free text | `Invariant Labs` |
| `date` | `YYYY-MM-DD` | `2025-04-01` |
| `tags` | Array of strings | `["Data Exfiltration", "Prompt Injection"]` |
| `url` | URL to writeup | `https://example.com/blog/post` |
| `description` | Free text, `\n` for paragraphs | `Description here...` |

## Troubleshooting

- **Validation fails**: Check the error message -- it tells you exactly which field and entry has the issue
- **Build fails**: Make sure `npm install` has been run and `data/vulnerabilities.json` is valid JSON
- **Missing images on ETDI page**: Ensure PNG files are in the root directory (they get copied to `dist/` during build)

## Architecture

- `data/vulnerabilities.json` is the single source of truth
- `build.js` reads the JSON and renders EJS templates into `dist/`
- Templates in `src/templates/partials/` are shared across all pages (header, footer, head)
- GitHub Actions automatically builds and deploys on push to `main`
