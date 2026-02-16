# Contributing to The Vulnerable MCP Project

Thank you for your interest in contributing to The Vulnerable MCP Project! This project is a community-maintained database of Model Context Protocol (MCP) vulnerabilities and security issues. Your contributions help make AI systems safer.

## How to Contribute

There are three ways to report a vulnerability:

### Option 1: Use the Web Form (Recommended for Everyone)

Visit our **[Report Vulnerability](https://vulnerablemcp.info/report.html)** page on the website. The form will guide you through all the required fields and create a pre-filled GitHub issue for you.

### Option 2: GitHub Issue Template (For GitHub Users)

1. Go to [New Issue](https://github.com/vineethsai/vulnerablemcp/issues/new/choose)
2. Select **Vulnerability Report**
3. Fill in the structured form fields
4. Submit

### Option 3: Direct JSON Pull Request (For Technical Contributors)

If you're comfortable with JSON and Git, you can submit a PR directly:

1. **Fork** this repository
2. **Edit** `data/vulnerabilities.json` and add a new entry following the v2 schema:

```json
{
  "id": "your-vulnerability-id",
  "title": "Your Vulnerability Title",
  "alternativeNames": ["Other Name for This Vuln"],
  "severity": "critical|high|medium|low|info",
  "category": "prompt-injection|input-validation|authentication|session-management|integrity|trust-model|credential-management|network-security",
  "impactScore": 8,
  "exploitability": "trivial|easy|moderate|difficult|theoretical",
  "affectedComponents": ["client", "server", "protocol", "ecosystem"],
  "prevalence": "widespread|common|emerging|rare",
  "reportedBy": "Your Name or Research Team",
  "date": "2025-01-15",
  "tags": ["prompt-injection", "data-exfiltration"],
  "ciscoObjectives": ["goal-hijacking", "data-privacy-violation"],
  "url": "https://link-to-original-writeup",
  "cveIds": [],
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

3. **Validate** your changes: `npm run validate`
4. **Submit** a Pull Request with a clear description of the vulnerability

### Controlled Vocabularies

All categorical fields reference the taxonomy in `data/taxonomy.json`. Valid values:

- **Severity**: critical, high, medium, low, info
- **Category**: prompt-injection, input-validation, authentication, session-management, integrity, trust-model, credential-management, network-security
- **Exploitability**: trivial, easy, moderate, difficult, theoretical
- **Affected Components**: client, server, protocol, ecosystem
- **Prevalence**: widespread, common, emerging, rare
- **Tags**: See the full list in `data/taxonomy.json` or on the [Taxonomy page](https://vulnerablemcp.info/taxonomy.html)
- **Cisco Objectives**: goal-hijacking, data-privacy-violation, privilege-escalation, integrity-compromise, unauthorized-access, supply-chain-compromise, communication-compromise

## What Happens After You Report

1. A maintainer reviews your submission
2. The vulnerability is validated and, if accepted, added to `data/vulnerabilities.json` with full enrichment
3. On push to `main`, GitHub Actions automatically rebuilds and deploys the site
4. Your contribution appears on [vulnerablemcp.info](https://vulnerablemcp.info) with its own detail page, timeline entry, and taxonomy mappings

## Guidelines

- **Be specific**: Include as much detail as possible about attack vectors and impact
- **Provide sources**: Link to original research, advisories, or writeups when available
- **Use proper severity**: Critical = trivially exploitable with severe impact; High = significant risk requiring prompt attention; Medium = moderate risk with limited scope; Low = minor risk; Info = informational
- **Avoid duplicates**: Search existing issues and the vulnerability database before submitting
- **Use standardized tags**: Reference the taxonomy for consistent categorization

## Reporting Website Bugs

If you find a bug on the website itself (not a vulnerability report), please use the [Website Bug / Improvement](https://github.com/vineethsai/vulnerablemcp/issues/new?template=website-bug.yml) issue template.

## Code of Conduct

Please be respectful and constructive. This project exists to improve security for everyone.

## Questions?

Open a [discussion](https://github.com/vineethsai/vulnerablemcp/issues) or reach out to the maintainer at [vineethsai.com](https://vineethsai.com).
