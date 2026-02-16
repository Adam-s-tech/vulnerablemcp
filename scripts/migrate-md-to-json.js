const fs = require('fs');
const path = require('path');

const mdPath = path.join(__dirname, '..', 'vulnerabilities.md');
const jsonPath = path.join(__dirname, '..', 'data', 'vulnerabilities.json');

function slugify(text) {
  return text
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, '-')
    .replace(/(^-|-$)/g, '');
}

function parseDate(dateStr) {
  const months = {
    january: '01', february: '02', march: '03', april: '04',
    may: '05', june: '06', july: '07', august: '08',
    september: '09', october: '10', november: '11', december: '12'
  };
  const parts = dateStr.trim().split(/[\s,]+/).filter(Boolean);
  if (parts.length === 3) {
    const month = months[parts[0].toLowerCase()] || '01';
    const day = parts[1].replace(',', '').padStart(2, '0');
    const year = parts[2];
    return `${year}-${month}-${day}`;
  }
  if (parts.length === 2) {
    const month = months[parts[0].toLowerCase()] || '01';
    const year = parts[1];
    return `${year}-${month}-01`;
  }
  return '2025-01-01';
}

function migrate() {
  const md = fs.readFileSync(mdPath, 'utf8');
  const sections = md.split('---').filter(s => s.trim());
  const vulns = [];

  sections.forEach(section => {
    const lines = section.trim().split('\n');
    const titleMatch = lines[0].match(/^## (.+)$/);
    if (!titleMatch) return;

    const title = titleMatch[1];
    let severity = '', category = '', reportedBy = '', date = '', tags = [], url = '', description = '';
    let inDesc = false;

    for (let i = 1; i < lines.length; i++) {
      const line = lines[i];
      if (line.startsWith('**Severity:**')) severity = line.replace('**Severity:**', '').trim().toLowerCase();
      else if (line.startsWith('**Category:**')) category = line.replace('**Category:**', '').trim().toLowerCase();
      else if (line.startsWith('**Reported By:**')) reportedBy = line.replace('**Reported By:**', '').trim();
      else if (line.startsWith('**Date:**')) date = parseDate(line.replace('**Date:**', '').trim());
      else if (line.startsWith('**Tags:**')) tags = line.replace('**Tags:**', '').trim().split(',').map(t => t.trim());
      else if (line.startsWith('**URL:**')) url = line.replace('**URL:**', '').trim();
      else if (line.trim() !== '' && !line.startsWith('**')) {
        if (!inDesc) inDesc = true;
        description += line + '\n';
      }
    }

    vulns.push({
      id: slugify(title),
      title,
      severity,
      category,
      reportedBy,
      date,
      tags,
      url,
      description: description.trim()
    });
  });

  fs.writeFileSync(jsonPath, JSON.stringify(vulns, null, 2));
  console.log(`Migrated ${vulns.length} vulnerabilities to ${jsonPath}`);
}

migrate();
