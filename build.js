const fs = require('fs');
const path = require('path');
const ejs = require('ejs');

const ROOT = __dirname;
const DIST = path.join(ROOT, 'dist');
const TEMPLATES = path.join(ROOT, 'src', 'templates');
const DATA = path.join(ROOT, 'data');
const SITE_URL = 'https://vulnerablemcp.info';

function ensureDir(dir) {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
}

function copyDir(src, dest) {
  ensureDir(dest);
  for (const entry of fs.readdirSync(src, { withFileTypes: true })) {
    const srcPath = path.join(src, entry.name);
    const destPath = path.join(dest, entry.name);
    if (entry.isDirectory()) {
      copyDir(srcPath, destPath);
    } else {
      fs.copyFileSync(srcPath, destPath);
    }
  }
}

function formatDate(isoDate) {
  const d = new Date(isoDate + 'T00:00:00');
  return d.toLocaleDateString('en-US', { year: 'numeric', month: 'long', day: 'numeric' });
}

function extractSecurityMainContent(htmlPath) {
  if (!fs.existsSync(htmlPath)) return '';
  const html = fs.readFileSync(htmlPath, 'utf8');
  const startMarker = '<div class="security-main">';
  const startIdx = html.indexOf(startMarker);
  if (startIdx === -1) return '';
  
  let depth = 0;
  let i = startIdx + startMarker.length;
  const contentStart = i;
  
  while (i < html.length) {
    if (html.substring(i, i + 4) === '<div') {
      depth++;
    } else if (html.substring(i, i + 6) === '</div>') {
      if (depth === 0) {
        return html.substring(contentStart, i);
      }
      depth--;
    }
    i++;
  }
  return '';
}

function extractEtdiMainContent(htmlPath) {
  if (!fs.existsSync(htmlPath)) return '';
  const html = fs.readFileSync(htmlPath, 'utf8');
  const startMarker = '<main class="security-main">';
  const startIdx = html.indexOf(startMarker);
  if (startIdx === -1) return '';
  
  const endMarker = '</main>';
  const endIdx = html.indexOf(endMarker, startIdx);
  if (endIdx === -1) return '';
  
  return html.substring(startIdx + startMarker.length, endIdx);
}

function computeStats(vulnerabilities, taxonomy) {
  const total = vulnerabilities.length;
  const cveCount = vulnerabilities.reduce((n, v) => n + (v.cveIds ? v.cveIds.length : 0), 0);
  const criticalCount = vulnerabilities.filter(v => v.severity === 'critical').length;
  const researchers = new Set(vulnerabilities.map(v => v.reportedBy)).size;
  const dates = vulnerabilities.map(v => v.date).sort();
  const earliest = new Date(dates[0] + 'T00:00:00');
  const latest = new Date(dates[dates.length - 1] + 'T00:00:00');
  const dateRange = earliest.toLocaleDateString('en-US', { month: 'short', year: 'numeric' }) +
    ' - ' + latest.toLocaleDateString('en-US', { month: 'short', year: 'numeric' });

  const severityData = taxonomy.severities.map(s => ({
    label: s.label,
    color: s.color,
    count: vulnerabilities.filter(v => v.severity === s.id).length
  })).filter(s => s.count > 0);

  const categoryData = taxonomy.categories.map(c => ({
    label: c.shortLabel,
    count: vulnerabilities.filter(v => v.category === c.id).length
  })).filter(c => c.count > 0).sort((a, b) => b.count - a.count);

  const monthMap = {};
  vulnerabilities.forEach(v => {
    const key = v.date.substring(0, 7);
    monthMap[key] = (monthMap[key] || 0) + 1;
  });
  const sortedMonths = Object.keys(monthMap).sort();
  const timelineData = sortedMonths.map(m => {
    const d = new Date(m + '-01T00:00:00');
    return {
      label: d.toLocaleDateString('en-US', { month: 'short', year: '2-digit' }),
      count: monthMap[m]
    };
  });

  const exploitData = taxonomy.exploitability.map(e => ({
    label: e.label,
    count: vulnerabilities.filter(v => v.exploitability === e.id).length
  })).filter(e => e.count > 0);

  const componentMap = {};
  vulnerabilities.forEach(v => {
    (v.affectedComponents || []).forEach(c => {
      componentMap[c] = (componentMap[c] || 0) + 1;
    });
  });
  const componentData = taxonomy.affectedComponents.map(c => ({
    label: c.label,
    count: componentMap[c.id] || 0
  })).filter(c => c.count > 0).sort((a, b) => b.count - a.count);

  const ciscoMap = {};
  vulnerabilities.forEach(v => {
    (v.ciscoObjectives || []).forEach(c => {
      ciscoMap[c] = (ciscoMap[c] || 0) + 1;
    });
  });
  const ciscoData = taxonomy.ciscoObjectives.map(c => ({
    label: c.label,
    count: ciscoMap[c.id] || 0
  })).sort((a, b) => b.count - a.count);

  return {
    total,
    cveCount,
    criticalCount,
    researchers,
    dateRange,
    categories: taxonomy.categories.length,
    severityData,
    categoryData,
    timelineData,
    exploitData,
    componentData,
    ciscoData
  };
}

function generateSitemap(staticPages, sortedVulns) {
  const today = new Date().toISOString().split('T')[0];
  let xml = '<?xml version="1.0" encoding="UTF-8"?>\n';
  xml += '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n';

  const staticUrls = [
    { loc: '', priority: '1.0', changefreq: 'weekly' },
    { loc: 'stats.html', priority: '0.8', changefreq: 'weekly' },
    { loc: 'taxonomy.html', priority: '0.8', changefreq: 'monthly' },
    { loc: 'report.html', priority: '0.6', changefreq: 'monthly' },
    { loc: 'about.html', priority: '0.5', changefreq: 'monthly' },
    { loc: 'security.html', priority: '0.7', changefreq: 'monthly' },
    { loc: 'etdi-security.html', priority: '0.7', changefreq: 'monthly' }
  ];

  for (const page of staticUrls) {
    xml += `  <url>\n`;
    xml += `    <loc>${SITE_URL}/${page.loc}</loc>\n`;
    xml += `    <lastmod>${today}</lastmod>\n`;
    xml += `    <changefreq>${page.changefreq}</changefreq>\n`;
    xml += `    <priority>${page.priority}</priority>\n`;
    xml += `  </url>\n`;
  }

  for (const vuln of sortedVulns) {
    xml += `  <url>\n`;
    xml += `    <loc>${SITE_URL}/vuln/${vuln.id}.html</loc>\n`;
    xml += `    <lastmod>${vuln.date}</lastmod>\n`;
    xml += `    <changefreq>monthly</changefreq>\n`;
    xml += `    <priority>0.7</priority>\n`;
    xml += `  </url>\n`;
  }

  xml += '</urlset>\n';
  return xml;
}

function generateRobotsTxt() {
  return `User-agent: *\nAllow: /\n\nSitemap: ${SITE_URL}/sitemap.xml\n`;
}

async function build() {
  console.log('Building website...');

  const vulnsRaw = fs.readFileSync(path.join(DATA, 'vulnerabilities.json'), 'utf8');
  const vulnerabilities = JSON.parse(vulnsRaw).map(v => ({
    ...v,
    displayDate: formatDate(v.date)
  }));

  const taxonomy = JSON.parse(fs.readFileSync(path.join(DATA, 'taxonomy.json'), 'utf8'));

  console.log(`Loaded ${vulnerabilities.length} vulnerabilities`);
  console.log(`Loaded taxonomy: ${taxonomy.categories.length} categories, ${taxonomy.tags.length} tags, ${taxonomy.ciscoObjectives.length} Cisco objectives`);

  if (fs.existsSync(DIST)) {
    fs.rmSync(DIST, { recursive: true });
  }
  ensureDir(DIST);
  ensureDir(path.join(DIST, 'vuln'));

  copyDir(path.join(ROOT, 'assets'), path.join(DIST, 'assets'));

  for (const f of ['favicon.ico', 'favicon.svg']) {
    const src = path.join(ROOT, f);
    if (fs.existsSync(src)) fs.copyFileSync(src, path.join(DIST, f));
  }

  for (const f of fs.readdirSync(ROOT)) {
    if (f.endsWith('.png') || f.endsWith('.jpg') || f.endsWith('.jpeg')) {
      fs.copyFileSync(path.join(ROOT, f), path.join(DIST, f));
    }
  }

  const securityContent = extractSecurityMainContent(path.join(ROOT, 'security.html'));
  const etdiContent = extractEtdiMainContent(path.join(ROOT, 'etdi-security.html'));
  const sortedVulns = [...vulnerabilities].sort((a, b) => b.date.localeCompare(a.date));
  const stats = computeStats(sortedVulns, taxonomy);

  const pages = [
    {
      template: 'index',
      output: 'index.html',
      data: {
        currentPage: 'index',
        vulnerabilities: sortedVulns,
        taxonomy,
        meta: {
          title: 'The Vulnerable MCP Project: Comprehensive Model Context Protocol Security Database',
          description: 'A comprehensive database of Model Context Protocol (MCP) vulnerabilities, security issues, and exploits. Track the latest MCP security research, tool poisoning attacks, and protocol vulnerabilities.',
          keywords: 'MCP vulnerabilities, Model Context Protocol security, prompt injection, tool poisoning, MCP exploits, AI security, LLM vulnerabilities, Claude security, MCP attacks',
          ogTitle: 'The Vulnerable MCP Project - Comprehensive MCP Security Database',
          ogDescription: 'Track and understand Model Context Protocol vulnerabilities with our comprehensive security database. Latest research on MCP exploits, tool poisoning, and security best practices.',
          twitterTitle: 'The Vulnerable MCP Project - MCP Security Database',
          twitterDescription: 'Comprehensive database of Model Context Protocol vulnerabilities and security research',
          canonical: '',
          structuredData: {
            '@context': 'https://schema.org',
            '@type': 'WebSite',
            name: 'The Vulnerable MCP Project',
            url: `${SITE_URL}/`,
            description: 'A comprehensive database of Model Context Protocol vulnerabilities, security issues, and exploits',
            author: { '@type': 'Person', name: 'Vineeth Sai', url: 'https://vineethsai.com' },
            potentialAction: {
              '@type': 'SearchAction',
              target: `${SITE_URL}/?q={search_term_string}`,
              'query-input': 'required name=search_term_string'
            }
          }
        }
      }
    },
    {
      template: 'stats',
      output: 'stats.html',
      data: {
        currentPage: 'stats',
        stats,
        meta: {
          title: 'Vulnerability Statistics | The Vulnerable MCP Project',
          description: `Data-driven overview of ${stats.total} MCP vulnerabilities: severity breakdown, timeline trends, category analysis, and Cisco AI Security Framework mapping.`,
          keywords: 'MCP vulnerability statistics, MCP security trends, vulnerability analysis, AI security metrics',
          canonical: 'stats.html',
          structuredData: {
            '@context': 'https://schema.org',
            '@type': 'WebPage',
            name: 'Vulnerability Statistics - The Vulnerable MCP Project',
            url: `${SITE_URL}/stats.html`,
            description: `Data-driven overview of ${stats.total} MCP vulnerabilities`,
            author: { '@type': 'Person', name: 'Vineeth Sai', url: 'https://vineethsai.com' }
          }
        }
      }
    },
    {
      template: 'taxonomy',
      output: 'taxonomy.html',
      data: {
        currentPage: 'taxonomy',
        taxonomy,
        vulnerabilities: sortedVulns,
        meta: {
          title: 'Vulnerability Taxonomy | The Vulnerable MCP Project',
          description: 'Structured classification framework for MCP security vulnerabilities, mapped to the Cisco AI Security Framework with severity ratings, categories, and exploitability levels.',
          keywords: 'MCP vulnerability taxonomy, Cisco AI Security Framework, vulnerability classification, MCP security categories, exploitability ratings',
          canonical: 'taxonomy.html',
          structuredData: {
            '@context': 'https://schema.org',
            '@type': 'WebPage',
            name: 'Vulnerability Taxonomy - The Vulnerable MCP Project',
            url: `${SITE_URL}/taxonomy.html`,
            description: 'Structured classification framework for MCP security vulnerabilities',
            author: { '@type': 'Person', name: 'Vineeth Sai', url: 'https://vineethsai.com' }
          }
        }
      }
    },
    {
      template: 'report',
      output: 'report.html',
      data: {
        currentPage: 'report',
        meta: {
          title: 'Report a Vulnerability | The Vulnerable MCP Project',
          description: 'Report a new MCP vulnerability or security issue. Use our guided form to submit to the community database.',
          keywords: 'report MCP vulnerability, submit vulnerability, MCP security report, contribute MCP security',
          canonical: 'report.html',
          structuredData: {
            '@context': 'https://schema.org',
            '@type': 'WebPage',
            name: 'Report a Vulnerability - The Vulnerable MCP Project',
            url: `${SITE_URL}/report.html`,
            description: 'Report a new MCP vulnerability or security issue using our guided form',
            author: { '@type': 'Person', name: 'Vineeth Sai', url: 'https://vineethsai.com' }
          }
        }
      }
    },
    {
      template: 'about',
      output: 'about.html',
      data: {
        currentPage: 'about',
        meta: {
          title: 'About The Vulnerable MCP Project | Our Mission & Community',
          description: 'About The Vulnerable MCP Project: Our mission, features, and how to contribute to improving Model Context Protocol security and AI safety',
          keywords: 'MCP Project mission, Model Context Protocol community, AI security contributors, LLM vulnerability database, MCP security research, contribute to AI safety',
          ogTitle: 'About The Vulnerable MCP Project | Our Mission & Community',
          ogDescription: 'Learn about our mission, features, and how to contribute to improving Model Context Protocol security and AI safety',
          robots: 'index, follow',
          canonical: 'about.html',
          structuredData: {
            '@context': 'https://schema.org',
            '@type': 'WebPage',
            name: 'About The Vulnerable MCP Project | Our Mission & Community',
            url: `${SITE_URL}/about.html`,
            description: 'Learn about our mission, features, and how to contribute to improving Model Context Protocol security and AI safety',
            author: { '@type': 'Person', name: 'Vineeth Sai', url: 'https://vineethsai.com' }
          }
        }
      }
    },
    {
      template: 'security',
      output: 'security.html',
      data: {
        currentPage: 'security',
        securityContent,
        meta: {
          title: 'MCP Security: Best Practices & Implementation Guide | The Vulnerable MCP Project',
          description: 'Learn comprehensive MCP security strategies and best practices for securing Model Context Protocol implementations against common vulnerabilities and attacks',
          keywords: 'MCP security, Model Context Protocol security, AI security best practices, LLM vulnerabilities, prompt injection prevention, MCP security checklist, AI safety, enterprise MCP security',
          ogTitle: 'Understanding MCP Security - The Vulnerable MCP Project',
          ogDescription: 'Learn comprehensive MCP security strategies and best practices for securing Model Context Protocol implementations against common vulnerabilities and attacks',
          canonical: 'security.html',
          structuredData: {
            '@context': 'https://schema.org',
            '@type': 'TechArticle',
            headline: 'Understanding MCP Security - The Vulnerable MCP Project',
            description: 'Learn comprehensive MCP security strategies and best practices for securing Model Context Protocol implementations against common vulnerabilities and attacks',
            author: { '@type': 'Person', name: 'Vineeth Sai' },
            publisher: { '@type': 'Organization', name: 'The Vulnerable MCP Project', url: `${SITE_URL}/` },
            mainEntityOfPage: { '@type': 'WebPage', '@id': `${SITE_URL}/security.html` },
            keywords: ['MCP security', 'Model Context Protocol', 'AI security', 'LLM vulnerabilities', 'prompt injection prevention', 'enterprise MCP security', 'AI safety']
          }
        }
      }
    },
    {
      template: 'etdi-security',
      output: 'etdi-security.html',
      data: {
        currentPage: 'etdi-security',
        etdiContent,
        meta: {
          title: 'ETDI: Enhanced Tool Definition Interface | MCP Security Framework',
          description: 'Complete guide to ETDI: Enhanced Tool Definition Interface for securing Model Context Protocol against tool poisoning and rug pull attacks',
          keywords: 'ETDI, MCP security, Enhanced Tool Definition Interface, tool poisoning prevention, rug pull prevention, OAuth 2.0, policy-based access control, Cedar, OPA, AI security',
          author: 'ETDI Security Framework',
          ogTitle: 'ETDI: Comprehensive MCP Security Framework',
          ogDescription: 'Complete security framework for protecting Large Language Model applications from critical vulnerabilities using Enhanced Tool Definition Interface',
          twitterTitle: 'ETDI: Comprehensive MCP Security Framework',
          twitterDescription: 'Complete security framework for protecting Large Language Model applications from critical vulnerabilities',
          canonical: 'etdi-security.html',
          structuredData: {
            '@context': 'https://schema.org',
            '@type': 'TechArticle',
            headline: 'ETDI: Enhanced Tool Definition Interface for MCP Security',
            description: 'Complete security framework for protecting Large Language Model applications from tool poisoning and rug pull attacks',
            author: { '@type': 'Organization', name: 'ETDI Security Framework' },
            publisher: { '@type': 'Organization', name: 'The Vulnerable MCP Project', url: `${SITE_URL}/` },
            mainEntityOfPage: { '@type': 'WebPage', '@id': `${SITE_URL}/etdi-security.html` },
            keywords: ['ETDI', 'MCP security', 'OAuth 2.0', 'policy-based access control', 'tool poisoning', 'rug pull attacks']
          }
        }
      }
    },
    {
      template: '404',
      output: '404.html',
      data: {
        currentPage: '',
        meta: {
          title: 'Page Not Found | The Vulnerable MCP Project',
          description: 'The page you are looking for does not exist.',
          keywords: 'MCP vulnerabilities, 404, page not found',
          canonical: '404.html'
        }
      }
    }
  ];

  for (const page of pages) {
    const templatePath = path.join(TEMPLATES, 'pages', `${page.template}.ejs`);
    const html = await ejs.renderFile(templatePath, page.data, {
      views: [TEMPLATES]
    });
    fs.writeFileSync(path.join(DIST, page.output), html);
    console.log(`  Built ${page.output}`);
  }

  const detailTemplate = path.join(TEMPLATES, 'pages', 'vuln-detail.ejs');
  for (let i = 0; i < sortedVulns.length; i++) {
    const vuln = sortedVulns[i];
    const prevVuln = i > 0 ? sortedVulns[i - 1] : null;
    const nextVuln = i < sortedVulns.length - 1 ? sortedVulns[i + 1] : null;

    const detailHtml = await ejs.renderFile(detailTemplate, {
      currentPage: 'vuln-detail',
      vuln,
      taxonomy,
      prevVuln,
      nextVuln,
      basePath: '../',
      meta: {
        title: `${vuln.title} | The Vulnerable MCP Project`,
        description: vuln.description.substring(0, 160) + '...',
        keywords: vuln.tags.map(t => {
          const tagObj = taxonomy.tags.find(tag => tag.id === t);
          return tagObj ? tagObj.label : t;
        }).join(', '),
        ogTitle: vuln.title + ' - MCP Vulnerability',
        ogDescription: vuln.description.substring(0, 200),
        canonical: `vuln/${vuln.id}.html`,
        structuredData: [
          {
            '@context': 'https://schema.org',
            '@type': 'TechArticle',
            headline: vuln.title,
            description: vuln.description.substring(0, 200),
            datePublished: vuln.date,
            author: { '@type': 'Person', name: vuln.reportedBy },
            publisher: { '@type': 'Organization', name: 'The Vulnerable MCP Project', url: `${SITE_URL}/` },
            mainEntityOfPage: { '@type': 'WebPage', '@id': `${SITE_URL}/vuln/${vuln.id}.html` }
          },
          {
            '@context': 'https://schema.org',
            '@type': 'BreadcrumbList',
            itemListElement: [
              { '@type': 'ListItem', position: 1, name: 'Home', item: `${SITE_URL}/` },
              { '@type': 'ListItem', position: 2, name: vuln.title, item: `${SITE_URL}/vuln/${vuln.id}.html` }
            ]
          }
        ]
      }
    }, {
      views: [TEMPLATES]
    });

    fs.writeFileSync(path.join(DIST, 'vuln', `${vuln.id}.html`), detailHtml);
  }
  console.log(`  Built ${sortedVulns.length} vulnerability detail pages in vuln/`);

  // Generate sitemap.xml
  fs.writeFileSync(path.join(DIST, 'sitemap.xml'), generateSitemap(pages, sortedVulns));
  console.log('  Built sitemap.xml');

  // Generate robots.txt
  fs.writeFileSync(path.join(DIST, 'robots.txt'), generateRobotsTxt());
  console.log('  Built robots.txt');

  // Create CNAME
  fs.writeFileSync(path.join(DIST, 'CNAME'), 'vulnerablemcp.info\n');

  console.log(`\nBuild complete! Output in dist/`);
  console.log(`  ${vulnerabilities.length} vulnerabilities rendered`);
  console.log(`  ${pages.length + sortedVulns.length} total pages generated`);
}

build().catch(err => {
  console.error('Build failed:', err);
  process.exit(1);
});
