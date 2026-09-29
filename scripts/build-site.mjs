import fs from 'node:fs';
import path from 'node:path';
import { execFileSync } from 'node:child_process';
import { fileURLToPath } from 'node:url';
import { aidefendData } from '../main.js';
import { aidefendVersion } from '../aidefend-intro.js';
import { techniquePath, protectCodeBlocks } from '../js/technique-page.js';

export const escapeHtml = value => String(value ?? '').replace(/[&<>"']/g, c => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const escapeText = value => escapeHtml(value).replace(/&amp;((?:#\d+|#x[\da-f]+|[a-z][a-z\d]+);)/gi, '&$1');
const tags = new Set('p h2 h3 h4 h5 h6 pre code br strong em b i u ul ol li div span table thead tbody tr th td blockquote hr'.split(' '));

// Reconstruct only inert prose/code markup. Never pass authored attributes or
// executable HTML into the static response; the interactive UI uses DOMPurify.
export function readableHtml(value) {
    return protectCodeBlocks(value).split(/(<\/?[A-Za-z][^>]*>)/g).map(token => {
        const match = token.match(/^<(\/)?([a-z][a-z\d]*)([^>]*)>$/i);
        if (!match) return escapeText(token);
        const [, closing, rawName, attrs] = match;
        const name = rawName.toLowerCase();
        if (tags.has(name)) return '<' + (closing ? '/' : '') + name + '>';
        if (name === 'a') {
            if (closing) return '</a>';
            const href = attrs.match(/\bhref\s*=\s*(?:"([^"]*)"|'([^']*)')/i);
            const target = href?.[1] ?? href?.[2] ?? '';
            if (/^https?:\/\//i.test(target)) return '<a href="' + escapeText(target) + '" rel="noopener noreferrer">';
            return '<a>';
        }
        return escapeText(token);
    }).join('');
}

export function renderTechnique(entry, { tactic, parent, version }) {
    const e = escapeHtml;
    const family = Array.isArray(entry.subTechniques);
    const sections = [];
    const section = (title, body) => body ? `<section><h2>${e(title)}</h2>${body}</section>` : '';
    sections.push(`<nav><a href="/">AIDEFEND</a> / ${e(tactic)}${parent ? ` / <a href="${techniquePath(parent.id)}">${e(parent.id)}</a>` : ''}</nav>`);
    sections.push(`<h1>${e(entry.id)}: ${e(entry.name)}</h1><p class="reader-meta">Version ${e(version)} · ${family ? 'Family — navigation only' : parent ? 'Actionable sub-technique' : 'Actionable technique'}</p>`);
    sections.push(`<div class="technique-description">${readableHtml(entry.description)}</div>`);
    if (entry.pillar) sections.push(`<p><strong>Pillars:</strong> ${e(entry.pillar.join(', '))}</p>`);
    if (entry.phase) sections.push(`<p><strong>Lifecycle:</strong> ${e(entry.phase.join(', '))}</p>`);
    if (entry.scopeBoundary) {
        const b = entry.scopeBoundary;
        sections.push(section('Scope boundary', `<p>${e(b.responsibility)}</p>` + (b.relatedTechniques || []).map(r => `<p><a href="${techniquePath(r.id)}">${e(r.id)}</a>: ${e(r.comparison)}</p>`).join('')));
    }
    if (entry.warning) sections.push(section('Warning', `<p>${e(entry.warning.level || '')}</p>${readableHtml(entry.warning.description || entry.warning)}`));
    if (family) sections.push(section('Sub-techniques', '<ul>' + entry.subTechniques.map(child => `<li><a href="${techniquePath(child.id)}">${e(child.id)}: ${e(child.name)}</a></li>`).join('') + '</ul>'));
    const guidance = entry.implementationGuidance || [];
    if (guidance.length) {
        sections.push(section('Implementation guidance', '<ul>' + guidance.map(g => `<li><a href="${techniquePath(entry.id, g.id)}">${e(g.id)}</a>: ${readableHtml(g.implementation)}</li>`).join('') + '</ul>'));
        for (const g of guidance) sections.push(`<section id="${e(g.id)}" data-guidance-id="${e(g.id)}"><h2>${e(g.id)}</h2><div>${readableHtml(g.implementation)}</div>${readableHtml(g.howTo)}</section>`);
    }
    for (const [field, title] of [['toolsOpenSource', 'Open-source tools'], ['toolsSourceAvailable', 'Source-available / open-weight tools'], ['toolsCommercial', 'Commercial / hosted tools']]) {
        if (entry[field]?.length) sections.push(section(title, '<ul>' + entry[field].map(t => `<li>${e(t)}</li>`).join('') + '</ul>'));
    }
    sections.push(section('Threat mappings', (entry.defendsAgainst || []).map(f => `<h3>${e(f.framework)}</h3><ul>${f.items.map(i => `<li>${e(i)}</li>`).join('')}</ul>`).join('')));
    return `<article id="reader-content" class="reader-content">${sections.join('\n')}</article>`;
}

export const ROOT = fileURLToPath(new URL('../', import.meta.url));
export const OUTPUT = path.join(ROOT, '_site');
const SOURCE = path.join(ROOT, 'index.html');

export function buildSite() {
    if (fs.existsSync(OUTPUT) && (fs.lstatSync(OUTPUT).isSymbolicLink() || fs.realpathSync(OUTPUT) !== path.resolve(OUTPUT))) {
        throw new Error('Build output must be a real directory inside the repository');
    }
    fs.mkdirSync(OUTPUT, { recursive: true });
    const written = new Set();
    function write(relative, content) {
        const target = path.resolve(OUTPUT, relative);
        if (!target.startsWith(OUTPUT + path.sep)) throw new Error('Output path escaped build directory');
        fs.mkdirSync(path.dirname(target), { recursive: true });
        fs.writeFileSync(target, content);
        written.add(relative.replaceAll('\\', '/'));
    }

    // Only tracked public inputs and explicitly named new UI files are copied.
    // Local reviews, credentials, node_modules and workspaces never enter Pages.
    const tracked = execFileSync('git', ['ls-files', '-z'], { cwd: ROOT, encoding: 'utf8' }).split('\0').filter(Boolean);
    const explicit = ['js/technique-page.js'];
    const publicFile = p => /^(?:assets|css|js|kids|tactics|data)\//.test(p) ||
        /^(?:main|aidefend-intro|cisco-framework|framework-migrations|integration-catalogs|webmcp-tools|webmcp-query)\.js$/.test(p) ||
        /^(?:kids\.html|CNAME|LICENSE|LICENSE-CONTENT|LICENSING\.md|NOTICE|SECURITY\.md|THIRD_PARTY_NOTICES\.md|TRADEMARKS\.md)$/.test(p);
    for (const file of new Set([...tracked.filter(publicFile), ...explicit])) {
        const input = path.join(ROOT, file);
        if (fs.lstatSync(input).isSymbolicLink()) throw new Error(`Refusing public symlink: ${file}`);
        write(file, fs.readFileSync(input));
    }

    const source = fs.readFileSync(SOURCE, 'utf8');
    const modules = [...source.matchAll(/<script type="module">([\s\S]*?)<\/script>/g)];
    if (modules.length !== 1) throw new Error('Expected exactly one application module');
    // Extract only in the build: source/tests keep their existing ownership.
    write('site-app.js', modules[0][1]);
    let template = source.replace(modules[0][0], '<script type="module" src="/site-app.js"></script>');
    template = template.replace('<head>', '<head>\n    <base href="/">\n    <meta name="aidefend-site-base" content="/">');
    template = template.replace('https://edward-playground.github.io/aidefense-framework/', '/');
    write('index.html', template);
    const entries = aidefendData.tactics.flatMap(tactic => tactic.techniques.flatMap(entry => [
        { entry, tactic: tactic.name },
        ...(entry.subTechniques || []).map(child => ({ entry: child, parent: entry, tactic: tactic.name })),
    ]));
    const ids = new Set();
    for (const item of entries) {
        const { entry } = item;
        if (ids.has(entry.id)) throw new Error(`Duplicate technique: ${entry.id}`);
        ids.add(entry.id);
        const route = techniquePath(entry.id);
        const title = escapeHtml(`${entry.id}: ${entry.name} | AIDEFEND`);
        const summary = escapeHtml(entry.description.replace(/<[^>]*>/g, '').slice(0, 280));
        let page = template.replace(/<title>[\s\S]*?<\/title>/, () => `<title>${title}</title>`);
        page = page.replace(/(<meta (?:name="description"|property="og:description"|name="twitter:description") content=")[^"]*(">)/g, (_, a, b) => a + summary + b);
        page = page.replace(/(<meta (?:property="og:title"|name="twitter:title") content=")[^"]*(">)/g, (_, a, b) => a + title + b);
        page = page.replace(/(<link rel="canonical" href=")[^"]*(">)/, `$1https://aidefend.net${route}$2`);
        page = page.replace(/(<meta property="og:url" content=")[^"]*(">)/, `$1https://aidefend.net${route}$2`);
        page = page.replace('<body class="text-gray-800">', () => `<body class="text-gray-800 reader-page">\n${renderTechnique(entry, { ...item, version: aidefendVersion })}\n<div class="reader-loading" role="status"><h1>${title}</h1><p>Loading interactive view…</p></div>`);
        // A short loading state avoids flashing a second layout. Failed/blocked
        // application code automatically falls back to the complete HTML.
        page = page.replace('</head>', `<script>document.documentElement.classList.add('reader-booting');setTimeout(function(){document.documentElement.classList.remove('reader-booting')},6000);</script>\n</head>`);
        write(route.slice(1) + 'index.html', page);
    }
    write('.nojekyll', '');

    // Clean only previously recorded outputs, never arbitrary workspace paths.
    const manifestPath = path.join(OUTPUT, '.build-files.json');
    if (fs.existsSync(manifestPath)) {
        for (const old of JSON.parse(fs.readFileSync(manifestPath, 'utf8'))) {
            const target = path.resolve(OUTPUT, old);
            if (!target.startsWith(OUTPUT + path.sep)) throw new Error('Invalid prior output path');
            if (!written.has(old) && fs.existsSync(target)) fs.unlinkSync(target);
        }
    }
    // The cleanup ledger is local build state, not a public website asset.
    if (process.env.CI === 'true') {
        if (fs.existsSync(manifestPath)) fs.unlinkSync(manifestPath);
    } else {
        fs.writeFileSync(manifestPath, JSON.stringify([...written].sort()));
    }
    console.log(`Built ${entries.length} complete technique/family pages in ${OUTPUT}`);
    return { directory: OUTPUT, entries, files: [...written] };
}

if (process.argv[1] && path.resolve(process.argv[1]) === fileURLToPath(import.meta.url)) buildSite();
