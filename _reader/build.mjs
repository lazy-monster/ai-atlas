// Builds the encrypted Atlas Reader into ../read from the Sutskever reading-list folder.
//
//   node build.mjs [--src DIR] [--out DIR]
//
// Password source, in order: $ATLAS_READER_PASSWORD, ~/.config/atlas-reader/password, prompt.

import { spawnSync } from 'node:child_process';
import { webcrypto as crypto } from 'node:crypto';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import zlib from 'node:zlib';
import katex from 'katex';

const here = path.dirname(fileURLToPath(import.meta.url));
const args = Object.fromEntries(
  process.argv.slice(2).reduce((acc, a, i, all) => (a.startsWith('--') ? [...acc, [a.slice(2), all[i + 1]]] : acc), [])
);
const SRC = path.resolve(args.src ?? path.join(os.homedir(), 'Documents/AI Research/Ilya Sutskever Reading List'));
const OUT = path.resolve(args.out ?? path.join(here, '..', 'read'));
const DATA = path.join(OUT, 'data');
const ITERATIONS = 600000;

// ---------- password and keys ----------

async function readPassword(confirm) {
  if (process.env.ATLAS_READER_PASSWORD) return process.env.ATLAS_READER_PASSWORD;
  const file = path.join(os.homedir(), '.config/atlas-reader/password');
  if (fs.existsSync(file)) return fs.readFileSync(file, 'utf8').replace(/\r?\n$/, '');
  if (!process.stdin.isTTY) throw new Error('No password: set ATLAS_READER_PASSWORD or create ~/.config/atlas-reader/password');
  // Raw mode, so nothing is echoed while the password is typed.
  const ask = (question) =>
    new Promise((resolve) => {
      const stdin = process.stdin;
      let typed = '';
      const finish = () => {
        stdin.removeListener('data', onData);
        stdin.setRawMode(false);
        stdin.pause();
        process.stdout.write('\n');
      };
      const onData = (chunk) => {
        for (const ch of chunk) {
          if (ch === '\r' || ch === '\n') return finish(), resolve(typed);
          if (ch === '\u0003') return finish(), process.exit(130);
          if (ch === '\u007f' || ch === '\b') typed = typed.slice(0, -1);
          else if (ch >= ' ') typed += ch;
        }
      };
      process.stdout.write(question);
      stdin.setEncoding('utf8');
      stdin.setRawMode(true);
      stdin.resume();
      stdin.on('data', onData);
    });
  const pw = await ask('Reader password: ');
  if (!pw) throw new Error('The password is empty');
  if (confirm && (await ask('Repeat password: ')) !== pw) throw new Error('Passwords do not match');
  return pw;
}

async function deriveKeys(password, salt) {
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = new Uint8Array(
    await crypto.subtle.deriveBits({ name: 'PBKDF2', hash: 'SHA-256', salt, iterations: ITERATIONS }, base, 512)
  );
  const aes = await crypto.subtle.importKey('raw', bits.slice(0, 32), 'AES-GCM', false, ['encrypt']);
  const mac = await crypto.subtle.importKey('raw', bits.slice(32), { name: 'HMAC', hash: 'SHA-256' }, false, ['sign']);
  const keyId = Buffer.from(await crypto.subtle.sign('HMAC', mac, new TextEncoder().encode('key-id'))).toString('hex').slice(0, 16);
  return { aes, mac, keyId };
}

// Output names come from an HMAC of the content, so unchanged files keep their name and are not re-encrypted.
async function writeEncrypted(keys, bytes, fixedName) {
  const name =
    fixedName ?? Buffer.from(await crypto.subtle.sign('HMAC', keys.mac, bytes)).toString('hex').slice(0, 24) + '.bin';
  const file = path.join(DATA, name);
  if (fixedName || !fs.existsSync(file)) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ct = new Uint8Array(await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, keys.aes, bytes));
    fs.writeFileSync(file, Buffer.concat([iv, ct]));
  }
  return name;
}

const gzipJson = (obj) => zlib.gzipSync(Buffer.from(JSON.stringify(obj)), { level: 9 });

// ---------- markdown to html ----------

const unescapeHtml = (s) =>
  s.replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&amp;/g, '&');

const mathErrors = [];

function renderMarkdown(file) {
  const r = spawnSync(
    'pandoc',
    [file, '--from', 'markdown+tex_math_dollars+lists_without_preceding_blankline+hard_line_breaks', '--to', 'html5', '--katex', '--wrap=none'],
    { encoding: 'utf8', maxBuffer: 64 << 20 }
  );
  if (r.status !== 0) throw new Error(`pandoc failed on ${file}\n${r.stderr}`);
  return r.stdout.replace(/<span class="math (inline|display)">([\s\S]*?)<\/span>/g, (_, kind, tex) => {
    const src = unescapeHtml(tex).trim();
    const opts = { displayMode: kind === 'display', output: 'html', strict: 'ignore' };
    try {
      return katex.renderToString(src, { ...opts, throwOnError: true });
    } catch (e) {
      mathErrors.push(`${path.basename(file)}: ${e.message}`);
      return katex.renderToString(src, { ...opts, throwOnError: false });
    }
  });
}

const stripTags = (html) => unescapeHtml(html.replace(/<[^>]+>/g, '')).replace(/\s+/g, ' ').trim();

// Plain-text names a term can be found under: "BPE (byte pair encoding)" gives "BPE" and "byte pair encoding".
// Terms that are only symbols get none and are found by their definition text instead.
function termAliases(mdTerm) {
  const plain = mdTerm.replace(/\$[^$]*\$/g, ' ').replace(/\*\*/g, '').trim();
  const out = new Set();
  for (const part of plain.split(/,\s+|\s+\/\s+|\s*[()]\s*/)) {
    const a = part.replace(/\s+/g, ' ').replace(/^[\s:;-]+|[\s:;-]+$/g, '');
    if (a.length >= 3 || (a.length === 2 && /^[A-Z][A-Z0-9]$/.test(a))) out.add(a);
  }
  return [...out];
}

function extractTerms(md, html, docId) {
  const mdSection = md.split(/^## Terms\s*$/m)[1] ?? '';
  const mdTerms = [...mdSection.matchAll(/^- \*\*(.+?):\*\*/gm)].map((m) => m[1]);
  const htmlSection = html.split(/<h2 id="terms">Terms<\/h2>/)[1] ?? '';
  const items = [...htmlSection.matchAll(/<li>([\s\S]*?)<\/li>/g)].map((m) => m[1]);
  return items.map((li, i) => {
    const m = li.match(/^\s*<strong>([\s\S]*?)<\/strong>\s*([\s\S]*)$/);
    const termHtml = (m ? m[1] : '').replace(/:\s*$/, '');
    return {
      term: termHtml,
      text: stripTags(termHtml),
      aliases: termAliases(mdTerms[i] ?? stripTags(termHtml)),
      def: m ? m[2].trim() : li,
      doc: docId,
    };
  });
}

function readParts(readme) {
  const parts = [];
  let current = null;
  for (const line of readme.split('\n')) {
    const h = line.match(/^### (.+)$/);
    if (h) {
      const [label, ...rest] = h[1].split('. ');
      current = { label, name: rest.join('. '), ids: [] };
      parts.push(current);
      continue;
    }
    const row = line.match(/^\| (\d{2}) \|/);
    if (row && current) current.ids.push(row[1]);
  }
  return parts.filter((p) => p.ids.length);
}

// ---------- build ----------

async function main() {
  fs.mkdirSync(DATA, { recursive: true });
  const configFile = path.join(OUT, 'config.json');
  const config = fs.existsSync(configFile) ? JSON.parse(fs.readFileSync(configFile, 'utf8')) : null;
  const salt = config ? Buffer.from(config.salt, 'base64') : crypto.getRandomValues(new Uint8Array(16));

  const keys = await deriveKeys(await readPassword(!config), salt);
  if (config && config.keyId !== keys.keyId) {
    console.log('Password differs from the last build: all files are encrypted again.');
    for (const f of fs.readdirSync(DATA)) fs.unlinkSync(path.join(DATA, f));
  }

  const files = fs.readdirSync(SRC);
  const readme = fs.readFileSync(path.join(SRC, 'README.md'), 'utf8');
  const parts = readParts(readme);
  const used = new Set(['manifest.bin']);
  const items = [];
  const glossary = [];

  for (const mdName of files.filter((f) => /^\d{2} - .+ - Explained\.md$/.test(f)).sort()) {
    const id = mdName.slice(0, 2);
    const title = mdName.slice(5, -' - Explained.md'.length);
    const md = fs.readFileSync(path.join(SRC, mdName), 'utf8');
    const html = renderMarkdown(path.join(SRC, mdName));
    const terms = extractTerms(md, html, id);
    glossary.push(...terms);

    const doc = await writeEncrypted(keys, gzipJson({ html }));
    used.add(doc);

    const pdfName = files.find((f) => f.startsWith(`${id} - `) && f.endsWith('.pdf'));
    let pdf = null;
    if (pdfName) {
      const bytes = fs.readFileSync(path.join(SRC, pdfName));
      const file = await writeEncrypted(keys, bytes);
      used.add(file);
      pdf = { file, name: pdfName, size: bytes.length };
    }
    const byline = pdfName ? (pdfName.match(/\(([^()]*(?:\([^()]*\)[^()]*)*)\)\.pdf$/) ?? [])[1] ?? '' : '';
    items.push({ id, title, byline, doc, pdf, terms: terms.length, part: parts.find((p) => p.ids.includes(id))?.label ?? '' });
    process.stdout.write(`  ${id} ${title}${pdf ? '' : '  (no PDF)'}\n`);
  }

  const about = await writeEncrypted(keys, gzipJson({ html: renderMarkdown(path.join(SRC, 'README.md')) }));
  used.add(about);

  const manifest = { built: new Date().toISOString(), parts, items, about, glossary };
  await writeEncrypted(keys, gzipJson(manifest), 'manifest.bin');

  for (const f of fs.readdirSync(DATA)) if (!used.has(f)) fs.unlinkSync(path.join(DATA, f));

  for (const f of fs.readdirSync(path.join(here, 'web'))) fs.copyFileSync(path.join(here, 'web', f), path.join(OUT, f));
  const katexDist = path.join(here, 'node_modules/katex/dist');
  fs.rmSync(path.join(OUT, 'katex'), { recursive: true, force: true });
  fs.mkdirSync(path.join(OUT, 'katex/fonts'), { recursive: true });
  fs.copyFileSync(path.join(katexDist, 'katex.min.css'), path.join(OUT, 'katex/katex.min.css'));
  for (const f of fs.readdirSync(path.join(katexDist, 'fonts')).filter((f) => f.endsWith('.woff2')))
    fs.copyFileSync(path.join(katexDist, 'fonts', f), path.join(OUT, 'katex/fonts', f));
  fs.writeFileSync(
    configFile,
    JSON.stringify({ v: 1, salt: Buffer.from(salt).toString('base64'), iterations: ITERATIONS, keyId: keys.keyId }, null, 2) + '\n'
  );

  console.log(`\n${items.length} explainers, ${items.filter((i) => i.pdf).length} PDFs, ${glossary.length} glossary terms.`);
  if (mathErrors.length) {
    console.log(`\n${mathErrors.length} formulas did not typeset cleanly:`);
    for (const e of mathErrors) console.log('  ' + e);
  }
  console.log(`Output: ${OUT}`);
}

main().catch((e) => {
  console.error(e.message);
  process.exit(1);
});
