// Atlas Reader: decrypts the reading list built by _reader/build.mjs and presents it.

const PDFJS = 'https://cdnjs.cloudflare.com/ajax/libs/pdf.js/4.10.38/';

const FONTS = {
  spectral: { label: 'Spectral', css: '"Spectral", Georgia, serif', gf: 'Spectral:ital,wght@0,400;0,600;1,400' },
  literata: { label: 'Literata', css: '"Literata", Georgia, serif', gf: 'Literata:ital,opsz,wght@0,7..72,400;0,7..72,600;1,7..72,400' },
  sourceserif: { label: 'Source Serif', css: '"Source Serif 4", Georgia, serif', gf: 'Source+Serif+4:ital,opsz,wght@0,8..60,400;0,8..60,600;1,8..60,400' },
  atkinson: { label: 'Atkinson Hyperlegible', css: '"Atkinson Hyperlegible", system-ui, sans-serif', gf: 'Atkinson+Hyperlegible:ital,wght@0,400;0,700;1,400' },
  inter: { label: 'Inter', css: '"Inter", system-ui, sans-serif', gf: null },
  system: { label: 'System', css: 'system-ui, -apple-system, "Segoe UI", Roboto, sans-serif', gf: null },
};
const THEMES = [
  ['auto', 'Auto', 'linear-gradient(135deg, #f5efe4 50%, #1a1612 50%)'],
  ['light', 'Light', '#fdfcf9'],
  ['sepia', 'Sepia', '#f5efe4'],
  ['dark', 'Dark', '#1a1612'],
  ['black', 'Black', '#000'],
];
const WIDTHS = { narrow: '34em', medium: '40em', wide: '48em', full: '100%' };
const DEFAULTS = { theme: 'auto', font: 'spectral', size: 19, lh: 1.7, width: 'medium', justify: false, marks: true, pdfDark: false };

const ICONS = {
  back: '<path d="M15 18l-6-6 6-6"/>',
  search: '<circle cx="11" cy="11" r="7"/><path d="M20 20l-3.5-3.5"/>',
  glossary: '<path d="M4 5a2 2 0 012-2h13v16H6a2 2 0 00-2 2z"/><path d="M4 21V5"/><path d="M9 8h6M9 12h4"/>',
  settings: '<path d="M4 19l5-14h2l5 14"/><path d="M6.5 13h7"/><path d="M17 19v-6.5a2.5 2.5 0 015 0V19M17 15.5h5"/>',
  toc: '<path d="M8 6h13M8 12h13M8 18h13"/><circle cx="3.5" cy="6" r="1"/><circle cx="3.5" cy="12" r="1"/><circle cx="3.5" cy="18" r="1"/>',
  paper: '<path d="M14 3H6a2 2 0 00-2 2v14a2 2 0 002 2h12a2 2 0 002-2V9z"/><path d="M14 3v6h6M8 13h8M8 17h5"/>',
  explainer: '<path d="M2 4h7a3 3 0 013 3v13a2 2 0 00-2-2H2z"/><path d="M22 4h-7a3 3 0 00-3 3v13a2 2 0 012-2h8z"/>',
  close: '<path d="M6 6l12 12M18 6L6 18"/>',
  download: '<path d="M12 3v12M7 10l5 5 5-5"/><path d="M4 20h16"/>',
  zoomIn: '<circle cx="11" cy="11" r="7"/><path d="M20 20l-3.5-3.5M8 11h6M11 8v6"/>',
  zoomOut: '<circle cx="11" cy="11" r="7"/><path d="M20 20l-3.5-3.5M8 11h6"/>',
};
const icon = (name) =>
  `<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">${ICONS[name]}</svg>`;

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);
const htmlText = (html) => new DOMParser().parseFromString(html, 'text/html').body.textContent.replace(/\s+/g, ' ').trim();
const reEsc = (s) => s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');

const store = {
  get(key, fallback, area = localStorage) {
    try {
      const v = area.getItem(key);
      return v == null ? fallback : JSON.parse(v);
    } catch {
      return fallback;
    }
  },
  set(key, value, area = localStorage) {
    try {
      area.setItem(key, JSON.stringify(value));
    } catch {}
  },
  remove(key) {
    try {
      localStorage.removeItem(key);
      sessionStorage.removeItem(key);
    } catch {}
  },
};

const view = $('#view');
const sheet = $('#sheet');
const scrim = $('#scrim');
const chip = $('#chip');

let settings = { ...DEFAULTS, ...store.get('ar.settings', {}) };
let key = null;
let manifest = null;
let byId = {};
const docCache = new Map();
let routeToken = 0;
let cleanup = [];

// ---------- crypto ----------

const b64 = {
  decode: (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0)),
  encode: (bytes) => btoa(String.fromCharCode(...bytes)),
};

async function deriveRawKey(password, config) {
  const base = await crypto.subtle.importKey('raw', new TextEncoder().encode(password), 'PBKDF2', false, ['deriveBits']);
  const bits = await crypto.subtle.deriveBits(
    { name: 'PBKDF2', hash: 'SHA-256', salt: b64.decode(config.salt), iterations: config.iterations },
    base,
    512
  );
  return new Uint8Array(bits).slice(0, 32);
}

const importKey = (raw) => crypto.subtle.importKey('raw', raw, 'AES-GCM', false, ['decrypt']);

async function fetchBytes(name, onProgress) {
  const res = await fetch(`data/${name}`, { cache: name === 'manifest.bin' ? 'no-cache' : 'default' });
  if (!res.ok) throw new Error(`Could not load ${name}`);
  if (!onProgress || !res.body) return new Uint8Array(await res.arrayBuffer());
  const total = Number(res.headers.get('content-length')) || 0;
  const reader = res.body.getReader();
  const chunks = [];
  let loaded = 0;
  for (;;) {
    const { done, value } = await reader.read();
    if (done) break;
    chunks.push(value);
    loaded += value.length;
    onProgress(loaded, total);
  }
  const out = new Uint8Array(loaded);
  let at = 0;
  for (const c of chunks) {
    out.set(c, at);
    at += c.length;
  }
  return out;
}

async function decrypt(bytes, k = key) {
  return new Uint8Array(await crypto.subtle.decrypt({ name: 'AES-GCM', iv: bytes.slice(0, 12) }, k, bytes.slice(12)));
}

async function gunzipJson(bytes) {
  const stream = new Blob([bytes]).stream().pipeThrough(new DecompressionStream('gzip'));
  return JSON.parse(await new Response(stream).text());
}

async function loadDoc(name) {
  if (!docCache.has(name)) docCache.set(name, fetchBytes(name).then(decrypt).then(gunzipJson));
  try {
    return await docCache.get(name);
  } catch (e) {
    docCache.delete(name);
    throw e;
  }
}

// ---------- settings ----------

const loadedFonts = new Set();
function loadFont(id) {
  const f = FONTS[id];
  if (!f?.gf || loadedFonts.has(id)) return;
  loadedFonts.add(id);
  const link = document.createElement('link');
  link.rel = 'stylesheet';
  link.href = `https://fonts.googleapis.com/css2?family=${f.gf}&display=swap`;
  document.head.append(link);
}

const darkQuery = matchMedia('(prefers-color-scheme: dark)');
darkQuery.addEventListener('change', () => settings.theme === 'auto' && applySettings());

function applySettings() {
  const root = document.documentElement;
  const theme = settings.theme === 'auto' ? (darkQuery.matches ? 'dark' : 'sepia') : settings.theme;
  root.dataset.theme = theme;
  root.dataset.justify = settings.justify;
  root.dataset.marks = settings.marks;
  root.dataset.pdfdark = settings.pdfDark;
  root.style.setProperty('--read-font', FONTS[settings.font]?.css ?? FONTS.spectral.css);
  root.style.setProperty('--read-size', `${settings.size}px`);
  root.style.setProperty('--read-lh', settings.lh);
  root.style.setProperty('--read-width', WIDTHS[settings.width] ?? WIDTHS.medium);
  loadFont(settings.font);
  $('meta[name="theme-color"]').content = getComputedStyle(root).getPropertyValue('--bg').trim();
}

function updateSetting(name, value) {
  const ratio = scrollRatio();
  settings = { ...settings, [name]: value };
  store.set('ar.settings', settings);
  applySettings();
  if (view.dataset.view === 'doc') requestAnimationFrame(() => scrollToRatio(ratio));
}

// ---------- reading progress ----------

const progress = store.get('ar.progress', {});
const scrollRatio = () => {
  const max = document.documentElement.scrollHeight - innerHeight;
  return max > 0 ? Math.min(1, Math.max(0, scrollY / max)) : 0;
};
const scrollToRatio = (r) => scrollTo(0, r * (document.documentElement.scrollHeight - innerHeight));

function setBarProgress(r) {
  $('.bar-progress i').style.width = `${(r * 100).toFixed(1)}%`;
}

// ---------- shell ----------

function setBar({ back = null, title = '', actions = [] }) {
  $('.bar-left').innerHTML = back
    ? `<a class="icon-btn" href="${back}" aria-label="Back">${icon('back')}</a>`
    : '';
  $('.bar-title').innerHTML = title || '<span class="brand">Atlas Reader</span>';
  $('.bar-right').innerHTML = actions
    .map(([action, label, iconName, href]) =>
      href
        ? `<a class="icon-btn" href="${href}" aria-label="${label}" title="${label}">${icon(iconName)}</a>`
        : `<button class="icon-btn" type="button" data-action="${action}" aria-label="${label}" title="${label}">${icon(iconName)}</button>`
    )
    .join('');
  setBarProgress(0);
}

const commonActions = [
  ['search', 'Search', 'search', '#/search'],
  ['glossary', 'Glossary', 'glossary', '#/glossary'],
  ['settings', 'Reading settings', 'settings'],
];

function openSheet(html, onOpen) {
  sheet.innerHTML = html;
  sheet.hidden = false;
  scrim.hidden = false;
  hideChip();
  onOpen?.(sheet);
}

function closeSheet() {
  sheet.hidden = true;
  scrim.hidden = true;
  sheet.innerHTML = '';
}

const sheetHead = (title) =>
  `<div class="sheet-head"><h2>${title}</h2><button class="icon-btn" type="button" data-action="close" aria-label="Close">${icon('close')}</button></div>`;

const loading = (text) => `<div class="center-msg"><div class="spinner"></div>${esc(text)}</div>`;

// ---------- password gate ----------

async function getConfig() {
  const res = await fetch('config.json', { cache: 'no-cache' });
  if (!res.ok) throw new Error('The reader has not been built yet.');
  return res.json();
}

async function unlockWith(raw) {
  const k = await importKey(raw);
  const m = await gunzipJson(await decrypt(await fetchBytes('manifest.bin'), k));
  key = k;
  manifest = m;
  byId = Object.fromEntries(m.items.map((it, i) => [it.id, { ...it, index: i }]));
  prepareGlossary();
}

function showGate(config, message = '') {
  setBar({});
  view.dataset.view = 'gate';
  view.innerHTML = `
    <div class="gate">
      <h1>Atlas Reader</h1>
      <p>Enter the password to open your reading list.</p>
      <form>
        <input class="field" type="password" name="password" autocomplete="current-password" placeholder="Password" required autofocus>
        <label class="check"><input type="checkbox" name="remember" checked> Remember this device</label>
        <button class="btn primary" type="submit">Open</button>
        <p class="error" role="alert">${esc(message)}</p>
      </form>
    </div>`;
  const form = $('form', view);
  form.addEventListener('submit', async (e) => {
    e.preventDefault();
    const button = $('button', form);
    button.disabled = true;
    button.textContent = 'Opening…';
    try {
      const raw = await deriveRawKey(form.password.value, config);
      await unlockWith(raw);
      const area = form.remember.checked ? localStorage : sessionStorage;
      store.set('ar.key', b64.encode(raw), area);
      route();
    } catch {
      button.disabled = false;
      button.textContent = 'Open';
      $('.error', form).textContent = 'Wrong password.';
      form.password.select();
    }
  });
}

function lock() {
  store.remove('ar.key');
  location.hash = '';
  location.reload();
}

// ---------- library ----------

function itemProgress(id) {
  return progress[id]?.max ?? 0;
}

function showLibrary() {
  setBar({ actions: commonActions });
  view.dataset.view = 'library';
  const last = store.get('ar.last', null);
  const lastItem = last && byId[last];
  const row = (it) => {
    const p = itemProgress(it.id);
    return `
      <li class="item">
        <span class="num">${it.id}</span>
        <div>
          <a class="title" href="#/read/${it.id}">${esc(it.title)}</a>
          <span class="by">${esc(it.byline)}</span>
        </div>
        ${it.pdf ? `<a class="btn paper-link" href="#/paper/${it.id}" aria-label="Paper for ${esc(it.title)}">Paper</a>` : '<span></span>'}
        ${p > 0.97 ? '<span class="done-tag" style="grid-column:2">Read</span>' : p > 0.01 ? `<div class="meter"><i style="width:${(p * 100).toFixed(0)}%"></i></div>` : ''}
      </li>`;
  };
  view.innerHTML = `
    <div class="page">
      <div class="lib-head">
        <h1>Sutskever reading list</h1>
        <p>${manifest.items.length} explainers, each with its paper.</p>
      </div>
      <div class="lib-links">
        <a class="btn" href="#/about">About the list</a>
        <a class="btn" href="#/glossary">Glossary</a>
        <a class="btn" href="#/search">Search</a>
      </div>
      ${
        lastItem
          ? `<a class="continue" href="#/read/${lastItem.id}">
              <small>Continue reading</small>
              <strong>${lastItem.id}. ${esc(lastItem.title)}</strong>
              <div class="meter"><i style="width:${(itemProgress(lastItem.id) * 100).toFixed(0)}%"></i></div>
            </a>`
          : ''
      }
      ${manifest.parts
        .map(
          (part) => `
        <section class="part">
          <h2>${esc(part.label)}</h2>
          <h3>${esc(part.name)}</h3>
          <ul class="items">${part.ids.map((id) => byId[id]).filter(Boolean).map(row).join('')}</ul>
        </section>`
        )
        .join('')}
      <p class="foot"><a href="../">Back to the Atlas</a></p>
    </div>`;
  scrollTo(0, 0);
}

// ---------- reading ----------

let glossaryNames = [];

function prepareGlossary() {
  const stem = (w) => (w.length > 3 && w.endsWith('s') && !w.endsWith('ss') ? w.slice(0, -1) : w);
  const norm = (s) =>
    s.toLowerCase().normalize('NFKD').replace(/[̀-ͯ]/g, '').replace(/[^\p{L}\p{N}]+/gu, ' ').trim().split(' ').map(stem).join(' ');
  glossaryNorm = norm;
  glossaryNames = manifest.glossary.map((g) => ({
    names: [...new Set([g.text, ...g.aliases].map(norm).filter(Boolean))],
    def: null,
  }));
}
let glossaryNorm = (s) => s;

function glossaryMatches(query) {
  const q = glossaryNorm(query);
  if (!q) return [];
  const scored = [];
  manifest.glossary.forEach((g, i) => {
    const entry = glossaryNames[i];
    let score = 0;
    if (entry.names.includes(q)) score = 3;
    else if (entry.names.some((n) => n.length >= 3 && (n.includes(q) || q.includes(n)))) score = 2;
    else if (q.length >= 4) {
      entry.def ??= glossaryNorm(htmlText(g.def));
      if (entry.def.includes(q)) score = 1;
    }
    if (score) scored.push([score, i]);
  });
  return scored.sort((a, b) => b[0] - a[0] || a[1] - b[1]).slice(0, 12).map(([, i]) => i);
}

function markTerms(root, id) {
  const aliasToIndex = new Map();
  manifest.glossary.forEach((g, i) => {
    if (g.doc !== id) return;
    for (const a of g.aliases) if (!aliasToIndex.has(a.toLowerCase())) aliasToIndex.set(a.toLowerCase(), i);
  });
  if (!aliasToIndex.size) return;
  const alternatives = [...aliasToIndex.keys()].sort((a, b) => b.length - a.length).map(reEsc);
  const re = new RegExp(`(?<![\\p{L}\\p{N}_-])(${alternatives.join('|')})(?![\\p{L}\\p{N}_-])`, 'giu');
  const termsHeading = $('#terms', root);
  const walker = document.createTreeWalker(root, NodeFilter.SHOW_TEXT, {
    acceptNode(node) {
      const parent = node.parentElement;
      if (!parent || parent.closest('h1, h2, h3, h4, .katex, code, pre, a, table')) return NodeFilter.FILTER_REJECT;
      if (termsHeading && termsHeading.compareDocumentPosition(node) & Node.DOCUMENT_POSITION_FOLLOWING) return NodeFilter.FILTER_REJECT;
      return NodeFilter.FILTER_ACCEPT;
    },
  });
  const nodes = [];
  while (walker.nextNode()) nodes.push(walker.currentNode);
  const marked = new Set();
  for (const node of nodes) {
    const text = node.data;
    let frag = null;
    let last = 0;
    re.lastIndex = 0;
    for (let m; (m = re.exec(text)); ) {
      const gi = aliasToIndex.get(m[1].toLowerCase());
      if (marked.has(gi)) continue;
      marked.add(gi);
      frag ??= document.createDocumentFragment();
      frag.append(text.slice(last, m.index));
      const span = document.createElement('span');
      span.className = 'gl';
      span.dataset.g = gi;
      span.tabIndex = 0;
      span.setAttribute('role', 'button');
      span.textContent = m[1];
      frag.append(span);
      last = m.index + m[1].length;
    }
    if (frag) {
      frag.append(text.slice(last));
      node.replaceWith(frag);
    }
  }
}

async function showDoc(id, anchor, token) {
  const item = byId[id];
  if (!item) return showLibrary();
  setBar({
    back: '#/',
    title: `${item.id}. ${esc(item.title)}`,
    actions: [
      ['toc', 'Contents', 'toc'],
      ...(item.pdf ? [['paper', 'Paper', 'paper', `#/paper/${id}`]] : []),
      ...commonActions,
    ],
  });
  view.dataset.view = 'loading';
  view.innerHTML = loading('Opening…');
  const { html } = await loadDoc(item.doc);
  if (token !== routeToken) return;

  const prev = manifest.items[item.index - 1];
  const next = manifest.items[item.index + 1];
  const part = manifest.parts.find((p) => p.label === item.part);
  view.dataset.view = 'doc';
  view.innerHTML = `
    <div class="doc-wrap">
      <div class="doc-meta">${esc(part ? `${part.label}. ${part.name}` : '')}</div>
      <article class="doc" lang="en">${html}</article>
      <div class="doc-end">
        ${item.pdf ? `<a class="btn primary paper-cta" href="#/paper/${id}">${icon('paper')} Read the paper</a>` : ''}
        <nav class="pager">
          ${prev ? `<a class="prev" href="#/read/${prev.id}"><small>Previous</small><span>${prev.id}. ${esc(prev.title)}</span></a>` : ''}
          ${next ? `<a class="next" href="#/read/${next.id}"><small>Next</small><span>${next.id}. ${esc(next.title)}</span></a>` : ''}
        </nav>
      </div>
    </div>`;
  const article = $('.doc', view);
  markTerms(article, id);
  store.set('ar.last', id);

  const restore = () => {
    const target = anchor && document.getElementById(anchor);
    if (target) {
      target.scrollIntoView();
      target.classList.add('flash');
    } else {
      scrollToRatio(progress[id]?.p ?? 0);
    }
  };
  restore();
  let userScrolled = false;
  const markScrolled = () => (userScrolled = true);
  addEventListener('wheel', markScrolled, { passive: true, once: true });
  addEventListener('touchmove', markScrolled, { passive: true, once: true });
  addEventListener('keydown', markScrolled, { once: true });
  // Web fonts change the page height, so the first restore can land in the wrong place.
  document.fonts?.ready.then(() => token === routeToken && !userScrolled && restore());

  let pending = false;
  const onScroll = () => {
    if (pending) return;
    pending = true;
    requestAnimationFrame(() => {
      pending = false;
      const r = scrollRatio();
      setBarProgress(r);
      progress[id] = { p: r, max: Math.max(progress[id]?.max ?? 0, r), t: Date.now() };
    });
  };
  const save = () => store.set('ar.progress', progress);
  const saveTimer = setInterval(save, 2000);
  addEventListener('scroll', onScroll, { passive: true });
  addEventListener('pagehide', save);
  cleanup.push(() => {
    removeEventListener('wheel', markScrolled);
    removeEventListener('touchmove', markScrolled);
    removeEventListener('keydown', markScrolled);
    removeEventListener('scroll', onScroll);
    removeEventListener('pagehide', save);
    clearInterval(saveTimer);
    save();
  });
  onScroll();
}

function showToc() {
  const headings = $$('.doc h2, .doc h3', view);
  const mid = innerHeight * 0.3;
  let current = headings.findLast?.((h) => h.getBoundingClientRect().top < mid);
  openSheet(
    `${sheetHead('Contents')}<nav class="sheet-body toc">${headings
      .map(
        (h) =>
          `<a href="#" data-target="${esc(h.id)}" class="${h.tagName.toLowerCase()}${h === current ? ' current' : ''}">${esc(h.textContent)}</a>`
      )
      .join('')}</nav>`,
    (el) => $('.current', el)?.scrollIntoView({ block: 'center' })
  );
}

// ---------- about ----------

async function showAbout(token) {
  setBar({ back: '#/', title: 'About the list', actions: commonActions });
  view.dataset.view = 'loading';
  view.innerHTML = loading('Opening…');
  const { html } = await loadDoc(manifest.about);
  if (token !== routeToken) return;
  view.dataset.view = 'about';
  view.innerHTML = `<div class="doc-wrap"><article class="doc" lang="en">${html}</article></div>`;
  scrollTo(0, 0);
}

// ---------- glossary ----------

function showGlossary() {
  setBar({ back: '#/', title: 'Glossary', actions: [['search', 'Search', 'search', '#/search'], ['settings', 'Reading settings', 'settings']] });
  view.dataset.view = 'glossary';
  const order = manifest.glossary
    .map((g, i) => i)
    .sort((a, b) => manifest.glossary[a].text.localeCompare(manifest.glossary[b].text, 'en', { sensitivity: 'base' }));
  view.innerHTML = `
    <div class="page">
      <div class="list-head">
        <h1>Glossary</h1>
        <p>${manifest.glossary.length} terms from the Terms section of every explainer.</p>
      </div>
      <div class="sticky-search"><input class="field" type="search" placeholder="Filter terms" aria-label="Filter terms"></div>
      <div class="g-list"></div>
    </div>`;
  const list = $('.g-list', view);
  const render = (filter) => {
    const q = glossaryNorm(filter);
    const ids = filter ? [...new Set([...glossaryMatches(filter), ...order.filter((i) => glossaryNames[i].names.some((n) => n.includes(q)))])] : order;
    let letter = '';
    list.innerHTML = ids.length
      ? ids
          .map((i) => {
            const g = manifest.glossary[i];
            const first = (g.text[0] || '#').toUpperCase();
            const head = !filter && /[A-Z]/.test(first) && first !== letter ? `<h2 class="letter">${(letter = first)}</h2>` : '';
            const it = byId[g.doc];
            return `${head}<div class="g-entry"><span class="term">${g.term}</span>: ${g.def}<a class="src" href="#/read/${g.doc}/terms">${it.id}. ${esc(it.title)}</a></div>`;
          })
          .join('')
      : '<p class="lk-note">No terms match.</p>';
  };
  render('');
  $('input', view).addEventListener('input', (e) => render(e.target.value.trim()));
  scrollTo(0, 0);
}

// ---------- search ----------

let searchIndex = null;
let lastQuery = '';

async function buildSearchIndex(onProgress) {
  const sections = [];
  let done = 0;
  await Promise.all(
    manifest.items.map(async (it) => {
      const { html } = await loadDoc(it.doc);
      onProgress(++done);
      const doc = new DOMParser().parseFromString(`<article>${html}</article>`, 'text/html');
      $$('.katex', doc).forEach((k) => k.replaceWith(k.textContent.replace(/\u200b/g, '')));
      let current = { id: it.id, anchor: '', title: it.title, text: '' };
      const list = [current];
      for (const el of doc.body.firstChild.children) {
        if (/^H[1-3]$/.test(el.tagName)) {
          current = { id: it.id, anchor: el.id, title: el.textContent.trim(), text: '' };
          list.push(current);
        } else {
          current.text += ' ' + el.textContent;
        }
      }
      for (const s of list) {
        s.text = s.text.replace(/\s+/g, ' ').trim();
        s.lower = s.text.toLowerCase();
        s.order = it.index ?? byId[it.id].index;
      }
      sections.push(...list.filter((s) => s.text));
    })
  );
  return sections.sort((a, b) => a.order - b.order);
}

function snippet(text, lower, words) {
  const at = Math.max(0, Math.min(...words.map((w) => lower.indexOf(w)).filter((i) => i >= 0)));
  const start = Math.max(0, at - 70);
  let s = (start > 0 ? '…' : '') + text.slice(start, at + 150) + (at + 150 < text.length ? '…' : '');
  s = esc(s);
  const re = new RegExp(`(${words.map((w) => reEsc(esc(w))).join('|')})`, 'gi');
  return s.replace(re, '<mark>$1</mark>');
}

function showSearch(token) {
  setBar({ back: '#/', title: 'Search', actions: [['glossary', 'Glossary', 'glossary', '#/glossary'], ['settings', 'Reading settings', 'settings']] });
  view.dataset.view = 'search';
  view.innerHTML = `
    <div class="page">
      <div class="sticky-search"><input class="field" type="search" placeholder="Search all explainers" aria-label="Search all explainers" value="${esc(lastQuery)}"></div>
      <div class="s-status"></div>
      <div class="s-results"></div>
    </div>`;
  const input = $('input', view);
  const status = $('.s-status', view);
  const results = $('.s-results', view);

  const run = () => {
    const q = input.value.trim();
    lastQuery = q;
    const words = q.toLowerCase().split(/\s+/).filter((w) => w.length > 1);
    if (!words.length || !searchIndex) {
      results.innerHTML = '';
      status.textContent = searchIndex ? '' : status.textContent;
      return;
    }
    const hits = searchIndex.filter((s) => words.every((w) => s.lower.includes(w) || s.title.toLowerCase().includes(w)));
    status.textContent = hits.length ? `${hits.length} sections` : 'No matches.';
    let currentDoc = '';
    results.innerHTML = hits
      .slice(0, 80)
      .map((s) => {
        const it = byId[s.id];
        const head = s.id !== currentDoc ? `<h2 class="s-doc">${(currentDoc = s.id)}. ${esc(it.title)}</h2>` : '';
        return `${head}<a class="s-hit" href="#/read/${s.id}/${encodeURIComponent(s.anchor)}"><b>${esc(s.title)}</b><span>${snippet(s.text, s.lower, words)}</span></a>`;
      })
      .join('');
  };

  let timer;
  input.addEventListener('input', () => {
    clearTimeout(timer);
    timer = setTimeout(run, 150);
  });
  input.focus();
  if (searchIndex) return run();
  status.textContent = 'Loading explainers…';
  buildSearchIndex((n) => token === routeToken && (status.textContent = `Loading explainers… ${n} of ${manifest.items.length}`)).then((idx) => {
    searchIndex = idx;
    if (token !== routeToken) return;
    status.textContent = '';
    run();
  });
}

// ---------- paper viewer ----------

let pdfjsLib = null;
async function getPdfjs() {
  if (!pdfjsLib) {
    pdfjsLib = await import(`${PDFJS}pdf.min.mjs`);
    pdfjsLib.GlobalWorkerOptions.workerSrc = `${PDFJS}pdf.worker.min.mjs`;
  }
  return pdfjsLib;
}

async function showPaper(id, token) {
  const item = byId[id];
  if (!item?.pdf) return showLibrary();
  setBar({
    back: `#/read/${id}`,
    title: `${item.id}. ${esc(item.title)}`,
    actions: [
      ['zoomOut', 'Zoom out', 'zoomOut'],
      ['zoomIn', 'Zoom in', 'zoomIn'],
      ['download', 'Download PDF', 'download'],
      ['settings', 'Reading settings', 'settings'],
    ],
  });
  view.dataset.view = 'paper';
  view.innerHTML = `
    <div class="pdf-wrap">
      <div class="pdf-status">Opening the paper<progress max="1" value="0"></progress></div>
      <div class="pdf-pages"></div>
    </div>
    <div class="pageno" hidden></div>`;
  scrollTo(0, 0);
  const bar = $('progress', view);
  const [bytes, lib] = await Promise.all([
    fetchBytes(item.pdf.file, (loaded) => (bar.value = Math.min(1, loaded / (item.pdf.size + 28)))).then(decrypt),
    getPdfjs(),
  ]);
  if (token !== routeToken) return;
  const blobUrl = URL.createObjectURL(new Blob([bytes], { type: 'application/pdf' }));
  const pdf = await lib.getDocument({ data: bytes }).promise;
  if (token !== routeToken) {
    pdf.destroy();
    return;
  }
  $('.pdf-status', view).remove();

  const first = (await pdf.getPage(1)).getViewport({ scale: 1 });
  const pages = $('.pdf-pages', view);
  const pageno = $('.pageno', view);
  let zoom = 1;
  pages.innerHTML = Array.from(
    { length: pdf.numPages },
    (_, i) => `<div class="pdf-page" data-n="${i + 1}" style="aspect-ratio:${first.width} / ${first.height}"><span class="pnum">${i + 1}</span></div>`
  ).join('');

  const render = async (div) => {
    if (div.dataset.state) return;
    div.dataset.state = 'rendering';
    try {
      const page = await pdf.getPage(Number(div.dataset.n));
      const base = page.getViewport({ scale: 1 });
      div.style.aspectRatio = `${base.width} / ${base.height}`;
      const scale = (div.clientWidth / base.width) * Math.min(devicePixelRatio || 1, 2.5);
      const viewport = page.getViewport({ scale });
      const canvas = document.createElement('canvas');
      canvas.width = Math.floor(viewport.width);
      canvas.height = Math.floor(viewport.height);
      div.task = page.render({ canvasContext: canvas.getContext('2d'), viewport });
      await div.task.promise;
      if (div.dataset.state !== 'rendering') return;
      div.replaceChildren(canvas);
      div.dataset.state = 'done';
    } catch {
      if (div.dataset.state === 'rendering') div.dataset.state = '';
    }
  };
  const clear = (div) => {
    div.task?.cancel();
    const canvas = $('canvas', div);
    if (canvas) canvas.width = canvas.height = 0;
    div.dataset.state = '';
    div.innerHTML = `<span class="pnum">${div.dataset.n}</span>`;
  };

  // Pages far from the screen give their canvas memory back.
  const observer = new IntersectionObserver(
    (entries) => entries.forEach((e) => (e.isIntersecting ? render(e.target) : clear(e.target))),
    { rootMargin: '150% 0px' }
  );
  const pageDivs = $$('.pdf-page', pages);
  pageDivs.forEach((d) => observer.observe(d));

  const updatePageNo = () => {
    const el = document.elementFromPoint(innerWidth / 2, innerHeight / 2)?.closest('.pdf-page');
    if (el) pageno.textContent = `${el.dataset.n} / ${pdf.numPages}`;
    pageno.hidden = false;
  };
  addEventListener('scroll', updatePageNo, { passive: true });
  updatePageNo();

  const setZoom = (z) => {
    const ratio = scrollRatio();
    zoom = Math.min(3, Math.max(0.5, z));
    pages.style.setProperty('--zoom', zoom);
    pageDivs.forEach((d) => {
      clear(d);
      observer.unobserve(d);
      observer.observe(d);
    });
    scrollToRatio(ratio);
  };
  let resizeTimer;
  const onResize = () => {
    clearTimeout(resizeTimer);
    resizeTimer = setTimeout(() => setZoom(zoom), 250);
  };
  addEventListener('resize', onResize);

  paperControls = {
    zoomIn: () => setZoom(zoom * 1.25),
    zoomOut: () => setZoom(zoom / 1.25),
    download: () => {
      const a = document.createElement('a');
      a.href = blobUrl;
      a.download = item.pdf.name;
      a.click();
    },
  };
  cleanup.push(() => {
    observer.disconnect();
    removeEventListener('scroll', updatePageNo);
    removeEventListener('resize', onResize);
    pdf.destroy();
    URL.revokeObjectURL(blobUrl);
    paperControls = null;
  });
}
let paperControls = null;

// ---------- settings sheet ----------

function showSettings() {
  const seg = (name, options) =>
    `<div class="seg">${options
      .map(([value, label, extra = '']) => `<button type="button" data-set="${name}" data-value="${value}" aria-pressed="${settings[name] === value}">${extra}${label}</button>`)
      .join('')}</div>`;
  openSheet(`
    ${sheetHead('Reading settings')}
    <div class="sheet-body">
      <div class="set-row"><span class="set-label">Theme</span>
        ${seg('theme', THEMES.map(([v, l, c]) => [v, l, `<span class="swatch" style="background:${c}"></span>`]))}</div>
      <div class="set-row"><span class="set-label">Font</span>
        <div class="font-list">${seg('font', Object.entries(FONTS).map(([v, f]) => [v, `<span style="font-family:${esc(f.css)}">${f.label}</span>`]))}</div></div>
      <div class="set-row"><label for="set-size">Text size</label>
        <div class="stepper"><input id="set-size" type="range" min="14" max="28" step="1" value="${settings.size}" data-range="size"><output>${settings.size}px</output></div></div>
      <div class="set-row"><label for="set-lh">Line spacing</label>
        <div class="stepper"><input id="set-lh" type="range" min="1.3" max="2.2" step="0.05" value="${settings.lh}" data-range="lh"><output>${settings.lh}</output></div></div>
      <div class="set-row"><span class="set-label">Page width</span>
        ${seg('width', [['narrow', 'Narrow'], ['medium', 'Medium'], ['wide', 'Wide'], ['full', 'Full']])}</div>
      <div class="set-row"><label class="toggle">Justify text <input type="checkbox" data-check="justify" ${settings.justify ? 'checked' : ''}></label></div>
      <div class="set-row"><label class="toggle">Underline glossary terms <input type="checkbox" data-check="marks" ${settings.marks ? 'checked' : ''}></label></div>
      <div class="set-row"><label class="toggle">Dark pages in papers <input type="checkbox" data-check="pdfDark" ${settings.pdfDark ? 'checked' : ''}></label></div>
      <div class="set-row"><button class="btn" type="button" data-action="lock">Lock this device</button></div>
    </div>`);
}

sheet.addEventListener('click', (e) => {
  const b = e.target.closest('[data-set]');
  if (!b) return;
  updateSetting(b.dataset.set, b.dataset.value);
  $$(`[data-set="${b.dataset.set}"]`, sheet).forEach((x) => x.setAttribute('aria-pressed', x === b));
});
sheet.addEventListener('input', (e) => {
  const t = e.target;
  if (t.dataset.range) {
    const v = Number(t.value);
    updateSetting(t.dataset.range, v);
    t.nextElementSibling.textContent = t.dataset.range === 'size' ? `${v}px` : v;
  }
  if (t.dataset.check) updateSetting(t.dataset.check, t.checked);
});

// ---------- lookup ----------

const lookupCache = new Map();
const cached = (k, fn) => {
  if (!lookupCache.has(k)) lookupCache.set(k, fn().catch(() => null));
  return lookupCache.get(k);
};

async function wiktionary(word) {
  for (const w of [...new Set([word.toLowerCase(), word])]) {
    const res = await fetch(`https://en.wiktionary.org/api/rest_v1/page/definition/${encodeURIComponent(w.replace(/ /g, '_'))}`);
    if (!res.ok) continue;
    const entries = ((await res.json()).en ?? [])
      .map((e) => ({ pos: e.partOfSpeech, defs: e.definitions.map((d) => htmlText(d.definition)).filter(Boolean).slice(0, 4) }))
      .filter((e) => e.defs.length);
    if (entries.length) return { word: w, entries };
  }
  return null;
}

const dictionary = (word) =>
  cached(`d:${word}`, async () => {
    const found = await wiktionary(word);
    if (found) {
      let { entries } = found;
      // "Plural of network" and "Alternative spelling of marginalization" lead to the main entry.
      const base = entries.length === 1 && entries[0].defs.length === 1 && entries[0].defs[0].match(/\b(?:spelling|form|plural|participle|tense) of ([\p{L}-]+)\.?$/iu);
      if (base) entries = [...entries, ...((await wiktionary(base[1]))?.entries ?? [])];
      return { source: 'Wiktionary', url: `https://en.wiktionary.org/wiki/${encodeURIComponent(found.word.replace(/ /g, '_'))}`, entries: entries.slice(0, 4) };
    }
    const res = await fetch(`https://api.datamuse.com/words?sp=${encodeURIComponent(word)}&md=d&max=1`);
    const [hit] = res.ok ? await res.json() : [];
    if (!hit?.defs) return null;
    const names = { n: 'noun', v: 'verb', adj: 'adjective', adv: 'adverb' };
    const groups = new Map();
    for (const d of hit.defs) {
      const [tag, text] = d.split('\t');
      const pos = names[tag] ?? tag;
      groups.set(pos, [...(groups.get(pos) ?? []), text.trim()]);
    }
    return { source: 'WordNet', url: null, entries: [...groups].map(([pos, defs]) => ({ pos, defs: defs.slice(0, 4) })) };
  });

const wikiSummary = async (title) => {
  const res = await fetch(`https://en.wikipedia.org/api/rest_v1/page/summary/${encodeURIComponent(title.replace(/ /g, '_'))}`);
  return res.ok ? res.json() : null;
};
const wikiSearch = async (q, limit) => {
  const res = await fetch(
    `https://en.wikipedia.org/w/api.php?action=opensearch&search=${encodeURIComponent(q)}&limit=${limit}&namespace=0&format=json&origin=*`
  );
  return res.ok ? (await res.json())[1] ?? [] : [];
};
const wikiFullText = async (q, limit) => {
  const res = await fetch(
    `https://en.wikipedia.org/w/api.php?action=query&list=search&srsearch=${encodeURIComponent(q)}&srlimit=${limit}&srprop=&format=json&origin=*`
  );
  return res.ok ? ((await res.json()).query?.search ?? []).map((x) => x.title) : [];
};
const GENERIC_PAGES = /^(Machine learning|Deep learning|Artificial intelligence|Neural network \(machine learning\))$|^(Outline|List|Glossary|Timeline) of /;

// For AI terms, articles found in a machine learning context are offered next to the title match.
const wikipedia = (q, aiTerm) =>
  cached(`w:${q}:${aiTerm}`, async () => {
    const [direct, related] = await Promise.all([wikiSummary(q), aiTerm ? wikiFullText(`${q} machine learning`, 6) : []]);
    let page = direct;
    if (!page || page.type === 'not_found') {
      const [best] = await wikiSearch(q, 1);
      page = best ? await wikiSummary(best) : null;
    }
    if (!page) return null;
    const choices = page.type === 'disambiguation' ? await wikiSearch(q, 8) : related.filter((t) => !GENERIC_PAGES.test(t)).slice(0, 4);
    return {
      title: page.title,
      description: page.description ?? '',
      extract: page.extract ?? '',
      thumb: page.thumbnail?.source ?? null,
      url: page.content_urls?.mobile?.page ?? page.content_urls?.desktop?.page,
      choices: choices.filter((c) => c !== page.title),
      related: page.type !== 'disambiguation',
    };
  });

function openLookup(query, { glossaryIndex = null, tab: startTab = null } = {}) {
  query = query.replace(/\s+/g, ' ').trim().slice(0, 80);
  const matches = glossaryIndex != null ? [glossaryIndex, ...glossaryMatches(query).filter((i) => i !== glossaryIndex)] : glossaryMatches(query);
  const tab = startTab ?? (matches.length ? 'glossary' : query.includes(' ') ? 'wiki' : 'dict');
  openSheet(`
    <div class="sheet-head">
      <form class="lk-form"><input class="field" name="q" value="${esc(query)}" aria-label="Look up" enterkeyhint="search"></form>
      <button class="icon-btn" type="button" data-action="close" aria-label="Close">${icon('close')}</button>
    </div>
    <div class="tabs" role="tablist">
      <button type="button" role="tab" data-tab="glossary">AI glossary <span class="count">${matches.length}</span></button>
      <button type="button" role="tab" data-tab="dict">Dictionary</button>
      <button type="button" role="tab" data-tab="wiki">Wikipedia</button>
    </div>
    <div class="sheet-body lk-body"></div>`);
  $('.lk-form', sheet).addEventListener('submit', (e) => {
    e.preventDefault();
    const q = e.target.q.value.trim();
    if (q) openLookup(q);
  });
  const body = $('.lk-body', sheet);

  const show = async (name) => {
    $$('[data-tab]', sheet).forEach((b) => b.setAttribute('aria-selected', b.dataset.tab === name));
    body.dataset.tab = name;
    if (name === 'glossary') {
      body.innerHTML = matches.length
        ? matches
            .map((i) => {
              const g = manifest.glossary[i];
              const it = byId[g.doc];
              return `<div class="lk-entry"><span class="term">${g.term}</span>: ${g.def}<a class="src" href="#/read/${g.doc}/terms">${it.id}. ${esc(it.title)}</a></div>`;
            })
            .join('')
        : '<p class="lk-note">No explainer defines this term.</p>';
      return;
    }
    body.innerHTML = loading('Looking up…');
    if (name === 'dict') {
      const d = await dictionary(query);
      if (body.dataset.tab !== 'dict') return;
      body.innerHTML = d
        ? d.entries.map((e) => `<div class="lk-pos">${esc(e.pos)}</div><ol class="lk-defs">${e.defs.map((x) => `<li>${esc(x)}</li>`).join('')}</ol>`).join('') +
          (d.url ? `<a class="lk-more" href="${d.url}" target="_blank" rel="noopener">More in ${d.source}</a>` : `<p class="lk-note">Source: ${d.source}</p>`)
        : '<p class="lk-note">No dictionary entry found.</p>';
    } else {
      const w = await wikipedia(query, matches.length > 0);
      if (body.dataset.tab !== 'wiki') return;
      body.innerHTML = w
        ? `<div class="lk-wiki">${w.thumb ? `<img src="${esc(w.thumb)}" alt="">` : ''}<h3>${esc(w.title)}</h3><div class="desc">${esc(w.description)}</div>
           <p>${esc(w.extract)}</p>
           ${w.choices.length ? `<div class="lk-sub">${w.related ? 'Related articles' : 'Other meanings'}</div><div class="lk-choices">${w.choices.map((c) => `<button type="button" data-lookup="${esc(c)}">${esc(c)}</button>`).join('')}</div>` : ''}
           ${w.url ? `<a class="lk-more" href="${esc(w.url)}" target="_blank" rel="noopener">Read on Wikipedia</a>` : ''}</div>`
        : '<p class="lk-note">No Wikipedia article found.</p>';
    }
  };
  sheet.onclick = (e) => {
    const t = e.target.closest('[data-tab]');
    if (t) show(t.dataset.tab);
    const l = e.target.closest('[data-lookup]');
    if (l) openLookup(l.dataset.lookup, { tab: 'wiki' });
  };
  show(tab);
}

// Selection chip: select a word or phrase in a document to look it up.
function hideChip() {
  chip.hidden = true;
}
function placeChip() {
  const sel = getSelection();
  const text = sel?.toString().trim() ?? '';
  if (!sel || sel.isCollapsed || !text || text.length > 80 || text.split(/\s+/).length > 6) return hideChip();
  const node = sel.anchorNode?.nodeType === 3 ? sel.anchorNode.parentElement : sel.anchorNode;
  if (!node?.closest?.('.doc, .g-entry')) return hideChip();
  const rect = sel.getRangeAt(0).getBoundingClientRect();
  if (!rect.width && !rect.height) return hideChip();
  const touch = matchMedia('(pointer: coarse)').matches;
  const top = touch || rect.top < 70 ? rect.bottom + 12 : rect.top - 48;
  chip.style.top = `${Math.min(innerHeight - 50, Math.max(60, top))}px`;
  chip.style.left = `${Math.min(innerWidth - 60, Math.max(60, rect.left + rect.width / 2))}px`;
  chip.dataset.text = text;
  chip.hidden = false;
}
let chipTimer;
document.addEventListener('selectionchange', () => {
  clearTimeout(chipTimer);
  chipTimer = setTimeout(placeChip, 220);
});
addEventListener('scroll', () => !chip.hidden && placeChip(), { passive: true });
// pointerdown, because on touch screens a tap can clear the selection before a click arrives.
chip.addEventListener('pointerdown', (e) => {
  e.preventDefault();
  const text = chip.dataset.text;
  hideChip();
  getSelection()?.removeAllRanges();
  openLookup(text);
});

// ---------- global events ----------

document.addEventListener('click', (e) => {
  const action = e.target.closest('[data-action]')?.dataset.action;
  if (action === 'close') return closeSheet();
  if (action === 'settings') return showSettings();
  if (action === 'toc') return showToc();
  if (action === 'lock') return lock();
  if (action && paperControls?.[action]) return paperControls[action]();

  const target = e.target.closest('[data-target]');
  if (target) {
    e.preventDefault();
    closeSheet();
    document.getElementById(target.dataset.target)?.scrollIntoView();
    return;
  }
  const term = e.target.closest('.gl');
  if (term && settings.marks) {
    openLookup(term.textContent, { glossaryIndex: Number(term.dataset.g) });
    return;
  }
  if (e.target.closest('#sheet a[href^="#/"]')) closeSheet();
});
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape' && !sheet.hidden) closeSheet();
  if (e.key === 'Enter' && e.target.classList?.contains('gl')) e.target.click();
});
scrim.addEventListener('click', closeSheet);

// ---------- routing ----------

async function route() {
  const token = ++routeToken;
  cleanup.splice(0).forEach((fn) => fn());
  closeSheet();
  hideChip();
  if (!manifest) return;
  const [, name = '', a, b] = location.hash.split('/');
  const anchor = b ? decodeURIComponent(b) : null;
  try {
    if (name === 'read') await showDoc(a, anchor, token);
    else if (name === 'paper') await showPaper(a, token);
    else if (name === 'glossary') showGlossary();
    else if (name === 'search') showSearch(token);
    else if (name === 'about') await showAbout(token);
    else showLibrary();
  } catch (e) {
    if (token !== routeToken) return;
    view.innerHTML = `<div class="center-msg">This page could not be opened. Check the connection and try again.</div>`;
    console.error(e);
  }
}
addEventListener('hashchange', route);

async function start() {
  applySettings();
  if (!window.crypto?.subtle) {
    view.innerHTML = '<div class="center-msg">Open this page over https.</div>';
    return;
  }
  view.innerHTML = loading('Opening…');
  let config;
  try {
    config = await getConfig();
  } catch (e) {
    view.innerHTML = `<div class="center-msg">${esc(e.message)}</div>`;
    return;
  }
  const saved = store.get('ar.key', null) ?? store.get('ar.key', null, sessionStorage);
  if (saved) {
    try {
      await unlockWith(b64.decode(saved));
      return route();
    } catch (e) {
      if (e.name !== 'OperationError') {
        view.innerHTML = '<div class="center-msg">The reader could not load. Check the connection and try again.</div>';
        return;
      }
      store.remove('ar.key');
    }
  }
  showGate(config);
}

start();
