/* global cytoscape */
const $ = (sel) => document.querySelector(sel);
const esc = (s) => String(s).replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[c]);

let META = { entityTypes: {}, transforms: [] };
const hiddenTypes = new Set();
let cy;

// ---------------------------------------------------------------- API
function token() {
  try { return localStorage.getItem('tg_token') || ''; } catch { return ''; }
}
async function api(path, body) {
  const res = await fetch(path, {
    method: body ? 'POST' : 'GET',
    headers: { 'content-type': 'application/json', 'x-access-token': token() },
    body: body ? JSON.stringify(body) : undefined
  });
  const data = await res.json().catch(() => ({ error: `HTTP ${res.status}` }));
  if (res.status === 401 && data.auth) {
    const t = prompt('This Tracegraph server needs an access token (APP_PASSWORD):');
    if (t) {
      try { localStorage.setItem('tg_token', t); } catch { /* storage unavailable */ }
      return api(path, body);
    }
  }
  if (!res.ok) throw new Error(data.error || `HTTP ${res.status}`);
  return data;
}

// Small concurrency limiter so "run all" on many nodes doesn't stampede upstream APIs.
let active = 0;
const queue = [];
function limit(fn) {
  return new Promise((resolve, reject) => {
    queue.push({ fn, resolve, reject });
    pump();
  });
}
function pump() {
  while (active < 4 && queue.length) {
    const { fn, resolve, reject } = queue.shift();
    active++;
    updateStatus();
    fn().then(resolve, reject).finally(() => { active--; updateStatus(); pump(); });
  }
}
function updateStatus() {
  const pending = active + queue.length;
  const n = cy ? cy.nodes().length : 0;
  const e = cy ? cy.edges().length : 0;
  $('#status').textContent = `${n} entities · ${e} links${pending ? ` · running ${pending} transform${pending > 1 ? 's' : ''}…` : ''}`;
}

// ---------------------------------------------------------------- Graph styling
function glyphSvg(glyph, color) {
  const fs = glyph.length > 2 ? 22 : glyph.length > 1 ? 28 : 34;
  const svg = `<svg xmlns="http://www.w3.org/2000/svg" width="80" height="80"><circle cx="40" cy="40" r="38" fill="${color}"/><text x="40" y="41" font-family="Arial,Helvetica,sans-serif" font-weight="700" font-size="${fs}" fill="#0f1218" text-anchor="middle" dominant-baseline="central">${esc(glyph)}</text></svg>`;
  return `data:image/svg+xml;utf8,${encodeURIComponent(svg)}`;
}

function buildStyle() {
  const base = [
    { selector: 'node', style: {
      width: 38, height: 38, 'background-opacity': 0, 'background-fit': 'contain', 'background-clip': 'none',
      label: 'data(label)', color: '#dfe5ee', 'font-size': 10, 'text-valign': 'bottom', 'text-margin-y': 5,
      'text-wrap': 'ellipsis', 'text-max-width': 170, 'text-outline-color': '#0f1218', 'text-outline-width': 2,
      'border-width': 0, 'underlay-shape': 'ellipse'
    } },
    { selector: 'node:selected', style: { 'border-width': 3, 'border-color': '#ffffff', 'border-opacity': 0.9, 'underlay-color': '#4f9cf9', 'underlay-opacity': 0.35, 'underlay-padding': 6 } },
    { selector: 'node.busy', style: { 'underlay-color': '#f2c94c', 'underlay-opacity': 0.5, 'underlay-padding': 8 } },
    { selector: 'node.new', style: { 'underlay-color': '#27ae60', 'underlay-opacity': 0.35, 'underlay-padding': 5 } },
    { selector: 'edge', style: {
      width: 1.3, 'line-color': '#4a5568', 'target-arrow-color': '#4a5568', 'target-arrow-shape': 'triangle',
      'arrow-scale': 0.8, 'curve-style': 'bezier', label: 'data(label)', 'font-size': 8, color: '#8592a6',
      'text-rotation': 'autorotate', 'text-background-color': '#0f1218', 'text-background-opacity': 0.8, 'text-background-padding': 1
    } },
    { selector: 'edge:selected', style: { 'line-color': '#4f9cf9', 'target-arrow-color': '#4f9cf9', width: 2.2 } },
    { selector: 'edge.no-label', style: { label: '' } },
    { selector: '.hidden', style: { display: 'none' } },
    { selector: '.faded', style: { opacity: 0.15 } },
    { selector: 'node.match', style: { 'underlay-color': '#f2c94c', 'underlay-opacity': 0.6, 'underlay-padding': 8 } }
  ];
  for (const [type, t] of Object.entries(META.entityTypes)) {
    base.splice(1, 0, { selector: `node[type = "${type}"]`, style: { 'background-image': glyphSvg(t.glyph, t.color) } });
  }
  return base;
}

// ---------------------------------------------------------------- Entities
const nodeId = (type, value) => `${type}:${value.toLowerCase()}`;
const shortLabel = (type, v) => (type === 'url' || type === 'social' ? v.replace(/^https?:\/\//, '') : v);

function addEntity(type, value, props = {}, position) {
  const id = nodeId(type, value);
  let node = cy.getElementById(id);
  let created = false;
  if (node.empty()) {
    node = cy.add({ group: 'nodes', data: { id, type, value, label: shortLabel(type, value), props: { ...props } }, position });
    created = true;
  } else if (Object.keys(props).length) {
    node.data('props', { ...node.data('props'), ...props });
  }
  return { node, created };
}

function addEdge(source, target, label) {
  const id = `${source.id()}->${target.id()}`;
  const existing = cy.getElementById(id);
  if (existing.nonempty()) {
    const labels = new Set(existing.data('label').split(' · '));
    labels.add(label);
    existing.data('label', [...labels].join(' · '));
    return existing;
  }
  const edge = cy.add({ group: 'edges', data: { id, source: source.id(), target: target.id(), label } });
  if (!$('#edge-labels').checked) edge.addClass('no-label');
  return edge;
}

// ---------------------------------------------------------------- Transforms
function transformsFor(type) {
  return META.transforms.filter((t) => t.input.includes(type));
}

async function runTransform(t, node) {
  const name = t.name;
  const value = node.data('value');
  node.addClass('busy');
  try {
    const res = await limit(() => api('/api/transform', { transform: t.id, type: node.data('type'), value }));
    if (node.removed()) return;
    if (Object.keys(res.sourceProps || {}).length) node.data('props', { ...node.data('props'), ...res.sourceProps });
    const newNodes = [];
    const center = node.position();
    const freshCount = res.entities.filter((e) => cy.getElementById(nodeId(e.type, e.value)).empty()).length;
    const radius = 110 + freshCount * 5;
    let i = 0;
    const offset = Math.random() * Math.PI * 2;
    cy.batch(() => {
      for (const e of res.entities) {
        const angle = offset + (i / Math.max(freshCount, 1)) * Math.PI * 2;
        const pos = { x: center.x + radius * Math.cos(angle), y: center.y + radius * Math.sin(angle) };
        const { node: n, created } = addEntity(e.type, e.value, e.props, pos);
        if (created) { newNodes.push(n); i++; }
        addEdge(node, n, e.edge || t.name);
      }
    });
    cy.nodes('.new').removeClass('new');
    cy.collection(newNodes).addClass('new');
    applyFilters();
    log('ok', `${name} on <b>${esc(value)}</b> → ${res.entities.length} result${res.entities.length === 1 ? '' : 's'} (${newNodes.length} new)${res.truncated ? ', truncated' : ''}`);
    if (newNodes.length && $('#auto-layout').checked) runLayout();
    refreshDetails();
  } catch (e) {
    log('err', `${name} on <b>${esc(value)}</b> failed: ${esc(e.message)}`);
  } finally {
    node.removeClass('busy');
    updateCounts();
    $('#empty').hidden = cy.nodes().length > 0;
  }
}

function runOnNodes(t, nodes) {
  return Promise.all(nodes.filter((n) => t.input.includes(n.data('type'))).map((n) => runTransform(t, n)));
}

// ---------------------------------------------------------------- Context menu
const menu = $('#menu');
function hideMenu() { menu.hidden = true; }

function showMenu(node, x, y) {
  let targets = cy.nodes(':selected');
  if (!node.selected() || targets.length < 2) targets = cy.collection([node]);
  const types = new Set(targets.map((n) => n.data('type')));
  const list = META.transforms.filter((t) => t.input.some((ty) => types.has(ty)));
  const free = list.filter((t) => t.available && !t.requires.length);
  const title = targets.length > 1 ? `${targets.length} selected entities` : `${META.entityTypes[node.data('type')]?.label}: ${node.data('value')}`;

  menu.innerHTML = `<div class="head">${esc(title.length > 60 ? `${title.slice(0, 57)}…` : title)}</div>`;
  const addBtn = (label, key, onClick, disabled = false, tip = '') => {
    const b = document.createElement('button');
    b.innerHTML = `<span>${esc(label)}</span>${key ? `<span class="key">${esc(key)}</span>` : ''}`;
    b.disabled = disabled;
    if (tip) b.title = tip;
    b.addEventListener('click', () => { hideMenu(); onClick(); });
    menu.appendChild(b);
  };
  if (free.length > 1) {
    addBtn(`Run all free transforms (${free.length})`, '', () => free.forEach((t) => runOnNodes(t, targets)));
    menu.appendChild(document.createElement('hr'));
  }
  let group = '';
  for (const t of list) {
    if (t.group !== group && group) menu.appendChild(document.createElement('hr'));
    group = t.group;
    addBtn(t.name, t.available ? '' : 'needs key', () => runOnNodes(t, targets), !t.available,
      t.available ? '' : `Set ${t.requires.join(', ')} on the server`);
  }
  if (!list.length) menu.insertAdjacentHTML('beforeend', '<div class="head">No transforms for this type</div>');
  menu.appendChild(document.createElement('hr'));
  addBtn('Select neighbours', '', () => targets.closedNeighborhood().nodes().select());
  addBtn('Hierarchical layout from here', '', () => runLayout('breadthfirst', targets));
  addBtn('Delete', 'Del', () => { cy.remove(targets); afterChange(); });

  menu.hidden = false;
  const r = menu.getBoundingClientRect();
  menu.style.left = `${Math.min(x, window.innerWidth - r.width - 8)}px`;
  menu.style.top = `${Math.min(y, window.innerHeight - r.height - 8)}px`;
}

// ---------------------------------------------------------------- Layouts & filters
function runLayout(name = $('#layout').value, roots) {
  const eles = cy.elements(':visible');
  const opts = {
    cose: { name: 'cose', animate: true, animationDuration: 600, nodeRepulsion: () => 9000, idealEdgeLength: () => 90, gravity: 0.25, numIter: 1500, randomize: false },
    breadthfirst: { name: 'breadthfirst', directed: true, spacingFactor: 1.15, animate: true, roots: roots && roots.length ? roots : eles.nodes().roots() },
    concentric: { name: 'concentric', animate: true, minNodeSpacing: 30, concentric: (n) => n.degree(), levelWidth: () => 2 },
    circle: { name: 'circle', animate: true },
    grid: { name: 'grid', animate: true, avoidOverlap: true }
  }[name];
  eles.layout({ ...opts, fit: true, padding: 40 }).run();
}

function applyFilters() {
  const hideLeaves = $('#hide-leaves').checked;
  cy.batch(() => {
    cy.nodes().forEach((n) => {
      const hide = hiddenTypes.has(n.data('type')) || (hideLeaves && n.degree() === 1 && !n.selected());
      n.toggleClass('hidden', hide);
    });
  });
  updateCounts();
}

function buildFilter() {
  const ul = $('#type-filter');
  ul.innerHTML = '';
  for (const [type, t] of Object.entries(META.entityTypes)) {
    const li = document.createElement('li');
    li.innerHTML = `<label><input type="checkbox" ${hiddenTypes.has(type) ? '' : 'checked'} data-type="${type}" />
      <span class="swatch" style="background:${t.color}"></span>${esc(t.label)}</label><span class="count" data-count="${type}">0</span>`;
    ul.appendChild(li);
  }
  ul.addEventListener('change', (e) => {
    const type = e.target.dataset.type;
    if (!type) return;
    if (e.target.checked) hiddenTypes.delete(type); else hiddenTypes.add(type);
    applyFilters();
  });
}

function updateCounts() {
  for (const type of Object.keys(META.entityTypes)) {
    const el = document.querySelector(`[data-count="${type}"]`);
    if (el) el.textContent = cy.nodes(`[type = "${type}"]`).length;
  }
  updateStatus();
}

// ---------------------------------------------------------------- Details panel
function linkFor(type, value) {
  if (type === 'url' || type === 'social') return /^https?:\/\//.test(value) ? value : null;
  if (type === 'domain') return `https://${value}`;
  return null;
}

function refreshDetails() {
  const box = $('#details');
  const sel = cy.elements(':selected');
  if (sel.length === 0) {
    box.innerHTML = '<p class="muted">Select an entity to see its properties.<br />Right-click an entity for transforms.</p>';
    return;
  }
  if (sel.length > 1) {
    const byType = {};
    sel.nodes().forEach((n) => { byType[n.data('type')] = (byType[n.data('type')] || 0) + 1; });
    box.innerHTML = `<h3>${sel.nodes().length} entities selected</h3><table>${Object.entries(byType)
      .map(([t, c]) => `<tr><td>${esc(META.entityTypes[t]?.label || t)}</td><td>${c}</td></tr>`).join('')}</table>
      <p class="muted">Right-click a selected entity to run a transform on all of them.</p>`;
    return;
  }
  const el = sel[0];
  if (el.isEdge()) {
    box.innerHTML = `<div class="type-tag">Link</div><h3>${esc(el.data('label'))}</h3>
      <table><tr><td>From</td><td>${esc(el.source().data('value'))}</td></tr><tr><td>To</td><td>${esc(el.target().data('value'))}</td></tr></table>`;
    return;
  }
  const type = el.data('type');
  const t = META.entityTypes[type] || {};
  const props = el.data('props') || {};
  const rows = Object.entries(props).map(([k, v]) => `<tr><td>${esc(k.replace(/_/g, ' '))}</td><td>${esc(typeof v === 'object' ? JSON.stringify(v) : v)}</td></tr>`).join('');
  const link = linkFor(type, el.data('value'));
  box.innerHTML = `
    <div class="type-tag"><span class="swatch" style="background:${t.color}"></span>${esc(t.label || type)}</div>
    <h3>${esc(el.data('value'))}</h3>
    <div class="actions">
      <button id="d-copy">Copy value</button>
      ${link ? '<button id="d-open">Open ↗</button>' : ''}
      <button id="d-focus">Focus</button>
    </div>
    ${rows ? `<h2>Properties</h2><table>${rows}</table>` : ''}
    <h2>Links (${el.connectedEdges().length})</h2>
    <ul>${el.connectedEdges().map((e) => {
      const other = e.source().same(el) ? e.target() : e.source();
      const dir = e.source().same(el) ? '→' : '←';
      return `<li><span class="edge-label">${dir} ${esc(e.data('label'))}</span><br /><a data-id="${esc(other.id())}">${esc(other.data('value'))}</a></li>`;
    }).join('') || '<li class="muted">None yet</li>'}</ul>`;
  $('#d-copy').onclick = () => navigator.clipboard?.writeText(el.data('value'));
  $('#d-focus').onclick = () => cy.animate({ fit: { eles: el.closedNeighborhood(), padding: 60 } }, { duration: 400 });
  if (link) $('#d-open').onclick = () => window.open(link, '_blank', 'noopener,noreferrer');
  box.querySelectorAll('a[data-id]').forEach((a) => a.addEventListener('click', () => {
    const n = cy.getElementById(a.dataset.id);
    cy.elements().unselect();
    n.select();
    cy.animate({ center: { eles: n } }, { duration: 300 });
  }));
}

// ---------------------------------------------------------------- Log
function log(kind, html) {
  const li = document.createElement('li');
  li.className = kind;
  li.innerHTML = `<span class="time">${new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' })}</span>${html}`;
  $('#log').prepend(li);
}

function afterChange() {
  updateCounts();
  refreshDetails();
  $('#empty').hidden = cy.nodes().length > 0;
}

// ---------------------------------------------------------------- Boot
async function init() {
  try {
    META = await api('/api/meta');
  } catch (e) {
    log('err', `Could not reach server: ${esc(e.message)}`);
    return;
  }
  cy = cytoscape({ container: $('#cy'), style: buildStyle(), wheelSensitivity: 0.3, minZoom: 0.1, maxZoom: 4, boxSelectionEnabled: true });
  window.tracegraph = cy; // handy for console scripting

  const sel = $('#add-type');
  for (const [type, t] of Object.entries(META.entityTypes)) sel.add(new Option(t.label, type));
  buildFilter();

  const keyed = META.transforms.filter((t) => !t.available);
  log('ok', `Ready: <b>${META.transforms.length - keyed.length}</b> transforms available${keyed.length ? `, ${keyed.length} need API keys` : ''}.`);

  $('#add-form').addEventListener('submit', (e) => {
    e.preventDefault();
    addSeed(sel.value, $('#add-value').value);
  });
  // Guess the type as the user types so the common case is just "paste + Enter".
  $('#add-value').addEventListener('input', (e) => {
    const v = e.target.value.trim();
    const guess = /^[^@\s]+@[^@\s]+$/.test(v) ? 'email'
      : /^https?:\/\//i.test(v) ? 'url'
      : /^\d{1,3}(\.\d{1,3}){3}\/\d+$|^[0-9a-f:]+\/\d+$/i.test(v) ? 'netblock'
      : /^\d{1,3}(\.\d{1,3}){3}$|^[0-9a-f]*:[0-9a-f:]+$/i.test(v) ? 'ip'
      : /^as\d+$/i.test(v) ? 'asn'
      : /^[a-z0-9-]+(\.[a-z0-9-]+)+$/i.test(v) ? 'domain' : null;
    if (guess) sel.value = guess;
  });
  document.querySelectorAll('.examples button').forEach((b) => b.addEventListener('click', () => addSeed(b.dataset.type, b.dataset.value)));

  $('#run-layout').onclick = () => runLayout();
  $('#fit').onclick = () => cy.animate({ fit: { eles: cy.elements(':visible'), padding: 40 } }, { duration: 300 });
  $('#delete-selected').onclick = () => { cy.remove(cy.elements(':selected')); afterChange(); };
  $('#clear').onclick = () => { if (cy.nodes().length && confirm('Remove every entity from the graph?')) { cy.elements().remove(); afterChange(); } };
  $('#edge-labels').onchange = (e) => cy.edges().toggleClass('no-label', !e.target.checked);
  $('#hide-leaves').onchange = applyFilters;
  $('#filter-all').onclick = () => { hiddenTypes.clear(); buildFilterChecks(); applyFilters(); };
  $('#filter-none').onclick = () => { Object.keys(META.entityTypes).forEach((t) => hiddenTypes.add(t)); buildFilterChecks(); applyFilters(); };
  $('#clear-log').onclick = () => { $('#log').innerHTML = ''; };

  $('#search').addEventListener('input', (e) => {
    const q = e.target.value.trim().toLowerCase();
    cy.batch(() => {
      cy.elements().removeClass('faded match');
      if (!q) return;
      const hits = cy.nodes().filter((n) => n.data('value').toLowerCase().includes(q) || JSON.stringify(n.data('props')).toLowerCase().includes(q));
      cy.elements().not(hits).not(hits.edgesWith(hits)).addClass('faded');
      hits.addClass('match');
    });
  });
  $('#search').addEventListener('keydown', (e) => {
    if (e.key !== 'Enter') return;
    const hits = cy.nodes('.match');
    if (hits.length) { cy.elements().unselect(); hits.select(); cy.animate({ fit: { eles: hits, padding: 80 } }, { duration: 300 }); }
  });

  cy.on('cxttap', 'node', (e) => {
    const oe = e.originalEvent;
    showMenu(e.target, oe.clientX, oe.clientY);
  });
  cy.on('taphold', 'node', (e) => { // touch devices: long-press opens the menu
    const r = $('#cy').getBoundingClientRect();
    showMenu(e.target, r.left + e.renderedPosition.x, r.top + e.renderedPosition.y);
  });
  cy.on('tap', (e) => { hideMenu(); if (e.target === cy) cy.elements().removeClass('new'); });
  cy.on('select unselect', () => queueMicrotask(refreshDetails));
  document.addEventListener('click', (e) => { if (!menu.contains(e.target)) hideMenu(); });
  document.addEventListener('keydown', (e) => {
    if (e.key === 'Escape') hideMenu();
    const typing = ['INPUT', 'SELECT', 'TEXTAREA'].includes(document.activeElement?.tagName);
    if (!typing && (e.key === 'Delete' || e.key === 'Backspace')) { cy.remove(cy.elements(':selected')); afterChange(); }
    if (!typing && (e.ctrlKey || e.metaKey) && e.key === 'a') { e.preventDefault(); cy.elements(':visible').select(); }
  });
  updateStatus();
}

function buildFilterChecks() {
  document.querySelectorAll('#type-filter input').forEach((i) => { i.checked = !hiddenTypes.has(i.dataset.type); });
}

async function addSeed(type, raw) {
  const value = String(raw || '').trim();
  if (!value) return;
  const ext = cy.extent();
  const { node, created } = addEntity(type, normalizeClient(type, value), {}, { x: (ext.x1 + ext.x2) / 2 + (Math.random() - 0.5) * 80, y: (ext.y1 + ext.y2) / 2 + (Math.random() - 0.5) * 80 });
  if (created && cy.nodes().length === 1) cy.center(node);
  cy.elements().unselect();
  node.select();
  $('#add-value').value = '';
  afterChange();
  applyFilters();
}

function normalizeClient(type, v) {
  if (type === 'domain') return v.toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '').replace(/\.$/, '');
  if (type === 'email' || type === 'ip') return v.toLowerCase();
  if (type === 'asn') return /^\d+$/.test(v) ? `AS${v}` : v.toUpperCase();
  return v;
}

init();
