// Shared helpers for the carousel terminals.

/** Split a command line into argv, honouring "double" and 'single' quotes. */
export function tokenize(line) {
    const out = [];
    const re = /"([^"]*)"|'([^']*)'|(\S+)/g;
    let m;
    while ((m = re.exec(line))) out.push(m[1] ?? m[2] ?? m[3]);
    return out;
}

/**
 * Tiny getopt. spec: { d: 'value', b: 'value', print-found: 'flag', site: 'multi' }
 * Accepts -x value, --long value, --long=value. Returns { opts, rest, unknown }.
 */
export function parseArgs(argv, spec) {
    const opts = {};
    const rest = [];
    const unknown = [];
    for (let i = 0; i < argv.length; i++) {
        let a = argv[i];
        if (!a.startsWith('-') || a === '-') {
            rest.push(a);
            continue;
        }
        let val;
        if (a.includes('=')) [a, val] = a.split(/=(.*)/s);
        const key = a.replace(/^-+/, '');
        const kind = spec[key];
        if (!kind) {
            unknown.push(a);
            continue;
        }
        if (kind === 'flag') opts[key] = true;
        else {
            if (val === undefined) val = argv[++i];
            if (val === undefined) {
                unknown.push(`${a} (missing value)`);
                continue;
            }
            if (kind === 'multi') (opts[key] = opts[key] || []).push(val);
            else opts[key] = val;
        }
    }
    return { opts, rest, unknown };
}

export async function api(path) {
    const res = await fetch(path);
    const body = await res.json().catch(() => ({}));
    if (!res.ok) {
        const err = new Error(body.error || `HTTP ${res.status}`);
        err.status = res.status;
        err.body = body;
        throw err;
    }
    return body;
}

export function download(filename, text, type = 'text/plain') {
    const blob = new Blob([text], { type });
    const a = document.createElement('a');
    a.href = URL.createObjectURL(blob);
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    a.remove();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
}

export function toCsv(rows) {
    if (!rows.length) return '';
    const cols = Object.keys(rows[0]);
    const esc = (v) => `"${String(Array.isArray(v) ? v.join(' ') : v ?? '').replace(/"/g, '""')}"`;
    return [cols.join(','), ...rows.map((r) => cols.map((c) => esc(r[c])).join(','))].join('\n');
}

export const pad = (s, n) => {
    s = String(s ?? '');
    return s.length >= n ? s : s + ' '.repeat(n - s.length);
};

/** ASCII table in recon-ng / CLI style. */
export function asciiTable(cols, rows) {
    const w = cols.map((c, i) => Math.min(48, Math.max(c.length, ...rows.map((r) => String(r[i] ?? '').length))));
    const line = '+' + w.map((n) => '-'.repeat(n + 2)).join('+') + '+';
    const fmt = (r) => '| ' + r.map((v, i) => pad(String(v ?? '').slice(0, w[i]), w[i])).join(' | ') + ' |';
    return [line, fmt(cols), line, ...rows.map(fmt), line];
}

export const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const IPV4 = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
const DOMAIN = /^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$/i;
const EMAIL = /^[^\s@]+@[^\s@]+\.[a-z]{2,}$/i;
export const isIp = (s) => IPV4.test(s);
export const isDomain = (s) => DOMAIN.test(s);
export const isEmail = (s) => EMAIL.test(s);

export function storageGet(key, fallback) {
    try {
        const v = localStorage.getItem(key);
        return v ? JSON.parse(v) : fallback;
    } catch {
        return fallback;
    }
}
export function storageSet(key, value) {
    try {
        localStorage.setItem(key, JSON.stringify(value));
    } catch {
        /* storage unavailable */
    }
}
