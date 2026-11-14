#!/usr/bin/env node
// osint-web: runs the real OSINT tools on this server and streams their output
// to the browser. No shell is ever used: every request is parsed into argv,
// checked against a per-tool allowlist, and spawned directly.
//
// Env:
//   OSINT_USER / OSINT_PASS  HTTP Basic auth (required unless ALLOW_NO_AUTH=1)
//   PORT (8080)  HOST (0.0.0.0)  MAX_JOBS (3)  JOB_TIMEOUT (900 seconds)
//   SPIDERFOOT_CMD ("spiderfoot")  RECON_CLI ("recon-cli")

'use strict';
const http = require('http');
const fs = require('fs');
const fsp = require('fs/promises');
const path = require('path');
const os = require('os');
const crypto = require('crypto');
const dns = require('dns').promises;
const { spawn, execFile } = require('child_process');

const PORT = Number(process.env.PORT || 8080);
const HOST = process.env.HOST || '0.0.0.0';
const MAX_JOBS = Number(process.env.MAX_JOBS || 3);
const JOB_TIMEOUT = Number(process.env.JOB_TIMEOUT || 900) * 1000;
const USER = process.env.OSINT_USER;
const PASS = process.env.OSINT_PASS;
const JOBS_DIR = process.env.JOBS_DIR || path.join(os.tmpdir(), 'osint-jobs');
const PUBLIC = path.join(__dirname, 'public');

fs.mkdirSync(JOBS_DIR, { recursive: true });

// ---------------------------------------------------------------- validation

const RE = {
    domain: /^(?=.{1,253}$)[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,62}[a-z0-9])?)+$/i,
    word: /^[\w.-]{1,253}$/,
    ip: /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/,
    target: /^[\w.@:/+-]{1,253}$/,
    list: /^[\w,.-]{1,400}$/,
    int: /^\d{1,6}$/,
    file: /^[\w.-]{1,64}$/,
    user: /^[\w.{}%-]{1,64}$/,
    site: /^[\w. -]{1,40}$/,
    phone: /^\+?[\d().\s-]{5,22}$/,
    query: /^[^\0\n\r`;|&$<>\\]{1,200}$/,
    module: /^[a-z0-9_/-]{1,120}$/,
    option: /^[A-Z_]{1,40}=[^\0\n\r`;|&$<>\\]{0,200}$/
};

class Reject extends Error {}

/** Generic flag checker. spec: { '-d': 'domain', '--print-all': true, ... } (true = flag without value) */
function checkFlags(args, spec, { positional = null, maxPositional = 0 } = {}) {
    const out = [];
    let pos = 0;
    for (let i = 0; i < args.length; i++) {
        let a = args[i];
        let inline;
        if (a.startsWith('--') && a.includes('=')) [a, inline] = [a.slice(0, a.indexOf('=')), a.slice(a.indexOf('=') + 1)];
        if (a.startsWith('-') && a !== '-') {
            if (!(a in spec)) throw new Reject(`option not allowed from the web: ${a}`);
            const kind = spec[a];
            if (kind === true) {
                out.push(a);
                continue;
            }
            const v = inline ?? args[++i];
            if (v === undefined) throw new Reject(`${a} needs a value`);
            if (!RE[kind].test(v)) throw new Reject(`invalid value for ${a}: ${v}`);
            out.push(a, v);
        } else {
            if (!positional || pos >= maxPositional) throw new Reject(`unexpected argument: ${a}`);
            if (!RE[positional].test(a)) throw new Reject(`invalid argument: ${a}`);
            out.push(a);
            pos++;
        }
    }
    return out;
}

function tokenize(line) {
    const out = [];
    const re = /"([^"]*)"|'([^']*)'|(\S+)/g;
    let m;
    while ((m = re.exec(line))) out.push(m[1] ?? m[2] ?? m[3]);
    return out;
}

const SF = (process.env.SPIDERFOOT_CMD || 'spiderfoot').split(' ');
const RECON = process.env.RECON_CLI || 'recon-cli';

/** Map a web command line to [bin, argv, timeoutMs]. Throws Reject. */
function buildCommand(tool, line, ctx) {
    const argv = tokenize(String(line || '').trim());
    if (!argv.length) throw new Reject('empty command');
    if (argv.length > 40) throw new Reject('too many arguments');
    const [bin, ...args] = argv;
    const b = bin.toLowerCase();

    switch (tool) {
        case 'theharvester': {
            if (b !== 'theharvester') throw new Reject('this terminal runs: theHarvester …');
            const a = checkFlags(args, { '-d': 'word', '--domain': 'word', '-b': 'list', '--source': 'list', '-l': 'int', '--limit': 'int', '-S': 'int', '--start': 'int', '-f': 'file', '--filename': 'file', '-n': true, '--dns-lookup': true, '-c': true, '--dns-brute': true, '-s': true, '--shodan': true, '-q': true, '--quiet': true, '-h': true, '--help': true });
            return ['theHarvester', a, 600e3];
        }
        case 'spiderfoot': {
            if (!['spiderfoot', 'sf.py', 'sf'].includes(b)) throw new Reject('this terminal runs: spiderfoot …');
            const a = checkFlags(args, { '-s': 'target', '-u': 'word', '-m': 'list', '-t': 'list', '-o': 'word', '-x': true, '-q': true, '-n': true, '-r': true, '-S': 'int', '-H': true, '-M': true, '-T': true, '-F': 'list', '-f': true, '-h': true, '--help': true });
            const u = a[a.indexOf('-u') + 1];
            if (a.includes('-u') && !['all', 'footprint', 'investigate', 'passive'].includes(u)) throw new Reject('-u must be all, footprint, investigate or passive');
            const o = a[a.indexOf('-o') + 1];
            if (a.includes('-o') && !['tab', 'csv', 'json', 'gexf'].includes(o)) throw new Reject('-o must be tab, csv, json or gexf');
            return [SF[0], [...SF.slice(1), ...a], JOB_TIMEOUT];
        }
        case 'sherlock': {
            if (b !== 'sherlock') throw new Reject('this terminal runs: sherlock …');
            const a = checkFlags(args, { '--print-all': true, '--print-found': true, '--site': 'site', '--timeout': 'int', '--csv': true, '--xlsx': true, '--nsfw': true, '--verbose': true, '-v': true, '--no-color': true, '--local': true, '-l': true, '--help': true, '-h': true, '--version': true }, { positional: 'user', maxPositional: 5 });
            return ['sherlock', ['--no-color', ...a.filter((x) => x !== '--no-color')], 600e3];
        }
        case 'shodan': {
            if (b !== 'shodan') throw new Reject('this terminal runs: shodan …');
            const [sub, ...rest] = args;
            const subs = {
                host: () => checkFlags(rest, { '--history': true, '--format': 'word' }, { positional: 'ip', maxPositional: 1 }),
                honeyscore: () => checkFlags(rest, {}, { positional: 'ip', maxPositional: 1 }),
                domain: () => checkFlags(rest, { '-D': true, '--details': true, '-S': true, '--save': true }, { positional: 'domain', maxPositional: 1 }),
                search: () => checkFlags(rest, { '--limit': 'int', '--fields': 'list', '--separator': 'word', '--color': true, '--no-color': true }, { positional: 'query', maxPositional: 12 }),
                count: () => checkFlags(rest, {}, { positional: 'query', maxPositional: 12 }),
                stats: () => checkFlags(rest, { '--facets': 'list', '--limit': 'int' }, { positional: 'query', maxPositional: 12 }),
                info: () => checkFlags(rest, {}),
                myip: () => checkFlags(rest, {}),
                version: () => checkFlags(rest, {}),
                '--help': () => [],
                '-h': () => []
            };
            if (!sub || !subs[sub]) throw new Reject(`allowed: shodan ${Object.keys(subs).filter((x) => !x.startsWith('-')).join(' | ')}`);
            return ['shodan', [sub, ...subs[sub]()], 180e3];
        }
        case 'phoneinfoga': {
            if (b !== 'phoneinfoga') throw new Reject('this terminal runs: phoneinfoga …');
            const [sub, ...rest] = args;
            if (sub === 'version' || sub === '--help' || sub === '-h') return ['phoneinfoga', [sub], 30e3];
            if (sub === 'scanners') return ['phoneinfoga', ['scanners'], 30e3];
            if (sub !== 'scan') throw new Reject('allowed: phoneinfoga scan -n NUMBER [-D scanner] | scanners | version (serve: this page is the web UI)');
            const a = checkFlags(rest, { '-n': 'phone', '--number': 'phone', '-D': 'word', '--disable': 'word', '--plugin': 'word' });
            if (a.includes('--plugin')) throw new Reject('--plugin loads code from disk and is disabled on the web');
            return ['phoneinfoga', ['scan', ...a], 180e3];
        }
        case 'reconng': {
            // Console verbs are translated to recon-cli calls on a persistent workspace.
            const ws = ['-w', 'web', '--no-analytics'];
            const kw = args.join(' ');
            if (b === 'marketplace' && args[0] === 'search') {
                if (args[1] && !RE.module.test(args[1])) throw new Reject('invalid search term');
                return [RECON, [...ws, '-C', `marketplace search ${args[1] || ''}`.trim()], 120e3];
            }
            if (b === 'marketplace' && args[0] === 'install') {
                if (!args[1] || !RE.module.test(args[1])) throw new Reject('usage: marketplace install <module path|all>');
                return [RECON, [...ws, '-C', `marketplace install ${args[1]}`], 300e3];
            }
            if (b === 'marketplace' && args[0] === 'refresh') return [RECON, [...ws, '-C', 'marketplace refresh'], 120e3];
            if (b === 'modules' && args[0] === 'search') {
                if (args[1] && !RE.module.test(args[1])) throw new Reject('invalid search term');
                return [RECON, [...ws, '-C', `modules search ${args[1] || ''}`.trim()], 60e3];
            }
            if (b === 'show') {
                const tables = ['domains', 'companies', 'netblocks', 'locations', 'vulnerabilities', 'ports', 'hosts', 'contacts', 'credentials', 'leaks', 'pushpins', 'profiles', 'repositories'];
                if (!tables.includes(args[0])) throw new Reject(`usage: show <${tables.join('|')}>`);
                return [RECON, [...ws, '-C', `show ${args[0]}`], 60e3];
            }
            if (b === 'info' || (b === 'options' && (!args[0] || args[0] === 'list'))) {
                if (!ctx.module || !RE.module.test(ctx.module)) throw new Reject('load a module first: modules load <path>');
                return [RECON, [...ws, '-m', ctx.module, '-c', 'info'], 60e3];
            }
            if (b === 'run') {
                if (!ctx.module || !RE.module.test(ctx.module)) throw new Reject('load a module first: modules load <path>');
                const opts = Object.entries(ctx.options || {}).map(([k, v]) => `${k}=${v}`);
                opts.forEach((o) => {
                    if (!RE.option.test(o)) throw new Reject(`invalid option ${o}`);
                });
                return [RECON, [...ws, '-m', ctx.module, ...opts.flatMap((o) => ['-o', o]), '-x'], JOB_TIMEOUT];
            }
            throw new Reject(`unknown command: ${kw ? `${bin} ${kw}` : bin}`);
        }
        default:
            throw new Reject('unknown tool');
    }
}

// ---------------------------------------------------------------- jobs

let running = 0;
const ANSI = /\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[()][0-9A-B]|\r(?!\n)/g;

async function runJob(req, res, body) {
    let bin, argv, timeout;
    try {
        [bin, argv, timeout] = buildCommand(body.tool, body.cmd, body.ctx || {});
    } catch (e) {
        if (e instanceof Reject) return json(res, 400, { error: e.message });
        throw e;
    }
    if (running >= MAX_JOBS) return json(res, 429, { error: `server busy: ${running} jobs running, try again shortly` });

    const id = crypto.randomBytes(8).toString('hex');
    const dir = path.join(JOBS_DIR, id);
    await fsp.mkdir(dir);
    running++;
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store', 'X-Accel-Buffering': 'no', 'X-Job': id });

    const started = Date.now();
    const child = spawn(bin, argv, {
        cwd: dir,
        env: { ...process.env, PYTHONWARNINGS: 'ignore', NO_COLOR: '1', TERM: 'dumb', PYTHONUNBUFFERED: '1', COLUMNS: '120', HOME: process.env.HOME || dir },
        stdio: ['ignore', 'pipe', 'pipe']
    });
    const write = (chunk) => res.write(chunk.toString('utf8').replace(ANSI, ''));
    child.stdout.on('data', write);
    child.stderr.on('data', write);
    const timer = setTimeout(() => {
        res.write(`\n[web] timed out after ${timeout / 1000}s, stopping\n`);
        child.kill('SIGTERM');
        setTimeout(() => child.kill('SIGKILL'), 5000);
    }, timeout);
    req.on('close', () => {
        if (child.exitCode === null) child.kill('SIGTERM');
    });
    child.on('error', (e) => res.write(`\n[web] could not start ${bin}: ${e.code === 'ENOENT' ? 'not installed on this server' : e.message}\n`));
    child.on('close', async (code) => {
        clearTimeout(timer);
        running--;
        let files = [];
        try {
            files = await listFiles(dir);
        } catch {}
        res.end(`\n\x1e${JSON.stringify({ job: id, code, seconds: Math.round((Date.now() - started) / 1000), files })}`);
    });
}

async function listFiles(dir, base = '') {
    const out = [];
    for (const e of await fsp.readdir(path.join(dir, base), { withFileTypes: true })) {
        const rel = path.join(base, e.name);
        if (e.isDirectory()) out.push(...(await listFiles(dir, rel)));
        else if (e.isFile()) out.push(rel);
    }
    return out.slice(0, 50);
}

// Delete job folders older than 2h
setInterval(async () => {
    for (const d of await fsp.readdir(JOBS_DIR).catch(() => [])) {
        const p = path.join(JOBS_DIR, d);
        const st = await fsp.stat(p).catch(() => null);
        if (st && Date.now() - st.mtimeMs > 2 * 3600e3) fsp.rm(p, { recursive: true, force: true });
    }
}, 600e3).unref();

// ---------------------------------------------------------------- Maltego-style transforms
// Real lookups run on this server: DNS, whois, crt.sh, Shodan InternetDB.

const fetchJson = async (url, ms = 15000) => {
    const r = await fetch(url, { signal: AbortSignal.timeout(ms), headers: { 'User-Agent': 'osint-web' } });
    if (!r.ok) throw new Error(`HTTP ${r.status} from ${new URL(url).host}`);
    return r.json();
};
const whois = (q) =>
    new Promise((resolve, reject) =>
        execFile('whois', [q], { timeout: 20000, maxBuffer: 2e6 }, (err, out) => (err && !out ? reject(err) : resolve(out || '')))
    );
const uniq = (a) => [...new Set(a)];

const TRANSFORMS = {
    'dns-from-domain': async (v) => {
        const rows = await fetchJson(`https://crt.sh/?q=%25.${encodeURIComponent(v)}&output=json`, 30000);
        const names = uniq(rows.flatMap((r) => String(r.name_value).split('\n')).map((n) => n.trim().toLowerCase().replace(/^\*\./, '')).filter((n) => n.endsWith(`.${v}`)));
        return names.slice(0, 60).map((n) => ['dns', n]);
    },
    'to-ip': async (v) => (await dns.resolve4(v).catch(() => [])).map((ip) => ['ip', ip]),
    'to-mx-ns': async (v) => [...(await dns.resolveMx(v).catch(() => [])).map((m) => ['mx', m.exchange]), ...(await dns.resolveNs(v).catch(() => [])).map((n) => ['ns', n])],
    'to-email-whois': async (v) => uniq((await whois(v)).match(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi) || []).map((e) => ['email', e.toLowerCase()]),
    'to-registrar': async (v) => {
        const m = (await whois(v)).match(/^\s*Registrar:\s*(.+)$/im);
        return m ? [['org', m[1].trim()]] : [];
    },
    'to-netblock': async (v) => {
        const w = await whois(v);
        const cidr = w.match(/^\s*(?:CIDR|route|inetnum|NetRange):\s*(.+)$/im);
        return cidr ? [['netblock', cidr[1].trim()]] : [];
    },
    'to-owner': async (v) => {
        const w = await whois(v);
        const org = w.match(/^\s*(?:OrgName|org-name|descr|owner|netname):\s*(.+)$/im);
        return org ? [['org', org[1].trim()]] : [];
    },
    'to-reverse': async (v) => (await dns.reverse(v).catch(() => [])).map((n) => ['dns', n]),
    'to-ports': async (v) => ((await fetchJson(`https://internetdb.shodan.io/${v}`).catch(() => null))?.ports || []).map((p) => ['port', `${v}:${p}`]),
    'to-vulns': async (v) => ((await fetchJson(`https://internetdb.shodan.io/${v}`).catch(() => null))?.vulns || []).map((c) => ['cve', c]),
    'email-to-domain': async (v) => [['domain', v.split('@')[1]]]
};
const TRANSFORM_INPUT = { 'dns-from-domain': 'domain', 'to-ip': 'domain', 'to-mx-ns': 'domain', 'to-email-whois': 'domain', 'to-registrar': 'domain', 'to-netblock': 'ip', 'to-owner': 'ip', 'to-reverse': 'ip', 'to-ports': 'ip', 'to-vulns': 'ip', 'email-to-domain': 'target' };

async function transform(res, q) {
    const t = q.get('t');
    const v = String(q.get('v') || '').toLowerCase();
    if (!TRANSFORMS[t]) return json(res, 400, { error: 'unknown transform' });
    if (!RE[TRANSFORM_INPUT[t]].test(v)) return json(res, 400, { error: 'invalid entity value' });
    try {
        json(res, 200, { entities: await TRANSFORMS[t](v) });
    } catch (e) {
        json(res, 502, { error: e.message });
    }
}

// ---------------------------------------------------------------- http

function json(res, code, obj) {
    res.writeHead(code, { 'Content-Type': 'application/json', 'Cache-Control': 'no-store' });
    res.end(JSON.stringify(obj));
}

function authorized(req) {
    if (!USER) return true;
    const h = req.headers.authorization || '';
    if (!h.startsWith('Basic ')) return false;
    const [u, ...p] = Buffer.from(h.slice(6), 'base64').toString().split(':');
    const a = Buffer.from(`${u}:${p.join(':')}`);
    const b = Buffer.from(`${USER}:${PASS}`);
    return a.length === b.length && crypto.timingSafeEqual(a, b);
}

const TYPES = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.svg': 'image/svg+xml' };

const server = http.createServer(async (req, res) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'no-referrer');
    if (req.url === '/healthz') {
        res.writeHead(200, { 'Content-Type': 'text/plain' });
        return res.end('ok');
    }
    if (!authorized(req)) {
        res.writeHead(401, { 'WWW-Authenticate': 'Basic realm="osint-web"' });
        return res.end('Authentication required');
    }
    const url = new URL(req.url, 'http://x');
    try {
        if (req.method === 'POST' && url.pathname === '/api/run') {
            let raw = '';
            for await (const c of req) {
                raw += c;
                if (raw.length > 8192) return json(res, 413, { error: 'request too large' });
            }
            let body;
            try {
                body = JSON.parse(raw);
            } catch {
                return json(res, 400, { error: 'invalid JSON' });
            }
            return await runJob(req, res, body);
        }
        if (req.method === 'GET' && url.pathname === '/api/transform') return await transform(res, url.searchParams);
        if (req.method === 'GET' && url.pathname === '/api/status') {
            const which = (b) => new Promise((r) => execFile('sh', ['-c', `command -v "$0"`, b], (e) => r(!e)));
            const tools = { theHarvester: 'theHarvester', spiderfoot: SF[0], sherlock: 'sherlock', shodan: 'shodan', phoneinfoga: 'phoneinfoga', 'recon-cli': RECON, whois: 'whois' };
            const status = {};
            for (const [k, b] of Object.entries(tools)) status[k] = await which(b);
            return json(res, 200, { running, maxJobs: MAX_JOBS, tools: status, shodanKey: Boolean(process.env.SHODAN_API_KEY) });
        }
        const fm = url.pathname.match(/^\/api\/files\/([a-f0-9]{16})\/(.+)$/);
        if (req.method === 'GET' && fm) {
            const dir = path.join(JOBS_DIR, fm[1]);
            const file = path.resolve(dir, decodeURIComponent(fm[2]));
            if (!file.startsWith(dir + path.sep)) return json(res, 400, { error: 'bad path' });
            const st = await fsp.stat(file).catch(() => null);
            if (!st?.isFile()) return json(res, 404, { error: 'not found' });
            res.writeHead(200, { 'Content-Type': 'application/octet-stream', 'Content-Disposition': `attachment; filename="${path.basename(file).replace(/"/g, '')}"` });
            return fs.createReadStream(file).pipe(res);
        }
        if (req.method === 'GET') {
            const p = url.pathname === '/' ? '/index.html' : url.pathname;
            const file = path.resolve(PUBLIC, '.' + p);
            if (!file.startsWith(PUBLIC)) return json(res, 400, { error: 'bad path' });
            const data = await fsp.readFile(file).catch(() => null);
            if (!data) return json(res, 404, { error: 'not found' });
            res.writeHead(200, { 'Content-Type': TYPES[path.extname(file)] || 'application/octet-stream' });
            return res.end(data);
        }
        json(res, 405, { error: 'method not allowed' });
    } catch (e) {
        console.error(e);
        if (!res.headersSent) json(res, 500, { error: 'internal error' });
        else res.end();
    }
});

if (require.main === module) {
    if ((!USER || !PASS) && process.env.ALLOW_NO_AUTH !== '1') {
        console.error('Refusing to start: set OSINT_USER and OSINT_PASS (or ALLOW_NO_AUTH=1 for a localhost-only setup).');
        process.exit(1);
    }
    server.listen(PORT, HOST, () => console.log(`osint-web listening on http://${HOST}:${PORT} (auth ${USER ? 'on' : 'OFF'})`));
}
module.exports = { buildCommand, Reject };
