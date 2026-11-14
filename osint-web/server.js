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

// theHarvester sources that work without an API key (verified on the deployed server).
const TH_FREE = (process.env.THEHARVESTER_FREE_SOURCES || 'crtsh,hackertarget,rapiddns,otx,urlscan,certspotter,subdomaincenter,thc,waybackarchive,commoncrawl,duckduckgo,yahoo').split(',');
const SF = (process.env.SPIDERFOOT_CMD || 'spiderfoot').split(' ');
// Keyless passive modules verified to run together within 512 MB.
const SF_LITE = (process.env.SPIDERFOOT_LITE_MODULES || 'sfp_dnsresolve,sfp_crt,sfp_hackertarget,sfp_whois,sfp_spfdmarc,sfp_email,sfp_pgp,sfp_robtex,sfp_certspotter,sfp_bgpview,sfp_arin,sfp_ripe,sfp_internetdb,sfp_dnsraw,sfp_urlscan,sfp_threatminer').split(',');
const SF_LITE_MAX = Number(process.env.SPIDERFOOT_LITE_MAX || 25);
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
            // No API keys are configured for theHarvester, so `-b all` would mostly print
            // missing-key errors. `all` and `free` run the sources that need no key.
            for (const f of ['-b', '--source']) {
                const i = a.indexOf(f);
                if (i >= 0 && ['all', 'free'].includes(a[i + 1].toLowerCase()) && process.env.THEHARVESTER_KEYS !== '1') {
                    ctx.notice = `[web] -b ${a[i + 1]} → ${TH_FREE.length} free sources that need no API key:\n      ${TH_FREE.join(',')}\n\n`;
                    a[i + 1] = TH_FREE.join(',');
                }
            }
            return ['theHarvester', a, 600e3];
        }
        case 'spiderfoot': {
            if (!['spiderfoot', 'sf.py', 'sf'].includes(b)) throw new Reject('this terminal runs: spiderfoot …');
            const a = checkFlags(args, { '-s': 'target', '-u': 'word', '-m': 'list', '-t': 'list', '-o': 'word', '-x': true, '-q': true, '-n': true, '-r': true, '-S': 'int', '-H': true, '-M': true, '-T': true, '-F': 'list', '-f': true, '-max-threads': 'int', '-h': true, '--help': true });
            // SpiderFoot runs up to ~150 modules at once by default, which exhausts a
            // small instance. Cap concurrency unless the user sets it explicitly.
            if (!a.includes('-max-threads')) a.push('-max-threads', process.env.SPIDERFOOT_THREADS || '3');
            // On a small instance (SPIDERFOOT_LITE=1) a -u use case starts ~150 modules at once and the
            // memory spike gets the whole container killed. Map it to a tested keyless module set instead.
            if (process.env.SPIDERFOOT_LITE === '1') {
                const mi = a.indexOf('-m');
                if (mi >= 0 && a[mi + 1].split(',').length > SF_LITE_MAX) throw new Reject(`this server runs at most ${SF_LITE_MAX} SpiderFoot modules per scan (small instance); pick fewer with -m, or upgrade the instance and set SPIDERFOOT_LITE=0`);
                const ui = a.indexOf('-u');
                if (ui >= 0) {
                    ctx.notice = `[web] -u ${a[ui + 1]} → ${SF_LITE.length} tested passive modules (small instance; full use cases need 2 GB RAM, then set SPIDERFOOT_LITE=0):\n      ${SF_LITE.join(',')}\n\n`;
                    a.splice(ui, 2, '-m', SF_LITE.join(','));
                }
            }
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
            const checked = subs[sub]();
            // Without an API key the CLI refuses everything; answer `host` from Shodan's free InternetDB instead.
            if (!process.env.SHODAN_API_KEY) {
                // No key: answer from free public data instead of failing.
                const words = checked.filter((x) => !x.startsWith('-'));
                if (sub === 'host') return ['@internetdb', words.filter((x) => RE.ip.test(x)), 30e3];
                if (sub === 'domain') return ['@ctdomain', words, 60e3];
                if (sub === 'myip') return ['@myip', [], 15e3];
                if (sub === 'search' || sub === 'count') {
                    const q = words.join(' ').trim();
                    const m = q.match(/^(net|ip|hostname):(\S+)$/i);
                    if (!m) throw new Reject(`without an API key, shodan ${sub} supports: net:<CIDR /24 or smaller>, ip:<address>, hostname:<domain> (answered from free InternetDB). Any other query needs a free key from account.shodan.io set as SHODAN_API_KEY. Same query on the web: https://www.shodan.io/search?query=${encodeURIComponent(q)}`);
                    return ['@idbsearch', [sub, m[1].toLowerCase(), m[2]], 120e3];
                }
            }
            return ['shodan', [sub, ...checked], 180e3];
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
let sfRunning = false; // one SpiderFoot scan at a time: it is the memory-heavy one
const ANSI = /\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b[()][0-9A-B]|\r(?!\n)/g;

async function runJob(req, res, body) {
    let bin, argv, timeout;
    try {
        body.ctx = body.ctx && typeof body.ctx === 'object' ? body.ctx : {};
        delete body.ctx.notice; // set only by buildCommand
        [bin, argv, timeout] = buildCommand(body.tool, body.cmd, body.ctx);
    } catch (e) {
        if (e instanceof Reject) return json(res, 400, { error: e.message });
        throw e;
    }
    if (running >= MAX_JOBS) return json(res, 429, { error: `server busy: ${running} jobs running, try again shortly` });
    const isSf = body.tool === 'spiderfoot' && argv.includes('-s');
    if (isSf && sfRunning) return json(res, 429, { error: 'a SpiderFoot scan is already running; wait for it to finish or stop it' });
    if (isSf) sfRunning = true;

    const id = crypto.randomBytes(8).toString('hex');
    const dir = path.join(JOBS_DIR, id);
    await fsp.mkdir(dir);
    running++;
    res.writeHead(200, { 'Content-Type': 'text/plain; charset=utf-8', 'Cache-Control': 'no-store', 'X-Accel-Buffering': 'no', 'X-Job': id });

    const started = Date.now();
    if (bin.startsWith('@')) {
        const w = (s) => res.write(s);
        try {
            if (bin === '@internetdb') await internetdbHost(argv[0], w);
            else if (bin === '@ctdomain') await freeDomain(argv[0], w);
            else if (bin === '@myip') w(`${(await fetchJson('https://api.ipify.org?format=json')).ip}\n`);
            else if (bin === '@idbsearch') await freeSearch(argv[0], argv[1], argv[2], w);
        } catch (e) {
            res.write(`Error: ${e.message}\n`);
        }
        running--;
        return res.end(`\n\x1e${JSON.stringify({ job: id, code: 0, seconds: Math.round((Date.now() - started) / 1000), files: [] })}`);
    }
    if (body.ctx?.notice) res.write(body.ctx.notice);
    const child = spawn(bin, argv, {
        cwd: dir,
        env: { ...process.env, PYTHONWARNINGS: 'ignore', NO_COLOR: '1', TERM: 'dumb', PYTHONUNBUFFERED: '1', COLUMNS: '120', HOME: process.env.HOME || dir },
        stdio: ['ignore', 'pipe', 'pipe'],
        // Own process group: SpiderFoot's CLI SIGKILLs its whole group when a scan
        // ends, which would otherwise take this server down with it.
        detached: true
    });
    const killTree = (sig) => {
        try {
            process.kill(-child.pid, sig);
        } catch {
            child.kill(sig);
        }
    };
    const write = (chunk) => res.write(chunk.toString('utf8').replace(ANSI, ''));
    child.stdout.on('data', write);
    child.stderr.on('data', write);
    const timer = setTimeout(() => {
        res.write(`\n[web] timed out after ${timeout / 1000}s, stopping\n`);
        killTree('SIGTERM');
        setTimeout(() => killTree('SIGKILL'), 5000);
    }, timeout);
    // Stop the tool if the browser goes away (res 'close' before the response finished).
    res.on('close', () => {
        if (!res.writableFinished && child.exitCode === null && child.signalCode === null) {
            console.log(`[job ${id}] client disconnected, stopping ${bin}`);
            killTree('SIGTERM');
        }
    });
    console.log(`[job ${id}] start ${bin} ${argv.join(' ')}`);
    child.on('error', (e) => res.write(`\n[web] could not start ${bin}: ${e.code === 'ENOENT' ? 'not installed on this server' : e.message}\n`));
    child.on('close', async (code) => {
        clearTimeout(timer);
        running--;
        if (isSf) sfRunning = false;
        console.log(`[job ${id}] exit code=${code} signal=${child.signalCode} after ${Math.round((Date.now() - started) / 1000)}s`);
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

/** `shodan host` output, built from Shodan InternetDB (free, no key). */
async function internetdbHost(ip, write) {
    const r = await fetch(`https://internetdb.shodan.io/${ip}`, { signal: AbortSignal.timeout(15000) });
    if (r.status === 404) return write(`${ip}\nNo information available for that IP.\n`);
    if (!r.ok) throw new Error(`InternetDB HTTP ${r.status}`);
    const d = await r.json();
    const pad = (s) => (s + ':').padEnd(25);
    write(`${ip}\n`);
    if (d.hostnames.length) write(`${pad('Hostnames')}${d.hostnames.join(';')}\n`);
    write(`${pad('Number of open ports')}${d.ports.length}\n`);
    if (d.tags.length) write(`${pad('Tags')}${d.tags.join(', ')}\n`);
    if (d.vulns.length) write(`${pad('Vulnerabilities')}${d.vulns.join('  ')}\n`);
    write('\nPorts:\n');
    d.ports.forEach((p) => write(`     ${p}/tcp\n`));
    if (d.cpes.length) write(`\nSoftware (CPE):\n${d.cpes.map((c) => `     ${c}\n`).join('')}`);
    write('\nSource: Shodan InternetDB (no API key). Add SHODAN_API_KEY for banners, org, location and history.\n');
}

/** `shodan domain` without a key: subdomains from certificate transparency + DNS. */
async function freeDomain(domain, write) {
    write(`${domain.toUpperCase()}\n\n`);
    const row = (sub, type, value) => write(`${sub.padEnd(32)}${type.padEnd(8)}${value}\n`);
    for (const [type, fn] of [['A', (d) => dns.resolve4(d)], ['AAAA', (d) => dns.resolve6(d)], ['NS', (d) => dns.resolveNs(d)], ['MX', async (d) => (await dns.resolveMx(d)).map((m) => m.exchange)], ['TXT', async (d) => (await dns.resolveTxt(d)).map((c) => c.join(''))]]) {
        (await fn(domain).catch(() => [])).forEach((v) => row('', type, v));
    }
    let names = [];
    try {
        const rows = await fetchJson(`https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`, 30000);
        names = uniq(rows.flatMap((r) => String(r.name_value).split('\n')).map((n) => n.trim().toLowerCase().replace(/^\*\./, '')).filter((n) => n.endsWith(`.${domain}`))).sort();
    } catch (e) {
        write(`[crt.sh unavailable: ${e.message}]\n`);
    }
    const shown = names.slice(0, 150);
    for (let i = 0; i < shown.length; i += 20) {
        await Promise.all(shown.slice(i, i + 20).map(async (n) => {
            const ips = await dns.resolve4(n).catch(() => []);
            const sub = n.slice(0, -(domain.length + 1));
            if (ips.length) ips.forEach((ip) => row(sub, 'A', ip));
            else row(sub, 'CT', '(no A record)');
        }));
    }
    if (names.length > shown.length) write(`… ${names.length - shown.length} more subdomains not shown\n`);
    write('\nSource: certificate transparency (crt.sh) + DNS, no API key. Add SHODAN_API_KEY for Shodan\'s own DNS data.\n');
}

/** `shodan search|count net:/ip:/hostname:` without a key, from InternetDB. */
async function freeSearch(mode, kind, value, write) {
    let ips = [];
    if (kind === 'ip') {
        if (!RE.ip.test(value)) throw new Error('ip: needs an IPv4 address');
        ips = [value];
    } else if (kind === 'net') {
        const m = value.match(/^(\d+\.\d+\.\d+\.\d+)\/(\d+)$/);
        if (!m || !RE.ip.test(m[1]) || +m[2] < 24 || +m[2] > 32) throw new Error('net: needs an IPv4 CIDR of /24 or smaller, e.g. net:198.51.100.0/24');
        const base = m[1].split('.').reduce((a, o) => a * 256 + +o, 0);
        const size = 2 ** (32 - +m[2]);
        const start = Math.floor(base / size) * size;
        for (let i = 0; i < size; i++) ips.push([24, 16, 8, 0].map((s) => Math.floor((start + i) / 2 ** s) % 256).join('.'));
    } else {
        if (!RE.domain.test(value)) throw new Error('hostname: needs a domain');
        const names = [value];
        try {
            const rows = await fetchJson(`https://crt.sh/?q=%25.${encodeURIComponent(value)}&output=json`, 30000);
            names.push(...uniq(rows.flatMap((r) => String(r.name_value).split('\n')).map((n) => n.trim().toLowerCase().replace(/^\*\./, '')).filter((n) => n.endsWith(`.${value}`))).slice(0, 80));
        } catch {}
        const found = await Promise.all(names.map((n) => dns.resolve4(n).catch(() => [])));
        ips = uniq(found.flat()).slice(0, 64);
    }
    const hits = [];
    for (let i = 0; i < ips.length; i += 8) {
        const part = await Promise.all(ips.slice(i, i + 8).map((ip) => fetchJson(`https://internetdb.shodan.io/${ip}`).catch(() => null)));
        part.forEach((d) => d && d.ports && d.ports.length && hits.push(d));
    }
    if (mode === 'count') write(`${hits.reduce((n, d) => n + d.ports.length, 0)}\n`);
    else {
        for (const d of hits) for (const p of d.ports) write(`${d.ip.padEnd(16)}${String(p).padEnd(7)}${(d.hostnames[0] || '').padEnd(36)}${d.cpes.slice(0, 2).join(' ')}${d.vulns.length ? `  [${d.vulns.length} CVE]` : ''}\n`);
        if (!hits.length) write('No results found\n');
    }
    write(`\nSource: Shodan InternetDB for ${ips.length} address(es), no API key. Full search filters need SHODAN_API_KEY.\n`);
}

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

process.on('uncaughtException', (e) => console.error('[server] uncaught', e));
process.on('unhandledRejection', (e) => console.error('[server] unhandled rejection', e));
for (const sig of ['SIGTERM', 'SIGINT', 'SIGHUP']) process.on(sig, () => (console.log(`[server] received ${sig}, exiting`), process.exit(0)));
process.on('exit', (c) => console.log(`[server] exit ${c} (pid ${process.pid})`));

if (require.main === module) {
    if ((!USER || !PASS) && process.env.ALLOW_NO_AUTH !== '1') {
        console.error('Refusing to start: set OSINT_USER and OSINT_PASS (or ALLOW_NO_AUTH=1 for a localhost-only setup).');
        process.exit(1);
    }
    server.listen(PORT, HOST, () => console.log(`osint-web listening on http://${HOST}:${PORT} (auth ${USER ? 'on' : 'OFF'}, pid ${process.pid})`));
}
module.exports = { buildCommand, Reject };
