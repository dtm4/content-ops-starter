import { tokenize, api, asciiTable, toCsv, download, isDomain, storageGet, storageSet, pad } from '../runtime';

// recon-ng-style console. Modules write into a workspace database (kept in
// this browser) so later modules build on earlier results.

const STORE = 'osint-reconng-v1';
const TABLES = {
    domains: ['domain', 'module'],
    hosts: ['host', 'ip_address', 'module'],
    contacts: ['email', 'name', 'module'],
    ports: ['ip_address', 'host', 'port', 'module'],
    vulnerabilities: ['host', 'reference', 'module'],
    netblocks: ['netblock', 'org', 'module']
};

const MODULES = {
    'recon/domains-hosts/hackertarget': { desc: 'Uses the HackerTarget.com API to find host names', source: 'domains', input: 'domain' },
    'recon/domains-hosts/certificate_transparency': { desc: 'Searches certificate transparency (crt.sh) for host names', source: 'domains', input: 'domain' },
    'recon/hosts-hosts/resolve': { desc: 'Resolves the IP address for hosts without one', source: 'hosts', input: 'host' },
    'recon/hosts-ports/shodan_ip': { desc: 'Harvests open ports and CVEs for host IPs from Shodan InternetDB', source: 'hosts', input: 'ip_address' },
    'recon/domains-contacts/whois_pocs': { desc: 'Uses RDAP/WHOIS to harvest points of contact for a domain', source: 'domains', input: 'domain' },
    'recon/hosts-netblocks/rdap_netblock': { desc: 'Looks up the owning netblock and org of host IPs via RDAP', source: 'hosts', input: 'ip_address' },
    'reporting/csv': { desc: 'Creates a CSV file of the hosts table', report: true },
    'reporting/json': { desc: 'Creates a JSON file of the whole workspace', report: true }
};

export function initialState() {
    const saved = storageGet(STORE, null);
    const db = Object.fromEntries(Object.keys(TABLES).map((t) => [t, saved?.db?.[t] || []]));
    return { db, installed: saved?.installed || [], module: null, options: { SOURCE: 'default' } };
}

const save = (s) => storageSet(STORE, { db: s.db, installed: s.installed });

function insert(state, table, row) {
    const key = TABLES[table].filter((c) => c !== 'module').map((c) => row[c] ?? '').join('|');
    const exists = state.db[table].some((r) => TABLES[table].filter((c) => c !== 'module').map((c) => r[c] ?? '').join('|') === key);
    if (exists) return false;
    state.db[table].push(row);
    return true;
}

function sourceValues(state, mod) {
    const src = state.options.SOURCE;
    if (src && src !== 'default') return [src];
    const rows = state.db[mod.source];
    if (mod.input === 'host') return rows.filter((r) => !r.ip_address).map((r) => r.host);
    return [...new Set(rows.map((r) => r[mod.input]).filter(Boolean))];
}

export default {
    id: 'reconng',
    n: '07',
    name: 'recon-ng',
    color: '#58a6ff',
    subtitle: 'Modular recon framework',
    example: 'modules load recon/domains-hosts/hackertarget',
    comment: 'modular recon framework · try: options set SOURCE example.com → run → show hosts',
    usage: [
        ['marketplace search', 'find modules'],
        ['modules load', 'load a module'],
        ['options set', 'configure input'],
        ['run', 'execute the module']
    ],
    overview:
        'recon-ng runs recon like Metasploit. Load a module from the marketplace, point it at a domain and run it, and results flow into a shared database that later modules build on, chaining hosts, contacts and ports into one workspace.',
    initialState,
    prompt: (s) => `[recon-ng][default]${s.module ? `[${s.module.split('/').pop()}]` : ''} >`,

    async exec(line, io, state) {
        const argv = tokenize(line);
        const [c0, c1, ...rest] = argv;
        const cmd = (c0 || '').toLowerCase();
        const sub = (c1 || '').toLowerCase();

        const listModules = (filter = '') => {
            const rows = Object.entries(MODULES)
                .filter(([p]) => p.includes(filter))
                .map(([p, m]) => [p, state.installed.includes(p) || m.report ? 'installed' : 'not installed', m.desc.slice(0, 48)]);
            if (!rows.length) return io.print(`[*] No modules found containing '${filter}'.`, 'warn');
            asciiTable(['Path', 'Status', 'Description'], rows).forEach((l) => io.print(l));
        };

        if (cmd === 'help' || cmd === '?') {
            [['back', 'Exits the current context'], ['db insert', 'Inserts a row: db insert domains example.com'], ['db delete', 'Clears a table: db delete hosts'], ['marketplace', 'search / install modules'], ['modules', 'search / load modules'], ['options', 'list / set / unset options'], ['run', 'Runs the loaded module'], ['show', `Shows a table: ${Object.keys(TABLES).join(', ')}`], ['info', 'Shows details about the loaded module'], ['clear', 'Clears the screen']].forEach(([a, b]) => io.print(`${pad(a, 14)}${b}`));
            return;
        }
        if (cmd === 'marketplace') {
            if (sub === 'search') return listModules(rest[0] || '');
            if (sub === 'install') {
                const target = rest[0] === 'all' ? Object.keys(MODULES) : Object.keys(MODULES).filter((p) => p === rest[0] || p.endsWith(`/${rest[0]}`));
                if (!target.length) return io.print(`[!] Invalid module path: ${rest[0] || ''}`, 'bad');
                target.forEach((p) => {
                    if (!state.installed.includes(p)) state.installed.push(p);
                    io.print(`[*] Module installed: ${p}`, 'ok');
                });
                save(state);
                return;
            }
            return io.print('Usage: marketplace <search|install> [path]');
        }
        if (cmd === 'modules') {
            if (sub === 'search') return listModules(rest[0] || '');
            if (sub === 'load') {
                const path = Object.keys(MODULES).find((p) => p === rest[0] || p.endsWith(`/${rest[0]}`));
                if (!path) return io.print(`[!] Invalid module name: ${rest[0] || ''}`, 'bad');
                if (!state.installed.includes(path) && !MODULES[path].report) {
                    state.installed.push(path);
                    save(state);
                    io.print(`[*] Module not installed. Installing from marketplace: ${path}`, 'muted');
                }
                state.module = path;
                state.options = { SOURCE: 'default' };
                io.print(`[*] Loaded ${path}`, 'ok');
                io.print('    next: options set SOURCE <value>  (or leave "default" to use the workspace)  →  run', 'muted');
                return;
            }
            return io.print('Usage: modules <search|load> [path]');
        }
        if (cmd === 'back') {
            state.module = null;
            return;
        }
        if (cmd === 'options' || cmd === 'info') {
            if (!state.module) return io.print('[!] Load a module first: modules load <path>', 'bad');
            const m = MODULES[state.module];
            if (cmd === 'info' || sub === 'list' || !sub) {
                if (cmd === 'info') {
                    io.print(`      Name: ${state.module}`);
                    io.print(`  Description: ${m.desc}`);
                    io.print('');
                }
                if (m.report) return io.print('  (no options)', 'muted');
                asciiTable(['Name', 'Current Value', 'Required', 'Description'], [['SOURCE', state.options.SOURCE, 'yes', `source of input (default = ${m.source} table)`]]).forEach((l) => io.print(l));
                return;
            }
            if (sub === 'set') {
                if ((rest[0] || '').toUpperCase() !== 'SOURCE' || !rest[1]) return io.print('Usage: options set SOURCE <value>', 'bad');
                state.options.SOURCE = rest[1];
                return io.print(`SOURCE => ${rest[1]}`);
            }
            if (sub === 'unset') {
                state.options.SOURCE = 'default';
                return io.print('SOURCE => default');
            }
            return io.print('Usage: options <list|set|unset>');
        }
        if (cmd === 'show') {
            const t = sub;
            if (!TABLES[t]) return io.print(`Usage: show <${Object.keys(TABLES).join('|')}>`);
            const rows = state.db[t];
            if (!rows.length) return io.print(`[*] No data returned.`, 'muted');
            asciiTable(['rowid', ...TABLES[t]], rows.map((r, i) => [i + 1, ...TABLES[t].map((c) => r[c])])).forEach((l) => io.print(l));
            io.print(`[*] ${rows.length} rows returned`, 'muted');
            return;
        }
        if (cmd === 'db') {
            if (sub === 'insert' && rest[0] === 'domains' && isDomain(rest[1] || '')) {
                insert(state, 'domains', { domain: rest[1].toLowerCase(), module: 'user_defined' });
                save(state);
                return io.print(`[*] 1 rows affected.`, 'ok');
            }
            if (sub === 'delete' && TABLES[rest[0]]) {
                const n = state.db[rest[0]].length;
                state.db[rest[0]] = [];
                save(state);
                return io.print(`[*] ${n} rows affected.`, 'ok');
            }
            return io.print('Usage: db insert domains <domain> | db delete <table>');
        }
        if (cmd === 'run') return this.run(io, state);
        if (cmd === 'workspaces') return io.print('[*] Web edition uses a single workspace: default (stored in this browser).', 'muted');
        io.print(`[!] Invalid command: ${c0}. Type help.`, 'bad');
    },

    async run(io, state) {
        if (!state.module) return io.print('[!] Load a module first: modules load <path>', 'bad');
        const path = state.module;
        const m = MODULES[path];
        const short = path.split('/').pop();

        if (m.report) {
            if (path === 'reporting/csv') download('recon-ng-hosts.csv', toCsv(state.db.hosts.length ? state.db.hosts : [{ host: '', ip_address: '', module: '' }]), 'text/csv');
            else download('recon-ng-workspace.json', JSON.stringify(state.db, null, 2), 'application/json');
            return io.print('[*] Report generated.', 'ok');
        }

        const values = sourceValues(state, m);
        if (!values.length) return io.print(`[!] No inputs: set SOURCE or add rows to the ${m.source} table first.`, 'bad');
        if (state.options.SOURCE !== 'default' && m.input === 'domain' && isDomain(values[0])) insert(state, 'domains', { domain: values[0].toLowerCase(), module: 'user_defined' });

        let added = 0;
        const add = (table, row) => {
            if (insert(state, table, { ...row, module: short })) {
                added++;
                const first = TABLES[table].filter((c) => c !== 'module').map((c) => `${pad(`[${c === 'ip_address' ? 'ip' : c}]`, 10)} ${row[c] ?? ''}`);
                io.print(`[*] ${first.join('   ')}`, 'ok');
            }
        };
        const banner = (v) => {
            io.print('');
            io.print('-'.repeat(Math.min(60, v.length + 4)), 'muted');
            io.print(v.toUpperCase(), 'accent');
            io.print('-'.repeat(Math.min(60, v.length + 4)), 'muted');
        };

        try {
            if (path.startsWith('recon/domains-hosts/')) {
                const b = short === 'hackertarget' ? 'hackertarget' : 'crtsh';
                for (const d of values) {
                    banner(d);
                    const r = await api(`/api/osint/domain/?d=${encodeURIComponent(d)}&b=${b}`);
                    if (r.sources[b] !== 'ok') io.print(`[!] ${r.sources[b]}`, 'warn');
                    r.hosts.forEach((h) => (h.ips.length ? h.ips.forEach((ip) => add('hosts', { host: h.host, ip_address: ip })) : add('hosts', { host: h.host })));
                }
            } else if (short === 'resolve') {
                for (let i = 0; i < values.length; i += 50) {
                    const r = await api(`/api/osint/resolve/?h=${values.slice(i, i + 50).join(',')}`);
                    for (const [host, ips] of Object.entries(r.results)) {
                        if (!ips.length) {
                            io.print(`[*] ${host} => no record`, 'muted');
                            continue;
                        }
                        state.db.hosts = state.db.hosts.filter((x) => !(x.host === host && !x.ip_address));
                        ips.forEach((ip) => add('hosts', { host, ip_address: ip }));
                    }
                }
            } else if (short === 'shodan_ip') {
                const ips = values.slice(0, 20);
                if (values.length > 20) io.print(`[*] ${values.length} IPs; querying the first 20`, 'muted');
                for (const ip of ips) {
                    banner(ip);
                    const r = await api(`/api/osint/ip/?ip=${ip}`).catch((e) => (io.print(`[!] ${e.message}`, 'warn'), null));
                    if (!r?.internetdb) {
                        io.print('[*] No data.', 'muted');
                        continue;
                    }
                    const host = state.db.hosts.find((h) => h.ip_address === ip)?.host || r.internetdb.hostnames[0] || '';
                    r.internetdb.ports.forEach((p) => add('ports', { ip_address: ip, host, port: p }));
                    r.internetdb.vulns.forEach((v) => add('vulnerabilities', { host: host || ip, reference: v }));
                }
            } else if (short === 'whois_pocs') {
                for (const d of values) {
                    banner(d);
                    const r = await api(`/api/osint/rdap/?q=${d}`);
                    r.contacts.filter((c) => c.email).forEach((c) => add('contacts', { email: c.email, name: c.name || c.org || '' }));
                    if (!r.contacts.some((c) => c.email)) io.print('[*] No points of contact published (likely privacy-redacted).', 'muted');
                }
            } else if (short === 'rdap_netblock') {
                for (const ip of values.slice(0, 10)) {
                    banner(ip);
                    const r = await api(`/api/osint/rdap/?q=${ip}`).catch((e) => (io.print(`[!] ${e.message}`, 'warn'), null));
                    if (r) (r.cidrs.length ? r.cidrs : [r.range]).filter(Boolean).forEach((c) => add('netblocks', { netblock: c, org: r.org || r.name || '' }));
                }
            }
        } catch (e) {
            io.print(`[!] ${e.message}`, 'bad');
        }
        save(state);
        io.print('');
        io.print('-------', 'muted');
        io.print('SUMMARY', 'accent');
        io.print('-------', 'muted');
        io.print(`[*] ${added} total (${added} new) records found.`, 'ok');
        io.exports({ 'recon-ng-workspace.json': () => JSON.stringify(state.db, null, 2), 'recon-ng-hosts.csv': () => toCsv(state.db.hosts.length ? state.db.hosts : [{ host: '' }]) });
    }
};
