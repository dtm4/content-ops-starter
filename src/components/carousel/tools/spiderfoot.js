import { tokenize, parseArgs, api, toCsv, pad, isIp, isDomain, isEmail } from '../runtime';

// SpiderFoot-style scan orchestrated from the browser: each module is one
// passive API call; results become typed events, then correlation rules run
// over the whole event set.

const MODULES = {
    sfp_dnsresolve: 'DNS records + host resolution',
    sfp_crt: 'Certificate transparency (crt.sh)',
    sfp_hackertarget: 'HackerTarget host search',
    sfp_whois: 'Domain RDAP / WHOIS',
    sfp_shodan: 'Shodan InternetDB (ports, CPEs, CVEs)',
    sfp_netblock: 'IP RDAP: owning netblock + org'
};
const USE_CASES = {
    all: Object.keys(MODULES),
    footprint: Object.keys(MODULES),
    investigate: Object.keys(MODULES),
    passive: ['sfp_crt', 'sfp_hackertarget', 'sfp_whois', 'sfp_shodan', 'sfp_netblock']
};
const RISKY_PORTS = { 21: 'FTP', 23: 'Telnet', 445: 'SMB', 1433: 'MSSQL', 2375: 'Docker API', 3306: 'MySQL', 3389: 'RDP', 5432: 'PostgreSQL', 5900: 'VNC', 6379: 'Redis', 9200: 'Elasticsearch', 11211: 'Memcached', 27017: 'MongoDB' };
const SENSITIVE = /(^|[.-])(dev|staging|stage|test|uat|qa|admin|jenkins|git|gitlab|vpn|internal|intranet|beta|old|backup|db|sql|grafana|kibana|jira|confluence)([.-]|\d|$)/;
const RISK_TONE = { HIGH: 'bad', MEDIUM: 'warn', LOW: 'accent', INFO: 'muted' };

function correlate(ev, ctx) {
    const out = [];
    const by = (t) => ev.filter((e) => e.type === t);
    const add = (risk, rule, detail) => out.push({ risk, rule, detail });

    if (ctx.records) {
        const spf = ctx.records.TXT.find((t) => t.startsWith('v=spf1'));
        if (!spf) add('MEDIUM', 'MISSING_SPF', 'No SPF record: anyone can spoof mail from this domain.');
        else if (/[+?]all\b/.test(spf)) add('HIGH', 'PERMISSIVE_SPF', `SPF ends in a permissive qualifier: ${spf}`);
        if (!ctx.records.DMARC.length) add('MEDIUM', 'MISSING_DMARC', 'No DMARC policy at _dmarc. Spoofed mail is not rejected.');
        else if (/p=none/i.test(ctx.records.DMARC[0])) add('LOW', 'DMARC_MONITOR_ONLY', `DMARC is p=none (monitor only): ${ctx.records.DMARC[0]}`);
        if (!ctx.records.CAA.length) add('INFO', 'NO_CAA', 'No CAA record: any CA may issue certificates for this domain.');
    }
    const sens = by('INTERNET_NAME').filter((e) => SENSITIVE.test(e.data.split('.')[0] + '.'));
    if (sens.length) add('MEDIUM', 'SENSITIVE_HOSTNAMES', `${sens.length} dev/admin-style hosts are public: ${sens.slice(0, 6).map((e) => e.data).join(', ')}${sens.length > 6 ? '…' : ''}`);
    const unresolved = by('INTERNET_NAME_UNRESOLVED');
    if (unresolved.length) add('LOW', 'STALE_DNS_CANDIDATES', `${unresolved.length} names from CT/DNS no longer resolve. Check for dangling records / takeover risk.`);
    const cves = by('VULNERABILITY_CVE');
    if (cves.length) add('HIGH', 'KNOWN_CVES', `${cves.length} CVE(s) inferred from banners on ${new Set(cves.map((c) => c.src)).size} IP(s): ${[...new Set(cves.map((c) => c.data))].slice(0, 8).join(', ')}`);
    const risky = by('TCP_PORT_OPEN').filter((e) => RISKY_PORTS[e.data.split(':')[1]]);
    if (risky.length) add('HIGH', 'RISKY_SERVICE_EXPOSED', risky.map((e) => `${e.data} (${RISKY_PORTS[e.data.split(':')[1]]})`).join(', '));
    const emails = by('EMAILADDR');
    if (emails.length) add('LOW', 'EMAILS_EXPOSED', `${emails.length} address(es) public. Phishing / password-spray targets: ${emails.slice(0, 5).map((e) => e.data).join(', ')}`);
    if (ctx.whois?.expires) {
        const days = Math.round((new Date(ctx.whois.expires) - Date.now()) / 864e5);
        if (days < 60) add(days < 0 ? 'HIGH' : 'MEDIUM', 'DOMAIN_EXPIRING', `Registration expires in ${days} days (${ctx.whois.expires.slice(0, 10)}).`);
    }
    const nb = new Set(by('NETBLOCK_OWNER').map((e) => e.data.split(' · ')[1]).filter(Boolean));
    if (nb.size > 1) add('INFO', 'MULTIPLE_HOSTING_PROVIDERS', `Infrastructure spans ${nb.size} organisations: ${[...nb].join(', ')}`);
    return out.sort((a, b) => ['HIGH', 'MEDIUM', 'LOW', 'INFO'].indexOf(a.risk) - ['HIGH', 'MEDIUM', 'LOW', 'INFO'].indexOf(b.risk));
}

export default {
    id: 'spiderfoot',
    n: '02',
    name: 'SpiderFoot',
    color: '#b48cff',
    subtitle: 'OSINT automation + correlation engine',
    example: 'spiderfoot -s example.com -u footprint -o tab',
    comment: 'osint automation + correlation engine',
    usage: [
        ['-s', 'Target (domain/IP/email)'],
        ['-u', 'Use case (footprint/passive)'],
        ['-m', 'Modules to enable'],
        ['-o', 'Output (tab/csv/json)']
    ],
    overview:
        'Point SpiderFoot at a domain, IP or email and it fans out across its modules, then a correlation engine stitches the hits into one map of names, IPs, emails, ports and leaks, ranked by risk.',

    async exec(line, io) {
        const argv = tokenize(line);
        if (!/^(spiderfoot|sf\.py|sf)$/i.test(argv[0] || '')) return io.print(`zsh: command not found: ${argv[0]}. Try: ${this.example}`, 'bad');
        const { opts, unknown } = parseArgs(argv.slice(1), { s: 'value', u: 'value', m: 'value', o: 'value', M: 'flag', h: 'flag', help: 'flag' });
        if (opts.M) {
            Object.entries(MODULES).forEach(([k, v]) => io.print(`${pad(k, 20)}${v}`));
            return;
        }
        if (opts.h || opts.help) {
            io.print('usage: spiderfoot -s TARGET [-u all|footprint|investigate|passive] [-m mod1,mod2] [-o tab|csv|json] [-M]');
            return;
        }
        unknown.forEach((u) => io.print(`[!] ignoring unsupported option ${u}`, 'warn'));
        const target = String(opts.s || '').trim().toLowerCase();
        const kind = isIp(target) ? 'ip' : isEmail(target) ? 'email' : isDomain(target) ? 'domain' : null;
        if (!kind) return io.print('spiderfoot: -s TARGET must be a domain, IPv4 address or email', 'bad');
        const useCase = String(opts.u || 'all').toLowerCase();
        if (!USE_CASES[useCase]) return io.print(`spiderfoot: unknown use case "${useCase}" (all, footprint, investigate, passive)`, 'bad');
        let mods = USE_CASES[useCase];
        if (opts.m) {
            const want = String(opts.m).split(',').map((m) => m.trim());
            want.filter((m) => !MODULES[m]).forEach((m) => io.print(`[!] module ${m} not available in web edition (see -M)`, 'warn'));
            mods = want.filter((m) => MODULES[m]);
        }
        const on = (m) => mods.includes(m);
        const fmt = String(opts.o || 'tab').toLowerCase();

        const events = [];
        const seen = new Set();
        const emit = (type, data, module, src = target) => {
            const k = `${type}|${data}`;
            if (seen.has(k)) return;
            seen.add(k);
            events.push({ type, data, module, src });
            if (fmt === 'tab') io.print(`${pad(module, 18)}${pad(type, 26)}${data}`, type.startsWith('VULN') ? 'bad' : type === 'TCP_PORT_OPEN' ? 'warn' : 'plain');
        };

        io.print(`[*] Scan target: ${target} (${kind}) · use case: ${useCase} · ${mods.length} modules`, 'accent');
        if (fmt === 'tab') {
            io.print(`${pad('Source', 18)}${pad('Type', 26)}Data`, 'muted');
            io.print('-'.repeat(72), 'muted');
        }
        const ctx = {};
        let ips = [];

        if (kind === 'domain' || kind === 'email') {
            const domain = kind === 'email' ? target.split('@')[1] : target;
            if (kind === 'email') {
                emit('EMAILADDR', target, 'sfp_input');
                emit('INTERNET_NAME', domain, 'sfp_input');
            }
            const b = [on('sfp_crt') && kind === 'domain' && 'crtsh', on('sfp_hackertarget') && kind === 'domain' && 'hackertarget', 'dns'].filter(Boolean);
            const [h, w] = await Promise.all([
                api(`/api/osint/domain/?d=${domain}&b=${b.join(',')}`).catch((e) => (io.print(`[!] harvest: ${e.message}`, 'warn'), null)),
                on('sfp_whois') ? api(`/api/osint/rdap/?q=${domain}`).catch((e) => (io.print(`[!] sfp_whois: ${e.message}`, 'warn'), null)) : null
            ]);
            if (h) {
                ctx.records = h.records;
                Object.entries(h.sources).forEach(([s, st]) => st !== 'ok' && io.print(`[!] ${s}: ${st}`, 'warn'));
                h.records.A.forEach((ip) => emit('IP_ADDRESS', ip, 'sfp_dnsresolve', domain));
                h.records.MX.forEach((v) => emit('PROVIDER_MAIL', v.split(' ')[1], 'sfp_dnsresolve', domain));
                h.records.NS.forEach((v) => emit('PROVIDER_DNS', v, 'sfp_dnsresolve', domain));
                h.records.TXT.forEach((v) => emit(v.startsWith('v=spf1') ? 'DNS_SPF' : 'DNS_TEXT', v, 'sfp_dnsresolve', domain));
                h.records.DMARC.forEach((v) => emit('DNS_DMARC', v, 'sfp_dnsresolve', domain));
                for (const host of h.hosts) {
                    const mod = host.sources.includes('crtsh') ? 'sfp_crt' : 'sfp_hackertarget';
                    if (host.ips.length) {
                        emit('INTERNET_NAME', host.host, mod, domain);
                        host.ips.forEach((ip) => emit('IP_ADDRESS', ip, 'sfp_dnsresolve', host.host));
                    } else emit('INTERNET_NAME_UNRESOLVED', host.host, mod, domain);
                }
                h.emails.forEach((e) => emit('EMAILADDR', e, 'sfp_email', domain));
                ips = [...new Set([...h.records.A, ...h.hosts.flatMap((x) => x.ips)])];
            }
            if (w) {
                ctx.whois = w;
                if (w.registrar) emit('DOMAIN_REGISTRAR', w.registrar, 'sfp_whois', domain);
                if (w.created) emit('DOMAIN_WHOIS', `created ${w.created.slice(0, 10)} · expires ${(w.expires || '?').slice(0, 10)}`, 'sfp_whois', domain);
                w.emails.forEach((e) => emit('EMAILADDR', e, 'sfp_whois', domain));
            }
        } else {
            ips = [target];
            emit('IP_ADDRESS', target, 'sfp_input');
        }

        const scanIps = ips.slice(0, 12);
        if (ips.length > scanIps.length) io.print(`[*] ${ips.length} IPs found; enriching the first ${scanIps.length}`, 'muted');
        if (on('sfp_shodan') || kind === 'ip') {
            for (let i = 0; i < scanIps.length; i += 4) {
                await Promise.all(
                    scanIps.slice(i, i + 4).map(async (ip) => {
                        try {
                            const r = await api(`/api/osint/ip/?ip=${ip}`);
                            r.reverse.forEach((n) => emit('INTERNET_NAME', n, 'sfp_dnsresolve', ip));
                            const idb = r.internetdb;
                            if (!idb) return;
                            idb.ports.forEach((p) => emit('TCP_PORT_OPEN', `${ip}:${p}`, 'sfp_shodan', ip));
                            idb.cpes.forEach((c) => emit('SOFTWARE_USED', `${c} @ ${ip}`, 'sfp_shodan', ip));
                            idb.vulns.forEach((v) => emit('VULNERABILITY_CVE', v, 'sfp_shodan', ip));
                            idb.hostnames.forEach((n) => emit('INTERNET_NAME', n, 'sfp_shodan', ip));
                        } catch (e) {
                            io.print(`[!] sfp_shodan ${ip}: ${e.message}`, 'warn');
                        }
                    })
                );
            }
        }
        if (on('sfp_netblock') || kind === 'ip') {
            await Promise.all(
                scanIps.slice(0, 4).map(async (ip) => {
                    try {
                        const r = await api(`/api/osint/rdap/?q=${ip}`);
                        (r.cidrs.length ? r.cidrs : [r.range]).filter(Boolean).forEach((c) => emit('NETBLOCK_OWNER', `${c} · ${r.org || r.name || 'unknown'}`, 'sfp_netblock', ip));
                        r.abuse.forEach((e) => emit('EMAILADDR_ABUSE', e, 'sfp_netblock', ip));
                    } catch (e) {
                        io.print(`[!] sfp_netblock ${ip}: ${e.message}`, 'warn');
                    }
                })
            );
        }

        if (fmt === 'csv') {
            io.print('Source,Type,Data', 'muted');
            events.forEach((e) => io.print(`${e.module},${e.type},"${e.data.replace(/"/g, '""')}"`));
        } else if (fmt === 'json') {
            JSON.stringify(events, null, 2).split('\n').slice(0, 400).forEach((l) => io.print(l));
        }

        const corr = correlate(events, ctx);
        io.print('');
        io.print(`[*] Scan complete: ${events.length} events. Correlations: ${corr.length}`, 'accent');
        io.print('-'.repeat(72), 'muted');
        if (!corr.length) io.print('No correlation rules fired.', 'muted');
        corr.forEach((c) => io.print(`[${c.risk}] ${c.rule}: ${c.detail}`, RISK_TONE[c.risk]));

        const base = target.replace(/[^a-z0-9.@-]/gi, '_');
        io.exports({
            [`spiderfoot-${base}.csv`]: () => toCsv(events.map(({ module, type, data, src }) => ({ module, type, data, source: src }))),
            [`spiderfoot-${base}.json`]: () => JSON.stringify({ target, useCase, events, correlations: corr }, null, 2)
        });
    }
};
