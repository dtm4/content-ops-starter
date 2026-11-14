import { tokenize, parseArgs, api, download, toCsv, isDomain } from '../runtime';

const SOURCES = ['crtsh', 'hackertarget', 'dns'];
const CLI_ONLY = ['anubis', 'baidu', 'bevigil', 'bing', 'brave', 'censys', 'certspotter', 'criminalip', 'dnsdumpster', 'duckduckgo', 'fullhunt', 'github-code', 'hunter', 'intelx', 'otx', 'rapiddns', 'securitytrails', 'shodan', 'subdomaincenter', 'threatminer', 'urlscan', 'virustotal', 'yahoo', 'zoomeye'];

function toXml(d) {
    const esc = (s) => String(s).replace(/[<>&"]/g, (c) => ({ '<': '&lt;', '>': '&gt;', '&': '&amp;', '"': '&quot;' })[c]);
    return [
        '<?xml version="1.0" encoding="UTF-8"?>',
        `<theHarvester target="${esc(d.domain)}">`,
        ...d.emails.map((e) => `  <email>${esc(e)}</email>`),
        ...d.hosts.map((h) => `  <host><hostname>${esc(h.host)}</hostname>${h.ips.map((ip) => `<ip>${esc(ip)}</ip>`).join('')}</host>`),
        '</theHarvester>'
    ].join('\n');
}

export default {
    id: 'theharvester',
    n: '01',
    name: 'theHarvester',
    color: '#58a6ff',
    subtitle: 'Email & subdomain OSINT harvester',
    example: 'theHarvester -d example.com -b all',
    comment: 'email & subdomain osint harvester',
    usage: [
        ['-d', 'Target domain or company'],
        ['-b', 'Data source (or all)'],
        ['-l', 'Limit results (default 500)'],
        ['-f', 'Save to file (XML + JSON)']
    ],
    overview:
        'theHarvester is where most engagements begin. Point it at a domain and it pulls emails, subdomains, hosts and IPs from public sources, mapping the external attack surface without sending a packet to the target.',

    async exec(line, io) {
        const argv = tokenize(line);
        if (!/^theharvester$/i.test(argv[0] || '')) return io.print(`zsh: command not found: ${argv[0]}. Try: ${this.example}`, 'bad');
        const { opts, unknown } = parseArgs(argv.slice(1), { d: 'value', domain: 'value', b: 'value', source: 'value', l: 'value', limit: 'value', f: 'value', filename: 'value', h: 'flag', help: 'flag' });
        if (opts.h || opts.help) {
            io.print('usage: theHarvester -d DOMAIN [-b SOURCE] [-l LIMIT] [-f FILENAME]');
            io.print(`sources (web edition): ${SOURCES.join(', ')}, all`, 'muted');
            return;
        }
        unknown.forEach((u) => io.print(`[!] ignoring unsupported option ${u}`, 'warn'));
        const domain = String(opts.d || opts.domain || '').toLowerCase();
        if (!isDomain(domain)) return io.print('theHarvester: error: -d DOMAIN is required (e.g. -d example.com)', 'bad');

        const requested = String(opts.b || opts.source || 'all').toLowerCase().split(',');
        const sources = requested.includes('all') ? SOURCES : requested.filter((s) => SOURCES.includes(s));
        requested.filter((s) => s !== 'all' && !SOURCES.includes(s)).forEach((s) => io.print(`[!] ${s}: ${CLI_ONLY.includes(s) ? 'available in the CLI kit (needs network/API key), skipped' : 'unknown source, skipped'}`, 'warn'));
        if (!sources.length) return io.print('[!] no usable sources. Use crtsh, hackertarget, dns or all.', 'bad');
        const limit = parseInt(opts.l || opts.limit, 10) || 500;

        io.print('*******************************************************************', 'accent');
        io.print('*  theHarvester · web edition · passive sources only              *', 'accent');
        io.print('*******************************************************************', 'accent');
        io.print(`[*] Target: ${domain}`);
        io.print(`[*] Searching ${sources.join(', ')} ...`, 'muted');

        const d = await api(`/api/osint/domain/?d=${encodeURIComponent(domain)}&b=${sources.join(',')}&l=${limit}`);
        for (const [src, st] of Object.entries(d.sources)) io.print(`[*] ${src}: ${st}`, st === 'ok' ? 'ok' : 'warn');

        const ips = [...new Set([...(d.records?.A || []), ...d.hosts.flatMap((h) => h.ips)])].sort();
        io.print('');
        io.print(`[*] IPs found: ${ips.length}`, 'accent');
        io.print('-------------------');
        ips.forEach((ip) => io.print(ip));

        io.print('');
        io.print(`[*] Emails found: ${d.emails.length}`, 'accent');
        io.print('----------------------');
        if (!d.emails.length) io.print('No emails found.', 'muted');
        d.emails.forEach((e) => io.print(e));

        io.print('');
        io.print(`[*] Hosts found: ${d.hosts.length}`, 'accent');
        io.print('---------------------');
        d.hosts.forEach((h) => io.print(h.ips.length ? `${h.host}:${h.ips.join(', ')}` : h.host, h.ips.length ? 'plain' : 'muted'));

        if (d.records && (d.records.MX.length || d.records.NS.length || d.records.TXT.length)) {
            io.print('');
            io.print('[*] DNS records', 'accent');
            io.print('---------------------');
            d.records.NS.forEach((v) => io.print(`NS   ${v}`));
            d.records.MX.forEach((v) => io.print(`MX   ${v}`));
            d.records.TXT.forEach((v) => io.print(`TXT  ${v}`));
            d.records.DMARC.forEach((v) => io.print(`DMARC ${v}`));
        }

        const rows = d.hosts.map((h) => ({ host: h.host, ips: h.ips, sources: h.sources }));
        if (opts.f || opts.filename) {
            const base = String(opts.f || opts.filename).replace(/\.(json|xml)$/i, '');
            download(`${base}.json`, JSON.stringify(d, null, 2), 'application/json');
            download(`${base}.xml`, toXml(d), 'application/xml');
            io.print(`[*] Reports written to ${base}.json and ${base}.xml`, 'ok');
        }
        io.exports({ [`${domain}-hosts.csv`]: () => toCsv(rows), [`${domain}.json`]: () => JSON.stringify(d, null, 2) });
    }
};
