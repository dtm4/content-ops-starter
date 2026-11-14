import { tokenize, api, pad, isIp, isDomain } from '../runtime';

export default {
    id: 'shodan',
    n: '05',
    name: 'Shodan',
    color: '#3fb950',
    subtitle: 'Search engine for exposed devices',
    example: 'shodan host 1.1.1.1',
    comment: 'search engine for exposed devices',
    usage: [
        ['host', 'all info for an IP'],
        ['domain', 'subdomains & DNS'],
        ['search', 'query the database'],
        ['count', 'number of matches']
    ],
    overview:
        "Shodan scans the whole internet so you don't have to. Query an IP, domain or service and it returns open ports, banners and software versions: the public-facing attack surface, searchable like Google.",

    async exec(line, io) {
        const argv = tokenize(line);
        if (!/^shodan$/i.test(argv[0] || '')) return io.print(`zsh: command not found: ${argv[0]}. Try: ${this.example}`, 'bad');
        const [cmd, ...args] = argv.slice(1);
        const q = args.join(' ');

        if (!cmd || cmd === '-h' || cmd === '--help' || cmd === 'help') {
            io.print('Usage: shodan COMMAND [ARGS]');
            [['host', 'View all available information for an IP address'], ['domain', 'View all available information for a domain'], ['search', 'Search the Shodan database (API key)'], ['count', 'Returns the number of results for a search (API key)']].forEach(([c, d]) => io.print(`  ${pad(c, 10)}${d}`));
            return;
        }

        if (cmd === 'host') {
            if (!isIp(q)) return io.print('Error: Invalid IP address. Usage: shodan host 198.51.100.23', 'bad');
            const r = await api(`/api/osint/ip/?ip=${q}`);
            const idb = r.internetdb;
            const sh = r.shodan;
            io.print(q, 'accent');
            const kv = (k, v) => v && io.print(`${pad(k + ':', 25)}${v}`);
            kv('Hostnames', [...new Set([...(idb?.hostnames || []), ...r.reverse])].join(';'));
            if (sh) {
                kv('City', sh.city);
                kv('Country', sh.country);
                kv('Organization', sh.org);
                kv('ISP', sh.isp);
                kv('ASN', sh.asn);
                kv('Operating System', sh.os);
                kv('Updated', sh.last_update);
            }
            if (!idb && !sh) {
                io.print('No information available for that IP.', 'muted');
                if (r.sources.internetdb !== 'no data') io.print(`(InternetDB: ${r.sources.internetdb})`, 'warn');
                return;
            }
            const ports = sh ? [...new Set(sh.services.map((s) => s.port))] : idb.ports;
            kv('Number of open ports', String(ports.length));
            if (idb?.tags?.length) kv('Tags', idb.tags.join(', '));
            if (idb?.vulns?.length) {
                io.print(`${pad('Vulnerabilities:', 25)}${idb.vulns.slice(0, 1).join('')}`, 'bad');
                idb.vulns.slice(1).forEach((v) => io.print(`${' '.repeat(25)}${v}`, 'bad'));
            }
            io.print('');
            io.print('Ports:');
            if (sh) {
                for (const s of sh.services) {
                    io.print(`  ${pad(`${s.port}/${s.transport}`, 10)}${[s.product, s.version && `(${s.version})`].filter(Boolean).join(' ')}`, 'ok');
                    s.banner.split('\n').slice(0, 4).forEach((l) => l.trim() && io.print(`        |-- ${l.trim().slice(0, 100)}`, 'muted'));
                }
            } else {
                idb.ports.forEach((p) => io.print(`  ${p}/tcp`, 'ok'));
                if (idb.cpes.length) {
                    io.print('');
                    io.print('Software (CPE):');
                    idb.cpes.forEach((c) => io.print(`  ${c}`));
                }
                io.print('');
                io.print('Source: Shodan InternetDB (free). Set SHODAN_API_KEY on the server for banners, org and geo.', 'muted');
            }
            io.exports({ [`shodan-${q}.json`]: () => JSON.stringify(r, null, 2) });
            return;
        }

        if (cmd === 'domain') {
            if (!isDomain(q)) return io.print('Error: Invalid domain. Usage: shodan domain example.com', 'bad');
            const r = await api(`/api/osint/shodan/?cmd=domain&q=${encodeURIComponent(q)}`);
            io.print(q.toUpperCase(), 'accent');
            if (r.tags.length) io.print(r.tags.join(', '), 'muted');
            io.print('');
            r.records.forEach((x) => io.print(`${pad(x.sub, 28)}${pad(x.type, 8)}${x.value}`, x.value === '(unresolved)' ? 'muted' : 'plain'));
            io.print('');
            io.print(`Source: ${r.source}`, 'muted');
            io.exports({ [`shodan-domain-${q}.json`]: () => JSON.stringify(r, null, 2) });
            return;
        }

        if (cmd === 'search' || cmd === 'count') {
            if (!q) return io.print(`Usage: shodan ${cmd} QUERY   e.g. shodan ${cmd} "product:nginx country:DE"`, 'bad');
            try {
                const r = await api(`/api/osint/shodan/?cmd=${cmd}&q=${encodeURIComponent(q)}`);
                if (cmd === 'count') {
                    io.print(String(r.total), 'accent');
                    for (const [facet, vals] of Object.entries(r.facets || {})) {
                        io.print('');
                        io.print(`Top ${facet}:`, 'muted');
                        vals.forEach((v) => io.print(`  ${pad(v.value, 30)}${v.count}`));
                    }
                } else {
                    io.print(`${r.total} results (showing ${r.matches.length})`, 'accent');
                    r.matches.forEach((m) => io.print(`${pad(m.ip, 16)}${pad(m.port, 7)}${pad((m.hostnames || [])[0] || '', 30)}${[m.product, m.version].filter(Boolean).join(' ')} · ${m.org || ''}`));
                    io.exports({ [`shodan-search.json`]: () => JSON.stringify(r, null, 2) });
                }
            } catch (e) {
                io.print(`Error: ${e.message}`, 'bad');
                if (e.body?.needsKey) io.print(`Search and count need a Shodan API key on the server. Meanwhile run it on shodan.io: https://www.shodan.io/search?query=${encodeURIComponent(q)}`, 'warn', `https://www.shodan.io/search?query=${encodeURIComponent(q)}`);
            }
            return;
        }
        io.print(`Error: No such command '${cmd}'. Try: host, domain, search, count`, 'bad');
    }
};
