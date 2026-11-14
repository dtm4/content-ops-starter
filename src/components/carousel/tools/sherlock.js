import { tokenize, parseArgs, api, toCsv, download } from '../runtime';

const USERNAME = /^[A-Za-z0-9._-]{2,40}$/;

export default {
    id: 'sherlock',
    n: '04',
    name: 'Sherlock',
    color: '#e8b84a',
    subtitle: 'Username enumeration across 34 sites',
    example: 'sherlock johndoe',
    comment: 'username enumeration (web: 34 sites · cli kit: 400+)',
    usage: [
        ['--print-all', 'also show sites where it was not found'],
        ['--site', 'limit to one site (repeatable)'],
        ['--timeout', 'per-request timeout (seconds)'],
        ['--csv', 'export results']
    ],
    overview:
        "Sherlock hunts a username across many networks at once. Hand it a handle and it checks GitHub, Reddit, social and gaming sites in parallel, surfacing candidate profiles to verify across one person's online presence.",

    async exec(line, io) {
        const argv = tokenize(line);
        if (!/^sherlock$/i.test(argv[0] || '')) return io.print(`zsh: command not found: ${argv[0]}. Try: ${this.example}`, 'bad');
        const { opts, rest, unknown } = parseArgs(argv.slice(1), { 'print-all': 'flag', 'print-found': 'flag', site: 'multi', timeout: 'value', csv: 'flag', h: 'flag', help: 'flag' });
        if (opts.h || opts.help || !rest.length) {
            io.print('usage: sherlock USERNAME [USERNAME ...] [--print-all] [--site SITE] [--timeout SECONDS] [--csv]');
            return;
        }
        unknown.forEach((u) => io.print(`[!] ignoring unsupported option ${u}`, 'warn'));
        const all = [];
        for (const user of rest) {
            if (!USERNAME.test(user)) {
                io.print(`[!] skipping "${user}": use 2-40 letters, digits, . _ -`, 'warn');
                continue;
            }
            io.print(`[*] Checking username ${user} on:`, 'accent');
            const qs = new URLSearchParams({ u: user });
            (opts.site || []).forEach((s) => qs.append('site', s));
            if (opts.timeout) qs.set('timeout', opts.timeout);
            let d;
            try {
                d = await api(`/api/osint/username/?${qs}`);
            } catch (e) {
                io.print(`[!] ${e.message}`, 'bad');
                continue;
            }
            io.print('');
            for (const r of d.results) {
                if (r.status === 'found') io.print(`[+] ${r.site}: ${r.url}`, 'ok', r.url);
                else if (opts['print-all']) io.print(r.status === 'not_found' ? `[-] ${r.site}: Not Found!` : `[-] ${r.site}: ${r.status === 'unknown' ? `Blocked / rate-limited (HTTP ${r.http}), check manually` : 'Error'}`, r.status === 'not_found' ? 'muted' : 'warn');
                all.push({ username: user, name: r.site, url_user: r.url, exists: r.status, http_status: r.http, response_time_ms: r.ms });
            }
            io.print('');
            io.print(`[*] Search completed with ${d.found} results`, 'accent');
            if (!opts['print-all']) io.print('    (add --print-all to list misses and blocked checks)', 'muted');
        }
        if (!all.length) return;
        const name = `${rest[0]}${rest.length > 1 ? '-and-more' : ''}.csv`;
        if (opts.csv) {
            download(name, toCsv(all), 'text/csv');
            io.print(`[*] Saved ${name}`, 'ok');
        }
        io.exports({ [name]: () => toCsv(all) });
    }
};
