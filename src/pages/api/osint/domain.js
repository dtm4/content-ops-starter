import { promises as dns } from 'dns';
import { rateLimit, fetchWithTimeout, onlyGet, isDomain } from '../../../utils/osint/server';

// GET /api/osint/domain?d=example.com
// theHarvester / recon-ng style passive recon:
//   - DNS records (A, AAAA, MX, NS, TXT, CAA)
//   - subdomains from certificate transparency (crt.sh)
//   - host/IP pairs from HackerTarget hostsearch (free tier, keyless, ~50 req/day)
//   - email addresses seen in TXT/SOA/CT data
// Nothing is sent to the target itself except ordinary DNS resolution.

async function safe(fn, fallback) {
    try {
        return await fn();
    } catch {
        return fallback;
    }
}

async function dnsRecords(domain) {
    const [A, AAAA, MX, NS, TXT, CAA, SOA] = await Promise.all([
        safe(() => dns.resolve4(domain), []),
        safe(() => dns.resolve6(domain), []),
        safe(() => dns.resolveMx(domain), []),
        safe(() => dns.resolveNs(domain), []),
        safe(() => dns.resolveTxt(domain), []),
        safe(() => dns.resolveCaa(domain), []),
        safe(() => dns.resolveSoa(domain), null)
    ]);
    return {
        A,
        AAAA,
        MX: MX.sort((a, b) => a.priority - b.priority).map((m) => `${m.priority} ${m.exchange}`),
        NS,
        TXT: TXT.map((chunks) => chunks.join('')),
        CAA: CAA.map((c) => Object.entries(c).map(([k, v]) => `${k}=${v}`).join(' ')),
        SOA: SOA ? `${SOA.nsname} ${SOA.hostmaster}` : null
    };
}

async function crtsh(domain) {
    const res = await fetchWithTimeout(`https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`, { timeoutMs: 20000 });
    if (!res.ok) throw new Error(`crt.sh HTTP ${res.status}`);
    const rows = await res.json();
    const names = new Set();
    const emails = new Set();
    for (const row of rows) {
        for (const n of String(row.name_value || '').split('\n')) {
            const name = n.trim().toLowerCase().replace(/^\*\./, '');
            if (name.includes('@')) emails.add(name);
            else if (name === domain || name.endsWith(`.${domain}`)) names.add(name);
        }
    }
    return { subdomains: [...names], emails: [...emails] };
}

async function hackertarget(domain) {
    const res = await fetchWithTimeout(`https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(domain)}`, { timeoutMs: 15000 });
    const text = await res.text();
    if (!res.ok || /error|API count exceeded/i.test(text)) throw new Error(text.slice(0, 120) || `HTTP ${res.status}`);
    return text
        .split('\n')
        .map((l) => l.trim())
        .filter(Boolean)
        .map((l) => {
            const [host, ip] = l.split(',');
            return { host: host.toLowerCase(), ip };
        });
}

export default async function handler(req, res) {
    if (!onlyGet(req, res)) return;
    if (!rateLimit(req, res, { key: 'domain', limit: 6 })) return;

    const domain = String(req.query.d || '').trim().toLowerCase().replace(/^https?:\/\//, '').replace(/\/.*$/, '');
    if (!isDomain(domain)) return res.status(400).json({ error: 'Enter a valid domain, e.g. example.com' });

    const sources = {};
    const [records, ct, ht] = await Promise.all([
        dnsRecords(domain),
        crtsh(domain).then(
            (v) => ((sources.crtsh = 'ok'), v),
            (e) => ((sources.crtsh = e.message), { subdomains: [], emails: [] })
        ),
        hackertarget(domain).then(
            (v) => ((sources.hackertarget = 'ok'), v),
            (e) => ((sources.hackertarget = e.message), [])
        )
    ]);

    // Merge hosts from both sources, then resolve the ones without an IP (capped).
    const hosts = new Map();
    for (const s of ct.subdomains) hosts.set(s, { host: s, ips: [], sources: ['crt.sh'] });
    for (const { host, ip } of ht) {
        const h = hosts.get(host) || { host, ips: [], sources: [] };
        if (ip && !h.ips.includes(ip)) h.ips.push(ip);
        if (!h.sources.includes('hackertarget')) h.sources.push('hackertarget');
        hosts.set(host, h);
    }
    const unresolved = [...hosts.values()].filter((h) => h.ips.length === 0).slice(0, 60);
    await Promise.all(
        unresolved.map(async (h) => {
            h.ips = await safe(() => dns.resolve4(h.host), []);
        })
    );

    const emailRe = /[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi;
    const emails = new Set(ct.emails);
    for (const t of records.TXT) (t.match(emailRe) || []).forEach((e) => emails.add(e.toLowerCase()));
    if (records.SOA) {
        const hm = records.SOA.split(' ')[1];
        if (hm) emails.add(hm.replace('.', '@'));
    }

    const hostList = [...hosts.values()].sort((a, b) => a.host.localeCompare(b.host));
    res.setHeader('Cache-Control', 'no-store');
    res.status(200).json({
        domain,
        sources,
        records,
        hosts: hostList,
        live: hostList.filter((h) => h.ips.length).length,
        emails: [...emails].sort()
    });
}
