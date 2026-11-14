// Server-side lookup primitives shared by the /api/osint/* routes.
// Every source here is passive: public datasets (CT logs, Shodan's existing
// scans, RDAP, HackerTarget) plus ordinary DNS resolution.

import { promises as dns } from 'dns';
import { fetchWithTimeout } from './server';

// Short timeouts so a whole request stays inside a 10s serverless limit.
const resolver = new dns.Resolver({ timeout: 2000, tries: 1 });

export async function safe(fn, fallback) {
    try {
        return await fn();
    } catch {
        return fallback;
    }
}

export async function dnsRecords(domain) {
    const [A, AAAA, MX, NS, TXT, CAA, SOA, DMARC] = await Promise.all([
        safe(() => resolver.resolve4(domain), []),
        safe(() => resolver.resolve6(domain), []),
        safe(() => resolver.resolveMx(domain), []),
        safe(() => resolver.resolveNs(domain), []),
        safe(() => resolver.resolveTxt(domain), []),
        safe(() => resolver.resolveCaa(domain), []),
        safe(() => resolver.resolveSoa(domain), null),
        safe(() => resolver.resolveTxt(`_dmarc.${domain}`), [])
    ]);
    return {
        A,
        AAAA,
        MX: MX.sort((a, b) => a.priority - b.priority).map((m) => `${m.priority} ${m.exchange}`),
        NS,
        TXT: TXT.map((c) => c.join('')),
        CAA: CAA.map((c) => Object.entries(c).map(([k, v]) => `${k}=${v}`).join(' ')),
        SOA: SOA ? `${SOA.nsname} ${SOA.hostmaster}` : null,
        DMARC: DMARC.map((c) => c.join('')).filter((t) => t.startsWith('v=DMARC'))
    };
}

export async function crtsh(domain) {
    const res = await fetchWithTimeout(`https://crt.sh/?q=%25.${encodeURIComponent(domain)}&output=json`, { timeoutMs: 7000 });
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

export async function hackertarget(domain) {
    const res = await fetchWithTimeout(`https://api.hackertarget.com/hostsearch/?q=${encodeURIComponent(domain)}`, { timeoutMs: 6500 });
    const text = await res.text();
    if (!res.ok || /^error|API count exceeded/i.test(text)) throw new Error(text.slice(0, 100) || `HTTP ${res.status}`);
    return text
        .split('\n')
        .map((l) => l.trim())
        .filter((l) => l.includes(','))
        .map((l) => {
            const [host, ip] = l.split(',');
            return { host: host.toLowerCase(), ip };
        });
}

export async function resolveMany(hosts, cap = 80) {
    const out = {};
    await Promise.all(hosts.slice(0, cap).map(async (h) => (out[h] = await safe(() => resolver.resolve4(h), []))));
    return out;
}

/** theHarvester-style harvest. sources: subset of ['crtsh','hackertarget','dns'] */
export async function harvestDomain(domain, sources = ['crtsh', 'hackertarget', 'dns'], limit = 500) {
    const status = {};
    const want = (s) => sources.includes(s);
    const [records, ct, ht] = await Promise.all([
        want('dns') ? dnsRecords(domain) : null,
        want('crtsh')
            ? crtsh(domain).then(
                  (v) => ((status.crtsh = 'ok'), v),
                  (e) => ((status.crtsh = e.message), { subdomains: [], emails: [] })
              )
            : { subdomains: [], emails: [] },
        want('hackertarget')
            ? hackertarget(domain).then(
                  (v) => ((status.hackertarget = 'ok'), v),
                  (e) => ((status.hackertarget = e.message), [])
              )
            : []
    ]);
    if (records) status.dns = 'ok';

    const hosts = new Map();
    for (const s of ct.subdomains) hosts.set(s, { host: s, ips: [], sources: ['crtsh'] });
    for (const { host, ip } of ht) {
        const h = hosts.get(host) || { host, ips: [], sources: [] };
        if (ip && !h.ips.includes(ip)) h.ips.push(ip);
        if (!h.sources.includes('hackertarget')) h.sources.push('hackertarget');
        hosts.set(host, h);
    }
    const unresolved = [...hosts.values()].filter((h) => !h.ips.length).map((h) => h.host);
    const resolved = await resolveMany(unresolved, 80);
    for (const [h, ips] of Object.entries(resolved)) hosts.get(h).ips = ips;

    const emails = new Set(ct.emails);
    const re = /[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,}/gi;
    if (records) {
        [...records.TXT, ...records.DMARC].forEach((t) => (t.match(re) || []).forEach((e) => emails.add(e.toLowerCase())));
        if (records.SOA) {
            const hm = records.SOA.split(' ')[1];
            if (hm && hm.includes('.')) emails.add(hm.replace('.', '@'));
        }
    }
    const list = [...hosts.values()].sort((a, b) => a.host.localeCompare(b.host)).slice(0, limit);
    return { domain, sources: status, records, hosts: list, emails: [...emails].sort() };
}

export async function internetdb(ip) {
    const r = await fetchWithTimeout(`https://internetdb.shodan.io/${ip}`, { timeoutMs: 7000 });
    if (r.status === 404) return null;
    if (!r.ok) throw new Error(`InternetDB HTTP ${r.status}`);
    return r.json();
}

export async function shodanApi(path, params = {}) {
    const key = process.env.SHODAN_API_KEY;
    if (!key) throw new Error('SHODAN_API_KEY not set on the server');
    const qs = new URLSearchParams({ ...params, key });
    const r = await fetchWithTimeout(`https://api.shodan.io${path}?${qs}`, { timeoutMs: 8500 });
    const body = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(body.error || `Shodan HTTP ${r.status}`);
    return body;
}

export async function reverseDns(ip) {
    return safe(() => resolver.reverse(ip), []);
}

// ---------- RDAP (structured WHOIS)

function vcardOf(entity) {
    const out = { roles: entity.roles || [], handle: entity.handle };
    const card = entity.vcardArray?.[1] || [];
    for (const [k, , , v] of card) {
        if (k === 'fn') out.name = v;
        if (k === 'org') out.org = Array.isArray(v) ? v.join(' ') : v;
        if (k === 'email') out.email = String(v).toLowerCase();
        if (k === 'tel') out.tel = String(v).replace(/^tel:/, '');
        if (k === 'adr' && Array.isArray(v)) out.country = v[6] || undefined;
    }
    return out;
}

function flattenEntities(list = [], acc = []) {
    for (const e of list) {
        acc.push(vcardOf(e));
        if (e.entities) flattenEntities(e.entities, acc);
    }
    return acc;
}

export async function rdapDomain(domain) {
    const r = await fetchWithTimeout(`https://rdap.org/domain/${encodeURIComponent(domain)}`, { timeoutMs: 8000 });
    if (!r.ok) throw new Error(`RDAP HTTP ${r.status}`);
    const j = await r.json();
    const ev = Object.fromEntries((j.events || []).map((e) => [e.eventAction, e.eventDate]));
    const contacts = flattenEntities(j.entities);
    return {
        domain: j.ldhName?.toLowerCase() || domain,
        registrar: contacts.find((c) => c.roles.includes('registrar'))?.name || null,
        created: ev.registration || null,
        updated: ev['last changed'] || null,
        expires: ev.expiration || null,
        status: j.status || [],
        nameservers: (j.nameservers || []).map((n) => n.ldhName?.toLowerCase()).filter(Boolean),
        contacts: contacts.filter((c) => !c.roles.includes('registrar') || c.email),
        emails: [...new Set(contacts.map((c) => c.email).filter(Boolean))]
    };
}

export async function rdapIp(ip) {
    const r = await fetchWithTimeout(`https://rdap.org/ip/${encodeURIComponent(ip)}`, { timeoutMs: 8000 });
    if (!r.ok) throw new Error(`RDAP HTTP ${r.status}`);
    const j = await r.json();
    const cidrs = (j.cidr0_cidrs || []).map((c) => `${c.v4prefix || c.v6prefix}/${c.length}`);
    const contacts = flattenEntities(j.entities);
    return {
        ip,
        name: j.name || null,
        handle: j.handle || null,
        range: j.startAddress && j.endAddress ? `${j.startAddress} - ${j.endAddress}` : null,
        cidrs,
        country: j.country || null,
        org: contacts.find((c) => c.roles.includes('registrant'))?.name || contacts[0]?.name || null,
        abuse: contacts.filter((c) => c.roles.includes('abuse')).map((c) => c.email).filter(Boolean)
    };
}
