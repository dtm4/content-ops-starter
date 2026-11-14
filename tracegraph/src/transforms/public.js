// Keyless public alternatives to the key-gated transforms in apis.js.
// These services are free and unauthenticated, so expect rate limits and older data.
import net from 'node:net';
import { getJson, request, HttpError } from '../lib/http.js';
import { safeFetch } from '../lib/safe-fetch.js';
import { isDomain } from '../entities.js';
import { resolve } from './dns.js';
import { extractFromHtml } from './web.js';
import { ent, clean } from './util.js';

async function getText(url, opts = {}) {
  const res = await request(url, opts);
  if (res.status === 404) return '';
  if (!res.ok) throw new HttpError(res.status, url, await res.text().catch(() => ''));
  return res.text();
}

/** Pulls hostnames out of a plain-text listing, ignoring comment lines. */
export function parseHostList(text) {
  const out = new Set();
  for (const line of String(text).split('\n')) {
    if (/^\s*([;#]|\/\/)/.test(line)) continue;
    for (const tok of line.split(/[\s,|]+/)) {
      const h = tok.trim().toLowerCase().replace(/\.$/, '');
      if (isDomain(h)) out.add(h);
    }
  }
  return [...out];
}

const DISPOSABLE = new Set(['mailinator.com', 'guerrillamail.com', '10minutemail.com', 'tempmail.com', 'temp-mail.org', 'yopmail.com', 'trashmail.com', 'sharklasers.com', 'getnada.com', 'throwawaymail.com', 'maildrop.cc', 'dispostable.com']);
const CONTACT_PATH = /(contact|about|team|staff|people|impressum|imprint|kontakt|support|legal)/i;
const GUESS_PATHS = ['/contact', '/contact-us', '/about', '/about-us', '/team'];

export const publicTransforms = [
  {
    id: 'internetdb.host',
    name: 'Open ports, hostnames, CVEs [Shodan InternetDB, free]',
    input: ['ip'],
    async run(ip) {
      const d = await getJson(`https://internetdb.shodan.io/${ip}`, { allow404: true });
      if (!d || !Array.isArray(d.ports)) return [];
      const out = d.ports.map((p) => ent('service', `${ip}:${p}/tcp`, 'Exposes', { port: p, source: 'InternetDB' }));
      for (const h of d.hostnames || []) if (isDomain(h)) out.push(ent('domain', h, 'Hostname (InternetDB)'));
      for (const v of (d.vulns || []).slice(0, 100)) out.push(ent('note', v, 'Possibly vulnerable to', { source: 'InternetDB (unverified, version-based)' }));
      return { entities: out, sourceProps: clean({ software: (d.cpes || []).join(', '), tags: (d.tags || []).join(', ') }) };
    }
  },
  {
    id: 'thc.subdomains',
    name: 'To subdomains [ip.thc.org, free]',
    input: ['domain'],
    async run(domain) {
      const text = await getText(`https://ip.thc.org/sb/${encodeURIComponent(domain)}?l=100`);
      return parseHostList(text)
        .filter((h) => h !== domain && h.endsWith(`.${domain}`))
        .map((h) => ent('domain', h, 'Subdomain (THC)'));
    }
  },
  {
    id: 'thc.rdns',
    name: 'To domains hosted on this IP [free]',
    input: ['ip'],
    async run(ip) {
      let hosts = [];
      let firstErr;
      try {
        hosts = parseHostList(await getText(`https://ip.thc.org/${ip}?l=100`)).filter((h) => !/(^|\.)thc\.org$/.test(h));
      } catch (e) {
        firstErr = e;
      }
      if (!hosts.length && net.isIPv4(ip)) {
        try {
          const text = await getText(`https://api.hackertarget.com/reverseiplookup/?q=${ip}`);
          if (/API count exceeded|error/i.test(text.slice(0, 200)) && !parseHostList(text).length) throw new Error(`HackerTarget: ${text.trim().slice(0, 120)}`);
          hosts = parseHostList(text);
        } catch (e) {
          if (firstErr) throw firstErr;
          if (/API count exceeded/.test(e.message)) throw e;
        }
      }
      return hosts.slice(0, 200).map((h) => ent('domain', h, 'Hosted on IP'));
    }
  },
  {
    id: 'otx.domain',
    name: 'Passive DNS & threat reports [AlienVault OTX, free]',
    input: ['domain'],
    async run(domain) {
      const base = `https://otx.alienvault.com/api/v1/indicators/domain/${encodeURIComponent(domain)}`;
      const [pdns, general] = await Promise.all([getJson(`${base}/passive_dns`), getJson(`${base}/general`).catch(() => null)]);
      const seen = new Set();
      const out = [];
      for (const r of pdns.passive_dns || []) {
        if (!net.isIP(r.address || '') || seen.has(r.address)) continue;
        if (r.hostname && r.hostname !== domain) continue;
        seen.add(r.address);
        out.push(ent('ip', r.address, 'Resolved to (OTX)', clean({ first_seen: r.first, last_seen: r.last })));
      }
      return { entities: out.slice(0, 60), sourceProps: clean({ otx_threat_reports: general?.pulse_info?.count }) };
    }
  },
  {
    id: 'otx.ip',
    name: 'Passive DNS & threat reports [AlienVault OTX, free]',
    input: ['ip'],
    async run(ip) {
      const base = `https://otx.alienvault.com/api/v1/indicators/${net.isIPv6(ip) ? 'IPv6' : 'IPv4'}/${ip}`;
      const [pdns, general] = await Promise.all([getJson(`${base}/passive_dns`), getJson(`${base}/general`).catch(() => null)]);
      const hosts = [...new Set((pdns.passive_dns || []).map((r) => String(r.hostname || '').toLowerCase()).filter(isDomain))];
      return {
        entities: hosts.slice(0, 100).map((h) => ent('domain', h, 'Resolved here (OTX)')),
        sourceProps: clean({ otx_threat_reports: general?.pulse_info?.count, otx_reputation: general?.reputation })
      };
    }
  },
  {
    id: 'mail.verify',
    name: 'Check mail domain: MX & disposable [free]',
    input: ['email'],
    async run(email) {
      const domain = email.split('@')[1];
      const mx = (await resolve(domain, 'MX')).map((r) => r.split(/\s+/)[1]).filter((h) => h && h !== '.').map((h) => h.replace(/\.$/, '').toLowerCase());
      let disposable = DISPOSABLE.has(domain);
      if (!disposable) {
        const k = await getJson(`https://open.kickbox.com/v1/disposable/${encodeURIComponent(domain)}`).catch(() => null);
        if (k && typeof k.disposable === 'boolean') disposable = k.disposable;
      }
      return {
        entities: mx.filter(isDomain).map((h) => ent('domain', h, 'Mail handled by')),
        sourceProps: { domain_accepts_mail: mx.length > 0, disposable_address: disposable, mailbox_verified: 'not checked (needs Hunter key)' }
      };
    }
  },
  {
    id: 'web.crawl',
    name: 'To emails & phones on contact/about pages [crawl]',
    input: ['domain'],
    async run(domain) {
      const home = await safeFetch(`https://${domain}/`).catch(() => safeFetch(`http://${domain}/`));
      const origin = new URL(home.url).origin;
      const pages = new Set();
      for (const m of home.body.matchAll(/href\s*=\s*["']([^"'#]+)["']/gi)) {
        try {
          const u = new URL(m[1], home.url);
          if (u.origin === origin && CONTACT_PATH.test(u.pathname)) pages.add(u.origin + u.pathname);
        } catch { /* bad href */ }
      }
      for (const p of GUESS_PATHS) if (pages.size < 6) pages.add(origin + p);
      const emails = new Map();
      const phones = new Map();
      const collect = (body, url) => {
        const d = extractFromHtml(body, url);
        for (const e of d.emails) if (!emails.has(e)) emails.set(e, url);
        for (const p of d.phones) if (!phones.has(p)) phones.set(p, url);
      };
      collect(home.body, home.url);
      const fetched = await Promise.allSettled([...pages].slice(0, 6).map((u) => safeFetch(u, { timeoutMs: 8000 })));
      let crawled = 1;
      for (const r of fetched) {
        if (r.status !== 'fulfilled' || r.value.status !== 200) continue;
        crawled++;
        collect(r.value.body, r.value.url);
      }
      return {
        entities: [
          ...[...emails].slice(0, 100).map(([e, url]) => ent('email', e, 'Found on site', { found_on: url })),
          ...[...phones].slice(0, 30).map(([p, url]) => ent('phone', p, 'Found on site', { found_on: url }))
        ],
        sourceProps: { pages_crawled: crawled }
      };
    }
  }
];
