import net from 'node:net';
import { getJson } from '../lib/http.js';
import { isDomain } from '../entities.js';
import { ent } from './util.js';

// DNS over HTTPS (JSON API) so results are the same wherever the server runs.
const RESOLVERS = ['https://cloudflare-dns.com/dns-query', 'https://dns.google/resolve'];
const TYPE_NUM = { A: 1, NS: 2, CNAME: 5, SOA: 6, PTR: 12, MX: 15, TXT: 16, AAAA: 28 };

export async function resolve(name, type) {
  let lastErr;
  for (const base of RESOLVERS) {
    try {
      const data = await getJson(`${base}?name=${encodeURIComponent(name)}&type=${type}`, {
        headers: { accept: 'application/dns-json' }
      });
      return (data.Answer || []).filter((a) => a.type === TYPE_NUM[type]).map((a) => a.data);
    } catch (e) {
      lastErr = e;
    }
  }
  throw lastErr;
}

const stripDot = (s) => s.replace(/\.$/, '').toLowerCase();

export function expandIPv6(ip) {
  let [head, tail] = ip.toLowerCase().split('::');
  const h = head ? head.split(':') : [];
  const t = tail !== undefined && tail ? tail.split(':') : [];
  const missing = 8 - h.length - t.length;
  const groups = tail !== undefined ? [...h, ...Array(missing).fill('0'), ...t] : h;
  return groups.map((g) => g.padStart(4, '0')).join('');
}

export function reverseName(ip) {
  if (net.isIPv4(ip)) return `${ip.split('.').reverse().join('.')}.in-addr.arpa`;
  return `${expandIPv6(ip).split('').reverse().join('.')}.ip6.arpa`;
}

/** Joins the quoted character-strings of a TXT record into one string. */
export function parseTxt(data) {
  const parts = [...data.matchAll(/"((?:[^"\\]|\\.)*)"/g)].map((m) => m[1].replace(/\\(.)/g, '$1'));
  return parts.length ? parts.join('') : data;
}

/** Pulls domains / IPs / netblocks out of an SPF record. */
export function parseSpf(txt, label = 'SPF') {
  const out = [];
  for (const term of txt.split(/\s+/)) {
    const m = /^[+~?-]?(include|redirect|a|mx|exists|ip4|ip6)[:=](.+)$/i.exec(term);
    if (!m) continue;
    const mech = m[1].toLowerCase();
    const val = m[2];
    if (mech === 'ip4' || mech === 'ip6') {
      out.push(val.includes('/') ? ent('netblock', val, `${label} ${mech}`) : ent('ip', val, `${label} ${mech}`));
    } else {
      const d = val.split('/')[0];
      if (isDomain(d)) out.push(ent('domain', d, `${label} ${mech}`));
    }
  }
  return out;
}

export const dnsTransforms = [
  {
    id: 'dns.a',
    name: 'To IP addresses [A/AAAA]',
    input: ['domain'],
    async run(domain) {
      const [a, aaaa] = await Promise.all([resolve(domain, 'A'), resolve(domain, 'AAAA')]);
      return [...a.map((ip) => ent('ip', ip, 'A')), ...aaaa.map((ip) => ent('ip', ip, 'AAAA'))];
    }
  },
  {
    id: 'dns.mx',
    name: 'To mail servers [MX]',
    input: ['domain'],
    async run(domain) {
      const recs = await resolve(domain, 'MX');
      return recs
        .map((r) => r.split(/\s+/))
        .filter(([, host]) => host && host !== '.')
        .map(([prio, host]) => ent('domain', stripDot(host), 'MX', { mx_priority: Number(prio) }));
    }
  },
  {
    id: 'dns.ns',
    name: 'To name servers [NS]',
    input: ['domain'],
    async run(domain) {
      return (await resolve(domain, 'NS')).map((h) => ent('domain', stripDot(h), 'NS'));
    }
  },
  {
    id: 'dns.cname',
    name: 'To canonical name [CNAME]',
    input: ['domain'],
    async run(domain) {
      return (await resolve(domain, 'CNAME')).map((h) => ent('domain', stripDot(h), 'CNAME'));
    }
  },
  {
    id: 'dns.txt',
    name: 'To TXT records (+ SPF pivots)',
    input: ['domain'],
    async run(domain) {
      const txts = (await resolve(domain, 'TXT')).map(parseTxt);
      const out = [];
      for (const t of txts) {
        out.push(ent('note', t.length > 120 ? `${t.slice(0, 117)}...` : t, 'TXT', { full_text: t }));
        if (/^v=spf1/i.test(t)) out.push(...parseSpf(t));
      }
      // DMARC lives on a sub-name; worth surfacing because it often leaks report addresses.
      const dmarc = (await resolve(`_dmarc.${domain}`, 'TXT').catch(() => [])).map(parseTxt);
      for (const d of dmarc) {
        out.push(ent('note', d.length > 120 ? `${d.slice(0, 117)}...` : d, 'DMARC', { full_text: d }));
        for (const m of d.matchAll(/mailto:([^,;\s!]+)/gi)) out.push(ent('email', m[1], 'DMARC report to'));
      }
      return out;
    }
  },
  {
    id: 'dns.ptr',
    name: 'To hostname [reverse DNS]',
    input: ['ip'],
    async run(ip) {
      return (await resolve(reverseName(ip), 'PTR')).map((h) => ent('domain', stripDot(h), 'PTR'));
    }
  }
];
