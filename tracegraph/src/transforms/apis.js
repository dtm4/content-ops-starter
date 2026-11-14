// Transforms backed by keyed third-party APIs. Each declares `requires`; the UI shows
// them greyed out until the matching env var is set on the server.
import { getJson } from '../lib/http.js';
import { isDomain } from '../entities.js';
import { ent, clean } from './util.js';

const env = (k) => process.env[k];
const vt = (path) => getJson(`https://www.virustotal.com/api/v3/${path}`, { headers: { 'x-apikey': env('VT_API_KEY') }, allow404: true });

function vtStats(attrs = {}) {
  const s = attrs.last_analysis_stats || {};
  return clean({
    vt_malicious: s.malicious,
    vt_suspicious: s.suspicious,
    vt_harmless: s.harmless,
    vt_reputation: attrs.reputation,
    vt_categories: attrs.categories ? [...new Set(Object.values(attrs.categories))].join(', ') : undefined
  });
}

export const apiTransforms = [
  // ---------- Shodan ----------
  {
    id: 'shodan.host',
    name: 'Shodan: open ports, hostnames, CVEs',
    input: ['ip'],
    requires: ['SHODAN_API_KEY'],
    async run(ip) {
      const d = await getJson(`https://api.shodan.io/shodan/host/${ip}?key=${env('SHODAN_API_KEY')}`, { allow404: true });
      if (!d) return [];
      const out = [];
      for (const s of d.data || []) {
        out.push(ent('service', `${ip}:${s.port}/${s.transport || 'tcp'}`, 'Exposes', clean({
          port: s.port, product: s.product, version: s.version, banner: s.data?.slice(0, 300), seen: s.timestamp
        })));
      }
      for (const h of d.hostnames || []) if (isDomain(h)) out.push(ent('domain', h, 'Hostname (Shodan)'));
      for (const v of Object.keys(d.vulns || {})) out.push(ent('note', v, 'Vulnerable to', { source: 'Shodan' }));
      if (d.asn) out.push(ent('asn', d.asn, 'Announced by'));
      return { entities: out, sourceProps: clean({ shodan_org: d.org, shodan_isp: d.isp, os: d.os, last_update: d.last_update }) };
    }
  },
  {
    id: 'shodan.domain',
    name: 'Shodan: subdomains & DNS',
    input: ['domain'],
    requires: ['SHODAN_API_KEY'],
    async run(domain) {
      const d = await getJson(`https://api.shodan.io/dns/domain/${domain}?key=${env('SHODAN_API_KEY')}`, { allow404: true });
      if (!d) return [];
      const out = (d.subdomains || []).slice(0, 300).map((s) => ent('domain', `${s}.${domain}`, 'Subdomain (Shodan)'));
      for (const r of d.data || []) {
        if (r.subdomain) continue;
        if (r.type === 'A' || r.type === 'AAAA') out.push(ent('ip', r.value, `${r.type} (Shodan)`));
      }
      return out;
    }
  },
  // ---------- VirusTotal ----------
  {
    id: 'vt.domain',
    name: 'VirusTotal: reputation & passive DNS',
    input: ['domain'],
    requires: ['VT_API_KEY'],
    async run(domain) {
      const [info, res] = await Promise.all([vt(`domains/${domain}`), vt(`domains/${domain}/resolutions?limit=40`)]);
      const out = (res?.data || []).map((r) =>
        ent('ip', r.attributes.ip_address, 'Resolved to (VT)', clean({ last_seen: r.attributes.date && new Date(r.attributes.date * 1000).toISOString().slice(0, 10) }))
      );
      return { entities: out, sourceProps: vtStats(info?.data?.attributes) };
    }
  },
  {
    id: 'vt.ip',
    name: 'VirusTotal: reputation & hosted domains',
    input: ['ip'],
    requires: ['VT_API_KEY'],
    async run(ip) {
      const [info, res] = await Promise.all([vt(`ip_addresses/${ip}`), vt(`ip_addresses/${ip}/resolutions?limit=40`)]);
      const out = (res?.data || [])
        .filter((r) => isDomain(r.attributes.host_name))
        .map((r) => ent('domain', r.attributes.host_name, 'Hosted (VT)'));
      return { entities: out, sourceProps: vtStats(info?.data?.attributes) };
    }
  },
  // ---------- Hunter.io ----------
  {
    id: 'hunter.domain',
    name: 'Hunter: emails & people at domain',
    input: ['domain'],
    requires: ['HUNTER_API_KEY'],
    async run(domain) {
      const d = await getJson(`https://api.hunter.io/v2/domain-search?domain=${domain}&limit=100&api_key=${env('HUNTER_API_KEY')}`);
      const data = d.data || {};
      const out = [];
      for (const e of data.emails || []) {
        const name = [e.first_name, e.last_name].filter(Boolean).join(' ');
        out.push(ent('email', e.value, 'Employee email', clean({ name, position: e.position, confidence: e.confidence, linkedin: e.linkedin })));
        if (name) out.push(ent('person', name, 'Works at', clean({ position: e.position, email: e.value })));
      }
      if (data.organization) out.push(ent('organization', data.organization, 'Owned by'));
      return { entities: out, sourceProps: clean({ email_pattern: data.pattern }) };
    }
  },
  {
    id: 'hunter.verify',
    name: 'Hunter: verify deliverability',
    input: ['email'],
    requires: ['HUNTER_API_KEY'],
    async run(email) {
      const d = await getJson(`https://api.hunter.io/v2/email-verifier?email=${encodeURIComponent(email)}&api_key=${env('HUNTER_API_KEY')}`);
      const v = d.data || {};
      return { entities: [], sourceProps: clean({ deliverability: v.status, hunter_score: v.score, disposable: v.disposable, webmail: v.webmail }) };
    }
  }
];
