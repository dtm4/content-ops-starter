// Registration data (RDAP), geolocation, routing (RIPEstat) and certificate transparency.
import { getJson } from '../lib/http.js';
import { isDomain, isEmail } from '../entities.js';
import { ent, clean } from './util.js';

const REDACTED = /redact|privacy|private|protected|withheld|not disclosed|gdpr|proxy|whoisguard|contact privacy|data protected/i;

/** Flattens an RDAP jCard into { fn, org, emails[], phones[], address, country }. */
export function parseVcard(vcardArray) {
  const out = { emails: [], phones: [] };
  const props = Array.isArray(vcardArray) && Array.isArray(vcardArray[1]) ? vcardArray[1] : [];
  for (const [name, params, , value] of props) {
    if (name === 'fn') out.fn = String(value).trim();
    else if (name === 'org') out.org = String(Array.isArray(value) ? value[0] : value).trim();
    else if (name === 'email') out.emails.push(String(value).trim());
    else if (name === 'tel') out.phones.push(String(value).replace(/^tel:/, '').trim());
    else if (name === 'adr') {
      if (params && params.label) out.address = String(params.label).replace(/\n/g, ', ');
      else if (Array.isArray(value)) out.address = value.flat().filter(Boolean).join(', ');
      if (Array.isArray(value) && value[6]) out.country = value[6];
    }
  }
  return out;
}

/** Walks RDAP entities (including nested ones) yielding { roles, card, handle }. */
export function* walkEntities(entities = []) {
  for (const e of entities) {
    yield { roles: e.roles || [], card: parseVcard(e.vcardArray), handle: e.handle, publicIds: e.publicIds || [] };
    if (e.entities) yield* walkEntities(e.entities);
  }
}

function events(obj) {
  return Object.fromEntries((obj.events || []).map((e) => [e.eventAction.replace(/\s+/g, '_'), e.eventDate]));
}

/** Turns RDAP contacts into organization / person / email / phone entities. */
export function contactsToEntities(entities) {
  const out = [];
  for (const { roles, card, publicIds } of walkEntities(entities)) {
    const role = roles.join('/') || 'contact';
    const label = role.charAt(0).toUpperCase() + role.slice(1);
    const orgName = card.org || (roles.includes('registrar') ? card.fn : null);
    if (orgName && !REDACTED.test(orgName)) {
      const ianaId = publicIds.find((p) => /iana/i.test(p.type))?.identifier;
      out.push(ent('organization', orgName, label, clean({ iana_id: ianaId, address: card.address, country: card.country })));
    } else if (card.fn && !REDACTED.test(card.fn)) {
      out.push(ent('person', card.fn, label, clean({ address: card.address })));
    }
    for (const e of card.emails) if (isEmail(e) && !REDACTED.test(e)) out.push(ent('email', e, `${label} email`));
    for (const p of card.phones) if (p && !REDACTED.test(p)) out.push(ent('phone', p, `${label} phone`));
  }
  return out;
}

export const rdapTransforms = [
  {
    id: 'whois.domain',
    name: 'WHOIS / RDAP registration',
    input: ['domain'],
    async run(domain) {
      const data = await getJson(`https://rdap.org/domain/${encodeURIComponent(domain)}`, { allow404: true });
      if (!data) throw new Error('No RDAP record (subdomains have none; try the registered domain)');
      const ev = events(data);
      const out = contactsToEntities(data.entities);
      for (const ns of data.nameservers || []) if (ns.ldhName) out.push(ent('domain', ns.ldhName.toLowerCase(), 'NS (registry)'));
      return {
        entities: out,
        sourceProps: clean({
          registered: ev.registration,
          expires: ev.expiration,
          updated: ev.last_changed,
          status: (data.status || []).join(', '),
          rdap_handle: data.handle
        })
      };
    }
  },
  {
    id: 'whois.ip',
    name: 'To netblock & owner [RDAP]',
    input: ['ip', 'netblock'],
    async run(value) {
      const data = await getJson(`https://rdap.org/ip/${value}`);
      const out = [];
      const cidrs = (data.cidr0_cidrs || []).map((c) => `${c.v4prefix || c.v6prefix}/${c.length}`);
      for (const c of cidrs) {
        if (c !== value) out.push(ent('netblock', c, 'Netblock', clean({ name: data.name, handle: data.handle, country: data.country })));
      }
      out.push(...contactsToEntities(data.entities));
      return {
        entities: out,
        sourceProps: clean({ net_name: data.name, net_range: data.startAddress && `${data.startAddress} - ${data.endAddress}`, country: data.country })
      };
    }
  },
  {
    id: 'geo.ip',
    name: 'To location & ASN [GeoIP]',
    input: ['ip'],
    async run(ip) {
      const d = await getJson(`https://ipwho.is/${ip}`);
      if (d.success === false) throw new Error(d.message || 'GeoIP lookup failed');
      const out = [];
      const place = [d.city, d.region, d.country].filter(Boolean).join(', ');
      if (place) out.push(ent('location', place, 'Located in', clean({ latitude: d.latitude, longitude: d.longitude, country_code: d.country_code })));
      const c = d.connection || {};
      if (c.asn) out.push(ent('asn', `AS${c.asn}`, 'Announced by', clean({ holder: c.org })));
      if (c.isp) out.push(ent('organization', c.isp, 'ISP'));
      if (c.domain && isDomain(c.domain)) out.push(ent('domain', c.domain, 'ISP domain'));
      return { entities: out, sourceProps: clean({ geo: place, timezone: d.timezone?.id }) };
    }
  },
  {
    id: 'bgp.ip',
    name: 'To announcing ASN & prefix [RIPEstat]',
    input: ['ip', 'netblock'],
    async run(value) {
      const d = await getJson(`https://stat.ripe.net/data/network-info/data.json?resource=${encodeURIComponent(value)}`);
      const out = (d.data?.asns || []).map((a) => ent('asn', `AS${a}`, 'Announced by'));
      if (d.data?.prefix && d.data.prefix !== value) out.push(ent('netblock', d.data.prefix, 'BGP prefix'));
      return out;
    }
  },
  {
    id: 'bgp.asn',
    name: 'To holder & announced prefixes [RIPEstat]',
    input: ['asn'],
    async run(asn) {
      const [ov, pf] = await Promise.all([
        getJson(`https://stat.ripe.net/data/as-overview/data.json?resource=${asn}`),
        getJson(`https://stat.ripe.net/data/announced-prefixes/data.json?resource=${asn}`)
      ]);
      const out = [];
      const holder = ov.data?.holder;
      if (holder) out.push(ent('organization', holder.replace(/^[A-Z0-9-]+ - /, ''), 'Holder', { as_name: holder }));
      const prefixes = (pf.data?.prefixes || []).map((p) => p.prefix);
      for (const p of prefixes.slice(0, 100)) out.push(ent('netblock', p, 'Announces'));
      return { entities: out, sourceProps: clean({ holder, prefix_count: prefixes.length }) };
    }
  },
  {
    id: 'ct.subdomains',
    name: 'To subdomains [Certificate Transparency]',
    input: ['domain'],
    async run(domain) {
      const rows = await getJson(`https://crt.sh/?q=${encodeURIComponent(`%.${domain}`)}&output=json`, { timeoutMs: 60000 });
      const names = new Map();
      for (const r of rows || []) {
        for (let n of String(r.name_value || '').split('\n')) {
          n = n.trim().toLowerCase().replace(/^\*\./, '');
          if (n !== domain && n.endsWith(`.${domain}`) && isDomain(n) && !names.has(n)) {
            names.set(n, { first_cert: r.not_before, issuer: r.issuer_name });
          }
        }
      }
      return [...names.entries()].slice(0, 300).map(([n, p]) => ent('domain', n, 'Subdomain (CT)', clean(p)));
    }
  }
];
