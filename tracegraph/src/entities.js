import net from 'node:net';

// Entity types the graph understands. `glyph` and `color` are used by the UI.
export const ENTITY_TYPES = {
  domain: { label: 'Domain / Host', glyph: 'D', color: '#4f9cf9' },
  ip: { label: 'IP Address', glyph: 'IP', color: '#f2994a' },
  email: { label: 'Email', glyph: '@', color: '#27ae60' },
  url: { label: 'URL', glyph: 'URL', color: '#9b51e0' },
  organization: { label: 'Organization', glyph: 'ORG', color: '#eb5757' },
  person: { label: 'Person', glyph: 'P', color: '#f2c94c' },
  phone: { label: 'Phone', glyph: 'TEL', color: '#56ccf2' },
  location: { label: 'Location', glyph: 'LOC', color: '#6fcf97' },
  asn: { label: 'AS Number', glyph: 'AS', color: '#bb6bd9' },
  netblock: { label: 'Netblock', glyph: 'NET', color: '#f2994a' },
  social: { label: 'Social Profile', glyph: 'SOC', color: '#2d9cdb' },
  service: { label: 'Service / Port', glyph: 'SVC', color: '#828282' },
  note: { label: 'Note / Record', glyph: 'TXT', color: '#bdbdbd' }
};

const DOMAIN_RE = /^(?=.{1,253}$)(?!-)(?:[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$/i;
const EMAIL_RE = /^[a-z0-9._%+'-]+@([a-z0-9.-]+\.[a-z]{2,63})$/i;

export function isDomain(v) {
  return DOMAIN_RE.test(v) && !net.isIP(v);
}

export function isEmail(v) {
  return EMAIL_RE.test(v);
}

/**
 * Normalize and validate a user/transform supplied value for a type.
 * Returns the normalized value, or throws an Error with a readable message.
 */
export function normalizeValue(type, raw) {
  if (!ENTITY_TYPES[type]) throw new Error(`Unknown entity type "${type}"`);
  let v = String(raw ?? '').trim();
  if (!v) throw new Error('Value is empty');
  if (v.length > 2048) throw new Error('Value is too long');
  switch (type) {
    case 'domain':
      v = v.toLowerCase().replace(/\.$/, '').replace(/^\*\./, '');
      if (!isDomain(v)) throw new Error(`"${raw}" is not a valid domain name`);
      return v;
    case 'ip':
      if (!net.isIP(v)) throw new Error(`"${raw}" is not a valid IP address`);
      return v.toLowerCase();
    case 'email':
      v = v.toLowerCase().replace(/^mailto:/, '');
      if (!isEmail(v)) throw new Error(`"${raw}" is not a valid email address`);
      return v;
    case 'url': {
      let u;
      try {
        u = new URL(/^[a-z]+:\/\//i.test(v) ? v : `https://${v}`);
      } catch {
        throw new Error(`"${raw}" is not a valid URL`);
      }
      if (!['http:', 'https:'].includes(u.protocol)) throw new Error('Only http(s) URLs are supported');
      u.hash = '';
      return u.toString();
    }
    case 'asn': {
      const m = /^(?:as)?\s*(\d{1,10})$/i.exec(v);
      if (!m) throw new Error(`"${raw}" is not a valid AS number`);
      return `AS${m[1]}`;
    }
    case 'netblock': {
      const [addr, len] = v.split('/');
      const fam = net.isIP(addr);
      const n = Number(len);
      if (!fam || !Number.isInteger(n) || n < 0 || n > (fam === 4 ? 32 : 128)) {
        throw new Error(`"${raw}" is not a valid CIDR netblock`);
      }
      return `${addr.toLowerCase()}/${n}`;
    }
    default:
      return v;
  }
}
