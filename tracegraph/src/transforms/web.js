// Website / email pivots. Page fetches go through safeFetch (SSRF-guarded) and are
// cached briefly so the "to emails / to social / to links" transforms share one request.
import crypto from 'node:crypto';
import { safeFetch } from '../lib/safe-fetch.js';
import { getJson } from '../lib/http.js';
import { isDomain, isEmail } from '../entities.js';
import { ent, clean } from './util.js';

const SOCIAL = [
  [/^(?:www\.)?(?:twitter|x)\.com$/, /^\/(?!intent|share|home|search|hashtag|i\/)([A-Za-z0-9_]{1,15})\/?$/, 'X/Twitter'],
  [/^(?:[a-z]+\.)?facebook\.com$/, /^\/(?!sharer|share|dialog|plugins|tr\b)([A-Za-z0-9.\-]{2,})\/?$/, 'Facebook'],
  [/^(?:www\.)?instagram\.com$/, /^\/(?!p\/|explore)([A-Za-z0-9_.]{1,30})\/?$/, 'Instagram'],
  [/^(?:[a-z]+\.)?linkedin\.com$/, /^\/((?:in|company|school)\/[^/?#]+)\/?/, 'LinkedIn'],
  [/^(?:www\.)?github\.com$/, /^\/(?!sponsors|features|about|login)([A-Za-z0-9-]{1,39})\/?$/, 'GitHub'],
  [/^(?:www\.)?youtube\.com$/, /^\/((?:@|c\/|channel\/|user\/)[^/?#]+)\/?/, 'YouTube'],
  [/^(?:www\.)?tiktok\.com$/, /^\/(@[A-Za-z0-9_.]+)\/?$/, 'TikTok'],
  [/^t\.me$/, /^\/(?!share)([A-Za-z0-9_]{4,})\/?$/, 'Telegram']
];

const NOT_EMAIL_TLD = /\.(png|jpe?g|gif|svg|webp|css|js)$/i;

function decodeEntities(s) {
  return s.replace(/&amp;/g, '&').replace(/&#64;|&commat;/g, '@').replace(/&#46;|&period;/g, '.').replace(/&quot;/g, '"');
}

/** Pure HTML → indicators extraction (exported for tests). */
export function extractFromHtml(html, baseUrl) {
  const base = new URL(baseUrl);
  const baseHost = base.hostname.replace(/^www\./, '');
  const text = decodeEntities(html);
  const out = { emails: new Set(), phones: new Set(), socials: new Map(), domains: new Set(), trackers: new Set() };

  out.title = /<title[^>]*>([^<]*)<\/title>/i.exec(html)?.[1]?.trim().replace(/\s+/g, ' ');
  out.generator = /<meta[^>]+name=["']generator["'][^>]+content=["']([^"']+)/i.exec(html)?.[1];

  for (const m of text.matchAll(/[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,24}/gi)) {
    const e = m[0].toLowerCase().replace(/^[._-]+/, '');
    if (isEmail(e) && !NOT_EMAIL_TLD.test(e) && !/^(?:example|user|name|email|your)@/.test(e)) out.emails.add(e);
  }
  for (const m of text.matchAll(/(?:UA-\d{4,10}-\d{1,4}|\bG-[A-Z0-9]{6,12}\b|\bGTM-[A-Z0-9]{4,9}\b|\bpub-\d{10,20}\b)/g)) {
    out.trackers.add(m[0]);
  }

  for (const m of html.matchAll(/href\s*=\s*["']([^"'#]+)["']/gi)) {
    const href = decodeEntities(m[1].trim());
    if (/^tel:/i.test(href)) {
      const p = decodeURIComponent(href.slice(4)).replace(/[^\d+]/g, '');
      if (p.replace(/\D/g, '').length >= 7) out.phones.add(p);
      continue;
    }
    if (/^mailto:/i.test(href)) {
      const e = decodeURIComponent(href.slice(7).split('?')[0]).toLowerCase();
      if (isEmail(e)) out.emails.add(e);
      continue;
    }
    let u;
    try {
      u = new URL(href, base);
    } catch {
      continue;
    }
    if (!/^https?:$/.test(u.protocol)) continue;
    const host = u.hostname.toLowerCase();
    let social = false;
    for (const [hostRe, pathRe, network] of SOCIAL) {
      if (!hostRe.test(host)) continue;
      const pm = pathRe.exec(u.pathname);
      if (pm) {
        const handle = pm[1];
        const url = `https://${host.replace(/^(?:www|m|mobile|[a-z]{2})\./, '')}/${handle}`;
        out.socials.set(url.toLowerCase(), { network, handle });
      }
      social = true;
    }
    const bare = host.replace(/^www\./, '');
    if (!social && bare !== baseHost && !bare.endsWith(`.${baseHost}`) && isDomain(bare)) out.domains.add(bare);
  }
  return out;
}

const cache = new Map();
const TTL = 5 * 60 * 1000;

async function scrape(value, type) {
  const startUrl = type === 'url' ? value : `https://${value}/`;
  const hit = cache.get(startUrl);
  if (hit && Date.now() - hit.at < TTL) return hit.data;
  let res;
  try {
    res = await safeFetch(startUrl);
  } catch (e) {
    if (type !== 'domain' || e.code === 'EBLOCKED') throw e;
    res = await safeFetch(`http://${value}/`); // some sites still have no TLS
  }
  const data = { ...extractFromHtml(res.body, res.url), finalUrl: res.url, status: res.status, server: res.headers.server };
  cache.set(startUrl, { at: Date.now(), data });
  if (cache.size > 500) cache.delete(cache.keys().next().value);
  return data;
}

function pageProps(d) {
  return clean({ page_title: d.title, http_status: d.status, final_url: d.finalUrl, server: d.server, generator: d.generator });
}

const webInput = ['domain', 'url'];

export const webTransforms = [
  {
    id: 'web.emails',
    name: 'To email addresses [website]',
    input: webInput,
    async run(v, type) {
      const d = await scrape(v, type);
      return { entities: [...d.emails].slice(0, 100).map((e) => ent('email', e, 'Found on site')), sourceProps: pageProps(d) };
    }
  },
  {
    id: 'web.social',
    name: 'To social profiles [website]',
    input: webInput,
    async run(v, type) {
      const d = await scrape(v, type);
      return {
        entities: [...d.socials.entries()].map(([url, s]) => ent('social', url, s.network, { network: s.network, handle: s.handle })),
        sourceProps: pageProps(d)
      };
    }
  },
  {
    id: 'web.links',
    name: 'To linked domains [website]',
    input: webInput,
    async run(v, type) {
      const d = await scrape(v, type);
      return { entities: [...d.domains].slice(0, 100).map((h) => ent('domain', h, 'Links to')), sourceProps: pageProps(d) };
    }
  },
  {
    id: 'web.contact',
    name: 'To phones & tracking IDs [website]',
    input: webInput,
    async run(v, type) {
      const d = await scrape(v, type);
      return {
        entities: [
          ...[...d.phones].map((p) => ent('phone', p, 'Found on site')),
          ...[...d.trackers].map((t) => ent('note', t, 'Tracking ID', { hint: 'Search this ID to find sites run by the same owner' }))
        ],
        sourceProps: pageProps(d)
      };
    }
  },
  {
    id: 'web.redirect',
    name: 'To final URL [follow redirects]',
    input: webInput,
    async run(v, type) {
      const d = await scrape(v, type);
      const out = [ent('url', d.finalUrl, 'Serves')];
      const host = new URL(d.finalUrl).hostname;
      if (type === 'domain' && host !== v && isDomain(host)) out.push(ent('domain', host, 'Redirects to'));
      return { entities: out, sourceProps: pageProps(d) };
    }
  },
  {
    id: 'convert.domain',
    name: 'To domain',
    input: ['email', 'url'],
    async run(v, type) {
      const host = type === 'email' ? v.split('@')[1] : new URL(v).hostname;
      return isDomain(host) ? [ent('domain', host, type === 'email' ? 'Mail domain' : 'Hosted on')] : [];
    }
  },
  {
    id: 'gravatar.email',
    name: 'To Gravatar profile',
    input: ['email'],
    async run(email) {
      const hash = crypto.createHash('md5').update(email.trim().toLowerCase()).digest('hex');
      const data = await getJson(`https://en.gravatar.com/${hash}.json`, { allow404: true });
      const p = data?.entry?.[0];
      if (!p) return [];
      const out = [];
      const name = p.name?.formatted || p.displayName;
      if (name) out.push(ent('person', name, 'Gravatar name'));
      for (const a of p.accounts || []) if (a.url) out.push(ent('social', a.url, a.shortname || 'Account', { network: a.shortname }));
      for (const u of p.urls || []) if (u.value) out.push(ent('url', u.value, 'Gravatar link'));
      return { entities: out, sourceProps: clean({ gravatar: p.profileUrl, location: p.currentLocation }) };
    }
  }
];
