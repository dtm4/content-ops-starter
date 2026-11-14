import { rateLimit, onlyGet, isDomain } from '../../../utils/osint/server';
import { harvestDomain } from '../../../utils/osint/lib';

// GET /api/osint/domain?d=example.com[&b=crtsh,hackertarget,dns|all][&l=500]
// theHarvester-style passive harvest: CT subdomains, HackerTarget host/IP pairs,
// DNS records, and emails seen in those sources.

const SOURCES = ['crtsh', 'hackertarget', 'dns'];

export default async function handler(req, res) {
    if (!onlyGet(req, res)) return;
    if (!rateLimit(req, res, { key: 'domain', limit: 12 })) return;

    const domain = String(req.query.d || '')
        .trim()
        .toLowerCase()
        .replace(/^https?:\/\//, '')
        .replace(/\/.*$/, '');
    if (!isDomain(domain)) return res.status(400).json({ error: 'Enter a valid domain, e.g. example.com' });

    const b = String(req.query.b || 'all').toLowerCase();
    const sources = b === 'all' ? SOURCES : b.split(',').filter((s) => SOURCES.includes(s));
    if (!sources.length) return res.status(400).json({ error: `Unknown source. Use: ${SOURCES.join(', ')} or all` });
    const limit = Math.min(Math.max(parseInt(req.query.l, 10) || 500, 1), 2000);

    const data = await harvestDomain(domain, sources, limit);
    res.setHeader('Cache-Control', 'no-store');
    res.status(200).json({ ...data, live: data.hosts.filter((h) => h.ips.length).length });
}
