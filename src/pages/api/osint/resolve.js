import { rateLimit, onlyGet, isDomain } from '../../../utils/osint/server';
import { resolveMany } from '../../../utils/osint/lib';

// GET /api/osint/resolve?h=a.example.com,b.example.com  (max 50 hosts)

export default async function handler(req, res) {
    if (!onlyGet(req, res)) return;
    if (!rateLimit(req, res, { key: 'resolve', limit: 20 })) return;
    const hosts = String(req.query.h || '')
        .split(',')
        .map((h) => h.trim().toLowerCase())
        .filter(isDomain)
        .slice(0, 50);
    if (!hosts.length) return res.status(400).json({ error: 'Pass one or more hostnames: ?h=a.example.com,b.example.com' });
    res.status(200).json({ results: await resolveMany(hosts, 50) });
}
