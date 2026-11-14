import { rateLimit, onlyGet, isDomain, isPublicIPv4 } from '../../../utils/osint/server';
import { rdapDomain, rdapIp } from '../../../utils/osint/lib';

// GET /api/osint/rdap?q=example.com | 198.51.100.23
// Structured WHOIS (RDAP): registrar, dates, contacts/emails for a domain;
// owning netblock, org and abuse contacts for an IP.

export default async function handler(req, res) {
    if (!onlyGet(req, res)) return;
    if (!rateLimit(req, res, { key: 'rdap', limit: 20 })) return;
    const q = String(req.query.q || '').trim().toLowerCase();
    try {
        if (isPublicIPv4(q)) return res.status(200).json({ type: 'ip', ...(await rdapIp(q)) });
        if (isDomain(q)) return res.status(200).json({ type: 'domain', ...(await rdapDomain(q)) });
        return res.status(400).json({ error: 'Enter a domain or public IPv4 address.' });
    } catch (e) {
        return res.status(502).json({ error: `RDAP lookup failed: ${e.message}` });
    }
}
