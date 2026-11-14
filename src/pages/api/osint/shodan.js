import { rateLimit, onlyGet, isDomain } from '../../../utils/osint/server';
import { shodanApi, harvestDomain } from '../../../utils/osint/lib';

// GET /api/osint/shodan?cmd=search|count|domain&q=...
// search / count need SHODAN_API_KEY. domain uses Shodan's DNS API when a key
// is set and falls back to CT + DNS without one. (host lives in /api/osint/ip.)

export default async function handler(req, res) {
    if (!onlyGet(req, res)) return;
    if (!rateLimit(req, res, { key: 'shodan', limit: 15 })) return;
    const cmd = String(req.query.cmd || '');
    const q = String(req.query.q || '').trim();
    if (!q || q.length > 300) return res.status(400).json({ error: 'Missing query.' });
    const hasKey = Boolean(process.env.SHODAN_API_KEY);

    try {
        if (cmd === 'count') {
            const r = await shodanApi('/shodan/host/count', { query: q, facets: 'country:5,port:5,org:5' });
            return res.status(200).json({ total: r.total, facets: r.facets });
        }
        if (cmd === 'search') {
            const r = await shodanApi('/shodan/host/search', { query: q, minify: 'true' });
            return res.status(200).json({
                total: r.total,
                matches: (r.matches || []).slice(0, 50).map((m) => ({
                    ip: m.ip_str,
                    port: m.port,
                    org: m.org,
                    hostnames: m.hostnames,
                    country: m.location?.country_name,
                    product: m.product,
                    version: m.version
                }))
            });
        }
        if (cmd === 'domain') {
            if (!isDomain(q)) return res.status(400).json({ error: 'Enter a valid domain.' });
            if (hasKey) {
                const r = await shodanApi(`/dns/domain/${q}`);
                return res.status(200).json({
                    source: 'shodan',
                    domain: q,
                    tags: r.tags || [],
                    records: (r.data || []).map((d) => ({ sub: d.subdomain, type: d.type, value: d.value, last_seen: d.last_seen }))
                });
            }
            const h = await harvestDomain(q, ['crtsh', 'dns']);
            const records = [];
            for (const [type, vals] of Object.entries(h.records || {})) for (const v of [].concat(vals || [])) records.push({ sub: '', type, value: v });
            for (const host of h.hosts) {
                const sub = host.host === q ? '' : host.host.slice(0, -(q.length + 1));
                if (host.ips.length) host.ips.forEach((ip) => records.push({ sub, type: 'A', value: ip }));
                else records.push({ sub, type: 'CT', value: '(unresolved)' });
            }
            return res.status(200).json({ source: 'crt.sh + dns (no SHODAN_API_KEY)', domain: q, tags: [], records });
        }
        return res.status(400).json({ error: 'cmd must be search, count or domain' });
    } catch (e) {
        return res.status(hasKey ? 502 : 501).json({ error: e.message, needsKey: !hasKey });
    }
}
