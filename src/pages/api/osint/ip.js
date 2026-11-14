import { promises as dns } from 'dns';
import { rateLimit, fetchWithTimeout, onlyGet, isPublicIPv4 } from '../../../utils/osint/server';

// GET /api/osint/ip?ip=1.2.3.4
// Shodan-style host lookup.
//   - Always: Shodan InternetDB (free, keyless) -> ports, hostnames, CPEs, tags, CVEs
//   - If SHODAN_API_KEY is set: full Shodan host record (banners, org, ASN, geo)
//   - Reverse DNS via the server's resolver
// All data comes from Shodan's existing scans; nothing is sent to the target.

export default async function handler(req, res) {
    if (!onlyGet(req, res)) return;
    if (!rateLimit(req, res, { key: 'ip', limit: 15 })) return;

    const ip = String(req.query.ip || '').trim();
    if (!isPublicIPv4(ip)) return res.status(400).json({ error: 'Enter a public IPv4 address.' });

    const out = { ip, sources: {}, reverse: [], internetdb: null, shodan: null };

    const tasks = [
        dns.reverse(ip).then(
            (v) => (out.reverse = v),
            () => {}
        ),
        fetchWithTimeout(`https://internetdb.shodan.io/${ip}`, { timeoutMs: 10000 })
            .then(async (r) => {
                if (r.status === 404) {
                    out.sources.internetdb = 'no data';
                    return;
                }
                if (!r.ok) throw new Error(`HTTP ${r.status}`);
                out.internetdb = await r.json();
                out.sources.internetdb = 'ok';
            })
            .catch((e) => (out.sources.internetdb = e.message))
    ];

    const key = process.env.SHODAN_API_KEY;
    if (key) {
        tasks.push(
            fetchWithTimeout(`https://api.shodan.io/shodan/host/${ip}?key=${encodeURIComponent(key)}`, { timeoutMs: 15000 })
                .then(async (r) => {
                    const body = await r.json().catch(() => ({}));
                    if (!r.ok) throw new Error(body.error || `HTTP ${r.status}`);
                    out.shodan = {
                        org: body.org,
                        isp: body.isp,
                        asn: body.asn,
                        country: body.country_name,
                        city: body.city,
                        os: body.os,
                        last_update: body.last_update,
                        services: (body.data || []).map((d) => ({
                            port: d.port,
                            transport: d.transport,
                            product: d.product,
                            version: d.version,
                            banner: String(d.data || '').slice(0, 600)
                        }))
                    };
                    out.sources.shodan = 'ok';
                })
                .catch((e) => (out.sources.shodan = e.message))
        );
    } else {
        out.sources.shodan = 'SHODAN_API_KEY not set (InternetDB only)';
    }

    await Promise.all(tasks);
    res.setHeader('Cache-Control', 'no-store');
    res.status(200).json(out);
}
