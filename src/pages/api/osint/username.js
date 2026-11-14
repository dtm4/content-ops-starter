import sites from '../../../utils/osint/sites';
import { rateLimit, fetchWithTimeout, onlyGet, USERNAME_RE } from '../../../utils/osint/server';

// GET /api/osint/username?u=johndoe
// Sherlock-style: probes each site in parallel and classifies the result.

async function checkSite(site, username, timeoutMs = 6000) {
    const target = (site.probe || site.url).replace('{}', encodeURIComponent(username));
    const profile = site.url.replace('{}', encodeURIComponent(username));
    const started = Date.now();
    try {
        const res = await fetchWithTimeout(target, { redirect: 'manual', timeoutMs });
        const ms = Date.now() - started;
        let status;
        if (site.errorType === 'message') {
            if (res.status === 404) status = 'not_found';
            else if (res.status >= 200 && res.status < 300) {
                const body = await res.text();
                status = body.includes(site.errorMsg) || body.trim() === site.errorMsg ? 'not_found' : 'found';
            } else status = 'unknown';
        } else {
            if (res.status >= 200 && res.status < 300) status = 'found';
            else if (res.status === 404 || res.status === 410) status = 'not_found';
            else if (res.status >= 300 && res.status < 400) status = 'not_found'; // redirects usually mean "no such profile"
            else status = 'unknown'; // 403/429 etc: blocked or rate-limited
        }
        return { site: site.name, category: site.category, url: profile, status, http: res.status, ms };
    } catch (e) {
        return { site: site.name, category: site.category, url: profile, status: 'error', http: null, ms: Date.now() - started };
    }
}

export default async function handler(req, res) {
    if (!onlyGet(req, res)) return;
    if (!rateLimit(req, res, { key: 'username', limit: 6 })) return;

    const username = String(req.query.u || '').trim();
    if (!USERNAME_RE.test(username)) {
        return res.status(400).json({ error: 'Username must be 2-40 chars: letters, digits, dot, dash, underscore.' });
    }

    // ?site=GitHub&site=Reddit limits the check; ?timeout=N (seconds, 1-8)
    const only = [].concat(req.query.site || []).map((x) => String(x).toLowerCase());
    const list = only.length ? sites.filter((s) => only.some((o) => s.name.toLowerCase().includes(o))) : sites;
    if (!list.length) return res.status(400).json({ error: `No site matches: ${only.join(', ')}` });
    const timeoutMs = Math.min(Math.max(Number(req.query.timeout) || 6, 1), 8) * 1000;

    const results = await Promise.all(list.map((s) => checkSite(s, username, timeoutMs)));
    const order = { found: 0, unknown: 1, error: 2, not_found: 3 };
    results.sort((a, b) => order[a.status] - order[b.status] || a.site.localeCompare(b.site));

    res.setHeader('Cache-Control', 'no-store');
    res.status(200).json({
        username,
        checked: results.length,
        found: results.filter((r) => r.status === 'found').length,
        results
    });
}
