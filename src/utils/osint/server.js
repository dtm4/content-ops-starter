// Shared helpers for the /api/osint/* routes.

const buckets = new Map();

/**
 * Naive in-memory fixed-window rate limiter (per client IP, per route).
 * Good enough to stop casual abuse of a single instance; on serverless each
 * instance keeps its own window. Returns true if the request may proceed.
 */
export function rateLimit(req, res, { key, limit = 10, windowMs = 60_000 }) {
    const ip = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || req.socket?.remoteAddress || 'unknown';
    const id = `${key}:${ip}`;
    const now = Date.now();
    const entry = buckets.get(id);
    if (!entry || now > entry.reset) {
        buckets.set(id, { count: 1, reset: now + windowMs });
        return true;
    }
    entry.count += 1;
    if (entry.count > limit) {
        res.setHeader('Retry-After', Math.ceil((entry.reset - now) / 1000));
        res.status(429).json({ error: 'Rate limit exceeded. Try again shortly.' });
        return false;
    }
    return true;
}

export async function fetchWithTimeout(url, { timeoutMs = 8000, ...opts } = {}) {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), timeoutMs);
    try {
        return await fetch(url, {
            ...opts,
            signal: ctrl.signal,
            headers: {
                'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0 Safari/537.36',
                'Accept-Language': 'en-US,en;q=0.9',
                ...(opts.headers || {})
            }
        });
    } finally {
        clearTimeout(t);
    }
}

export function onlyGet(req, res) {
    if (req.method !== 'GET') {
        res.setHeader('Allow', 'GET');
        res.status(405).json({ error: 'Method not allowed' });
        return false;
    }
    return true;
}

const DOMAIN_RE = /^(?=.{1,253}$)(?!-)([a-z0-9-]{1,63}(?<!-)\.)+[a-z]{2,63}$/i;
export const isDomain = (s) => typeof s === 'string' && DOMAIN_RE.test(s);

const IPV4_RE = /^(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)(\.(25[0-5]|2[0-4]\d|1\d\d|[1-9]?\d)){3}$/;
export const isIPv4 = (s) => typeof s === 'string' && IPV4_RE.test(s);

/** Block private / reserved ranges so the server can't be pointed at internal targets. */
export function isPublicIPv4(ip) {
    if (!isIPv4(ip)) return false;
    const [a, b] = ip.split('.').map(Number);
    if (a === 0 || a === 10 || a === 127 || a >= 224) return false;
    if (a === 100 && b >= 64 && b <= 127) return false;
    if (a === 169 && b === 254) return false;
    if (a === 172 && b >= 16 && b <= 31) return false;
    if (a === 192 && b === 168) return false;
    if (a === 198 && (b === 18 || b === 19)) return false;
    return true;
}

export const USERNAME_RE = /^[A-Za-z0-9._-]{2,40}$/;
