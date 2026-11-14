import express from 'express';
import crypto from 'node:crypto';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { ENTITY_TYPES, normalizeValue } from './src/entities.js';
import { getTransform, describeTransforms, missingKeys } from './src/transforms/registry.js';

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PORT = Number(process.env.PORT) || 3000;
const APP_PASSWORD = process.env.APP_PASSWORD || '';
const RATE_PER_MIN = Number(process.env.RATE_LIMIT_PER_MIN) || 60;
const MAX_RESULTS = 300;

export function createApp() {
  const app = express();
  app.disable('x-powered-by');
  if (process.env.RENDER || process.env.TRUST_PROXY) app.set('trust proxy', 1); // correct client IP for rate limiting
  app.use(express.json({ limit: '16kb' }));
  app.use((req, res, next) => {
    res.set({
      'Content-Security-Policy': "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; connect-src 'self'; frame-ancestors 'none'",
      'X-Content-Type-Options': 'nosniff',
      'Referrer-Policy': 'no-referrer'
    });
    next();
  });

  app.use(express.static(path.join(__dirname, 'public')));
  app.get('/vendor/cytoscape.min.js', (req, res) =>
    res.sendFile(path.join(__dirname, 'node_modules/cytoscape/dist/cytoscape.min.js'))
  );

  app.get('/healthz', (req, res) => res.send('ok'));

  // Optional shared password: anyone who can reach a public deployment could otherwise
  // use it as an anonymous proxy for lookups and spend your API quotas.
  app.use('/api', (req, res, next) => {
    if (!APP_PASSWORD) return next();
    const given = Buffer.from(String(req.get('x-access-token') || ''));
    const want = Buffer.from(APP_PASSWORD);
    if (given.length === want.length && crypto.timingSafeEqual(given, want)) return next();
    res.status(401).json({ error: 'Access token required', auth: true });
  });

  const buckets = new Map();
  function rateLimited(ip) {
    const now = Date.now();
    const b = buckets.get(ip) || { tokens: RATE_PER_MIN, at: now };
    b.tokens = Math.min(RATE_PER_MIN, b.tokens + ((now - b.at) / 60000) * RATE_PER_MIN);
    b.at = now;
    buckets.set(ip, b);
    if (b.tokens < 1) return true;
    b.tokens -= 1;
    return false;
  }

  app.get('/api/meta', (req, res) => {
    res.json({ entityTypes: ENTITY_TYPES, transforms: describeTransforms(), authRequired: Boolean(APP_PASSWORD) });
  });

  app.post('/api/transform', async (req, res) => {
    const { transform: id, type, value } = req.body || {};
    const t = getTransform(id);
    if (!t) return res.status(400).json({ error: `Unknown transform "${id}"` });
    if (!t.input.includes(type)) return res.status(400).json({ error: `${t.name} does not accept ${type} entities` });
    const missing = missingKeys(t);
    if (missing.length) return res.status(400).json({ error: `Set ${missing.join(', ')} on the server to enable this transform` });
    let input;
    try {
      input = normalizeValue(type, value);
    } catch (e) {
      return res.status(400).json({ error: e.message });
    }
    if (rateLimited(req.ip)) return res.status(429).json({ error: 'Rate limit reached, wait a moment' });

    const started = Date.now();
    try {
      const raw = await t.run(input, type);
      const result = Array.isArray(raw) ? { entities: raw } : raw;
      const seen = new Set();
      const entities = [];
      let dropped = 0;
      for (const e of result.entities || []) {
        try {
          const v = normalizeValue(e.type, e.value);
          const key = `${e.type}:${v.toLowerCase()}`;
          if (seen.has(key) || (e.type === type && v === input)) continue;
          seen.add(key);
          entities.push({ ...e, value: v });
        } catch {
          dropped++;
        }
      }
      const truncated = entities.length > MAX_RESULTS;
      console.log(`[transform] ${id} ${type}=${input} -> ${entities.length} in ${Date.now() - started}ms`);
      res.json({ entities: entities.slice(0, MAX_RESULTS), sourceProps: result.sourceProps || {}, truncated, dropped });
    } catch (e) {
      console.warn(`[transform] ${id} ${type}=${input} failed: ${e.message}`);
      const msg = e.name === 'TimeoutError' ? 'Upstream service timed out' : e.message === 'fetch failed' ? `Network error: ${e.cause?.code || e.cause?.message || 'unreachable'}` : e.message;
      res.status(502).json({ error: msg });
    }
  });

  return app;
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  createApp().listen(PORT, () => {
    const keyed = describeTransforms().filter((t) => !t.available).map((t) => t.id);
    console.log(`Tracegraph listening on http://localhost:${PORT}`);
    if (keyed.length) console.log(`Disabled until API keys are set: ${keyed.join(', ')}`);
    if (!APP_PASSWORD) console.log('APP_PASSWORD not set: the API is open to anyone who can reach this port.');
  });
}
