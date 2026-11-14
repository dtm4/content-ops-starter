// Fetch a user-supplied URL without letting it reach internal networks (SSRF guard).
// The guard runs inside the socket's DNS lookup, so every connection — including each
// redirect hop — is checked against the address actually connected to (no DNS-rebinding gap).
import http from 'node:http';
import https from 'node:https';
import dns from 'node:dns';
import net from 'node:net';
import { USER_AGENT } from './http.js';

function v4ToInt(ip) {
  return ip.split('.').reduce((acc, o) => (acc << 8) + Number(o), 0) >>> 0;
}

const V4_BLOCKED = [
  ['0.0.0.0', 8], ['10.0.0.0', 8], ['100.64.0.0', 10], ['127.0.0.0', 8],
  ['169.254.0.0', 16], ['172.16.0.0', 12], ['192.0.0.0', 24], ['192.0.2.0', 24],
  ['192.168.0.0', 16], ['198.18.0.0', 15], ['198.51.100.0', 24], ['203.0.113.0', 24],
  ['224.0.0.0', 4], ['240.0.0.0', 4]
].map(([base, bits]) => [v4ToInt(base), bits]);

export function isPublicIp(ip) {
  const fam = net.isIP(ip);
  if (fam === 4) {
    const n = v4ToInt(ip);
    return !V4_BLOCKED.some(([base, bits]) => {
      const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
      return (n & mask) === (base & mask);
    });
  }
  if (fam === 6) {
    const lower = ip.toLowerCase();
    const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/.exec(lower);
    if (mapped) return isPublicIp(mapped[1]);
    if (lower === '::' || lower === '::1') return false;
    const first = parseInt(lower.split(':')[0] || '0', 16);
    if ((first & 0xfe00) === 0xfc00) return false; // fc00::/7 unique local
    if ((first & 0xffc0) === 0xfe80) return false; // fe80::/10 link local
    if ((first & 0xff00) === 0xff00) return false; // multicast
    if (lower.startsWith('64:ff9b:') || lower.startsWith('2001:db8:')) return false;
    return true;
  }
  return false;
}

function guardedLookup(hostname, options, callback) {
  dns.lookup(hostname, { ...options, all: true }, (err, addresses) => {
    if (err) return callback(err);
    const bad = addresses.find((a) => !isPublicIp(a.address));
    if (bad) {
      const e = new Error(`Blocked: ${hostname} resolves to non-public address ${bad.address}`);
      e.code = 'EBLOCKED';
      return callback(e);
    }
    if (options.all) return callback(null, addresses);
    callback(null, addresses[0].address, addresses[0].family);
  });
}

function getOnce(url, { timeoutMs, maxBytes }) {
  return new Promise((resolve, reject) => {
    const u = new URL(url);
    if (net.isIP(u.hostname.replace(/^\[|\]$/g, '')) && !isPublicIp(u.hostname.replace(/^\[|\]$/g, ''))) {
      return reject(new Error(`Blocked: ${u.hostname} is not a public address`));
    }
    const mod = u.protocol === 'https:' ? https : http;
    const req = mod.get(
      u,
      {
        lookup: guardedLookup,
        timeout: timeoutMs,
        headers: { 'user-agent': USER_AGENT, accept: 'text/html,application/xhtml+xml,*/*;q=0.8' }
      },
      (res) => {
        const chunks = [];
        let size = 0;
        res.on('data', (c) => {
          size += c.length;
          if (size > maxBytes) {
            res.destroy();
            resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8'), truncated: true });
            return;
          }
          chunks.push(c);
        });
        res.on('end', () => resolve({ status: res.statusCode, headers: res.headers, body: Buffer.concat(chunks).toString('utf8') }));
        res.on('error', reject);
      }
    );
    req.on('timeout', () => req.destroy(new Error(`Timed out fetching ${u.host}`)));
    req.on('error', reject);
  });
}

/** GET a public http(s) URL, following up to 5 redirects. Returns { url, status, headers, body }. */
export async function safeFetch(url, { timeoutMs = 12000, maxBytes = 2_000_000 } = {}) {
  let current = url;
  for (let hop = 0; hop <= 5; hop++) {
    const u = new URL(current);
    if (!['http:', 'https:'].includes(u.protocol)) throw new Error(`Unsupported protocol ${u.protocol}`);
    const res = await getOnce(current, { timeoutMs, maxBytes });
    if (res.status >= 300 && res.status < 400 && res.headers.location) {
      current = new URL(res.headers.location, current).toString();
      continue;
    }
    return { url: current, ...res };
  }
  throw new Error('Too many redirects');
}
