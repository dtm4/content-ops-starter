// Small JSON/text HTTP helpers for calling fixed, trusted OSINT APIs.
// (User-controlled URLs go through safe-fetch.js instead.)

export const USER_AGENT = 'Tracegraph/1.0 (link-analysis tool)';

export class HttpError extends Error {
  constructor(status, url, body = '') {
    super(`HTTP ${status} from ${new URL(url).host}${body ? `: ${body.slice(0, 200)}` : ''}`);
    this.status = status;
  }
}

export async function request(url, { headers = {}, timeoutMs = 15000, method = 'GET', body } = {}) {
  const res = await fetch(url, {
    method,
    body,
    headers: { 'user-agent': USER_AGENT, ...headers },
    signal: AbortSignal.timeout(timeoutMs)
  });
  return res;
}

export async function getJson(url, opts = {}) {
  const res = await request(url, { ...opts, headers: { accept: 'application/json', ...(opts.headers || {}) } });
  if (res.status === 404 && opts.allow404) return null;
  if (!res.ok) throw new HttpError(res.status, url, await res.text().catch(() => ''));
  return res.json();
}
