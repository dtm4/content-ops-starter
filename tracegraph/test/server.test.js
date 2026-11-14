import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { createApp } from '../server.js';

let server, base;
before(async () => {
  server = createApp().listen(0);
  await new Promise((r) => server.once('listening', r));
  base = `http://127.0.0.1:${server.address().port}`;
});
after(() => server.close());

const post = (body) => fetch(`${base}/api/transform`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) });

test('serves UI, vendor bundle and metadata', async () => {
  assert.equal((await fetch(`${base}/`)).status, 200);
  assert.equal((await fetch(`${base}/vendor/cytoscape.min.js`)).status, 200);
  const meta = await (await fetch(`${base}/api/meta`)).json();
  assert.ok(meta.entityTypes.domain);
  assert.ok(meta.transforms.length > 15);
});

test('rejects bad transform requests', async () => {
  assert.equal((await post({ transform: 'nope', type: 'domain', value: 'a.com' })).status, 400);
  assert.equal((await post({ transform: 'dns.ptr', type: 'domain', value: 'a.com' })).status, 400);
  assert.equal((await post({ transform: 'dns.a', type: 'domain', value: '../../etc' })).status, 400);
  const keyed = await post({ transform: 'vt.domain', type: 'domain', value: 'a.com' });
  assert.equal(keyed.status, 400);
  assert.match((await keyed.json()).error, /VT_API_KEY/);
});

test('runs a local transform end to end', async () => {
  const r = await post({ transform: 'convert.domain', type: 'email', value: 'Alice@Example.com' });
  assert.equal(r.status, 200);
  const body = await r.json();
  assert.deepEqual(body.entities, [{ type: 'domain', value: 'example.com', edge: 'Mail domain', props: {} }]);
});

test('web transforms refuse internal URLs', async () => {
  const r = await post({ transform: 'web.emails', type: 'url', value: 'http://169.254.169.254/latest' });
  assert.equal(r.status, 502);
  assert.match((await r.json()).error, /Blocked/);
});

test('health check is reachable', async () => {
  assert.equal(await (await fetch(`${base}/healthz`)).text(), 'ok');
});
