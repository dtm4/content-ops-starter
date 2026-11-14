import { test, beforeEach, afterEach } from 'node:test';
import assert from 'node:assert/strict';
import { normalizeValue } from '../src/entities.js';
import { isPublicIp, safeFetch } from '../src/lib/safe-fetch.js';
import { reverseName, parseTxt, parseSpf, expandIPv6 } from '../src/transforms/dns.js';
import { extractFromHtml } from '../src/transforms/web.js';
import { contactsToEntities } from '../src/transforms/rdap.js';
import { parseHostList } from '../src/transforms/public.js';
import { getTransform, describeTransforms } from '../src/transforms/registry.js';

// ---- fetch mock: maps URL substrings to JSON bodies -----------------------------
let routes = {};
const realFetch = globalThis.fetch;
beforeEach(() => {
  routes = {};
  globalThis.fetch = async (url) => {
    const hit = Object.entries(routes).find(([k]) => String(url).includes(k));
    if (!hit) return new Response('not found', { status: 404 });
    if (typeof hit[1] === 'string') return new Response(hit[1], { status: 200 });
    return new Response(JSON.stringify(hit[1]), { status: 200, headers: { 'content-type': 'application/json' } });
  };
});
afterEach(() => { globalThis.fetch = realFetch; });

const run = async (id, value, type) => {
  const r = await getTransform(id).run(value, type);
  return Array.isArray(r) ? { entities: r } : r;
};

test('normalizeValue validates and canonicalizes', () => {
  assert.equal(normalizeValue('domain', 'Example.COM.'), 'example.com');
  assert.equal(normalizeValue('domain', '*.example.com'), 'example.com');
  assert.equal(normalizeValue('asn', '13335'), 'AS13335');
  assert.equal(normalizeValue('url', 'example.com/a#frag'), 'https://example.com/a');
  assert.equal(normalizeValue('netblock', '10.0.0.0/8'), '10.0.0.0/8');
  assert.throws(() => normalizeValue('domain', 'not a domain'));
  assert.throws(() => normalizeValue('ip', '999.1.1.1'));
  assert.throws(() => normalizeValue('url', 'file:///etc/passwd'));
  assert.throws(() => normalizeValue('netblock', '1.2.3.4/40'));
});

test('SSRF guard classifies addresses', () => {
  for (const ip of ['127.0.0.1', '10.1.2.3', '172.20.0.1', '192.168.1.1', '169.254.169.254', '100.64.0.1', '::1', 'fd00::1', 'fe80::1', '::ffff:127.0.0.1', '0.0.0.0']) {
    assert.equal(isPublicIp(ip), false, ip);
  }
  for (const ip of ['1.1.1.1', '8.8.8.8', '172.32.0.1', '2606:4700::1111']) assert.equal(isPublicIp(ip), true, ip);
});

test('safeFetch refuses internal targets', async () => {
  await assert.rejects(safeFetch('http://127.0.0.1:1/'), /Blocked/);
  await assert.rejects(safeFetch('http://[::1]/'), /Blocked/);
  await assert.rejects(safeFetch('http://169.254.169.254/latest/meta-data/'), /Blocked/);
  await assert.rejects(safeFetch('http://localhost/'), /Blocked|ENOTFOUND/);
});

test('DNS helpers', () => {
  assert.equal(reverseName('1.2.3.4'), '4.3.2.1.in-addr.arpa');
  assert.equal(expandIPv6('2001:db8::1'), '20010db8000000000000000000000001');
  assert.ok(reverseName('2001:db8::1').startsWith('1.0.0.0.') && reverseName('2001:db8::1').endsWith('.8.b.d.0.1.0.0.2.ip6.arpa'));
  assert.equal(parseTxt('"v=spf1 include:_spf.google.com " "~all"'), 'v=spf1 include:_spf.google.com ~all');
  const spf = parseSpf('v=spf1 include:_spf.google.com ip4:192.0.2.0/24 ip4:198.51.100.7 -all');
  assert.deepEqual(spf.map((e) => [e.type, e.value]), [['domain', '_spf.google.com'], ['netblock', '192.0.2.0/24'], ['ip', '198.51.100.7']]);
});

test('dns.mx / dns.a parse DoH answers', async () => {
  routes['type=MX'] = { Answer: [{ type: 15, data: '10 mx1.example.com.' }, { type: 15, data: '20 mx2.example.com.' }] };
  const mx = await run('dns.mx', 'example.com', 'domain');
  assert.deepEqual(mx.entities.map((e) => e.value), ['mx1.example.com', 'mx2.example.com']);
  assert.equal(mx.entities[0].props.mx_priority, 10);
  routes = { 'type=AAAA': { Answer: [{ type: 28, data: '2606:2800::1' }] }, 'type=A': { Answer: [{ type: 5, data: 'cdn.example.net.' }, { type: 1, data: '93.184.216.34' }] } };
  const a = await run('dns.a', 'example.com', 'domain');
  assert.deepEqual(a.entities.map((e) => `${e.edge}:${e.value}`), ['A:93.184.216.34', 'AAAA:2606:2800::1']);
});

test('extractFromHtml finds emails, socials, phones, links, trackers', () => {
  const html = `<title> Acme  Corp </title><meta name="generator" content="WordPress 6.5">
    <a href="mailto:sales@acme.com?subject=hi">x</a> contact: info&#64;acme.com, logo@2x.png
    <a href="https://twitter.com/acmecorp">t</a><a href="https://twitter.com/intent/tweet?x">share</a>
    <a href="https://www.linkedin.com/company/acme/">li</a><a href="https://github.com/acme">gh</a>
    <a href="tel:+1 (555) 010-9999">call</a><a href="/about">about</a><a href="https://blog.acme.com/x">blog</a>
    <a href="https://partner.io/page">partner</a><script>gtag('config','G-ABC123XYZ')</script>`;
  const d = extractFromHtml(html, 'https://acme.com/');
  assert.equal(d.title, 'Acme Corp');
  assert.equal(d.generator, 'WordPress 6.5');
  assert.deepEqual([...d.emails].sort(), ['info@acme.com', 'sales@acme.com']);
  assert.deepEqual([...d.socials.keys()].sort(), ['https://github.com/acme', 'https://linkedin.com/company/acme', 'https://twitter.com/acmecorp']);
  assert.deepEqual([...d.phones], ['+15550109999']);
  assert.deepEqual([...d.domains], ['partner.io']);
  assert.deepEqual([...d.trackers], ['G-ABC123XYZ']);
});

test('RDAP contacts skip redacted data', () => {
  const ents = contactsToEntities([
    { roles: ['registrar'], publicIds: [{ type: 'IANA Registrar ID', identifier: '292' }],
      vcardArray: ['vcard', [['version', {}, 'text', '4.0'], ['fn', {}, 'text', 'MarkMonitor Inc.']]],
      entities: [{ roles: ['abuse'], vcardArray: ['vcard', [['fn', {}, 'text', ''], ['email', {}, 'text', 'abusecomplaints@markmonitor.com'], ['tel', {}, 'uri', 'tel:+1.2086851750']]] }] },
    { roles: ['registrant'], vcardArray: ['vcard', [['fn', {}, 'text', 'REDACTED FOR PRIVACY'], ['email', {}, 'text', 'redacted@privacy.example']]] }
  ]);
  assert.deepEqual(ents.map((e) => [e.type, e.value]), [
    ['organization', 'MarkMonitor Inc.'],
    ['email', 'abusecomplaints@markmonitor.com'],
    ['phone', '+1.2086851750']
  ]);
  assert.equal(ents[0].props.iana_id, '292');
});

test('whois.domain returns dates as source props', async () => {
  routes['rdap.org/domain/'] = {
    handle: 'D1', status: ['client transfer prohibited'],
    events: [{ eventAction: 'registration', eventDate: '1995-08-14T04:00:00Z' }, { eventAction: 'expiration', eventDate: '2030-08-13T04:00:00Z' }],
    nameservers: [{ ldhName: 'A.IANA-SERVERS.NET' }], entities: []
  };
  const r = await run('whois.domain', 'example.com', 'domain');
  assert.equal(r.sourceProps.registered, '1995-08-14T04:00:00Z');
  assert.deepEqual(r.entities.map((e) => e.value), ['a.iana-servers.net']);
});

test('ct.subdomains dedupes and scopes names', async () => {
  routes['crt.sh'] = [
    { name_value: 'www.example.com\n*.example.com\nexample.com', issuer_name: 'X' },
    { name_value: 'api.example.com\nwww.example.com\nevil-example.com', issuer_name: 'Y' }
  ];
  const r = await run('ct.subdomains', 'example.com', 'domain');
  assert.deepEqual(r.entities.map((e) => e.value), ['www.example.com', 'api.example.com']);
});

test('geo.ip and bgp.asn map to location/asn/netblocks', async () => {
  routes['ipwho.is'] = { success: true, city: 'Sydney', region: 'NSW', country: 'Australia', latitude: 1, longitude: 2, connection: { asn: 13335, org: 'Cloudflare', isp: 'Cloudflare, Inc.', domain: 'cloudflare.com' } };
  const g = await run('geo.ip', '1.1.1.1', 'ip');
  assert.deepEqual(g.entities.map((e) => `${e.type}:${e.value}`), ['location:Sydney, NSW, Australia', 'asn:AS13335', 'organization:Cloudflare, Inc.', 'domain:cloudflare.com']);
  routes['as-overview'] = { data: { holder: 'CLOUDFLARENET - Cloudflare, Inc.' } };
  routes['announced-prefixes'] = { data: { prefixes: [{ prefix: '1.1.1.0/24' }, { prefix: '104.16.0.0/13' }] } };
  const a = await run('bgp.asn', 'AS13335', 'asn');
  assert.deepEqual(a.entities.map((e) => e.value), ['Cloudflare, Inc.', '1.1.1.0/24', '104.16.0.0/13']);
});

test('keyed transforms report availability from env', () => {
  const list = describeTransforms({ SHODAN_API_KEY: 'x' });
  assert.equal(list.find((t) => t.id === 'shodan.host').available, true);
  assert.equal(list.find((t) => t.id === 'vt.domain').available, false);
  assert.equal(list.find((t) => t.id === 'dns.a').available, true);
});

test('shodan.host maps services, hostnames and CVEs', async () => {
  process.env.SHODAN_API_KEY = 'test';
  routes['api.shodan.io/shodan/host'] = { org: 'Acme', hostnames: ['host.acme.com'], vulns: { 'CVE-2021-44228': {} }, asn: 'AS64500', data: [{ port: 443, transport: 'tcp', product: 'nginx' }] };
  const r = await run('shodan.host', '203.0.113.5', 'ip');
  assert.deepEqual(r.entities.map((e) => `${e.type}:${e.value}`), ['service:203.0.113.5:443/tcp', 'domain:host.acme.com', 'note:CVE-2021-44228', 'asn:AS64500']);
  delete process.env.SHODAN_API_KEY;
});

test('internetdb.host maps ports, hostnames and CVEs; 404 means no data', async () => {
  routes['internetdb.shodan.io'] = { cpes: ['cpe:/a:nginx:nginx'], hostnames: ['one.one.one.one'], ip: '1.1.1.1', ports: [53, 443], tags: ['cdn'], vulns: ['CVE-2020-0001'] };
  const r = await run('internetdb.host', '1.1.1.1', 'ip');
  assert.deepEqual(r.entities.map((e) => `${e.type}:${e.value}`), ['service:1.1.1.1:53/tcp', 'service:1.1.1.1:443/tcp', 'domain:one.one.one.one', 'note:CVE-2020-0001']);
  assert.equal(r.sourceProps.tags, 'cdn');
  routes = {};
  assert.deepEqual((await run('internetdb.host', '203.0.113.9', 'ip')).entities, []);
});

test('thc transforms parse text listings', async () => {
  assert.deepEqual(parseHostList(';; comment example.net\nwww.example.com\napi.example.com.  extra\n# x\nnot_a_host\n'), ['www.example.com', 'api.example.com']);
  routes['ip.thc.org/sb/'] = ';; subdomains\nwww.example.com\nexample.com\nother.net\nmail.example.com\n';
  const s = await run('thc.subdomains', 'example.com', 'domain');
  assert.deepEqual(s.entities.map((e) => e.value), ['www.example.com', 'mail.example.com']);
  routes = { 'ip.thc.org/': '', 'hackertarget.com/reverseiplookup': 'a.example\nb.example\n' };
  const r = await run('thc.rdns', '203.0.113.9', 'ip');
  assert.deepEqual(r.entities.map((e) => e.value), ['a.example', 'b.example']);
  routes = { 'ip.thc.org/': '', 'hackertarget.com/reverseiplookup': 'API count exceeded - Increase Quota with Membership' };
  await assert.rejects(run('thc.rdns', '203.0.113.9', 'ip'), /API count exceeded/);
});

test('otx.domain returns historical IPs and report count', async () => {
  routes['/passive_dns'] = { passive_dns: [{ address: '93.184.216.34', hostname: 'example.com', first: '2020-01-01', last: '2024-01-01' }, { address: '93.184.216.34', hostname: 'example.com' }, { address: 'NXDOMAIN', hostname: 'example.com' }, { address: '10.9.9.9', hostname: 'sub.example.com' }] };
  routes['/general'] = { pulse_info: { count: 7 } };
  const r = await run('otx.domain', 'example.com', 'domain');
  assert.deepEqual(r.entities.map((e) => e.value), ['93.184.216.34']);
  assert.equal(r.sourceProps.otx_threat_reports, 7);
});

test('mail.verify reports MX and disposable status', async () => {
  routes['type=MX'] = { Answer: [{ type: 15, data: '10 mx.example.com.' }] };
  routes['open.kickbox.com'] = { disposable: true };
  const r = await run('mail.verify', 'a@example.com', 'email');
  assert.deepEqual(r.entities.map((e) => e.value), ['mx.example.com']);
  assert.equal(r.sourceProps.domain_accepts_mail, true);
  assert.equal(r.sourceProps.disposable_address, true);
});
