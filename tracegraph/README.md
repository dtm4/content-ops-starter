# Tracegraph

A self-hosted link-analysis workbench for OSINT and recon. Add a seed entity (domain, IP, email, URL, ASN, netblock), right-click it, and run **transforms** that pivot to related entities. Results are drawn as a graph you can lay out, filter and explore.

> Use it only on assets you own or are authorized to assess.

## Run locally

```bash
cd tracegraph
npm install
npm start            # http://localhost:3000
npm test             # unit + API tests (no network needed)
```

Requires Node 20+.

## Using the graph

- **Add entity**: paste a value. The type is auto-detected, then press Enter.
- **Right-click** (or long-press on touch) an entity to open the transforms menu. If several entities are selected, the transform runs on all of them. **Run all free transforms** fires every keyless transform at once.
- **Box-select**: drag on the empty canvas. **Del** deletes the selection. **Ctrl/Cmd+A** selects all.
- **Layouts**: Organic (force), Hierarchical, Centrality (by degree), Circular, Grid. Use *Hierarchical layout from here* in the menu to root a tree at the clicked entity.
- **Filters**: show or hide entity types, hide single-link leaves, and toggle edge labels.
- **Find**: highlights entities whose value or properties match. Press Enter to select and zoom to them.
- The details panel shows properties gathered by transforms (registration dates, page title, VirusTotal score, and so on) and every link, each one clickable.

## Transforms

| Group | Input | Transform | Source |
|---|---|---|---|
| DNS | domain | A/AAAA, MX, NS, CNAME, TXT (+ SPF includes/IPs, DMARC report emails) | DNS-over-HTTPS (Cloudflare, falls back to Google) |
| DNS | ip | Reverse DNS (PTR) | DoH |
| WHOIS | domain | Registrar, contacts (redacted ones are skipped), registry NS, created/expiry dates | RDAP via rdap.org |
| WHOIS | ip, netblock | Netblock, owner org, abuse contacts | RDAP |
| GeoIP | ip | Location, ASN, ISP | ipwho.is |
| BGP | ip, netblock | Announcing ASN, BGP prefix | RIPEstat |
| BGP | asn | Holder org, announced prefixes | RIPEstat |
| CT | domain | Subdomains from certificate transparency logs | crt.sh |
| Web | domain, url | Emails, social profiles, linked domains, phones, analytics/ad tracking IDs, final redirect URL | Fetches the site |
| Convert | email, url | To domain | local |
| Gravatar | email | Name, linked accounts | Gravatar |
| Shodan* | ip | Open ports and services, hostnames, CVEs | `SHODAN_API_KEY` |
| Shodan* | domain | Subdomains and DNS | `SHODAN_API_KEY` |
| VirusTotal* | domain, ip | Reputation and passive DNS | `VT_API_KEY` |
| Hunter* | domain | Emails, people, organization, email pattern | `HUNTER_API_KEY` |
| Hunter* | email | Deliverability check | `HUNTER_API_KEY` |

\* Keyed transforms appear greyed out in the menu until their environment variable is set on the server.

### Adding a transform

Add an object to any array in `src/transforms/` (or a new module registered in `registry.js`):

```js
{
  id: 'mygroup.thing',            // group = text before the dot (used for menu sections)
  name: 'To thing [Source]',
  input: ['domain'],              // entity types it accepts
  requires: ['MY_API_KEY'],       // optional env vars
  async run(value, type) {
    return {
      entities: [ent('ip', '203.0.113.7', 'Edge label', { some: 'prop' })],
      sourceProps: { merged_into: 'the input entity' }   // optional
    };                             // or just return an array of ent(...)
  }
}
```

The server validates and normalizes every returned value, dedupes results, and caps them at 300 per run.

## Configuration

| Env var | Purpose |
|---|---|
| `PORT` | Listen port (default 3000) |
| `APP_PASSWORD` | Require this token for all `/api` calls. The UI prompts for it once. **Set this on any public deployment.** |
| `RATE_LIMIT_PER_MIN` | Transform calls per client IP per minute (default 60) |
| `SHODAN_API_KEY`, `VT_API_KEY`, `HUNTER_API_KEY` | Enable the paid/keyed transforms |
| `TRUST_PROXY` | Set when running behind a reverse proxy, so rate limiting sees real client IPs (set automatically on Render) |

## Security notes

- Website transforms fetch user-supplied URLs. Every connection, including each redirect hop, is checked at DNS-lookup time and refused if it resolves to a private, loopback, link-local or reserved address. This blocks SSRF into your hosting network and cloud metadata endpoints, including via DNS rebinding.
- API keys stay server-side and are never sent to the browser or written to logs.
- Every transform run is logged to stdout: transform, input and result count.

## Deploy to Render

The repo root contains `render.yaml`, a Blueprint for this folder. In Render, choose **New → Blueprint**, pick this repo, then set `APP_PASSWORD` and any API keys when prompted.
