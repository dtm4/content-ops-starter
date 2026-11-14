# osint-web

osint-web runs the real OSINT tools on a server and controls them from the browser. You get a 7-slide carousel in which each terminal runs the actual program (theHarvester, SpiderFoot, Sherlock, Shodan CLI, PhoneInfoga and recon-ng) and streams its output live. Any files a tool writes, such as `-f` reports or Sherlock `--csv`, show up as download buttons. The Maltego slide is a graph whose transforms run on the server: DNS, whois, crt.sh and Shodan InternetDB.

> **Authorised use only.** Run it only against targets you own or have written permission to assess. The UI is password-protected. Don't publish it without auth.

## Run it (any OS with Docker)

```bash
cd osint-web
cp .env.example .env        # set OSINT_USER / OSINT_PASS (and SHODAN_API_KEY if you have one)
docker compose up -d --build
```

Open **http://localhost:8080** and log in. The top bar shows `server ready · 7 tools` once everything is installed.

The first build takes about 5–10 minutes. It installs the tools from Kali's packages and pre-installs the recon-ng modules the UI suggests.

## Put it on the web

You need a host that runs Docker containers. Netlify and Vercel can't run these programs.

| Host | How |
|---|---|
| **Any VPS** (Hetzner, DigitalOcean, Lightsail…) | Install Docker, clone the repo, run the commands above, then put HTTPS in front with Caddy: `caddy reverse-proxy --from osint.yourdomain.com --to localhost:8080` |
| **Render** | New → Web Service → this repo, root directory `osint-web`, runtime Docker. Add the env vars `OSINT_USER`, `OSINT_PASS` and `SHODAN_API_KEY`. Use a paid instance, because SpiderFoot scans run for minutes. |
| **Railway / Fly.io** | Point them at `osint-web/Dockerfile` and set the same env vars. On Fly, mount a volume at `/home/osint` to keep the recon-ng workspace. |

Recommended size: 2 GB RAM, 1–2 vCPU.

## Using each slide

| Slide | Example |
|---|---|
| 01 theHarvester | `theHarvester -d example.com -b all -f report` (then download `report.json` / `report.xml`) |
| 02 SpiderFoot | `spiderfoot -s example.com -u passive -o tab -q` (`footprint` and `investigate` can run 10+ minutes) |
| 03 Maltego | Type `example.com`, then tap or right-click it and pick a transform or "Run all transforms" |
| 04 Sherlock | `sherlock johndoe --csv` |
| 05 Shodan | `shodan host 198.51.100.23`, `shodan domain example.com`, `shodan search "product:nginx"`, `shodan count …` (all need `SHODAN_API_KEY`) |
| 06 PhoneInfoga | `phoneinfoga scan -n +12025550143` |
| 07 recon-ng | `marketplace install recon/domains-hosts/hackertarget` → `modules load recon/domains-hosts/hackertarget` → `options set SOURCE example.com` → `run` → `show hosts` |

Each terminal supports up/down history, `clear`, and a stop button (■) while a job runs.

## Security model

- **Login required:** HTTP Basic auth. The server refuses to start without it unless `ALLOW_NO_AUTH=1`. Always serve it over HTTPS when it's online.
- **No shell:** each command is tokenized and checked against a per-tool allowlist of options and value patterns, then started directly with `spawn`. Options that touch the filesystem, proxies, plugins or start servers are rejected, for example `--output`, `--json`, `--proxy`, `-l`, `serve`, `--plugin` and `shodan init`.
- **Keys stay out of the browser:** API keys come only from env vars and are set up at container start.
- **Limits:** `MAX_JOBS` (default 3) concurrent jobs and `JOB_TIMEOUT` (default 900 s). Each job runs in its own folder, and folders are deleted after 2 hours.
- **Unprivileged user:** the container runs as `osint`, not root.

## Without Docker

The server is a single Node file with no dependencies. Install the tools so they're on `PATH` (see `../osint-kit`), then:

```bash
OSINT_USER=me OSINT_PASS=secret node server.js
```

Override binary names with `SPIDERFOOT_CMD="python3 /opt/spiderfoot/sf.py"` and `RECON_CLI=/path/to/recon-cli` if needed.
