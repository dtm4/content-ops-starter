# osint-kit

This kit installs and runs the open-source OSINT toolchain from one launcher. Each tool gets its own isolated Python venv or a standalone binary under `~/.osint-kit`, so nothing is installed system-wide.

> **Authorised use only.** Run these tools only against domains, IPs and identities you own or have written permission to assess. Collecting personal data may be regulated by GDPR/CCPA and similar laws.

## Requirements

- Linux or macOS (on Windows, use WSL2)
- Python 3.10+, `git`, `curl`, `tar`
- Network access to GitHub and PyPI

## Install

```bash
cd osint-kit
./osint install            # everything
./osint install sherlock shodan   # or pick tools
./osint doctor             # show what's installed
```

To install somewhere else, set `OSINT_HOME=/path`. To use a different interpreter, set `PYTHON=python3.12`.

## Tools

| # | Tool | Run | Notes |
|---|------|-----|-------|
| 01 | **theHarvester** | `./osint theharvester -d example.com -b crtsh,hackertarget,rapiddns -f out` | Emails, subdomains, hosts and IPs. `-b all` also uses sources that need keys (add them to `~/.osint-kit/src/theHarvester/theHarvester/data/api-keys.yaml`). |
| 02 | **SpiderFoot** | `./osint spiderfoot -s example.com -u passive -o csv > sf.csv` | 200+ modules plus correlation. Web UI: `./osint spiderfoot -l 127.0.0.1:5001`. |
| 03 | **Maltego** | `./osint maltego` | Commercial GUI with a free Community tier. The command prints setup steps and how to import kit CSVs. |
| 04 | **Sherlock** | `./osint sherlock johndoe --print-found --csv` | Checks one username across 400+ sites. |
| 05 | **Shodan** | `./osint shodan init <KEY>` then `./osint shodan host 198.51.100.23` | Needs a free or paid key from account.shodan.io. Keyless option: `curl https://internetdb.shodan.io/<ip>`. |
| 06 | **PhoneInfoga** | `./osint phoneinfoga scan -n +12025550143` | Web UI: `./osint phoneinfoga serve -p 8080`. |
| 07 | **recon-ng** | `./osint reconng` | Inside the console: `marketplace install recon/domains-hosts/hackertarget`, `modules load recon/domains-hosts/hackertarget`, `options set SOURCE example.com`, `run`. |

## Example passive workflow

```bash
D=example.com
./osint theharvester -d $D -b crtsh,hackertarget -f harvest      # 1. map the surface
./osint spiderfoot -s $D -u passive -o csv > spiderfoot.csv      # 2. correlate
./osint shodan domain $D                                         # 3. exposed services
# 4. load the CSVs into Maltego (or the /tools/domain graph view) and pivot
```

## Troubleshooting

- **SpiderFoot install fails on Python 3.13:** some of its pinned dependencies lag behind. Run `PYTHON=python3.11 ./osint install spiderfoot`, or use Docker: `docker run -p 5001:5001 smicallef/spiderfoot`.
- **Shodan `pkg_resources` error:** the installer already pins `setuptools<81`. Rerun `./osint install shodan`.
- **Updates:** rerun `./osint install <tool>`. It pulls the latest source and upgrades packages.
- **Uninstall:** `rm -rf ~/.osint-kit`.
