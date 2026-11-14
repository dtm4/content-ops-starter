#!/bin/sh
set -e
# Started as root only to fix ownership of a mounted disk (e.g. Render's
# /home/osint), then re-executes itself as the unprivileged osint user.
if [ "$(id -u)" = "0" ]; then
    mkdir -p /home/osint /tmp/osint-jobs
    chown -R osint:osint /home/osint /tmp/osint-jobs
    exec setpriv --reuid=osint --regid=osint --init-groups env HOME=/home/osint "$0" "$@"
fi

rc() { recon-cli -w web --no-analytics -C "$1" >/dev/null 2>&1 || true; }

# Keyless recon-ng module shipped with this app (Shodan InternetDB).
mkdir -p "$HOME/.recon-ng/modules"
cp -r /app/recon-modules/. "$HOME/.recon-ng/modules/"

# Configure tool API keys from the environment (never from the web UI).
if [ -n "$SHODAN_API_KEY" ]; then
    shodan init "$SHODAN_API_KEY" >/dev/null 2>&1 && echo "shodan: API key configured" || echo "shodan: key rejected"
    rc "keys add shodan_api $SHODAN_API_KEY"
fi

# Install the keyless, passive recon-ng modules once per disk (marker is versioned).
MARK="$HOME/.recon-ng/.osint-web-modules-v2"
if [ ! -f "$MARK" ]; then
    (
        rc "marketplace refresh"
        for m in recon/domains-hosts/hackertarget recon/domains-hosts/certificate_transparency \
                 recon/domains-hosts/threatminer recon/domains-hosts/mx_spf_ip recon/domains-hosts/brute_hosts \
                 recon/hosts-hosts/resolve recon/hosts-hosts/reverse_resolve \
                 recon/domains-contacts/whois_pocs recon/domains-contacts/pgp_search \
                 recon/netblocks-hosts/reverse_resolve recon/netblocks-companies/whois_orgs \
                 recon/companies-multi/whois_miner reporting/csv reporting/json reporting/html; do
            rc "marketplace install $m"
        done
        if [ -n "$SHODAN_API_KEY" ]; then rc "marketplace install recon/hosts-ports/shodan_ip"
        else rc "marketplace remove recon/hosts-ports/shodan_ip"; fi   # avoids a missing-key warning on every command
        touch "$MARK"
        echo "recon-ng: keyless modules installed"
    ) &
fi
exec node server.js
