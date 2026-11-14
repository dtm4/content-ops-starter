#!/bin/sh
set -e
# Started as root only to fix ownership of a mounted disk (e.g. Render's
# /home/osint), then re-executes itself as the unprivileged osint user.
if [ "$(id -u)" = "0" ]; then
    mkdir -p /home/osint /tmp/osint-jobs
    chown -R osint:osint /home/osint /tmp/osint-jobs
    exec setpriv --reuid=osint --regid=osint --init-groups env HOME=/home/osint "$0" "$@"
fi

# Configure tool API keys from the environment (never from the web UI).
if [ -n "$SHODAN_API_KEY" ]; then
    shodan init "$SHODAN_API_KEY" >/dev/null 2>&1 && echo "shodan: API key configured" || echo "shodan: key rejected"
    recon-cli -w web --no-analytics -C "keys add shodan_api $SHODAN_API_KEY" >/dev/null 2>&1 || true
fi

# A fresh persistent disk hides the modules installed at build time: reinstall in the background.
if [ ! -d "$HOME/.recon-ng/modules/recon" ]; then
    (
        recon-cli -w web --no-analytics -C "marketplace refresh" >/dev/null 2>&1 || true
        for m in recon/domains-hosts/hackertarget recon/domains-hosts/certificate_transparency \
                 recon/hosts-hosts/resolve recon/domains-contacts/whois_pocs recon/hosts-ports/shodan_ip; do
            recon-cli -w web --no-analytics -C "marketplace install $m" >/dev/null 2>&1 || true
        done
        echo "recon-ng: default modules installed"
    ) &
fi
exec node server.js
