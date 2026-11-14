#!/bin/sh
set -e
# Configure tool API keys from the environment (never from the web UI).
if [ -n "$SHODAN_API_KEY" ]; then
    shodan init "$SHODAN_API_KEY" >/dev/null 2>&1 && echo "shodan: API key configured" || echo "shodan: key rejected"
    recon-cli -w web --no-analytics -C "keys add shodan_api $SHODAN_API_KEY" >/dev/null 2>&1 || true
fi
exec node server.js
