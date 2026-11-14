# osint-web: the real OSINT tools behind a browser UI.
# Kali's packages are used because they ship these tools with dependencies
# that are known to work together.
FROM kalilinux/kali-rolling

ENV DEBIAN_FRONTEND=noninteractive \
    PIP_BREAK_SYSTEM_PACKAGES=1 \
    PYTHONUNBUFFERED=1

RUN apt-get update \
 && apt-get install -y --no-install-recommends \
      ca-certificates curl tar whois dnsutils nodejs python3-pip python3-venv \
      theharvester spiderfoot sherlock recon-ng \
 && (apt-get install -y --no-install-recommends python3-shodan || true) \
 && (apt-get install -y --no-install-recommends phoneinfoga || true) \
 && rm -rf /var/lib/apt/lists/*

# Shodan CLI in its own venv: it still imports pkg_resources, which current
# setuptools (and Kali's python3-shodan) no longer provide.
RUN python3 -m venv /opt/shodan \
 && /opt/shodan/bin/pip install --no-cache-dir shodan "setuptools<81" \
 && ln -sf /opt/shodan/bin/shodan /usr/local/bin/shodan \
 && /usr/local/bin/shodan -h >/dev/null

# PhoneInfoga: fall back to the upstream release binary.
RUN command -v phoneinfoga || { \
      arch="$(uname -m)"; case "$arch" in aarch64) arch=arm64 ;; esac; \
      curl -fsSL "https://github.com/sundowndev/phoneinfoga/releases/latest/download/phoneinfoga_Linux_${arch}.tar.gz" \
        | tar -xz -C /usr/local/bin phoneinfoga && chmod 0755 /usr/local/bin/phoneinfoga; }

# Unprivileged runtime user; tools keep their state (recon-ng workspace,
# SpiderFoot DB, Shodan key) in its home.
RUN useradd --create-home --shell /usr/sbin/nologin osint
WORKDIR /app
COPY server.js entrypoint.sh ./
COPY public ./public
COPY recon-modules ./recon-modules
RUN chmod 0755 entrypoint.sh && mkdir -p /tmp/osint-jobs && chown osint:osint /tmp/osint-jobs
USER osint
ENV HOME=/home/osint PORT=8080

# The entrypoint starts as root only to chown a mounted disk, then drops to osint.
USER root
EXPOSE 8080
HEALTHCHECK --interval=60s --timeout=5s CMD curl -fsS "http://127.0.0.1:${PORT}/healthz" >/dev/null || exit 1
ENTRYPOINT ["./entrypoint.sh"]
