# Privileged sandbox the e2e suite runs in: its own dockerd, network namespace and
# nftables ruleset, so a run never touches the host firewall or host containers.
FROM debian:trixie-slim

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl gnupg iproute2 iptables nftables procps socat \
    && install -m 0755 -d /etc/apt/keyrings \
    && curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc \
    && echo "deb [signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian trixie stable" \
        > /etc/apt/sources.list.d/docker.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends docker-ce docker-ce-cli containerd.io docker-compose-plugin \
    && rm -rf /var/lib/apt/lists/*

COPY entrypoint.sh hs-serve hs-probe /usr/local/bin/

ENV HARBORSHIELD_E2E_SANDBOX=1

ENTRYPOINT ["/usr/local/bin/entrypoint.sh"]
