FROM ubuntu:26.04

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       ca-certificates curl jq openssl git bash python3 \
    && rm -rf /var/lib/apt/lists/* \
    && (id -u boat >/dev/null 2>&1 || useradd --uid 10001 --shell /bin/bash --create-home boat) \
    && mkdir -p /etc/backplane-boat/certs /var/lib/backplane-boat/home /var/lib/backplane-boat/projects \
    && chown -R 10001:10001 /etc/backplane-boat /var/lib/backplane-boat

COPY backplane-hub /usr/local/bin/backplane-hub
COPY bp-ent-relay /usr/local/bin/bp-ent-relay
COPY boat-relay-agent.sh /usr/local/bin/boat-relay-agent.sh
COPY entrypoint.sh /usr/local/bin/boat-entrypoint.sh

RUN chmod 0755 /usr/local/bin/backplane-hub /usr/local/bin/bp-ent-relay \
    /usr/local/bin/boat-relay-agent.sh /usr/local/bin/boat-entrypoint.sh

USER boat:boat
WORKDIR /var/lib/backplane-boat

ENV HOME=/home/boat
ENV BOAT_HOME=/var/lib/backplane-boat/home
ENV BOAT_PORT=3798
ENV CERT_DIR=/etc/backplane-boat/certs
ENV LOCAL_HUB_URL=http://127.0.0.1:3798
ENV PEER_LISTEN_ADDR=127.0.0.1:3799

ENTRYPOINT ["/usr/local/bin/boat-entrypoint.sh"]
