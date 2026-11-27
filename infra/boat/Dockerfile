FROM ubuntu:26.04

ARG TARGETARCH
ARG SOLIDCRAFT_VERSION=0.50.0
ARG SOLIDCRAFT_SHA256_AMD64=b0c63f45fe58ab13c40145132b21fdc309f45e294301f1ba525050aa99575920
ARG SOLIDCRAFT_SHA256_ARM64=5a5c6e87533f70de2ad0fcc23c7b36f45144ccf9ded77ff0099cbbea39b4c337

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       ca-certificates curl jq openssl git bash python3 \
    && rm -rf /var/lib/apt/lists/* \
    && arch="${TARGETARCH:-$(dpkg --print-architecture)}" \
    && case "${arch}" in \
         amd64) sc_arch="x86_64"; sc_sha="${SOLIDCRAFT_SHA256_AMD64}" ;; \
         arm64) sc_arch="aarch64"; sc_sha="${SOLIDCRAFT_SHA256_ARM64}" ;; \
         *) echo "unsupported Boat architecture for SolidCraft: ${arch}" >&2; exit 1 ;; \
       esac \
    && sc_tgz="solidcraft-${SOLIDCRAFT_VERSION}-linux-${sc_arch}.tar.gz" \
    && curl --fail --silent --show-error --location \
       "https://github.com/tangency-labs/solidcraft/releases/download/v${SOLIDCRAFT_VERSION}/${sc_tgz}" \
       -o "/tmp/${sc_tgz}" \
    && echo "${sc_sha}  /tmp/${sc_tgz}" | sha256sum -c - \
    && tar -xzf "/tmp/${sc_tgz}" -C /tmp "solidcraft-${SOLIDCRAFT_VERSION}-linux-${sc_arch}/bin/solidcraft-cli" \
    && install -m 0755 "/tmp/solidcraft-${SOLIDCRAFT_VERSION}-linux-${sc_arch}/bin/solidcraft-cli" /usr/local/bin/solidcraft-cli \
    && rm -rf "/tmp/${sc_tgz}" "/tmp/solidcraft-${SOLIDCRAFT_VERSION}-linux-${sc_arch}" \
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
