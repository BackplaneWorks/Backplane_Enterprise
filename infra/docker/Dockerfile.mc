FROM cgr.dev/chainguard/minio-client:latest AS mc
FROM debian:bookworm-slim
COPY --from=mc /usr/bin/mc /usr/local/bin/mc
