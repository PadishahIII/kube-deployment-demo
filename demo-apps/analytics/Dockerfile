# demo-apps/analytics — a minimal non-root web server (tenant-b, :9090).
# Built FROM a distroless base: no shell, no package manager, tiny attack surface.
FROM gcr.io/distroless/nodejs22

# Run as uid 1000 (non-root) — matches the chart's fsGroup: 1000.
USER 1000:1000
WORKDIR /app
COPY --chown=1000:1000 server.js ./

ENV PORT=9090
EXPOSE 9090
# The base image sets ENTRYPOINT ["/nodejs/bin/node"], so CMD is just the script.
CMD ["server.js"]
