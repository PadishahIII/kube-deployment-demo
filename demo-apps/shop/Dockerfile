# demo-apps/shop — a minimal non-root web server (tenant-a, :8080).
# Built FROM a distroless base: no shell, no package manager, tiny attack surface.
# The final image is pushed to the governed registry (docker.io/padishahiii/*)
# and cosign-signed — see SETUP_DEMO.md "Producing the demo signed images".
FROM gcr.io/distroless/nodejs22

# Run as uid 1000 (non-root). distroless/nodejs provides a `node` user at uid 1000;
# the numeric id is used for portability across base-image versions. It matches
# the chart's fsGroup: 1000 so the app can write its /tmp volume.
USER 1000:1000
WORKDIR /app
COPY --chown=1000:1000 server.js ./

ENV PORT=8080
EXPOSE 8080
# The base image sets ENTRYPOINT ["/nodejs/bin/node"], so CMD is just the script.
# (CMD ["node", "server.js"] would become "node node server.js" and crash.)
CMD ["server.js"]
