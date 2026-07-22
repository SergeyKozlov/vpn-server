# api/Dockerfile
#
# Binaries are built on the host (`make build-api`) rather than inside this
# image: the target host has ~1GB RAM shared with Postgres/Xray/Hysteria2/
# Caddy and can't reliably afford a golang:alpine build stage (module
# download + compile) alongside them. This Dockerfile only packages
# already-built static binaries into a minimal distroless runtime.
FROM gcr.io/distroless/static-debian12
COPY vpn-api /vpn-api
COPY vpn-createadmin /createadmin
EXPOSE 8080
ENTRYPOINT ["/vpn-api"]
