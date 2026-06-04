# ---- build stage --------------------------------------------------------
# Works on both the legacy builder and BuildKit (no BuildKit-only features).
FROM golang:1.25-alpine AS build
WORKDIR /src

# cache modules in their own layer
COPY go.mod go.sum ./
RUN go mod download

# build the fully-static, CGO-free binary (assets are go:embed'd)
COPY . .
ARG VERSION=dev
RUN CGO_ENABLED=0 go build -trimpath \
    -ldflags="-s -w -X main.version=${VERSION}" \
    -o /out/grafted ./cmd/grafted

# Pre-create data/backup dirs so a fresh named volume inherits nonroot ownership
# (distroless has no shell to chown at runtime).
RUN mkdir -p /data /backups

# ---- runtime stage ------------------------------------------------------
# distroless static: CA certs, tzdata, /etc/passwd, nonroot user, no shell.
FROM gcr.io/distroless/static-debian12:nonroot
COPY --from=build /out/grafted /grafted
COPY --from=build --chown=65532:65532 /data /data
COPY --from=build --chown=65532:65532 /backups /backups

ENV GRAFTED_ADDR=:8080 \
    GRAFTED_DATA_DIR=/data \
    GRAFTED_BACKUP_DIR=/backups
EXPOSE 8080
VOLUME ["/data", "/backups"]

# No shell in distroless: the binary self-checks /healthz in -healthcheck mode.
HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \
    CMD ["/grafted", "-healthcheck"]

USER nonroot:nonroot
ENTRYPOINT ["/grafted"]
