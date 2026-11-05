FROM golang:1.27.3-bookworm AS source
WORKDIR /src
ENV GOTOOLCHAIN=local
COPY go.mod go.sum ./
RUN go mod download
COPY cmd/ ./cmd/
COPY internal/ ./internal/
COPY migrations/ ./migrations/
COPY tests/ ./tests/
COPY openapi.yaml ./

# A separate target for unit/vet/integration runs; not part of the runtime image.
FROM source AS test
CMD ["go", "test", "./..."]

FROM source AS build
RUN CGO_ENABLED=0 go build -mod=readonly -trimpath -buildvcs=false \
    -ldflags='-s -w -buildid=' -o /out/server ./cmd/server

FROM scratch AS runtime
COPY --from=build /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY --from=build /out/server /server
USER 65532:65532
EXPOSE 8443
STOPSIGNAL SIGTERM
ENTRYPOINT ["/server"]
