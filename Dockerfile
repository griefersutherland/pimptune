FROM golang:1.25 AS build

WORKDIR /src

ENV GOMODCACHE=/go/pkg/mod
ENV GOCACHE=/go/.cache/go-build

COPY go.mod .
COPY go.sum .
RUN --mount=type=cache,target=/go/pkg/mod go mod download

COPY internal/ ./internal
COPY cmd/ ./cmd
COPY VERSION .

ARG CGO_ENABLED=0
ARG GOOS=linux
ARG GOARCH=amd64
ARG MAIN_PKG=/src/cmd/main.go
ARG BIN_NAME=pimptune
ARG VERSION_SYMBOL=github.com/griefersutherland/pimptune/internal/utils.pimptuneVersion

ENV CGO_ENABLED=${CGO_ENABLED} \
    GOOS=${GOOS} \
    GOARCH=${GOARCH}

# Read VERSION file and inject via -X
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/go/.cache/go-build \
    set -eu; \
    VERSION="$(tr -d '\r\n' < VERSION)"; \
    echo "Building ${BIN_NAME} version=${VERSION}"; \
    go build -trimpath \
      -ldflags="-s -w -X ${VERSION_SYMBOL}=${VERSION}" \
      -o /out/${BIN_NAME} \
      ${MAIN_PKG}

# Runtime
FROM gcr.io/distroless/static-debian12:nonroot AS runtime
WORKDIR /app
ARG BIN_NAME=pimptune
COPY --from=build /out/${BIN_NAME} /app/${BIN_NAME}
EXPOSE 8080
USER nonroot:nonroot
ENTRYPOINT ["/app/pimptune"]
CMD ["run"]