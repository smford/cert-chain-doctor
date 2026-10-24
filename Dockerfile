# Multi-stage Dockerfile for cert-chain-doctor
FROM --platform=$BUILDPLATFORM golang:alpine AS builder
ENV GOTOOLCHAIN=auto

WORKDIR /src
COPY go.mod ./
RUN go mod download

COPY . .

ARG TARGETOS
ARG TARGETARCH
ARG VERSION=0.1.0
ARG COMMIT=none
ARG DATE=unknown

RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build \
    -trimpath \
    -ldflags="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
    -o /cert-chain-doctor ./cmd/cert-chain-doctor

# Final distroless nonroot image
FROM gcr.io/distroless/static-debian12:nonroot

WORKDIR /
COPY --from=builder /cert-chain-doctor /usr/local/bin/cert-chain-doctor

EXPOSE 8080
USER nonroot:nonroot

ENTRYPOINT ["/usr/local/bin/cert-chain-doctor"]
CMD ["serve", "--addr", ":8080"]
