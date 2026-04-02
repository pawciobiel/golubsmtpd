FROM golang:1.25-alpine AS builder

WORKDIR /build

COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build -trimpath -ldflags="-s -w" -o golubsmtpd ./cmd/golubsmtpd

FROM scratch

COPY --from=builder /build/golubsmtpd /golubsmtpd
COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/

EXPOSE 587

ENTRYPOINT ["/golubsmtpd"]
CMD ["-config", "/data/conf/golubsmtpd.yaml"]
