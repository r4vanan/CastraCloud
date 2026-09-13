# syntax=docker/dockerfile:1

# Build all Go binaries (api, waf, cspm) in a single stage.
FROM golang:1.27-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/api ./cmd/api \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/waf ./cmd/waf \
 && CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/cspm ./cmd/cspm

FROM alpine:3.20
RUN apk add --no-cache ca-certificates tzdata
WORKDIR /app
COPY --from=build /out/api /out/waf /out/cspm /app/
COPY migrations /app/migrations
EXPOSE 8080 8000
CMD ["/app/api"]
