# syntax=docker/dockerfile:1
# 多阶段构建：必须带 -tags "with_utls with_quic"，否则 sing-box 的
# Reality（依赖 uTLS）与 Hysteria/Hysteria2（依赖 QUIC）测活会全部误判 dead。
# 见 https://github.com/chao2hang/proxy2sub/issues/1

FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=linux go build \
    -tags "with_utls with_quic" \
    -ldflags "-s -w" \
    -o /out/proxy2sub .

FROM alpine:3.20
# 运行时需要 CA 证书：访问 ip-api.com、抓取远程订阅、测活目标均为 HTTPS。
RUN apk add --no-cache ca-certificates tzdata
COPY --from=build /out/proxy2sub /usr/local/bin/proxy2sub

ENV PROXY2SUB_ADDR=:8080 \
    PROXY2SUB_DB=/data/proxy2sub.db
EXPOSE 8080
VOLUME ["/data"]

ENTRYPOINT ["proxy2sub"]
