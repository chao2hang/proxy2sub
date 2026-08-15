# Changelog

本项目所有重要变更记录于此。格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循 [SemVer](https://semver.org/lang/zh-CN/)。

## [0.1.3] - 2026-08-15

### Added

- **支持 `anytls://` 协议节点**：此前 `ParseLink` 未实现 anytls 分支，推送含 anytls 节点的订阅时整批落入 `invalid`（机场订阅中 anytls 占比日益升高）。新增 `parseAnyTLS` 解析 `password`/`sni`/`alpn`/`fp`/`insecure`，sing-box 测活走原生 `anytls` outbound（强制 TLS），订阅输出（v2ray URI / Clash.Meta YAML）完整往返。([#3](https://github.com/chao2hang/proxy2sub/issues/3))

## [0.1.2] - 2026-08-12

### Fixed

- **Hysteria2 节点带 `pinSHA256` 证书指纹参数时测活全部误判 dead**：`parseHysteria2` 此前未解析 `pinSHA256`，sing-box 配置也缺证书指纹字段，导致自签证书节点按系统 CA 校验必然失败（`x509: certificate signed by unknown authority`）。现已解析并在 sing-box 测活配置中输出 `certificate_public_key_sha256`，命中后 sing-box 自动改用 SPKI 指纹校验（与 Hysteria2 官方 `pinSHA256` 语义一致），比 `insecure: true` 更安全——指纹不匹配仍会失败，能检出真正坏掉的节点。订阅输出（v2ray URI / Clash.Meta YAML）同步保留 `pinSHA256` 供下游客户端校验。([#2](https://github.com/chao2hang/proxy2sub/issues/2))

## [0.1.1] - 2026-08-12

### Fixed

- **构建缺 `-tags "with_utls with_quic"` 导致 Reality/Hysteria2 节点测活全部误判 dead**：sing-box 的 uTLS（Reality 必需）与 QUIC（Hysteria/Hysteria2 必需）支持需要显式开启编译标签。新增多阶段 Dockerfile 与 release workflow 均带 tag 构建。([#1](https://github.com/chao2hang/proxy2sub/issues/1))

### Added

- 支持 `hysteria://` v1 协议：拆分 v1/v2 解析，v1 用 `auth` 串与 xplus `obfs`，新增 `up_mbps`/`down_mbps` 字段；订阅输出（v2ray URI / Clash YAML）完整往返。老格式不再被当 v2 报 "missing password"。([#1](https://github.com/chao2hang/proxy2sub/issues/1))
- 推送响应 `?detail=1` 新增 `reason` 字段：区分 `dead`（节点本身不可用）与 `unreachable`（环境不可达，如超时、DNS 失败、无 IPv6 路由），便于排查。([#1](https://github.com/chao2hang/proxy2sub/issues/1))
- 新增 Docker 镜像：每次 Release（`v*` tag）自动构建并推送至 `ghcr.io/chao2hang/proxy2sub`。
- 新增 `with_utls`/`with_quic` 编译标签回归测试，防止 build tag 再次遗漏。
