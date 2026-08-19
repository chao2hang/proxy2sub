# Changelog

本项目所有重要变更记录于此。格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循 [SemVer](https://semver.org/lang/zh-CN/)。

## [0.1.5] - 2026-08-19

### Fixed

- **v0.1.4 `checkOnce` 死锁 / 多轮叠加**：`testConcurrent` 同步 `wg.Wait()` 等待所有测活完成，但 sing-box 内部 syscall 泄漏（QUIC/UTLS/DNS 底层 socket）不响应 ctx 取消，单节点测活永久阻塞 → 后续节点在 `sem <- struct{}{}` 处永久卡住 → `wg.Wait()` 永不返回 → `checkOnce` 卡死，每 10min ticker 叠加新一轮最终 OOM。([#5](https://github.com/chao2hang/proxy2sub/issues/5))

  现重写并发模型：
  - `sem <- struct{}{}` 移入 goroutine 内 + `select default` 跳过（信号量满的节点本轮直接标 `dead/skipped: concurrency full` 留待下轮再测），主循环不再阻塞
  - 全局 `testCtx = TestTimeout*3 + 30s` 兜底，轮询 `done` 计数；deadline 一到立即 return，不再等泄漏 goroutine
  - 最佳努力 `go wg.Wait()` 在后台清点泄漏（不阻塞 checkOnce 返回）
  - `safeCheckOnce` 加 `atomic.Bool.CompareAndSwap` 单飞：上一轮未结束则本轮 `skip, previous round still running` 立即返回，避免多轮叠加
  - `checkOnce` 起始日志补 `concurrency=%d timeout=%s`，便于排障
  - `Server.tester` 改接口 (`TesterIface`)，便于测试注入 fake tester 覆盖泄漏场景

## [0.1.4] - 2026-08-18

### Fixed

- **官方镜像 `checkLoop` 周期检查从未执行**：`testConcurrent` / `checkOnce` / `checkLoop` 全程无 panic recover，遇到畸形节点（如 sing-box 配置异常、参数组合越界）时单节点测活 panic 会直接杀死整个周期 goroutine，main 无感知，导致 `last_check` 仅随 push 更新、失效节点永不清理。现已为每节点 goroutine、`checkOnce`、`checkLoop` 三层加 `defer recover()`，单节点 panic 仅记日志并标记 dead，不影响其他节点也不影响后续周期；同步 `safeCheckOnce` 复用于 `POST /api/check`。`checkOnce` 同时增加起始行 `start total=N` 日志，让"ticker 在转"对空库也可见。([#4](https://github.com/chao2hang/proxy2sub/issues/4))
- **`PROXY2SUB_CHECK_ON_START` 真正生效**：原实现是独立 goroutine `time.Sleep(3s)` 后调 `checkOnce`，无 recover 且与 ticker 解耦。现已并入 `checkLoop`，首轮与 ticker 同栈走 `safeCheckOnce`，确保即便首轮 panic 也不影响后续周期。([#4](https://github.com/chao2hang/proxy2sub/issues/4))

### Added

- **`POST /api/check` 手动触发测活**：同步模式返回 `{status, total, alive, dead}`；`?sync=0` 异步模式立即返回 202。复用 `PROXY2SUB_PUSH_TOKEN` 鉴权。便于排障时无需等待周期。([#4](https://github.com/chao2hang/proxy2sub/issues/4))

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
