# Changelog

本项目所有重要变更记录于此。格式参考 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，版本号遵循 [SemVer](https://semver.org/lang/zh-CN/)。

## [0.1.7] - 2026-09-18

### Fixed

- **长期运行内存持续增长（#9）**：#5 的全局 deadline 兜底让 `checkOnce` 不再无限等待，但 deadline 时仍卡在 sing-box 内部 syscall（QUIC/UTLS/DNS 底层 socket，不响应 ctx 取消）的测活 goroutine 从此无人接管——`Test` 不返回则 `defer inst.Close()` 永不执行，每个卡死的测试永久泄漏一个完整 sing-box 实例（注册表 context、内部 goroutine、缓冲区、fd），GC 无法回收，`GOMEMLIMIT` 无效；~753 节点 / `concurrency=20` 实测 29 天 RSS 从 ~55MB 涨到数 GB。

  现为 `Tester.Test` 挂 `time.AfterFunc(2×TestTimeout)` 看门狗：超时后从外部强制 `inst.Close()`——关闭 outbound 解除卡死的 dial，goroutine 得以返回并走完清理。`sync.Once` 保证 Close 只执行一次；sing-box `Box.Close` 内部 done channel 对二次关闭直接返回 `os.ErrClosed`，并发/幂等语义安全。

  同时修正 deadline 日志文案（原 `714/723 items unresolved` 实际含义是"完成 714、剩 7 个"，极易误读为 714 个泄漏）与 `/healthz`、`/api/stats` 可观测性（见 Added）。
- **大库周期检查永远测不完、alive 统计失真（#8）**：`testConcurrent` 的"非阻塞抢信号量、抢不到即 skipped"使每轮只随机测到 Concurrency 个节点（1446 节点 × 10min 周期 = 每轮随机抽样 20 个），其余瞬间 skipped 且无"未测优先"逻辑，alive 统计只反映当轮被抽到的节点。

  现重写为 **worker-pool**：固定 Concurrency 个 worker 从队列逐个领取节点，**每轮全量节点都被真实测完**；全局 deadline 随规模伸缩（`3×TestTimeout×⌈N/Concurrency⌉ + 30s`）；deadline 截断的节点标 `skipped`（保留、下轮重测），绝不判 dead。push 与周期检查共用该路径，push 响应与日志同步区分 `skipped`（v0.1.6 及之前 skipped 节点在 push 中被计入 dead）。
- **联通绿通节点测活误判 dead（#7）**：`vless+tcp+headerType=http`（HTTP 头伪装）与 `vmess+ws+host` 伪装节点 TCP 连通但 p2s 判 dead、无法入库。实测确认 sing-box v1.13 的 v2ray 传输层仅支持 http(h2)/ws/quic/grpc/httpupgrade，**不支持 v2ray 的 tcp+HTTP 头伪装**，标准协议探测对这些节点必然超时。

  现按 v2ray-core `transport/internet/headers/http` 协议语义自实现轻量探测器（`obfsprobe.go`）：发伪装 HTTP 请求 + VLESS 握手 + 隧道内 HTTP GET，服务端 404/400 错误模板（已对真实绿通服务器联调核对）快速判 dead，VLESS 响应头 + 隧道状态码判 alive；支持 tcp / tcp+tls 两种形态。`vmess` 的 tcp+http 伪装因协议加密无法独立握手，标 `skipped` 保留不删（`errUnsupportedTransport`）。订阅输出完整往返：v2ray URI 携带 `headerType`/`type`，Clash 输出 `network: http` + `http-opts`。另修复 ws 传输向 sing-box 下发空 `Host: ""` 头的问题（节点无 host 时不再干扰握手）。
- **周期检查误删节点收尾（#6）**：在 v0.1.6 修复（sem-full 不再标 dead + 删除熔断）基础上，deadline 截断的在飞测试现统一标 `skipped`（此前 per-ctx 取消错误会被标 dead 进入删除队列），实现"超时未完成 ≠ 节点失败，保留原状态下轮重测"的完整语义；pushItem 结果读写加锁，消除 deadline 残留 goroutine 迟到写入与主流程读取的数据竞争。

### Added

- `/healthz` 与 `/api/stats` 新增 `goroutines` 字段（`runtime.NumGoroutine()`）：健康实例稳定在低位，测活 goroutine 泄漏时线性上涨，可据此提前告警（#9 建议的可观测性）。
- `POST /api/push` 响应与日志新增 `skipped` 计数（deadline 截断 / 不支持传输，未入库、非 dead）；`POST /api/check` 同步响应新增 `skipped`。

## [0.1.6] - 2026-08-19

### Fixed

- **周期检查误删全部节点（v0.1.5 #6 复盘 2555→17）**：`testConcurrent` 的 `sem-full` 跳过分支曾把"本轮未测到"的节点直接打上 `dead` 标签，`checkOnce` 的删除条件又是"非 alive 即删"，导致并发数小于节点数时首轮把 keep-alive 之外的 TCP 类节点（vless/trojan/anytls/hy2）批量误判死节点并删除；全局 deadline 兜底触发时残留的未完成项同样落在"非 alive 即删"路径下被误删。([#6](https://github.com/chao2hang/proxy2sub/issues/6))

  现修复三处歧义：
  - `api.go` `testConcurrent` 的 `sem-full` 默认分支：放弃 dead 标，改用 `status = "skipped"` —— 仅表示"本轮因 sem 满未测到"，留待下轮再测
  - `api.go` `checkOnce` 删除条件：由 `if it.status != "alive"` 改为 `if it.status == "dead"` —— 只有确认 sing-box 报错或 panics 的节点才进删除队列，`pending` / `skipped` / `""` 全部保留，下一轮重测
  - `api.go` `checkOnce` 新增删除熔断 `PROXY2SUB_MAX_DEAD_RATIO`（默认 `50`）：单轮 `dead/total` 比例超阈值时立即中止本轮删除，仅刷新 alive 元数据并 `log.Printf` 强告警，避免单点故障导致批量误删灾难。小库（`total<20`）直通删除避免误触发

### Added

- `PROXY2SUB_MAX_DEAD_RATIO` 环境变量：单轮删除熔断阈值百分比（`0` 禁用，默认 `50`）。

## [0.1.5] - 2026-08-19

### Fixed

- **v0.1.4 `checkOnce` 死锁 / 多轮叠加**：`testConcurrent` 同步 `wg.Wait()` 等待所有测活完成，但 sing-box 内部 syscall 泄漏（QUIC/UTLS/DNS 底层 socket）不响应 ctx 取消，单节点测活永久阻塞 → 后续节点在 `sem <- struct{}{}` 处永久卡住 → `wg.Wait()` 永不返回 → `checkOnce` 卡死，每 10min ticker 叠加新一轮最终 OOM。([#5](https://github.com/chao2hang/proxy2sub/issues/5))

  现重写并发模型：
  - `sem <- struct{}{}` 移入 goroutine 内 + `select default` 跳过（信号量满的节点本轮直接标 `skipped` 留待下轮再测），主循环不再阻塞
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
