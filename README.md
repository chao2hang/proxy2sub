# proxy2sub

> 极简的代理订阅网关：接收各渠道推送的代理线路，测活后入库，按国家分组输出订阅。

![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?logo=go) ![Release](https://img.shields.io/github/v/release/chao2hang/proxy2sub)

接收各渠道推送的代理线路（vmess / vless / trojan / shadowsocks / hysteria2 / anytls / http / socks5），**入库前真实测活，活的才放行**；**周期性复测，失效的自动删除**；对外提供按国家分组的订阅链接（Clash YAML / v2ray base64），节点名为 `国家代码_IP`（如 `US_1.2.3.4`）。

## 特性

- **推送即测活**：`POST /api/push` 收到线路后经 sing-box 真实建连访问测活目标，只有活着的线路才入库
- **周期复测**：后台定时全量测活，失效线路自动删除，存活线路刷新延迟
- **国家识别**：按服务器 IP 解析国家（支持本地 mmdb 离线库，缺省走 ip-api.com 在线批量接口）
- **规范命名**：`US_8.8.8.8` 形式，域名服务器先解析为 IP 再命名
- **订阅输出**：`GET /sub` 按 `Accept`/`User-Agent` 自动返回 Clash YAML 或 v2ray base64，Clash 中按国家生成 `proxy-groups`
- **支持 base64 导入**：整体 base64 订阅、每行单独 base64、JSON `links` 内嵌 base64 均可
- 支持 `?country=US` 过滤、`?type=clash|v2ray` 强制指定格式
- 可选鉴权：推送 / 订阅可分别配置 token

## 安装

**方式一：直接下载二进制（推荐）**

从 [Releases](https://github.com/chao2hang/proxy2sub/releases) 下载对应平台的文件：

| 文件 | 平台 |
| --- | --- |
| `proxy2sub-darwin-amd64` | macOS Intel |
| `proxy2sub-darwin-arm64` | macOS Apple Silicon |
| `proxy2sub-linux-amd64` | Linux x86_64 |
| `proxy2sub-linux-arm64` | Linux ARM64 |

```bash
chmod +x proxy2sub-linux-amd64
./proxy2sub-linux-amd64
```

**方式二：源码构建**

```bash
git clone https://github.com/chao2hang/proxy2sub.git
cd proxy2sub
go build -tags "with_utls with_quic" -o proxy2sub .
./proxy2sub
```

默认监听 `:8080`，数据存于同目录 `proxy2sub.db`。可通过环境变量配置（见[配置](#配置环境变量)）。

> ⚠️ **必须带 `-tags "with_utls with_quic"`**：sing-box 的 Reality（依赖 uTLS）与 Hysteria/Hysteria2（依赖 QUIC）支持需要这两个编译标签显式开启，否则这两类节点测活会全部误判 dead（详见 [#1](https://github.com/chao2hang/proxy2sub/issues/1)）。下载 Release 二进制无需关心，已带 tag 构建。

**方式三：Docker**

```bash
docker run -d --name proxy2sub \
  -p 8080:8080 -v proxy2sub-data:/data \
  ghcr.io/chao2hang/proxy2sub:latest
```

镜像在每次 Release（`v*` tag）时自动构建并推送至 GHCR。

## 快速开始

### 推送线路

文本格式（每行一条，支持 base64 导入）：

```bash
# 每行一条线路
curl -X POST http://127.0.0.1:8080/api/push \
  --data-binary 'vmess://...
vless://...
ss://...
http://user:pass@1.2.3.4:8080'

# 整个 v2ray 订阅（base64 整体编码）
curl -X POST http://127.0.0.1:8080/api/push \
  --data-binary 'aHR0cDovLzEyNy4wLjAuMToxODA4MAo...'

# 每行单独 base64 也可以
curl -X POST http://127.0.0.1:8080/api/push \
  --data-binary 'aHR0cDovLzEyNy4wLjAuMToxODA4MAo=
dm1lc3M6Ly9leUowLi4u'
```

JSON 格式（`links` 为线路，支持 base64 编码的条目；`urls` 为远程订阅地址，会被抓取后解析）：

```bash
curl -X POST http://127.0.0.1:8080/api/push \
  -H 'Content-Type: application/json' \
  -d '{"links":["vmess://...","aHR0cDovLzEuMi4zLjQ6ODA4MAo="],"urls":["https://example.com/sub"]}'
```

返回：

```json
{
  "received": 4,
  "parsed": 4,
  "invalid": 0,
  "duplicates": 0,
  "alive": 1,
  "dead": 3,
  "added": 1
}
```

加 `?detail=1` 可查看每条线路的处理结果（含失败原因、延迟、命名）。

### 获取订阅

```bash
# 默认：curl 等普通 UA 返回 v2ray base64
curl -s http://127.0.0.1:8080/sub

# Clash 客户端自动命中（Accept/UA 含 clash/mihomo/stash/surge），或强制指定
curl -s http://127.0.0.1:8080/sub?type=clash

# 只取某个国家
curl -s 'http://127.0.0.1:8080/sub?type=clash&country=US'
```

v2rayN / Clash 客户端的订阅地址均填写：`http://<host>:<port>/sub`

### 其他接口

| 路径 | 说明 |
| --- | --- |
| `POST /api/push` | 批量推送节点（详见下文） |
| `POST /api/check` | 手动触发一轮周期测活（同步返回结果，`?sync=0` 异步立即 202） |
| `GET /sub` | 订阅输出（v2ray URI / Clash YAML，按 `Accept` / `?format=` 选择） |
| `GET /api/stats` | 节点总数、按国家/协议统计 |
| `GET /healthz` | 健康检查 |

## 配置（环境变量）

| 变量 | 默认 | 说明 |
| --- | --- | --- |
| `PROXY2SUB_ADDR` | `:8080` | HTTP 监听地址 |
| `PROXY2SUB_DB` | `proxy2sub.db` | SQLite 数据库路径 |
| `PROXY2SUB_PUSH_TOKEN` | 空 | 推送接口 token（`Authorization: Bearer xxx` 或 `?token=xxx`） |
| `PROXY2SUB_SUB_TOKEN` | 空 | 订阅接口 token |
| `PROXY2SUB_CHECK_INTERVAL` | `10m` | 周期测活间隔（如 `5m`、`30s`） |
| `PROXY2SUB_CHECK_ON_START` | `false` | 启动 3 秒后先跑一轮测活；周期任务自带 panic recover，畸形节点不会杀死 ticker goroutine |
| `PROXY2SUB_TEST_TIMEOUT` | `8s` | 单节点测活超时 |
| `PROXY2SUB_TEST_URL` | `http://www.gstatic.com/generate_204` | 测活目标（经代理访问） |
| `PROXY2SUB_CONCURRENCY` | `20` | 测活并发数；大于节点数时所有节点都能测试；小于节点数时多余的会被本轮标记 `skipped`（不影响存活判定） |
| `PROXY2SUB_MAX_DEAD_RATIO` | `50` | 单轮删除熔断阈值（百分比）。`dead/total` 超过该值时中止本轮删除并告警，避免类似 #6 类批量误删灾难。设 `0` 禁用熔断。仅在 `total >= 20` 时生效 |
| `PROXY2SUB_GEOIP_DB` | 空 | 本地 mmdb 文件路径（缺省读取同目录 `Country.mmdb`，都没有则用 ip-api.com 在线接口） |

## 国家识别

默认使用在线接口 `ip-api.com/batch`（免费无 key，批量 100 IP/请求，带缓存）。如需离线识别，下载 Country 级 mmdb 放到同目录或指定 `PROXY2SUB_GEOIP_DB`：

```bash
# 例如使用 Loyalsoldier/geoip 发布的 Country.mmdb
curl -L -o Country.mmdb https://github.com/Loyalsoldier/geoip/releases/latest/download/Country.mmdb
```

## 说明与限制

- 去重键为 `协议 + 服务器 + 端口`，同一服务器不同账号的线路视为重复
- 测活通过 sing-box 真实建连完成，支持 ws/grpc/h2/reality 等传输层；ss 插件（obfs-local、v2ray-plugin）按原样透传
- 文本输入中 `http(s)://` 开头的行按 **HTTP 代理线路** 处理；抓取远程订阅请用 JSON 的 `urls` 字段
- 只有存活线路才会出现在订阅中，死线路不会下发
- 构建必须带 `-tags "with_utls with_quic"`：Reality 需要 uTLS、Hysteria/Hysteria2 需要 QUIC，缺 tag 时这两类节点会全部误判 dead
- `hysteria://`（v1，`?auth=` 格式）与 `hy2://`/`hysteria2://`（v2）均支持；推送响应的 `reason` 字段区分 `dead`（节点本身不可用）与 `unreachable`（环境不可达，如超时、无 IPv6 路由）
- 支持 `anytls://` 协议（Clash/mihomo 订阅中常见），解析后经 sing-box 原生 anytls outbound 测活，订阅输出（v2ray URI / Clash YAML）完整往返

## 开发

```bash
go test ./...          # 单元测试（含各协议解析、base64 导入、Clash YAML 合法性）
go build -tags "with_utls with_quic" -o proxy2sub .
```

`tools/testproxy` 是一个极简本地 CONNECT 代理，便于本地联调测活流程。
