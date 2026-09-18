package main

// vless tcp+http 伪装传输探测器（联通绿通等 v2ray headerType=http 节点，见 #7）。
//
// sing-box 不支持 v2ray 的 tcp+HTTP 头伪装传输（其 v2ray 传输层仅有
// http(h2) / ws / quic / grpc / httpupgrade），因此按 v2ray-core
// transport/internet/headers/http 的协议语义自实现轻量测活：
//
//  1. TCP 连上后发送伪装 HTTP 请求（method/uri/headers 按服务端常见模板）
//  2. 紧随 VLESS 请求头（uuid + tcp 目标 = 测活地址），首段 payload 即隧道内
//     发往测活目标的 HTTP GET
//  3. 读侧先丢弃服务端的伪装 HTTP 响应模板，再读 VLESS 响应头（version + addons），
//     最后按隧道内 HTTP 状态码判定存活
//
// 服务端失败路径（已对真实联通绿通服务器联调验证）：
//   - 伪装 path 不匹配 → Close 时回 404 模板（ErrHeaderMisMatch）
//   - path 匹配但 VLESS 认证失败 → Close 时回 400 模板
//   两个模板均带 Connection: close + Content-Length: 0，读到即快速判 dead。

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"time"
)

// errUnsupportedTransport 表示 p2s 尚无法对该传输配置真实测活。
// 调用方（testItem）据此标记 skipped 保留节点，绝不判 dead 误删。
var errUnsupportedTransport = errors.New("unsupported transport for liveness probing")

const obfsUserAgent = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"

// parseUUID 把 "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx" 解析为 16 字节。
func parseUUID(s string) ([]byte, error) {
	clean := strings.ReplaceAll(strings.TrimSpace(s), "-", "")
	b, err := hex.DecodeString(clean)
	if err != nil || len(b) != 16 {
		return nil, fmt.Errorf("bad uuid %q", s)
	}
	return b, nil
}

// probeVlessHTTPObfs 对 vless+tcp+headerType=http 节点执行真实测活。
// ctx 已带整体 deadline（Tester.Test 统一设置）。
func (t *Tester) probeVlessHTTPObfs(ctx context.Context, n *Node) (time.Duration, error) {
	uuid, uerr := parseUUID(n.UUID)
	if uerr != nil {
		return 0, fmt.Errorf("vless obfs probe: %w", uerr)
	}

	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(n.Server, strconv.Itoa(n.Port)))
	if err != nil {
		return 0, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	if d, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(d)
	}

	// TLS 在外层（tcp+tls+http 伪装时，HTTP 伪装跑在 TLS 隧道内）。
	if n.TLS {
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName:         orDefault(n.SNI, n.Server),
			InsecureSkipVerify: n.Insecure,
			MinVersion:         tls.VersionTLS12,
		})
		if herr := tlsConn.HandshakeContext(ctx); herr != nil {
			return 0, fmt.Errorf("tls handshake: %w", herr)
		}
		conn = tlsConn
	}

	// 解析测活目标：优先 IP（与 sing-box 路径行为一致），解析不出则发域名交由远端解析。
	// VLESS 地址类型：0x01=IPv4，0x02=域名，0x03=IPv6。
	targetHost, targetPort, targetPath, targetTLS := t.targetHost, int(t.targetPort), t.targetPath, t.targetTLS
	var addrType byte
	var addr []byte
	if ip, rerr := resolveOne(ctx, targetHost); rerr == nil && ip.Is4() {
		a4 := ip.As4()
		addrType, addr = 0x01, a4[:]
	} else {
		addrType, addr = 0x02, []byte(targetHost)
	}

	var req strings.Builder
	req.WriteString("GET " + orDefault(n.Path, "/") + " HTTP/1.1\r\n")
	req.WriteString("Host: " + orDefault(n.Host, n.Server) + "\r\n")
	req.WriteString("User-Agent: " + obfsUserAgent + "\r\n")
	req.WriteString("Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8\r\n")
	req.WriteString("Accept-Language: zh-CN,zh;q=0.8,en-US;q=0.5,en;q=0.3\r\n")
	req.WriteString("Accept-Encoding: gzip, deflate\r\n")
	req.WriteString("Connection: keep-alive\r\n")
	req.WriteString("Pragma: no-cache\r\n\r\n")

	// VLESS 请求：version(0) + uuid + addonLen(0) + cmd(tcp) + port(BE) + addrType + addr
	vless := []byte{0x00}
	vless = append(vless, uuid...)
	vless = append(vless, 0x00, 0x01)
	var portBE [2]byte
	binary.BigEndian.PutUint16(portBE[:], uint16(targetPort))
	vless = append(vless, portBE[:]...)
	vless = append(vless, addrType, byte(len(addr)))
	vless = append(vless, addr...)
	// 首段 payload：隧道内发往测活目标的 HTTP 请求（与 sing-box 路径一致）
	scheme := "http"
	if targetTLS {
		scheme = "https"
	}
	vless = append(vless, []byte(fmt.Sprintf(
		"GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: %s\r\nAccept: */*\r\nConnection: close\r\n\r\n",
		targetPath, targetHost, scheme))...)

	start := time.Now()
	if _, werr := conn.Write([]byte(req.String() + string(vless))); werr != nil {
		return 0, fmt.Errorf("write: %w", werr)
	}

	br := bufio.NewReader(conn)

	// 1) 伪装 HTTP 响应模板：状态码 >= 400 说明 path/Host/认证被服务端拒绝（快速判 dead）
	line, err := br.ReadString('\n')
	if err != nil {
		return 0, fmt.Errorf("read obfs status: %w", err)
	}
	if code := parseStatus(line); code >= 400 {
		return 0, fmt.Errorf("obfs rejected: HTTP %d", code)
	}
	// 丢弃剩余响应头直到空行
	for {
		hdr, herr := br.ReadString('\n')
		if herr != nil {
			return 0, fmt.Errorf("read obfs headers: %w", herr)
		}
		if hdr == "\r\n" || hdr == "\n" {
			break
		}
	}

	// 2) VLESS 响应头：version(1) + addonLen(1) + addons
	respHeader := make([]byte, 2)
	if _, rerr := io.ReadFull(br, respHeader); rerr != nil {
		return 0, fmt.Errorf("read vless response: %w", rerr)
	}
	if respHeader[1] > 0 {
		if _, rerr := io.CopyN(io.Discard, br, int64(respHeader[1])); rerr != nil {
			return 0, fmt.Errorf("read vless addons: %w", rerr)
		}
	}

	// 3) 隧道内测活目标的 HTTP 状态码（与 sing-box 路径判定一致：2xx/3xx = alive）
	statusLine, err := br.ReadString('\n')
	if err != nil {
		return 0, fmt.Errorf("read: %w", err)
	}
	latency := time.Since(start)
	code := parseStatus(statusLine)
	if code >= 200 && code < 400 {
		return latency, nil
	}
	return latency, fmt.Errorf("status %d", code)
}
