package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	sj "github.com/sagernet/sing/common/json"
	"github.com/sagernet/sing/common/metadata"
)

// Tester 通过 sing-box 真实建立代理连接并访问测活目标，返回延迟。
type Tester struct {
	timeout    time.Duration
	targetHost string
	targetPort uint16
	targetPath string
	targetTLS  bool
}

func NewTester(timeout time.Duration, testURL string) (*Tester, error) {
	u, err := url.Parse(testURL)
	if err != nil {
		return nil, fmt.Errorf("bad test url: %w", err)
	}
	host := u.Hostname()
	if host == "" {
		return nil, fmt.Errorf("bad test url: missing host")
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	p, err := strconv.Atoi(port)
	if err != nil {
		return nil, fmt.Errorf("bad test url port: %s", port)
	}
	path := u.RequestURI()
	if path == "" {
		path = "/"
	}
	return &Tester{
		timeout:    timeout,
		targetHost: host,
		targetPort: uint16(p),
		targetPath: path,
		targetTLS:  u.Scheme == "https",
	}, nil
}

// Test 建立真实连接并访问测活目标。成功返回延迟；失败返回错误。
func (t *Tester) Test(ctx context.Context, n *Node) (time.Duration, error) {
	ctx, cancel := context.WithTimeout(ctx, t.timeout)
	defer cancel()

	// 每个实例使用独立的注册表 context，避免并发 Box 相互覆盖
	bctx := box.Context(ctx,
		include.InboundRegistry(),
		include.OutboundRegistry(),
		include.EndpointRegistry(),
		include.DNSTransportRegistry(),
		include.ServiceRegistry())

	opts, err := singboxOptions(bctx, n)
	if err != nil {
		return 0, fmt.Errorf("parse options: %w", err)
	}
	inst, err := box.New(box.Options{Context: bctx, Options: opts})
	if err != nil {
		return 0, fmt.Errorf("init singbox: %w", err)
	}
	defer inst.Close()
	if err := inst.Start(); err != nil {
		return 0, fmt.Errorf("start singbox: %w", err)
	}

	out, ok := inst.Outbound().Outbound("proxy")
	if !ok {
		return 0, fmt.Errorf("outbound proxy not found")
	}

	ip, err := resolveOne(ctx, t.targetHost)
	if err != nil {
		return 0, fmt.Errorf("resolve %s: %w", t.targetHost, err)
	}
	dst := metadata.ParseSocksaddr(ip.String() + ":" + strconv.Itoa(int(t.targetPort)))

	start := time.Now()
	conn, err := out.DialContext(ctx, "tcp", dst)
	if err != nil {
		return 0, fmt.Errorf("dial: %w", err)
	}
	defer conn.Close()
	if d, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(d)
	}

	var rw io.ReadWriter = conn
	if t.targetTLS {
		tlsConn := tls.Client(conn, &tls.Config{
			ServerName: t.targetHost,
			MinVersion: tls.VersionTLS12,
		})
		if err := tlsConn.HandshakeContext(ctx); err != nil {
			return 0, fmt.Errorf("tls handshake: %w", err)
		}
		rw = tlsConn
	}
	req := fmt.Sprintf("GET %s HTTP/1.1\r\nHost: %s\r\nUser-Agent: Mozilla/5.0\r\nAccept: */*\r\nConnection: close\r\n\r\n",
		t.targetPath, t.targetHost)
	if _, err := io.WriteString(rw, req); err != nil {
		return 0, fmt.Errorf("write: %w", err)
	}
	line, err := bufio.NewReader(rw).ReadString('\n')
	if err != nil {
		return 0, fmt.Errorf("read: %w", err)
	}
	latency := time.Since(start)
	code := parseStatus(line)
	if code >= 200 && code < 400 {
		return latency, nil
	}
	return latency, fmt.Errorf("status %d", code)
}

// singboxOptions 把 Node 转成 sing-box 配置。
func singboxOptions(ctx context.Context, n *Node) (option.Options, error) {
	cfg := map[string]any{
		"log":       map[string]any{"disabled": true, "level": "fatal"},
		"inbounds":  []any{},
		"outbounds": []any{singboxOutbound(n)},
		"route":     map[string]any{"final": "proxy"},
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		return option.Options{}, err
	}
	return sj.UnmarshalExtendedContext[option.Options](ctx, data)
}

var vmessSecurities = map[string]bool{
	"auto": true, "aes-128-gcm": true, "chacha20-poly1305": true, "none": true, "zero": true,
}

func singboxOutbound(n *Node) map[string]any {
	m := map[string]any{
		"type":        n.Protocol,
		"tag":         "proxy",
		"server":      n.Server,
		"server_port": n.Port,
	}
	switch n.Protocol {
	case "vmess":
		m["uuid"] = n.UUID
		sec := n.Security
		if !vmessSecurities[sec] {
			sec = "auto"
		}
		m["security"] = sec
		if n.AlterID > 0 {
			m["alter_id"] = n.AlterID
		}
	case "vless":
		m["uuid"] = n.UUID
		if n.Flow != "" {
			m["flow"] = n.Flow
		}
	case "trojan":
		m["password"] = n.Password
	case "shadowsocks":
		m["method"] = n.Security
		m["password"] = n.Password
		if n.Plugin != "" {
			m["plugin"] = n.Plugin
			m["plugin_opts"] = n.PluginOpt
		}
	case "hysteria2":
		m["password"] = n.Password
		if n.Obfs != "" {
			m["obfs"] = map[string]any{"type": n.Obfs, "password": n.ObfsPass}
		}
	case "anytls":
		// anytls：TCP+TLS，认证用 password；无 obfs/传输层。
		m["password"] = n.Password
	case "hysteria":
		// hysteria v1: auth_str 是认证串，obfs 是 xplus 密码。
		// up/down 缺省给 100 Mbps（测活数据量小，0 可能导致 BBR 协商异常）。
		m["auth_str"] = n.Password
		if n.Obfs != "" {
			m["obfs"] = n.Obfs
		}
		if n.UpMbps > 0 {
			m["up_mbps"] = n.UpMbps
		} else {
			m["up_mbps"] = 100
		}
		if n.DownMbps > 0 {
			m["down_mbps"] = n.DownMbps
		} else {
			m["down_mbps"] = 100
		}
	case "http":
		if n.Username != "" {
			m["username"] = n.Username
		}
		m["password"] = n.Password
	case "socks":
		if n.Username != "" {
			m["username"] = n.Username
		}
		m["password"] = n.Password
	}

	if n.TLS && (n.Protocol == "vmess" || n.Protocol == "vless" ||
		n.Protocol == "trojan" || n.Protocol == "hysteria" ||
		n.Protocol == "hysteria2" || n.Protocol == "anytls" ||
		n.Protocol == "http") {
		tlsObj := map[string]any{
			"enabled":     true,
			"server_name": orDefault(n.SNI, n.Server),
		}
		if n.Insecure {
			tlsObj["insecure"] = true
		}
		if len(n.ALPN) > 0 {
			tlsObj["alpn"] = n.ALPN
		}
		if n.FP != "" && n.FP != "none" && n.FP != "randomized" {
			tlsObj["utls"] = map[string]any{"enabled": true, "fingerprint": n.FP}
		}
		if n.RealityPK != "" {
			tlsObj["reality"] = map[string]any{
				"enabled": true, "public_key": n.RealityPK, "short_id": n.RealitySID,
			}
		}
		// pinSHA256：Hysteria2 自签证书靠证书指纹固定校验。
		// sing-box 的 certificate_public_key_sha256 是 Listable[[]byte]，
		// JSON 反序列化时 []byte 走 base64 std，因此这里 hex→bytes→base64。
		// 命中后 sing-box 自动 InsecureSkipVerify=true 并改用 pin 校验，
		// 比直接 insecure:true 更安全（指纹不匹配仍会失败）。
		if b, ok := decodePinSHA256(n.PinSHA256); ok {
			tlsObj["certificate_public_key_sha256"] = []string{base64.StdEncoding.EncodeToString(b)}
		}
		m["tls"] = tlsObj
	}

	switch n.Network {
	case "ws":
		ws := map[string]any{"path": n.Path}
		if n.Host != "" {
			ws["headers"] = map[string]any{"Host": n.Host}
		}
		m["transport"] = map[string]any{"type": "ws", "path": n.Path, "headers": map[string]any{"Host": n.Host}}
	case "grpc":
		m["transport"] = map[string]any{"type": "grpc", "service_name": orDefault(n.Service, n.Path)}
	case "h2":
		m["transport"] = map[string]any{"type": "http", "host": []string{n.Host}, "path": n.Path}
	}
	return m
}

// decodePinSHA256 把 Hysteria2 链接里的 pinSHA256(hex) 解成 32 字节摘要。
// 合法值是 64 个 hex 字符；非法返回 (nil, false)，调用方静默跳过。
func decodePinSHA256(s string) ([]byte, bool) {
	s = strings.TrimSpace(s)
	if len(s) != 64 {
		return nil, false
	}
	b, err := hex.DecodeString(s)
	if err != nil || len(b) != 32 {
		return nil, false
	}
	return b, true
}

func resolveOne(ctx context.Context, host string) (netip.Addr, error) {
	if ip := net.ParseIP(host); ip != nil {
		if a, ok := netip.AddrFromSlice(ip); ok {
			return a.Unmap(), nil
		}
	}
	addrs, err := net.DefaultResolver.LookupNetIP(ctx, "ip", host)
	if err != nil {
		return netip.Addr{}, err
	}
	for _, a := range addrs {
		if a.Is4() {
			return a, nil
		}
	}
	if len(addrs) > 0 {
		return addrs[0], nil
	}
	return netip.Addr{}, fmt.Errorf("no address")
}

func parseStatus(line string) int {
	parts := strings.Fields(line)
	if len(parts) >= 2 {
		if code, err := strconv.Atoi(parts[1]); err == nil {
			return code
		}
	}
	return 0
}
