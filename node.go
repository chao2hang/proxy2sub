package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Node 统一描述一条代理线路（支持：vmess / vless / trojan / shadowsocks /
// hysteria2 / anytls / http / socks5）。测活、入库、订阅输出均基于该结构。
type Node struct {
	Protocol   string            `json:"protocol"`
	Server     string            `json:"server"`
	Port       int               `json:"port"`
	Name       string            `json:"name,omitempty"`     // 规范名，如 US_1.2.3.4
	IP         string            `json:"ip,omitempty"`       // Server 解析出的 IP
	Country    string            `json:"country,omitempty"`  // 国家代码，如 US
	UUID       string            `json:"uuid,omitempty"`     // vmess / vless
	AlterID    int               `json:"alter_id,omitempty"` // vmess
	Security   string            `json:"security,omitempty"` // vmess 加密 / ss 加密方法
	Flow       string            `json:"flow,omitempty"`     // vless
	Password   string            `json:"password,omitempty"` // trojan / ss / hysteria2 / http / socks
	Username   string            `json:"username,omitempty"` // http / socks
	Plugin     string            `json:"plugin,omitempty"`   // ss 插件（obfs-local / v2ray-plugin）
	PluginOpt  string            `json:"plugin_opts,omitempty"`
	TLS        bool              `json:"tls,omitempty"`
	Insecure   bool              `json:"insecure,omitempty"`
	SNI        string            `json:"sni,omitempty"`
	PinSHA256  string            `json:"pin_sha256,omitempty"` // 证书 SPKI SHA256 指纹（hex），hysteria2 pinSHA256
	FP         string            `json:"fp,omitempty"` // 指纹
	ALPN       []string          `json:"alpn,omitempty"`
	Network    string            `json:"network,omitempty"` // tcp / ws / grpc / h2
	Host       string            `json:"host,omitempty"`    // ws / h2 的 Host
	Path       string            `json:"path,omitempty"`
	Service    string            `json:"service_name,omitempty"` // grpc
	Header     map[string]string `json:"header,omitempty"`       // ws 自定义头
	RealityPK  string            `json:"reality_pk,omitempty"`   // vless reality
	RealitySID string            `json:"reality_sid,omitempty"`
	Obfs       string            `json:"obfs,omitempty"` // hysteria2 混淆
	ObfsPass   string            `json:"obfs_password,omitempty"`
	UpMbps     int               `json:"up_mbps,omitempty"`   // hysteria v1 上行带宽
	DownMbps   int               `json:"down_mbps,omitempty"` // hysteria v1 下行带宽

	// 运行时信息
	LatencyMS int64 `json:"latency_ms,omitempty"`
	LastCheck int64 `json:"last_check,omitempty"`
	CreatedAt int64 `json:"created_at,omitempty"`
	ID        int64 `json:"id,omitempty"`
}

// Key 用于去重：同协议 + 同服务器 + 同端口视为同一线路。
func (n *Node) Key() string {
	return n.Protocol + "|" + n.Server + "|" + strconv.Itoa(n.Port)
}

// ErrUnsupported 表示该链接格式无法解析。
var ErrUnsupported = errors.New("unsupported or malformed link")

// ParseLink 解析一行订阅链接，返回 Node；无法识别返回 ErrUnsupported。
func ParseLink(raw string) (*Node, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, ErrUnsupported
	}
	scheme, rest, ok := splitScheme(raw)
	if !ok {
		return nil, ErrUnsupported
	}
	switch strings.ToLower(scheme) {
	case "vmess":
		return parseVmess(rest, raw)
	case "vless":
		return parseVless(raw)
	case "trojan":
		return parseTrojan(raw)
	case "ss", "shadowsocks":
		return parseSS(rest, raw)
	case "hy2", "hysteria2":
		return parseHysteria2(raw)
	case "anytls":
		return parseAnyTLS(raw)
	case "hysteria":
		return parseHysteria(raw)
	case "http", "https":
		return parseHTTP(raw)
	case "socks", "socks5", "socks4":
		return parseSocks(raw)
	}
	return nil, ErrUnsupported
}

// splitScheme 拆分 scheme:// 前缀。
func splitScheme(raw string) (scheme, rest string, ok bool) {
	i := strings.Index(raw, "://")
	if i <= 0 {
		return "", "", false
	}
	return raw[:i], raw[i+3:], true
}

func cutFragment(s string) (rest, frag string) {
	if i := strings.LastIndex(s, "#"); i >= 0 {
		return s[:i], s[i+1:]
	}
	return s, ""
}

func b64Decode(s string) []byte {
	for _, enc := range []*base64.Encoding{
		base64.StdEncoding, base64.URLEncoding,
		base64.RawStdEncoding, base64.RawURLEncoding,
	} {
		if b, err := enc.DecodeString(strings.TrimSpace(s)); err == nil {
			return b
		}
	}
	return nil
}

// splitHostPort 拆 host:port，host 可能含 IPv6 中括号。
func splitHostPort(s string) (host string, port int, err error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return "", 0, errors.New("empty host")
	}
	var p string
	if strings.HasPrefix(s, "[") { // IPv6
		i := strings.Index(s, "]")
		if i < 0 {
			return "", 0, errors.New("bad ipv6")
		}
		host = s[1:i]
		p = strings.TrimPrefix(s[i+1:], ":")
	} else if n := strings.Count(s, ":"); n == 1 {
		i := strings.LastIndex(s, ":")
		host, p = s[:i], s[i+1:]
	} else {
		host, p = s, ""
	}
	if p == "" {
		port = 443 // 多数代理默认 443
		return
	}
	port, err = strconv.Atoi(p)
	if err != nil || port <= 0 || port > 65535 {
		return "", 0, errors.New("bad port")
	}
	return
}

func portStr(port int) string { return strconv.Itoa(port) }

// ---------------------------------------------------------------------------
// vmess：v2rayN 的 base64(JSON) 格式，以及 vmess://uuid:alterid@host:port?... 旧格式
// ---------------------------------------------------------------------------

func parseVmess(rest, raw string) (*Node, error) {
	// 含 @ 走旧格式
	if strings.Contains(rest, "@") {
		return parseVmessLegacy(rest, raw)
	}
	dec := b64Decode(rest)
	if dec == nil {
		return nil, ErrUnsupported
	}
	var v struct {
		V    string `json:"v"`
		PS   string `json:"ps"`
		Add  string `json:"add"`
		Port string `json:"port"`
		ID   string `json:"id"`
		Aid  string `json:"aid"`
		Net  string `json:"net"`
		Type string `json:"type"`
		Host string `json:"host"`
		Path string `json:"path"`
		TLS  string `json:"tls"`
		SNI  string `json:"sni"`
		FP   string `json:"fp"`
		SCy  string `json:"scy"`
		ALPN string `json:"alpn"`
	}
	if err := json.Unmarshal(dec, &v); err != nil {
		return nil, ErrUnsupported
	}
	port, err := strconv.Atoi(strings.TrimSpace(v.Port))
	if err != nil || v.Add == "" || v.ID == "" {
		return nil, ErrUnsupported
	}
	n := &Node{
		Protocol: "vmess",
		Server:   v.Add,
		Port:     port,
		UUID:     v.ID,
		Security: orDefault(v.SCy, "auto"),
		Network:  orDefault(v.Net, "tcp"),
		Host:     v.Host,
		Path:     v.Path,
		TLS:      truthy(v.TLS),
		SNI:      orDefault(v.SNI, v.Host),
		FP:       v.FP,
	}
	if aid, err := strconv.Atoi(v.Aid); err == nil {
		n.AlterID = aid
	}
	if v.ALPN != "" {
		n.ALPN = strings.Split(v.ALPN, ",")
	}
	if n.Network == "grpc" && v.Path != "" {
		n.Service = v.Path // 部分客户端把 grpc serviceName 放 path
	}
	return n, nil
}

func parseVmessLegacy(rest, raw string) (*Node, error) {
	rest, _ = cutFragment(rest)
	userinfo, hostpart, _ := strings.Cut(rest, "@")
	hp, qs := hostpart, ""
	if idx := strings.Index(hostpart, "?"); idx >= 0 {
		hp, qs = hostpart[:idx], hostpart[idx+1:]
	}
	host, port, err := splitHostPort(hp)
	if err != nil {
		return nil, ErrUnsupported
	}
	uid, aidStr, _ := strings.Cut(userinfo, ":")
	n := &Node{Protocol: "vmess", Server: host, Port: port, UUID: uid, Security: "auto"}
	if a, err := strconv.Atoi(aidStr); err == nil {
		n.AlterID = a
	}
	if qs != "" {
		if vals, qerr := url.ParseQuery(qs); qerr == nil {
			n.Network = vals.Get("type")
			n.Host = vals.Get("host")
			n.Path = vals.Get("path")
			n.SNI = vals.Get("sni")
			n.FP = vals.Get("fp")
			n.TLS = truthy(vals.Get("tls"))
			n.Insecure = truthy(vals.Get("allowInsecure")) || truthy(vals.Get("insecure"))
		}
		if n.Network == "" {
			n.Network = "tcp"
		}
	}
	return n, nil
}

// ---------------------------------------------------------------------------
// vless
// ---------------------------------------------------------------------------

func parseVless(raw string) (*Node, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || u.User == nil {
		return nil, ErrUnsupported
	}
	host, port, err := splitHostPort(u.Host)
	if err != nil {
		return nil, ErrUnsupported
	}
	n := &Node{Protocol: "vless", Server: host, Port: port, UUID: u.User.Username()}
	q := u.Query()
	n.Flow = q.Get("flow")
	n.FP = q.Get("fp")
	n.ALPN = splitComma(q.Get("alpn"))
	n.Network = orDefault(q.Get("type"), "tcp")
	n.Host = q.Get("host")
	n.Path = q.Get("path")
	if q.Get("serviceName") != "" {
		n.Service = q.Get("serviceName")
	} else if n.Network == "grpc" {
		n.Service = q.Get("path")
	}
	n.Insecure = truthy(q.Get("allowInsecure")) || truthy(q.Get("insecure"))
	switch q.Get("security") {
	case "tls", "reality", "tls,reality", "reality,tls":
		n.TLS = true
	}
	n.SNI = orDefault(q.Get("sni"), n.Host)
	n.RealityPK = q.Get("pbk")
	n.RealitySID = q.Get("sid")
	return n, nil
}

// ---------------------------------------------------------------------------
// trojan
// ---------------------------------------------------------------------------

func parseTrojan(raw string) (*Node, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, ErrUnsupported
	}
	host, port, err := splitHostPort(u.Host)
	if err != nil {
		return nil, ErrUnsupported
	}
	n := &Node{Protocol: "trojan", Server: host, Port: port}
	if u.User != nil {
		n.Password = u.User.Username()
	}
	q := u.Query()
	n.TLS = true // trojan 默认 TLS
	n.SNI = q.Get("sni")
	if n.SNI == "" {
		n.SNI = q.Get("peer")
	}
	if n.SNI == "" {
		n.SNI = host
	}
	n.FP = q.Get("fp")
	n.ALPN = splitComma(q.Get("alpn"))
	n.Network = orDefault(q.Get("type"), "tcp")
	n.Host = q.Get("host")
	n.Path = q.Get("path")
	n.Insecure = truthy(q.Get("allowInsecure")) || truthy(q.Get("insecure"))
	if q.Get("serviceName") != "" {
		n.Service = q.Get("serviceName")
	}
	return n, nil
}

// ---------------------------------------------------------------------------
// shadowsocks（SIP002 与旧格式）
// ---------------------------------------------------------------------------

func parseSS(rest, raw string) (*Node, error) {
	rest, _ = cutFragment(rest)
	var query string
	if i := strings.Index(rest, "?"); i >= 0 {
		query, rest = rest[i+1:], rest[:i]
	}
	n := &Node{Protocol: "shadowsocks"}

	var methodPass, hostport string
	if at := strings.LastIndex(rest, "@"); at >= 0 {
		userinfo, hp := rest[:at], rest[at+1:]
		hostport = hp
		dec := b64Decode(userinfo)
		if dec != nil && strings.Contains(string(dec), ":") {
			methodPass = string(dec)
		} else if strings.Contains(userinfo, ":") {
			methodPass = userinfo
		} else {
			return nil, ErrUnsupported
		}
	} else {
		// 旧格式：整段 base64(method:password@host:port)
		dec := b64Decode(rest)
		if dec == nil || !strings.Contains(string(dec), "@") {
			return nil, ErrUnsupported
		}
		mp, hp, _ := strings.Cut(string(dec), "@")
		methodPass, hostport = mp, hp
	}
	if methodPass == "" || hostport == "" {
		return nil, ErrUnsupported
	}
	method, pass, _ := strings.Cut(methodPass, ":")
	method = strings.TrimSpace(method)
	if pass != "" {
		if unescaped, err := url.PathUnescape(pass); err == nil {
			pass = unescaped
		}
	}
	host, port, err := splitHostPort(hostport)
	if err != nil {
		return nil, ErrUnsupported
	}
	n.Method(method)
	n.Password = pass
	n.Server, n.Port = host, port

	// plugin 参数，如 obfs-local;obfs=http;obfs-host=...
	if q, err := url.ParseQuery(query); err == nil {
		if p := q.Get("plugin"); p != "" {
			parts := strings.Split(p, ";")
			n.Plugin = parts[0]
			n.PluginOpt = strings.Join(parts[1:], ";")
		}
	}
	return n, nil
}

// Method 设置加密方法。
func (n *Node) Method(m string) { n.Security = m }

// ---------------------------------------------------------------------------
// hysteria2
// ---------------------------------------------------------------------------

func parseHysteria2(raw string) (*Node, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, ErrUnsupported
	}
	host, port, err := splitHostPort(u.Host)
	if err != nil {
		return nil, ErrUnsupported
	}
	n := &Node{Protocol: "hysteria2", Server: host, Port: port}
	if u.User != nil {
		n.Password = u.User.Username()
	}
	q := u.Query()
	n.SNI = orDefault(q.Get("sni"), host)
	n.Insecure = truthy(q.Get("insecure")) || truthy(q.Get("allowInsecure"))
	n.PinSHA256 = q.Get("pinSHA256")
	n.ALPN = splitComma(q.Get("alpn"))
	n.Obfs = q.Get("obfs")
	n.ObfsPass = q.Get("obfs-password")
	n.TLS = true
	return n, nil
}

// parseAnyTLS 解析 anytls 链接：anytls://password@host:port?sni=...&alpn=...&fp=...&insecure=...
// anytls 是 TCP+TLS 协议，无传输层与 obfs；与 hysteria2 不同的是认证用 password 而非 auth 串。
func parseAnyTLS(raw string) (*Node, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, ErrUnsupported
	}
	host, port, err := splitHostPort(u.Host)
	if err != nil {
		return nil, ErrUnsupported
	}
	n := &Node{Protocol: "anytls", Server: host, Port: port}
	if u.User != nil {
		n.Password = u.User.Username()
	}
	q := u.Query()
	n.SNI = orDefault(q.Get("sni"), host)
	n.Insecure = truthy(q.Get("insecure")) || truthy(q.Get("allowInsecure"))
	n.ALPN = splitComma(q.Get("alpn"))
	n.FP = q.Get("fp")
	n.TLS = true // anytls 必须开启 TLS（sing-box outbound 强制校验）
	return n, nil
}

// parseHysteria 解析 hysteria v1 链接：hysteria://host:port/?auth=xxx&peer=xxx
// v1 与 v2 协议不同：v1 用 auth 串、obfs=xplus（密码放 obfsParam）、需 up/down 带宽。
func parseHysteria(raw string) (*Node, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, ErrUnsupported
	}
	host, port, err := splitHostPort(u.Host)
	if err != nil {
		return nil, ErrUnsupported
	}
	n := &Node{Protocol: "hysteria", Server: host, Port: port}
	q := u.Query()
	// auth: 标准放 query param，少数客户端放 userinfo
	if a := q.Get("auth"); a != "" {
		n.Password = a
	} else if u.User != nil {
		n.Password = u.User.Username()
	}
	n.SNI = orDefault(q.Get("sni"), q.Get("peer"))
	if n.SNI == "" {
		n.SNI = host
	}
	n.Insecure = truthy(q.Get("insecure")) || truthy(q.Get("allowInsecure"))
	n.ALPN = splitComma(q.Get("alpn"))
	// obfsParam 是 xplus 密码；部分链接把密码直接放 obfs（而非 "xplus" 类型）
	if op := q.Get("obfsParam"); op != "" {
		n.Obfs = op
	} else if o := q.Get("obfs"); o != "" && o != "xplus" {
		n.Obfs = o
	}
	if up, err := strconv.Atoi(q.Get("upmbps")); err == nil && up > 0 {
		n.UpMbps = up
	}
	if down, err := strconv.Atoi(q.Get("downmbps")); err == nil && down > 0 {
		n.DownMbps = down
	}
	n.TLS = true
	return n, nil
}

// ---------------------------------------------------------------------------
// http / socks5
// ---------------------------------------------------------------------------

func parseHTTP(raw string) (*Node, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, ErrUnsupported
	}
	host, port, err := splitHostPort(u.Host)
	if err != nil {
		return nil, ErrUnsupported
	}
	n := &Node{Protocol: "http", Server: host, Port: port}
	if u.User != nil {
		n.Username = u.User.Username()
		if p, ok := u.User.Password(); ok {
			n.Password = p
		}
	}
	n.TLS = u.Scheme == "https"
	return n, nil
}

func parseSocks(raw string) (*Node, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return nil, ErrUnsupported
	}
	host, port, err := splitHostPort(u.Host)
	if err != nil {
		return nil, ErrUnsupported
	}
	n := &Node{Protocol: "socks", Server: host, Port: port}
	if u.User != nil {
		n.Username = u.User.Username()
		if p, ok := u.User.Password(); ok {
			n.Password = p
		}
	}
	return n, nil
}

// ---------------------------------------------------------------------------
// 工具
// ---------------------------------------------------------------------------

func orDefault(s, def string) string {
	if s == "" {
		return def
	}
	return s
}

func truthy(s string) bool {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "1", "true", "tls", "yes", "on":
		return true
	}
	return false
}

func splitComma(s string) []string {
	var out []string
	for _, p := range strings.Split(s, ",") {
		if p = strings.TrimSpace(p); p != "" {
			out = append(out, p)
		}
	}
	return out
}

// ResolveServerIP 解析服务器域名，得到 IP（供国家识别与命名）。
func (n *Node) ResolveServerIP() string {
	if n.IP != "" {
		return n.IP
	}
	if ip := net.ParseIP(n.Server); ip != nil {
		n.IP = ip.String()
		return n.IP
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if ips, err := net.DefaultResolver.LookupIP(ctx, "ip", n.Server); err == nil {
		for _, ip := range ips {
			if ip.To4() != nil || ip.To16() != nil {
				n.IP = ip.String()
				break
			}
		}
	}
	return n.IP
}

// SetName 依据 国家代码_IP 生成规范名，如 US_1.2.3.4。
func (n *Node) SetName() {
	cc := n.Country
	if cc == "" {
		cc = "ZZ"
	}
	host := n.IP
	if host == "" {
		host = n.Server
	}
	host = strings.ReplaceAll(host, ":", ".")
	n.Name = strings.ToUpper(cc) + "_" + host
}

// Verify 检查必填字段是否齐全。
func (n *Node) Verify() error {
	switch n.Protocol {
	case "vmess", "vless":
		if n.UUID == "" {
			return fmt.Errorf("%s: missing uuid", n.Protocol)
		}
	case "trojan", "hysteria", "hysteria2", "anytls":
		if n.Password == "" {
			return fmt.Errorf("%s: missing password", n.Protocol)
		}
	case "shadowsocks":
		if n.Security == "" {
			return fmt.Errorf("ss: missing method")
		}
	}
	if n.Server == "" || n.Port == 0 {
		return errors.New("missing server/port")
	}
	return nil
}
