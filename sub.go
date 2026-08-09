package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"sort"
	"strconv"
	"strings"
)

// ---------------------------------------------------------------------------
// 单节点规范 URI（v2ray 订阅格式）
// ---------------------------------------------------------------------------

// ToURI 依据 Node 字段重新生成标准分享链接，名称片段统一为规范名。
func (n *Node) ToURI() string {
	switch n.Protocol {
	case "vmess":
		return n.toVmessURI()
	case "vless":
		return n.toVlessURI()
	case "trojan":
		return n.toTrojanURI()
	case "shadowsocks":
		return n.toSSURI()
	case "hysteria2":
		return n.toHysteria2URI()
	case "http":
		return n.toAuthURI("http")
	case "socks":
		return n.toAuthURI("socks5")
	}
	return ""
}

func (n *Node) toVmessURI() string {
	v := map[string]string{
		"v":    "2",
		"ps":   n.Name,
		"add":  n.Server,
		"port": strconv.Itoa(n.Port),
		"id":   n.UUID,
		"aid":  strconv.Itoa(n.AlterID),
		"net":  orDefault(n.Network, "tcp"),
		"type": "none",
	}
	if n.TLS {
		v["tls"] = "tls"
	}
	if n.SNI != "" {
		v["sni"] = n.SNI
	}
	if n.Host != "" {
		v["host"] = n.Host
	}
	if n.Path != "" {
		v["path"] = n.Path
	}
	if n.Security != "" && n.Security != "auto" {
		v["scy"] = n.Security
	}
	if n.FP != "" {
		v["fp"] = n.FP
	}
	b, _ := json.Marshal(v)
	return "vmess://" + base64.StdEncoding.EncodeToString(b)
}

func (n *Node) toVlessURI() string {
	q := url.Values{}
	q.Set("encryption", "none")
	q.Set("type", orDefault(n.Network, "tcp"))
	if n.Security == "reality" || n.RealityPK != "" {
		q.Set("security", "reality")
	} else if n.TLS {
		q.Set("security", "tls")
	} else {
		q.Set("security", "none")
	}
	if n.Flow != "" {
		q.Set("flow", n.Flow)
	}
	if n.SNI != "" {
		q.Set("sni", n.SNI)
	}
	if n.FP != "" {
		q.Set("fp", n.FP)
	}
	if n.Host != "" {
		q.Set("host", n.Host)
	}
	if n.Path != "" {
		q.Set("path", n.Path)
	}
	if n.Service != "" {
		q.Set("serviceName", n.Service)
	}
	if n.Insecure {
		q.Set("allowInsecure", "1")
	}
	if len(n.ALPN) > 0 {
		q.Set("alpn", strings.Join(n.ALPN, ","))
	}
	if n.RealityPK != "" {
		q.Set("pbk", n.RealityPK)
	}
	if n.RealitySID != "" {
		q.Set("sid", n.RealitySID)
	}
	return fmt.Sprintf("vless://%s@%s:%d?%s#%s",
		n.UUID, n.Server, n.Port, q.Encode(), url.QueryEscape(n.Name))
}

func (n *Node) toTrojanURI() string {
	q := url.Values{}
	q.Set("security", "tls")
	if n.SNI != "" {
		q.Set("sni", n.SNI)
	}
	if n.FP != "" {
		q.Set("fp", n.FP)
	}
	if n.Network != "" && n.Network != "tcp" {
		q.Set("type", n.Network)
	}
	if n.Host != "" {
		q.Set("host", n.Host)
	}
	if n.Path != "" {
		q.Set("path", n.Path)
	}
	if n.Insecure {
		q.Set("allowInsecure", "1")
	}
	pass := url.PathEscape(n.Password)
	return fmt.Sprintf("trojan://%s@%s:%d?%s#%s",
		pass, n.Server, n.Port, q.Encode(), url.QueryEscape(n.Name))
}

func (n *Node) toSSURI() string {
	userinfo := base64.StdEncoding.EncodeToString([]byte(n.Security + ":" + n.Password))
	uri := fmt.Sprintf("ss://%s@%s:%d", userinfo, n.Server, n.Port)
	if n.Plugin != "" {
		opts := n.PluginOpt
		if opts != "" {
			opts = ";" + opts
		}
		uri += "?plugin=" + url.QueryEscape(n.Plugin+opts)
	}
	return uri + "#" + url.QueryEscape(n.Name)
}

func (n *Node) toHysteria2URI() string {
	q := url.Values{}
	if n.SNI != "" {
		q.Set("sni", n.SNI)
	}
	if n.Insecure {
		q.Set("insecure", "1")
	}
	if len(n.ALPN) > 0 {
		q.Set("alpn", strings.Join(n.ALPN, ","))
	}
	if n.Obfs != "" {
		q.Set("obfs", n.Obfs)
		q.Set("obfs-password", n.ObfsPass)
	}
	auth := url.PathEscape(n.Password)
	return fmt.Sprintf("hysteria2://%s@%s:%d?%s#%s",
		auth, n.Server, n.Port, q.Encode(), url.QueryEscape(n.Name))
}

func (n *Node) toAuthURI(scheme string) string {
	u := url.URL{Scheme: scheme, Host: fmt.Sprintf("%s:%d", n.Server, n.Port)}
	if n.Username != "" {
		u.User = url.UserPassword(n.Username, n.Password)
	}
	return u.String() + "#" + url.QueryEscape(n.Name)
}

// ---------------------------------------------------------------------------
// v2ray base64 订阅
// ---------------------------------------------------------------------------

// BuildV2raySub 输出标准 base64 订阅（每行一个节点 URI）。
func BuildV2raySub(nodes []*Node) string {
	var sb strings.Builder
	for _, n := range nodes {
		if uri := n.ToURI(); uri != "" {
			sb.WriteString(uri)
			sb.WriteByte('\n')
		}
	}
	return base64.StdEncoding.EncodeToString([]byte(sb.String()))
}

// ---------------------------------------------------------------------------
// Clash YAML 订阅
// ---------------------------------------------------------------------------

// yamlWriter 简单的保序 YAML 输出器。
type yamlWriter struct {
	sb strings.Builder
}

func (w *yamlWriter) line(indent int, s string) {
	if s == "" {
		w.sb.WriteByte('\n')
		return
	}
	w.sb.WriteString(strings.Repeat("  ", indent))
	w.sb.WriteString(s)
	w.sb.WriteByte('\n')
}

func (w *yamlWriter) kv(indent int, k, v string) {
	w.line(indent, k+": "+v)
}

func (w *yamlWriter) kvB(indent int, k string, v bool) {
	w.kv(indent, k, strconv.FormatBool(v))
}

func (w *yamlWriter) kvI(indent int, k string, v int) {
	w.kv(indent, k, strconv.Itoa(v))
}

// yamlQuote 简单加引号（含特殊字符时）。
func yamlQuote(s string) string {
	if s == "" {
		return `""`
	}
	if strings.ContainsAny(s, ":{}[],&*#?|-<>=!%@`\" \t\n") {
		return strconv.Quote(s)
	}
	return s
}

// BuildClashSub 生成 Clash YAML：节点按国家分组，节点名为 国家_IP。
func BuildClashSub(nodes []*Node, testURL string) string {
	// 按国家分组
	byCountry := make(map[string][]*Node)
	var countries []string
	for _, n := range nodes {
		cc := strings.ToUpper(n.Country)
		if cc == "" {
			cc = "ZZ"
		}
		if _, ok := byCountry[cc]; !ok {
			countries = append(countries, cc)
		}
		byCountry[cc] = append(byCountry[cc], n)
	}
	sort.Strings(countries)

	u, _ := url.Parse(testURL)
	testUrl := "http://www.gstatic.com/generate_204"
	if u != nil && u.String() != "" {
		testUrl = u.String()
	}

	w := &yamlWriter{}
	w.line(0, "mixed-port: 7890")
	w.line(0, "allow-lan: false")
	w.line(0, "mode: rule")
	w.line(0, "log-level: info")
	w.line(0, "")
	w.line(0, "proxies:")

	if len(nodes) == 0 {
		w.line(0, "")
		w.line(0, "proxy-groups:")
		w.line(1, "- name: PROXY")
		w.line(1, "  type: select")
		w.line(1, "  proxies:")
		w.line(2, "- DIRECT")
		w.line(0, "")
		w.line(0, "rules:")
		w.line(0, "- MATCH,DIRECT")
		return w.sb.String()
	}

	// 节点：按国家 -> IP 排序，名称带国家前缀
	for _, cc := range countries {
		ns := byCountry[cc]
		sort.Slice(ns, func(i, j int) bool { return ns[i].Name < ns[j].Name })
		for _, n := range ns {
			w.line(1, "- name: "+yamlQuote(n.Name))
			w.kv(2, "type", n.Protocol)
			w.kv(2, "server", yamlQuote(n.Server))
			w.kvI(2, "port", n.Port)
			w.kvB(2, "udp", true)
			writeClashFields(w, n)
		}
	}

	w.line(0, "")
	w.line(0, "proxy-groups:")
	w.line(1, "- name: PROXY")
	w.line(1, "  type: select")
	w.line(1, "  proxies:")
	for _, cc := range countries {
		w.line(2, "- "+cc)
	}
	w.line(1, "  - DIRECT")
	for _, cc := range countries {
		w.line(1, "- name: "+cc)
		w.line(1, "  type: url-test")
		w.line(1, "  url: "+testUrl)
		w.line(1, "  interval: 300")
		w.line(1, "  proxies:")
		for _, n := range byCountry[cc] {
			w.line(2, "- "+n.Name)
		}
	}

	w.line(0, "")
	w.line(0, "rules:")
	w.line(0, "- MATCH,PROXY")
	return w.sb.String()
}

// writeClashFields 输出协议相关的 Clash 字段（缩进 2 = 4 空格，与 type/server 对齐）。
func writeClashFields(w *yamlWriter, n *Node) {
	const ind = 2
	switch n.Protocol {
	case "vmess":
		w.kv(ind, "uuid", n.UUID)
		w.kvI(ind, "alterId", n.AlterID)
		w.kv(ind, "cipher", orDefault(n.Security, "auto"))
	case "vless":
		w.kv(ind, "uuid", n.UUID)
		if n.Flow != "" {
			w.kv(ind, "flow", n.Flow)
		}
	case "trojan":
		w.kv(ind, "password", yamlQuote(n.Password))
	case "shadowsocks":
		w.kv(ind, "cipher", n.Security)
		w.kv(ind, "password", yamlQuote(n.Password))
		if n.Plugin != "" {
			w.kv(ind, "plugin", n.Plugin)
			w.kv(ind, "plugin-opts", yamlQuote(n.PluginOpt))
		}
	case "hysteria2":
		w.kv(ind, "password", yamlQuote(n.Password))
		if n.SNI != "" {
			w.kv(ind, "sni", n.SNI)
		}
	case "http":
		if n.Username != "" {
			w.kv(ind, "username", n.Username)
			w.kv(ind, "password", yamlQuote(n.Password))
		}
	case "socks":
		if n.Username != "" {
			w.kv(ind, "username", n.Username)
			w.kv(ind, "password", yamlQuote(n.Password))
		}
	}

	if n.Protocol == "vmess" || n.Protocol == "vless" || n.Protocol == "trojan" || n.Protocol == "http" {
		if n.TLS {
			w.kvB(ind, "tls", true)
			if n.SNI != "" {
				w.kv(ind, "servername", n.SNI)
			}
			if n.FP != "" && n.FP != "none" {
				w.kv(ind, "client-fingerprint", n.FP)
			}
			w.kvB(ind, "skip-cert-verify", n.Insecure)
			if n.Protocol == "vless" && n.RealityPK != "" {
				w.line(ind, "reality-opts:")
				w.kv(ind+1, "public-key", n.RealityPK)
				w.kv(ind+1, "short-id", n.RealitySID)
			}
		}
	}

	// 传输层
	switch n.Network {
	case "ws":
		w.kv(ind, "network", "ws")
		w.line(ind, "ws-opts:")
		if n.Path != "" {
			w.kv(ind+1, "path", yamlQuote(n.Path))
		}
		if n.Host != "" {
			w.line(ind+1, "headers:")
			w.kv(ind+2, "Host", yamlQuote(n.Host))
		}
	case "grpc":
		w.kv(ind, "network", "grpc")
		w.line(ind, "grpc-opts:")
		w.kv(ind+1, "grpc-service-name", orDefault(n.Service, n.Path))
	case "h2":
		w.kv(ind, "network", "h2")
		w.line(ind, "h2-opts:")
		if n.Path != "" {
			w.kv(ind+1, "path", yamlQuote(n.Path))
		}
		if n.Host != "" {
			w.kv(ind+1, "host", yamlQuote(n.Host))
		}
	}
}
