package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func mustParse(t *testing.T, raw string) *Node {
	t.Helper()
	n, err := ParseLink(raw)
	if err != nil {
		t.Fatalf("ParseLink(%q): %v", raw, err)
	}
	return n
}

func TestParseVmess(t *testing.T) {
	v := map[string]string{
		"v": "2", "ps": "测试", "add": "1.2.3.4", "port": "443",
		"id": "uuid-1234", "aid": "0", "net": "ws", "type": "none",
		"host": "cdn.example.com", "path": "/ws", "tls": "tls", "sni": "cdn.example.com", "fp": "chrome",
	}
	b, _ := json.Marshal(v)
	raw := "vmess://" + base64.StdEncoding.EncodeToString(b)
	n := mustParse(t, raw)
	if n.Protocol != "vmess" || n.Server != "1.2.3.4" || n.Port != 443 || n.UUID != "uuid-1234" {
		t.Fatalf("bad vmess: %+v", n)
	}
	if n.Network != "ws" || n.Host != "cdn.example.com" || n.Path != "/ws" || !n.TLS || n.SNI != "cdn.example.com" {
		t.Fatalf("bad vmess transport: %+v", n)
	}
	if n.Key() != "vmess|1.2.3.4|443" {
		t.Fatalf("bad key: %s", n.Key())
	}
}

func TestParseVmessLegacy(t *testing.T) {
	n := mustParse(t, "vmess://uuid-1:0@1.2.3.4:443?type=ws&host=cdn.com&path=%2Fws&tls=1&sni=cdn.com#name")
	if n.UUID != "uuid-1" || n.Network != "ws" || n.Host != "cdn.com" || n.Path != "/ws" || !n.TLS {
		t.Fatalf("bad legacy vmess: %+v", n)
	}
}

func TestParseVless(t *testing.T) {
	raw := "vless://uuid-abc@1.2.3.4:443?encryption=none&security=reality&sni=example.com&fp=chrome&type=ws&host=example.com&path=%2Fxyz&flow=xtls-rprx-vision&pbk=pubkey&sid=abcd#name"
	n := mustParse(t, raw)
	if n.Protocol != "vless" || n.UUID != "uuid-abc" || n.TLS != true || n.RealityPK != "pubkey" || n.RealitySID != "abcd" {
		t.Fatalf("bad vless: %+v", n)
	}
	if n.Network != "ws" || n.Host != "example.com" || n.Path != "/xyz" || n.Flow != "xtls-rprx-vision" {
		t.Fatalf("bad vless fields: %+v", n)
	}
}

func TestParseTrojan(t *testing.T) {
	n := mustParse(t, "trojan://pass@1.2.3.4:443?sni=cdn.com&type=grpc&serviceName=gserv#name")
	if n.Password != "pass" || n.SNI != "cdn.com" || n.Network != "grpc" || n.Service != "gserv" || !n.TLS {
		t.Fatalf("bad trojan: %+v", n)
	}
}

func TestParseSS(t *testing.T) {
	// SIP002 base64 userinfo
	ui := base64.StdEncoding.EncodeToString([]byte("aes-256-gcm:secret"))
	n := mustParse(t, "ss://"+ui+"@1.2.3.4:8388#name")
	if n.Protocol != "shadowsocks" || n.Security != "aes-256-gcm" || n.Password != "secret" || n.Port != 8388 {
		t.Fatalf("bad ss: %+v", n)
	}
	// 明文 method:password
	n2 := mustParse(t, "ss://chacha20-ietf-poly1305:pass%40word@1.2.3.4:8388#n")
	if n2.Security != "chacha20-ietf-poly1305" || n2.Password != "pass@word" {
		t.Fatalf("bad ss plain: %+v", n2)
	}
	// 旧格式整段 base64
	old := base64.StdEncoding.EncodeToString([]byte("aes-128-gcm:pw@5.6.7.8:9000"))
	n3 := mustParse(t, "ss://"+old+"#n")
	if n3.Security != "aes-128-gcm" || n3.Server != "5.6.7.8" || n3.Port != 9000 {
		t.Fatalf("bad ss old: %+v", n3)
	}
}

func TestParseHysteria2(t *testing.T) {
	n := mustParse(t, "hysteria2://auth-pass@1.2.3.4:443?sni=hy.example.com&insecure=1#name")
	if n.Password != "auth-pass" || n.SNI != "hy.example.com" || !n.Insecure || n.Port != 443 {
		t.Fatalf("bad hy2: %+v", n)
	}
}

// TestParseAnyTLS 是 issue #3 的回归测试：
// anytls:// 节点（Clash/mihomo 订阅常见）必须被解析，而不是落入 invalid。
func TestParseAnyTLS(t *testing.T) {
	raw := "anytls://pass-word@1.2.3.4:443?sni=www.bing.com&alpn=h2%2Chttp%2F1.1&fp=chrome&insecure=1#测试"
	n := mustParse(t, raw)
	if n.Protocol != "anytls" || n.Password != "pass-word" || n.Server != "1.2.3.4" || n.Port != 443 {
		t.Fatalf("bad anytls: %+v", n)
	}
	if n.SNI != "www.bing.com" {
		t.Fatalf("bad anytls sni: %q", n.SNI)
	}
	if !n.TLS {
		t.Fatalf("anytls must require TLS")
	}
	if !n.Insecure {
		t.Fatalf("bad anytls insecure: %+v", n)
	}
	if len(n.ALPN) != 2 || n.ALPN[0] != "h2" || n.ALPN[1] != "http/1.1" {
		t.Fatalf("bad anytls alpn: %+v", n.ALPN)
	}
	if n.FP != "chrome" {
		t.Fatalf("bad anytls fp: %q", n.FP)
	}

	// 订阅 URI 往返
	uri := n.ToURI()
	n2, err := ParseLink(uri)
	if err != nil {
		t.Fatalf("reparse anytls uri: %v (%s)", err, uri)
	}
	if n2.Password != n.Password || n2.SNI != n.SNI || n2.FP != n.FP {
		t.Fatalf("anytls roundtrip field loss: %+v vs %+v (%s)", n2, n, uri)
	}
	if n2.Key() != n.Key() {
		t.Fatalf("roundtrip key mismatch: %q vs %q", n2.Key(), n.Key())
	}
}

func TestParseAnyTLSMissingPassword(t *testing.T) {
	// 无 userinfo 的 anytls 应解析失败（Verify 报 missing password）
	if n, err := ParseLink("anytls://1.2.3.4:443?sni=x#n"); err == nil {
		if verr := n.Verify(); verr == nil {
			t.Fatalf("expected missing password error, got %+v", n)
		}
	}
}

// TestParseHysteria2PinSHA256 是 issue #2 的回归测试：
// 带 pinSHA256 的自签 Hysteria2 节点必须被正确解析，并在订阅 URI 往返保留。
func TestParseHysteria2PinSHA256(t *testing.T) {
	raw := "hysteria2://4e562fc8-abcd-1234-5678-abcdef012345@208.87.242.105:50000/?insecure=false&sni=www.bing.com&pinSHA256=d2fb4f1b833ee7e77e8304dc4652eb13e1b0e064e0874cde3a1a1a1660b74eef&mport=50000-53000#测试"
	n := mustParse(t, raw)
	if n.PinSHA256 != "d2fb4f1b833ee7e77e8304dc4652eb13e1b0e064e0874cde3a1a1a1660b74eef" {
		t.Fatalf("pinSHA256 not parsed: %+v", n)
	}
	if n.Insecure {
		t.Fatalf("insecure should be false when pinSHA256 present: %+v", n)
	}

	// 订阅 URI 往返：pinSHA256 参数必须保留
	uri := n.ToURI()
	n2, err := ParseLink(uri)
	if err != nil {
		t.Fatalf("reparse hy2 uri: %v (%s)", err, uri)
	}
	if n2.PinSHA256 != n.PinSHA256 {
		t.Fatalf("pinSHA256 lost in roundtrip: %q vs %q (%s)", n2.PinSHA256, n.PinSHA256, uri)
	}
}

// TestDecodePinSHA256 校验指纹格式校验：合法 hex 才通过。
func TestDecodePinSHA256(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"d2fb4f1b833ee7e77e8304dc4652eb13e1b0e064e0874cde3a1a1a1660b74eef", true},
		{"", false},
		{"abc", false},                       // 太短
		{"zz" + "00", false},                 // 4 字符非 hex
		{"d2fb4f1b833ee7e77e8304dc4652eb13e1b0e064e0874cde3a1a1a1660b74e", false}, // 63 字符
	}
	for _, c := range cases {
		_, ok := decodePinSHA256(c.in)
		if ok != c.want {
			t.Errorf("decodePinSHA256(%q) ok=%v want %v", c.in, ok, c.want)
		}
	}
}

func TestParseAuth(t *testing.T) {
	n := mustParse(t, "http://user:pw@1.2.3.4:8080#name")
	if n.Protocol != "http" || n.Username != "user" || n.Password != "pw" {
		t.Fatalf("bad http: %+v", n)
	}
	n2 := mustParse(t, "socks5://u:p@1.2.3.4:1080#name")
	if n2.Protocol != "socks" || n2.Username != "u" || n2.Password != "p" {
		t.Fatalf("bad socks: %+v", n2)
	}
}

func TestParseInvalid(t *testing.T) {
	for _, raw := range []string{"", "hello", "ftp://x:1", "vmess://!!!"} {
		if n, err := ParseLink(raw); err == nil {
			t.Fatalf("expected error for %q, got %+v", raw, n)
		}
	}
}

func TestToURIRoundtrip(t *testing.T) {
	raws := []string{
		"vmess://eyJ2IjoiMiIsInBzIjoibmFtZSIsImFkZCI6IjEuMi4zLjQiLCJwb3J0IjoiNDQzIiwiaWQiOiJ1dWlkLWFiYyIsImFpZCI6IjAiLCJuZXQiOiJ0Y3AiLCJ0eXBlIjoibm9uZSIsImhvc3QiOiIiLCJwYXRoIjoiIiwidGxzIjoiIn0K",
		"vless://uuid-abc@1.2.3.4:443?encryption=none&security=tls&sni=cdn.com&type=ws&host=cdn.com&path=%2Fws#name",
		"trojan://pass@1.2.3.4:443?sni=cdn.com#name",
		"ss://YWVzLTI1Ni1nY206c2VjcmV0@1.2.3.4:8388#name",
		"hysteria2://auth@1.2.3.4:443?insecure=1#name",
		"anytls://pass@1.2.3.4:443?sni=cdn.com&alpn=h2&fp=chrome&insecure=1#name",
		"http://u:p@1.2.3.4:8080#name",
		"socks5://u:p@1.2.3.4:1080#name",
	}
	for _, raw := range raws {
		n := mustParse(t, raw)
		uri := n.ToURI()
		if uri == "" {
			t.Fatalf("empty ToURI for %s", raw)
		}
		n2, err := ParseLink(uri)
		if err != nil {
			t.Fatalf("reparse %s -> %s: %v", raw, uri, err)
		}
		if n2.Key() != n.Key() {
			t.Fatalf("roundtrip key mismatch: %q vs %q (%s)", n2.Key(), n.Key(), raw)
		}
	}
}

func TestBuildClashAndV2ray(t *testing.T) {
	n := mustParse(t, "vless://uuid-abc@1.2.3.4:443?encryption=none&security=tls&sni=cdn.com&type=ws&host=cdn.com&path=%2Fws#name")
	n.Country = "US"
	n.IP = "1.2.3.4"
	n.SetName()
	if n.Name != "US_1.2.3.4" {
		t.Fatalf("bad name: %s", n.Name)
	}
	clashOut := BuildClashSub([]*Node{n}, "http://www.gstatic.com/generate_204")
	if !strings.Contains(clashOut, "US_1.2.3.4") || !strings.Contains(clashOut, "name: US") {
		t.Fatalf("clash missing group: %s", clashOut)
	}
	// 输出必须是合法 YAML
	var parsed map[string]any
	if err := yaml.Unmarshal([]byte(clashOut), &parsed); err != nil {
		t.Fatalf("invalid clash yaml: %v\n%s", err, clashOut)
	}
	sub := BuildV2raySub([]*Node{n})
	dec, err := base64.StdEncoding.DecodeString(sub)
	if err != nil || !strings.Contains(string(dec), "US_1.2.3.4") {
		t.Fatalf("v2ray sub bad: %s / %v", string(dec), err)
	}
}

func TestClashYAMLMultiProtocol(t *testing.T) {
	raws := []string{
		"vmess://eyJ2IjoiMiIsInBzIjoibmFtZSIsImFkZCI6IjEuMi4zLjQiLCJwb3J0IjoiNDQzIiwiaWQiOiJ1dWlkLWFiYyIsImFpZCI6IjAiLCJuZXQiOiJ3cyIsInR5cGUiOiJub25lIiwiaG9zdCI6ImNkbi5jb20iLCJwYXRoIjoiL3dzIiwidGxzIjoidGxzIiwic25pIjoiY2RuLmNvbSJ9",
		"vless://uuid-abc@1.2.3.4:443?encryption=none&security=reality&sni=ex.com&type=tcp&flow=xtls-rprx-vision&pbk=pk&sid=ab#name",
		"trojan://pass@1.2.3.4:443?sni=cdn.com#name",
		"ss://YWVzLTI1Ni1nY206c2VjcmV0@1.2.3.4:8388#name",
		"hysteria2://auth@1.2.3.4:443?insecure=1#name",
		"anytls://pass@1.2.3.4:443?sni=cdn.com&alpn=h2&fp=chrome&insecure=1#name",
		"http://u:p@1.2.3.4:8080#name",
		"socks5://u:p@1.2.3.4:1080#name",
	}
	var nodes []*Node
	for _, raw := range raws {
		n := mustParse(t, raw)
		n.Country = "US"
		n.IP = "1.2.3.4"
		n.SetName()
		nodes = append(nodes, n)
	}
	out := BuildClashSub(nodes, "http://www.gstatic.com/generate_204")
	var parsed map[string]any
	if err := yaml.Unmarshal([]byte(out), &parsed); err != nil {
		t.Fatalf("invalid clash yaml: %v\n%s", err, out)
	}
	proxies := parsed["proxies"].([]any)
	if len(proxies) != len(raws) {
		t.Fatalf("expected %d proxies, got %d", len(raws), len(proxies))
	}
	for i, p := range proxies {
		m := p.(map[string]any)
		if _, ok := m["name"].(string); !ok {
			t.Fatalf("proxy %d missing name: %v", i, m)
		}
	}
}

func TestParseHysteriaV1(t *testing.T) {
	raw := "hysteria://auth-str@1.2.3.4:443?peer=hy.example.com&insecure=1&obfsParam=xplus-pw&upmbps=50&downmbps=100&alpn=h2#name"
	n := mustParse(t, raw)
	if n.Protocol != "hysteria" || n.Password != "auth-str" || n.SNI != "hy.example.com" {
		t.Fatalf("bad hysteria v1: %+v", n)
	}
	if !n.Insecure || n.Obfs != "xplus-pw" || n.UpMbps != 50 || n.DownMbps != 100 {
		t.Fatalf("bad hysteria v1 fields: %+v", n)
	}
	if !n.TLS {
		t.Fatalf("hysteria v1 must have TLS")
	}
}

func TestParseHysteriaV1QueryAuth(t *testing.T) {
	// auth 在 query param 而非 userinfo（hysteria v1 标准格式）
	n := mustParse(t, "hysteria://1.2.3.4:443?auth=query-auth&peer=hy.example.com#n")
	if n.Password != "query-auth" {
		t.Fatalf("bad hysteria v1 query auth: %+v", n)
	}
}

func TestHysteriaV1Roundtrip(t *testing.T) {
	raw := "hysteria://auth@1.2.3.4:443?peer=hy.example.com&insecure=1&upmbps=50&downmbps=100#name"
	n := mustParse(t, raw)
	uri := n.ToURI()
	if uri == "" {
		t.Fatalf("empty ToURI for hysteria v1")
	}
	n2, err := ParseLink(uri)
	if err != nil {
		t.Fatalf("reparse hysteria v1: %v (%s)", err, uri)
	}
	if n2.Key() != n.Key() {
		t.Fatalf("roundtrip key mismatch: %q vs %q", n2.Key(), n.Key())
	}
	if n2.Password != n.Password || n2.UpMbps != n.UpMbps || n2.DownMbps != n.DownMbps {
		t.Fatalf("roundtrip field loss: %+v vs %+v", n2, n)
	}
}

func TestHysteriaV1NotTreatedAsV2(t *testing.T) {
	// 老 hysteria:// 链接不应被当 hysteria2 处理（issue #1 补充点）
	n := mustParse(t, "hysteria://auth@1.2.3.4:443?peer=hy.example.com#n")
	if n.Protocol != "hysteria" {
		t.Fatalf("hysteria:// must parse as v1, got protocol=%s", n.Protocol)
	}
}

func TestClassifyTestError(t *testing.T) {
	cases := []struct {
		err  string
		want string
	}{
		{"dial tcp 1.2.3.4:443: i/o timeout", "unreachable"},
		{"resolve example.com: no such host", "unreachable"},
		{"dial: network is unreachable", "unreachable"},
		{"context deadline exceeded", "unreachable"},
		{"dial [2606:4700::1]:443: no route to host", "unreachable"},
		{"tls handshake: certificate signed by unknown authority", "dead"},
		{"status 502", "dead"},
		{"init singbox: uTLS is not included", "dead"},
	}
	for _, c := range cases {
		if got := classifyTestError(fmt.Errorf("%s", c.err)); got != c.want {
			t.Errorf("classifyTestError(%q) = %q, want %q", c.err, got, c.want)
		}
	}
}
