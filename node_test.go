package main

import (
	"encoding/base64"
	"encoding/json"
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
