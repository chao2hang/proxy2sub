package main

import (
	"encoding/base64"
	"testing"
)

func TestParseInputWholeBodyBase64(t *testing.T) {
	plain := "vmess://eyJ2IjoiMiIsImFkZCI6IjEuMi4zLjQiLCJwb3J0IjoiNDQzIiwiaWQiOiJ1dWlkLTEiLCJhaWQiOiIwIiwibmV0IjoidGNwIiwidHlwZSI6Im5vbmUiLCJob3N0IjoiIiwicGF0aCI6IiIsInRscyI6IiJ9\n" +
		"vless://uuid-2@1.2.3.5:443?encryption=none&security=tls&sni=cdn.com#n\n"
	body := base64.StdEncoding.EncodeToString([]byte(plain))

	links, urls := parseInput([]byte(body))
	if len(urls) != 0 || len(links) != 2 {
		t.Fatalf("whole-body base64: got links=%d urls=%d, want 2/0", len(links), len(urls))
	}
	if links[0][:8] != "vmess://" || links[1][:8] != "vless://" {
		t.Fatalf("whole-body base64 decode wrong: %v", links)
	}
}

func TestParseInputPerLineBase64(t *testing.T) {
	b1 := base64.StdEncoding.EncodeToString([]byte("http://1.2.3.4:8080#a"))
	b2 := base64.StdEncoding.EncodeToString([]byte("socks5://user:pass@5.6.7.8:1080#b"))
	body := b1 + "\n" + b2 + "\n"

	links, urls := parseInput([]byte(body))
	if len(urls) != 0 || len(links) != 2 {
		t.Fatalf("per-line base64: got %d links", len(links))
	}
	for _, l := range links {
		if _, err := ParseLink(l); err != nil {
			t.Fatalf("per-line base64 link unparseable: %q (%v)", l, err)
		}
	}
}

func TestParseInputJSONLinksBase64(t *testing.T) {
	enc := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	body := `{"links":["` + enc("http://1.2.3.4:8080#a") + `","` + enc("vless://uuid-3@1.2.3.6:443#b") + `"]}`
	links, urls := parseInput([]byte(body))
	if len(urls) != 0 || len(links) != 2 {
		t.Fatalf("json links base64: got %d links", len(links))
	}
	if n, err := ParseLink(links[0]); err != nil || n.Protocol != "http" {
		t.Fatalf("json base64 link[0] bad: %v %v", n, err)
	}
	if n, err := ParseLink(links[1]); err != nil || n.Protocol != "vless" {
		t.Fatalf("json base64 link[1] bad: %v %v", n, err)
	}
}

func TestParseInputMixed(t *testing.T) {
	plain := "vmess://eyJ2IjoiMiIsImFkZCI6IjEuMi4zLjQiLCJwb3J0IjoiNDQzIiwiaWQiOiJ1dWlkLTEiLCJhaWQiOiIwIiwibmV0IjoidGNwIiwidHlwZSI6Im5vbmUiLCJob3N0IjoiIiwicGF0aCI6IiIsInRscyI6IiJ9"
	b64 := base64.StdEncoding.EncodeToString([]byte("http://9.9.9.9:8080#c"))
	body := plain + "\n" + b64 + "\n" + "ss://YWVzLTI1Ni1nY206c2VjcmV0@1.2.3.4:8388#d"

	links, _ := parseInput([]byte(body))
	if len(links) != 3 {
		t.Fatalf("mixed: got %d links, want 3: %v", len(links), links)
	}
	for _, l := range links {
		if _, err := ParseLink(l); err != nil {
			t.Fatalf("mixed link unparseable: %q (%v)", l, err)
		}
	}
}

func TestParseInputPlainNoBase64Confusion(t *testing.T) {
	// 普通线路（本身含 ://）不应被误判为 base64
	body := "http://1.2.3.4:8080#a\nvless://uuid-x@5.6.7.8:443?security=tls&sni=cdn.com#b"
	links, _ := parseInput([]byte(body))
	if len(links) != 2 {
		t.Fatalf("plain lines: got %d links, want 2", len(links))
	}
}
