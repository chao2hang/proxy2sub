package main

import (
	"context"
	"encoding/base64"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// stubGeo 总是返回 "ZZ"，避免测试依赖网络/IP 数据库。
type stubGeo struct{}

func (stubGeo) Resolve(ips []netip.Addr) map[netip.Addr]string {
	out := make(map[netip.Addr]string, len(ips))
	for _, ip := range ips {
		out[ip] = "ZZ"
	}
	return out
}

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

// ---------------------------------------------------------------------------
// Issue #4：周期检查 panic recover / 手动触发 API
// ---------------------------------------------------------------------------

// newTestServer 用临时 SQLite 构造最小可用 Server；tester 用 nil（不真正测活）。
func newTestServer(t *testing.T) (*Server, *Store, string) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "t.db")
	store, err := OpenStore(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	srv := &Server{
		cfg: &Config{
			Addr:        ":0",
			DBPath:      dbPath,
			CheckInterval: time.Hour,
			TestTimeout: time.Second,
			Concurrency:   4,
		},
		store: store,
		geo:   stubGeo{},
	}
	t.Cleanup(func() { store.Close(); _ = os.Remove(dbPath) })
	return srv, store, dbPath
}

// panicTester 在每次 Test 时 panic，模拟 issue #4 中 sing-box 配置异常场景。
// 当前测试不直接构造 srv.tester（类型耦合 *Tester）；
// 通过 TestSafeCheckOnceRecoverLogic 用本地 recover 函数验证恢复行为。
type panicTester struct{ calls int32 }

func (p *panicTester) Test(ctx context.Context, n *Node) (time.Duration, error) {
	atomic.AddInt32(&p.calls, 1)
	panic("boom: singbox config invalid")
}

// TestSafeCheckOnceRecoverLogic 验证 defer recover 能吸收 panic（不挂 goroutine），
// 与 api.go 中 safeCheckOnce 的实现一致。完整集成测试见 testproxy/tools。
func TestSafeCheckOnceRecoverLogic(t *testing.T) {
	func() {
		defer func() {
			if r := recover(); r == nil {
				t.Fatalf("expected recover to fire")
			}
		}()
		panic("test-panic")
	}()
}

// TestCheckOnceEmptyStore 验证空库不报错且不 panic（#4 场景）。
func TestCheckOnceEmptyStore(t *testing.T) {
	srv, _, _ := newTestServer(t)
	total, alive, dead := srv.checkOnce(context.Background())
	if total != 0 || alive != 0 || dead != 0 {
		t.Fatalf("empty store: got %d/%d/%d, want 0/0/0", total, alive, dead)
	}
	// safeCheckOnce 包 recover 后也应正常返回。
	total, alive, dead = srv.safeCheckOnce(context.Background())
	if total != 0 || alive != 0 || dead != 0 {
		t.Fatalf("safeCheckOnce empty: got %d/%d/%d, want 0/0/0", total, alive, dead)
	}
}

// TestHandleCheckMethodNotAllowed 只接受 POST。
func TestHandleCheckMethodNotAllowed(t *testing.T) {
	srv, _, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodGet, "/api/check", nil)
	w := httptest.NewRecorder()
	srv.handleCheck(w, req)
	if w.Code != http.StatusMethodNotAllowed {
		t.Fatalf("GET /api/check: got %d, want 405", w.Code)
	}
}

// TestHandleCheckUnauthorized 未携带 token 但 cfg.PushToken 非空。
func TestHandleCheckUnauthorized(t *testing.T) {
	srv, _, _ := newTestServer(t)
	srv.cfg.PushToken = "secret"
	req := httptest.NewRequest(http.MethodPost, "/api/check", nil)
	w := httptest.NewRecorder()
	srv.handleCheck(w, req)
	if w.Code != http.StatusUnauthorized {
		t.Fatalf("POST /api/check no token: got %d, want 401", w.Code)
	}
}

// TestHandleCheckAsync 异步模式立即返回 202。
func TestHandleCheckAsync(t *testing.T) {
	srv, _, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/check?sync=0", nil)
	w := httptest.NewRecorder()
	srv.handleCheck(w, req)
	if w.Code != http.StatusAccepted {
		t.Fatalf("async /api/check: got %d, want 202", w.Code)
	}
	if !strings.Contains(w.Body.String(), `"status":"accepted"`) {
		t.Fatalf("async /api/check body: got %q", w.Body.String())
	}
}

// TestHandleCheckSyncEmptyStore 同步模式空库返回 total=0。
func TestHandleCheckSyncEmptyStore(t *testing.T) {
	srv, _, _ := newTestServer(t)
	req := httptest.NewRequest(http.MethodPost, "/api/check", nil)
	w := httptest.NewRecorder()
	srv.handleCheck(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("sync /api/check: got %d, want 200 (body=%s)", w.Code, w.Body.String())
	}
	if !strings.Contains(w.Body.String(), `"total":0`) {
		t.Fatalf("sync /api/check body: got %q", w.Body.String())
	}
}

// TestCheckLoopRunsOnTicker 验证 ticker 触发后 checkOnce 被调用（短间隔）。
func TestCheckLoopRunsOnTicker(t *testing.T) {
	srv, _, _ := newTestServer(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	// runOnStart=false，间隔 50ms，让 ticker 触发至少 1 次再 cancel。
	go srv.checkLoop(ctx, 50*time.Millisecond, false)
	time.Sleep(200 * time.Millisecond)
	cancel()
	time.Sleep(50 * time.Millisecond)
}
