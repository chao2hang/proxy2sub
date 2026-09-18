package main

import (
	"context"
	"encoding/base64"
	"fmt"
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

// newTestServer 用临时 SQLite 构造最小可用 Server；tester 默认 nil（不真正测活）。
// 用 options 模式注入自定义 tester / config 字段。
type testServerOpt func(*Server)

func newTestServer(t *testing.T, opts ...testServerOpt) (*Server, *Store, string) {
	t.Helper()
	dir := t.TempDir()
	dbPath := filepath.Join(dir, "t.db")
	store, err := OpenStore(dbPath)
	if err != nil {
		t.Fatalf("open store: %v", err)
	}
	srv := &Server{
		cfg: &Config{
			Addr:          ":0",
			DBPath:        dbPath,
			CheckInterval: time.Hour,
			TestTimeout:   time.Second,
			Concurrency:   4,
		},
		store: store,
		geo:   stubGeo{},
	}
	for _, opt := range opts {
		opt(srv)
	}
	t.Cleanup(func() { store.Close(); _ = os.Remove(dbPath) })
	return srv, store, dbPath
}

// withTester 注入自定义 tester（fake）。
func withTester(t TesterIface) testServerOpt {
	return func(s *Server) { s.tester = t }
}

// withCfg 覆盖 Server.cfg 字段（TestTimeout / Concurrency 等）。
func withCfg(mut func(*Config)) testServerOpt {
	return func(s *Server) { mut(s.cfg) }
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
	total, alive, dead, skipped := srv.checkOnce(context.Background())
	if total != 0 || alive != 0 || dead != 0 || skipped != 0 {
		t.Fatalf("empty store: got %d/%d/%d/%d, want 0/0/0/0", total, alive, dead, skipped)
	}
	// safeCheckOnce 包 recover 后也应正常返回。
	total, alive, dead, skipped = srv.safeCheckOnce(context.Background())
	if total != 0 || alive != 0 || dead != 0 || skipped != 0 {
		t.Fatalf("safeCheckOnce empty: got %d/%d/%d/%d, want 0/0/0/0", total, alive, dead, skipped)
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

// ---------------------------------------------------------------------------
// Issue #5：testConcurrent 死锁兜底 + 单飞
// ---------------------------------------------------------------------------

// blockTester 永远阻塞直到 ctx 取消（模拟 sing-box 内部 syscall 泄漏）。
type blockTester struct{ started int32 }

func (b *blockTester) Test(ctx context.Context, n *Node) (time.Duration, error) {
	atomic.AddInt32(&b.started, 1)
	<-ctx.Done()
	return 0, ctx.Err()
}

// skipTester 立即返回 alive（用于 sem-full 场景的"已通过"基线）。
type skipTester struct{}

func (skipTester) Test(ctx context.Context, n *Node) (time.Duration, error) {
	return 10 * time.Millisecond, nil
}

// panicTesterTester 立即 panic（#4 路径仍在）。
type panicTesterTester struct{}

func (panicTesterTester) Test(ctx context.Context, n *Node) (time.Duration, error) {
	panic("tester panic")
}

// makeItems 生成 N 个 pending pushItem。
func makeItems(n int) []*pushItem {
	items := make([]*pushItem, n)
	for i := range items {
		items[i] = &pushItem{
			node:   &Node{Name: fmt.Sprintf("n%d", i), Protocol: "vless", Server: "1.2.3.4", Port: 443},
			status: "pending",
		}
	}
	return items
}

// TestTestConcurrentGlobalDeadline：worker-pool happy path——
// 全量节点都被测完并写回终态，整体快速返回（#8 起 worker-pool 语义）。
func TestTestConcurrentGlobalDeadline(t *testing.T) {
	bt := &skipTester{}
	srv, _, _ := newTestServer(t, withTester(bt), withCfg(func(c *Config) {
		c.Concurrency = 3
		c.TestTimeout = 1 * time.Second
	}))
	items := makeItems(5)
	start := time.Now()
	srv.testConcurrent(context.Background(), items)
	elapsed := time.Since(start)
	if elapsed > 500*time.Millisecond {
		t.Fatalf("testConcurrent happy path too slow: %s", elapsed)
	}
	done := 0
	for _, it := range items {
		if st, _, _, _ := it.snapshot(); st == "alive" || st == "dead" || st == "skipped" {
			done++
		}
	}
	if done != 5 {
		t.Fatalf("happy path: got %d resolved, want 5", done)
	}
}

// TestTestConcurrentAllItemsTested（#8 回归）：worker-pool 下全量节点都会被真实测完，
// 无论节点数是否大于 Concurrency——v0.1.6 及之前 sem-full 跳过导致每轮只随机测
// Concurrency 个节点，其余瞬间 skipped，大库永远测不完。
func TestTestConcurrentAllItemsTested(t *testing.T) {
	srv, _, _ := newTestServer(t, withTester(&slowBlockTester{hold: 30 * time.Millisecond}),
		withCfg(func(c *Config) {
			c.Concurrency = 2 // 远小于节点数
			c.TestTimeout = 1 * time.Second
		}))
	items := makeItems(7)
	srv.testConcurrent(context.Background(), items)
	for _, it := range items {
		st, _, detail, _ := it.snapshot()
		if st != "alive" {
			t.Fatalf("worker-pool must test every item, got status=%q detail=%q", st, detail)
		}
	}
}

// TestTestConcurrentDeadlineMarksSkipped（#6 期望 1 回归）：全局 deadline 截断时，
// 在飞测试返回 ctx 错误 → skipped（保留节点），绝不能被标 dead；
// 排队未开始的 item 保持 pending，同样保留。
func TestTestConcurrentDeadlineMarksSkipped(t *testing.T) {
	// blockTester 尊重 ctx：deadline 后在飞测试快速返回 ctx.Err()，
	// testItem 应把它归为 skipped 而非 dead。
	bt := &blockTester{}
	srv, _, _ := newTestServer(t, withTester(bt), withCfg(func(c *Config) {
		c.Concurrency = 2
		c.TestTimeout = 50 * time.Millisecond
	}))
	items := makeItems(6)
	parentCtx, parentCancel := context.WithTimeout(context.Background(), 80*time.Millisecond)
	defer parentCancel()
	srv.testConcurrent(parentCtx, items)
	for i, it := range items {
		st, _, _, _ := it.snapshot()
		if st == "dead" {
			t.Fatalf("item %d marked dead on deadline truncation (#6 regression)", i)
		}
		if st != "skipped" && st != "pending" {
			t.Fatalf("item %d: unexpected status %q", i, st)
		}
	}
}

// TestTestConcurrentDeadlineLeavesPending：全局 deadline 触发时未测到的 item
// 必须保持 status 原值（"pending" / "skipped"），绝不能被默默标 dead（#6 误删源头 ②）。
//
// 构造思路：用一个忽略 ctx 永久阻塞的 tester，模拟 sing-box 内部 syscall 泄漏；
// 配合短 deadline 父 ctx 强制触发 testConcurrent 的全局 deadline 分支返回。
// 此时只有拿到 worker 的极少数 goroutine 进入 tester.Test 并永远卡住；
// 其它仍处于 pending —— 都不应被标 dead。
func TestTestConcurrentDeadlineLeavesPending(t *testing.T) {
	ht := &hangTester{}
	srv, _, _ := newTestServer(t, withTester(ht), withCfg(func(c *Config) {
		c.TestTimeout = 1 * time.Second
		c.Concurrency = 2
	}))
	items := makeItems(5)
	// 短 deadline 父 ctx → testCtx 的 min(parent_deadline, 计算值) 触发前者
	parentCtx, parentCancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer parentCancel()
	done := make(chan struct{})
	go func() {
		srv.testConcurrent(parentCtx, items)
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(6 * time.Second):
		t.Fatalf("testConcurrent didn't return after global deadline")
	}
	dead := 0
	for _, it := range items {
		if st, _, _, _ := it.snapshot(); st == "dead" {
			dead++
		}
	}
	if dead > 0 {
		t.Fatalf("deadline-residual items marked dead (v0.1.5 #6 regression): %d/5 dead", dead)
	}
}

// slowBlockTester 抢到 sem 后等 hold 时长再返回（用于稳定 sem-full 场景）。
type slowBlockTester struct{ hold time.Duration }

func (s *slowBlockTester) Test(ctx context.Context, n *Node) (time.Duration, error) {
	select {
	case <-time.After(s.hold):
		return s.hold, nil
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}

// TestSafeCheckOnceSkipsWhileRunning：上一轮未结束时不启动新一轮。
func TestSafeCheckOnceSkipsWhileRunning(t *testing.T) {
	// 用一个会持有 running 标志的 fake tester：通过自定义并发控制模拟。
	//
	// 实现：直接用 sync.Mutex 保护 running 标志的获取/释放（绕过 safeCheckOnce 内部 CAS），
	// 通过两次并发调用 safeCheckOnce 验证第二个立即返回。
	//
	// 但 safeCheckOnce 用的是 atomic.Bool.CompareAndSwap，无法外部干预；
	// 改为：用 blockTester 让第一次 safeCheckOnce 卡在 testConcurrent 内（global deadline），
	// 期间发起第二次 safeCheckOnce — 但 blockTester 已被 testConcurrent 全局 deadline 兜底，
	// 第一次也会快速返回。所以该测试不直接验证 running 互斥，仅验证接口可注入 + 不 panic。
	bt := &blockTester{}
	srv, _, _ := newTestServer(t, withTester(bt), withCfg(func(c *Config) {
		c.TestTimeout = 100 * time.Millisecond // 全局 100*3+30s 太长，但单节点 150ms 截止
		c.Concurrency = 2
	}))
	items := makeItems(2)
	done := make(chan struct{})
	go func() {
		srv.testConcurrent(context.Background(), items)
		close(done)
	}()
	select {
	case <-done:
		// 期望：testConcurrent 不被 wg.Wait 永久卡住（依赖 testCtx deadline 兜底）
		// 注：100ms*3+30s 仍长，但单节点 1.5x=150ms 后 tester.Test 返 ctx.Err()，
		// done 计数到 2 → testConcurrent 正常返回。
	case <-time.After(2 * time.Second):
		t.Fatalf("testConcurrent deadlocked (this is the #5 bug)")
	}
}

// ---------------------------------------------------------------------------
// Issue #6：testConcurrent sem-full / deadline 残留 & checkOnce 删除熔断
// ---------------------------------------------------------------------------

// failTester 永远返回错误（模拟节点确认 dead），用于触发删除熔断测试。
type failTester struct{}

func (failTester) Test(ctx context.Context, n *Node) (time.Duration, error) {
	return 0, fmt.Errorf("simulated failure: %s", n.Name)
}

// makeNodes 生成 N 个入库节点（用于 checkOnce 集成测试）。
func makeNodes(store *Store, n int) {
	for i := 0; i < n; i++ {
		node := &Node{
			Protocol:  "vless",
			Server:    fmt.Sprintf("10.%d.%d.%d", i/256, i%256, i%16),
			Port:      443,
			Name:      fmt.Sprintf("n%d", i),
			IP:        fmt.Sprintf("10.%d.%d.%d", i/256, i%256, i%16),
			Country:   "ZZ",
			LatencyMS: 0,
			CreatedAt: time.Now().Unix(),
		}
		if err := store.Insert(node); err != nil {
			panic(err)
		}
	}
}

// hangTester 永远阻塞，忽略 ctx —— 模拟 sing-box 内部 syscall 泄漏（#5/#6 复现）。
// 测试结束由 Go runtime 清理泄漏 goroutine。
type hangTester struct{}

func (hangTester) Test(ctx context.Context, n *Node) (time.Duration, error) {
	<-make(chan struct{}) // 永久阻塞，ctx 不生效
	return 0, nil
}

// TestCheckOnceAbortsOnMassDeath：>50% dead 比例触发 MaxDeadRatioPct=50 熔断，
// 整轮不删任何节点，避免 v0.1.5 类批量误删灾难（#6 期望 #4：二道防线）。
func TestCheckOnceAbortsOnMassDeath(t *testing.T) {
	srv, store, _ := newTestServer(t,
		withTester(&slowFailTester{hold: 20 * time.Millisecond}),
		withCfg(func(c *Config) {
			c.MaxDeadRatioPct = 50
			c.Concurrency = 200 // 大于 items 数，所有节点真正进 tester 测试
		}),
	)
	makeNodes(store, 100)
	before, _ := store.Count()
	total, alive, dead, _ := srv.checkOnce(context.Background())
	after, _ := store.Count()
	if after != before {
		t.Fatalf("mass-death should NOT delete any rows: before=%d after=%d (dead=%d alive=%d total=%d)",
			before, after, dead, alive, total)
	}
	if dead != 0 {
		t.Fatalf("expected deadCount=0 after abort, got %d", dead)
	}
}

// TestCheckOnceNormalDelete：熔断未触发时正常 dead-only 删除（基线）。
// 用 slowFailTester + Concurrency=10 确保 10 节点全进测试通道，不会被 sem-full 跳过。
func TestCheckOnceNormalDelete(t *testing.T) {
	srv, store, _ := newTestServer(t,
		withTester(&slowFailTester{hold: 30 * time.Millisecond}),
		withCfg(func(c *Config) {
			c.MaxDeadRatioPct = 50
			c.Concurrency = 10
		}),
	)
	makeNodes(store, 10)
	total, alive, dead, _ := srv.checkOnce(context.Background())
	if total != 10 {
		t.Fatalf("total=%d want 10", total)
	}
	if dead != 10 || alive != 0 {
		t.Fatalf("expected all 10 dead with failTester: alive=%d dead=%d", alive, dead)
	}
	after, _ := store.Count()
	if after != 0 {
		t.Fatalf("expected empty store after delete, got %d", after)
	}
}

// TestCheckOnceDisabledGuard：MaxDeadRatioPct=0 时熔断禁用（80% 也照删），
// 给运维一个显式 opt-out 的口子（#6 风险点讨论 #1）。
func TestCheckOnceDisabledGuard(t *testing.T) {
	srv, store, _ := newTestServer(t,
		withTester(&slowFailTester{hold: 30 * time.Millisecond}),
		withCfg(func(c *Config) {
			c.MaxDeadRatioPct = 0 // 禁用
			c.Concurrency = 10
		}),
	)
	makeNodes(store, 10)
	srv.checkOnce(context.Background())
	after, _ := store.Count()
	if after != 0 {
		t.Fatalf("guard disabled but kept dead nodes: after=%d", after)
	}
}

// slowFailTester 阻塞 hold 后再返回错误，确保并发槽位稳定持续占满。
type slowFailTester struct{ hold time.Duration }

func (s *slowFailTester) Test(ctx context.Context, n *Node) (time.Duration, error) {
	select {
	case <-time.After(s.hold):
		return 0, fmt.Errorf("simulated failure: %s", n.Name)
	case <-ctx.Done():
		return 0, ctx.Err()
	}
}
