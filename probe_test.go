package main

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// Issue #10：子进程隔离测活（SubprocessTester / probe 子命令）
// ---------------------------------------------------------------------------

// writeFakeExe 在 tempdir 写入可执行的 sh 脚本并返回路径。
func writeFakeExe(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "fake-exe.sh")
	if err := os.WriteFile(p, []byte("#!/bin/sh\n"+body), 0o755); err != nil {
		t.Fatalf("write fake exe: %v", err)
	}
	return p
}

// TestSubprocessTesterCleanSuccess：子进程干净返回成功 → 延迟透传。
// 顺带验证 stderr 杂讯不影响 stdout 协议解析。
func TestSubprocessTesterCleanSuccess(t *testing.T) {
	exe := writeFakeExe(t, `cat > /dev/null
echo "probe child: init ok" >&2
echo '{"ok":true,"latency_ms":42}'
`)
	st := NewSubprocessTester(nil, exe, time.Second)
	dur, err := st.Test(context.Background(), &Node{Protocol: "vless", Server: "1.2.3.4", Port: 443})
	if err != nil {
		t.Fatalf("clean success: got error: %v", err)
	}
	if dur != 42*time.Millisecond {
		t.Fatalf("latency: got %v, want 42ms", dur)
	}
}

// TestSubprocessTesterCleanError：子进程干净报告失败 → 错误保留原始文案，
// 供 classifyTestError 归类（i/o timeout → unreachable）。
func TestSubprocessTesterCleanError(t *testing.T) {
	exe := writeFakeExe(t, `cat > /dev/null
echo '{"ok":false,"error":"dial: i/o timeout"}'
`)
	st := NewSubprocessTester(nil, exe, time.Second)
	_, err := st.Test(context.Background(), &Node{Protocol: "vless", Server: "1.2.3.4", Port: 443})
	if err == nil {
		t.Fatal("clean error: expected error, got nil")
	}
	if got := classifyTestError(err); got != "unreachable" {
		t.Fatalf("classify: got %q, want unreachable (err=%v)", got, err)
	}
}

// TestSubprocessTesterHangKilled：子进程挂死（忽略 ctx）→ 父进程在 hard=2×timeout
// SIGKILL，返回 hang 错误。这是 #10 的核心回归：挂死探测必须在硬上限内被处置。
func TestSubprocessTesterHangKilled(t *testing.T) {
	// exec 使 sleep 直接成为子进程（无孤儿），kill 一击即中。
	exe := writeFakeExe(t, "cat > /dev/null\nexec sleep 30")
	st := NewSubprocessTester(nil, exe, 300*time.Millisecond) // hard = 600ms
	start := time.Now()
	_, err := st.Test(context.Background(), &Node{Protocol: "vless", Server: "1.2.3.4", Port: 443})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("hang: expected error, got nil")
	}
	if elapsed > 5*time.Second {
		t.Fatalf("hang not killed in hard limit: took %s", elapsed)
	}
	if elapsed < 500*time.Millisecond {
		t.Fatalf("killed too early: %s", elapsed)
	}
	if !strings.Contains(err.Error(), "hard-killed") || !strings.Contains(err.Error(), "hang") {
		t.Fatalf("hang error text: %q", err)
	}
}

// TestSubprocessTesterUnsupportedShortCircuit：vmess+tcp+http 伪装在父进程短路，
// 不启动子进程（脚本若被执行会留下 marker 文件）。
func TestSubprocessTesterUnsupportedShortCircuit(t *testing.T) {
	marker := filepath.Join(t.TempDir(), "ran")
	exe := writeFakeExe(t, "cat > /dev/null\nexec touch "+marker)
	st := NewSubprocessTester(nil, exe, time.Second)
	n := &Node{Protocol: "vmess", Network: "tcp", HeaderType: "http",
		Server: "1.2.3.4", Port: 443, UUID: "00000000-0000-0000-0000-000000000000"}
	_, err := st.Test(context.Background(), n)
	if !errors.Is(err, errUnsupportedTransport) {
		t.Fatalf("short-circuit: got %v, want errUnsupportedTransport", err)
	}
	if _, serr := os.Stat(marker); !os.IsNotExist(serr) {
		t.Fatal("child must not be spawned for unsupported transport (marker exists)")
	}
}

// TestTestConcurrentHangSubprocessSkipped（#10 端到端回归）：
// 挂死子进程被硬 kill 后，testItem 必须把节点归 skipped（保留、下轮重测），
// 绝不能标 dead（#6 语义）；且整体在硬上限附近返回，不再毒占 worker。
func TestTestConcurrentHangSubprocessSkipped(t *testing.T) {
	exe := writeFakeExe(t, "cat > /dev/null\nexec sleep 30")
	st := NewSubprocessTester(nil, exe, 300*time.Millisecond) // hard/perCtx = 600ms
	srv, _, _ := newTestServer(t, withTester(st), withCfg(func(c *Config) {
		c.TestTimeout = 300 * time.Millisecond
		c.Concurrency = 3
	}))
	items := makeItems(3)
	start := time.Now()
	srv.testConcurrent(context.Background(), items)
	elapsed := time.Since(start)
	if elapsed > 5*time.Second {
		t.Fatalf("testConcurrent with hung probes took %s, want ~600ms+overhead", elapsed)
	}
	for i, it := range items {
		stt, reason, detail, _ := it.snapshot()
		if stt == "dead" {
			t.Fatalf("item %d marked dead on hung probe (#6 regression): reason=%q detail=%q", i, reason, detail)
		}
		if stt != "skipped" {
			t.Fatalf("item %d: got status=%q, want skipped (detail=%q)", i, stt, detail)
		}
		if !strings.Contains(detail, "hang") {
			t.Fatalf("item %d: skipped detail should mention hang: %q", i, detail)
		}
	}
}

// TestCheckOnceOrdersByLastCheck（#10 建议 3 回归）：
// 周期测活按 last_check 升序测试（最旧优先），修复固定批次重复测、其余饿死。
func TestCheckOnceOrdersByLastCheck(t *testing.T) {
	srv, store, _ := newTestServer(t, withTester(&recordingTester{}), withCfg(func(c *Config) {
		c.Concurrency = 1 // 串行，顺序确定
		c.TestTimeout = time.Second
	}))
	base := int64(1_000_000)
	cases := []struct {
		name      string
		server    string
		lastCheck int64
	}{
		{"n-latest", "10.0.0.4", base + 3000},
		{"n-mid", "10.0.0.3", base + 1000},
		{"n-never", "10.0.0.2", 0},
		{"n-old", "10.0.0.1", base + 500},
	}
	for _, c := range cases {
		n := &Node{
			Protocol:  "vless",
			Server:    c.server,
			Port:      443,
			Name:      c.name,
			UUID:      "00000000-0000-0000-0000-000000000000",
			CreatedAt: base,
			LastCheck: c.lastCheck,
		}
		if err := store.Insert(n); err != nil {
			t.Fatalf("insert %s: %v", c.name, err)
		}
	}
	srv.checkOnce(context.Background())
	want := []string{"n-never", "n-old", "n-mid", "n-latest"}
	got := getRecordingTesterOrder()
	if len(got) != len(want) {
		t.Fatalf("test order: got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("test order[%d]: got %s, want %s (full=%v)", i, got[i], want[i], got)
		}
	}
}

// recordingTester 记录被测试节点的顺序（并发=1 下确定）。
var (
	recordingMu    sync.Mutex
	recordingOrder []string
)

type recordingTester struct{}

func (recordingTester) Test(ctx context.Context, n *Node) (time.Duration, error) {
	recordingMu.Lock()
	recordingOrder = append(recordingOrder, n.Name)
	recordingMu.Unlock()
	return 10 * time.Millisecond, nil
}

func getRecordingTesterOrder() []string {
	recordingMu.Lock()
	defer recordingMu.Unlock()
	out := make([]string, len(recordingOrder))
	copy(out, recordingOrder)
	return out
}

// TestRunProbeChildProtocol：probe 子命令侧——stdin 收节点 JSON、stdout 输出单行
// 结果 JSON（此处用闭合端口节点得到干净的 dial 失败）。
func TestRunProbeChildProtocol(t *testing.T) {
	// 本地测试目标，避免依赖外网 DNS。
	t.Setenv("PROXY2SUB_TEST_URL", "http://127.0.0.1:9/generate_204")
	t.Setenv("PROXY2SUB_TEST_TIMEOUT", "3s")
	out, _ := runProbeWithInput(t, `{"protocol":"socks","server":"127.0.0.1","port":1}`)
	if !strings.Contains(out, `"ok":false`) || !strings.Contains(out, `"error":`) {
		t.Fatalf("runProbe output: %q", out)
	}
}

// TestRunProbeChildBadJSON：stdin 非 JSON → 干净报错，不 panic。
func TestRunProbeChildBadJSON(t *testing.T) {
	out, _ := runProbeWithInput(t, `not-json`)
	if !strings.Contains(out, `"ok":false`) || !strings.Contains(out, "bad node json") {
		t.Fatalf("runProbe bad-json output: %q", out)
	}
}

// runProbeWithInput 替换 os.Stdin/os.Stdout 执行 runProbe，返回 stdout 输出。
func runProbeWithInput(t *testing.T, input string) (string, error) {
	t.Helper()
	oldStdin, oldStdout := os.Stdin, os.Stdout
	defer func() { os.Stdin, os.Stdout = oldStdin, oldStdout }()

	rIn, wIn, err := os.Pipe()
	if err != nil {
		return "", err
	}
	rOut, wOut, err := os.Pipe()
	if err != nil {
		return "", err
	}
	os.Stdin, os.Stdout = rIn, wOut

	go func() {
		_, _ = wIn.WriteString(input)
		_ = wIn.Close()
	}()
	done := make(chan struct{})
	go func() {
		runProbe()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(15 * time.Second):
		return "", errors.New("runProbe did not return")
	}
	_ = wOut.Close()
	out, _ := io.ReadAll(rOut)
	return string(out), nil
}
