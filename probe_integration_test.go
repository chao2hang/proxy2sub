package main

// 集成测试：构建真实二进制，端到端验证 probe 子进程隔离测活（#10）。
// 依赖 go 工具链与 with_utls/with_quic 构建，耗时较长，仅在
// PROXY2SUB_INTEGRATION=1 时运行（CI test job 显式开启）。

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// buildRealBinary 构建带编译 tag 的真实二进制（三个集成测试共享一次构建）。
var realBinary = sync.OnceValues(func() (string, error) {
	bin := filepath.Join(os.TempDir(), fmt.Sprintf("proxy2sub-int-%d", os.Getpid()))
	cmd := exec.Command("go", "build",
		"-tags", "with_utls with_quic",
		"-ldflags", "-s -w",
		"-o", bin, ".")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("go build: %v\n%s", err, out)
	}
	return bin, nil
})

func buildRealBinary(t *testing.T) string {
	t.Helper()
	bin, err := realBinary()
	if err != nil {
		t.Fatalf("%v", err)
	}
	return bin
}

// setTestEnv 临时设置子进程可见的环境变量（probe 子进程继承父进程 env）。
func setTestEnv(t *testing.T, k, v string) {
	t.Helper()
	old, ok := os.LookupEnv(k)
	if err := os.Setenv(k, v); err != nil {
		t.Fatalf("setenv %s: %v", k, err)
	}
	t.Cleanup(func() {
		if ok {
			_ = os.Setenv(k, old)
		} else {
			_ = os.Unsetenv(k)
		}
	})
}

// startConnectProxy 起一个极简 CONNECT 代理，隧道到 target。
func startConnectProxy(t *testing.T, target string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen proxy: %v", err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			client, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				br := bufio.NewReader(c)
				line, err := br.ReadString('\n')
				if err != nil || !strings.HasPrefix(line, "CONNECT") {
					return
				}
				// 读到空行（请求头结束）
				for {
					l, lerr := br.ReadString('\n')
					if lerr != nil {
						return
					}
					if l == "\r\n" || l == "\n" {
						break
					}
				}
				host := strings.Fields(strings.TrimSpace(line))[1]
				up, err := net.Dial("tcp", host)
				if err != nil {
					_, _ = fmt.Fprint(c, "HTTP/1.1 502 Bad Gateway\r\n\r\n")
					return
				}
				defer up.Close()
				_, _ = fmt.Fprint(c, "HTTP/1.1 200 Connection Established\r\n\r\n")
				go func() { _, _ = io.Copy(up, c) }()
				_, _ = io.Copy(c, up)
			}(client)
		}
	}()
	return ln.Addr().String()
}

// silentUDPBlackhole bind 一个 UDP 端口但永不读包（静默黑洞，模拟防火墙 DROP）。
func silentUDPBlackhole(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen udp: %v", err)
	}
	t.Cleanup(func() { _ = pc.Close() })
	return pc.LocalAddr().(*net.UDPAddr).Port
}

// TestIntegrationProbeAlive：http 节点经本地 CONNECT 代理测活目标 → alive + 延迟。
func TestIntegrationProbeAlive(t *testing.T) {
	if os.Getenv("PROXY2SUB_INTEGRATION") != "1" {
		t.Skip("set PROXY2SUB_INTEGRATION=1 to run")
	}
	target := newTestTarget(t) // 本地 204 目标
	proxyAddr := startConnectProxy(t, target)

	bin := buildRealBinary(t)
	setTestEnv(t, "PROXY2SUB_TEST_URL", "http://"+target)
	setTestEnv(t, "PROXY2SUB_TEST_TIMEOUT", "5s")

	st := NewSubprocessTester(nil, bin, 5*time.Second)
	dur, err := st.Test(context.Background(), &Node{
		Protocol: "http", Server: "127.0.0.1",
		Port: atoiAddrPort(proxyAddr),
	})
	if err != nil {
		t.Fatalf("probe alive: %v", err)
	}
	// loopback 往返可能 <1ms（取整为 0），只断言非负；关键断言是 err==nil（alive）。
	if dur < 0 {
		t.Fatalf("latency should be >= 0, got %v", dur)
	}
}

// TestIntegrationProbeDeadClosedPort：闭合端口节点 → 快速失败。
// connection refused = 节点服务未运行（节点本身死亡）→ 归 dead，应被周期检查清理。
func TestIntegrationProbeDeadClosedPort(t *testing.T) {
	if os.Getenv("PROXY2SUB_INTEGRATION") != "1" {
		t.Skip("set PROXY2SUB_INTEGRATION=1 to run")
	}
	bin := buildRealBinary(t)
	setTestEnv(t, "PROXY2SUB_TEST_URL", "http://127.0.0.1:9/generate_204")
	setTestEnv(t, "PROXY2SUB_TEST_TIMEOUT", "3s")

	st := NewSubprocessTester(nil, bin, 3*time.Second)
	start := time.Now()
	_, err := st.Test(context.Background(), &Node{
		Protocol: "http", Server: "127.0.0.1", Port: 1, // 闭合端口
	})
	if err == nil {
		t.Fatal("closed port: expected error")
	}
	if elapsed := time.Since(start); elapsed > 10*time.Second {
		t.Fatalf("closed port probe took %s, want fast fail", elapsed)
	}
	if got := classifyTestError(err); got != "dead" {
		t.Fatalf("classify: got %q, want dead (connection refused = node down, err=%v)", got, err)
	}
}

// TestIntegrationProbeHangHardKilled（#10 生产场景复现）：
// hysteria2 节点指向静默 UDP 黑洞——QUIC 握手若挂死（ctx 取消无效，即生产根因），
// 父进程必须在 hard=2×timeout SIGKILL 子进程并返回 hang 错误；
// 若 quic-go 版本尊重 ctx 则得到干净超时错误。两种结果都必须快速返回、不毒占 worker。
func TestIntegrationProbeHangHardKilled(t *testing.T) {
	if os.Getenv("PROXY2SUB_INTEGRATION") != "1" {
		t.Skip("set PROXY2SUB_INTEGRATION=1 to run")
	}
	blackholePort := silentUDPBlackhole(t)
	bin := buildRealBinary(t)
	setTestEnv(t, "PROXY2SUB_TEST_URL", "http://127.0.0.1:9/generate_204")
	setTestEnv(t, "PROXY2SUB_TEST_TIMEOUT", "1s")

	st := NewSubprocessTester(nil, bin, 1*time.Second) // hard = 2s
	start := time.Now()
	_, err := st.Test(context.Background(), &Node{
		Protocol: "hysteria2", Server: "127.0.0.1", Port: blackholePort,
		Password: "0123456789abcdef", SNI: "127.0.0.1", TLS: true,
	})
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("udp blackhole: expected error (no response will ever come)")
	}
	if elapsed > 6*time.Second {
		t.Fatalf("probe not bounded: took %s (hang must be hard-killed at ~2s)", elapsed)
	}
	t.Logf("blackhole probe bounded in %s: %v", elapsed, err)
	if strings.Contains(err.Error(), "hang") {
		t.Logf("reproduced production hang: hard-killed at 2x timeout (issue #10 root cause)")
	}
}

// newTestTarget 起一个返回 204 的本地 HTTP 目标，返回 host:port。
func newTestTarget(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen target: %v", err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})}
	go func() { _ = srv.Serve(ln) }()
	t.Cleanup(func() { _ = srv.Close() })
	return ln.Addr().String()
}

func atoiAddrPort(addr string) int {
	_, p, err := net.SplitHostPort(addr)
	if err != nil {
		panic(err)
	}
	var n int
	_, _ = fmt.Sscanf(p, "%d", &n)
	return n
}
