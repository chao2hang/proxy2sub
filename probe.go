package main

// 子进程隔离测活（见 #10）。
//
// 背景：sing-box 内部底层调用（vless+tcp+tls 的 kTLS offload ioctl、QUIC 握手等）
// 在容器化内核上可能无限阻塞——ctx 取消打不断，`Box.Close()` 也不跟踪进行中的
// 握手连接，所以 #9 的看门狗 Close 无法解除阻塞（#10 生产实测：单探测挂死 >15min，
// 20 个 worker 全被毒占）。进程内已无可靠手段约束单次探测生命周期，唯一可靠边界
// 是进程边界：SIGKILL 必然生效，且进程退出由内核全量回收 fd/内存/goroutine，无泄漏。
//
// 模型：每次测活 fork 一个 `proxy2sub probe` 子进程，节点 JSON 走 stdin，
// 结果 JSON 走 stdout。父进程用 exec.CommandContext 在 2×TestTimeout 硬 kill：
//   - 子进程在 TestTimeout 内干净返回（成功/协议失败/可取消超时）→ 按结果归类
//   - 子进程超过 2×TestTimeout 仍不返回（挂死）→ SIGKILL，父进程归 skipped
//     （保留节点下轮重测，#6 语义：超时未完成 ≠ 节点失败）
//
// 子进程自清理：父进程被 SIGKILL 时子进程孤立，但会在自身 TestTimeout 到期后
// 自行退出，不会残留。

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// probeResult 是 probe 子进程 stdout 的单行 JSON 协议。
type probeResult struct {
	OK          bool   `json:"ok"`
	LatencyMS   int64  `json:"latency_ms,omitempty"`
	Error       string `json:"error,omitempty"`
	Unsupported bool   `json:"unsupported,omitempty"` // 对应 errUnsupportedTransport
}

// runProbe 执行 `proxy2sub probe` 子命令：从 stdin 读一条 Node JSON，
// 真实测活一次，向 stdout 输出一行结果 JSON。日志全部走 stderr。
// 除内部致命错误外总以退出码 0 结束（结果在 JSON 里，父进程据此归类）。
func runProbe() {
	emit := func(pr probeResult) {
		b, _ := json.Marshal(pr)
		fmt.Fprintln(os.Stdout, string(b))
	}
	defer func() {
		if r := recover(); r != nil {
			emit(probeResult{OK: false, Error: fmt.Sprintf("probe panic: %v", r)})
		}
	}()

	body, err := io.ReadAll(io.LimitReader(os.Stdin, 1<<20))
	if err != nil {
		emit(probeResult{OK: false, Error: "read stdin: " + err.Error()})
		return
	}
	var n Node
	if err := json.Unmarshal(bytes.TrimSpace(body), &n); err != nil {
		emit(probeResult{OK: false, Error: "bad node json: " + err.Error()})
		return
	}
	if verr := n.Verify(); verr != nil {
		emit(probeResult{OK: false, Error: "bad node: " + verr.Error()})
		return
	}

	cfg := loadConfig()
	tester, err := NewTester(cfg.TestTimeout, cfg.TestURL)
	if err != nil {
		emit(probeResult{OK: false, Error: "bad test url: " + err.Error()})
		return
	}

	dur, terr := tester.Test(context.Background(), &n)
	if terr != nil {
		pr := probeResult{OK: false, Error: terr.Error()}
		if errors.Is(terr, errUnsupportedTransport) {
			pr.Unsupported = true
		}
		emit(pr)
		return
	}
	emit(probeResult{OK: true, LatencyMS: dur.Milliseconds()})
}

// probeExePath 解析当前可执行文件路径（os.Executable 异常时回退 /proc/self/exe）。
func probeExePath() string {
	if exe, err := os.Executable(); err == nil && exe != "" {
		if abs, aerr := filepath.Abs(exe); aerr == nil {
			if _, serr := os.Stat(abs); serr == nil {
				return abs
			}
		}
	}
	if p, err := os.Readlink("/proc/self/exe"); err == nil && p != "" {
		return p
	}
	return ""
}

// SubprocessTester 以子进程隔离方式执行测活，实现 TesterIface。
// 每个节点一次 `probe` 子进程；挂死的探测在 hard（2×TestTimeout）被 SIGKILL。
type SubprocessTester struct {
	base *Tester // 进程内测活器（probe 子命令内部使用）
	exe  string  // 本进程可执行文件路径
	hard time.Duration
}

// NewSubprocessTester 构造 SubprocessTester。timeout 应等于 cfg.TestTimeout。
func NewSubprocessTester(base *Tester, exe string, timeout time.Duration) *SubprocessTester {
	hard := 2 * timeout
	if hard <= 0 {
		hard = 16 * time.Second
	}
	return &SubprocessTester{base: base, exe: exe, hard: hard}
}

var _ TesterIface = (*SubprocessTester)(nil)

// Test 测活单个节点。语义见文件头注释。
func (t *SubprocessTester) Test(ctx context.Context, n *Node) (time.Duration, error) {
	if t.exe == "" {
		return 0, errors.New("probe: no executable path (os.Executable failed)")
	}
	// 轻量短路（#7）：p2s 尚无法验证的传输配置不启动子进程，直接 unsupported。
	if (n.Network == "tcp" || n.Network == "") && n.HeaderType == "http" &&
		(n.Protocol == "vmess" || n.Protocol == "trojan") {
		return 0, errUnsupportedTransport
	}

	nodeJSON, err := json.Marshal(n)
	if err != nil {
		return 0, fmt.Errorf("probe: marshal node: %w", err)
	}

	hardCtx, cancel := context.WithTimeout(ctx, t.hard)
	defer cancel()

	cmd := exec.CommandContext(hardCtx, t.exe, "probe")
	cmd.Env = append(os.Environ(), "GOMEMLIMIT=256MiB")
	cmd.Stdin = bytes.NewReader(nodeJSON)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()

	var pr probeResult
	if line := lastNonEmptyLine(stdout.String()); line != "" {
		_ = json.Unmarshal([]byte(line), &pr)
	}

	switch {
	case runErr == nil && pr.OK:
		return time.Duration(pr.LatencyMS) * time.Millisecond, nil
	case runErr == nil && pr.Unsupported:
		return 0, errUnsupportedTransport
	case runErr == nil && pr.Error != "":
		// 子进程干净退出并报告失败（协议错误 / 可取消超时），保留原始错误文案供 classifyTestError 归类。
		return 0, errors.New(pr.Error + stderrTail(stderr.String()))
	case hardCtx.Err() != nil:
		// 2×TestTimeout 硬 kill：探测挂死（ctx 取消与 Close 均无法解除的底层阻塞）。
		return 0, fmt.Errorf("probe hard-killed after %s (hang)%s", t.hard, stderrTail(stderr.String()))
	default:
		// 子进程崩溃（panic / 非 0 退出）：单点失败，归 dead 由删除熔断兜底。
		return 0, fmt.Errorf("probe exited: %v%s", runErr, stderrTail(stderr.String()))
	}
}

// lastNonEmptyLine 取输出中最后一个非空行（协议行最后输出，防御前面混入的杂讯）。
func lastNonEmptyLine(s string) string {
	lines := strings.Split(s, "\n")
	for i := len(lines) - 1; i >= 0; i-- {
		if l := strings.TrimSpace(lines[i]); l != "" {
			return l
		}
	}
	return ""
}

// stderrTail 截取 stderr 尾部 ~1KB 附在错误 detail 里，便于线上排障。
func stderrTail(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return ""
	}
	if len(s) > 1024 {
		s = "…" + s[len(s)-1024:]
	}
	return "; stderr: " + s
}
