package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"runtime"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Server 持有配置、存储、地理解析与测活器。
type Server struct {
	cfg        *Config
	store      *Store
	geo        GeoResolver
	tester     TesterIface
	httpClient *http.Client

	checkRunning atomic.Bool // 周期测活单飞（见 #5）
}

// TesterIface 测活器接口；*Tester 隐式满足，测试可注入 fake。
type TesterIface interface {
	Test(ctx context.Context, n *Node) (time.Duration, error)
}

// pushItem 一次推送/周期测活中单条线路的状态。
// status/reason/detail/latency 由测活 goroutine 写入、请求/周期 goroutine 读取；
// 全局 deadline 后残留 goroutine 仍可能迟到写入（卡死的 sing-box 实例被看门狗
// 解除后才返回，见 #9），因此用互斥锁保护，保证 checkOnce/handlePush 读取时
// 不与迟到写入构成数据竞争。
type pushItem struct {
	link string
	node *Node

	mu      sync.Mutex
	status  string // pending / alive / dead / skipped / added / duplicate / invalid
	reason  string // dead / unreachable（仅 status=dead 时有意义）
	detail  string
	latency int64
}

// finish 由测活 goroutine 写入最终结果（仅补空字段，不覆盖已有非空值）。
func (it *pushItem) finish(status, reason, detail string, latency int64) {
	it.mu.Lock()
	defer it.mu.Unlock()
	it.status = status
	if reason != "" {
		it.reason = reason
	}
	if detail != "" {
		it.detail = detail
	}
	it.latency = latency
}

// snapshot 读取当前结果。
func (it *pushItem) snapshot() (status, reason, detail string, latency int64) {
	it.mu.Lock()
	defer it.mu.Unlock()
	return it.status, it.reason, it.detail, it.latency
}

func ipToAddr(s string) netip.Addr {
	if ip := net.ParseIP(s); ip != nil {
		if a, ok := netip.AddrFromSlice(ip); ok {
			return a.Unmap()
		}
	}
	return netip.Addr{}
}

func (s *Server) requireToken(token string, r *http.Request) bool {
	if token == "" {
		return true
	}
	if given := r.Header.Get("Authorization"); strings.HasPrefix(given, "Bearer ") {
		return given[len("Bearer "):] == token
	}
	return r.URL.Query().Get("token") == token
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// ---------------------------------------------------------------------------
// 推送：POST /api/push
// ---------------------------------------------------------------------------

type pushResult struct {
	Link    string `json:"link"`
	Status  string `json:"status"`
	Name    string `json:"name,omitempty"`
	Detail  string `json:"detail,omitempty"`
	Reason  string `json:"reason,omitempty"` // dead / unreachable（仅 status=dead 时有值）
	Latency int64  `json:"latency_ms,omitempty"`
}

type pushResponse struct {
	Received   int          `json:"received"`
	Parsed     int          `json:"parsed"`
	Invalid    int          `json:"invalid"`
	Duplicates int          `json:"duplicates"`
	Alive      int          `json:"alive"`
	Dead       int          `json:"dead"`
	Skipped    int          `json:"skipped,omitempty"` // 本轮未完成测活（deadline 截断/不支持传输），未入库
	Added      int          `json:"added"`
	Results    []pushResult `json:"results,omitempty"`
}

func (s *Server) handlePush(w http.ResponseWriter, r *http.Request) {
	if !s.requireToken(s.cfg.PushToken, r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, 10<<20))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "read body: " + err.Error()})
		return
	}

	// 展开：文本/base64 行一律视为代理线路；JSON 支持 {links:[...], urls:[...]}
	// 其中 urls 为远程订阅地址（会被抓取后解析），links 为线路本身。
	links, urls := parseInput(body)
	for _, u := range urls {
		fetched, ferr := s.fetchLinks(u)
		if ferr != nil {
			log.Printf("fetch %s: %v", u, ferr)
			continue
		}
		links = append(links, fetched...)
	}

	resp := pushResponse{Received: len(links)}
	if len(links) == 0 {
		writeJSON(w, http.StatusOK, resp)
		return
	}

	// 解析 + 去重
	seen := make(map[string]bool, len(links))
	var items []*pushItem
	for _, l := range links {
		n, perr := ParseLink(l)
		if perr != nil {
			resp.Invalid++
			items = append(items, &pushItem{link: l, status: "invalid"})
			continue
		}
		if verr := n.Verify(); verr != nil {
			resp.Invalid++
			items = append(items, &pushItem{link: l, status: "invalid", detail: verr.Error()})
			continue
		}
		resp.Parsed++
		key := n.Key()
		if seen[key] {
			resp.Duplicates++
			items = append(items, &pushItem{link: l, status: "duplicate"})
			continue
		}
		seen[key] = true
		exists, eerr := s.store.Exists(n)
		if eerr != nil {
			writeJSON(w, http.StatusInternalServerError, map[string]string{"error": eerr.Error()})
			return
		}
		if exists {
			resp.Duplicates++
			items = append(items, &pushItem{link: l, status: "duplicate"})
			continue
		}
		items = append(items, &pushItem{link: l, node: n, status: "pending"})
	}

	// 测活（入库前，活的才放行）。
	// 全局 deadline 由 testConcurrent 内部按规模计算；即使客户端提前断开，也把测活与入库做完。
	var pending []*pushItem
	for _, it := range items {
		if it.node != nil && it.status == "pending" {
			pending = append(pending, it)
		}
	}
	s.testConcurrent(context.Background(), pending)

	// 地理识别 + 入库
	var addrs []netip.Addr
	for _, it := range pending {
		if st, _, _, _ := it.snapshot(); st == "alive" {
			if a := ipToAddr(it.node.ResolveServerIP()); a.IsValid() {
				addrs = append(addrs, a)
			}
		}
	}
	ccMap := s.geo.Resolve(addrs)
	now := time.Now().Unix()
	for _, it := range pending {
		n := it.node
		st, _, _, lat := it.snapshot()
		if st == "alive" {
			resp.Alive++
			n.LatencyMS = lat
			if a := ipToAddr(n.IP); a.IsValid() {
				if cc, ok := ccMap[a]; ok {
					n.Country = cc
				}
			}
			if n.Country == "" {
				n.Country = "ZZ"
			}
			n.SetName()
			n.CreatedAt = now
			n.LastCheck = now
			if ierr := s.store.Insert(n); ierr != nil {
				log.Printf("insert %s: %v", n.Name, ierr)
				continue
			}
			resp.Added++
			it.finish("added", "", n.Name, lat)
		} else if st == "skipped" {
			resp.Skipped++
		} else {
			resp.Dead++
		}
	}

	if r.URL.Query().Get("detail") == "1" {
		resp.Results = make([]pushResult, 0, len(items))
		for _, it := range items {
			st, reason, detail, lat := it.snapshot()
			resp.Results = append(resp.Results, pushResult{
				Link: it.link, Status: st, Name: detail, Detail: detail, Reason: reason, Latency: lat,
			})
		}
	}
	log.Printf("push: received=%d parsed=%d invalid=%d dup=%d alive=%d dead=%d skipped=%d added=%d",
		resp.Received, resp.Parsed, resp.Invalid, resp.Duplicates, resp.Alive, resp.Dead, resp.Skipped, resp.Added)
	writeJSON(w, http.StatusOK, resp)
}

// classifyTestError 把 sing-box 测活错误归类为面向用户的 reason。
//
//	unreachable: 环境不可达（超时 / DNS / 无 IPv6 路由 / 本地网络）
//	dead:        节点本身问题（协议 / 认证 / TLS / 状态码）
func classifyTestError(err error) string {
	if err == nil {
		return ""
	}
	msg := strings.ToLower(err.Error())
	switch {
	case strings.Contains(msg, "timeout"),
		strings.Contains(msg, "deadline exceeded"),
		strings.Contains(msg, "i/o timeout"),
		strings.Contains(msg, "no route to host"),
		strings.Contains(msg, "network is unreachable"),
		strings.Contains(msg, "cannot assign requested address"),
		strings.Contains(msg, "no such host"),
		strings.Contains(msg, "resolve "),
		strings.Contains(msg, "no address"):
		return "unreachable"
	default:
		return "dead"
	}
}

// testConcurrent 并发测活，结果写入各 item。
//
// worker-pool 模型（见 #8）：固定 Concurrency 个 worker 从队列逐个领取节点测试，
// 每一轮全量节点都会被真实测完——v0.1.6 及之前的"非阻塞抢信号量、抢不到即
// skipped"只让每轮随机测到 Concurrency 个节点，大库永远测不完、alive 统计失真。
//
// 超时语义（见 #5/#6/#9/#10）：
//   - 单节点硬截止 2x TestTimeout（与 SubprocessTester 的硬 kill 上限对齐）
//   - 全局 deadline 随规模伸缩：3x TestTimeout x ⌈N/Concurrency⌉ + 30s，
//     到点后未完成的 item 一律标 skipped（保留节点、下轮重测），绝不判 dead
//   - 挂死在 sing-box 底层调用（kTLS ioctl / QUIC 等，ctx 取消与 Close 均无效）
//     的测试由子进程隔离兜底：父进程在 2x TestTimeout SIGKILL 子进程（见 #10）
func (s *Server) testConcurrent(ctx context.Context, items []*pushItem) {
	n := len(items)
	if n == 0 {
		return
	}
	concurrency := s.cfg.Concurrency
	if concurrency <= 0 {
		concurrency = 1
	}
	if concurrency > n {
		concurrency = n
	}
	batches := (n + concurrency - 1) / concurrency
	globalTimeout := time.Duration(batches)*3*s.cfg.TestTimeout + 30*time.Second
	testCtx, cancel := context.WithTimeout(ctx, globalTimeout)
	defer cancel()

	queue := make(chan *pushItem, n)
	for _, it := range items {
		queue <- it
	}
	close(queue)

	var done int32
	var wg sync.WaitGroup
	wg.Add(concurrency)
	for i := 0; i < concurrency; i++ {
		go func() {
			defer wg.Done()
			for it := range queue {
				s.testItem(testCtx, it)
				atomic.AddInt32(&done, 1)
			}
		}()
	}
	finished := make(chan struct{})
	go func() {
		wg.Wait()
		close(finished)
	}()

	select {
	case <-finished:
		return
	case <-testCtx.Done():
	}
	// 全局 deadline：给在飞测试一小段宽限让它们感知 ctx 取消并写回 skipped，
	// 避免迟到写入与 checkOnce 的读取重叠；仍卡死的由看门狗事后解除（不阻塞本轮）。
	grace := time.NewTimer(3 * time.Second)
	defer grace.Stop()
	select {
	case <-finished:
	case <-grace.C:
		d := atomic.LoadInt32(&done)
		log.Printf("periodic check: global deadline hit, %d done / %d expected, %d unresolved (stuck tests will be reaped by watchdog)",
			d, n, n-int(d))
	}
}

// testItem 测活单个节点并写入结果。
func (s *Server) testItem(testCtx context.Context, it *pushItem) {
	defer func() {
		if r := recover(); r != nil {
			// 单节点测活 panic：保守归 unreachable，不传染其他节点、不杀整个 checkOnce（见 #4）。
			it.finish("dead", "unreachable", fmt.Sprintf("tester panic: %v", r), 0)
			log.Printf("tester panic on %s: %v\n%s", it.node.Name, r, debug.Stack())
		}
	}()
	// 2×TestTimeout：与 SubprocessTester 的硬 kill 上限对齐（#10）。
	// 挂死的探测在 2× 时点被父进程 SIGKILL 返回错误，此时 perCtx 恰好到期，
	// 下方 deadline 分支将其归 skipped（保留节点、下轮重测），绝不判 dead。
	perCtx, perCancel := context.WithTimeout(testCtx, time.Duration(float64(s.cfg.TestTimeout)*2))
	defer perCancel()
	dur, err := s.tester.Test(perCtx, it.node)
	if err != nil {
		if errors.Is(err, errUnsupportedTransport) {
			// p2s 尚无法验证的传输配置（如 vmess tcp+http 伪装）：保留节点，不判 dead（见 #7）
			it.finish("skipped", "", err.Error(), 0)
			log.Printf("tester unsupported transport on %s://%s:%d, node kept untested",
				it.node.Protocol, it.node.Server, it.node.Port)
			return
		}
		if testCtx.Err() != nil || perCtx.Err() != nil {
			// 本轮被 deadline 截断 ≠ 节点自身失败：保留，下轮重测（见 #6 期望 1）
			it.finish("skipped", "", "test deadline: "+err.Error(), 0)
			return
		}
		it.finish("dead", classifyTestError(err), err.Error(), 0)
		return
	}
	it.finish("alive", "", "", dur.Milliseconds())
}

// checkOnce 周期测活：失效删除，存活更新结果。
// 返回 total/alive/dead/skipped 计数（供 /api/check 同步模式使用）。
//
// 删除规则 (见 #6)：
//   - 仅删除 status == "dead" 的节点（确认 sing-box 失败 / panics）
//   - "pending"（未测到）/ "skipped"（deadline 截断 / 不支持传输）/ ""（默认值）全部保留
//
// 删除熔断：单轮 dead/total 比例超过 MaxDeadRatioPct（默认 50%）时中止删除，
// 整轮只刷新 alive 元数据，避免类似 v0.1.5 的批量误删（见 #6 复盘 2555→17）。
// 阈值 0 = 禁用熔断。小库（total<20）直通删除，避免误触发熔断。
func (s *Server) checkOnce(ctx context.Context) (total, alive, deadCount, skippedCount int) {
	nodes, err := s.store.All()
	if err != nil {
		log.Printf("periodic check: load: %v", err)
		return 0, 0, 0, 0
	}
	log.Printf("periodic check: start total=%d concurrency=%d timeout=%s",
		len(nodes), s.cfg.Concurrency, s.cfg.TestTimeout)
	if len(nodes) == 0 {
		return 0, 0, 0, 0
	}
	// 最旧 last_check 优先测（#10 建议 3）：此前按 rowid（入库顺序）排队，
	// 队列头固定那批节点每轮被重复测、其余饿死（生产 61% 节点 last_check >1d）。
	// 排序后每轮先覆盖最久未测的节点，全库均匀轮转；LastCheck=0 天然排最前。
	sort.Slice(nodes, func(i, j int) bool {
		return nodes[i].LastCheck < nodes[j].LastCheck
	})
	items := make([]*pushItem, 0, len(nodes))
	for _, n := range nodes {
		items = append(items, &pushItem{node: n, status: "pending"})
	}
	s.testConcurrent(ctx, items)

	var addrs []netip.Addr
	for _, it := range items {
		if st, _, _, _ := it.snapshot(); st == "alive" {
			if a := ipToAddr(it.node.ResolveServerIP()); a.IsValid() {
				addrs = append(addrs, a)
			}
		}
	}
	ccMap := s.geo.Resolve(addrs)
	now := time.Now().Unix()
	var dead []int64
	for _, it := range items {
		n := it.node
		st, _, _, lat := it.snapshot()
		switch st {
		case "alive":
			alive++
			n.LatencyMS = lat
			n.LastCheck = now
			if a := ipToAddr(n.IP); a.IsValid() {
				if cc, ok := ccMap[a]; ok && cc != "ZZ" {
					n.Country = cc
				}
			}
			n.SetName()
			if uerr := s.store.UpdateResult(n); uerr != nil {
				log.Printf("periodic check: update %d: %v", n.ID, uerr)
			}
		case "skipped":
			skippedCount++
		case "dead":
			dead = append(dead, n.ID)
		}
	}
	// 删除熔断：单轮 dead/total 比例超阈值时中止整轮删除，避免单点故障导致批量误删。
	ratioPct := 0
	if nodeTotal := len(nodes); nodeTotal > 0 {
		ratioPct = len(dead) * 100 / nodeTotal
	}
	if s.cfg.MaxDeadRatioPct > 0 && len(nodes) >= 20 && ratioPct > s.cfg.MaxDeadRatioPct {
		log.Printf("periodic check: ABORT deletion: dead=%d total=%d ratio=%d%% > %d%% (nodes kept untouched, will retry next round)",
			len(dead), len(nodes), ratioPct, s.cfg.MaxDeadRatioPct)
		// 不删任何 ID；deadCount 计为 0 表示本轮没真正删除任何节点
		log.Printf("periodic check: total=%d alive=%d dead=%d skipped=%d", len(nodes), alive, 0, skippedCount)
		return len(nodes), alive, 0, skippedCount
	}
	for _, id := range dead {
		if derr := s.store.Delete(id); derr != nil {
			log.Printf("periodic check: delete %d: %v", id, derr)
		}
	}
	deadCount = len(dead)
	total = len(nodes)
	log.Printf("periodic check: total=%d alive=%d dead=%d skipped=%d", total, alive, deadCount, skippedCount)
	return total, alive, deadCount, skippedCount
}

// safeCheckOnce 包 recover + running 互斥的 checkOnce。
// - recover：单次 panic 不杀死周期 goroutine（见 #4）
// - 单飞：上一轮未结束时不启动新一轮，避免泄漏 goroutine 叠加（见 #5）
func (s *Server) safeCheckOnce(ctx context.Context) (total, alive, dead, skipped int) {
	if !s.checkRunning.CompareAndSwap(false, true) {
		log.Printf("periodic check: skip, previous round still running")
		return 0, 0, 0, 0
	}
	defer s.checkRunning.Store(false)
	defer func() {
		if r := recover(); r != nil {
			log.Printf("periodic check: panic recovered: %v\n%s", r, debug.Stack())
		}
	}()
	return s.checkOnce(ctx)
}

// checkLoop 按 CheckInterval 周期触发 safeCheckOnce。
// 若 runOnStart 为 true，启动后先 sleep 3s 跑一轮（让 store/geo/tester 就绪），
// 随后进入 ticker 循环。
func (s *Server) checkLoop(ctx context.Context, interval time.Duration, runOnStart bool) {
	if runOnStart {
		time.Sleep(3 * time.Second)
		s.safeCheckOnce(ctx)
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.safeCheckOnce(ctx)
		}
	}
}

// ---------------------------------------------------------------------------
// 输入解析
// ---------------------------------------------------------------------------

// parseInput 返回 (proxyLinks, remoteSubURLs)。
// JSON: {"links":[代理线路], "urls":[远程订阅地址]}
// 文本: 每行一个代理线路。
// 两种输入都支持 base64：
//   - 整体 base64 的 v2ray 订阅（正文就是一整段 base64）
//   - 每条线路单独 base64（如 vmess 链接常见）
func parseInput(body []byte) (links, urls []string) {
	trim := bytes.TrimSpace(body)
	if len(trim) == 0 {
		return nil, nil
	}
	if trim[0] == '{' {
		var v struct {
			Links []string `json:"links"`
			URLs  []string `json:"urls"`
		}
		if err := json.Unmarshal(trim, &v); err == nil {
			for _, l := range v.Links {
				links = append(links, expandBase64(l)...)
			}
			for _, u := range v.URLs {
				urls = append(urls, splitLines(u)...)
			}
			return links, urls
		}
	}
	text := strings.Trim(string(trim), `"`)
	lines := splitLines(text)
	// 单行且不含 :// 时，尝试整体 base64（标准 v2ray 订阅格式）。
	// 注意 Go 的 base64 解码会忽略换行，因此多行正文必须逐行处理，
	// 否则"每行各是一个 base64"会被错误地拼接解码。
	if len(lines) == 1 && !strings.Contains(lines[0], "://") {
		if dec := b64Decode(lines[0]); dec != nil && strings.Contains(string(dec), "://") {
			lines = splitLines(string(dec))
		}
	}
	for _, line := range lines {
		links = append(links, expandBase64(line)...)
	}
	return links, nil
}

// expandBase64 若一行整体是 base64（解码后含代理链接），展开为多行；否则原样返回。
func expandBase64(line string) []string {
	if dec := b64Decode(line); dec != nil && strings.Contains(string(dec), "://") {
		return splitLines(string(dec))
	}
	return []string{line}
}

func splitLines(s string) []string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if l = strings.TrimSpace(l); l != "" && !strings.HasPrefix(l, "#") {
			out = append(out, l)
		}
	}
	return out
}

func (s *Server) fetchLinks(rawURL string) ([]string, error) {
	req, err := http.NewRequest(http.MethodGet, rawURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)")
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	req = req.WithContext(ctx)
	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("status %d", resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20))
	if err != nil {
		return nil, err
	}
	links, _ := parseInput(body)
	return links, nil
}

// ---------------------------------------------------------------------------
// 订阅：GET /sub
// ---------------------------------------------------------------------------

func (s *Server) handleSub(w http.ResponseWriter, r *http.Request) {
	if !s.requireToken(s.cfg.SubToken, r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	typ := strings.ToLower(r.URL.Query().Get("type"))
	if typ == "" {
		accept := r.Header.Get("Accept")
		ua := strings.ToLower(r.UserAgent())
		if strings.Contains(accept, "clash") || strings.Contains(accept, "yaml") ||
			strings.Contains(ua, "clash") || strings.Contains(ua, "mihomo") ||
			strings.Contains(ua, "stash") || strings.Contains(ua, "surge") {
			typ = "clash"
		} else {
			typ = "v2ray"
		}
	}

	nodes, err := s.store.All()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	if cc := strings.ToUpper(r.URL.Query().Get("country")); cc != "" {
		var filtered []*Node
		for _, n := range nodes {
			if strings.EqualFold(n.Country, cc) {
				filtered = append(filtered, n)
			}
		}
		nodes = filtered
	}
	sort.Slice(nodes, func(i, j int) bool {
		if nodes[i].Country != nodes[j].Country {
			return nodes[i].Country < nodes[j].Country
		}
		return nodes[i].Name < nodes[j].Name
	})

	date := time.Now().Format("20060102")
	switch typ {
	case "clash":
		w.Header().Set("Content-Type", "application/yaml; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="proxy2sub-%s.yaml"`, date))
		_, _ = fmt.Fprint(w, BuildClashSub(nodes, s.cfg.TestURL))
	case "v2ray":
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename="proxy2sub-%s.txt"`, date))
		_, _ = fmt.Fprint(w, BuildV2raySub(nodes))
	default:
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "type must be clash or v2ray"})
	}
}

// ---------------------------------------------------------------------------
// 统计 / 健康检查
// ---------------------------------------------------------------------------

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	nodes, err := s.store.All()
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": err.Error()})
		return
	}
	byCountry := map[string]int{}
	byProtocol := map[string]int{}
	for _, n := range nodes {
		byCountry[strings.ToUpper(n.Country)]++
		byProtocol[n.Protocol]++
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"total":      len(nodes),
		"country":    byCountry,
		"protocol":   byProtocol,
		"goroutines": runtime.NumGoroutine(),
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	n, _ := s.store.Count()
	// goroutines（见 #9）：长期运行的健康实例该值稳定在低位，测活 goroutine 泄漏时
	// 线性上涨，可据此提前告警，避免数周后内存耗尽才发现。
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "nodes": n, "goroutines": runtime.NumGoroutine()})
}

// handleCheck 手动触发一轮周期测活（见 #4）。
//
//	POST /api/check                → 同步执行，返回结果
//	POST /api/check?sync=0         → 异步执行，立即 202
//
// 鉴权复用 PushToken（管理员操作）。
func (s *Server) handleCheck(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeJSON(w, http.StatusMethodNotAllowed, map[string]string{"error": "method not allowed"})
		return
	}
	if !s.requireToken(s.cfg.PushToken, r) {
		writeJSON(w, http.StatusUnauthorized, map[string]string{"error": "unauthorized"})
		return
	}
	if r.URL.Query().Get("sync") == "0" {
		go s.safeCheckOnce(context.Background())
		writeJSON(w, http.StatusAccepted, map[string]string{"status": "accepted"})
		return
	}
	// 同步：复用 safeCheckOnce（自带 recover），单节点测活 panic 也不影响整体返回。
	total, alive, dead, skipped := s.safeCheckOnce(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"status":  "ok",
		"total":   total,
		"alive":   alive,
		"dead":    dead,
		"skipped": skipped,
	})
}
