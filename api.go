package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/netip"
	"runtime/debug"
	"sort"
	"strings"
	"sync"
	"time"
)

// Server 持有配置、存储、地理解析与测活器。
type Server struct {
	cfg        *Config
	store      *Store
	geo        GeoResolver
	tester     *Tester
	httpClient *http.Client
}

// pushItem 一次推送中单条线路的状态。
type pushItem struct {
	link    string
	node    *Node
	status  string // pending / alive / dead / added / duplicate / invalid
	detail  string
	reason  string // dead / unreachable（仅 status=dead 时有意义）
	latency int64
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
	// 使用独立超时 context：即使客户端提前断开，也把测活与入库做完。
	var pending []*pushItem
	for _, it := range items {
		if it.status == "pending" {
			pending = append(pending, it)
		}
	}
	testCtx, cancel := context.WithTimeout(context.Background(), s.cfg.TestTimeout*3+30*time.Second)
	defer cancel()
	s.testConcurrent(testCtx, pending)

	// 地理识别 + 入库
	var addrs []netip.Addr
	for _, it := range pending {
		if it.status == "alive" {
			if a := ipToAddr(it.node.ResolveServerIP()); a.IsValid() {
				addrs = append(addrs, a)
			}
		}
	}
	ccMap := s.geo.Resolve(addrs)
	now := time.Now().Unix()
	for _, it := range pending {
		n := it.node
		if it.status == "alive" {
			resp.Alive++
			if a := ipToAddr(n.IP); a.IsValid() {
				if cc, ok := ccMap[a]; ok {
					n.Country = cc
				}
			}
			if n.Country == "" {
				n.Country = "ZZ"
			}
			n.SetName()
			n.LatencyMS = it.latency
			n.CreatedAt = now
			n.LastCheck = now
			if ierr := s.store.Insert(n); ierr != nil {
				log.Printf("insert %s: %v", n.Name, ierr)
				continue
			}
			resp.Added++
			it.status = "added"
			it.detail = n.Name
		} else {
			resp.Dead++
		}
	}

	if r.URL.Query().Get("detail") == "1" {
		resp.Results = make([]pushResult, 0, len(items))
		for _, it := range items {
			resp.Results = append(resp.Results, pushResult{
				Link: it.link, Status: it.status, Name: it.detail, Detail: it.detail, Reason: it.reason, Latency: it.latency,
			})
		}
	}
	log.Printf("push: received=%d parsed=%d invalid=%d dup=%d alive=%d dead=%d added=%d",
		resp.Received, resp.Parsed, resp.Invalid, resp.Duplicates, resp.Alive, resp.Dead, resp.Added)
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

// testConcurrent 并发测活，结果写入 item.status / item.latency。
func (s *Server) testConcurrent(ctx context.Context, items []*pushItem) {
	if len(items) == 0 {
		return
	}
	sem := make(chan struct{}, s.cfg.Concurrency)
	var wg sync.WaitGroup
	for _, it := range items {
		wg.Add(1)
		sem <- struct{}{}
		go func(it *pushItem) {
			defer wg.Done()
			defer func() { <-sem }()
			defer func() {
				if r := recover(); r != nil {
					// 单节点测活 panic：标记为 dead（保守归 unreachable），
					// 不传染其他节点、不杀整个 checkOnce（见 #4）。
					it.status = "dead"
					it.reason = "unreachable"
					it.detail = fmt.Sprintf("tester panic: %v", r)
					log.Printf("tester panic on %s: %v\n%s", it.node.Name, r, debug.Stack())
				}
			}()
			dur, err := s.tester.Test(ctx, it.node)
			if err != nil {
				it.status = "dead"
				it.reason = classifyTestError(err)
				it.detail = err.Error()
				return
			}
			it.status = "alive"
			it.latency = dur.Milliseconds()
		}(it)
	}
	wg.Wait()
}

// checkOnce 周期测活：失效删除，存活更新结果。
// 返回 total/alive/dead 计数（供 /api/check 同步模式使用）。
func (s *Server) checkOnce(ctx context.Context) (total, alive, deadCount int) {
	nodes, err := s.store.All()
	if err != nil {
		log.Printf("periodic check: load: %v", err)
		return 0, 0, 0
	}
	log.Printf("periodic check: start total=%d", len(nodes))
	if len(nodes) == 0 {
		return 0, 0, 0
	}
	items := make([]*pushItem, 0, len(nodes))
	for _, n := range nodes {
		items = append(items, &pushItem{node: n, status: "pending"})
	}
	s.testConcurrent(ctx, items)

	var addrs []netip.Addr
	for _, it := range items {
		if it.status == "alive" {
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
		if it.status != "alive" {
			dead = append(dead, n.ID)
			continue
		}
		alive++
		n.LatencyMS = it.latency
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
	}
	for _, id := range dead {
		if derr := s.store.Delete(id); derr != nil {
			log.Printf("periodic check: delete %d: %v", id, derr)
		}
	}
	deadCount = len(dead)
	total = len(nodes)
	log.Printf("periodic check: total=%d alive=%d dead=%d", total, alive, deadCount)
	return total, alive, deadCount
}

// safeCheckOnce 包 recover 的 checkOnce，确保单次 panic 不杀死周期 goroutine（见 #4）。
func (s *Server) safeCheckOnce(ctx context.Context) (total, alive, dead int) {
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
		"total":    len(nodes),
		"country":  byCountry,
		"protocol": byProtocol,
	})
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	n, _ := s.store.Count()
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "nodes": n})
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
	total, alive, dead := s.safeCheckOnce(r.Context())
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ok",
		"total":  total,
		"alive":  alive,
		"dead":   dead,
	})
}
