package main

import (
	"bufio"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"
)

// ---------------------------------------------------------------------------
// mock vless tcp+http-obfs 服务器：按 v2ray 服务端语义应答
//   - path 不匹配 → 404 模板（ErrHeaderMisMatch）
//   - uuid 不匹配 → 400 模板（VLESS 认证失败）
//   - 匹配 → 200 模板 + VLESS 响应头 + 隧道内 HTTP 204
// ---------------------------------------------------------------------------

const (
	mockResp400 = "HTTP/1.1 400 Bad Request\r\nConnection: close\r\nCache-Control: private\r\nContent-Length: 0\r\n\r\n"
	mockResp404 = "HTTP/1.1 404 Not Found\r\nConnection: close\r\nCache-Control: private\r\nContent-Length: 0\r\n\r\n"
)

type mockObfsOptions struct {
	expectPath string
	expectUUID [16]byte
	useTLS     bool
}

// startMockObfsServer 启动本地 mock，返回 host:port。
func startMockObfsServer(t *testing.T, o mockObfsOptions) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("mock listen: %v", err)
	}
	var tlsCfg *tls.Config
	if o.useTLS {
		cert := mustSelfSignedCert(t)
		tlsCfg = &tls.Config{Certificates: []tls.Certificate{cert}}
	}
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleMockObfs(conn, o, tlsCfg)
		}
	}()
	t.Cleanup(func() { _ = ln.Close() })
	return ln.Addr().String()
}

func handleMockObfs(conn net.Conn, o mockObfsOptions, tlsCfg *tls.Config) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(5 * time.Second))
	if tlsCfg != nil {
		conn = tls.Server(conn, tlsCfg)
	}
	br := bufio.NewReader(conn)

	line, err := br.ReadString('\n')
	if err != nil {
		return
	}
	path := "/"
	if parts := strings.Fields(line); len(parts) >= 2 {
		if u, perr := url.Parse(parts[1]); perr == nil {
			path = u.Path
		}
	}
	for {
		h, herr := br.ReadString('\n')
		if herr != nil || h == "\r\n" || h == "\n" {
			break
		}
	}
	if path != o.expectPath {
		_, _ = conn.Write([]byte(mockResp404))
		return
	}

	// VLESS 请求头：version(1) + uuid(16) + addonLen(1) + cmd(1) + port(2) + addrType(1)
	head := make([]byte, 22)
	if _, err := io.ReadFull(br, head); err != nil {
		return
	}
	if head[0] != 0x00 {
		_, _ = conn.Write([]byte(mockResp400))
		return
	}
	var gotUUID [16]byte
	copy(gotUUID[:], head[1:17])
	if gotUUID != o.expectUUID {
		_, _ = conn.Write([]byte(mockResp400))
		return
	}
	if n := int(head[17]); n > 0 {
		_, _ = io.CopyN(io.Discard, br, int64(n))
	}
	switch head[21] {
	case 0x01:
		_, _ = io.CopyN(io.Discard, br, 4)
	case 0x02:
		l := make([]byte, 1)
		if _, err := io.ReadFull(br, l); err == nil && l[0] > 0 {
			_, _ = io.CopyN(io.Discard, br, int64(l[0]))
		}
	case 0x03:
		_, _ = io.CopyN(io.Discard, br, 16)
	}

	_, _ = conn.Write([]byte("HTTP/1.1 200 OK\r\nCache-Control: private\r\nConnection: keep-alive\r\nContent-Type: application/octet-stream\r\n\r\n"))
	_, _ = conn.Write([]byte{0x00, 0x00})
	_, _ = conn.Write([]byte("HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n"))
	// 留出时间让客户端读完再关闭
	time.Sleep(300 * time.Millisecond)
}

func mustSelfSignedCert(t *testing.T) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "mock-obfs"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		IPAddresses:  []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:     []string{"localhost"},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("gen cert: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: cert}
}

// newObfsProbeTester 构造指向 mock 的 Tester（测试 URL 指向本地 dump 服务器亦可，
// 探测器仅向远端发请求行，mock 直接回 204，无需真实可达的测活目标）。
func newObfsProbeTester(t *testing.T) *Tester {
	t.Helper()
	tr, err := NewTester(3*time.Second, "http://192.0.2.1/generate_204")
	if err != nil {
		t.Fatalf("new tester: %v", err)
	}
	return tr
}

func obfsTestNode(addr string, uuidHex string) *Node {
	host, port, _ := splitHostPort(addr)
	return &Node{
		Protocol:   "vless",
		Server:     host,
		Port:       port,
		UUID:       uuidHex,
		Network:    "tcp",
		HeaderType: "http",
		Host:       "upay.10010.com",
		Path:       "/jf_tjjf",
	}
}

const testUUID = "0123456789abcdef0123456789abcdef"

// TestProbeVlessHTTPObfsAlive：path/uuid 都匹配 → 测活成功，返回延迟。
func TestProbeVlessHTTPObfsAlive(t *testing.T) {
	uid, err := parseUUID(testUUID)
	if err != nil {
		t.Fatal(err)
	}
	var want [16]byte
	copy(want[:], uid)
	addr := startMockObfsServer(t, mockObfsOptions{expectPath: "/jf_tjjf", expectUUID: want})
	tr := newObfsProbeTester(t)
	dur, terr := tr.Test(context.Background(), obfsTestNode(addr, testUUID))
	if terr != nil {
		t.Fatalf("expected alive, got error: %v", terr)
	}
	if dur <= 0 {
		t.Fatalf("expected positive latency, got %s", dur)
	}
}

// TestProbeVlessHTTPObfsWrongPath：伪装 path 不匹配 → 服务端 404 模板 → 判 dead。
func TestProbeVlessHTTPObfsWrongPath(t *testing.T) {
	uid, _ := parseUUID(testUUID)
	var want [16]byte
	copy(want[:], uid)
	// mock 期望 /other，节点带 /jf_tjjf → 404
	addr := startMockObfsServer(t, mockObfsOptions{expectPath: "/other", expectUUID: want})
	tr := newObfsProbeTester(t)
	_, terr := tr.Test(context.Background(), obfsTestNode(addr, testUUID))
	if terr == nil {
		t.Fatal("expected dead on 404 obfs rejection")
	}
	if !strings.Contains(terr.Error(), "404") {
		t.Fatalf("expected 404 in error, got: %v", terr)
	}
	if reason := classifyTestError(terr); reason != "dead" {
		t.Fatalf("expected reason dead, got %q (%v)", reason, terr)
	}
}

// TestProbeVlessHTTPObfsAuthFail：path 匹配但 uuid 错误 → 服务端 400 模板 → 判 dead。
func TestProbeVlessHTTPObfsAuthFail(t *testing.T) {
	uid, _ := parseUUID(testUUID)
	var want [16]byte
	copy(want[:], uid)
	addr := startMockObfsServer(t, mockObfsOptions{expectPath: "/jf_tjjf", expectUUID: want})
	tr := newObfsProbeTester(t)
	_, terr := tr.Test(context.Background(), obfsTestNode(addr, "ffffffffffffffffffffffffffffffff"))
	if terr == nil {
		t.Fatal("expected dead on auth rejection")
	}
	if !strings.Contains(terr.Error(), "400") {
		t.Fatalf("expected 400 in error, got: %v", terr)
	}
}

// TestProbeVlessHTTPObfsTLS：tcp+tls+http 伪装（TLS 在外层）也能测活。
func TestProbeVlessHTTPObfsTLS(t *testing.T) {
	uid, _ := parseUUID(testUUID)
	var want [16]byte
	copy(want[:], uid)
	addr := startMockObfsServer(t, mockObfsOptions{expectPath: "/jf_tjjf", expectUUID: want, useTLS: true})
	tr := newObfsProbeTester(t)
	n := obfsTestNode(addr, testUUID)
	n.TLS = true
	n.Insecure = true // mock 自签证书
	if _, terr := tr.Test(context.Background(), n); terr != nil {
		t.Fatalf("expected alive over TLS, got error: %v", terr)
	}
}

// TestProbeVlessHTTPObfsBadUUID：非法 uuid 直接报错不拨号。
func TestProbeVlessHTTPObfsBadUUID(t *testing.T) {
	tr := newObfsProbeTester(t)
	n := obfsTestNode("127.0.0.1:1", "not-a-uuid")
	if _, terr := tr.Test(context.Background(), n); terr == nil || !strings.Contains(terr.Error(), "bad uuid") {
		t.Fatalf("expected bad uuid error, got: %v", terr)
	}
}

// TestParseUUID 覆盖带/不带连字符与非法输入。
func TestParseUUID(t *testing.T) {
	b, err := parseUUID("01234567-89ab-cdef-0123-456789abcdef")
	if err != nil || len(b) != 16 {
		t.Fatalf("dashed uuid: %v %v", b, err)
	}
	b2, err := parseUUID("0123456789abcdef0123456789abcdef")
	if err != nil || len(b2) != 16 {
		t.Fatalf("plain uuid: %v %v", b2, err)
	}
	for i := range b {
		if b[i] != b2[i] {
			t.Fatalf("dashed vs plain mismatch")
		}
	}
	if _, err := parseUUID("xyz"); err == nil {
		t.Fatal("expected error for invalid uuid")
	}
}

// TestTesterUnsupportedVmessHTTPObfs（#7）：vmess 的 tcp+http 伪装因协议加密无法
// 独立握手，返回 errUnsupportedTransport（testItem 据此保留节点，不判 dead）。
func TestTesterUnsupportedVmessHTTPObfs(t *testing.T) {
	tr := newObfsProbeTester(t)
	n := &Node{
		Protocol: "vmess", Server: "127.0.0.1", Port: 1,
		UUID: testUUID, Network: "tcp", HeaderType: "http",
	}
	if _, terr := tr.Test(context.Background(), n); !errors.Is(terr, errUnsupportedTransport) {
		t.Fatalf("expected errUnsupportedTransport, got: %v", terr)
	}
}

// ---------------------------------------------------------------------------
// headerType 解析与订阅输出往返（#7）
// ---------------------------------------------------------------------------

// TestParseHeaderTypeVless：联通绿通 vless URI（headerType=http）。
func TestParseHeaderTypeVless(t *testing.T) {
	raw := "vless://01234567-89ab-cdef-0123-456789abcdef@47.92.247.66:5005?security=none&encryption=none&host=upay.10010.com&headerType=http&type=tcp&path=%2Fjf_tjjf#unicom-green"
	n := mustParse(t, raw)
	if n.HeaderType != "http" || n.Network != "tcp" || n.Host != "upay.10010.com" || n.Path != "/jf_tjjf" {
		t.Fatalf("bad headerType node: %+v", n)
	}
	// 订阅输出完整往返
	n2 := mustParse(t, n.ToURI())
	if n2.HeaderType != "http" || n2.Host != n.Host || n2.Path != n.Path {
		t.Fatalf("ToURI lost headerType: %s -> %+v", n.ToURI(), n2)
	}
}

// TestParseHeaderTypeVmessJSON：vmess base64 JSON 中 net=tcp + type=http。
func TestParseHeaderTypeVmessJSON(t *testing.T) {
	v := map[string]string{
		"v": "2", "ps": "green", "add": "47.92.247.66", "port": "12345",
		"id": "uuid-1", "aid": "0", "net": "tcp", "type": "http",
		"host": "upay.10010.com", "path": "/jf_tjjf", "tls": "",
	}
	b, _ := json.Marshal(v)
	n := mustParse(t, "vmess://"+base64.StdEncoding.EncodeToString(b))
	if n.HeaderType != "http" || n.Network != "tcp" {
		t.Fatalf("bad vmess headerType: %+v", n)
	}
	// ws 节点的 type 应为 none，不误标 headerType
	v["net"], v["type"] = "ws", "none"
	b2, _ := json.Marshal(v)
	n2 := mustParse(t, "vmess://"+base64.StdEncoding.EncodeToString(b2))
	if n2.HeaderType != "" {
		t.Fatalf("ws node should not carry headerType: %+v", n2)
	}
}

// TestParseHeaderTypeVmessLegacy：vmess 旧格式 query 中的 headerType。
func TestParseHeaderTypeVmessLegacy(t *testing.T) {
	n := mustParse(t, "vmess://uuid-1:0@1.2.3.4:12345?type=tcp&headerType=http&host=upay.10010.com&path=%2Fjf_tjjf#x")
	if n.HeaderType != "http" {
		t.Fatalf("bad legacy headerType: %+v", n)
	}
}

// TestClashHTTPObfsOutput（#7）：Clash 订阅用 network: http + http-opts 表达 tcp+HTTP 伪装。
func TestClashHTTPObfsOutput(t *testing.T) {
	n := &Node{
		Protocol: "vless", Server: "47.92.247.66", Port: 5005,
		UUID: "uuid-x", Network: "tcp", HeaderType: "http",
		Host: "upay.10010.com", Path: "/jf_tjjf", Name: "ZZ_47.92.247.66",
	}
	yamlOut := BuildClashSub([]*Node{n}, "http://www.gstatic.com/generate_204")
	for _, want := range []string{"network: http", "http-opts:", "path:", "/jf_tjjf", "Host:", "upay.10010.com"} {
		if !strings.Contains(yamlOut, want) {
			t.Fatalf("clash output missing %q:\n%s", want, yamlOut)
		}
	}
	// 输出的 YAML 必须可被标准解析器解析（结构合法）
	var v map[string]any
	if err := yaml.Unmarshal([]byte(yamlOut), &v); err != nil {
		t.Fatalf("invalid yaml: %v\n%s", err, yamlOut)
	}
}

// TestHealthAndStatsExposeGoroutines（#9 可观测性）：goroutine 数随健康检查暴露。
func TestHealthAndStatsExposeGoroutines(t *testing.T) {
	srv, _, _ := newTestServer(t)

	w := httptest.NewRecorder()
	srv.handleHealth(w, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("healthz: got %d", w.Code)
	}
	var health struct {
		OK         bool `json:"ok"`
		Goroutines int  `json:"goroutines"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &health); err != nil || !health.OK || health.Goroutines <= 0 {
		t.Fatalf("healthz body: %s (err=%v)", w.Body.String(), err)
	}

	w2 := httptest.NewRecorder()
	srv.handleStats(w2, httptest.NewRequest(http.MethodGet, "/api/stats", nil))
	var stats struct {
		Goroutines int `json:"goroutines"`
	}
	if err := json.Unmarshal(w2.Body.Bytes(), &stats); err != nil || stats.Goroutines <= 0 {
		t.Fatalf("stats body: %s (err=%v)", w2.Body.String(), err)
	}
}
