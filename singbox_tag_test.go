//go:build with_utls && with_quic

package main

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
)

// TestBuildTagsCompiled 是 issue #1 的回归测试：
// 验证 with_utls / with_quic 已编译进二进制。
// 若构建漏带 -tags "with_utls with_quic"，Reality（依赖 uTLS）与
// Hysteria/Hysteria2（依赖 QUIC）会在 box.New 阶段报
// "not included in this build"，导致节点测活全部误判 dead。
//
// 本测试用 build tag 隔离，仅在带 tag 时运行；
// release workflow 始终带 tag，因此 CI 会执行此测试。
// TestHysteria2PinSHA256InConfig 是 issue #2 的回归测试：
// 带 pinSHA256 的 Hysteria2 节点生成的 sing-box 配置必须包含
// certificate_public_key_sha256（base64 编码的 32 字节摘要），
// 否则 sing-box 会按系统 CA 校验自签证书，导致节点全部误判 dead。
func TestHysteria2PinSHA256InConfig(t *testing.T) {
	pin := "d2fb4f1b833ee7e77e8304dc4652eb13e1b0e064e0874cde3a1a1a1660b74eef"
	node := &Node{
		Protocol:  "hysteria2",
		Server:    "208.87.242.105",
		Port:      50000,
		Password:  "4e562fc8-abcd-1234-5678-abcdef012345",
		SNI:       "www.bing.com",
		PinSHA256: pin,
		TLS:       true,
	}

	m := singboxOutbound(node)
	tls, ok := m["tls"].(map[string]any)
	if !ok {
		t.Fatalf("tls block missing: %+v", m)
	}
	pins, ok := tls["certificate_public_key_sha256"].([]string)
	if !ok || len(pins) != 1 {
		t.Fatalf("certificate_public_key_sha256 missing/wrong type: %#v", tls["certificate_public_key_sha256"])
	}
	raw, err := base64.StdEncoding.DecodeString(pins[0])
	if err != nil || len(raw) != 32 {
		t.Fatalf("pin not base64 of 32 bytes: %q err=%v len=%d", pins[0], err, len(raw))
	}
	if hex.EncodeToString(raw) != pin {
		t.Fatalf("pin value mismatch: got %x want %s", raw, pin)
	}
	// 带 pin 时不应同时 insecure:true（让 sing-box 走 pin 校验路径，更安全）
	if tls["insecure"] == true {
		t.Fatalf("insecure should not be set when pinSHA256 present: %+v", tls)
	}

	// 整体配置能被 sing-box 接受（不会因 pin 字段导致解析失败）
	ctx := context.Background()
	bctx := box.Context(ctx,
		include.InboundRegistry(), include.OutboundRegistry(),
		include.EndpointRegistry(), include.DNSTransportRegistry(),
		include.ServiceRegistry())
	opts, err := singboxOptions(bctx, node)
	if err != nil {
		t.Fatalf("singboxOptions: %v", err)
	}
	if _, err := box.New(box.Options{Context: bctx, Options: opts}); err != nil {
		t.Fatalf("box.New with pinSHA256: %v", err)
	}
}

func TestBuildTagsCompiled(t *testing.T) {
	cases := []struct {
		name string
		node *Node
	}{
		{
			name: "reality(vless)",
			node: &Node{
				Protocol: "vless", Server: "127.0.0.1", Port: 443,
				UUID:      "00000000-0000-0000-0000-000000000000",
				TLS:       true,
				RealityPK: "pubkey", RealitySID: "sid",
				Network: "tcp",
			},
		},
		{
			name: "hysteria2",
			node: &Node{
				Protocol: "hysteria2", Server: "127.0.0.1", Port: 443,
				Password: "pass", TLS: true,
			},
		},
		{
			name: "hysteria-v1",
			node: &Node{
				Protocol: "hysteria", Server: "127.0.0.1", Port: 443,
				Password: "auth", TLS: true,
			},
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ctx := context.Background()
			bctx := box.Context(ctx,
				include.InboundRegistry(), include.OutboundRegistry(),
				include.EndpointRegistry(), include.DNSTransportRegistry(),
				include.ServiceRegistry())
			opts, err := singboxOptions(bctx, c.node)
			if err != nil {
				t.Fatalf("singboxOptions: %v", err)
			}
			_, err = box.New(box.Options{Context: bctx, Options: opts})
			if err != nil && strings.Contains(err.Error(), "not included in this build") {
				t.Fatalf("缺少编译 tag: %v\n请用 -tags \"with_utls with_quic\" 构建", err)
			}
			// 其他错误（如参数校验）可接受，关键是没报 "not included"
		})
	}
}
