//go:build with_utls && with_quic

package main

import (
	"context"
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
