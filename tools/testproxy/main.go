// testproxy 是一个用于本地验证的极简 HTTP CONNECT 代理。
// 用法: go run ./tools/testproxy [port]
package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
)

func main() {
	port := "18080"
	if len(os.Args) > 1 {
		port = os.Args[1]
	}
	server := &http.Server{Addr: "127.0.0.1:" + port, Handler: http.HandlerFunc(handle)}
	log.Printf("test http proxy listening on 127.0.0.1:%s", port)
	log.Fatal(server.ListenAndServe())
}

func handle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodConnect {
		http.Error(w, "only CONNECT supported", http.StatusMethodNotAllowed)
		return
	}
	upstream, err := net.Dial("tcp", r.Host)
	if err != nil {
		http.Error(w, "upstream dial failed", http.StatusBadGateway)
		return
	}
	hj, ok := w.(http.Hijacker)
	if !ok {
		upstream.Close()
		http.Error(w, "hijack unsupported", http.StatusInternalServerError)
		return
	}
	client, _, err := hj.Hijack()
	if err != nil {
		upstream.Close()
		return
	}
	_, _ = fmt.Fprint(client, "HTTP/1.1 200 Connection Established\r\n\r\n")
	go func() {
		_, _ = io.Copy(upstream, client)
		_ = upstream.Close()
		_ = client.Close()
	}()
	_, _ = io.Copy(client, upstream)
	_ = client.Close()
	_ = upstream.Close()
}
