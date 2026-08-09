package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"os"
	"sync"
	"time"

	"github.com/oschwald/maxminddb-golang"
)

// GeoResolver 解析一批 IP 的国家代码。返回 map[ip]国家代码。
type GeoResolver interface {
	Resolve(ips []netip.Addr) map[netip.Addr]string
}

// newGeoResolver 优先使用本地 mmdb（PROXY2SUB_GEOIP_DB 或同目录 Country.mmdb），
// 否则走在线接口 ip-api.com。
func newGeoResolver(dbPath string) (GeoResolver, error) {
	if dbPath == "" {
		if _, err := os.Stat("Country.mmdb"); err == nil {
			dbPath = "Country.mmdb"
		}
	}
	if dbPath != "" {
		r, err := maxminddb.Open(dbPath)
		if err != nil {
			return nil, fmt.Errorf("open geoip db %s: %w", dbPath, err)
		}
		return &mmdbResolver{reader: r}, nil
	}
	return &onlineResolver{
		client: &http.Client{Timeout: 5 * time.Second},
		cache:  make(map[string]string),
	}, nil
}

// ---------------------------------------------------------------------------
// 本地 mmdb
// ---------------------------------------------------------------------------

type mmdbResolver struct {
	reader *maxminddb.Reader
}

func (m *mmdbResolver) Resolve(ips []netip.Addr) map[netip.Addr]string {
	out := make(map[netip.Addr]string, len(ips))
	var rec struct {
		Country struct {
			ISOCode string `maxminddb:"iso_code"`
		} `maxminddb:"country"`
	}
	for _, ip := range ips {
		if !ip.IsValid() || !ip.IsGlobalUnicast() {
			out[ip] = "ZZ"
			continue
		}
		if err := m.reader.Lookup(ip.AsSlice(), &rec); err != nil || rec.Country.ISOCode == "" {
			out[ip] = "ZZ"
			continue
		}
		out[ip] = rec.Country.ISOCode
	}
	return out
}

// ---------------------------------------------------------------------------
// 在线 ip-api.com（批量，免费无 key，100 IP/请求）
// ---------------------------------------------------------------------------

type onlineResolver struct {
	client *http.Client
	mu     sync.Mutex
	cache  map[string]string
}

func (o *onlineResolver) Resolve(ips []netip.Addr) map[netip.Addr]string {
	out := make(map[netip.Addr]string, len(ips))
	var miss []netip.Addr
	o.mu.Lock()
	for _, ip := range ips {
		if !ip.IsValid() || !ip.IsGlobalUnicast() {
			out[ip] = "ZZ"
			continue
		}
		if cc, ok := o.cache[ip.String()]; ok {
			out[ip] = cc
		} else {
			miss = append(miss, ip)
		}
	}
	o.mu.Unlock()

	for i := 0; i < len(miss); i += 100 {
		end := i + 100
		if end > len(miss) {
			end = len(miss)
		}
		o.lookupBatch(miss[i:end], out)
	}
	return out
}

func (o *onlineResolver) lookupBatch(ips []netip.Addr, out map[netip.Addr]string) {
	strs := make([]string, 0, len(ips))
	for _, ip := range ips {
		strs = append(strs, ip.String())
	}
	body, _ := json.Marshal(strs)
	req, err := http.NewRequest(http.MethodPost,
		"http://ip-api.com/batch?fields=status,countryCode,query", bytes.NewReader(body))
	if err != nil {
		return
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := o.client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	var recs []struct {
		Status      string `json:"status"`
		Query       string `json:"query"`
		CountryCode string `json:"countryCode"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&recs); err != nil {
		return
	}
	o.mu.Lock()
	defer o.mu.Unlock()
	for _, r := range recs {
		cc := r.CountryCode
		if r.Status == "fail" || cc == "" {
			cc = "ZZ"
		}
		o.cache[r.Query] = cc
		if ip, err := netip.ParseAddr(r.Query); err == nil {
			out[ip] = cc
		}
	}
}

// helper: 解析域名得到第一个公网 IP。
func resolveIP(host string) net.IP {
	if ip := net.ParseIP(host); ip != nil {
		return ip
	}
	if ips, err := net.LookupIP(host); err == nil {
		for _, ip := range ips {
			if ip.To4() != nil || ip.To16() != nil {
				return ip
			}
		}
	}
	return nil
}
