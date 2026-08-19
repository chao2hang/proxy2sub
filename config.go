package main

import (
	"os"
	"strconv"
	"time"
)

// Config 从环境变量读取配置，未设置时使用默认值。
type Config struct {
	Addr            string        // HTTP 监听地址
	DBPath          string        // SQLite 数据库文件
	PushToken       string        // 推送接口鉴权 token（为空则不鉴权）
	SubToken        string        // 订阅接口鉴权 token（为空则不鉴权）
	CheckInterval   time.Duration // 周期测活间隔
	CheckOnStart    bool          // 启动时是否立即跑一轮测活
	TestTimeout     time.Duration // 单节点测活超时
	TestURL         string        // 测活目标（经代理访问）
	Concurrency     int           // 测活并发数
	MaxDeadRatioPct int           // 单轮 dead/total 比例熔断阈值（0=禁用，默认 50，见 #6）
	GeoIPDB         string        // 本地 mmdb 文件路径（可选，缺省走在线接口）
}

func loadConfig() *Config {
	return &Config{
		Addr:            envStr("PROXY2SUB_ADDR", ":8080"),
		DBPath:          envStr("PROXY2SUB_DB", "proxy2sub.db"),
		PushToken:       os.Getenv("PROXY2SUB_PUSH_TOKEN"),
		SubToken:        os.Getenv("PROXY2SUB_SUB_TOKEN"),
		CheckInterval:   envDur("PROXY2SUB_CHECK_INTERVAL", 10*time.Minute),
		CheckOnStart:    envBool("PROXY2SUB_CHECK_ON_START", false),
		TestTimeout:     envDur("PROXY2SUB_TEST_TIMEOUT", 8*time.Second),
		TestURL:         envStr("PROXY2SUB_TEST_URL", "http://www.gstatic.com/generate_204"),
		Concurrency:     envInt("PROXY2SUB_CONCURRENCY", 20),
		MaxDeadRatioPct: envInt("PROXY2SUB_MAX_DEAD_RATIO", 50),
		GeoIPDB:         os.Getenv("PROXY2SUB_GEOIP_DB"),
	}
}

func envStr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			return n
		}
	}
	return def
}

func envBool(key string, def bool) bool {
	if v := os.Getenv(key); v != "" {
		if b, err := strconv.ParseBool(v); err == nil {
			return b
		}
	}
	return def
}

func envDur(key string, def time.Duration) time.Duration {
	if v := os.Getenv(key); v != "" {
		if d, err := time.ParseDuration(v); err == nil {
			return d
		}
	}
	return def
}
