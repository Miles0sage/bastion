package main

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/acme/autocert"
)

// Bastion — Personal Edge Platform
// One binary. Zero config. Zero bills.
//
// Phase 1: Reverse proxy + auto SSL + dashboard
// Phase 2: WireGuard tunneling
// Phase 3: AI WAF (IsolationForest)
// Phase 4: Auth (OIDC/MFA)

const version = "0.1.0"

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "version":
			fmt.Printf("bastion v%s\n", version)
			return
		case "init":
			initConfig()
			return
		case "up":
			startBastion()
			return
		default:
			fmt.Printf("bastion v%s\n", version)
			fmt.Println("Usage: bastion [init|up|version]")
			return
		}
	}
	fmt.Printf("bastion v%s — Personal Edge Platform\n", version)
	fmt.Println("Usage: bastion [init|up|version]")
}

// Config represents the bastion configuration
type Config struct {
	Domain    string          `json:"domain"`
	Email     string          `json:"email"`
	Services  []ServiceConfig `json:"services"`
	Dashboard DashboardConfig `json:"dashboard"`
	TLS       TLSConfig       `json:"tls"`
}

type ServiceConfig struct {
	Name      string `json:"name"`
	Subdomain string `json:"subdomain"`
	Target    string `json:"target"`
	Health    string `json:"health,omitempty"`
}

type DashboardConfig struct {
	Port     int    `json:"port"`
	Password string `json:"password"`
}

type TLSConfig struct {
	Enabled  bool   `json:"enabled"`
	CertDir  string `json:"cert_dir"`
}

func defaultConfig() Config {
	return Config{
		Domain: "example.com",
		Email:  "you@example.com",
		Services: []ServiceConfig{
			{
				Name:      "app",
				Subdomain: "app",
				Target:    "http://localhost:3000",
			},
		},
		Dashboard: DashboardConfig{
			Port:     9090,
			Password: "changeme",
		},
		TLS: TLSConfig{
			Enabled: true,
			CertDir: ".bastion-certs",
		},
	}
}

func initConfig() {
	if _, err := os.Stat("bastion.json"); err == nil {
		fmt.Println("bastion.json already exists")
		return
	}
	cfg := defaultConfig()
	data, _ := json.MarshalIndent(cfg, "", "  ")
	os.WriteFile("bastion.json", data, 0644)
	fmt.Println("Created bastion.json — edit it with your domain and services")
}

func loadConfig() (Config, error) {
	data, err := os.ReadFile("bastion.json")
	if err != nil {
		return Config{}, fmt.Errorf("no bastion.json found — run 'bastion init' first")
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("invalid bastion.json: %w", err)
	}
	return cfg, nil
}

// ──────────────────────────────────────────────
// Reverse Proxy
// ──────────────────────────────────────────────

type ReverseProxy struct {
	services []ServiceConfig
	metrics  *MetricsCollector
}

func NewReverseProxy(services []ServiceConfig, metrics *MetricsCollector) *ReverseProxy {
	return &ReverseProxy{services: services, metrics: metrics}
}

func (rp *ReverseProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	host := r.Host

	for _, svc := range rp.services {
		expected := svc.Subdomain + "." + loadedConfig.Domain
		if host == expected {
			rp.metrics.Record(svc.Name, r, time.Since(start))
			proxyTo(w, r, svc.Target)
			return
		}
	}

	// No matching service
	http.Error(w, "not found", http.StatusNotFound)
}

func proxyTo(w http.ResponseWriter, r *http.Request, target string) {
	// Simple reverse proxy using stdlib
	client := &http.Client{Timeout: 30 * time.Second}

	proxyURL := target + r.URL.Path
	if r.URL.RawQuery != "" {
		proxyURL += "?" + r.URL.RawQuery
	}

	proxyReq, err := http.NewRequest(r.Method, proxyURL, r.Body)
	if err != nil {
		http.Error(w, "proxy error", http.StatusBadGateway)
		return
	}

	// Copy headers
	for key, values := range r.Header {
		for _, v := range values {
			proxyReq.Header.Add(key, v)
		}
	}
	proxyReq.Header.Set("X-Forwarded-For", r.RemoteAddr)
	proxyReq.Header.Set("X-Forwarded-Host", r.Host)

	resp, err := client.Do(proxyReq)
	if err != nil {
		http.Error(w, "upstream unavailable", http.StatusBadGateway)
		return
	}
	defer resp.Body.Close()

	// Copy response headers
	for key, values := range resp.Header {
		for _, v := range values {
			w.Header().Add(key, v)
		}
	}
	w.WriteHeader(resp.StatusCode)

	buf := make([]byte, 32*1024)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			w.Write(buf[:n])
		}
		if err != nil {
			break
		}
	}
}

// ──────────────────────────────────────────────
// Metrics Collector (feeds AI WAF later)
// ──────────────────────────────────────────────

type RequestMetric struct {
	Service    string    `json:"service"`
	Method     string    `json:"method"`
	Path       string    `json:"path"`
	StatusCode int       `json:"status_code"`
	Duration   float64   `json:"duration_ms"`
	IP         string    `json:"ip"`
	Timestamp  time.Time `json:"timestamp"`
}

type MetricsCollector struct {
	mu       sync.Mutex
	requests []RequestMetric
	totals   map[string]int64
}

func NewMetricsCollector() *MetricsCollector {
	return &MetricsCollector{
		requests: make([]RequestMetric, 0, 10000),
		totals:   make(map[string]int64),
	}
}

func (mc *MetricsCollector) Record(service string, r *http.Request, duration time.Duration) {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	metric := RequestMetric{
		Service:   service,
		Method:    r.Method,
		Path:      r.URL.Path,
		IP:        r.RemoteAddr,
		Duration:  float64(duration.Milliseconds()),
		Timestamp: time.Now(),
	}

	mc.requests = append(mc.requests, metric)
	mc.totals[service]++

	// Keep last 10K requests in memory (ring buffer style)
	if len(mc.requests) > 10000 {
		mc.requests = mc.requests[5000:]
	}
}

func (mc *MetricsCollector) GetStats() map[string]interface{} {
	mc.mu.Lock()
	defer mc.mu.Unlock()

	stats := map[string]interface{}{
		"total_requests":  len(mc.requests),
		"services":        mc.totals,
		"uptime":          time.Since(startTime).String(),
		"version":         version,
	}
	return stats
}

// ──────────────────────────────────────────────
// Dashboard API
// ──────────────────────────────────────────────

func dashboardHandler(metrics *MetricsCollector, cfg Config) http.Handler {
	mux := http.NewServeMux()

	// API endpoints
	mux.HandleFunc("/api/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(metrics.GetStats())
	})

	mux.HandleFunc("/api/services", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(cfg.Services)
	})

	mux.HandleFunc("/api/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		health := checkHealth(cfg.Services)
		json.NewEncoder(w).Encode(health)
	})

	// Dashboard UI
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(dashboardHTML))
	})

	return mux
}

func checkHealth(services []ServiceConfig) []map[string]interface{} {
	results := make([]map[string]interface{}, 0)
	client := &http.Client{Timeout: 5 * time.Second}

	for _, svc := range services {
		target := svc.Target
		if svc.Health != "" {
			target = svc.Health
		}

		start := time.Now()
		resp, err := client.Get(target)
		latency := time.Since(start)

		status := "down"
		statusCode := 0
		if err == nil {
			resp.Body.Close()
			statusCode = resp.StatusCode
			if statusCode < 500 {
				status = "up"
			}
		}

		results = append(results, map[string]interface{}{
			"name":       svc.Name,
			"status":     status,
			"latency_ms": latency.Milliseconds(),
			"code":       statusCode,
		})
	}
	return results
}

// Embedded dashboard HTML — single page, no build step
const dashboardHTML = `<!DOCTYPE html>
<html>
<head>
<title>Bastion — Personal Edge</title>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, system-ui, sans-serif; background: #0a0a0a; color: #e0e0e0; padding: 2rem; }
h1 { font-size: 1.5rem; margin-bottom: 0.5rem; color: #fff; }
.subtitle { color: #666; margin-bottom: 2rem; font-size: 0.9rem; }
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
.card { background: #141414; border: 1px solid #222; border-radius: 8px; padding: 1.5rem; }
.card h3 { font-size: 0.8rem; color: #888; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.5rem; }
.card .value { font-size: 2rem; font-weight: 700; color: #fff; }
.card .value.green { color: #22c55e; }
.service { display: flex; justify-content: space-between; align-items: center; padding: 0.75rem 0; border-bottom: 1px solid #1a1a1a; }
.service:last-child { border: none; }
.dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; margin-right: 8px; }
.dot.up { background: #22c55e; }
.dot.down { background: #ef4444; }
.latency { color: #666; font-size: 0.85rem; }
footer { margin-top: 2rem; color: #333; font-size: 0.8rem; text-align: center; }
</style>
</head>
<body>
<h1>Bastion</h1>
<p class="subtitle">Personal Edge Platform</p>
<div class="grid">
  <div class="card"><h3>Total Requests</h3><div class="value" id="total">—</div></div>
  <div class="card"><h3>Uptime</h3><div class="value green" id="uptime">—</div></div>
  <div class="card"><h3>Version</h3><div class="value" id="version">—</div></div>
</div>
<div class="card">
  <h3>Services</h3>
  <div id="services">Loading...</div>
</div>
<footer>bastion v0.1.0 — zero config, zero bills</footer>
<script>
async function refresh() {
  try {
    const stats = await (await fetch('/api/stats')).json();
    document.getElementById('total').textContent = stats.total_requests;
    document.getElementById('uptime').textContent = stats.uptime;
    document.getElementById('version').textContent = 'v' + stats.version;
    const health = await (await fetch('/api/health')).json();
    const el = document.getElementById('services');
    el.innerHTML = health.map(s =>
      '<div class="service">' +
        '<span><span class="dot ' + s.status + '"></span>' + s.name + '</span>' +
        '<span class="latency">' + s.latency_ms + 'ms</span>' +
      '</div>'
    ).join('');
  } catch(e) { console.error(e); }
}
refresh();
setInterval(refresh, 5000);
</script>
</body>
</html>`

// ──────────────────────────────────────────────
// Start Bastion
// ──────────────────────────────────────────────

var (
	startTime    time.Time
	loadedConfig Config
)

func startBastion() {
	cfg, err := loadConfig()
	if err != nil {
		log.Fatal(err)
	}
	loadedConfig = cfg
	startTime = time.Now()

	metrics := NewMetricsCollector()
	proxy := NewReverseProxy(cfg.Services, metrics)

	// Start dashboard
	go func() {
		addr := fmt.Sprintf(":%d", cfg.Dashboard.Port)
		log.Printf("Dashboard: http://localhost%s", addr)
		if err := http.ListenAndServe(addr, dashboardHandler(metrics, cfg)); err != nil {
			log.Fatal(err)
		}
	}()

	// Start reverse proxy
	log.Printf("Bastion v%s starting", version)
	log.Printf("Domain: %s", cfg.Domain)
	log.Printf("Services: %d", len(cfg.Services))
	for _, svc := range cfg.Services {
		log.Printf("  %s.%s → %s", svc.Subdomain, cfg.Domain, svc.Target)
	}

	if cfg.TLS.Enabled {
		startWithTLS(cfg, proxy)
	} else {
		log.Printf("Proxy listening on :80 (no TLS)")
		if err := http.ListenAndServe(":80", proxy); err != nil {
			log.Fatal(err)
		}
	}
}

func startWithTLS(cfg Config, handler http.Handler) {
	// Build list of allowed hostnames
	var hosts []string
	for _, svc := range cfg.Services {
		hosts = append(hosts, svc.Subdomain+"."+cfg.Domain)
	}
	hosts = append(hosts, cfg.Domain)

	certDir := cfg.TLS.CertDir
	if certDir == "" {
		certDir = ".bastion-certs"
	}

	manager := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		Email:      cfg.Email,
		Cache:      autocert.DirCache(certDir),
		HostPolicy: autocert.HostWhitelist(hosts...),
	}

	// HTTP server for ACME challenges + redirect to HTTPS
	go func() {
		httpHandler := manager.HTTPHandler(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			target := "https://" + r.Host + r.URL.RequestURI()
			http.Redirect(w, r, target, http.StatusMovedPermanently)
		}))
		log.Printf("HTTP→HTTPS redirect on :80")
		if err := http.ListenAndServe(":80", httpHandler); err != nil {
			log.Fatal(err)
		}
	}()

	// HTTPS server with auto-provisioned certs
	tlsConfig := &tls.Config{
		GetCertificate: manager.GetCertificate,
		MinVersion:     tls.VersionTLS12,
	}

	server := &http.Server{
		Addr:      ":443",
		Handler:   handler,
		TLSConfig: tlsConfig,
	}

	log.Printf("Proxy listening on :443 (auto-TLS)")
	log.Printf("Hosts: %s", strings.Join(hosts, ", "))
	if err := server.ListenAndServeTLS("", ""); err != nil {
		log.Fatal(err)
	}
}

