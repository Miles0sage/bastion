package main

import (
	"crypto/rand"
	"crypto/tls"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/Miles0sage/bastion/waf"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

// Bastion — Personal Edge Platform
// One binary. Zero config. Zero bills.
//
// Phase 1: Reverse proxy + auto SSL + dashboard
// Phase 2: WireGuard tunneling
// Phase 3: AI WAF (IsolationForest)
// Phase 4: Auth (OIDC/MFA)

const version = "0.2.0"

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
// SQLite Request Logger
// ──────────────────────────────────────────────

type RequestDB struct {
	db *sql.DB
	mu sync.Mutex
}

// DB returns the underlying *sql.DB for shared use (e.g., WAF).
func (rdb *RequestDB) DB() *sql.DB {
	return rdb.db
}

func NewRequestDB(path string) (*RequestDB, error) {
	db, err := sql.Open("sqlite", path+"?_journal_mode=WAL&_busy_timeout=5000")
	if err != nil {
		return nil, fmt.Errorf("failed to open sqlite: %w", err)
	}

	// Create tables
	schema := `
	CREATE TABLE IF NOT EXISTS requests (
		id INTEGER PRIMARY KEY,
		timestamp TEXT NOT NULL,
		service TEXT NOT NULL,
		method TEXT NOT NULL,
		path TEXT NOT NULL,
		ip TEXT NOT NULL,
		status_code INTEGER NOT NULL,
		duration_ms REAL NOT NULL,
		user_agent TEXT NOT NULL DEFAULT ''
	);
	CREATE INDEX IF NOT EXISTS idx_requests_timestamp ON requests(timestamp);
	CREATE INDEX IF NOT EXISTS idx_requests_ip ON requests(ip);
	CREATE INDEX IF NOT EXISTS idx_requests_service ON requests(service);

	CREATE TABLE IF NOT EXISTS blocked_ips (
		ip TEXT PRIMARY KEY,
		reason TEXT NOT NULL DEFAULT '',
		blocked_at TEXT NOT NULL
	);
	`
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("failed to create schema: %w", err)
	}

	return &RequestDB{db: db}, nil
}

func (rdb *RequestDB) LogRequest(service, method, path, ip string, statusCode int, durationMs float64, userAgent string) {
	rdb.mu.Lock()
	defer rdb.mu.Unlock()

	_, err := rdb.db.Exec(
		`INSERT INTO requests (timestamp, service, method, path, ip, status_code, duration_ms, user_agent)
		 VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
		time.Now().UTC().Format(time.RFC3339),
		service, method, path, ip, statusCode, durationMs, userAgent,
	)
	if err != nil {
		log.Printf("Failed to log request: %v", err)
	}
}

func (rdb *RequestDB) RecentRequests(limit int) []map[string]interface{} {
	rows, err := rdb.db.Query(
		`SELECT timestamp, service, method, path, ip, status_code, duration_ms, user_agent
		 FROM requests ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		log.Printf("RecentRequests query error: %v", err)
		return nil
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var ts, svc, method, path, ip, ua string
		var code int
		var dur float64
		if err := rows.Scan(&ts, &svc, &method, &path, &ip, &code, &dur, &ua); err != nil {
			continue
		}
		results = append(results, map[string]interface{}{
			"timestamp":   ts,
			"service":     svc,
			"method":      method,
			"path":        path,
			"ip":          ip,
			"status_code": code,
			"duration_ms": dur,
			"user_agent":  ua,
		})
	}
	return results
}

func (rdb *RequestDB) TopIPs(limit int) []map[string]interface{} {
	rows, err := rdb.db.Query(
		`SELECT ip, COUNT(*) as cnt FROM requests GROUP BY ip ORDER BY cnt DESC LIMIT ?`, limit)
	if err != nil {
		log.Printf("TopIPs query error: %v", err)
		return nil
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var ip string
		var cnt int
		if err := rows.Scan(&ip, &cnt); err != nil {
			continue
		}
		results = append(results, map[string]interface{}{
			"ip":    ip,
			"count": cnt,
		})
	}
	return results
}

func (rdb *RequestDB) RequestsPerMinute(minutes int) []map[string]interface{} {
	since := time.Now().UTC().Add(-time.Duration(minutes) * time.Minute).Format(time.RFC3339)
	rows, err := rdb.db.Query(
		`SELECT strftime('%Y-%m-%dT%H:%M:00Z', timestamp) as minute, COUNT(*) as cnt
		 FROM requests WHERE timestamp >= ? GROUP BY minute ORDER BY minute`, since)
	if err != nil {
		log.Printf("RequestsPerMinute query error: %v", err)
		return nil
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var minute string
		var cnt int
		if err := rows.Scan(&minute, &cnt); err != nil {
			continue
		}
		results = append(results, map[string]interface{}{
			"minute": minute,
			"count":  cnt,
		})
	}
	return results
}

func (rdb *RequestDB) ServiceCounts() map[string]int {
	rows, err := rdb.db.Query(`SELECT service, COUNT(*) as cnt FROM requests GROUP BY service ORDER BY cnt DESC`)
	if err != nil {
		log.Printf("ServiceCounts query error: %v", err)
		return nil
	}
	defer rows.Close()

	results := make(map[string]int)
	for rows.Next() {
		var svc string
		var cnt int
		if err := rows.Scan(&svc, &cnt); err != nil {
			continue
		}
		results[svc] = cnt
	}
	return results
}

// ──────────────────────────────────────────────
// IP Blocklist (SQLite-backed)
// ──────────────────────────────────────────────

func (rdb *RequestDB) BlockIP(ip, reason string) error {
	_, err := rdb.db.Exec(
		`INSERT OR REPLACE INTO blocked_ips (ip, reason, blocked_at) VALUES (?, ?, ?)`,
		ip, reason, time.Now().UTC().Format(time.RFC3339))
	return err
}

func (rdb *RequestDB) UnblockIP(ip string) error {
	_, err := rdb.db.Exec(`DELETE FROM blocked_ips WHERE ip = ?`, ip)
	return err
}

func (rdb *RequestDB) IsBlocked(ip string) bool {
	var count int
	err := rdb.db.QueryRow(`SELECT COUNT(*) FROM blocked_ips WHERE ip = ?`, ip).Scan(&count)
	if err != nil {
		return false
	}
	return count > 0
}

func (rdb *RequestDB) BlockedIPs() []map[string]interface{} {
	rows, err := rdb.db.Query(`SELECT ip, reason, blocked_at FROM blocked_ips ORDER BY blocked_at DESC`)
	if err != nil {
		return nil
	}
	defer rows.Close()

	var results []map[string]interface{}
	for rows.Next() {
		var ip, reason, blockedAt string
		if err := rows.Scan(&ip, &reason, &blockedAt); err != nil {
			continue
		}
		results = append(results, map[string]interface{}{
			"ip":         ip,
			"reason":     reason,
			"blocked_at": blockedAt,
		})
	}
	return results
}

// ──────────────────────────────────────────────
// Rate Limiter — Per-IP, 100 req/min
// ──────────────────────────────────────────────

type RateLimiter struct {
	mu       sync.Mutex
	requests map[string][]time.Time
	limit    int
	window   time.Duration
}

func NewRateLimiter(limit int, window time.Duration) *RateLimiter {
	rl := &RateLimiter{
		requests: make(map[string][]time.Time),
		limit:    limit,
		window:   window,
	}
	// Cleanup stale entries every 5 minutes
	go func() {
		for {
			time.Sleep(5 * time.Minute)
			rl.cleanup()
		}
	}()
	return rl
}

func (rl *RateLimiter) Allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-rl.window)

	// Filter out old timestamps
	timestamps := rl.requests[ip]
	filtered := timestamps[:0]
	for _, t := range timestamps {
		if t.After(cutoff) {
			filtered = append(filtered, t)
		}
	}

	if len(filtered) >= rl.limit {
		rl.requests[ip] = filtered
		return false
	}

	rl.requests[ip] = append(filtered, now)
	return true
}

func (rl *RateLimiter) cleanup() {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	cutoff := time.Now().Add(-rl.window)
	for ip, timestamps := range rl.requests {
		filtered := timestamps[:0]
		for _, t := range timestamps {
			if t.After(cutoff) {
				filtered = append(filtered, t)
			}
		}
		if len(filtered) == 0 {
			delete(rl.requests, ip)
		} else {
			rl.requests[ip] = filtered
		}
	}
}

func (rl *RateLimiter) RateLimitedCount() int {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	count := 0
	cutoff := time.Now().Add(-rl.window)
	for _, timestamps := range rl.requests {
		active := 0
		for _, t := range timestamps {
			if t.After(cutoff) {
				active++
			}
		}
		if active >= rl.limit {
			count++
		}
	}
	return count
}

func extractIP(r *http.Request) string {
	// Check X-Forwarded-For first (behind proxy)
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.SplitN(xff, ",", 2)
		return strings.TrimSpace(parts[0])
	}
	// Strip port from RemoteAddr
	ip := r.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}
	return ip
}

// ──────────────────────────────────────────────
// Reverse Proxy
// ──────────────────────────────────────────────

type ReverseProxy struct {
	services    []ServiceConfig
	metrics     *MetricsCollector
	rateLimiter *RateLimiter
	reqDB       *RequestDB
}

func NewReverseProxy(services []ServiceConfig, metrics *MetricsCollector, rl *RateLimiter, reqDB *RequestDB) *ReverseProxy {
	return &ReverseProxy{
		services:    services,
		metrics:     metrics,
		rateLimiter: rl,
		reqDB:       reqDB,
	}
}

func (rp *ReverseProxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	start := time.Now()
	ip := extractIP(r)

	// Check IP blocklist
	if rp.reqDB.IsBlocked(ip) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}

	// Rate limit check
	if !rp.rateLimiter.Allow(ip) {
		http.Error(w, "rate limit exceeded", http.StatusTooManyRequests)
		return
	}

	host := r.Host

	for _, svc := range rp.services {
		expected := svc.Subdomain + "." + loadedConfig.Domain
		if host == expected {
			statusCode := proxyTo(w, r, svc.Target)
			duration := time.Since(start)
			rp.metrics.Record(svc.Name, r, duration)
			rp.reqDB.LogRequest(svc.Name, r.Method, r.URL.Path, ip, statusCode, float64(duration.Milliseconds()), r.UserAgent())
			return
		}
	}

	// No matching service
	http.Error(w, "not found", http.StatusNotFound)
}

func proxyTo(w http.ResponseWriter, r *http.Request, target string) int {
	// Simple reverse proxy using stdlib
	client := &http.Client{Timeout: 30 * time.Second}

	proxyURL := target + r.URL.Path
	if r.URL.RawQuery != "" {
		proxyURL += "?" + r.URL.RawQuery
	}

	proxyReq, err := http.NewRequest(r.Method, proxyURL, r.Body)
	if err != nil {
		http.Error(w, "proxy error", http.StatusBadGateway)
		return http.StatusBadGateway
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
		return http.StatusBadGateway
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
	return resp.StatusCode
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
		"total_requests": len(mc.requests),
		"services":       mc.totals,
		"uptime":         time.Since(startTime).String(),
		"version":        version,
	}
	return stats
}

// ──────────────────────────────────────────────
// Session Store — random tokens, 24h expiry
// ──────────────────────────────────────────────

type Session struct {
	Token     string
	ExpiresAt time.Time
	CSRFToken string
}

type SessionStore struct {
	mu       sync.Mutex
	sessions map[string]*Session
}

func NewSessionStore() *SessionStore {
	ss := &SessionStore{sessions: make(map[string]*Session)}
	// Auto-cleanup expired sessions every 15 minutes
	go func() {
		for {
			time.Sleep(15 * time.Minute)
			ss.Cleanup()
		}
	}()
	return ss
}

func (ss *SessionStore) Create() *Session {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	token := generateToken(32)
	csrf := generateToken(32)
	s := &Session{
		Token:     token,
		ExpiresAt: time.Now().Add(24 * time.Hour),
		CSRFToken: csrf,
	}
	ss.sessions[token] = s
	return s
}

func (ss *SessionStore) Get(token string) (*Session, bool) {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	s, ok := ss.sessions[token]
	if !ok {
		return nil, false
	}
	if time.Now().After(s.ExpiresAt) {
		delete(ss.sessions, token)
		return nil, false
	}
	return s, true
}

func (ss *SessionStore) Delete(token string) {
	ss.mu.Lock()
	defer ss.mu.Unlock()
	delete(ss.sessions, token)
}

func (ss *SessionStore) Cleanup() {
	ss.mu.Lock()
	defer ss.mu.Unlock()

	now := time.Now()
	for token, s := range ss.sessions {
		if now.After(s.ExpiresAt) {
			delete(ss.sessions, token)
		}
	}
}

func generateToken(bytes int) string {
	b := make([]byte, bytes)
	if _, err := rand.Read(b); err != nil {
		log.Fatalf("Failed to generate random token: %v", err)
	}
	return hex.EncodeToString(b)
}

// ──────────────────────────────────────────────
// Auth Middleware — bcrypt, session tokens, CSRF
// ──────────────────────────────────────────────

func authMiddleware(passwordHash []byte, sessions *SessionStore, tlsEnabled bool, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// API stats endpoint is public (for monitoring)
		if r.URL.Path == "/api/stats" {
			next.ServeHTTP(w, r)
			return
		}

		// Logout endpoint
		if r.URL.Path == "/logout" && r.Method == http.MethodPost {
			if cookie, err := r.Cookie("bastion_session"); err == nil {
				sessions.Delete(cookie.Value)
			}
			http.SetCookie(w, &http.Cookie{
				Name:     "bastion_session",
				Value:    "",
				Path:     "/",
				MaxAge:   -1,
				HttpOnly: true,
				Secure:   tlsEnabled,
				SameSite: http.SameSiteStrictMode,
			})
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}

		// Check session cookie
		cookie, err := r.Cookie("bastion_session")
		if err == nil {
			if _, ok := sessions.Get(cookie.Value); ok {
				next.ServeHTTP(w, r)
				return
			}
		}

		// Login form submission
		if r.URL.Path == "/login" && r.Method == http.MethodPost {
			r.ParseForm()
			submittedCSRF := r.FormValue("csrf_token")
			csrfCookie, csrfErr := r.Cookie("bastion_csrf")

			// Validate CSRF token
			if csrfErr != nil || csrfCookie.Value == "" || csrfCookie.Value != submittedCSRF {
				w.WriteHeader(http.StatusForbidden)
				csrf := generateToken(32)
				w.Write([]byte(loginHTML("Invalid request. Please try again.", csrf)))
				http.SetCookie(w, &http.Cookie{
					Name:     "bastion_csrf",
					Value:    csrf,
					Path:     "/login",
					MaxAge:   600,
					HttpOnly: true,
					Secure:   tlsEnabled,
					SameSite: http.SameSiteStrictMode,
				})
				return
			}

			// Clear the used CSRF cookie
			http.SetCookie(w, &http.Cookie{
				Name:   "bastion_csrf",
				Value:  "",
				Path:   "/login",
				MaxAge: -1,
			})

			// Compare password with bcrypt hash
			pw := r.FormValue("password")
			if err := bcrypt.CompareHashAndPassword(passwordHash, []byte(pw)); err != nil {
				csrf := generateToken(32)
				http.SetCookie(w, &http.Cookie{
					Name:     "bastion_csrf",
					Value:    csrf,
					Path:     "/login",
					MaxAge:   600,
					HttpOnly: true,
					Secure:   tlsEnabled,
					SameSite: http.SameSiteStrictMode,
				})
				w.WriteHeader(http.StatusUnauthorized)
				w.Write([]byte(loginHTML("Wrong password", csrf)))
				return
			}

			// Create session
			session := sessions.Create()
			http.SetCookie(w, &http.Cookie{
				Name:     "bastion_session",
				Value:    session.Token,
				Path:     "/",
				MaxAge:   86400, // 24 hours
				HttpOnly: true,
				Secure:   tlsEnabled,
				SameSite: http.SameSiteStrictMode,
			})
			http.Redirect(w, r, "/", http.StatusSeeOther)
			return
		}

		// Show login page (GET /login or any unauthenticated request)
		if r.URL.Path == "/login" {
			csrf := generateToken(32)
			http.SetCookie(w, &http.Cookie{
				Name:     "bastion_csrf",
				Value:    csrf,
				Path:     "/login",
				MaxAge:   600, // 10 minutes
				HttpOnly: true,
				Secure:   tlsEnabled,
				SameSite: http.SameSiteStrictMode,
			})
			w.Write([]byte(loginHTML("", csrf)))
			return
		}

		// Not authenticated — redirect to login
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	})
}

const loginHTMLTemplate = `<!DOCTYPE html>
<html>
<head>
<title>Bastion — Login</title>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<style>
* { margin: 0; padding: 0; box-sizing: border-box; }
body { font-family: -apple-system, system-ui, sans-serif; background: #0a0a0a; color: #e0e0e0; display: flex; align-items: center; justify-content: center; min-height: 100vh; }
.login { background: #141414; border: 1px solid #222; border-radius: 12px; padding: 2.5rem; width: 340px; }
h1 { font-size: 1.3rem; margin-bottom: 0.3rem; color: #fff; }
.sub { color: #666; font-size: 0.85rem; margin-bottom: 1.5rem; }
input[type="password"] { width: 100%%; padding: 0.75rem; background: #0a0a0a; border: 1px solid #333; border-radius: 6px; color: #fff; font-size: 1rem; margin-bottom: 1rem; outline: none; }
input[type="password"]:focus { border-color: #22c55e; }
button { width: 100%%; padding: 0.75rem; background: #22c55e; border: none; border-radius: 6px; color: #000; font-size: 1rem; font-weight: 600; cursor: pointer; }
button:hover { background: #16a34a; }
.error { color: #ef4444; font-size: 0.85rem; margin-bottom: 1rem; }
</style>
</head>
<body>
<div class="login">
<h1>Bastion</h1>
<p class="sub">Personal Edge Platform</p>
%s
<form method="POST" action="/login">
<input type="hidden" name="csrf_token" value="%s">
<input type="password" name="password" placeholder="Password" autofocus>
<button type="submit">Login</button>
</form>
</div>
</body>
</html>`

func loginHTML(errMsg string, csrfToken string) string {
	errDiv := ""
	if errMsg != "" {
		errDiv = `<p class="error">` + html.EscapeString(errMsg) + `</p>`
	}
	return fmt.Sprintf(loginHTMLTemplate, errDiv, html.EscapeString(csrfToken))
}

// ──────────────────────────────────────────────
// Dashboard API + UI
// ──────────────────────────────────────────────

func dashboardHandler(metrics *MetricsCollector, cfg Config, reqDB *RequestDB, rl *RateLimiter, wafEngine *waf.Engine) http.Handler {
	mux := http.NewServeMux()

	// WAF API endpoints
	waf.RegisterAPI(mux, wafEngine)

	// API endpoints
	mux.HandleFunc("/api/stats", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		stats := metrics.GetStats()
		stats["rate_limited_ips"] = rl.RateLimitedCount()
		stats["blocked_ips"] = len(reqDB.BlockedIPs())
		stats["service_counts"] = reqDB.ServiceCounts()
		json.NewEncoder(w).Encode(stats)
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

	mux.HandleFunc("/api/requests/recent", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		recent := reqDB.RecentRequests(20)
		json.NewEncoder(w).Encode(recent)
	})

	mux.HandleFunc("/api/requests/top-ips", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		topIPs := reqDB.TopIPs(10)
		json.NewEncoder(w).Encode(topIPs)
	})

	mux.HandleFunc("/api/requests/per-minute", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		rpm := reqDB.RequestsPerMinute(60)
		json.NewEncoder(w).Encode(rpm)
	})

	mux.HandleFunc("/api/blocked-ips", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(reqDB.BlockedIPs())
	})

	mux.HandleFunc("/api/block-ip", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			IP     string `json:"ip"`
			Reason string `json:"reason"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IP == "" {
			http.Error(w, "invalid request: ip required", http.StatusBadRequest)
			return
		}
		if err := reqDB.BlockIP(req.IP, req.Reason); err != nil {
			http.Error(w, "failed to block ip", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "blocked", "ip": req.IP})
	})

	mux.HandleFunc("/api/unblock-ip", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodDelete {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		var req struct {
			IP string `json:"ip"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.IP == "" {
			http.Error(w, "invalid request: ip required", http.StatusBadRequest)
			return
		}
		if err := reqDB.UnblockIP(req.IP); err != nil {
			http.Error(w, "failed to unblock ip", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "unblocked", "ip": req.IP})
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
.grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
.card { background: #141414; border: 1px solid #222; border-radius: 8px; padding: 1.5rem; }
.card h3 { font-size: 0.8rem; color: #888; text-transform: uppercase; letter-spacing: 0.05em; margin-bottom: 0.5rem; }
.card .value { font-size: 2rem; font-weight: 700; color: #fff; }
.card .value.green { color: #22c55e; }
.card .value.red { color: #ef4444; }
.card .value.yellow { color: #eab308; }
.service { display: flex; justify-content: space-between; align-items: center; padding: 0.75rem 0; border-bottom: 1px solid #1a1a1a; }
.service:last-child { border: none; }
.dot { width: 8px; height: 8px; border-radius: 50%; display: inline-block; margin-right: 8px; }
.dot.up { background: #22c55e; }
.dot.down { background: #ef4444; }
.latency { color: #666; font-size: 0.85rem; }
.section { margin-bottom: 2rem; }
.section h2 { font-size: 1.1rem; margin-bottom: 1rem; color: #ccc; }
table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
th { text-align: left; padding: 0.5rem; color: #888; border-bottom: 1px solid #222; font-weight: 500; }
td { padding: 0.5rem; border-bottom: 1px solid #1a1a1a; }
.method { display: inline-block; padding: 2px 6px; border-radius: 3px; font-size: 0.75rem; font-weight: 600; }
.method.GET { background: #22c55e22; color: #22c55e; }
.method.POST { background: #3b82f622; color: #3b82f6; }
.method.PUT { background: #eab30822; color: #eab308; }
.method.DELETE { background: #ef444422; color: #ef4444; }
.chart-bar { height: 20px; background: #22c55e; border-radius: 3px; min-width: 2px; transition: width 0.3s; }
.chart-row { display: flex; align-items: center; gap: 0.5rem; margin-bottom: 4px; }
.chart-label { font-size: 0.75rem; color: #888; min-width: 50px; text-align: right; }
.chart-value { font-size: 0.75rem; color: #666; min-width: 30px; }
.ip-actions { display: flex; gap: 0.5rem; align-items: center; }
.btn-block { background: #ef4444; color: #fff; border: none; padding: 3px 8px; border-radius: 4px; font-size: 0.75rem; cursor: pointer; }
.btn-block:hover { background: #dc2626; }
.btn-unblock { background: #22c55e; color: #000; border: none; padding: 3px 8px; border-radius: 4px; font-size: 0.75rem; cursor: pointer; }
.btn-unblock:hover { background: #16a34a; }
.svc-count { display: flex; justify-content: space-between; padding: 0.5rem 0; border-bottom: 1px solid #1a1a1a; }
.svc-count:last-child { border: none; }
footer { margin-top: 2rem; color: #333; font-size: 0.8rem; text-align: center; }
</style>
</head>
<body>
<h1>Bastion</h1>
<p class="subtitle">Personal Edge Platform</p>

<div class="grid">
  <div class="card"><h3>Total Requests</h3><div class="value" id="total">--</div></div>
  <div class="card"><h3>Uptime</h3><div class="value green" id="uptime">--</div></div>
  <div class="card"><h3>Rate Limited IPs</h3><div class="value yellow" id="rate-limited">--</div></div>
  <div class="card"><h3>Blocked IPs</h3><div class="value red" id="blocked">--</div></div>
  <div class="card"><h3>Version</h3><div class="value" id="version">--</div></div>
</div>

<div class="grid">
  <div class="card section">
    <h3>Services</h3>
    <div id="services">Loading...</div>
  </div>
  <div class="card section">
    <h3>Requests per Service</h3>
    <div id="svc-counts">Loading...</div>
  </div>
</div>

<div class="card section">
  <h3>Requests per Minute (last 60 min)</h3>
  <div id="rpm-chart" style="padding: 0.5rem 0;"></div>
</div>

<div class="grid">
  <div class="card section">
    <h3>Top 10 IPs</h3>
    <table>
      <thead><tr><th>IP</th><th>Count</th><th>Action</th></tr></thead>
      <tbody id="top-ips"></tbody>
    </table>
  </div>
  <div class="card section">
    <h3>Blocked IPs</h3>
    <table>
      <thead><tr><th>IP</th><th>Reason</th><th>Action</th></tr></thead>
      <tbody id="blocked-ips"></tbody>
    </table>
  </div>
</div>

<div class="card section">
  <h3>Last 20 Requests</h3>
  <div style="overflow-x: auto;">
  <table>
    <thead><tr><th>Time</th><th>Service</th><th>Method</th><th>Path</th><th>IP</th><th>Status</th><th>Duration</th></tr></thead>
    <tbody id="recent-requests"></tbody>
  </table>
  </div>
</div>

<footer>bastion v0.2.0 — zero config, zero bills</footer>

<script>
async function blockIP(ip) {
  if (!confirm('Block ' + ip + '?')) return;
  const reason = prompt('Reason (optional):', 'manual block');
  await fetch('/api/block-ip', { method: 'POST', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ip: ip, reason: reason || 'manual block'}) });
  refresh();
}
async function unblockIP(ip) {
  await fetch('/api/unblock-ip', { method: 'DELETE', headers: {'Content-Type':'application/json'}, body: JSON.stringify({ip: ip}) });
  refresh();
}
async function refresh() {
  try {
    const [stats, health, recent, topIPs, rpm, blocked] = await Promise.all([
      fetch('/api/stats').then(r => r.json()),
      fetch('/api/health').then(r => r.json()),
      fetch('/api/requests/recent').then(r => r.json()),
      fetch('/api/requests/top-ips').then(r => r.json()),
      fetch('/api/requests/per-minute').then(r => r.json()),
      fetch('/api/blocked-ips').then(r => r.json()),
    ]);

    document.getElementById('total').textContent = stats.total_requests;
    document.getElementById('uptime').textContent = stats.uptime;
    document.getElementById('version').textContent = 'v' + stats.version;
    document.getElementById('rate-limited').textContent = stats.rate_limited_ips || 0;
    document.getElementById('blocked').textContent = stats.blocked_ips || 0;

    // Services health
    const el = document.getElementById('services');
    el.innerHTML = (health || []).map(s =>
      '<div class="service"><span><span class="dot ' + s.status + '"></span>' + s.name + '</span><span class="latency">' + s.latency_ms + 'ms</span></div>'
    ).join('');

    // Service counts
    const sc = stats.service_counts || {};
    document.getElementById('svc-counts').innerHTML = Object.entries(sc).map(([k,v]) =>
      '<div class="svc-count"><span>' + k + '</span><span style="color:#fff;font-weight:600">' + v + '</span></div>'
    ).join('') || '<span style="color:#666">No data yet</span>';

    // RPM chart
    const rpmEl = document.getElementById('rpm-chart');
    if (rpm && rpm.length > 0) {
      const maxRPM = Math.max(...rpm.map(r => r.count), 1);
      rpmEl.innerHTML = rpm.slice(-30).map(r => {
        const pct = (r.count / maxRPM * 100).toFixed(0);
        const label = r.minute ? r.minute.substring(11, 16) : '';
        return '<div class="chart-row"><span class="chart-label">' + label + '</span><div class="chart-bar" style="width:' + pct + '%"></div><span class="chart-value">' + r.count + '</span></div>';
      }).join('');
    } else {
      rpmEl.innerHTML = '<span style="color:#666">No data yet</span>';
    }

    // Top IPs
    const tipEl = document.getElementById('top-ips');
    tipEl.innerHTML = (topIPs || []).map(t =>
      '<tr><td>' + t.ip + '</td><td>' + t.count + '</td><td><button class="btn-block" onclick="blockIP(\'' + t.ip + '\')">Block</button></td></tr>'
    ).join('') || '<tr><td colspan="3" style="color:#666">No data yet</td></tr>';

    // Blocked IPs
    const bipEl = document.getElementById('blocked-ips');
    bipEl.innerHTML = (blocked || []).map(b =>
      '<tr><td>' + b.ip + '</td><td>' + (b.reason || '') + '</td><td><button class="btn-unblock" onclick="unblockIP(\'' + b.ip + '\')">Unblock</button></td></tr>'
    ).join('') || '<tr><td colspan="3" style="color:#666">None blocked</td></tr>';

    // Recent requests
    const rrEl = document.getElementById('recent-requests');
    rrEl.innerHTML = (recent || []).map(r => {
      const t = r.timestamp ? r.timestamp.substring(11, 19) : '';
      const sc = r.status_code >= 400 ? 'style="color:#ef4444"' : '';
      return '<tr><td>' + t + '</td><td>' + r.service + '</td><td><span class="method ' + r.method + '">' + r.method + '</span></td><td>' + r.path + '</td><td>' + r.ip + '</td><td ' + sc + '>' + r.status_code + '</td><td>' + (r.duration_ms || 0).toFixed(1) + 'ms</td></tr>';
    }).join('') || '<tr><td colspan="7" style="color:#666">No requests yet</td></tr>';

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

	// Initialize SQLite request logger
	reqDB, err := NewRequestDB("bastion.db")
	if err != nil {
		log.Fatalf("Failed to initialize request database: %v", err)
	}

	metrics := NewMetricsCollector()
	rateLimiter := NewRateLimiter(100, time.Minute)
	proxy := NewReverseProxy(cfg.Services, metrics, rateLimiter, reqDB)

	// Initialize WAF engine
	wafCfg := waf.DefaultConfig()
	wafEngine, err := waf.NewEngine(reqDB.DB(), wafCfg)
	if err != nil {
		log.Fatalf("Failed to initialize WAF: %v", err)
	}

	// Wrap proxy with WAF middleware: Rate Limiter -> IP Blocklist -> WAF -> Reverse Proxy
	// Rate limiter and IP blocklist are inside ReverseProxy.ServeHTTP already.
	// WAF sits between the proxy's blocklist check and the actual proxying.
	var proxyHandler http.Handler = proxy
	proxyHandler = waf.Middleware(wafEngine, proxyHandler)

	// Hash password with bcrypt on startup
	passwordHash, err := bcrypt.GenerateFromPassword([]byte(cfg.Dashboard.Password), bcrypt.DefaultCost)
	if err != nil {
		log.Fatalf("Failed to hash password: %v", err)
	}
	sessions := NewSessionStore()

	// Start dashboard
	go func() {
		addr := fmt.Sprintf(":%d", cfg.Dashboard.Port)
		log.Printf("Dashboard: http://localhost%s", addr)
		handler := authMiddleware(passwordHash, sessions, cfg.TLS.Enabled, dashboardHandler(metrics, cfg, reqDB, rateLimiter, wafEngine))
		if err := http.ListenAndServe(addr, handler); err != nil {
			log.Fatal(err)
		}
	}()

	// Start reverse proxy
	log.Printf("Bastion v%s starting", version)
	log.Printf("Domain: %s", cfg.Domain)
	log.Printf("Services: %d", len(cfg.Services))
	log.Printf("Rate limit: 100 req/min per IP")
	log.Printf("WAF: enabled (learning mode, %d samples to train)", wafCfg.LearningSize)
	log.Printf("SQLite logging: bastion.db")
	for _, svc := range cfg.Services {
		log.Printf("  %s.%s -> %s", svc.Subdomain, cfg.Domain, svc.Target)
	}

	if cfg.TLS.Enabled {
		startWithTLS(cfg, proxyHandler)
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
		log.Printf("HTTP->HTTPS redirect on :80")
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
