package alerts

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"strings"
	"sync"
	"time"
)

// ──────────────────────────────────────────────
// Configuration
// ──────────────────────────────────────────────

type AlertConfig struct {
	Enabled              bool   `json:"enabled"`
	WebhookURL           string `json:"webhook_url"`
	CheckIntervalSeconds int    `json:"check_interval_seconds"`
}

func DefaultAlertConfig() AlertConfig {
	return AlertConfig{
		Enabled:              false,
		WebhookURL:           "",
		CheckIntervalSeconds: 60,
	}
}

// ──────────────────────────────────────────────
// Alert Engine
// ──────────────────────────────────────────────

type AlertEngine struct {
	db         *sql.DB
	cfg        AlertConfig
	domain     string
	services   []ServiceInfo
	mu         sync.Mutex
	healthFail map[string]int    // service -> consecutive failure count
	sentAlerts map[string]time.Time // dedup key -> last sent time
	stopCh     chan struct{}
}

type ServiceInfo struct {
	Name      string
	Subdomain string
	Target    string
	Health    string
}

func NewAlertEngine(db *sql.DB, cfg AlertConfig, domain string, services []ServiceInfo) *AlertEngine {
	return &AlertEngine{
		db:         db,
		cfg:        cfg,
		domain:     domain,
		services:   services,
		healthFail: make(map[string]int),
		sentAlerts: make(map[string]time.Time),
		stopCh:     make(chan struct{}),
	}
}

func (ae *AlertEngine) Start() {
	if !ae.cfg.Enabled {
		log.Println("[alerts] Alerts disabled in config")
		return
	}
	if ae.cfg.WebhookURL == "" {
		log.Println("[alerts] No webhook_url configured, alerts disabled")
		return
	}

	interval := time.Duration(ae.cfg.CheckIntervalSeconds) * time.Second
	if interval < 10*time.Second {
		interval = 60 * time.Second
	}

	log.Printf("[alerts] Alert engine started (check every %s)", interval)

	go func() {
		// Initial delay to let services warm up
		time.Sleep(30 * time.Second)
		ae.runChecks()

		ticker := time.NewTicker(interval)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				ae.runChecks()
			case <-ae.stopCh:
				return
			}
		}
	}()
}

func (ae *AlertEngine) Stop() {
	close(ae.stopCh)
}

func (ae *AlertEngine) runChecks() {
	ae.checkHighRequestRate()
	ae.checkServiceHealth()
	ae.checkErrorSpike()
	ae.checkRateLimitHits()
	ae.checkWAFBlocks()
	ae.cleanupDedupCache()
}

// ──────────────────────────────────────────────
// Alert Rule: High request rate from single IP
// ──────────────────────────────────────────────

func (ae *AlertEngine) checkHighRequestRate() {
	since := time.Now().UTC().Add(-1 * time.Minute).Format(time.RFC3339)

	rows, err := ae.db.Query(`
		SELECT ip, COUNT(*) as cnt, GROUP_CONCAT(DISTINCT service) as services
		FROM requests
		WHERE timestamp >= ?
		GROUP BY ip
		HAVING cnt > 50
		ORDER BY cnt DESC
		LIMIT 5
	`, since)
	if err != nil {
		log.Printf("[alerts] High request rate query error: %v", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var ip string
		var count int
		var services string
		if err := rows.Scan(&ip, &count, &services); err != nil {
			continue
		}

		dedupKey := fmt.Sprintf("high-rate:%s", ip)
		if ae.isDuplicate(dedupKey, 5*time.Minute) {
			continue
		}

		svcList := strings.ReplaceAll(services, ",", ", ")
		msg := fmt.Sprintf(
			"\u26a0\ufe0f High traffic: %s sent %d requests in the last minute to %s. Rate limited.",
			ip, count, svcList,
		)
		ae.sendAlert(msg, dedupKey)
	}
}

// ──────────────────────────────────────────────
// Alert Rule: Service down (3 consecutive fails)
// ──────────────────────────────────────────────

func (ae *AlertEngine) checkServiceHealth() {
	client := &http.Client{Timeout: 5 * time.Second}

	for _, svc := range ae.services {
		target := svc.Target
		if svc.Health != "" {
			target = svc.Health
		}

		resp, err := client.Get(target)

		ae.mu.Lock()
		if err != nil || (resp != nil && resp.StatusCode >= 500) {
			ae.healthFail[svc.Name]++
			failCount := ae.healthFail[svc.Name]
			ae.mu.Unlock()

			if resp != nil {
				resp.Body.Close()
			}

			if failCount == 3 {
				reason := "timeout"
				if err == nil && resp != nil {
					reason = fmt.Sprintf("HTTP %d", resp.StatusCode)
				}

				host := svc.Subdomain + "." + ae.domain
				dedupKey := fmt.Sprintf("svc-down:%s", svc.Name)
				msg := fmt.Sprintf(
					"\U0001f534 Service DOWN: %s failed 3 consecutive health checks (last response: %s)",
					host, reason,
				)
				ae.sendAlert(msg, dedupKey)
			}
		} else {
			if resp != nil {
				resp.Body.Close()
			}
			// Service is back up — reset counter
			if ae.healthFail[svc.Name] >= 3 {
				host := svc.Subdomain + "." + ae.domain
				dedupKey := fmt.Sprintf("svc-up:%s", svc.Name)
				if !ae.isDuplicate(dedupKey, 10*time.Minute) {
					msg := fmt.Sprintf(
						"\u2705 Service RECOVERED: %s is back online",
						host,
					)
					ae.mu.Unlock()
					ae.sendAlert(msg, dedupKey)
					ae.mu.Lock()
				}
			}
			ae.healthFail[svc.Name] = 0
			ae.mu.Unlock()
		}
	}
}

// ──────────────────────────────────────────────
// Alert Rule: 4xx/5xx error spike (>20% in 5 min)
// ──────────────────────────────────────────────

func (ae *AlertEngine) checkErrorSpike() {
	since := time.Now().UTC().Add(-5 * time.Minute).Format(time.RFC3339)

	rows, err := ae.db.Query(`
		SELECT service,
		       COUNT(*) as total,
		       SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END) as errors,
		       SUM(CASE WHEN status_code >= 500 THEN 1 ELSE 0 END) as server_errors
		FROM requests
		WHERE timestamp >= ?
		GROUP BY service
		HAVING total >= 10
	`, since)
	if err != nil {
		log.Printf("[alerts] Error spike query error: %v", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var service string
		var total, errors, serverErrors int
		if err := rows.Scan(&service, &total, &errors, &serverErrors); err != nil {
			continue
		}

		errorRate := float64(errors) / float64(total) * 100
		if errorRate <= 20 {
			continue
		}

		dedupKey := fmt.Sprintf("error-spike:%s", service)
		if ae.isDuplicate(dedupKey, 5*time.Minute) {
			continue
		}

		errorType := "4xx/5xx"
		if serverErrors > errors/2 {
			errorType = "5xx"
		}

		msg := fmt.Sprintf(
			"\U0001f4ca Traffic spike: %s errors jumped to %.0f%% of requests in the last 5 minutes on %s.%s",
			errorType, errorRate, service, ae.domain,
		)
		ae.sendAlert(msg, dedupKey)
	}
}

// ──────────────────────────────────────────────
// Alert Rule: New IP hitting rate limiter
// ──────────────────────────────────────────────

func (ae *AlertEngine) checkRateLimitHits() {
	since := time.Now().UTC().Add(-1 * time.Minute).Format(time.RFC3339)

	rows, err := ae.db.Query(`
		SELECT ip, COUNT(*) as cnt
		FROM requests
		WHERE timestamp >= ? AND status_code = 429
		GROUP BY ip
		ORDER BY cnt DESC
		LIMIT 5
	`, since)
	if err != nil {
		log.Printf("[alerts] Rate limit hits query error: %v", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var ip string
		var count int
		if err := rows.Scan(&ip, &count); err != nil {
			continue
		}

		dedupKey := fmt.Sprintf("rate-limited:%s", ip)
		if ae.isDuplicate(dedupKey, 10*time.Minute) {
			continue
		}

		msg := fmt.Sprintf(
			"\U0001f6a8 Rate limited: %s hit the rate limiter %d times in the last minute",
			ip, count,
		)
		ae.sendAlert(msg, dedupKey)
	}
}

// ──────────────────────────────────────────────
// Alert Rule: WAF blocked request
// ──────────────────────────────────────────────

func (ae *AlertEngine) checkWAFBlocks() {
	since := time.Now().UTC().Add(-1 * time.Minute).Format(time.RFC3339)

	// Check for blocked_ips entries added recently
	rows, err := ae.db.Query(`
		SELECT ip, reason
		FROM blocked_ips
		WHERE blocked_at >= ?
		ORDER BY blocked_at DESC
		LIMIT 5
	`, since)
	if err != nil {
		log.Printf("[alerts] WAF blocks query error: %v", err)
		return
	}
	defer rows.Close()

	for rows.Next() {
		var ip, reason string
		if err := rows.Scan(&ip, &reason); err != nil {
			continue
		}

		dedupKey := fmt.Sprintf("waf-block:%s", ip)
		if ae.isDuplicate(dedupKey, 30*time.Minute) {
			continue
		}

		msg := fmt.Sprintf(
			"\U0001f6e1\ufe0f WAF blocked: %s was blocked (reason: %s)",
			ip, reason,
		)
		ae.sendAlert(msg, dedupKey)
	}
}

// ──────────────────────────────────────────────
// Webhook sender
// ──────────────────────────────────────────────

func (ae *AlertEngine) sendAlert(message, dedupKey string) {
	ae.mu.Lock()
	ae.sentAlerts[dedupKey] = time.Now()
	ae.mu.Unlock()

	log.Printf("[alerts] %s", message)

	go func() {
		url := ae.cfg.WebhookURL

		// Detect Telegram-style webhook (URL ends with text= param)
		if strings.Contains(url, "/sendMessage") && strings.Contains(url, "text=") {
			url = url + urlEncode(message)
			resp, err := http.Get(url)
			if err != nil {
				log.Printf("[alerts] Webhook failed: %v", err)
				return
			}
			resp.Body.Close()
			return
		}

		// Generic JSON webhook (Slack, Discord, custom)
		payload := map[string]string{
			"text":    message,
			"content": message, // Discord uses "content"
		}
		body, _ := json.Marshal(payload)

		resp, err := http.Post(url, "application/json", bytes.NewReader(body))
		if err != nil {
			log.Printf("[alerts] Webhook failed: %v", err)
			return
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()
}

func (ae *AlertEngine) isDuplicate(key string, window time.Duration) bool {
	ae.mu.Lock()
	defer ae.mu.Unlock()

	if lastSent, ok := ae.sentAlerts[key]; ok {
		if time.Since(lastSent) < window {
			return true
		}
	}
	return false
}

func (ae *AlertEngine) cleanupDedupCache() {
	ae.mu.Lock()
	defer ae.mu.Unlock()

	cutoff := time.Now().Add(-30 * time.Minute)
	for key, t := range ae.sentAlerts {
		if t.Before(cutoff) {
			delete(ae.sentAlerts, key)
		}
	}
}

// Simple URL encoding for Telegram text parameter
func urlEncode(s string) string {
	var buf strings.Builder
	for _, c := range s {
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9',
			c == '-', c == '_', c == '.', c == '~':
			buf.WriteRune(c)
		case c == ' ':
			buf.WriteString("%20")
		default:
			encoded := fmt.Sprintf("%c", c)
			for i := 0; i < len(encoded); i++ {
				buf.WriteString(fmt.Sprintf("%%%02X", encoded[i]))
			}
		}
	}
	return buf.String()
}

// ──────────────────────────────────────────────
// Claw Monitor — Autonomous SRE
// ──────────────────────────────────────────────

type ClawMonitor struct {
	db       *sql.DB
	domain   string
	services []ServiceInfo
	alerts   *AlertEngine
	stopCh   chan struct{}
}

type ClawReport struct {
	ID        int64  `json:"id"`
	Timestamp string `json:"timestamp"`
	Summary   string `json:"summary"`
	Severity  string `json:"severity"` // ok, warning, critical
	Metrics   string `json:"metrics"`  // JSON blob
}

type ServiceMetrics struct {
	Service       string  `json:"service"`
	RequestCount  int     `json:"request_count"`
	AvgResponseMs float64 `json:"avg_response_ms"`
	ErrorRate     float64 `json:"error_rate"`
	UniqueIPs     int     `json:"unique_ips"`
	P95ResponseMs float64 `json:"p95_response_ms"`
}

type HealthStatus struct {
	Service string `json:"service"`
	Status  string `json:"status"`
	Latency int64  `json:"latency_ms"`
}

func NewClawMonitor(db *sql.DB, domain string, services []ServiceInfo, alerts *AlertEngine) (*ClawMonitor, error) {
	// Create claw_reports table
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS claw_reports (
			id INTEGER PRIMARY KEY,
			timestamp TEXT NOT NULL,
			summary TEXT NOT NULL,
			severity TEXT NOT NULL DEFAULT 'ok',
			metrics TEXT NOT NULL DEFAULT '{}'
		);
		CREATE INDEX IF NOT EXISTS idx_claw_reports_timestamp ON claw_reports(timestamp);
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to create claw_reports table: %w", err)
	}

	return &ClawMonitor{
		db:       db,
		domain:   domain,
		services: services,
		alerts:   alerts,
		stopCh:   make(chan struct{}),
	}, nil
}

func (cm *ClawMonitor) Start() {
	log.Println("[claw] Autonomous monitor started (runs every 5 min)")

	go func() {
		// Initial delay
		time.Sleep(1 * time.Minute)
		cm.analyze()

		ticker := time.NewTicker(5 * time.Minute)
		defer ticker.Stop()

		for {
			select {
			case <-ticker.C:
				cm.analyze()
			case <-cm.stopCh:
				return
			}
		}
	}()
}

func (cm *ClawMonitor) Stop() {
	close(cm.stopCh)
}

func (cm *ClawMonitor) analyze() {
	since := time.Now().UTC().Add(-5 * time.Minute).Format(time.RFC3339)

	// Gather per-service metrics
	svcMetrics := cm.gatherServiceMetrics(since)
	healthStatuses := cm.checkAllHealth()

	// Determine severity and build summary
	severity := "ok"
	var findings []string

	totalRequests := 0
	for _, m := range svcMetrics {
		totalRequests += m.RequestCount

		if m.ErrorRate > 20 {
			severity = escalate(severity, "critical")
			findings = append(findings, fmt.Sprintf(
				"%s has %.1f%% error rate (%d requests)",
				m.Service, m.ErrorRate, m.RequestCount,
			))
		} else if m.ErrorRate > 10 {
			severity = escalate(severity, "warning")
			findings = append(findings, fmt.Sprintf(
				"%s has elevated error rate at %.1f%%",
				m.Service, m.ErrorRate,
			))
		}

		if m.AvgResponseMs > 2000 {
			severity = escalate(severity, "warning")
			findings = append(findings, fmt.Sprintf(
				"%s avg response time is slow: %.0fms",
				m.Service, m.AvgResponseMs,
			))
		}
	}

	downServices := 0
	for _, h := range healthStatuses {
		if h.Status == "down" {
			downServices++
			severity = escalate(severity, "critical")
			findings = append(findings, fmt.Sprintf(
				"%s is DOWN (health check failed)",
				h.Service,
			))
		}
	}

	// Build natural language summary
	var summary string
	now := time.Now().UTC().Format("15:04 UTC")

	if len(findings) == 0 {
		summary = fmt.Sprintf(
			"[%s] All systems nominal. %d requests across %d services in the last 5 minutes. No anomalies detected.",
			now, totalRequests, len(svcMetrics),
		)
	} else {
		summary = fmt.Sprintf(
			"[%s] %s detected (%d issue(s)). %d total requests, %d services down.\n\nFindings:\n- %s",
			now,
			strings.ToUpper(severity),
			len(findings),
			totalRequests,
			downServices,
			strings.Join(findings, "\n- "),
		)
	}

	// Serialize metrics
	metricsJSON, _ := json.Marshal(map[string]interface{}{
		"services": svcMetrics,
		"health":   healthStatuses,
		"total":    totalRequests,
	})

	// Save report
	_, err := cm.db.Exec(`
		INSERT INTO claw_reports (timestamp, summary, severity, metrics)
		VALUES (?, ?, ?, ?)
	`, time.Now().UTC().Format(time.RFC3339), summary, severity, string(metricsJSON))
	if err != nil {
		log.Printf("[claw] Failed to save report: %v", err)
	}

	// Send alert for non-ok reports
	if severity != "ok" && cm.alerts != nil && cm.alerts.cfg.Enabled {
		cm.alerts.sendAlert(fmt.Sprintf("\U0001f916 Claw Monitor Report:\n%s", summary), "claw-report")
	}

	log.Printf("[claw] Report: severity=%s requests=%d findings=%d", severity, totalRequests, len(findings))

	// Prune old reports (keep last 7 days)
	cutoff := time.Now().UTC().Add(-7 * 24 * time.Hour).Format(time.RFC3339)
	cm.db.Exec(`DELETE FROM claw_reports WHERE timestamp < ?`, cutoff)
}

func (cm *ClawMonitor) gatherServiceMetrics(since string) []ServiceMetrics {
	rows, err := cm.db.Query(`
		SELECT
			service,
			COUNT(*) as cnt,
			AVG(duration_ms) as avg_ms,
			SUM(CASE WHEN status_code >= 400 THEN 1 ELSE 0 END) * 100.0 / COUNT(*) as error_rate,
			COUNT(DISTINCT ip) as unique_ips
		FROM requests
		WHERE timestamp >= ?
		GROUP BY service
	`, since)
	if err != nil {
		log.Printf("[claw] Service metrics query error: %v", err)
		return nil
	}
	defer rows.Close()

	var results []ServiceMetrics
	for rows.Next() {
		var m ServiceMetrics
		if err := rows.Scan(&m.Service, &m.RequestCount, &m.AvgResponseMs, &m.ErrorRate, &m.UniqueIPs); err != nil {
			continue
		}
		// Get P95 response time
		m.P95ResponseMs = cm.getP95(m.Service, since)
		results = append(results, m)
	}
	return results
}

func (cm *ClawMonitor) getP95(service, since string) float64 {
	var p95 float64
	err := cm.db.QueryRow(`
		SELECT duration_ms FROM requests
		WHERE service = ? AND timestamp >= ?
		ORDER BY duration_ms DESC
		LIMIT 1 OFFSET (
			SELECT CAST(COUNT(*) * 0.05 AS INTEGER) FROM requests
			WHERE service = ? AND timestamp >= ?
		)
	`, service, since, service, since).Scan(&p95)
	if err != nil {
		return 0
	}
	return p95
}

func (cm *ClawMonitor) checkAllHealth() []HealthStatus {
	client := &http.Client{Timeout: 5 * time.Second}
	var results []HealthStatus

	for _, svc := range cm.services {
		target := svc.Target
		if svc.Health != "" {
			target = svc.Health
		}

		start := time.Now()
		resp, err := client.Get(target)
		latency := time.Since(start).Milliseconds()

		status := "down"
		if err == nil {
			resp.Body.Close()
			if resp.StatusCode < 500 {
				status = "up"
			}
		}

		results = append(results, HealthStatus{
			Service: svc.Name,
			Status:  status,
			Latency: latency,
		})
	}
	return results
}

// ──────────────────────────────────────────────
// API Handlers
// ──────────────────────────────────────────────

func (cm *ClawMonitor) HandleReports(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	rows, err := cm.db.Query(`
		SELECT id, timestamp, summary, severity, metrics
		FROM claw_reports
		ORDER BY id DESC
		LIMIT 50
	`)
	if err != nil {
		http.Error(w, `{"error":"query failed"}`, http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	var reports []ClawReport
	for rows.Next() {
		var r ClawReport
		if err := rows.Scan(&r.ID, &r.Timestamp, &r.Summary, &r.Severity, &r.Metrics); err != nil {
			continue
		}
		reports = append(reports, r)
	}

	if reports == nil {
		reports = []ClawReport{}
	}
	json.NewEncoder(w).Encode(reports)
}

func (cm *ClawMonitor) HandleStatus(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")

	since := time.Now().UTC().Add(-5 * time.Minute).Format(time.RFC3339)
	svcMetrics := cm.gatherServiceMetrics(since)
	healthStatuses := cm.checkAllHealth()

	// Get latest report severity
	var lastSeverity string
	err := cm.db.QueryRow(`SELECT severity FROM claw_reports ORDER BY id DESC LIMIT 1`).Scan(&lastSeverity)
	if err != nil {
		lastSeverity = "unknown"
	}

	status := map[string]interface{}{
		"status":     lastSeverity,
		"checked_at": time.Now().UTC().Format(time.RFC3339),
		"services":   svcMetrics,
		"health":     healthStatuses,
	}
	json.NewEncoder(w).Encode(status)
}

// ──────────────────────────────────────────────
// Helpers
// ──────────────────────────────────────────────

func escalate(current, proposed string) string {
	levels := map[string]int{"ok": 0, "warning": 1, "critical": 2}
	if levels[proposed] > levels[current] {
		return proposed
	}
	return current
}
