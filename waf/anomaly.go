package waf

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"math"
	"math/rand"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

// ──────────────────────────────────────────────
// Feature Extraction
// ──────────────────────────────────────────────

// Features represents numeric features extracted from an HTTP request.
type Features struct {
	URLLength       float64
	URLDepth        float64
	QueryParamCount float64
	QueryLength     float64
	BodySize        float64
	HeaderCount     float64
	URLEntropy      float64
	HasAttackPattern float64
	TimeSinceLastReq float64
}

// ToSlice converts features to a float64 slice for the model.
func (f Features) ToSlice() []float64 {
	return []float64{
		f.URLLength,
		f.URLDepth,
		f.QueryParamCount,
		f.QueryLength,
		f.BodySize,
		f.HeaderCount,
		f.URLEntropy,
		f.HasAttackPattern,
		f.TimeSinceLastReq,
	}
}

const NumFeatures = 9

// attackPatterns are common SQL injection, XSS, and path traversal signatures.
var attackPatterns = []string{
	"select ", "union ", "drop ", "insert ", "delete ", "update ",
	"<script", "javascript:", "onerror=", "onload=",
	"../", "..\\", "/etc/passwd", "/etc/shadow",
	"' or ", "\" or ", "1=1", "cmd=", "exec(", "eval(",
	"%00", "%0a", "%0d",
}

// shannon computes the Shannon entropy of a string.
func shannon(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]float64)
	for _, c := range s {
		freq[c]++
	}
	n := float64(len(s))
	entropy := 0.0
	for _, count := range freq {
		p := count / n
		if p > 0 {
			entropy -= p * math.Log2(p)
		}
	}
	return entropy
}

// hasAttackPattern checks if the URL or body contains common attack signatures.
func hasAttackPattern(rawURL, body string) bool {
	lower := strings.ToLower(rawURL + " " + body)
	for _, pattern := range attackPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

// ExtractFeatures pulls numeric features from an HTTP request.
func ExtractFeatures(r *http.Request, bodyBytes []byte, lastReqTime time.Time) Features {
	fullURL := r.URL.String()
	queryStr := r.URL.RawQuery
	params, _ := url.ParseQuery(queryStr)

	depth := 0
	trimmed := strings.Trim(r.URL.Path, "/")
	if trimmed != "" {
		depth = len(strings.Split(trimmed, "/"))
	}

	timeSinceLast := 0.0
	if !lastReqTime.IsZero() {
		timeSinceLast = time.Since(lastReqTime).Seconds()
	}

	bodyStr := ""
	if len(bodyBytes) > 0 && len(bodyBytes) < 4096 {
		bodyStr = string(bodyBytes)
	}

	attackFlag := 0.0
	if hasAttackPattern(fullURL, bodyStr) {
		attackFlag = 1.0
	}

	return Features{
		URLLength:        float64(len(fullURL)),
		URLDepth:         float64(depth),
		QueryParamCount:  float64(len(params)),
		QueryLength:      float64(len(queryStr)),
		BodySize:         float64(len(bodyBytes)),
		HeaderCount:      float64(len(r.Header)),
		URLEntropy:       shannon(fullURL),
		HasAttackPattern: attackFlag,
		TimeSinceLastReq: timeSinceLast,
	}
}

// ──────────────────────────────────────────────
// Isolation Forest (from scratch — ~100 lines)
// ──────────────────────────────────────────────

// iNode represents a node in an isolation tree.
type iNode struct {
	Left      *iNode
	Right     *iNode
	SplitFeat int
	SplitVal  float64
	Size      int // number of samples that reached this node
}

// iTree builds a single isolation tree from data.
func iTree(data [][]float64, maxDepth int, rng *rand.Rand) *iNode {
	n := len(data)
	if n <= 1 || maxDepth <= 0 {
		return &iNode{Size: n}
	}

	numFeats := len(data[0])
	feat := rng.Intn(numFeats)

	// Find min/max for chosen feature
	minVal, maxVal := data[0][feat], data[0][feat]
	for _, row := range data[1:] {
		if row[feat] < minVal {
			minVal = row[feat]
		}
		if row[feat] > maxVal {
			maxVal = row[feat]
		}
	}

	if minVal == maxVal {
		return &iNode{Size: n}
	}

	splitVal := minVal + rng.Float64()*(maxVal-minVal)

	var left, right [][]float64
	for _, row := range data {
		if row[feat] < splitVal {
			left = append(left, row)
		} else {
			right = append(right, row)
		}
	}

	// Avoid infinite recursion on degenerate splits
	if len(left) == 0 || len(right) == 0 {
		return &iNode{Size: n}
	}

	return &iNode{
		SplitFeat: feat,
		SplitVal:  splitVal,
		Left:      iTree(left, maxDepth-1, rng),
		Right:     iTree(right, maxDepth-1, rng),
		Size:      n,
	}
}

// pathLength computes the path length for a sample in an isolation tree.
func pathLength(node *iNode, sample []float64, depth int) float64 {
	if node == nil {
		return float64(depth)
	}
	if node.Left == nil && node.Right == nil {
		// Leaf: add average path length correction for remaining samples
		return float64(depth) + avgPathLength(node.Size)
	}
	if sample[node.SplitFeat] < node.SplitVal {
		return pathLength(node.Left, sample, depth+1)
	}
	return pathLength(node.Right, sample, depth+1)
}

// avgPathLength computes the average path length of unsuccessful search in BST.
// This is the standard correction factor c(n) from the Isolation Forest paper.
func avgPathLength(n int) float64 {
	if n <= 1 {
		return 0
	}
	if n == 2 {
		return 1
	}
	fn := float64(n)
	// H(n-1) approximation using Euler-Mascheroni constant
	h := math.Log(fn-1) + 0.5772156649
	return 2*h - 2*(fn-1)/fn
}

// IsolationForest is an ensemble of isolation trees for anomaly detection.
type IsolationForest struct {
	Trees     []*iNode
	NumTrees  int
	MaxDepth  int
	TrainSize int
}

// NewIsolationForest creates a new forest. Not yet trained.
func NewIsolationForest(numTrees int) *IsolationForest {
	return &IsolationForest{
		NumTrees: numTrees,
	}
}

// Train builds the forest from training data.
func (f *IsolationForest) Train(data [][]float64) {
	n := len(data)
	if n == 0 {
		return
	}
	f.TrainSize = n
	f.MaxDepth = int(math.Ceil(math.Log2(float64(n))))
	f.Trees = make([]*iNode, f.NumTrees)

	rng := rand.New(rand.NewSource(time.Now().UnixNano()))
	sampleSize := 256
	if sampleSize > n {
		sampleSize = n
	}

	for i := 0; i < f.NumTrees; i++ {
		// Subsample
		sample := make([][]float64, sampleSize)
		for j := 0; j < sampleSize; j++ {
			sample[j] = data[rng.Intn(n)]
		}
		f.Trees[i] = iTree(sample, f.MaxDepth, rng)
	}
}

// Score returns the anomaly score for a sample. Higher = more anomalous.
// Score is in [0, 1]. Above ~0.6 is suspicious, above ~0.7 is likely anomalous.
func (f *IsolationForest) Score(sample []float64) float64 {
	if len(f.Trees) == 0 {
		return 0
	}

	totalPath := 0.0
	for _, tree := range f.Trees {
		totalPath += pathLength(tree, sample, 0)
	}
	avgPath := totalPath / float64(len(f.Trees))
	c := avgPathLength(f.TrainSize)
	if c == 0 {
		return 0
	}
	// Anomaly score: s = 2^(-avgPath/c)
	return math.Pow(2, -avgPath/c)
}

// ──────────────────────────────────────────────
// WAF Engine
// ──────────────────────────────────────────────

// WAFConfig holds configuration for the WAF.
type WAFConfig struct {
	Enabled         bool    `json:"enabled"`
	LearningSize    int     `json:"learning_size"`    // Requests before training (default 1000)
	AnomalyThreshold float64 `json:"anomaly_threshold"` // Score above this = blocked (default 0.65)
	NumTrees        int     `json:"num_trees"`         // Isolation forest trees (default 100)
}

// DefaultConfig returns sensible WAF defaults.
func DefaultConfig() WAFConfig {
	return WAFConfig{
		Enabled:          true,
		LearningSize:     1000,
		AnomalyThreshold: 0.65,
		NumTrees:         100,
	}
}

// WAFEvent represents a logged WAF decision.
type WAFEvent struct {
	ID        int64   `json:"id"`
	Timestamp string  `json:"timestamp"`
	IP        string  `json:"ip"`
	Method    string  `json:"method"`
	Path      string  `json:"path"`
	Score     float64 `json:"score"`
	Blocked   bool    `json:"blocked"`
	Reason    string  `json:"reason"`
}

// Engine is the core WAF engine.
type Engine struct {
	mu            sync.RWMutex
	config        WAFConfig
	forest        *IsolationForest
	trainingData  [][]float64
	trained       bool
	totalAnalyzed int64
	totalBlocked  int64
	lastReqByIP   map[string]time.Time
	db            *sql.DB
}

// NewEngine creates a new WAF engine.
func NewEngine(db *sql.DB, cfg WAFConfig) (*Engine, error) {
	// Create waf_events table
	schema := `
	CREATE TABLE IF NOT EXISTS waf_events (
		id INTEGER PRIMARY KEY,
		timestamp TEXT NOT NULL,
		ip TEXT NOT NULL,
		method TEXT NOT NULL,
		path TEXT NOT NULL,
		score REAL NOT NULL,
		blocked INTEGER NOT NULL DEFAULT 0,
		reason TEXT NOT NULL DEFAULT ''
	);
	CREATE INDEX IF NOT EXISTS idx_waf_events_timestamp ON waf_events(timestamp);
	CREATE INDEX IF NOT EXISTS idx_waf_events_ip ON waf_events(ip);
	`
	if _, err := db.Exec(schema); err != nil {
		return nil, fmt.Errorf("waf: failed to create schema: %w", err)
	}

	return &Engine{
		config:      cfg,
		forest:      NewIsolationForest(cfg.NumTrees),
		lastReqByIP: make(map[string]time.Time),
		db:          db,
	}, nil
}

// Mode returns "learning" or "active".
func (e *Engine) Mode() string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	if e.trained {
		return "active"
	}
	return "learning"
}

// Stats returns WAF statistics.
func (e *Engine) Stats() map[string]interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()

	mode := "learning"
	if e.trained {
		mode = "active"
	}

	return map[string]interface{}{
		"enabled":          e.config.Enabled,
		"mode":             mode,
		"training_samples": len(e.trainingData),
		"learning_target":  e.config.LearningSize,
		"requests_analyzed": e.totalAnalyzed,
		"threats_blocked":  e.totalBlocked,
		"threshold":        e.config.AnomalyThreshold,
		"num_trees":        e.config.NumTrees,
	}
}

// Retrain forces a retrain of the model using collected data.
func (e *Engine) Retrain() {
	e.mu.Lock()
	defer e.mu.Unlock()

	if len(e.trainingData) < 10 {
		return
	}
	e.forest = NewIsolationForest(e.config.NumTrees)
	e.forest.Train(e.trainingData)
	e.trained = true
	log.Printf("[WAF] Retrained on %d samples", len(e.trainingData))
}

// ScoreURL scores a URL string for anomaly detection (for the test endpoint).
func (e *Engine) ScoreURL(rawURL string) float64 {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if !e.trained {
		return 0
	}

	parsed, err := url.Parse(rawURL)
	if err != nil {
		return 0
	}

	r := &http.Request{URL: parsed, Header: http.Header{}}
	feats := ExtractFeatures(r, nil, time.Time{})
	return e.forest.Score(feats.ToSlice())
}

// logEvent writes a WAF event to SQLite.
func (e *Engine) logEvent(ip, method, path string, score float64, blocked bool, reason string) {
	blockedInt := 0
	if blocked {
		blockedInt = 1
	}
	_, err := e.db.Exec(
		`INSERT INTO waf_events (timestamp, ip, method, path, score, blocked, reason) VALUES (?, ?, ?, ?, ?, ?, ?)`,
		time.Now().UTC().Format(time.RFC3339),
		ip, method, path, score, blockedInt, reason,
	)
	if err != nil {
		log.Printf("[WAF] Failed to log event: %v", err)
	}
}

// RecentEvents returns the most recent WAF events.
func (e *Engine) RecentEvents(limit int) []WAFEvent {
	rows, err := e.db.Query(
		`SELECT id, timestamp, ip, method, path, score, blocked, reason
		 FROM waf_events ORDER BY id DESC LIMIT ?`, limit)
	if err != nil {
		log.Printf("[WAF] RecentEvents query error: %v", err)
		return nil
	}
	defer rows.Close()

	var events []WAFEvent
	for rows.Next() {
		var ev WAFEvent
		var blocked int
		if err := rows.Scan(&ev.ID, &ev.Timestamp, &ev.IP, &ev.Method, &ev.Path, &ev.Score, &blocked, &ev.Reason); err != nil {
			continue
		}
		ev.Blocked = blocked != 0
		events = append(events, ev)
	}
	return events
}

// Analyze processes a request through the WAF. Returns (blocked, score, reason).
func (e *Engine) Analyze(r *http.Request, ip string) (bool, float64, string) {
	if !e.config.Enabled {
		return false, 0, ""
	}

	// Read body (limited) for analysis, then restore it
	var bodyBytes []byte
	if r.Body != nil {
		bodyBytes, _ = io.ReadAll(io.LimitReader(r.Body, 8192))
		r.Body = io.NopCloser(strings.NewReader(string(bodyBytes)))
	}

	// Get last request time for this IP
	e.mu.Lock()
	lastReq := e.lastReqByIP[ip]
	e.lastReqByIP[ip] = time.Now()
	e.totalAnalyzed++
	e.mu.Unlock()

	feats := ExtractFeatures(r, bodyBytes, lastReq)
	featSlice := feats.ToSlice()

	// Rule-based: always block obvious attack patterns regardless of model state
	if feats.HasAttackPattern > 0 {
		e.mu.Lock()
		e.totalBlocked++
		e.mu.Unlock()
		e.logEvent(ip, r.Method, r.URL.Path, 1.0, true, "attack pattern detected")
		return true, 1.0, "attack pattern detected"
	}

	e.mu.Lock()
	trained := e.trained
	trainingLen := len(e.trainingData)
	e.mu.Unlock()

	if !trained {
		// Learning mode: collect features, don't block
		e.mu.Lock()
		e.trainingData = append(e.trainingData, featSlice)
		if len(e.trainingData) >= e.config.LearningSize {
			// Auto-train
			e.forest = NewIsolationForest(e.config.NumTrees)
			e.forest.Train(e.trainingData)
			e.trained = true
			log.Printf("[WAF] Auto-trained on %d samples — switching to active mode", len(e.trainingData))
		}
		e.mu.Unlock()
		e.logEvent(ip, r.Method, r.URL.Path, 0, false, fmt.Sprintf("learning (%d/%d)", trainingLen+1, e.config.LearningSize))
		return false, 0, ""
	}

	// Active mode: score the request
	e.mu.RLock()
	score := e.forest.Score(featSlice)
	threshold := e.config.AnomalyThreshold
	e.mu.RUnlock()

	if score > threshold {
		e.mu.Lock()
		e.totalBlocked++
		e.mu.Unlock()
		reason := fmt.Sprintf("anomaly score %.3f exceeds threshold %.3f", score, threshold)
		e.logEvent(ip, r.Method, r.URL.Path, score, true, reason)
		return true, score, reason
	}

	e.logEvent(ip, r.Method, r.URL.Path, score, false, "")
	return false, score, ""
}

// ──────────────────────────────────────────────
// HTTP Middleware
// ──────────────────────────────────────────────

// ExtractIP extracts the client IP from a request.
func ExtractIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		parts := strings.SplitN(xff, ",", 2)
		return strings.TrimSpace(parts[0])
	}
	ip := r.RemoteAddr
	if idx := strings.LastIndex(ip, ":"); idx != -1 {
		ip = ip[:idx]
	}
	return ip
}

// Middleware wraps an http.Handler with WAF protection.
func Middleware(engine *Engine, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := ExtractIP(r)
		blocked, _, _ := engine.Analyze(r, ip)
		if blocked {
			http.Error(w, "blocked by Bastion WAF", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// ──────────────────────────────────────────────
// API Handlers
// ──────────────────────────────────────────────

// RegisterAPI adds WAF API endpoints to a mux.
func RegisterAPI(mux *http.ServeMux, engine *Engine) {
	// GET /api/waf/status
	mux.HandleFunc("/api/waf/status", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(engine.Stats())
	})

	// GET /api/waf/events
	mux.HandleFunc("/api/waf/events", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		events := engine.RecentEvents(50)
		if events == nil {
			events = []WAFEvent{}
		}
		json.NewEncoder(w).Encode(events)
	})

	// POST /api/waf/retrain
	mux.HandleFunc("/api/waf/retrain", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		engine.Retrain()
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"status": "retrained"})
	})

	// GET /api/waf/score?url=...
	mux.HandleFunc("/api/waf/score", func(w http.ResponseWriter, r *http.Request) {
		testURL := r.URL.Query().Get("url")
		if testURL == "" {
			http.Error(w, "url parameter required", http.StatusBadRequest)
			return
		}
		score := engine.ScoreURL(testURL)
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"url":       testURL,
			"score":     score,
			"threshold": engine.config.AnomalyThreshold,
			"anomalous": score > engine.config.AnomalyThreshold,
			"mode":      engine.Mode(),
		})
	})
}
