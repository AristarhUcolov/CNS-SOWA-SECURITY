package stats

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Collector handles DNS query statistics
type Collector struct {
	mu        sync.RWMutex
	dataDir   string
	stats     *Statistics
	queryChan chan QueryRecord
	done      chan struct{}
}

// Statistics holds aggregated stats
type Statistics struct {
	TotalQueries      int64            `json:"total_queries"`
	BlockedQueries    int64            `json:"blocked_queries"`
	CachedQueries     int64            `json:"cached_queries"`
	AverageTime       float64          `json:"average_time_ms"`
	TopBlockedDomains map[string]int64 `json:"top_blocked_domains"`
	TopQueriedDomains map[string]int64 `json:"top_queried_domains"`
	TopClients        map[string]int64 `json:"top_clients"`
	QueryTypes        map[string]int64 `json:"query_types"`
	HourlyQueries     [24]int64        `json:"hourly_queries"`
	HourlyBlocked     [24]int64        `json:"hourly_blocked"`
	StartTime         time.Time        `json:"start_time"`
	LastQuery         time.Time        `json:"last_query"`
}

// QueryRecord represents a single DNS query for recording
type QueryRecord struct {
	Domain    string        `json:"domain"`
	Type      string        `json:"type"`
	ClientIP  string        `json:"client_ip"`
	Blocked   bool          `json:"blocked"`
	Reason    string        `json:"reason"`
	Duration  time.Duration `json:"duration"`
	Timestamp time.Time     `json:"timestamp"`
}

// QueryLogEntry represents a query in the log
type QueryLogEntry struct {
	Domain    string    `json:"domain"`
	Type      string    `json:"type"`
	ClientIP  string    `json:"client_ip"`
	Blocked   bool      `json:"blocked"`
	Reason    string    `json:"reason"`
	Duration  string    `json:"duration"`
	Timestamp time.Time `json:"timestamp"`
}

// QueryLog stores recent queries for the log view
type QueryLog struct {
	mu      sync.RWMutex
	entries []QueryLogEntry
	maxSize int
}

var queryLog = &QueryLog{
	entries: make([]QueryLogEntry, 0, 1000),
	maxSize: 5000,
}

// NewCollector creates a new statistics collector
func NewCollector(dataDir string) *Collector {
	c := &Collector{
		dataDir:   dataDir,
		queryChan: make(chan QueryRecord, 10000),
		done:      make(chan struct{}),
		stats: &Statistics{
			TopBlockedDomains: make(map[string]int64),
			TopQueriedDomains: make(map[string]int64),
			TopClients:        make(map[string]int64),
			QueryTypes:        make(map[string]int64),
			StartTime:         time.Now(),
		},
	}

	// Try to load existing stats
	c.load()

	return c
}

// Start begins the stats collection goroutine
func (c *Collector) Start() {
	go c.processLoop()
	go c.saveLoop()
	log.Println("[Stats] Collector started")
}

// Stop stops the collector
func (c *Collector) Stop() {
	close(c.done)
	c.save()
	log.Println("[Stats] Collector stopped")
}

// RecordQuery records a DNS query
func (c *Collector) RecordQuery(domain, qType, clientIP string, blocked bool, reason string, duration time.Duration) {
	record := QueryRecord{
		Domain:    domain,
		Type:      qType,
		ClientIP:  clientIP,
		Blocked:   blocked,
		Reason:    reason,
		Duration:  duration,
		Timestamp: time.Now(),
	}

	select {
	case c.queryChan <- record:
	default:
		// Channel full, skip this record
	}
}

// processLoop processes query records from the channel
func (c *Collector) processLoop() {
	for {
		select {
		case record := <-c.queryChan:
			c.processRecord(record)
		case <-c.done:
			// Drain remaining records
			for {
				select {
				case record := <-c.queryChan:
					c.processRecord(record)
				default:
					return
				}
			}
		}
	}
}

// processRecord handles a single query record
func (c *Collector) processRecord(record QueryRecord) {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.stats.TotalQueries++
	c.stats.LastQuery = record.Timestamp

	hour := record.Timestamp.Hour()
	c.stats.HourlyQueries[hour]++

	if record.Blocked {
		c.stats.BlockedQueries++
		c.stats.HourlyBlocked[hour]++
		c.stats.TopBlockedDomains[record.Domain]++
	}

	if record.Reason == "cached" {
		c.stats.CachedQueries++
	}

	c.stats.TopQueriedDomains[record.Domain]++
	c.stats.TopClients[record.ClientIP]++
	c.stats.QueryTypes[record.Type]++

	// Update average time
	durationMs := float64(record.Duration.Microseconds()) / 1000.0
	c.stats.AverageTime = (c.stats.AverageTime*float64(c.stats.TotalQueries-1) + durationMs) / float64(c.stats.TotalQueries)

	// Add to query log
	queryLog.Add(QueryLogEntry{
		Domain:    record.Domain,
		Type:      record.Type,
		ClientIP:  record.ClientIP,
		Blocked:   record.Blocked,
		Reason:    record.Reason,
		Duration:  record.Duration.String(),
		Timestamp: record.Timestamp,
	})

	// Trim maps if too large
	if len(c.stats.TopBlockedDomains) > 1000 {
		c.trimMap(c.stats.TopBlockedDomains, 500)
	}
	if len(c.stats.TopQueriedDomains) > 1000 {
		c.trimMap(c.stats.TopQueriedDomains, 500)
	}
	if len(c.stats.TopClients) > 500 {
		c.trimMap(c.stats.TopClients, 250)
	}
}

// trimMap keeps only the top N entries by count
func (c *Collector) trimMap(m map[string]int64, keepN int) {
	// Simple approach: remove entries with lowest counts
	if len(m) <= keepN {
		return
	}

	type entry struct {
		key   string
		count int64
	}

	entries := make([]entry, 0, len(m))
	for k, v := range m {
		entries = append(entries, entry{k, v})
	}

	// Sort by count (simple bubble for small sizes)
	for i := 0; i < len(entries); i++ {
		for j := i + 1; j < len(entries); j++ {
			if entries[j].count > entries[i].count {
				entries[i], entries[j] = entries[j], entries[i]
			}
		}
	}

	// Remove excess entries
	for i := keepN; i < len(entries); i++ {
		delete(m, entries[i].key)
	}
}

// saveLoop periodically saves stats to disk
func (c *Collector) saveLoop() {
	ticker := time.NewTicker(5 * time.Minute)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			c.save()
		case <-c.done:
			return
		}
	}
}

// save persists stats to disk
func (c *Collector) save() {
	c.mu.RLock()
	data, err := json.MarshalIndent(c.stats, "", "  ")
	c.mu.RUnlock()

	if err != nil {
		log.Printf("[Stats] Error marshaling stats: %v", err)
		return
	}

	path := filepath.Join(c.dataDir, "config", "stats.json")
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		log.Printf("[Stats] Error creating stats directory: %v", err)
		return
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		log.Printf("[Stats] Error saving stats: %v", err)
	}
}

// load reads stats from disk
func (c *Collector) load() {
	path := filepath.Join(c.dataDir, "config", "stats.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return // No previous stats
	}

	var stats Statistics
	if err := json.Unmarshal(data, &stats); err != nil {
		log.Printf("[Stats] Error loading stats: %v", err)
		return
	}

	// Ensure maps are initialized
	if stats.TopBlockedDomains == nil {
		stats.TopBlockedDomains = make(map[string]int64)
	}
	if stats.TopQueriedDomains == nil {
		stats.TopQueriedDomains = make(map[string]int64)
	}
	if stats.TopClients == nil {
		stats.TopClients = make(map[string]int64)
	}
	if stats.QueryTypes == nil {
		stats.QueryTypes = make(map[string]int64)
	}

	c.stats = &stats
	log.Printf("[Stats] Loaded previous stats: %d total queries", stats.TotalQueries)
}

// GetStats returns a copy of the current statistics
func (c *Collector) GetStats() Statistics {
	c.mu.RLock()
	defer c.mu.RUnlock()

	// Return a copy
	s := *c.stats
	s.TopBlockedDomains = copyMapInt64(c.stats.TopBlockedDomains)
	s.TopQueriedDomains = copyMapInt64(c.stats.TopQueriedDomains)
	s.TopClients = copyMapInt64(c.stats.TopClients)
	s.QueryTypes = copyMapInt64(c.stats.QueryTypes)
	return s
}

// Reset clears all statistics
func (c *Collector) Reset() {
	c.mu.Lock()
	defer c.mu.Unlock()

	c.stats = &Statistics{
		TopBlockedDomains: make(map[string]int64),
		TopQueriedDomains: make(map[string]int64),
		TopClients:        make(map[string]int64),
		QueryTypes:        make(map[string]int64),
		StartTime:         time.Now(),
	}

	queryLog.Clear()
	c.save()
}

// GetQueryLog returns recent query log entries
func GetQueryLog(limit int) []QueryLogEntry {
	return queryLog.GetRecent(limit)
}

// Add adds an entry to the query log
func (ql *QueryLog) Add(entry QueryLogEntry) {
	ql.mu.Lock()
	defer ql.mu.Unlock()

	ql.entries = append(ql.entries, entry)
	if len(ql.entries) > ql.maxSize {
		ql.entries = ql.entries[len(ql.entries)-ql.maxSize:]
	}
}

// GetRecent returns the most recent entries
func (ql *QueryLog) GetRecent(limit int) []QueryLogEntry {
	ql.mu.RLock()
	defer ql.mu.RUnlock()

	if limit <= 0 || limit > len(ql.entries) {
		limit = len(ql.entries)
	}

	start := len(ql.entries) - limit
	result := make([]QueryLogEntry, limit)
	copy(result, ql.entries[start:])

	// Reverse to get newest first
	for i, j := 0, len(result)-1; i < j; i, j = i+1, j-1 {
		result[i], result[j] = result[j], result[i]
	}

	return result
}

// Clear removes all query log entries
func (ql *QueryLog) Clear() {
	ql.mu.Lock()
	defer ql.mu.Unlock()
	ql.entries = make([]QueryLogEntry, 0, 1000)
}

func copyMapInt64(src map[string]int64) map[string]int64 {
	dst := make(map[string]int64, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
