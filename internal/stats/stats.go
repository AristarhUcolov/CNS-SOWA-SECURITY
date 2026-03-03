package stats

import (
	"encoding/json"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
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
	TotalQueries       int64            `json:"total_queries"`
	BlockedQueries     int64            `json:"blocked_queries"`
	CachedQueries      int64            `json:"cached_queries"`
	RateLimitedQueries int64            `json:"rate_limited_queries"`
	AverageTime        float64          `json:"average_time_ms"`
	TopBlockedDomains  map[string]int64 `json:"top_blocked_domains"`
	TopQueriedDomains  map[string]int64 `json:"top_queried_domains"`
	TopClients         map[string]int64 `json:"top_clients"`
	QueryTypes         map[string]int64 `json:"query_types"`
	HourlyQueries      [24]int64        `json:"hourly_queries"`
	HourlyBlocked      [24]int64        `json:"hourly_blocked"`
	StartTime          time.Time        `json:"start_time"`
	LastQuery          time.Time        `json:"last_query"`
	LastHourlyResetDay int              `json:"last_hourly_reset_day"`
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
	dataDir string
	dirty   bool
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

	// Set dataDir on query log for persistence
	queryLog.dataDir = dataDir

	// Try to load existing stats
	c.load()

	// Load persisted query log
	queryLog.loadFromDisk()

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
	queryLog.saveToDisk()
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

	// Reset hourly arrays at the start of a new day (must be BEFORE incrementing)
	day := record.Timestamp.YearDay()
	if c.stats.LastHourlyResetDay != 0 && day != c.stats.LastHourlyResetDay {
		c.stats.HourlyQueries = [24]int64{}
		c.stats.HourlyBlocked = [24]int64{}
	}
	c.stats.LastHourlyResetDay = day

	hour := record.Timestamp.Hour()
	c.stats.HourlyQueries[hour]++

	if record.Blocked {
		c.stats.BlockedQueries++
		c.stats.HourlyBlocked[hour]++
		c.stats.TopBlockedDomains[record.Domain]++
	}

	if record.Reason == "cached" || record.Reason == "stale_cache" {
		c.stats.CachedQueries++
	}
	if record.Reason == "rate_limited" {
		c.stats.RateLimitedQueries++
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

	sort.Slice(entries, func(i, j int) bool {
		return entries[i].count > entries[j].count
	})

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
			queryLog.saveToDisk()
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

// Reset clears all statistics (counters, charts, top tables)
// Does NOT clear the query log — use ClearQueryLog() for that
func (c *Collector) Reset() {
	c.mu.Lock()
	c.stats = &Statistics{
		TopBlockedDomains: make(map[string]int64),
		TopQueriedDomains: make(map[string]int64),
		TopClients:        make(map[string]int64),
		QueryTypes:        make(map[string]int64),
		StartTime:         time.Now(),
	}
	c.mu.Unlock()

	// save() acquires RLock internally — must be called AFTER releasing the write lock
	// to avoid deadlock (RWMutex is not re-entrant in Go)
	c.save()
}

// GetQueryLog returns recent query log entries
func GetQueryLog(limit int) []QueryLogEntry {
	return queryLog.GetRecent(limit)
}

// SearchQueryLog returns filtered/paginated query log entries
func SearchQueryLog(search, filter string, offset, limit int) ([]QueryLogEntry, int) {
	return queryLog.Search(search, filter, offset, limit)
}

// Add adds an entry to the query log
func (ql *QueryLog) Add(entry QueryLogEntry) {
	ql.mu.Lock()
	defer ql.mu.Unlock()

	ql.entries = append(ql.entries, entry)
	if len(ql.entries) > ql.maxSize {
		ql.entries = ql.entries[len(ql.entries)-ql.maxSize:]
	}
	ql.dirty = true
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

// Search returns query log entries matching the search term, with pagination
func (ql *QueryLog) Search(search string, filter string, offset, limit int) ([]QueryLogEntry, int) {
	ql.mu.RLock()
	defer ql.mu.RUnlock()

	search = strings.ToLower(search)
	var matched []QueryLogEntry

	// Iterate in reverse (newest first)
	for i := len(ql.entries) - 1; i >= 0; i-- {
		e := ql.entries[i]

		// Apply blocked/allowed filter
		switch filter {
		case "blocked":
			if !e.Blocked {
				continue
			}
		case "allowed":
			if e.Blocked {
				continue
			}
		}

		// Apply search filter
		if search != "" {
			if !strings.Contains(strings.ToLower(e.Domain), search) &&
				!strings.Contains(strings.ToLower(e.ClientIP), search) &&
				!strings.Contains(strings.ToLower(e.Reason), search) {
				continue
			}
		}

		matched = append(matched, e)
	}

	total := len(matched)

	// Apply pagination
	if offset >= total {
		return []QueryLogEntry{}, total
	}
	end := offset + limit
	if end > total {
		end = total
	}

	return matched[offset:end], total
}

// Clear removes all query log entries
func (ql *QueryLog) Clear() {
	ql.mu.Lock()
	defer ql.mu.Unlock()
	ql.entries = make([]QueryLogEntry, 0, 1000)
	ql.dirty = true
}

// saveToDisk persists the query log to a JSON file
func (ql *QueryLog) saveToDisk() {
	ql.mu.RLock()
	if !ql.dirty {
		ql.mu.RUnlock()
		return
	}

	// Save last 1000 entries to disk (keep file size reasonable)
	saveCount := len(ql.entries)
	if saveCount > 1000 {
		saveCount = 1000
	}
	toSave := make([]QueryLogEntry, saveCount)
	copy(toSave, ql.entries[len(ql.entries)-saveCount:])
	ql.mu.RUnlock()

	data, err := json.Marshal(toSave)
	if err != nil {
		log.Printf("[Stats] Error marshaling query log: %v", err)
		return
	}

	path := filepath.Join(ql.dataDir, "config", "querylog.json")
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		log.Printf("[Stats] Error creating querylog directory: %v", err)
		return
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		log.Printf("[Stats] Error saving query log: %v", err)
		return
	}

	ql.mu.Lock()
	ql.dirty = false
	ql.mu.Unlock()
}

// loadFromDisk loads the query log from disk
func (ql *QueryLog) loadFromDisk() {
	if ql.dataDir == "" {
		return
	}

	path := filepath.Join(ql.dataDir, "config", "querylog.json")
	data, err := os.ReadFile(path)
	if err != nil {
		return // No previous query log
	}

	var entries []QueryLogEntry
	if err := json.Unmarshal(data, &entries); err != nil {
		log.Printf("[Stats] Error loading query log: %v", err)
		return
	}

	ql.mu.Lock()
	ql.entries = entries
	ql.mu.Unlock()

	log.Printf("[Stats] Loaded %d query log entries from disk", len(entries))
}

// ClearQueryLog clears only the query log, without resetting stats
func ClearQueryLog() {
	queryLog.Clear()
	queryLog.saveToDisk()
}

func copyMapInt64(src map[string]int64) map[string]int64 {
	dst := make(map[string]int64, len(src))
	for k, v := range src {
		dst[k] = v
	}
	return dst
}
