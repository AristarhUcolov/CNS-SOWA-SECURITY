package dnsserver

import (
	"context"
	"fmt"
	"log"
	"net"
	"strings"
	"sync"
	"time"

	"github.com/AristarhUcolov/CNS-SOWA-SECURITY/internal/config"
	"github.com/AristarhUcolov/CNS-SOWA-SECURITY/internal/filtering"
	"github.com/AristarhUcolov/CNS-SOWA-SECURITY/internal/stats"
	"github.com/miekg/dns"
)

// Server represents the DNS server
type Server struct {
	udpServer  *dns.Server
	tcpServer  *dns.Server
	dohServer  *DoHServer
	dotServer  *DoTServer
	cfg        *config.Config
	filter     *filtering.Engine
	upstream   *UpstreamResolver
	stats      *stats.Collector
	cache      *DNSCache
	mu         sync.RWMutex
	running    bool
	ctx        context.Context
	cancelFunc context.CancelFunc
}

// DNSCache is a simple DNS response cache
type DNSCache struct {
	mu      sync.RWMutex
	entries map[string]*CacheEntry
	maxSize int
}

// CacheEntry represents a cached DNS response
type CacheEntry struct {
	Msg       *dns.Msg
	ExpiresAt time.Time
}

// NewDNSCache creates a new DNS cache
func NewDNSCache(maxSize int) *DNSCache {
	return &DNSCache{
		entries: make(map[string]*CacheEntry),
		maxSize: maxSize,
	}
}

// Get retrieves a cached entry
func (c *DNSCache) Get(key string) (*dns.Msg, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()

	entry, ok := c.entries[key]
	if !ok {
		return nil, false
	}

	if time.Now().After(entry.ExpiresAt) {
		return nil, false
	}

	// Return a copy
	msg := entry.Msg.Copy()
	return msg, true
}

// Set stores a response in cache
func (c *DNSCache) Set(key string, msg *dns.Msg, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Evict if at capacity
	if len(c.entries) >= c.maxSize {
		c.evict()
	}

	c.entries[key] = &CacheEntry{
		Msg:       msg.Copy(),
		ExpiresAt: time.Now().Add(ttl),
	}
}

// evict removes expired entries (must be called with lock held)
func (c *DNSCache) evict() {
	now := time.Now()
	for key, entry := range c.entries {
		if now.After(entry.ExpiresAt) {
			delete(c.entries, key)
		}
	}
	// If still full, remove oldest entries
	if len(c.entries) >= c.maxSize {
		count := 0
		for key := range c.entries {
			if count >= c.maxSize/4 {
				break
			}
			delete(c.entries, key)
			count++
		}
	}
}

// Clear removes all cache entries
func (c *DNSCache) Clear() {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.entries = make(map[string]*CacheEntry)
}

// Size returns the number of cached entries
func (c *DNSCache) Size() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return len(c.entries)
}

// New creates a new DNS server
func New(cfg *config.Config, filterEngine *filtering.Engine, statsCollector *stats.Collector) *Server {
	ctx, cancel := context.WithCancel(context.Background())

	cacheSize := cfg.DNS.CacheSize
	if cacheSize <= 0 {
		cacheSize = 10000
	}

	return &Server{
		cfg:        cfg,
		filter:     filterEngine,
		stats:      statsCollector,
		cache:      NewDNSCache(cacheSize),
		upstream:   NewUpstreamResolver(cfg),
		ctx:        ctx,
		cancelFunc: cancel,
	}
}

// Start starts the DNS server on both UDP and TCP
func (s *Server) Start() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.running {
		return fmt.Errorf("DNS server is already running")
	}

	addr := fmt.Sprintf("%s:%d", s.cfg.DNS.BindHost, s.cfg.DNS.Port)

	handler := dns.HandlerFunc(s.handleDNS)

	s.udpServer = &dns.Server{
		Addr:    addr,
		Net:     "udp",
		Handler: handler,
	}

	s.tcpServer = &dns.Server{
		Addr:    addr,
		Net:     "tcp",
		Handler: handler,
	}

	errChan := make(chan error, 2)

	go func() {
		log.Printf("[DNS] Starting UDP server on %s", addr)
		if err := s.udpServer.ListenAndServe(); err != nil {
			errChan <- fmt.Errorf("UDP server error: %w", err)
		}
	}()

	go func() {
		log.Printf("[DNS] Starting TCP server on %s", addr)
		if err := s.tcpServer.ListenAndServe(); err != nil {
			errChan <- fmt.Errorf("TCP server error: %w", err)
		}
	}()

	// Wait a moment for servers to start
	time.Sleep(100 * time.Millisecond)

	select {
	case err := <-errChan:
		return err
	default:
		s.running = true
		log.Printf("[DNS] Server started successfully on %s (UDP+TCP)", addr)
	}

	// Start encrypted DNS servers
	if err := s.StartDoH(); err != nil {
		log.Printf("[DNS] Warning: DoH server failed to start: %v", err)
	}
	if err := s.StartDoT(); err != nil {
		log.Printf("[DNS] Warning: DoT server failed to start: %v", err)
	}

	return nil
}

// Stop gracefully shuts down the DNS server
func (s *Server) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running {
		return nil
	}

	s.cancelFunc()

	// Stop encrypted DNS servers
	s.StopDoH()
	s.StopDoT()

	var errs []string
	if s.udpServer != nil {
		if err := s.udpServer.Shutdown(); err != nil {
			errs = append(errs, fmt.Sprintf("UDP: %v", err))
		}
	}
	if s.tcpServer != nil {
		if err := s.tcpServer.Shutdown(); err != nil {
			errs = append(errs, fmt.Sprintf("TCP: %v", err))
		}
	}

	s.running = false
	log.Println("[DNS] Server stopped")

	if len(errs) > 0 {
		return fmt.Errorf("errors stopping DNS server: %s", strings.Join(errs, "; "))
	}
	return nil
}

// handleDNS is the main DNS request handler
func (s *Server) handleDNS(w dns.ResponseWriter, r *dns.Msg) {
	startTime := time.Now()

	if len(r.Question) == 0 {
		dns.HandleFailed(w, r)
		return
	}

	question := r.Question[0]
	domain := strings.TrimSuffix(strings.ToLower(question.Name), ".")
	qType := dns.TypeToString[question.Qtype]

	// Get client IP
	clientIP := ""
	if addr, ok := w.RemoteAddr().(*net.UDPAddr); ok {
		clientIP = addr.IP.String()
	} else if addr, ok := w.RemoteAddr().(*net.TCPAddr); ok {
		clientIP = addr.IP.String()
	}

	// Check access control
	if !s.checkAccess(clientIP) {
		log.Printf("[DNS] Access denied for client %s", clientIP)
		refuse(w, r)
		return
	}

	// Check rate limiting
	// TODO: Implement per-client rate limiting

	// Log query
	log.Printf("[DNS] Query from %s: %s %s", clientIP, domain, qType)

	// Check filtering
	if s.cfg.Filtering.Enabled {
		result := s.filter.Check(domain, clientIP)
		if result.IsBlocked {
			log.Printf("[DNS] Blocked: %s (reason: %s, rule: %s)", domain, result.Reason, result.Rule)
			s.stats.RecordQuery(domain, qType, clientIP, true, result.Reason, time.Since(startTime))
			s.writeBlockedResponse(w, r, result)
			return
		}
	}

	// Check cache
	if s.cfg.DNS.CacheEnabled {
		cacheKey := fmt.Sprintf("%s_%d_%d", question.Name, question.Qtype, question.Qclass)
		if cachedMsg, found := s.cache.Get(cacheKey); found {
			cachedMsg.Id = r.Id
			if err := w.WriteMsg(cachedMsg); err != nil {
				log.Printf("[DNS] Cache write error: %v", err)
			}
			s.stats.RecordQuery(domain, qType, clientIP, false, "cached", time.Since(startTime))
			return
		}
	}

	// Forward to upstream
	resp, err := s.upstream.Resolve(r)
	if err != nil {
		log.Printf("[DNS] Upstream error for %s: %v", domain, err)
		dns.HandleFailed(w, r)
		s.stats.RecordQuery(domain, qType, clientIP, false, "error", time.Since(startTime))
		return
	}

	// Cache the response
	if s.cfg.DNS.CacheEnabled && resp != nil && resp.Rcode == dns.RcodeSuccess {
		ttl := s.getResponseTTL(resp)
		if ttl > 0 {
			cacheKey := fmt.Sprintf("%s_%d_%d", question.Name, question.Qtype, question.Qclass)
			s.cache.Set(cacheKey, resp, ttl)
		}
	}

	// Write response
	resp.Id = r.Id
	if err := w.WriteMsg(resp); err != nil {
		log.Printf("[DNS] Write error: %v", err)
	}

	s.stats.RecordQuery(domain, qType, clientIP, false, "resolved", time.Since(startTime))
}

// writeBlockedResponse sends a blocked response (NXDOMAIN or 0.0.0.0)
func (s *Server) writeBlockedResponse(w dns.ResponseWriter, r *dns.Msg, result filtering.Result) {
	resp := new(dns.Msg)
	resp.SetReply(r)
	resp.Authoritative = true

	question := r.Question[0]

	switch question.Qtype {
	case dns.TypeA:
		// Return 0.0.0.0 for blocked domains
		resp.Answer = append(resp.Answer, &dns.A{
			Hdr: dns.RR_Header{
				Name:   question.Name,
				Rrtype: dns.TypeA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			A: net.ParseIP("0.0.0.0"),
		})
	case dns.TypeAAAA:
		// Return :: for blocked domains
		resp.Answer = append(resp.Answer, &dns.AAAA{
			Hdr: dns.RR_Header{
				Name:   question.Name,
				Rrtype: dns.TypeAAAA,
				Class:  dns.ClassINET,
				Ttl:    300,
			},
			AAAA: net.ParseIP("::"),
		})
	default:
		resp.Rcode = dns.RcodeNameError
	}

	if err := w.WriteMsg(resp); err != nil {
		log.Printf("[DNS] Failed to write blocked response: %v", err)
	}
}

// checkAccess verifies if a client is allowed to query
func (s *Server) checkAccess(clientIP string) bool {
	access := s.cfg.Access

	// If allowed list is set, only those clients can access
	if len(access.AllowedClients) > 0 {
		for _, allowed := range access.AllowedClients {
			if matchClient(clientIP, allowed) {
				return true
			}
		}
		return false
	}

	// Check disallowed list
	for _, disallowed := range access.DisallowedClients {
		if matchClient(clientIP, disallowed) {
			return false
		}
	}

	return true
}

// matchClient checks if clientIP matches a pattern (IP, CIDR)
func matchClient(clientIP, pattern string) bool {
	// Direct IP match
	if clientIP == pattern {
		return true
	}

	// CIDR match
	_, network, err := net.ParseCIDR(pattern)
	if err == nil {
		ip := net.ParseIP(clientIP)
		if ip != nil && network.Contains(ip) {
			return true
		}
	}

	return false
}

// refuse sends a REFUSED response
func refuse(w dns.ResponseWriter, r *dns.Msg) {
	resp := new(dns.Msg)
	resp.SetRcode(r, dns.RcodeRefused)
	w.WriteMsg(resp)
}

// getResponseTTL extracts TTL from response for caching
func (s *Server) getResponseTTL(msg *dns.Msg) time.Duration {
	minTTL := uint32(s.cfg.DNS.CacheTTLMax)

	for _, rr := range msg.Answer {
		if rr.Header().Ttl < minTTL {
			minTTL = rr.Header().Ttl
		}
	}

	ttl := int(minTTL)
	if ttl < s.cfg.DNS.CacheTTLMin {
		ttl = s.cfg.DNS.CacheTTLMin
	}
	if ttl > s.cfg.DNS.CacheTTLMax {
		ttl = s.cfg.DNS.CacheTTLMax
	}

	return time.Duration(ttl) * time.Second
}

// ClearCache clears the DNS cache
func (s *Server) ClearCache() {
	s.cache.Clear()
	log.Println("[DNS] Cache cleared")
}

// CacheSize returns the number of cached entries
func (s *Server) CacheSize() int {
	return s.cache.Size()
}

// IsRunning returns whether the server is running
func (s *Server) IsRunning() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.running
}
