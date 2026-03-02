package api

import (
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/AristarhUcolov/CNS-SOWA-SECURITY/internal/auth"
	"github.com/AristarhUcolov/CNS-SOWA-SECURITY/internal/config"
	"github.com/AristarhUcolov/CNS-SOWA-SECURITY/internal/dhcp"
	"github.com/AristarhUcolov/CNS-SOWA-SECURITY/internal/dnsserver"
	"github.com/AristarhUcolov/CNS-SOWA-SECURITY/internal/filtering"
	"github.com/AristarhUcolov/CNS-SOWA-SECURITY/internal/stats"
)

// Server represents the API/Web server
type Server struct {
	cfg       *config.Config
	dns       *dnsserver.Server
	filter    *filtering.Engine
	dhcp      *dhcp.Server
	stats     *stats.Collector
	auth      *auth.Manager
	httpSrv   *http.Server
	mux       *http.ServeMux
	webDir    string
	startTime time.Time
}

// New creates a new API server
func New(cfg *config.Config, dns *dnsserver.Server, filter *filtering.Engine, dhcpSrv *dhcp.Server, statsCollector *stats.Collector, authMgr *auth.Manager, webDir string) *Server {
	s := &Server{
		cfg:       cfg,
		dns:       dns,
		filter:    filter,
		dhcp:      dhcpSrv,
		stats:     statsCollector,
		auth:      authMgr,
		mux:       http.NewServeMux(),
		webDir:    webDir,
		startTime: time.Now(),
	}

	s.registerRoutes()
	return s
}

// Start starts the HTTP server
func (s *Server) Start() error {
	addr := fmt.Sprintf("%s:%d", s.cfg.Web.BindHost, s.cfg.Web.Port)

	// Wrap handler with auth middleware
	handler := s.corsMiddleware(s.auth.Middleware(s.mux, []string{
		"/api/auth/login",
		"/api/auth/setup",
		"/api/auth/status",
		"/api/system/info",
	}))

	s.httpSrv = &http.Server{
		Addr:    addr,
		Handler: handler,
	}

	log.Printf("[Web] Starting admin interface on http://%s", addr)

	if s.cfg.Web.TLS && s.cfg.Web.CertFile != "" && s.cfg.Web.KeyFile != "" {
		log.Printf("[Web] TLS enabled")
		go func() {
			if err := s.httpSrv.ListenAndServeTLS(s.cfg.Web.CertFile, s.cfg.Web.KeyFile); err != nil && err != http.ErrServerClosed {
				log.Printf("[Web] TLS Server error: %v", err)
			}
		}()
	} else {
		go func() {
			if err := s.httpSrv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
				log.Printf("[Web] Server error: %v", err)
			}
		}()
	}

	return nil
}

// Stop stops the HTTP server
func (s *Server) Stop() error {
	if s.httpSrv != nil {
		return s.httpSrv.Close()
	}
	return nil
}

// registerRoutes sets up all HTTP routes
func (s *Server) registerRoutes() {
	// Auth routes (no auth required)
	s.mux.HandleFunc("/api/auth/login", s.handleLogin)
	s.mux.HandleFunc("/api/auth/logout", s.handleLogout)
	s.mux.HandleFunc("/api/auth/setup", s.handleAuthSetup)
	s.mux.HandleFunc("/api/auth/status", s.handleAuthStatus)
	s.mux.HandleFunc("/api/auth/password", s.handleChangePassword)
	s.mux.HandleFunc("/api/auth/sessions", s.handleSessions)

	// API routes
	s.mux.HandleFunc("/api/stats", s.handleStats)
	s.mux.HandleFunc("/api/config", s.handleConfig)
	s.mux.HandleFunc("/api/protection/toggle", s.handleProtectionToggle)
	s.mux.HandleFunc("/api/filtering/stats", s.handleFilteringStats)
	s.mux.HandleFunc("/api/filtering/refresh", s.handleFilteringRefresh)
	s.mux.HandleFunc("/api/filtering/blocklist", s.handleBlocklistAdd)
	s.mux.HandleFunc("/api/filtering/whitelist", s.handleWhitelistAdd)
	s.mux.HandleFunc("/api/filtering/blocklist/", s.handleBlocklistAction)
	s.mux.HandleFunc("/api/filtering/whitelist/", s.handleWhitelistAction)
	s.mux.HandleFunc("/api/querylog", s.handleQueryLog)
	s.mux.HandleFunc("/api/clients", s.handleClients)
	s.mux.HandleFunc("/api/clients/", s.handleClientAction)
	s.mux.HandleFunc("/api/dhcp/leases", s.handleDHCPLeases)
	s.mux.HandleFunc("/api/dhcp/static", s.handleDHCPStatic)
	s.mux.HandleFunc("/api/cache/clear", s.handleCacheClear)
	s.mux.HandleFunc("/api/status", s.handleStatus)
	s.mux.HandleFunc("/api/test", s.handleTestDomain)
	s.mux.HandleFunc("/api/system/info", s.handleSystemInfo)
	s.mux.HandleFunc("/api/blocked-services", s.handleBlockedServices)
	s.mux.HandleFunc("/api/blocked-services/available", s.handleAvailableServices)
	s.mux.HandleFunc("/api/dns-rewrites", s.handleDNSRewrites)
	s.mux.HandleFunc("/api/querylog/export", s.handleQueryLogExport)
	s.mux.HandleFunc("/api/stats/export", s.handleStatsExport)
	s.mux.HandleFunc("/api/stats/reset", s.handleStatsReset)
	s.mux.HandleFunc("/api/health", s.handleHealth)
	s.mux.HandleFunc("/api/upstream/stats", s.handleUpstreamStats)
	s.mux.HandleFunc("/api/config/backup", s.handleConfigBackup)
	s.mux.HandleFunc("/api/config/restore", s.handleConfigRestore)
	s.mux.HandleFunc("/api/auth/sessions/revoke", s.handleSessionRevoke)

	// Static files (web UI)
	s.mux.Handle("/", http.FileServer(http.Dir(s.webDir)))
}

// corsMiddleware adds CORS headers
func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}

		next.ServeHTTP(w, r)
	})
}

// ==================== Handlers ====================

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	st := s.stats.GetStats()
	jsonResponse(w, st)
}

func (s *Server) handleConfig(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		// Return current config (without sensitive fields)
		jsonResponse(w, s.cfg)

	case "PUT":
		var partial map[string]json.RawMessage
		if err := json.NewDecoder(r.Body).Decode(&partial); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		if err := s.cfg.Update(func(cfg *config.Config) {
			// Apply partial updates
			if dnsData, ok := partial["dns"]; ok {
				json.Unmarshal(dnsData, &cfg.DNS)
			}
			if filterData, ok := partial["filtering"]; ok {
				// Merge filtering config
				var filterPartial map[string]json.RawMessage
				json.Unmarshal(filterData, &filterPartial)

				if v, ok := filterPartial["enabled"]; ok {
					json.Unmarshal(v, &cfg.Filtering.Enabled)
				}
				if v, ok := filterPartial["safe_browsing"]; ok {
					json.Unmarshal(v, &cfg.Filtering.SafeBrowsing)
				}
				if v, ok := filterPartial["parental_control"]; ok {
					json.Unmarshal(v, &cfg.Filtering.ParentalControl)
				}
				if v, ok := filterPartial["safe_search"]; ok {
					json.Unmarshal(v, &cfg.Filtering.SafeSearch)
				}
				if v, ok := filterPartial["custom_rules"]; ok {
					json.Unmarshal(v, &cfg.Filtering.CustomRules)
				}
				if v, ok := filterPartial["blocked_services"]; ok {
					json.Unmarshal(v, &cfg.Filtering.BlockedServices)
				}
				if v, ok := filterPartial["parental"]; ok {
					json.Unmarshal(v, &cfg.Filtering.Parental)
				}
			}
			if dhcpData, ok := partial["dhcp"]; ok {
				json.Unmarshal(dhcpData, &cfg.DHCP)
			}
			if accessData, ok := partial["access"]; ok {
				json.Unmarshal(accessData, &cfg.Access)
			}
			if authData, ok := partial["auth"]; ok {
				json.Unmarshal(authData, &cfg.Auth)
			}
			if webData, ok := partial["web"]; ok {
				json.Unmarshal(webData, &cfg.Web)
			}
		}); err != nil {
			http.Error(w, "Failed to save config", http.StatusInternalServerError)
			return
		}

		// Refresh safe search rewrite map after config change
		s.filter.RefreshSafeSearch()

		jsonResponse(w, map[string]string{"status": "ok"})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleProtectionToggle(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	s.cfg.Filtering.Enabled = !s.cfg.Filtering.Enabled
	s.cfg.Save()

	jsonResponse(w, map[string]bool{"enabled": s.cfg.Filtering.Enabled})
}

func (s *Server) handleFilteringStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	jsonResponse(w, s.filter.GetStats())
}

func (s *Server) handleFilteringRefresh(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	log.Println("[API] Manual blocklist refresh triggered")
	if err := s.filter.Refresh(); err != nil {
		log.Printf("[API] Error refreshing filters: %v", err)
		jsonResponse(w, map[string]interface{}{
			"status": "error",
			"error":  err.Error(),
			"stats":  s.filter.GetStats(),
		})
		return
	}

	stats := s.filter.GetStats()
	log.Printf("[API] Blocklist refresh completed: %v rules loaded", stats["total_rules"])
	jsonResponse(w, map[string]interface{}{
		"status": "ok",
		"stats":  stats,
	})
}

func (s *Server) handleBlocklistAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var bl config.BlockListConfig
	if err := json.NewDecoder(r.Body).Decode(&bl); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	s.cfg.Update(func(cfg *config.Config) {
		cfg.Filtering.BlockLists = append(cfg.Filtering.BlockLists, bl)
	})

	jsonResponse(w, map[string]string{"status": "ok"})
}

func (s *Server) handleWhitelistAdd(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var wl config.WhiteListConfig
	if err := json.NewDecoder(r.Body).Decode(&wl); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	s.cfg.Update(func(cfg *config.Config) {
		cfg.Filtering.WhiteLists = append(cfg.Filtering.WhiteLists, wl)
	})

	jsonResponse(w, map[string]string{"status": "ok"})
}

func (s *Server) handleBlocklistAction(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	parts := strings.Split(strings.TrimSuffix(path, "/"), "/")

	if len(parts) < 4 {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	// Check for toggle action: /api/filtering/blocklist/{index}/toggle
	if len(parts) >= 5 && parts[len(parts)-1] == "toggle" {
		indexStr := parts[len(parts)-2]
		index, err := strconv.Atoi(indexStr)
		if err != nil || index < 0 || index >= len(s.cfg.Filtering.BlockLists) {
			http.Error(w, "Invalid index", http.StatusBadRequest)
			return
		}

		var body struct {
			Enabled bool `json:"enabled"`
		}
		json.NewDecoder(r.Body).Decode(&body)

		s.cfg.Update(func(cfg *config.Config) {
			cfg.Filtering.BlockLists[index].Enabled = body.Enabled
		})
		jsonResponse(w, map[string]string{"status": "ok"})
		return
	}

	// DELETE: /api/filtering/blocklist/{index}
	if r.Method == "DELETE" {
		indexStr := parts[len(parts)-1]
		index, err := strconv.Atoi(indexStr)
		if err != nil || index < 0 || index >= len(s.cfg.Filtering.BlockLists) {
			http.Error(w, "Invalid index", http.StatusBadRequest)
			return
		}

		// Prevent deletion of default blocklists
		if s.cfg.Filtering.BlockLists[index].Default {
			http.Error(w, `{"error":"Cannot delete default blocklist. You can disable it instead."}`, http.StatusForbidden)
			return
		}

		s.cfg.Update(func(cfg *config.Config) {
			cfg.Filtering.BlockLists = append(cfg.Filtering.BlockLists[:index], cfg.Filtering.BlockLists[index+1:]...)
		})
		jsonResponse(w, map[string]string{"status": "ok"})
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func (s *Server) handleWhitelistAction(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	parts := strings.Split(strings.TrimSuffix(path, "/"), "/")

	if len(parts) < 4 {
		http.Error(w, "Invalid path", http.StatusBadRequest)
		return
	}

	// Toggle
	if len(parts) >= 5 && parts[len(parts)-1] == "toggle" {
		indexStr := parts[len(parts)-2]
		index, err := strconv.Atoi(indexStr)
		if err != nil || index < 0 || index >= len(s.cfg.Filtering.WhiteLists) {
			http.Error(w, "Invalid index", http.StatusBadRequest)
			return
		}

		var body struct {
			Enabled bool `json:"enabled"`
		}
		json.NewDecoder(r.Body).Decode(&body)

		s.cfg.Update(func(cfg *config.Config) {
			cfg.Filtering.WhiteLists[index].Enabled = body.Enabled
		})
		jsonResponse(w, map[string]string{"status": "ok"})
		return
	}

	// DELETE
	if r.Method == "DELETE" {
		indexStr := parts[len(parts)-1]
		index, err := strconv.Atoi(indexStr)
		if err != nil || index < 0 || index >= len(s.cfg.Filtering.WhiteLists) {
			http.Error(w, "Invalid index", http.StatusBadRequest)
			return
		}

		s.cfg.Update(func(cfg *config.Config) {
			cfg.Filtering.WhiteLists = append(cfg.Filtering.WhiteLists[:index], cfg.Filtering.WhiteLists[index+1:]...)
		})
		jsonResponse(w, map[string]string{"status": "ok"})
		return
	}

	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
}

func (s *Server) handleQueryLog(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	limitStr := r.URL.Query().Get("limit")
	limit := 100
	if limitStr != "" {
		if v, err := strconv.Atoi(limitStr); err == nil && v > 0 {
			limit = v
		}
	}

	offsetStr := r.URL.Query().Get("offset")
	offset := 0
	if offsetStr != "" {
		if v, err := strconv.Atoi(offsetStr); err == nil && v >= 0 {
			offset = v
		}
	}

	filterType := r.URL.Query().Get("filter")
	search := r.URL.Query().Get("search")

	entries, total := stats.SearchQueryLog(search, filterType, offset, limit)

	jsonResponse(w, map[string]interface{}{
		"entries": entries,
		"total":   total,
		"offset":  offset,
		"limit":   limit,
	})
}

func (s *Server) handleClients(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		jsonResponse(w, s.cfg.Clients)

	case "POST":
		var client config.ClientConfig
		if err := json.NewDecoder(r.Body).Decode(&client); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		s.cfg.Update(func(cfg *config.Config) {
			cfg.Clients = append(cfg.Clients, client)
		})
		jsonResponse(w, map[string]string{"status": "ok"})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleClientAction(w http.ResponseWriter, r *http.Request) {
	if r.Method != "DELETE" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	parts := strings.Split(strings.TrimSuffix(r.URL.Path, "/"), "/")
	indexStr := parts[len(parts)-1]
	index, err := strconv.Atoi(indexStr)
	if err != nil || index < 0 || index >= len(s.cfg.Clients) {
		http.Error(w, "Invalid index", http.StatusBadRequest)
		return
	}

	s.cfg.Update(func(cfg *config.Config) {
		cfg.Clients = append(cfg.Clients[:index], cfg.Clients[index+1:]...)
	})
	jsonResponse(w, map[string]string{"status": "ok"})
}

func (s *Server) handleDHCPLeases(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	jsonResponse(w, s.dhcp.GetLeases())
}

func (s *Server) handleCacheClear(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.dns.ClearCache()
	jsonResponse(w, map[string]string{"status": "ok"})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	uptime := time.Since(s.startTime)
	jsonResponse(w, map[string]interface{}{
		"dns_running":  s.dns.IsRunning(),
		"dhcp_running": s.dhcp.IsRunning(),
		"protection":   s.cfg.Filtering.Enabled,
		"version":      "1.4.1",
		"cache_size":   s.dns.CacheSize(),
		"dhcp_leases":  s.dhcp.GetLeaseCount(),
		"uptime":       int64(uptime.Seconds()),
		"start_time":   s.startTime.Format(time.RFC3339),
	})
}

// ==================== Auth Handlers ====================

func (s *Server) handleAuthStatus(w http.ResponseWriter, r *http.Request) {
	jsonResponse(w, map[string]interface{}{
		"configured": s.auth.IsConfigured(),
		"username":   s.cfg.Auth.Username,
	})
}

func (s *Server) handleAuthSetup(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	if s.auth.IsConfigured() {
		http.Error(w, `{"error":"already configured"}`, http.StatusBadRequest)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if req.Username == "" {
		req.Username = "admin"
	}

	if err := s.auth.SetupPassword(req.Username, req.Password); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusBadRequest)
		return
	}

	log.Printf("[API] Authentication configured for user '%s'", req.Username)
	jsonResponse(w, map[string]string{"status": "ok"})
}

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	ip := strings.Split(r.RemoteAddr, ":")[0]
	resp, err := s.auth.Login(req.Username, req.Password, ip, r.UserAgent())
	if err != nil {
		w.WriteHeader(http.StatusUnauthorized)
		jsonResponse(w, map[string]string{"error": err.Error()})
		return
	}

	// Set session cookie
	http.SetCookie(w, &http.Cookie{
		Name:     "sowa_session",
		Value:    resp.Token,
		Path:     "/",
		HttpOnly: true,
		MaxAge:   s.cfg.Auth.SessionTTL * 3600,
	})

	jsonResponse(w, resp)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Get token from various sources
	token := ""
	if authHeader := r.Header.Get("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
		token = strings.TrimPrefix(authHeader, "Bearer ")
	}
	if token == "" {
		if cookie, err := r.Cookie("sowa_session"); err == nil {
			token = cookie.Value
		}
	}

	if token != "" {
		s.auth.Logout(token)
	}

	// Clear cookie
	http.SetCookie(w, &http.Cookie{
		Name:   "sowa_session",
		Value:  "",
		Path:   "/",
		MaxAge: -1,
	})

	jsonResponse(w, map[string]string{"status": "ok"})
}

func (s *Server) handleChangePassword(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		OldPassword string `json:"old_password"`
		NewPassword string `json:"new_password"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Invalid JSON", http.StatusBadRequest)
		return
	}

	if err := s.auth.ChangePassword(req.OldPassword, req.NewPassword); err != nil {
		http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusBadRequest)
		return
	}

	jsonResponse(w, map[string]string{"status": "ok"})
}

func (s *Server) handleSessions(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	jsonResponse(w, s.auth.GetSessions())
}

// ==================== New Endpoints ====================

func (s *Server) handleDHCPStatic(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "POST":
		var req struct {
			MAC      string `json:"mac"`
			IP       string `json:"ip"`
			Hostname string `json:"hostname"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}

		ip := net.ParseIP(req.IP)
		if ip == nil {
			http.Error(w, `{"error":"invalid IP address"}`, http.StatusBadRequest)
			return
		}

		if err := s.dhcp.AddStaticLease(req.MAC, ip, req.Hostname); err != nil {
			http.Error(w, fmt.Sprintf(`{"error":"%s"}`, err.Error()), http.StatusBadRequest)
			return
		}

		jsonResponse(w, map[string]string{"status": "ok"})

	case "DELETE":
		mac := r.URL.Query().Get("mac")
		if mac == "" {
			http.Error(w, `{"error":"mac parameter required"}`, http.StatusBadRequest)
			return
		}
		s.dhcp.RemoveStaticLease(mac)
		jsonResponse(w, map[string]string{"status": "ok"})

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleTestDomain(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	domain := r.URL.Query().Get("domain")
	if domain == "" {
		http.Error(w, `{"error":"domain parameter required"}`, http.StatusBadRequest)
		return
	}

	result := s.filter.Check(domain, "")
	jsonResponse(w, result)
}

func (s *Server) handleSystemInfo(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Detect local IPs
	var ips []string
	ifaces, err := net.Interfaces()
	if err == nil {
		for _, iface := range ifaces {
			if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
				continue
			}
			addrs, err := iface.Addrs()
			if err != nil {
				continue
			}
			for _, addr := range addrs {
				var ip net.IP
				switch v := addr.(type) {
				case *net.IPNet:
					ip = v.IP
				case *net.IPAddr:
					ip = v.IP
				}
				if ip == nil || ip.IsLoopback() {
					continue
				}
				if ip.To4() != nil && !strings.HasPrefix(ip.String(), "169.254") {
					ips = append(ips, ip.String())
				}
			}
		}
	}

	jsonResponse(w, map[string]interface{}{
		"version":  "1.4.1",
		"dns_port": s.cfg.DNS.Port,
		"web_port": s.cfg.Web.Port,
		"ips":      ips,
	})
}

// ==================== Blocked Services ====================

func (s *Server) handleBlockedServices(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		jsonResponse(w, map[string]interface{}{
			"blocked": s.cfg.Filtering.BlockedServices,
		})
	case "PUT":
		var req struct {
			Services []string `json:"services"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}
		s.cfg.Update(func(cfg *config.Config) {
			cfg.Filtering.BlockedServices = req.Services
		})
		jsonResponse(w, map[string]string{"status": "ok"})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleAvailableServices(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	jsonResponse(w, map[string]interface{}{
		"services": filtering.GetAvailableServices(),
	})
}

// ==================== DNS Rewrites ====================

func (s *Server) handleDNSRewrites(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case "GET":
		jsonResponse(w, map[string]interface{}{
			"rewrites": s.cfg.Filtering.DNSRewrites,
		})
	case "POST":
		var rw config.DNSRewrite
		if err := json.NewDecoder(r.Body).Decode(&rw); err != nil {
			http.Error(w, "Invalid JSON", http.StatusBadRequest)
			return
		}
		if rw.Domain == "" || rw.Answer == "" {
			http.Error(w, `{"error":"domain and answer required"}`, http.StatusBadRequest)
			return
		}
		s.cfg.Update(func(cfg *config.Config) {
			cfg.Filtering.DNSRewrites = append(cfg.Filtering.DNSRewrites, rw)
		})
		jsonResponse(w, map[string]string{"status": "ok"})
	case "DELETE":
		indexStr := r.URL.Query().Get("index")
		index, err := strconv.Atoi(indexStr)
		if err != nil || index < 0 || index >= len(s.cfg.Filtering.DNSRewrites) {
			http.Error(w, `{"error":"invalid index"}`, http.StatusBadRequest)
			return
		}
		s.cfg.Update(func(cfg *config.Config) {
			cfg.Filtering.DNSRewrites = append(cfg.Filtering.DNSRewrites[:index], cfg.Filtering.DNSRewrites[index+1:]...)
		})
		jsonResponse(w, map[string]string{"status": "ok"})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}

// ==================== Export ====================

func (s *Server) handleQueryLogExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	entries, _ := stats.SearchQueryLog("", "", 0, 10000)

	format := r.URL.Query().Get("format")
	if format == "json" {
		w.Header().Set("Content-Disposition", "attachment; filename=querylog.json")
		jsonResponse(w, entries)
		return
	}

	// CSV export
	w.Header().Set("Content-Type", "text/csv")
	w.Header().Set("Content-Disposition", "attachment; filename=querylog.csv")
	fmt.Fprintln(w, "Timestamp,Domain,Type,Client IP,Blocked,Reason,Duration")
	for _, e := range entries {
		fmt.Fprintf(w, "%s,%s,%s,%s,%t,%s,%s\n",
			e.Timestamp.Format("2006-01-02 15:04:05"),
			e.Domain, e.Type, e.ClientIP, e.Blocked, e.Reason, e.Duration)
	}
}

func (s *Server) handleStatsExport(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	st := s.stats.GetStats()
	w.Header().Set("Content-Disposition", "attachment; filename=stats.json")
	jsonResponse(w, st)
}

func (s *Server) handleStatsReset(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	s.stats.Reset()
	jsonResponse(w, map[string]string{"status": "ok"})
}

// ==================== Health ====================

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var mem runtime.MemStats
	runtime.ReadMemStats(&mem)

	uptime := time.Since(s.startTime)

	jsonResponse(w, map[string]interface{}{
		"status":       "ok",
		"uptime":       int64(uptime.Seconds()),
		"uptime_human": formatDuration(uptime),
		"start_time":   s.startTime.Format(time.RFC3339),
		"version":      "1.4.1",
		"go_version":   runtime.Version(),
		"os":           runtime.GOOS,
		"arch":         runtime.GOARCH,
		"goroutines":   runtime.NumGoroutine(),
		"memory": map[string]interface{}{
			"alloc_mb":       float64(mem.Alloc) / 1024 / 1024,
			"total_alloc_mb": float64(mem.TotalAlloc) / 1024 / 1024,
			"sys_mb":         float64(mem.Sys) / 1024 / 1024,
			"num_gc":         mem.NumGC,
		},
		"dns_running":     s.dns.IsRunning(),
		"dhcp_running":    s.dhcp.IsRunning(),
		"protection":      s.cfg.Filtering.Enabled,
		"cache_size":      s.dns.CacheSize(),
		"dns_port":        s.cfg.DNS.Port,
		"web_port":        s.cfg.Web.Port,
		"blocklist_count": len(s.cfg.Filtering.BlockLists),
		"auto_update_hrs": s.cfg.Filtering.AutoUpdateInterval,
	})
}

func formatDuration(d time.Duration) string {
	days := int(d.Hours()) / 24
	hours := int(d.Hours()) % 24
	minutes := int(d.Minutes()) % 60
	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
	return fmt.Sprintf("%dm", minutes)
}

// ==================== Upstream Stats ====================

func (s *Server) handleUpstreamStats(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}
	jsonResponse(w, map[string]interface{}{
		"upstreams": s.dns.GetUpstreamLatency(),
	})
}

// ==================== Config Backup/Restore ====================

func (s *Server) handleConfigBackup(w http.ResponseWriter, r *http.Request) {
	if r.Method != "GET" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Export config as JSON download
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Content-Disposition", "attachment; filename=sowa-config-backup.json")
	json.NewEncoder(w).Encode(s.cfg)
}

func (s *Server) handleConfigRestore(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var incoming config.Config
	if err := json.NewDecoder(r.Body).Decode(&incoming); err != nil {
		http.Error(w, `{"error":"invalid JSON: `+err.Error()+`"}`, http.StatusBadRequest)
		return
	}

	// Apply the restored config (preserve current auth to prevent lockout)
	currentAuth := s.cfg.Auth
	s.cfg.Update(func(cfg *config.Config) {
		cfg.DNS = incoming.DNS
		cfg.Web = incoming.Web
		cfg.Filtering = incoming.Filtering
		cfg.DHCP = incoming.DHCP
		cfg.Clients = incoming.Clients
		cfg.Access = incoming.Access
		// Restore auth only if provided, otherwise keep current
		if incoming.Auth.PasswordHash != "" {
			cfg.Auth = incoming.Auth
		} else {
			cfg.Auth = currentAuth
		}
	})

	log.Println("[API] Configuration restored from backup")
	jsonResponse(w, map[string]string{"status": "ok", "message": "Configuration restored. Restart recommended."})
}

// ==================== Session Management ====================

func (s *Server) handleSessionRevoke(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Token == "" {
		http.Error(w, `{"error":"token required"}`, http.StatusBadRequest)
		return
	}

	s.auth.Logout(req.Token)
	log.Printf("[API] Session revoked")
	jsonResponse(w, map[string]string{"status": "ok"})
}

// ==================== Helpers ====================

func jsonResponse(w http.ResponseWriter, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(data)
}
