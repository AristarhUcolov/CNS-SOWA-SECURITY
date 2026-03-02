package filtering

import (
	"bufio"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/AristarhUcolov/CNS-SOWA-SECURITY/internal/config"
)

// Result represents the result of a domain check
type Result struct {
	IsBlocked bool   `json:"is_blocked"`
	Reason    string `json:"reason"`    // "blocklist", "safesearch", "parental", "custom_rule", etc.
	Rule      string `json:"rule"`      // The specific rule that matched
	ListName  string `json:"list_name"` // Name of the blocklist
}

// Engine is the main filtering engine
type Engine struct {
	cfg          *config.Config
	blockedMap   map[string]*BlockInfo
	whitelistMap map[string]bool
	customRules  map[string]bool
	safeSearch   *SafeSearch
	mu           sync.RWMutex
	dataDir      string
	lastUpdate   time.Time
	totalRules   int
}

// BlockInfo stores info about why a domain is blocked
type BlockInfo struct {
	ListName string
	Rule     string
}

// New creates a new filtering engine
func New(cfg *config.Config, dataDir string) *Engine {
	e := &Engine{
		cfg:          cfg,
		blockedMap:   make(map[string]*BlockInfo),
		whitelistMap: make(map[string]bool),
		customRules:  make(map[string]bool),
		safeSearch:   NewSafeSearch(cfg),
		dataDir:      dataDir,
	}
	return e
}

// Start initializes the filtering engine and loads all lists
func (e *Engine) Start() error {
	log.Println("[Filter] Starting filtering engine...")

	// Load blocklists
	if err := e.LoadBlockLists(); err != nil {
		log.Printf("[Filter] Warning: error loading blocklists: %v", err)
	}

	// Load whitelists
	if err := e.LoadWhiteLists(); err != nil {
		log.Printf("[Filter] Warning: error loading whitelists: %v", err)
	}

	// Load custom rules
	e.loadCustomRules()

	log.Printf("[Filter] Engine started with %d blocked domains", e.totalRules)
	return nil
}

// Check verifies if a domain should be blocked
func (e *Engine) Check(domain, clientIP string) Result {
	if !e.cfg.Filtering.Enabled {
		return Result{IsBlocked: false}
	}

	domain = strings.ToLower(strings.TrimSuffix(domain, "."))

	// Check whitelist first
	if e.isWhitelisted(domain) {
		return Result{IsBlocked: false}
	}

	// Check custom rules
	if rule, blocked := e.checkCustomRules(domain); blocked {
		return Result{
			IsBlocked: true,
			Reason:    "custom_rule",
			Rule:      rule,
			ListName:  "Custom Rules",
		}
	}

	// Check Safe Search
	if e.cfg.Filtering.SafeSearch.Enabled {
		if result := e.safeSearch.Check(domain); result.IsBlocked {
			return result
		}
	}

	// Check per-client config
	clientCfg := e.getClientConfig(clientIP)
	if clientCfg != nil && !clientCfg.FilteringEnabled {
		return Result{IsBlocked: false}
	}

	// Check blocklists
	e.mu.RLock()
	defer e.mu.RUnlock()

	// Exact match
	if info, ok := e.blockedMap[domain]; ok {
		return Result{
			IsBlocked: true,
			Reason:    "blocklist",
			Rule:      info.Rule,
			ListName:  info.ListName,
		}
	}

	// Subdomain match - check parent domains
	parts := strings.Split(domain, ".")
	for i := 1; i < len(parts); i++ {
		parent := strings.Join(parts[i:], ".")
		if info, ok := e.blockedMap[parent]; ok {
			return Result{
				IsBlocked: true,
				Reason:    "blocklist",
				Rule:      fmt.Sprintf("*.%s", info.Rule),
				ListName:  info.ListName,
			}
		}
	}

	return Result{IsBlocked: false}
}

// LoadBlockLists downloads and loads all enabled blocklists
func (e *Engine) LoadBlockLists() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.blockedMap = make(map[string]*BlockInfo)
	e.totalRules = 0

	for _, bl := range e.cfg.Filtering.BlockLists {
		if !bl.Enabled {
			continue
		}

		var domains []string
		var err error

		switch bl.Type {
		case "url":
			domains, err = e.downloadList(bl.URL, bl.Name)
		case "file":
			domains, err = e.loadListFromFile(bl.URL)
		default:
			domains, err = e.downloadList(bl.URL, bl.Name)
		}

		if err != nil {
			log.Printf("[Filter] Error loading blocklist '%s': %v", bl.Name, err)
			continue
		}

		for _, domain := range domains {
			e.blockedMap[domain] = &BlockInfo{
				ListName: bl.Name,
				Rule:     domain,
			}
		}

		e.totalRules += len(domains)
		log.Printf("[Filter] Loaded blocklist '%s': %d domains", bl.Name, len(domains))
	}

	e.lastUpdate = time.Now()
	return nil
}

// LoadWhiteLists loads all enabled whitelists
func (e *Engine) LoadWhiteLists() error {
	e.mu.Lock()
	defer e.mu.Unlock()

	e.whitelistMap = make(map[string]bool)

	for _, wl := range e.cfg.Filtering.WhiteLists {
		if !wl.Enabled {
			continue
		}

		var domains []string
		var err error

		switch wl.Type {
		case "url":
			domains, err = e.downloadList(wl.URL, wl.Name)
		case "file":
			domains, err = e.loadListFromFile(wl.URL)
		default:
			domains, err = e.downloadList(wl.URL, wl.Name)
		}

		if err != nil {
			log.Printf("[Filter] Error loading whitelist '%s': %v", wl.Name, err)
			continue
		}

		for _, domain := range domains {
			e.whitelistMap[domain] = true
		}

		log.Printf("[Filter] Loaded whitelist '%s': %d domains", wl.Name, len(domains))
	}

	return nil
}

// downloadList downloads a blocklist from a URL and saves it locally
func (e *Engine) downloadList(url, name string) ([]string, error) {
	// Check if we have a cached version
	cacheFile := filepath.Join(e.dataDir, "blacklist", sanitizeFilename(name)+".txt")

	// Try to download
	log.Printf("[Filter] Downloading list '%s' from %s", name, url)

	client := &http.Client{Timeout: 30 * time.Second}
	resp, err := client.Get(url)
	if err != nil {
		// Try to use cached version
		log.Printf("[Filter] Download failed, trying cached version: %v", err)
		return e.loadListFromFile(cacheFile)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return e.loadListFromFile(cacheFile)
	}

	// Parse and save
	domains := parseHostsList(resp.Body)

	// Save to cache
	if err := e.saveListToFile(cacheFile, domains); err != nil {
		log.Printf("[Filter] Warning: failed to cache list '%s': %v", name, err)
	}

	return domains, nil
}

// loadListFromFile loads a blocklist from a local file
func (e *Engine) loadListFromFile(path string) ([]string, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file %s: %w", path, err)
	}
	defer file.Close()

	return parseHostsList(file), nil
}

// saveListToFile saves domains to a local file
func (e *Engine) saveListToFile(path string, domains []string) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return err
	}

	file, err := os.Create(path)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	for _, domain := range domains {
		fmt.Fprintln(writer, domain)
	}
	return writer.Flush()
}

// parseHostsList parses a hosts-file or domain list
func parseHostsList(r io.Reader) []string {
	var domains []string
	scanner := bufio.NewScanner(r)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}

		// Handle hosts file format: "0.0.0.0 domain.com" or "127.0.0.1 domain.com"
		if strings.HasPrefix(line, "0.0.0.0") || strings.HasPrefix(line, "127.0.0.1") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				domain := strings.ToLower(parts[1])
				if isValidDomain(domain) {
					domains = append(domains, domain)
				}
			}
			continue
		}

		// Handle AdGuard-style rules: "||domain.com^"
		if strings.HasPrefix(line, "||") {
			domain := strings.TrimPrefix(line, "||")
			domain = strings.TrimSuffix(domain, "^")
			domain = strings.TrimSuffix(domain, "$important")
			domain = strings.Split(domain, "$")[0]
			domain = strings.ToLower(domain)
			if isValidDomain(domain) {
				domains = append(domains, domain)
			}
			continue
		}

		// Handle plain domain format
		domain := strings.ToLower(line)
		if isValidDomain(domain) {
			domains = append(domains, domain)
		}
	}

	return domains
}

// isValidDomain performs basic domain validation
func isValidDomain(domain string) bool {
	if len(domain) == 0 || len(domain) > 253 {
		return false
	}
	if domain == "localhost" || domain == "local" {
		return false
	}
	if !strings.Contains(domain, ".") {
		return false
	}
	// Basic character check
	for _, c := range domain {
		if !((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

// isWhitelisted checks if a domain is in the whitelist
func (e *Engine) isWhitelisted(domain string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()

	if e.whitelistMap[domain] {
		return true
	}

	// Check parent domains
	parts := strings.Split(domain, ".")
	for i := 1; i < len(parts); i++ {
		parent := strings.Join(parts[i:], ".")
		if e.whitelistMap[parent] {
			return true
		}
	}

	return false
}

// checkCustomRules checks domain against custom user rules
func (e *Engine) checkCustomRules(domain string) (string, bool) {
	for _, rule := range e.cfg.Filtering.CustomRules {
		rule = strings.TrimSpace(rule)
		if rule == "" || strings.HasPrefix(rule, "#") {
			continue
		}

		// Allow rules start with @@
		if strings.HasPrefix(rule, "@@") {
			continue
		}

		// Block rules
		ruleStr := strings.TrimPrefix(rule, "||")
		ruleStr = strings.TrimSuffix(ruleStr, "^")
		ruleStr = strings.ToLower(ruleStr)

		if domain == ruleStr || strings.HasSuffix(domain, "."+ruleStr) {
			return rule, true
		}
	}

	return "", false
}

// loadCustomRules loads custom rules from config
func (e *Engine) loadCustomRules() {
	e.customRules = make(map[string]bool)
	for _, rule := range e.cfg.Filtering.CustomRules {
		rule = strings.TrimSpace(rule)
		if rule != "" && !strings.HasPrefix(rule, "#") {
			e.customRules[rule] = true
		}
	}
}

// getClientConfig retrieves per-client configuration
func (e *Engine) getClientConfig(clientIP string) *config.ClientConfig {
	for i, client := range e.cfg.Clients {
		for _, id := range client.IDs {
			if id == clientIP {
				return &e.cfg.Clients[i]
			}
		}
	}
	return nil
}

// sanitizeFilename makes a string safe for use as a filename
func sanitizeFilename(name string) string {
	replacer := strings.NewReplacer(
		"/", "_",
		"\\", "_",
		":", "_",
		"*", "_",
		"?", "_",
		"\"", "_",
		"<", "_",
		">", "_",
		"|", "_",
		" ", "_",
	)
	return replacer.Replace(name)
}

// GetStats returns filtering statistics
func (e *Engine) GetStats() map[string]interface{} {
	e.mu.RLock()
	defer e.mu.RUnlock()

	return map[string]interface{}{
		"total_rules":    e.totalRules,
		"blocklists":     len(e.cfg.Filtering.BlockLists),
		"whitelists":     len(e.cfg.Filtering.WhiteLists),
		"custom_rules":   len(e.cfg.Filtering.CustomRules),
		"last_update":    e.lastUpdate.Format(time.RFC3339),
		"whitelist_size": len(e.whitelistMap),
	}
}

// AddCustomRule adds a custom filtering rule
func (e *Engine) AddCustomRule(rule string) {
	e.cfg.Filtering.CustomRules = append(e.cfg.Filtering.CustomRules, rule)
	e.loadCustomRules()
}

// RemoveCustomRule removes a custom filtering rule
func (e *Engine) RemoveCustomRule(rule string) {
	var newRules []string
	for _, r := range e.cfg.Filtering.CustomRules {
		if r != rule {
			newRules = append(newRules, r)
		}
	}
	e.cfg.Filtering.CustomRules = newRules
	e.loadCustomRules()
}

// GetSafeSearchRewrite returns the safe search CNAME target for a domain, if any
func (e *Engine) GetSafeSearchRewrite(domain string) (string, bool) {
	if e.safeSearch == nil || !e.cfg.Filtering.SafeSearch.Enabled {
		return "", false
	}
	return e.safeSearch.GetRewrite(domain)
}

// Refresh reloads all lists
func (e *Engine) Refresh() error {
	if err := e.LoadBlockLists(); err != nil {
		return err
	}
	if err := e.LoadWhiteLists(); err != nil {
		return err
	}
	e.loadCustomRules()
	return nil
}
