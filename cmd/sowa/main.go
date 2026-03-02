package main

import (
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"

	"github.com/AristarhUcolov/CNS-SOWA-SECURITY/internal/api"
	"github.com/AristarhUcolov/CNS-SOWA-SECURITY/internal/auth"
	"github.com/AristarhUcolov/CNS-SOWA-SECURITY/internal/config"
	"github.com/AristarhUcolov/CNS-SOWA-SECURITY/internal/dhcp"
	"github.com/AristarhUcolov/CNS-SOWA-SECURITY/internal/dnsserver"
	"github.com/AristarhUcolov/CNS-SOWA-SECURITY/internal/filtering"
	"github.com/AristarhUcolov/CNS-SOWA-SECURITY/internal/stats"
)

const (
	appName    = "S.O.W.A Security"
	appVersion = "1.0.0"
	banner     = `
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║     ███████╗ ██████╗ ██╗    ██╗ █████╗                       ║
║     ██╔════╝██╔═══██╗██║    ██║██╔══██╗                      ║
║     ███████╗██║   ██║██║ █╗ ██║███████║                      ║
║     ╚════██║██║   ██║██║███╗██║██╔══██║                      ║
║     ███████║╚██████╔╝╚███╔███╔╝██║  ██║                      ║
║     ╚══════╝ ╚═════╝  ╚══╝╚══╝ ╚═╝  ╚═╝                      ║
║                                                              ║
║         S.O.W.A Security Software v1.0.0                     ║
║         DNS Protection & Filtering                           ║
║         by C.N.S (Clear Net Sky)                             ║
║                                                              ║
║         https://github.com/AristarhUcolov/CNS-SOWA-SECURITY ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
`
)

func main() {
	// Parse command-line flags
	var (
		dataDir    string
		webDir     string
		configFile string
		dnsPort    int
		webPort    int
		bindHost   string
		showHelp   bool
		showVer    bool
	)

	flag.StringVar(&dataDir, "data", "./data", "Data directory for configs, lists, and stats")
	flag.StringVar(&webDir, "web", "./web", "Web UI directory")
	flag.StringVar(&configFile, "config", "", "Config file path (defaults to data/config/config.json)")
	flag.IntVar(&dnsPort, "dns-port", 0, "DNS server port (overrides config)")
	flag.IntVar(&webPort, "web-port", 0, "Web interface port (overrides config)")
	flag.StringVar(&bindHost, "host", "", "Bind host (overrides config)")
	flag.BoolVar(&showHelp, "help", false, "Show help")
	flag.BoolVar(&showVer, "version", false, "Show version")
	flag.Parse()

	if showHelp {
		fmt.Print(banner)
		flag.Usage()
		return
	}

	if showVer {
		fmt.Printf("%s v%s\n", appName, appVersion)
		return
	}

	// Print banner
	fmt.Print(banner)

	// Resolve paths
	execPath, err := os.Executable()
	if err != nil {
		log.Fatalf("[Main] Failed to get executable path: %v", err)
	}
	execDir := filepath.Dir(execPath)

	// If data dir is relative, make it relative to executable
	if !filepath.IsAbs(dataDir) {
		dataDir = filepath.Join(execDir, dataDir)
	}
	if !filepath.IsAbs(webDir) {
		webDir = filepath.Join(execDir, webDir)
	}

	// Ensure directories exist
	for _, dir := range []string{
		dataDir,
		filepath.Join(dataDir, "blacklist"),
		filepath.Join(dataDir, "whitelist"),
		filepath.Join(dataDir, "config"),
	} {
		if err := os.MkdirAll(dir, 0755); err != nil {
			log.Fatalf("[Main] Failed to create directory %s: %v", dir, err)
		}
	}

	// Load configuration
	if configFile == "" {
		configFile = filepath.Join(dataDir, "config", "config.json")
	}
	config.SetConfigDir(filepath.Dir(configFile))

	log.Printf("[Main] Loading config from %s", configFile)
	cfg, err := config.Load(configFile)
	if err != nil {
		log.Fatalf("[Main] Failed to load config: %v", err)
	}

	// Apply CLI overrides
	if dnsPort > 0 {
		cfg.DNS.Port = dnsPort
	}
	if webPort > 0 {
		cfg.Web.Port = webPort
	}
	if bindHost != "" {
		cfg.DNS.BindHost = bindHost
		cfg.Web.BindHost = bindHost
	}

	// Initialize components
	log.Println("[Main] Initializing S.O.W.A Security...")

	// Stats collector
	statsCollector := stats.NewCollector(dataDir)
	statsCollector.Start()

	// Filtering engine
	filterEngine := filtering.New(cfg, dataDir)
	if err := filterEngine.Start(); err != nil {
		log.Printf("[Main] Warning: filtering engine error: %v", err)
	}

	// DNS server
	dnsServer := dnsserver.New(cfg, filterEngine, statsCollector)
	if err := dnsServer.Start(); err != nil {
		log.Printf("[Main] Warning: DNS server failed to start: %v", err)
		log.Println("[Main] The DNS server might need administrator privileges for port 53")
		log.Println("[Main] Try running with --dns-port 5353 for non-privileged port")
	}

	// DHCP server
	dhcpServer := dhcp.New(cfg)
	if cfg.DHCP.Enabled {
		if err := dhcpServer.Start(); err != nil {
			log.Printf("[Main] Warning: DHCP server failed to start: %v", err)
		}
	}

	// Authentication manager
	authManager := auth.New(cfg)
	if !authManager.IsConfigured() {
		log.Println("[Main] ⚠ Authentication is not configured! Visit the web UI to set up a password.")
	}

	// API/Web server
	apiServer := api.New(cfg, dnsServer, filterEngine, dhcpServer, statsCollector, authManager, webDir)
	if err := apiServer.Start(); err != nil {
		log.Fatalf("[Main] Failed to start web server: %v", err)
	}

	log.Println("[Main] ════════════════════════════════════════════")
	log.Printf("[Main]  S.O.W.A Security is running!")
	log.Printf("[Main]  DNS Server:    %s:%d", cfg.DNS.BindHost, cfg.DNS.Port)
	if cfg.DNS.DOHEnabled {
		log.Printf("[Main]  DNS-over-HTTPS: %s:%d", cfg.DNS.BindHost, cfg.DNS.DOHPort)
	}
	if cfg.DNS.DOTEnabled {
		log.Printf("[Main]  DNS-over-TLS:   %s:%d", cfg.DNS.BindHost, cfg.DNS.DOTPort)
	}
	log.Printf("[Main]  Web Interface: http://%s:%d", cfg.Web.BindHost, cfg.Web.Port)
	log.Printf("[Main]  Data Dir:      %s", dataDir)
	log.Println("[Main] ════════════════════════════════════════════")

	// Wait for shutdown signal
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, syscall.SIGINT, syscall.SIGTERM)
	<-sigChan

	log.Println("[Main] Shutting down S.O.W.A Security...")

	// Graceful shutdown
	apiServer.Stop()
	dnsServer.Stop()
	dhcpServer.Stop()
	statsCollector.Stop()
	cfg.Save()

	log.Println("[Main] S.O.W.A Security stopped. Stay safe!")
}
