package dnsserver

import (
	"crypto/tls"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/AristarhUcolov/CNS-SOWA-SECURITY/internal/config"
	"github.com/miekg/dns"
)

// UpstreamResolver handles forwarding DNS queries to upstream servers
type UpstreamResolver struct {
	cfg       *config.Config
	client    *dns.Client
	tlsClient *dns.Client
	httpClient *http.Client
	mu        sync.RWMutex
}

// NewUpstreamResolver creates a new upstream resolver
func NewUpstreamResolver(cfg *config.Config) *UpstreamResolver {
	return &UpstreamResolver{
		cfg: cfg,
		client: &dns.Client{
			Net:          "udp",
			Timeout:      5 * time.Second,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
		},
		tlsClient: &dns.Client{
			Net: "tcp-tls",
			TLSConfig: &tls.Config{
				MinVersion: tls.VersionTLS12,
			},
			Timeout:      5 * time.Second,
			ReadTimeout:  5 * time.Second,
			WriteTimeout: 5 * time.Second,
		},
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{
					MinVersion: tls.VersionTLS12,
				},
				MaxIdleConns:        100,
				MaxIdleConnsPerHost: 10,
				IdleConnTimeout:     90 * time.Second,
			},
		},
	}
}

// Resolve forwards a DNS query to upstream servers
func (u *UpstreamResolver) Resolve(req *dns.Msg) (*dns.Msg, error) {
	upstreams := u.cfg.DNS.Upstreams
	if len(upstreams) == 0 {
		upstreams = u.cfg.DNS.FallbackServers
	}

	var lastErr error

	for _, upstream := range upstreams {
		resp, err := u.resolveWithUpstream(req, upstream)
		if err != nil {
			lastErr = err
			log.Printf("[Upstream] Error with %s: %v", upstream, err)
			continue
		}
		return resp, nil
	}

	// Try fallback servers
	for _, fallback := range u.cfg.DNS.FallbackServers {
		resp, err := u.resolveWithUpstream(req, fallback)
		if err != nil {
			lastErr = err
			continue
		}
		return resp, nil
	}

	return nil, fmt.Errorf("all upstream servers failed, last error: %w", lastErr)
}

// resolveWithUpstream forwards to a specific upstream server
func (u *UpstreamResolver) resolveWithUpstream(req *dns.Msg, upstream string) (*dns.Msg, error) {
	switch {
	case strings.HasPrefix(upstream, "https://"):
		return u.resolveDoH(req, upstream)
	case strings.HasPrefix(upstream, "tls://"):
		return u.resolveDoT(req, upstream)
	case strings.HasPrefix(upstream, "sdns://"):
		return u.resolveDNSCrypt(req, upstream)
	default:
		return u.resolvePlain(req, upstream)
	}
}

// resolvePlain forwards via plain DNS (UDP/TCP)
func (u *UpstreamResolver) resolvePlain(req *dns.Msg, server string) (*dns.Msg, error) {
	if !strings.Contains(server, ":") {
		server = net.JoinHostPort(server, "53")
	}

	resp, _, err := u.client.Exchange(req, server)
	if err != nil {
		// Retry with TCP
		tcpClient := &dns.Client{
			Net:     "tcp",
			Timeout: 5 * time.Second,
		}
		resp, _, err = tcpClient.Exchange(req, server)
		if err != nil {
			return nil, fmt.Errorf("plain DNS error: %w", err)
		}
	}

	return resp, nil
}

// resolveDoT forwards via DNS-over-TLS
func (u *UpstreamResolver) resolveDoT(req *dns.Msg, server string) (*dns.Msg, error) {
	addr := strings.TrimPrefix(server, "tls://")
	if !strings.Contains(addr, ":") {
		addr = net.JoinHostPort(addr, "853")
	}

	resp, _, err := u.tlsClient.Exchange(req, addr)
	if err != nil {
		return nil, fmt.Errorf("DNS-over-TLS error: %w", err)
	}

	return resp, nil
}

// resolveDoH forwards via DNS-over-HTTPS
func (u *UpstreamResolver) resolveDoH(req *dns.Msg, server string) (*dns.Msg, error) {
	// Pack the DNS message
	packed, err := req.Pack()
	if err != nil {
		return nil, fmt.Errorf("failed to pack DNS message: %w", err)
	}

	// Create HTTP request
	httpReq, err := http.NewRequest("POST", server, strings.NewReader(string(packed)))
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/dns-message")
	httpReq.Header.Set("Accept", "application/dns-message")

	// Send request
	httpResp, err := u.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("DoH request error: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("DoH server returned status %d", httpResp.StatusCode)
	}

	// Read response
	body, err := io.ReadAll(httpResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read DoH response: %w", err)
	}

	// Unpack response
	resp := new(dns.Msg)
	if err := resp.Unpack(body); err != nil {
		return nil, fmt.Errorf("failed to unpack DoH response: %w", err)
	}

	return resp, nil
}

// resolveDNSCrypt forwards via DNSCrypt protocol
func (u *UpstreamResolver) resolveDNSCrypt(req *dns.Msg, server string) (*dns.Msg, error) {
	// DNSCrypt implementation placeholder
	// For now, fall back to the first plain upstream
	log.Printf("[Upstream] DNSCrypt not fully implemented yet, using fallback")
	if len(u.cfg.DNS.FallbackServers) > 0 {
		return u.resolvePlain(req, u.cfg.DNS.FallbackServers[0])
	}
	return nil, fmt.Errorf("DNSCrypt not implemented and no fallback available")
}
