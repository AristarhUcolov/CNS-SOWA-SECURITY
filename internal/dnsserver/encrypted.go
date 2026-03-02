package dnsserver

import (
	"crypto/tls"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"

	"github.com/miekg/dns"
)

// DoHServer handles DNS-over-HTTPS incoming queries
type DoHServer struct {
	server   *Server
	httpSrv  *http.Server
	certFile string
	keyFile  string
	addr     string
}

// DoTServer handles DNS-over-TLS incoming queries
type DoTServer struct {
	server   *Server
	listener net.Listener
	certFile string
	keyFile  string
	addr     string
	running  bool
}

// StartDoH starts the DNS-over-HTTPS server
func (s *Server) StartDoH() error {
	if !s.cfg.DNS.DOHEnabled {
		return nil
	}

	if s.cfg.DNS.DOHCert == "" || s.cfg.DNS.DOHKey == "" {
		return fmt.Errorf("DoH requires TLS certificate and key")
	}

	addr := fmt.Sprintf("%s:%d", s.cfg.DNS.BindHost, s.cfg.DNS.DOHPort)

	mux := http.NewServeMux()
	doh := &DoHServer{
		server:   s,
		certFile: s.cfg.DNS.DOHCert,
		keyFile:  s.cfg.DNS.DOHKey,
		addr:     addr,
	}

	mux.HandleFunc("/dns-query", doh.handleDoHQuery)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("S.O.W.A Security - DNS-over-HTTPS Server"))
	})

	doh.httpSrv = &http.Server{
		Addr:    addr,
		Handler: mux,
	}

	s.dohServer = doh

	go func() {
		log.Printf("[DNS] Starting DNS-over-HTTPS server on %s", addr)
		if err := doh.httpSrv.ListenAndServeTLS(doh.certFile, doh.keyFile); err != nil && err != http.ErrServerClosed {
			log.Printf("[DNS] DoH server error: %v", err)
		}
	}()

	return nil
}

// StartDoT starts the DNS-over-TLS server
func (s *Server) StartDoT() error {
	if !s.cfg.DNS.DOTEnabled {
		return nil
	}

	if s.cfg.DNS.DOTCert == "" || s.cfg.DNS.DOTKey == "" {
		return fmt.Errorf("DoT requires TLS certificate and key")
	}

	addr := fmt.Sprintf("%s:%d", s.cfg.DNS.BindHost, s.cfg.DNS.DOTPort)

	cert, err := tls.LoadX509KeyPair(s.cfg.DNS.DOTCert, s.cfg.DNS.DOTKey)
	if err != nil {
		return fmt.Errorf("failed to load DoT certificates: %w", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		NextProtos:   []string{"dot"},
	}

	listener, err := tls.Listen("tcp", addr, tlsConfig)
	if err != nil {
		return fmt.Errorf("failed to start DoT listener: %w", err)
	}

	dot := &DoTServer{
		server:   s,
		listener: listener,
		certFile: s.cfg.DNS.DOTCert,
		keyFile:  s.cfg.DNS.DOTKey,
		addr:     addr,
		running:  true,
	}

	s.dotServer = dot

	go func() {
		log.Printf("[DNS] Starting DNS-over-TLS server on %s", addr)
		dot.serve()
	}()

	return nil
}

// handleDoHQuery handles DNS-over-HTTPS requests (RFC 8484)
func (doh *DoHServer) handleDoHQuery(w http.ResponseWriter, r *http.Request) {
	var dnsMsg []byte
	var err error

	switch r.Method {
	case "GET":
		// GET method: DNS query in ?dns= parameter (base64url encoded)
		dnsParam := r.URL.Query().Get("dns")
		if dnsParam == "" {
			http.Error(w, "Missing dns parameter", http.StatusBadRequest)
			return
		}
		dnsMsg, err = base64.RawURLEncoding.DecodeString(dnsParam)
		if err != nil {
			http.Error(w, "Invalid base64 encoding", http.StatusBadRequest)
			return
		}

	case "POST":
		// POST method: DNS query in request body
		contentType := r.Header.Get("Content-Type")
		if !strings.Contains(contentType, "application/dns-message") {
			http.Error(w, "Content-Type must be application/dns-message", http.StatusUnsupportedMediaType)
			return
		}
		dnsMsg, err = io.ReadAll(io.LimitReader(r.Body, 65535))
		if err != nil {
			http.Error(w, "Failed to read request body", http.StatusBadRequest)
			return
		}

	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Parse DNS message
	req := new(dns.Msg)
	if err := req.Unpack(dnsMsg); err != nil {
		http.Error(w, "Failed to parse DNS message", http.StatusBadRequest)
		return
	}

	// Create a response writer adapter for the DNS handler
	respWriter := &dohResponseWriter{
		remoteAddr: r.RemoteAddr,
	}

	// Handle the DNS query using the same handler as UDP/TCP
	doh.server.handleDNS(respWriter, req)

	// Get the response
	respMsg := respWriter.getResponse()
	if respMsg == nil {
		http.Error(w, "Failed to generate response", http.StatusInternalServerError)
		return
	}

	respBytes, err := respMsg.Pack()
	if err != nil {
		http.Error(w, "Failed to pack response", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/dns-message")
	w.Header().Set("Cache-Control", "no-cache, no-store")
	w.WriteHeader(http.StatusOK)
	w.Write(respBytes)
}

// serve accepts and handles DoT connections
func (dot *DoTServer) serve() {
	for dot.running {
		conn, err := dot.listener.Accept()
		if err != nil {
			if dot.running {
				log.Printf("[DNS] DoT accept error: %v", err)
			}
			continue
		}
		go dot.handleConnection(conn)
	}
}

// handleConnection handles a single DoT connection
func (dot *DoTServer) handleConnection(conn net.Conn) {
	defer conn.Close()

	for {
		// Read DNS message (2-byte length prefix for TCP/TLS)
		lenBuf := make([]byte, 2)
		_, err := io.ReadFull(conn, lenBuf)
		if err != nil {
			return // Connection closed
		}

		msgLen := int(lenBuf[0])<<8 | int(lenBuf[1])
		if msgLen < 12 || msgLen > 65535 {
			return
		}

		msgBuf := make([]byte, msgLen)
		_, err = io.ReadFull(conn, msgBuf)
		if err != nil {
			return
		}

		req := new(dns.Msg)
		if err := req.Unpack(msgBuf); err != nil {
			continue
		}

		// Handle the DNS query
		respWriter := &dotResponseWriter{
			conn:       conn,
			remoteAddr: conn.RemoteAddr(),
		}

		dot.server.handleDNS(respWriter, req)
	}
}

// dohResponseWriter adapts HTTP responses to dns.ResponseWriter interface
type dohResponseWriter struct {
	remoteAddr string
	response   *dns.Msg
}

func (w *dohResponseWriter) LocalAddr() net.Addr {
	return &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 443}
}

func (w *dohResponseWriter) RemoteAddr() net.Addr {
	host, portStr, _ := net.SplitHostPort(w.remoteAddr)
	port := 0
	fmt.Sscanf(portStr, "%d", &port)
	return &net.TCPAddr{IP: net.ParseIP(host), Port: port}
}

func (w *dohResponseWriter) WriteMsg(msg *dns.Msg) error {
	w.response = msg.Copy()
	return nil
}

func (w *dohResponseWriter) Write(b []byte) (int, error) {
	msg := new(dns.Msg)
	if err := msg.Unpack(b); err != nil {
		return 0, err
	}
	w.response = msg
	return len(b), nil
}

func (w *dohResponseWriter) Close() error        { return nil }
func (w *dohResponseWriter) TsigStatus() error   { return nil }
func (w *dohResponseWriter) TsigTimersOnly(bool) {}
func (w *dohResponseWriter) Hijack()             {}

func (w *dohResponseWriter) getResponse() *dns.Msg {
	return w.response
}

// dotResponseWriter adapts TLS connections to dns.ResponseWriter interface
type dotResponseWriter struct {
	conn       net.Conn
	remoteAddr net.Addr
}

func (w *dotResponseWriter) LocalAddr() net.Addr {
	return w.conn.LocalAddr()
}

func (w *dotResponseWriter) RemoteAddr() net.Addr {
	return w.remoteAddr
}

func (w *dotResponseWriter) WriteMsg(msg *dns.Msg) error {
	packed, err := msg.Pack()
	if err != nil {
		return err
	}

	// TCP/TLS uses 2-byte length prefix
	lenBuf := []byte{byte(len(packed) >> 8), byte(len(packed))}
	if _, err := w.conn.Write(lenBuf); err != nil {
		return err
	}
	_, err = w.conn.Write(packed)
	return err
}

func (w *dotResponseWriter) Write(b []byte) (int, error) {
	lenBuf := []byte{byte(len(b) >> 8), byte(len(b))}
	if _, err := w.conn.Write(lenBuf); err != nil {
		return 0, err
	}
	return w.conn.Write(b)
}

func (w *dotResponseWriter) Close() error        { return w.conn.Close() }
func (w *dotResponseWriter) TsigStatus() error   { return nil }
func (w *dotResponseWriter) TsigTimersOnly(bool) {}
func (w *dotResponseWriter) Hijack()             {}

// StopDoH shuts down the DoH server
func (s *Server) StopDoH() {
	if s.dohServer != nil && s.dohServer.httpSrv != nil {
		s.dohServer.httpSrv.Close()
		log.Println("[DNS] DoH server stopped")
	}
}

// StopDoT shuts down the DoT server
func (s *Server) StopDoT() {
	if s.dotServer != nil {
		s.dotServer.running = false
		if s.dotServer.listener != nil {
			s.dotServer.listener.Close()
		}
		log.Println("[DNS] DoT server stopped")
	}
}
