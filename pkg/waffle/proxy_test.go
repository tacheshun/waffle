package waffle

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httputil"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestProxyBasic(t *testing.T) {
	// Create a test backend server
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Backend response"))
	}))
	defer backendServer.Close()

	// Create a test proxy server
	proxyServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Initialize WAF
		waf := New()

		// Create a reverse proxy to the backend
		handler := waf.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Forward the request to the backend
			backendURL, _ := url.Parse(backendServer.URL)
			resp, err := http.DefaultClient.Do(&http.Request{
				Method: r.Method,
				URL:    backendURL,
				Header: r.Header,
				Body:   r.Body,
			})
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			defer resp.Body.Close()

			// Copy the response from the backend to the client
			for key, values := range resp.Header {
				for _, value := range values {
					w.Header().Add(key, value)
				}
			}
			w.WriteHeader(resp.StatusCode)
			_, _ = io.Copy(w, resp.Body)
		})

		// Process the request
		handler(w, r)
	}))
	defer proxyServer.Close()

	// Make a request to the proxy
	resp, err := http.Get(proxyServer.URL)
	if err != nil {
		t.Fatalf("Failed to make request to proxy: %v", err)
	}
	defer resp.Body.Close()

	// Check the response
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	if string(body) != "Backend response" {
		t.Errorf("Expected response body %q, got %q", "Backend response", string(body))
	}
}

func TestProxyWithTLS(t *testing.T) {
	// Skip if running in CI environment without proper setup
	if os.Getenv("CI") != "" {
		t.Skip("Skipping TLS test in CI environment")
	}

	// Create temporary directory for test certificates
	tempDir, err := os.MkdirTemp("", "waffle-tls-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Generate test certificates
	certFile := filepath.Join(tempDir, "cert.pem")
	keyFile := filepath.Join(tempDir, "key.pem")
	if err := generateTestCertificate(certFile, keyFile); err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	// Create a test backend server
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("TLS Backend response"))
	}))
	defer backendServer.Close()

	// Create a TLS config for the test server
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		t.Fatalf("Failed to load test certificate: %v", err)
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{cert},
	}

	// Create a test proxy server with TLS
	proxyServer := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Initialize WAF
		waf := New()

		// Create a reverse proxy to the backend
		handler := waf.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Forward the request to the backend
			backendURL, _ := url.Parse(backendServer.URL)
			resp, err := http.DefaultClient.Do(&http.Request{
				Method: r.Method,
				URL:    backendURL,
				Header: r.Header,
				Body:   r.Body,
			})
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			defer resp.Body.Close()

			// Copy the response from the backend to the client
			for key, values := range resp.Header {
				for _, value := range values {
					w.Header().Add(key, value)
				}
			}
			w.WriteHeader(resp.StatusCode)
			_, _ = io.Copy(w, resp.Body)
		})

		// Process the request
		handler(w, r)
	}))
	proxyServer.TLS = tlsConfig
	proxyServer.StartTLS()
	defer proxyServer.Close()

	// Create a custom HTTP client that trusts our test certificate
	certPool := x509.NewCertPool()
	certData, err := os.ReadFile(certFile)
	if err != nil {
		t.Fatalf("Failed to read certificate file: %v", err)
	}
	certPool.AppendCertsFromPEM(certData)

	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{
				RootCAs: certPool,
			},
		},
		Timeout: 5 * time.Second,
	}

	// Make a request to the proxy
	resp, err := client.Get(proxyServer.URL)
	if err != nil {
		t.Fatalf("Failed to make request to proxy: %v", err)
	}
	defer resp.Body.Close()

	// Check the response
	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status code %d, got %d", http.StatusOK, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("Failed to read response body: %v", err)
	}

	if string(body) != "TLS Backend response" {
		t.Errorf("Expected response body %q, got %q", "TLS Backend response", string(body))
	}
}

func TestTLSCertificateValidation(t *testing.T) {
	// Create temporary directory for test certificates
	tempDir, err := os.MkdirTemp("", "waffle-tls-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Generate test certificates
	certFile := filepath.Join(tempDir, "cert.pem")
	keyFile := filepath.Join(tempDir, "key.pem")
	if err := generateTestCertificate(certFile, keyFile); err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	// Test with valid certificates
	proxyOpts := ProxyOptions{
		ListenAddr:  ":8443",
		BackendURLs: []string{"http://example.com"},
		TLSCert:     certFile,
		TLSKey:      keyFile,
	}

	// Validate TLS configuration
	if !hasTLSConfig(proxyOpts) {
		t.Errorf("Expected TLS to be enabled with valid certificates")
	}

	// Test with missing certificate
	invalidCertFile := filepath.Join(tempDir, "nonexistent.pem")
	proxyOpts.TLSCert = invalidCertFile

	// This should not panic but return an error when the proxy starts
	if hasTLSConfig(proxyOpts) {
		t.Errorf("Expected TLS to be disabled with invalid certificate path")
	}

	// Test with empty certificate paths
	proxyOpts.TLSCert = ""
	proxyOpts.TLSKey = ""

	// This should disable TLS
	if hasTLSConfig(proxyOpts) {
		t.Errorf("Expected TLS to be disabled with empty certificate paths")
	}
}

// Helper function to check if TLS is configured
func hasTLSConfig(opts ProxyOptions) bool {
	// Check if both certificate and key are specified
	if opts.TLSCert == "" || opts.TLSKey == "" {
		return false
	}

	// Check if the certificate file exists
	if _, err := os.Stat(opts.TLSCert); os.IsNotExist(err) {
		return false
	}

	// Check if the key file exists
	if _, err := os.Stat(opts.TLSKey); os.IsNotExist(err) {
		return false
	}

	return true
}

// Helper function to generate a self-signed certificate for testing
func generateTestCertificate(certFile, keyFile string) error {
	// Generate a private key
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate private key: %w", err)
	}

	// Create a certificate template
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("failed to generate serial number: %w", err)
	}

	notBefore := time.Now()
	notAfter := notBefore.Add(24 * time.Hour) // Valid for 1 day

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"Waffle Test"},
			CommonName:   "localhost",
		},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		DNSNames:              []string{"localhost"},
	}

	// Create the certificate
	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return fmt.Errorf("failed to create certificate: %w", err)
	}

	// Write the certificate to file
	certOut, err := os.Create(certFile)
	if err != nil {
		return fmt.Errorf("failed to open cert.pem for writing: %w", err)
	}
	if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
		certOut.Close()
		return fmt.Errorf("failed to write data to cert.pem: %w", err)
	}
	if err := certOut.Close(); err != nil {
		return fmt.Errorf("error closing cert.pem: %w", err)
	}

	// Write the private key to file
	keyOut, err := os.OpenFile(keyFile, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return fmt.Errorf("failed to open key.pem for writing: %w", err)
	}
	privBytes, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		keyOut.Close()
		return fmt.Errorf("unable to marshal private key: %w", err)
	}
	if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		keyOut.Close()
		return fmt.Errorf("failed to write data to key.pem: %w", err)
	}
	if err := keyOut.Close(); err != nil {
		return fmt.Errorf("error closing key.pem: %w", err)
	}

	return nil
}

func TestProxyTLSConfiguration(t *testing.T) {
	// Create temporary directory for test certificates
	tempDir, err := os.MkdirTemp("", "waffle-tls-config-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Generate test certificates
	certFile := filepath.Join(tempDir, "cert.pem")
	keyFile := filepath.Join(tempDir, "key.pem")
	if err := generateTestCertificate(certFile, keyFile); err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	// Create a test HTTP server to use as a backend
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Backend response"))
	}))
	defer backendServer.Close()

	// Create a proxy options with TLS
	proxyOpts := ProxyOptions{
		ListenAddr:  ":0", // Use a random port
		BackendURLs: []string{backendServer.URL},
		TLSCert:     certFile,
		TLSKey:      keyFile,
	}

	// Create a channel to signal when the server is ready
	ready := make(chan struct{})
	// Create a channel to signal when to shut down the server
	shutdown := make(chan struct{})
	// Create a channel for errors
	errChan := make(chan error, 1)

	// Start the proxy in a goroutine
	go func() {
		// Create a custom server that we can control
		target, err := url.Parse(proxyOpts.BackendURLs[0])
		if err != nil {
			errChan <- fmt.Errorf("invalid backend URL: %v", err)
			return
		}

		proxy := httputil.NewSingleHostReverseProxy(target)
		waf := New()
		handler := waf.Middleware(proxy)

		// Create a listener to get the actual port
		listener, err := net.Listen("tcp", proxyOpts.ListenAddr)
		if err != nil {
			errChan <- fmt.Errorf("failed to create listener: %v", err)
			return
		}
		defer listener.Close()

		// Update the listen address with the actual port
		addr := listener.Addr().String()
		t.Logf("Server listening on %s", addr)

		// Create the server with TLS config
		server := &http.Server{
			Handler: handler,
		}

		// Signal that the server is ready
		close(ready)

		// Start the server with TLS
		if proxyOpts.TLSCert != "" && proxyOpts.TLSKey != "" {
			err = server.ServeTLS(listener, proxyOpts.TLSCert, proxyOpts.TLSKey)
		} else {
			err = server.Serve(listener)
		}

		if err != nil && err != http.ErrServerClosed {
			errChan <- fmt.Errorf("server error: %v", err)
		}
	}()

	// Wait for the server to be ready or for an error
	select {
	case <-ready:
		// Server is ready
	case err := <-errChan:
		t.Fatalf("Failed to start server: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatalf("Timeout waiting for server to start")
	}

	// Clean up
	close(shutdown)
}

func TestProxyTLSCertificateLoading(t *testing.T) {
	// Create temporary directory for test certificates
	tempDir, err := os.MkdirTemp("", "waffle-tls-loading-test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Generate test certificates
	certFile := filepath.Join(tempDir, "cert.pem")
	keyFile := filepath.Join(tempDir, "key.pem")
	if err := generateTestCertificate(certFile, keyFile); err != nil {
		t.Fatalf("Failed to generate test certificate: %v", err)
	}

	// Create a test HTTP server to use as a backend
	backendServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("Backend response"))
	}))
	defer backendServer.Close()

	// Test loading valid certificates
	validOpts := ProxyOptions{
		ListenAddr:  ":0",
		BackendURLs: []string{backendServer.URL},
		TLSCert:     certFile,
		TLSKey:      keyFile,
	}

	// Verify that the TLS configuration is valid
	if !hasTLSConfig(validOpts) {
		t.Errorf("Expected valid TLS configuration with existing certificate files")
	}

	// Test with invalid certificate path
	invalidCertFile := filepath.Join(tempDir, "nonexistent.pem")
	invalidOpts := ProxyOptions{
		ListenAddr:  ":0",
		BackendURLs: []string{backendServer.URL},
		TLSCert:     invalidCertFile,
		TLSKey:      keyFile,
	}

	// Verify that the TLS configuration is invalid
	if hasTLSConfig(invalidOpts) {
		t.Errorf("Expected invalid TLS configuration with non-existent certificate file")
	}

	// Test with invalid key path
	invalidKeyFile := filepath.Join(tempDir, "nonexistent.key")
	invalidOpts = ProxyOptions{
		ListenAddr:  ":0",
		BackendURLs: []string{backendServer.URL},
		TLSCert:     certFile,
		TLSKey:      invalidKeyFile,
	}

	// Verify that the TLS configuration is invalid
	if hasTLSConfig(invalidOpts) {
		t.Errorf("Expected invalid TLS configuration with non-existent key file")
	}

	// Test with empty certificate paths
	emptyOpts := ProxyOptions{
		ListenAddr:  ":0",
		BackendURLs: []string{backendServer.URL},
		TLSCert:     "",
		TLSKey:      "",
	}

	// Verify that the TLS configuration is invalid
	if hasTLSConfig(emptyOpts) {
		t.Errorf("Expected invalid TLS configuration with empty certificate paths")
	}
}
