// Package client implements the HTTP client for communicating with BeakMeshWall Central Server.
package client

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/anthropics/BeakMeshWall/agent/internal/config"
)

// Version is set at build time via -ldflags.
var Version = "dev"

const (
	httpTimeout = 30 * time.Second
)

// Client handles HTTP communication with the Central Server.
type Client struct {
	httpClient *http.Client
	baseURL    string
	agentID    string
	secret     string
	logger     *slog.Logger
}

// NewClient creates a Client configured from the given Config.
// It sets up TLS (optional client certs, CA cert, skip_verify) and
// authentication headers.
func NewClient(cfg *config.Config, logger *slog.Logger) (*Client, error) {
	tlsConfig, err := buildTLSConfig(cfg)
	if err != nil {
		return nil, fmt.Errorf("build TLS config: %w", err)
	}

	transport := &http.Transport{
		TLSClientConfig: tlsConfig,
	}

	return &Client{
		httpClient: &http.Client{
			Transport: transport,
			Timeout:   httpTimeout,
		},
		baseURL: strings.TrimRight(cfg.Central.URL, "/"),
		agentID: cfg.Agent.ID,
		secret:  cfg.Agent.Secret,
		logger:  logger,
	}, nil
}

// SetCredentials updates the agent ID and bearer token after registration.
func (c *Client) SetCredentials(agentID, secret string) {
	c.agentID = agentID
	c.secret = secret
}

// doGet performs an authenticated GET request to the given API path.
func (c *Client) doGet(path string) (*http.Response, error) {
	url := c.baseURL + path
	c.logger.Debug("GET request", "url", url)

	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, fmt.Errorf("create GET request: %w", err)
	}

	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute GET request: %w", err)
	}

	return resp, nil
}

// doPost performs an authenticated POST request with a JSON body.
func (c *Client) doPost(path string, body interface{}) (*http.Response, error) {
	url := c.baseURL + path
	c.logger.Debug("POST request", "url", url)

	jsonData, err := json.Marshal(body)
	if err != nil {
		return nil, fmt.Errorf("marshal request body: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(jsonData))
	if err != nil {
		return nil, fmt.Errorf("create POST request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	c.setHeaders(req)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("execute POST request: %w", err)
	}

	return resp, nil
}

// setHeaders applies common headers to a request.
func (c *Client) setHeaders(req *http.Request) {
	req.Header.Set("User-Agent", fmt.Sprintf("BeakMeshWall-Agent/%s", Version))

	if c.secret != "" {
		req.Header.Set("Authorization", "Bearer "+c.secret)
	}
	if c.agentID != "" {
		req.Header.Set("X-Agent-ID", c.agentID)
	}
}

// decodeResponse reads and decodes a JSON response body into the given target.
// It also closes the response body.
func decodeResponse(resp *http.Response, target interface{}) error {
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("read response body: %w", err)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(body)))
	}

	if target != nil {
		if err := json.Unmarshal(body, target); err != nil {
			return fmt.Errorf("decode response JSON: %w", err)
		}
	}

	return nil
}

// buildTLSConfig constructs a tls.Config from the agent configuration.
func buildTLSConfig(cfg *config.Config) (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	// Skip server certificate verification (development only)
	if cfg.TLS.SkipVerify {
		tlsConfig.InsecureSkipVerify = true
	}

	// Load custom CA certificate
	if cfg.TLS.CACert != "" {
		caCert, err := os.ReadFile(cfg.TLS.CACert)
		if err != nil {
			return nil, fmt.Errorf("read CA cert %q: %w", cfg.TLS.CACert, err)
		}

		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, fmt.Errorf("failed to parse CA cert %q", cfg.TLS.CACert)
		}

		tlsConfig.RootCAs = caCertPool
	}

	// Load client certificate for mTLS
	if cfg.TLS.ClientCert != "" && cfg.TLS.ClientKey != "" {
		cert, err := tls.LoadX509KeyPair(cfg.TLS.ClientCert, cfg.TLS.ClientKey)
		if err != nil {
			return nil, fmt.Errorf("load client cert/key: %w", err)
		}

		tlsConfig.Certificates = []tls.Certificate{cert}
	}

	return tlsConfig, nil
}
