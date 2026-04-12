package client

import (
	"bufio"
	"fmt"
	"log/slog"
	"net"
	"os"
	"strings"

	"github.com/anthropics/BeakMeshWall/agent/internal/config"
)

// RegisterRequest is the payload sent to POST /api/v1/agent/register.
type RegisterRequest struct {
	Token        string `json:"token"`
	Hostname     string `json:"hostname"`
	OSInfo       string `json:"os_info"`
	AgentVersion string `json:"agent_version"`
	IPAddress    string `json:"ip_address"`
}

// RegisterResponse is the response from POST /api/v1/agent/register.
type RegisterResponse struct {
	AgentID      string `json:"agent_id"`
	AgentSecret  string `json:"agent_secret"`
	PollInterval int    `json:"poll_interval"`
}

// Register performs agent registration with the Central Server using a one-time token.
// On success it saves the received agent_id and agent_secret back to the config file.
func Register(cfg *config.Config, token, centralURL string, logger *slog.Logger) (*RegisterResponse, error) {
	// Override central URL if provided via CLI flag
	if centralURL != "" {
		cfg.Central.URL = centralURL
	}

	client, err := NewClient(cfg, logger)
	if err != nil {
		return nil, fmt.Errorf("create client: %w", err)
	}

	hostname, err := os.Hostname()
	if err != nil {
		return nil, fmt.Errorf("get hostname: %w", err)
	}

	osInfo := detectOSInfo()
	ipAddr := detectPrimaryIP()

	reqBody := RegisterRequest{
		Token:        token,
		Hostname:     hostname,
		OSInfo:       osInfo,
		AgentVersion: Version,
		IPAddress:    ipAddr,
	}

	logger.Info("registering agent with Central Server",
		"central_url", cfg.Central.URL,
		"hostname", hostname,
		"ip_address", ipAddr,
	)

	resp, err := client.doPost("/api/v1/agent/register", reqBody)
	if err != nil {
		return nil, fmt.Errorf("registration request: %w", err)
	}

	var result RegisterResponse
	if err := decodeResponse(resp, &result); err != nil {
		return nil, fmt.Errorf("registration failed: %w", err)
	}

	// Save agent_id and agent_secret to config file
	cfg.Agent.ID = result.AgentID
	cfg.Agent.Secret = result.AgentSecret
	if result.PollInterval > 0 {
		cfg.Agent.PollInterval = result.PollInterval
	}

	if err := config.SaveConfig(cfg.FilePath(), cfg); err != nil {
		return nil, fmt.Errorf("save config after registration: %w", err)
	}

	logger.Info("registration successful",
		"agent_id", result.AgentID,
		"poll_interval", result.PollInterval,
	)

	return &result, nil
}

// detectOSInfo reads PRETTY_NAME from /etc/os-release.
// Returns a fallback string if the file is unavailable.
func detectOSInfo() string {
	f, err := os.Open("/etc/os-release")
	if err != nil {
		return "Linux (unknown)"
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if strings.HasPrefix(line, "PRETTY_NAME=") {
			value := strings.TrimPrefix(line, "PRETTY_NAME=")
			value = strings.Trim(value, "\"")
			return value
		}
	}

	return "Linux (unknown)"
}

// detectPrimaryIP iterates network interfaces and returns the first
// non-loopback IPv4 address, skipping Docker/veth/bridge interfaces.
func detectPrimaryIP() string {
	ifaces, err := net.Interfaces()
	if err != nil {
		return "unknown"
	}

	// Prefixes to skip: loopback, Docker bridge, veth pairs, container bridges
	skipPrefixes := []string{"lo", "docker", "veth", "br-", "virbr", "lxcbr"}

	for _, iface := range ifaces {
		// Skip interfaces that are down
		if iface.Flags&net.FlagUp == 0 {
			continue
		}

		// Skip loopback
		if iface.Flags&net.FlagLoopback != 0 {
			continue
		}

		// Skip known virtual interfaces
		skip := false
		for _, prefix := range skipPrefixes {
			if strings.HasPrefix(iface.Name, prefix) {
				skip = true
				break
			}
		}
		if skip {
			continue
		}

		addrs, err := iface.Addrs()
		if err != nil {
			continue
		}

		for _, addr := range addrs {
			ipNet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			ip := ipNet.IP
			if ip.To4() != nil && !ip.IsLoopback() {
				return ip.String()
			}
		}
	}

	return "unknown"
}
