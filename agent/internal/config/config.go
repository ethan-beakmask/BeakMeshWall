package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Central   CentralConfig   `yaml:"central"`
	Agent     AgentConfig     `yaml:"agent"`
	Firewall  FWConfig        `yaml:"firewall"`
	Modules   ModulesConfig   `yaml:"modules"`
	Nginx     NginxConfig     `yaml:"nginx"`
	Transport TransportConfig `yaml:"transport"`
}

type CentralConfig struct {
	URL   string `yaml:"url"`   // e.g. http://192.168.0.16:5100
	Token string `yaml:"token"` // Bearer token from registration
}

type AgentConfig struct {
	Hostname     string `yaml:"hostname"`
	PollInterval int    `yaml:"poll_interval"` // seconds
}

type FWConfig struct {
	Driver string `yaml:"driver"` // nftables, iptables, windows_firewall, pf
	Table  string `yaml:"table"`  // managed table name, default: inet beakmeshwall
}

type ModulesConfig struct {
	Firewall bool `yaml:"firewall"`
	Nginx    bool `yaml:"nginx"`
	Service  bool `yaml:"service"`
	Sysinfo  bool `yaml:"sysinfo"`
}

type NginxConfig struct {
	ConfigPath string `yaml:"config_path"` // default: /etc/nginx/sites-enabled
}

// TransportConfig selects how reports are delivered to Central.
type TransportConfig struct {
	Type  string      `yaml:"type"`  // "http" (default) or "email"
	Email EmailConfig `yaml:"email"` // required when type=email
}

// EmailConfig holds Gmail SMTP settings for email transport.
type EmailConfig struct {
	SMTPHost    string `yaml:"smtp_host"`    // default: smtp.gmail.com
	SMTPPort    int    `yaml:"smtp_port"`    // default: 587
	Username    string `yaml:"username"`     // Gmail address
	AppPassword string `yaml:"app_password"` // Gmail App Password
	To          string `yaml:"to"`           // recipient address
	EncryptKey  string `yaml:"encrypt_key"`  // AES-256 key (64 hex chars)
}

func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config: %w", err)
	}

	cfg := &Config{
		Agent: AgentConfig{
			PollInterval: 30,
		},
		Firewall: FWConfig{
			Driver: "nftables",
			Table:  "inet beakmeshwall",
		},
		Modules: ModulesConfig{
			Firewall: true,
			Nginx:    true,
			Service:  true,
			Sysinfo:  true,
		},
		Nginx: NginxConfig{
			ConfigPath: "/etc/nginx/sites-enabled",
		},
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	// Default transport type
	if cfg.Transport.Type == "" {
		cfg.Transport.Type = "http"
	}

	switch cfg.Transport.Type {
	case "http":
		if cfg.Central.URL == "" {
			return nil, fmt.Errorf("central.url is required for http transport")
		}
	case "email":
		e := &cfg.Transport.Email
		if e.SMTPHost == "" {
			e.SMTPHost = "smtp.gmail.com"
		}
		if e.SMTPPort == 0 {
			e.SMTPPort = 587
		}
		if e.Username == "" {
			return nil, fmt.Errorf("transport.email.username is required")
		}
		if e.AppPassword == "" {
			return nil, fmt.Errorf("transport.email.app_password is required")
		}
		if e.To == "" {
			return nil, fmt.Errorf("transport.email.to is required")
		}
		if e.EncryptKey == "" {
			return nil, fmt.Errorf("transport.email.encrypt_key is required")
		}
		if len(e.EncryptKey) != 64 {
			return nil, fmt.Errorf("transport.email.encrypt_key must be 64 hex chars (32 bytes)")
		}
	default:
		return nil, fmt.Errorf("unknown transport type: %s (use 'http' or 'email')", cfg.Transport.Type)
	}

	return cfg, nil
}
