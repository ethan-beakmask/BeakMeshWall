package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Central  CentralConfig `yaml:"central"`
	Agent    AgentConfig   `yaml:"agent"`
	Firewall FWConfig      `yaml:"firewall"`
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
	}

	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	if cfg.Central.URL == "" {
		return nil, fmt.Errorf("central.url is required")
	}

	return cfg, nil
}
