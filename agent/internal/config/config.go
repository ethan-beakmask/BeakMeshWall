// Package config handles YAML configuration loading and saving for BeakMeshWall Agent.
package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Config represents the complete agent configuration.
type Config struct {
	Central  CentralConfig  `yaml:"central"`
	Agent    AgentConfig    `yaml:"agent"`
	TLS      TLSConfig      `yaml:"tls"`
	Logging  LoggingConfig  `yaml:"logging"`
	filePath string         // internal: path to the loaded config file
}

// CentralConfig holds Central Server connection settings.
type CentralConfig struct {
	URL string `yaml:"url"`
}

// AgentConfig holds agent identity and polling settings.
type AgentConfig struct {
	ID           string `yaml:"id"`
	Secret       string `yaml:"secret"`
	PollInterval int    `yaml:"poll_interval"`
}

// TLSConfig holds optional mTLS settings.
type TLSConfig struct {
	CACert     string `yaml:"ca_cert"`
	ClientCert string `yaml:"client_cert"`
	ClientKey  string `yaml:"client_key"`
	SkipVerify bool   `yaml:"skip_verify"`
}

// LoggingConfig holds logging preferences.
type LoggingConfig struct {
	Level string `yaml:"level"`
	File  string `yaml:"file"`
}

// LoadConfig reads and parses a YAML configuration file from the given path.
func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config file: %w", err)
	}

	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, fmt.Errorf("parse config file: %w", err)
	}

	cfg.filePath = path

	// Apply defaults
	if cfg.Agent.PollInterval <= 0 {
		cfg.Agent.PollInterval = 30
	}
	if cfg.Logging.Level == "" {
		cfg.Logging.Level = "info"
	}

	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("config validation: %w", err)
	}

	return cfg, nil
}

// SaveConfig writes the configuration back to the given file path in YAML format.
func SaveConfig(path string, cfg *Config) error {
	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal config: %w", err)
	}

	if err := os.WriteFile(path, data, 0600); err != nil {
		return fmt.Errorf("write config file: %w", err)
	}

	return nil
}

// FilePath returns the path from which this config was loaded.
func (c *Config) FilePath() string {
	return c.filePath
}

// validate checks that the configuration contains required values.
func (c *Config) validate() error {
	var errs []string

	if c.Central.URL == "" {
		errs = append(errs, "central.url is required")
	}

	validLevels := map[string]bool{
		"debug": true, "info": true, "warn": true, "error": true,
	}
	if !validLevels[strings.ToLower(c.Logging.Level)] {
		errs = append(errs, fmt.Sprintf("logging.level must be one of: debug, info, warn, error (got %q)", c.Logging.Level))
	}

	if c.TLS.ClientCert != "" && c.TLS.ClientKey == "" {
		errs = append(errs, "tls.client_key is required when tls.client_cert is set")
	}
	if c.TLS.ClientKey != "" && c.TLS.ClientCert == "" {
		errs = append(errs, "tls.client_cert is required when tls.client_key is set")
	}

	if len(errs) > 0 {
		return fmt.Errorf("%s", strings.Join(errs, "; "))
	}

	return nil
}
