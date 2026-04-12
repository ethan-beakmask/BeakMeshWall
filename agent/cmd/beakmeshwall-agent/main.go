// Package main is the entry point for the BeakMeshWall Agent.
// It provides CLI subcommands for registration and continuous polling.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/anthropics/BeakMeshWall/agent/internal/client"
	"github.com/anthropics/BeakMeshWall/agent/internal/config"
	"github.com/anthropics/BeakMeshWall/agent/internal/driver/nftables"
	"github.com/anthropics/BeakMeshWall/agent/internal/module"
)

// version is set at build time via -ldflags "-X main.version=..."
var version = "dev"

func main() {
	// Propagate version to client package for User-Agent header
	client.Version = version

	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	subcommand := os.Args[1]

	switch subcommand {
	case "register":
		if err := cmdRegister(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "register error: %v\n", err)
			os.Exit(1)
		}

	case "run":
		if err := cmdRun(os.Args[2:]); err != nil {
			fmt.Fprintf(os.Stderr, "run error: %v\n", err)
			os.Exit(1)
		}

	case "version":
		fmt.Printf("BeakMeshWall Agent %s\n", version)

	case "--help", "-h", "help":
		printUsage()

	default:
		fmt.Fprintf(os.Stderr, "unknown subcommand: %s\n\n", subcommand)
		printUsage()
		os.Exit(1)
	}
}

// printUsage displays the Chinese usage message as required by the project spec.
func printUsage() {
	fmt.Printf(`BeakMeshWall Agent %s - 多主機防火牆管理代理程式

使用方式:
  beakmeshwall-agent register --config <path> --token <token> --central-url <url>
  beakmeshwall-agent run --config <path>
  beakmeshwall-agent version

子命令:
  register    向 Central Server 註冊此節點
  run         啟動代理程式（持續輪詢模式）
  version     顯示版本資訊

必要參數:
  --config    組態檔路徑 (YAML)

註冊參數:
  --token         一次性註冊令牌（從 Central 管理介面取得）
  --central-url   Central Server URL (例: https://192.168.0.16:5000)
`, version)
}

// cmdRegister handles the "register" subcommand.
func cmdRegister(args []string) error {
	fs := flag.NewFlagSet("register", flag.ExitOnError)
	configPath := fs.String("config", "", "Path to YAML config file")
	token := fs.String("token", "", "One-time registration token")
	centralURL := fs.String("central-url", "", "Central Server URL")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *configPath == "" {
		return fmt.Errorf("--config is required")
	}
	if *token == "" {
		return fmt.Errorf("--token is required")
	}
	if *centralURL == "" {
		return fmt.Errorf("--central-url is required")
	}

	cfg, err := loadOrCreateConfig(*configPath, *centralURL)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	logger := setupLogger(cfg)

	result, err := client.Register(cfg, *token, *centralURL, logger)
	if err != nil {
		return err
	}

	fmt.Printf("Registration successful.\n")
	fmt.Printf("  Agent ID:      %s\n", result.AgentID)
	fmt.Printf("  Poll Interval: %d seconds\n", result.PollInterval)
	fmt.Printf("  Config saved:  %s\n", *configPath)

	return nil
}

// cmdRun handles the "run" subcommand.
func cmdRun(args []string) error {
	fs := flag.NewFlagSet("run", flag.ExitOnError)
	configPath := fs.String("config", "", "Path to YAML config file")

	if err := fs.Parse(args); err != nil {
		return err
	}

	if *configPath == "" {
		return fmt.Errorf("--config is required")
	}

	cfg, err := config.LoadConfig(*configPath)
	if err != nil {
		return fmt.Errorf("config: %w", err)
	}

	// Validate that registration has been completed
	if cfg.Agent.ID == "" || cfg.Agent.Secret == "" {
		return fmt.Errorf("agent not registered: run 'beakmeshwall-agent register' first")
	}

	logger := setupLogger(cfg)

	// Initialize the firewall driver
	drv := nftables.New(logger)
	if err := drv.Init(); err != nil {
		// Log warning but continue -- nftables may not be available in all environments
		logger.Warn("nftables driver init failed (continuing without firewall control)",
			"error", err,
		)
	}
	defer drv.Close()

	// Build the module registry and register the firewall module
	registry := module.NewRegistry()
	registry.Register(module.NewFirewallModule(drv, logger))

	// Create HTTP client
	httpClient, err := client.NewClient(cfg, logger)
	if err != nil {
		return fmt.Errorf("create client: %w", err)
	}

	// Set up context with signal handling for graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		sig := <-sigCh
		logger.Info("received shutdown signal", "signal", sig)
		cancel()
	}()

	logger.Info("agent starting",
		"version", version,
		"agent_id", cfg.Agent.ID,
		"central_url", cfg.Central.URL,
		"poll_interval", cfg.Agent.PollInterval,
		"driver", drv.Name(),
	)

	// Start the poll loop (blocks until context is cancelled)
	return client.StartPollLoop(ctx, httpClient, registry, logger)
}

// setupLogger creates an slog.Logger based on the config.
func setupLogger(cfg *config.Config) *slog.Logger {
	var level slog.Level
	switch strings.ToLower(cfg.Logging.Level) {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	default:
		level = slog.LevelInfo
	}

	var handler slog.Handler

	if cfg.Logging.File != "" {
		f, err := os.OpenFile(cfg.Logging.File, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err != nil {
			fmt.Fprintf(os.Stderr, "warning: cannot open log file %q: %v (falling back to stdout)\n",
				cfg.Logging.File, err)
			handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})
		} else {
			handler = slog.NewJSONHandler(f, &slog.HandlerOptions{Level: level})
		}
	} else {
		handler = slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: level})
	}

	return slog.New(handler)
}

// loadOrCreateConfig loads an existing config or creates a minimal one
// suitable for the registration step. During registration the config file
// may not exist yet, so we create it with minimal defaults.
func loadOrCreateConfig(path, centralURL string) (*config.Config, error) {
	// Try loading existing config first
	cfg, err := config.LoadConfig(path)
	if err == nil {
		return cfg, nil
	}

	// If file does not exist, create a minimal config for registration
	if !os.IsNotExist(unwrapErr(err)) {
		return nil, err
	}

	cfg = &config.Config{
		Central: config.CentralConfig{
			URL: centralURL,
		},
		Agent: config.AgentConfig{
			PollInterval: 30,
		},
		TLS: config.TLSConfig{
			SkipVerify: false,
		},
		Logging: config.LoggingConfig{
			Level: "info",
		},
	}

	// Save the initial config so LoadConfig can be used later
	if err := config.SaveConfig(path, cfg); err != nil {
		return nil, fmt.Errorf("create initial config: %w", err)
	}

	// Reload to get filePath set properly
	return config.LoadConfig(path)
}

// unwrapErr extracts the deepest wrapped error for type checking.
func unwrapErr(err error) error {
	for {
		unwrapped := errors.Unwrap(err)
		if unwrapped == nil {
			return err
		}
		err = unwrapped
	}
}
