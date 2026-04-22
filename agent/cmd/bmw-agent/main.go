package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"runtime"
	"time"

	"github.com/anthropics/beakmeshwall-agent/internal/client"
	"github.com/anthropics/beakmeshwall-agent/internal/config"
	"github.com/anthropics/beakmeshwall-agent/internal/module"
	"github.com/anthropics/beakmeshwall-agent/internal/module/firewall"
	"github.com/anthropics/beakmeshwall-agent/internal/module/nginx"
	"github.com/anthropics/beakmeshwall-agent/internal/module/service"
	"github.com/anthropics/beakmeshwall-agent/internal/module/sysinfo"
	"github.com/anthropics/beakmeshwall-agent/internal/transport"
)

const version = "0.4.0"

// reporter is the interface for sending report data.
// Implemented by client.Client (HTTP) and transport.EmailReporter (email).
type reporter interface {
	Report(data map[string]interface{}) error
}

func main() {
	configPath := flag.String("config", "", "Path to agent config file (YAML)")
	showVersion := flag.Bool("version", false, "Show version")
	register := flag.Bool("register", false, "Register this agent with Central and save token to config")
	flag.Parse()

	if len(os.Args) == 1 {
		fmt.Println("BeakMeshWall Agent - Multi-module system management agent")
		fmt.Println()
		fmt.Println("Usage:")
		fmt.Println("  bmw-agent -config <path>              Start the agent")
		fmt.Println("  bmw-agent -config <path> -register    Register with Central server")
		fmt.Println("  bmw-agent -version                    Show version")
		fmt.Println()
		fmt.Println("Config file (YAML):")
		fmt.Println("  central:")
		fmt.Println("    url: http://192.168.0.16:5100   # required for http transport")
		fmt.Println("    token: <from registration>")
		fmt.Println("  agent:")
		fmt.Println("    hostname: my-server")
		fmt.Println("    poll_interval: 30")
		fmt.Println("  transport:")
		fmt.Println("    type: http                       # 'http' (default) or 'email'")
		fmt.Println("    email:                           # required when type=email")
		fmt.Println("      smtp_host: smtp.gmail.com")
		fmt.Println("      smtp_port: 587")
		fmt.Println("      username: report@gmail.com")
		fmt.Println("      app_password: xxxx-xxxx-xxxx-xxxx")
		fmt.Println("      to: receiver@gmail.com")
		fmt.Println("      encrypt_key: <64 hex chars>    # AES-256 key")
		fmt.Println("  firewall:")
		fmt.Println("    driver: nftables                 # or windows_firewall")
		fmt.Println("    table: inet beakmeshwall         # linux only")
		fmt.Println("  modules:")
		fmt.Println("    firewall: true")
		fmt.Println("    nginx: true")
		fmt.Println("    service: true")
		fmt.Println("    sysinfo: true                    # user account auditing")
		fmt.Println("  nginx:")
		fmt.Println("    config_path: /etc/nginx/sites-enabled")
		os.Exit(0)
	}

	if *showVersion {
		fmt.Printf("bmw-agent %s (%s/%s)\n", version, runtime.GOOS, runtime.GOARCH)
		os.Exit(0)
	}

	if *configPath == "" {
		log.Fatal("ERROR: -config is required")
	}

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Fatalf("ERROR: load config: %v", err)
	}

	hostname := cfg.Agent.Hostname
	if hostname == "" {
		hostname, _ = os.Hostname()
	}

	c := client.New(cfg.Central.URL, cfg.Central.Token)

	// Registration mode: output to console, then exit
	if *register {
		doRegister(c, cfg, hostname)
		return
	}

	// Daemon mode: redirect log on Windows
	initPlatform()

	// Initialize modules
	var modules []module.Module
	var executor module.Executor

	if cfg.Modules.Firewall {
		fwMod, err := firewall.New(cfg.Firewall.Driver, cfg.Firewall.Table)
		if err != nil {
			log.Fatalf("ERROR: init firewall module: %v", err)
		}
		modules = append(modules, fwMod)
		executor = fwMod
		log.Printf("INFO: firewall module enabled (driver: %s)", cfg.Firewall.Driver)
	}

	if cfg.Modules.Nginx {
		ngxMod := nginx.New(cfg.Nginx.ConfigPath)
		modules = append(modules, ngxMod)
		log.Printf("INFO: nginx module enabled (path: %s)", cfg.Nginx.ConfigPath)
	}

	if cfg.Modules.Service {
		svcMod := service.New()
		modules = append(modules, svcMod)
		log.Printf("INFO: service module enabled")
	}

	if cfg.Modules.Sysinfo {
		sysMod := sysinfo.New()
		modules = append(modules, sysMod)
		log.Printf("INFO: sysinfo module enabled")
	}

	if len(modules) == 0 {
		log.Fatal("ERROR: no modules enabled")
	}

	// Select transport and start the appropriate loop
	switch cfg.Transport.Type {
	case "email":
		emailCfg := transport.EmailConfig{
			SMTPHost:    cfg.Transport.Email.SMTPHost,
			SMTPPort:    cfg.Transport.Email.SMTPPort,
			Username:    cfg.Transport.Email.Username,
			AppPassword: cfg.Transport.Email.AppPassword,
			To:          cfg.Transport.Email.To,
			EncryptKey:  cfg.Transport.Email.EncryptKey,
		}
		rpt := transport.NewEmailReporter(emailCfg, hostname, cfg.Central.Token)
		log.Printf("INFO: agent %s started (%d modules), email transport to %s every %ds",
			version, len(modules), cfg.Transport.Email.To, cfg.Agent.PollInterval)

		done := make(chan struct{})
		go runCollectLoop(rpt, modules, cfg.Agent.PollInterval, done)
		waitForShutdown(len(modules), cfg.Agent.PollInterval)
		close(done)

	default: // "http"
		if cfg.Central.Token == "" {
			log.Fatal("ERROR: central.token is required. Run with -register first.")
		}
		log.Printf("INFO: agent %s started (%d modules), polling %s every %ds",
			version, len(modules), cfg.Central.URL, cfg.Agent.PollInterval)

		done := make(chan struct{})
		go runPollLoop(c, modules, executor, cfg.Agent.PollInterval, done)
		waitForShutdown(len(modules), cfg.Agent.PollInterval)
		close(done)
	}

	log.Println("INFO: agent stopped")
}

func doRegister(c *client.Client, cfg *config.Config, hostname string) {
	resp, err := c.Register(client.RegisterRequest{
		Hostname:     hostname,
		OSType:       runtime.GOOS,
		FWDriver:     cfg.Firewall.Driver,
		AgentVersion: version,
	})
	if err != nil {
		log.Fatalf("ERROR: registration failed: %v", err)
	}

	fmt.Printf("Registered as node %d\n", resp.NodeID)
	fmt.Printf("Token: %s\n", resp.Token)
	fmt.Printf("Add this token to your config file under central.token\n")
}

// runCollectLoop collects module state and sends via the given reporter
// (email transport). No task polling -- this is one-way reporting only.
func runCollectLoop(rpt reporter, modules []module.Module, intervalSec int, done <-chan struct{}) {
	ticker := time.NewTicker(time.Duration(intervalSec) * time.Second)
	defer ticker.Stop()

	doCollectAndReport(rpt, modules)

	for {
		select {
		case <-ticker.C:
			doCollectAndReport(rpt, modules)
		case <-done:
			return
		}
	}
}

func doCollectAndReport(rpt reporter, modules []module.Module) {
	reportData := make(map[string]interface{})

	for _, mod := range modules {
		state, err := mod.Collect()
		if err != nil {
			log.Printf("WARN: %s collect failed: %v", mod.Name(), err)
			continue
		}
		switch mod.Name() {
		case "firewall":
			reportData["fw_state"] = state
		case "nginx":
			reportData["nginx_state"] = state
		case "service":
			reportData["service_state"] = state
		case "sysinfo":
			reportData["system_info"] = state
		}
	}

	if err := rpt.Report(reportData); err != nil {
		log.Printf("WARN: report failed: %v", err)
		return
	}
	log.Printf("INFO: collect ok, state reported (%d modules)", len(modules))
}

func runPollLoop(c *client.Client, modules []module.Module, executor module.Executor, intervalSec int, done <-chan struct{}) {
	ticker := time.NewTicker(time.Duration(intervalSec) * time.Second)
	defer ticker.Stop()

	doPoll(c, modules, executor)

	for {
		select {
		case <-ticker.C:
			doPoll(c, modules, executor)
		case <-done:
			return
		}
	}
}

func doPoll(c *client.Client, modules []module.Module, executor module.Executor) {
	resp, err := c.Poll()
	if err != nil {
		log.Printf("WARN: poll failed: %v", err)
		return
	}

	// Execute tasks via the executor (firewall module)
	var taskResults []map[string]interface{}
	if executor != nil {
		for _, task := range resp.Tasks {
			result := executeTask(executor, task)
			taskResults = append(taskResults, result)
		}
	}

	// Collect state from all modules
	reportData := make(map[string]interface{})

	for _, mod := range modules {
		state, err := mod.Collect()
		if err != nil {
			log.Printf("WARN: %s collect failed: %v", mod.Name(), err)
			continue
		}

		// Map module name to report key
		switch mod.Name() {
		case "firewall":
			reportData["fw_state"] = state
		case "nginx":
			reportData["nginx_state"] = state
		case "service":
			reportData["service_state"] = state
		case "sysinfo":
			reportData["system_info"] = state
		}
	}

	if len(taskResults) > 0 {
		reportData["task_results"] = taskResults
	}

	if err := c.Report(reportData); err != nil {
		log.Printf("WARN: report failed: %v", err)
		return
	}

	if len(resp.Tasks) > 0 {
		log.Printf("INFO: poll ok, executed %d tasks, state reported (%d modules)", len(resp.Tasks), len(modules))
	} else {
		log.Printf("INFO: poll ok, state reported (%d modules)", len(modules))
	}
}

func executeTask(executor module.Executor, task client.TaskItem) map[string]interface{} {
	result := map[string]interface{}{
		"task_id": task.ID,
		"success": false,
	}

	var payload map[string]interface{}
	if err := json.Unmarshal(task.Payload, &payload); err != nil {
		result["detail"] = fmt.Sprintf("invalid payload: %v", err)
		log.Printf("ERROR: task %d: invalid payload: %v", task.ID, err)
		return result
	}

	success, detail := executor.Execute(task.Action, payload)
	result["success"] = success
	result["detail"] = detail
	log.Printf("INFO: task %d: %s -> success=%v detail=%s", task.ID, task.Action, success, detail)

	return result
}
