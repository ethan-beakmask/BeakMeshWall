package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/anthropics/beakmeshwall-agent/internal/client"
	"github.com/anthropics/beakmeshwall-agent/internal/config"
	"github.com/anthropics/beakmeshwall-agent/internal/driver/nftables"
)

const version = "0.1.0"

func main() {
	configPath := flag.String("config", "", "Path to agent config file (YAML)")
	showVersion := flag.Bool("version", false, "Show version")
	register := flag.Bool("register", false, "Register this agent with Central and save token to config")
	flag.Parse()

	if len(os.Args) == 1 {
		fmt.Println("BeakMeshWall Agent - Firewall management agent")
		fmt.Println()
		fmt.Println("Usage:")
		fmt.Println("  bmw-agent -config <path>              Start the agent")
		fmt.Println("  bmw-agent -config <path> -register    Register with Central server")
		fmt.Println("  bmw-agent -version                    Show version")
		fmt.Println()
		fmt.Println("Config file (YAML):")
		fmt.Println("  central:")
		fmt.Println("    url: http://192.168.0.16:5100")
		fmt.Println("    token: <from registration>")
		fmt.Println("  agent:")
		fmt.Println("    hostname: my-server")
		fmt.Println("    poll_interval: 30")
		fmt.Println("  firewall:")
		fmt.Println("    driver: nftables")
		fmt.Println("    table: inet beakmeshwall")
		os.Exit(0)
	}

	if *showVersion {
		fmt.Printf("bmw-agent %s\n", version)
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

	if *register {
		doRegister(c, cfg, hostname)
		return
	}

	if cfg.Central.Token == "" {
		log.Fatal("ERROR: central.token is required. Run with -register first.")
	}

	drv := nftables.New(cfg.Firewall.Table)
	if err := drv.Init(); err != nil {
		log.Fatalf("ERROR: init firewall driver: %v", err)
	}
	log.Printf("INFO: firewall driver initialized (table: %s)", cfg.Firewall.Table)

	log.Printf("INFO: agent started, polling %s every %ds", cfg.Central.URL, cfg.Agent.PollInterval)
	runPollLoop(c, drv, cfg.Agent.PollInterval)
}

func doRegister(c *client.Client, cfg *config.Config, hostname string) {
	resp, err := c.Register(client.RegisterRequest{
		Hostname:     hostname,
		OSType:       "linux",
		FWDriver:     cfg.Firewall.Driver,
		AgentVersion: version,
	})
	if err != nil {
		log.Fatalf("ERROR: registration failed: %v", err)
	}

	log.Printf("INFO: registered as node %d", resp.NodeID)
	log.Printf("INFO: token: %s", resp.Token)
	log.Printf("INFO: add this token to your config file under central.token")
}

func runPollLoop(c *client.Client, drv *nftables.NFTDriver, intervalSec int) {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)

	ticker := time.NewTicker(time.Duration(intervalSec) * time.Second)
	defer ticker.Stop()

	doPoll(c, drv)

	for {
		select {
		case <-ticker.C:
			doPoll(c, drv)
		case s := <-sig:
			log.Printf("INFO: received %v, shutting down", s)
			return
		}
	}
}

func doPoll(c *client.Client, drv *nftables.NFTDriver) {
	resp, err := c.Poll()
	if err != nil {
		log.Printf("WARN: poll failed: %v", err)
		return
	}

	// Execute tasks
	var taskResults []map[string]interface{}
	for _, task := range resp.Tasks {
		result := executeTask(drv, task)
		taskResults = append(taskResults, result)
	}

	// Get current firewall state
	state, err := drv.GetState()
	if err != nil {
		log.Printf("WARN: get firewall state: %v", err)
		return
	}

	reportData := map[string]interface{}{
		"fw_state": state,
	}
	if len(taskResults) > 0 {
		reportData["task_results"] = taskResults
	}

	if err := c.Report(reportData); err != nil {
		log.Printf("WARN: report failed: %v", err)
		return
	}

	if len(resp.Tasks) > 0 {
		log.Printf("INFO: poll ok, executed %d tasks, state reported", len(resp.Tasks))
	} else {
		log.Printf("INFO: poll ok, no tasks, state reported")
	}
}

func executeTask(drv *nftables.NFTDriver, task client.TaskItem) map[string]interface{} {
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

	var execErr error
	switch task.Action {
	case "block_ip":
		ip, _ := payload["ip"].(string)
		comment, _ := payload["comment"].(string)
		if ip == "" {
			result["detail"] = "missing ip"
			break
		}
		execErr = drv.BlockIP(ip, comment)
		log.Printf("INFO: task %d: block_ip %s -> %v", task.ID, ip, execErr)

	case "unblock_ip":
		ip, _ := payload["ip"].(string)
		if ip == "" {
			result["detail"] = "missing ip"
			break
		}
		execErr = drv.UnblockIP(ip)
		log.Printf("INFO: task %d: unblock_ip %s -> %v", task.ID, ip, execErr)

	case "add_rule":
		chain, _ := payload["chain"].(string)
		rule, _ := payload["rule"].(string)
		comment, _ := payload["comment"].(string)
		if rule == "" {
			result["detail"] = "missing rule"
			break
		}
		if chain == "" {
			chain = "filter_input"
		}
		execErr = drv.AddRule(chain, rule, comment)
		log.Printf("INFO: task %d: add_rule [%s] %s -> %v", task.ID, chain, rule, execErr)

	case "delete_rule":
		chain, _ := payload["chain"].(string)
		handle, _ := payload["handle"].(float64)
		if chain == "" {
			chain = "filter_input"
		}
		execErr = drv.DeleteRule(chain, int(handle))
		log.Printf("INFO: task %d: delete_rule [%s] handle %d -> %v", task.ID, chain, int(handle), execErr)

	default:
		result["detail"] = fmt.Sprintf("unknown action: %s", task.Action)
		log.Printf("WARN: task %d: unknown action: %s", task.ID, task.Action)
		return result
	}

	if execErr != nil {
		result["detail"] = execErr.Error()
	} else {
		result["success"] = true
		result["detail"] = "ok"
	}

	return result
}
