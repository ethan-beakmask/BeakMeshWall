package module

import (
	"fmt"
	"log/slog"

	"github.com/anthropics/BeakMeshWall/agent/internal/driver"
)

// FirewallModule wraps a driver.Driver to satisfy the Module interface.
// It translates task actions (block_ip, unblock_ip, list_rules, list_tables)
// into driver method calls.
type FirewallModule struct {
	driver driver.Driver
	logger *slog.Logger
}

// NewFirewallModule creates a FirewallModule backed by the given driver.
func NewFirewallModule(drv driver.Driver, logger *slog.Logger) *FirewallModule {
	return &FirewallModule{driver: drv, logger: logger}
}

// Name returns "firewall", matching the Task.Module field for firewall tasks.
func (m *FirewallModule) Name() string { return "firewall" }

// HandleTask dispatches a firewall task to the underlying driver.
func (m *FirewallModule) HandleTask(task Task) TaskResult {
	m.logger.Info("executing firewall task",
		"task_id", task.ID,
		"action", task.Action,
	)

	switch task.Action {
	case "block_ip":
		ip, _ := task.Params["ip"].(string)
		comment, _ := task.Params["comment"].(string)
		if ip == "" {
			return TaskResult{TaskID: task.ID, Status: "error", Message: "missing ip parameter"}
		}
		if err := m.driver.BlockIP(ip, comment); err != nil {
			m.logger.Error("block_ip failed", "task_id", task.ID, "ip", ip, "error", err)
			return TaskResult{TaskID: task.ID, Status: "error", Message: err.Error()}
		}
		m.logger.Info("block_ip succeeded", "task_id", task.ID, "ip", ip)
		return TaskResult{TaskID: task.ID, Status: "success"}

	case "unblock_ip":
		ip, _ := task.Params["ip"].(string)
		if ip == "" {
			return TaskResult{TaskID: task.ID, Status: "error", Message: "missing ip parameter"}
		}
		if err := m.driver.UnblockIP(ip); err != nil {
			m.logger.Error("unblock_ip failed", "task_id", task.ID, "ip", ip, "error", err)
			return TaskResult{TaskID: task.ID, Status: "error", Message: err.Error()}
		}
		m.logger.Info("unblock_ip succeeded", "task_id", task.ID, "ip", ip)
		return TaskResult{TaskID: task.ID, Status: "success"}

	case "list_rules":
		rules, err := m.driver.ListRules()
		if err != nil {
			m.logger.Error("list_rules failed", "task_id", task.ID, "error", err)
			return TaskResult{TaskID: task.ID, Status: "error", Message: err.Error()}
		}
		m.logger.Info("list_rules succeeded", "task_id", task.ID, "count", len(rules))
		return TaskResult{TaskID: task.ID, Status: "success", Data: rules}

	case "list_tables":
		tables, err := m.driver.ListTables()
		if err != nil {
			m.logger.Error("list_tables failed", "task_id", task.ID, "error", err)
			return TaskResult{TaskID: task.ID, Status: "error", Message: err.Error()}
		}
		m.logger.Info("list_tables succeeded", "task_id", task.ID, "count", len(tables))
		return TaskResult{TaskID: task.ID, Status: "success", Data: tables}

	default:
		return TaskResult{
			TaskID:  task.ID,
			Status:  "error",
			Message: fmt.Sprintf("unknown action: %s", task.Action),
		}
	}
}
