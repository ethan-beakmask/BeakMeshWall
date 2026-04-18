// Package firewall wraps the existing driver as a module.
package firewall

import (
	"fmt"

	"github.com/anthropics/beakmeshwall-agent/internal/driver"
	"github.com/anthropics/beakmeshwall-agent/internal/driver/nftables"
)

// Module implements module.Module and module.Executor for firewall management.
type Module struct {
	drv driver.Driver
}

// New creates a firewall module with the specified driver.
func New(driverName, tableName string) (*Module, error) {
	var drv driver.Driver
	switch driverName {
	case "nftables", "":
		drv = nftables.New(tableName)
	default:
		return nil, fmt.Errorf("unsupported firewall driver: %s", driverName)
	}

	if err := drv.Init(); err != nil {
		return nil, fmt.Errorf("init firewall driver: %w", err)
	}

	return &Module{drv: drv}, nil
}

func (m *Module) Name() string {
	return "firewall"
}

// Collect returns the current firewall state (managed + external tables).
func (m *Module) Collect() (interface{}, error) {
	return m.drv.GetState()
}

// Execute runs a firewall task and returns success/detail.
func (m *Module) Execute(action string, payload map[string]interface{}) (bool, string) {
	switch action {
	case "block_ip":
		ip, _ := payload["ip"].(string)
		comment, _ := payload["comment"].(string)
		if ip == "" {
			return false, "missing ip"
		}
		if err := m.drv.BlockIP(ip, comment); err != nil {
			return false, err.Error()
		}
		return true, "ok"

	case "unblock_ip":
		ip, _ := payload["ip"].(string)
		if ip == "" {
			return false, "missing ip"
		}
		if err := m.drv.UnblockIP(ip); err != nil {
			return false, err.Error()
		}
		return true, "ok"

	case "add_rule":
		chain, _ := payload["chain"].(string)
		rule, _ := payload["rule"].(string)
		comment, _ := payload["comment"].(string)
		if rule == "" {
			return false, "missing rule"
		}
		if chain == "" {
			chain = "filter_input"
		}
		if err := m.drv.AddRule(chain, rule, comment); err != nil {
			return false, err.Error()
		}
		return true, "ok"

	case "delete_rule":
		chain, _ := payload["chain"].(string)
		handle, _ := payload["handle"].(float64)
		if chain == "" {
			chain = "filter_input"
		}
		if err := m.drv.DeleteRule(chain, int(handle)); err != nil {
			return false, err.Error()
		}
		return true, "ok"

	case "flush":
		if err := m.drv.Flush(); err != nil {
			return false, err.Error()
		}
		return true, "ok"

	default:
		return false, fmt.Sprintf("unknown firewall action: %s", action)
	}
}
