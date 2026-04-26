// Package firewall wraps the OS-specific driver as a module.
package firewall

import (
	"encoding/json"
	"fmt"

	"github.com/anthropics/beakmeshwall-agent/internal/driver"
)

// Module implements module.Module and module.Executor for firewall management.
type Module struct {
	drv driver.Driver
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

	case "apply_rule":
		rule, err := decodeSchemaRule(payload)
		if err != nil {
			return false, err.Error()
		}
		if err := m.drv.ApplyRule(rule); err != nil {
			return false, err.Error()
		}
		return true, "ok"

	case "remove_rule":
		rule, err := decodeSchemaRule(payload)
		if err != nil {
			return false, err.Error()
		}
		if err := m.drv.RemoveRule(rule); err != nil {
			return false, err.Error()
		}
		return true, "ok"

	default:
		return false, fmt.Sprintf("unknown firewall action: %s", action)
	}
}

// decodeSchemaRule extracts the "rule" sub-object from a payload and
// unmarshals it into driver.SchemaRule. The payload comes from JSON, so the
// "rule" value is a map[string]interface{} we re-serialize into the typed struct.
func decodeSchemaRule(payload map[string]interface{}) (driver.SchemaRule, error) {
	raw, ok := payload["rule"]
	if !ok {
		return driver.SchemaRule{}, fmt.Errorf("missing rule")
	}
	b, err := json.Marshal(raw)
	if err != nil {
		return driver.SchemaRule{}, fmt.Errorf("encode rule: %w", err)
	}
	var rule driver.SchemaRule
	if err := json.Unmarshal(b, &rule); err != nil {
		return driver.SchemaRule{}, fmt.Errorf("decode rule: %w", err)
	}
	if rule.Action == "" || rule.Direction == "" {
		return driver.SchemaRule{}, fmt.Errorf("rule missing required action/direction")
	}
	return rule, nil
}
