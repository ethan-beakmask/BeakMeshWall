// Package firewall wraps the OS-specific driver as a module.
package firewall

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/anthropics/beakmeshwall-agent/internal/driver"
)

// Module implements module.Module and module.Executor for firewall management.
type Module struct {
	drv driver.Driver
}

func (m *Module) Name() string {
	return "firewall"
}

// Collect returns the current firewall state plus the set of BMW-IDs found
// in the managed area. Central uses managed_ids for drift detection
// (P6 Stage D). See docs/ROADMAP-CONFIG-MANAGEMENT.md section 4.2.
func (m *Module) Collect() (interface{}, error) {
	state, err := m.drv.GetState()
	if err != nil {
		return nil, err
	}
	report := struct {
		*driver.FirewallState
		ManagedIDs []string `json:"managed_ids"`
	}{
		FirewallState: state,
		ManagedIDs:    extractManagedIDs(state),
	}
	return report, nil
}

// extractManagedIDs walks the managed table and returns every BMW-ID tag
// found in rule comments. The BMW-ID is the schema rule fingerprint that
// driver.Fingerprint() produces (8 hex chars).
func extractManagedIDs(state *driver.FirewallState) []string {
	ids := []string{}
	if state == nil || state.ManagedTable == nil {
		return ids
	}
	for _, ch := range state.ManagedTable.Chains {
		for _, r := range ch.Rules {
			if id := extractBMWID(r.Comment); id != "" {
				ids = append(ids, id)
			}
		}
	}
	return ids
}

func extractBMWID(comment string) string {
	const tag = "BMW-ID="
	idx := strings.Index(comment, tag)
	if idx < 0 {
		return ""
	}
	rest := comment[idx+len(tag):]
	if len(rest) < 8 {
		return ""
	}
	candidate := rest[:8]
	for _, ch := range candidate {
		if !(ch >= '0' && ch <= '9') && !(ch >= 'a' && ch <= 'f') && !(ch >= 'A' && ch <= 'F') {
			return ""
		}
	}
	return candidate
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

	case "cleanup_unmanaged":
		// Reconcile action triggered by the overwrite drift policy.
		// Removes every managed-area rule whose BMW-ID is not in keep_ids.
		// Snapshot the managed area before mutating so the operator can
		// recover if the cleanup decision was wrong.
		// See docs/ROADMAP-CONFIG-MANAGEMENT.md sections 4.3 and 7 item 3.
		keepRaw, _ := payload["keep_ids"].([]interface{})
		keep := map[string]bool{}
		for _, v := range keepRaw {
			if s, ok := v.(string); ok {
				keep[s] = true
			}
		}
		state, err := m.drv.GetState()
		if err != nil {
			return false, err.Error()
		}
		if state == nil || state.ManagedTable == nil {
			return true, "no managed area"
		}
		backupPath, err := backupManagedArea(state)
		if err != nil {
			return false, fmt.Sprintf("backup failed: %s", err)
		}
		removed := 0
		seen := map[string]bool{}
		for _, ch := range state.ManagedTable.Chains {
			for _, r := range ch.Rules {
				id := extractBMWID(r.Comment)
				if id == "" || keep[id] || seen[id] {
					continue
				}
				if err := m.drv.RemoveByFingerprint(id); err != nil {
					return false, fmt.Sprintf("remove %s: %s (backup=%s)", id, err, backupPath)
				}
				seen[id] = true
				removed++
			}
		}
		return true, fmt.Sprintf("removed %d unmanaged (backup=%s)", removed, backupPath)

	default:
		return false, fmt.Sprintf("unknown firewall action: %s", action)
	}
}

// backupManagedArea writes the current FirewallState JSON to a timestamped
// file inside BMW_DRIFT_BACKUP_DIR (default: <TempDir>/beakmeshwall-drift-backup).
// Returns the file path so it can be reported back to Central.
//
// Per docs/ROADMAP-CONFIG-MANAGEMENT.md section 2.4 (overwrite must back up).
func backupManagedArea(state *driver.FirewallState) (string, error) {
	dir := os.Getenv("BMW_DRIFT_BACKUP_DIR")
	if dir == "" {
		dir = filepath.Join(os.TempDir(), "beakmeshwall-drift-backup")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", fmt.Errorf("mkdir %s: %w", dir, err)
	}
	ts := time.Now().UTC().Format("20060102-150405")
	path := filepath.Join(dir, "firewall-"+ts+".json")
	body, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return "", fmt.Errorf("marshal state: %w", err)
	}
	if err := os.WriteFile(path, body, 0o600); err != nil {
		return "", fmt.Errorf("write backup: %w", err)
	}
	return path, nil
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
