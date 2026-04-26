package nftables

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/anthropics/beakmeshwall-agent/internal/driver"
)

const (
	defaultFamily = "inet"
	defaultTable  = "beakmeshwall"
	defaultChain  = "filter_input"
	chainPriority = -150
)

// NFTDriver implements driver.Driver for nftables.
type NFTDriver struct {
	family string
	table  string
}

func New(tableName string) *NFTDriver {
	family := defaultFamily
	table := defaultTable

	// Parse "inet beakmeshwall" format
	if tableName != "" {
		parts := strings.SplitN(tableName, " ", 2)
		if len(parts) == 2 {
			family = parts[0]
			table = parts[1]
		} else {
			table = parts[0]
		}
	}

	return &NFTDriver{family: family, table: table}
}

func (d *NFTDriver) Init() error {
	// Create table and the three Stage A chains (input/output/forward).
	// All chains share priority chainPriority (-150) so we sit before
	// most other tools while still leaving room for stricter overrides.
	cmds := []string{
		fmt.Sprintf("add table %s %s", d.family, d.table),
		fmt.Sprintf("add chain %s %s filter_input { type filter hook input priority %d ; policy accept ; }",
			d.family, d.table, chainPriority),
		fmt.Sprintf("add chain %s %s filter_output { type filter hook output priority %d ; policy accept ; }",
			d.family, d.table, chainPriority),
		fmt.Sprintf("add chain %s %s filter_forward { type filter hook forward priority %d ; policy accept ; }",
			d.family, d.table, chainPriority),
	}
	for _, cmd := range cmds {
		if err := d.nft(cmd); err != nil {
			// Tolerate re-runs: existing table/chain returns "File exists".
			if !strings.Contains(err.Error(), "File exists") {
				return fmt.Errorf("init nft: %w (cmd: %s)", err, cmd)
			}
		}
	}
	return nil
}

func (d *NFTDriver) GetState() (*driver.FirewallState, error) {
	// Get full ruleset as JSON
	out, err := exec.Command("nft", "-j", "list", "ruleset").Output()
	if err != nil {
		return nil, fmt.Errorf("nft list ruleset: %w", err)
	}

	var nftJSON map[string]interface{}
	if err := json.Unmarshal(out, &nftJSON); err != nil {
		return nil, fmt.Errorf("parse nft json: %w", err)
	}

	state := &driver.FirewallState{}
	items, _ := nftJSON["nftables"].([]interface{})

	// Collect tables, chains, rules
	tables := make(map[string]*driver.Table) // key: "family name"
	for _, item := range items {
		obj, ok := item.(map[string]interface{})
		if !ok {
			continue
		}

		if t, ok := obj["table"].(map[string]interface{}); ok {
			key := fmt.Sprintf("%s %s", t["family"], t["name"])
			if _, exists := tables[key]; !exists {
				tables[key] = &driver.Table{
					Family: fmt.Sprint(t["family"]),
					Name:   fmt.Sprint(t["name"]),
				}
			}
		}

		if c, ok := obj["chain"].(map[string]interface{}); ok {
			key := fmt.Sprintf("%s %s", c["family"], c["table"])
			if tbl, exists := tables[key]; exists {
				chain := driver.Chain{
					Name: fmt.Sprint(c["name"]),
				}
				if v, ok := c["type"]; ok {
					chain.Type = fmt.Sprint(v)
				}
				if v, ok := c["hook"]; ok {
					chain.Hook = fmt.Sprint(v)
				}
				if v, ok := c["policy"]; ok {
					chain.Policy = fmt.Sprint(v)
				}
				if v, ok := c["prio"].(float64); ok {
					chain.Priority = int(v)
				}
				tbl.Chains = append(tbl.Chains, chain)
			}
		}

		if r, ok := obj["rule"].(map[string]interface{}); ok {
			key := fmt.Sprintf("%s %s", r["family"], r["table"])
			chainName := fmt.Sprint(r["chain"])
			if tbl, exists := tables[key]; exists {
				rule := driver.Rule{
					Chain: chainName,
				}
				if h, ok := r["handle"].(float64); ok {
					rule.Handle = int(h)
				}
				if expr, ok := r["expr"].([]interface{}); ok {
					exprJSON, _ := json.Marshal(expr)
					rule.Expr = string(exprJSON)
				}
				if comment, ok := r["comment"].(string); ok {
					rule.Comment = comment
				}
				// Append rule to matching chain
				for i, ch := range tbl.Chains {
					if ch.Name == chainName {
						tbl.Chains[i].Rules = append(tbl.Chains[i].Rules, rule)
						break
					}
				}
			}
		}
	}

	// Separate managed vs external
	managedKey := fmt.Sprintf("%s %s", d.family, d.table)
	for key, tbl := range tables {
		if key == managedKey {
			state.ManagedTable = tbl
		} else {
			state.ExternalTables = append(state.ExternalTables, *tbl)
		}
	}

	return state, nil
}

func (d *NFTDriver) AddRule(chain, rule, comment string) error {
	cmd := fmt.Sprintf("add rule %s %s %s %s", d.family, d.table, chain, rule)
	if comment != "" {
		cmd += fmt.Sprintf(" comment \"%s\"", comment)
	}
	return d.nft(cmd)
}

func (d *NFTDriver) DeleteRule(chain string, handle int) error {
	cmd := fmt.Sprintf("delete rule %s %s %s handle %d", d.family, d.table, chain, handle)
	return d.nft(cmd)
}

func (d *NFTDriver) BlockIP(ip, comment string) error {
	rule := fmt.Sprintf("ip saddr %s drop", ip)
	if comment == "" {
		comment = "bmw-block"
	}
	return d.AddRule(defaultChain, rule, comment)
}

func (d *NFTDriver) UnblockIP(ip string) error {
	// Find the rule handle for this IP, then delete
	state, err := d.GetState()
	if err != nil {
		return err
	}
	if state.ManagedTable == nil {
		return fmt.Errorf("managed table not found")
	}

	target := fmt.Sprintf("ip saddr %s drop", ip)
	for _, ch := range state.ManagedTable.Chains {
		if ch.Name != defaultChain {
			continue
		}
		for _, r := range ch.Rules {
			// Match by checking if the expression contains the IP drop pattern
			if r.Handle > 0 && strings.Contains(r.Expr, ip) && strings.Contains(r.Expr, "drop") {
				return d.DeleteRule(defaultChain, r.Handle)
			}
			_ = target
		}
	}
	return fmt.Errorf("no matching rule found for %s", ip)
}

func (d *NFTDriver) Flush() error {
	return d.nft(fmt.Sprintf("flush table %s %s", d.family, d.table))
}

func (d *NFTDriver) nft(cmd string) error {
	args := strings.Fields(cmd)
	out, err := exec.Command("nft", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
