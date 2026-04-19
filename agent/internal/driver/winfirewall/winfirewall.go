// Package winfirewall implements driver.Driver for Windows Firewall
// via PowerShell NetSecurity cmdlets.
package winfirewall

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync"

	"github.com/anthropics/beakmeshwall-agent/internal/driver"
)

const (
	groupName  = "BeakMeshWall"
	rulePrefix = "BMW"
)

// WinDriver implements driver.Driver for Windows Firewall.
type WinDriver struct {
	mu      sync.Mutex
	counter int
}

// New creates a WinDriver instance.
func New() *WinDriver {
	return &WinDriver{}
}

func (d *WinDriver) Init() error {
	// Verify PowerShell and NetSecurity module access
	if _, err := d.ps("Get-NetFirewallProfile | Out-Null"); err != nil {
		return fmt.Errorf("cannot access Windows Firewall (need Administrator): %w", err)
	}

	// Scan existing BMW rules to set counter
	rules, err := d.getManagedRules()
	if err != nil {
		return nil // no existing rules
	}
	for _, r := range rules {
		if n := extractHandle(r.Name); n > d.counter {
			d.counter = n
		}
	}
	return nil
}

func (d *WinDriver) GetState() (*driver.FirewallState, error) {
	script := `
$ErrorActionPreference = 'SilentlyContinue'
$all = Get-NetFirewallRule
$managed = @()
$external = @()
foreach ($r in $all) {
    if ($r.Group -eq '` + groupName + `') {
        $af = $r | Get-NetFirewallAddressFilter
        $pf = $r | Get-NetFirewallPortFilter
        $managed += @{
            Name          = $r.Name
            DisplayName   = $r.DisplayName
            Direction     = "$($r.Direction)"
            Action        = "$($r.Action)"
            Enabled       = "$($r.Enabled)"
            RemoteAddress = @($af.RemoteAddress)
            LocalPort     = @($pf.LocalPort)
            Protocol      = "$($pf.Protocol)"
        }
    } else {
        $external += @{
            Name        = $r.Name
            DisplayName = $r.DisplayName
            Direction   = "$($r.Direction)"
            Action      = "$($r.Action)"
            Enabled     = "$($r.Enabled)"
            Group       = "$($r.Group)"
        }
    }
}
$profiles = @(Get-NetFirewallProfile | ForEach-Object {
    @{
        Name           = $_.Name
        Enabled        = "$($_.Enabled)"
        InboundAction  = "$($_.DefaultInboundAction)"
        OutboundAction = "$($_.DefaultOutboundAction)"
    }
})
@{managed=$managed; external=$external; profiles=$profiles} | ConvertTo-Json -Depth 4 -Compress`

	out, err := d.ps(script)
	if err != nil {
		return nil, fmt.Errorf("get firewall state: %w", err)
	}

	var fs psFullState
	if err := json.Unmarshal(out, &fs); err != nil {
		return nil, fmt.Errorf("parse firewall state: %w", err)
	}

	// Build managed table
	managed := &driver.Table{
		Family: "windows",
		Name:   groupName,
	}
	mIn := driver.Chain{Name: "Inbound", Type: "filter", Hook: "input"}
	mOut := driver.Chain{Name: "Outbound", Type: "filter", Hook: "output"}
	for _, r := range fs.Managed {
		rule := driver.Rule{
			Handle:  extractHandle(r.Name),
			Expr:    formatManagedExpr(r),
			Comment: r.DisplayName,
		}
		switch r.Direction {
		case "Inbound":
			mIn.Rules = append(mIn.Rules, rule)
		case "Outbound":
			mOut.Rules = append(mOut.Rules, rule)
		}
	}
	managed.Chains = append(managed.Chains, mIn, mOut)

	// Build external rules table (all non-BMW rules)
	extTable := driver.Table{
		Family: "windows",
		Name:   "External",
	}
	eIn := driver.Chain{Name: "Inbound", Type: "filter", Hook: "input"}
	eOut := driver.Chain{Name: "Outbound", Type: "filter", Hook: "output"}
	for _, r := range fs.External {
		rule := driver.Rule{
			Expr:    fmt.Sprintf("%s %s", r.Action, r.Enabled),
			Comment: r.DisplayName,
		}
		if r.Group != "" {
			rule.Comment = fmt.Sprintf("[%s] %s", r.Group, r.DisplayName)
		}
		switch r.Direction {
		case "Inbound":
			eIn.Rules = append(eIn.Rules, rule)
		case "Outbound":
			eOut.Rules = append(eOut.Rules, rule)
		}
	}
	extTable.Chains = append(extTable.Chains, eIn, eOut)

	// Build profile table
	profTable := driver.Table{
		Family: "windows",
		Name:   "Profiles",
	}
	for _, p := range fs.Profiles {
		ch := driver.Chain{Name: p.Name}
		if p.Enabled == "True" {
			ch.Policy = fmt.Sprintf("in:%s out:%s", p.InboundAction, p.OutboundAction)
		} else {
			ch.Policy = "disabled"
		}
		profTable.Chains = append(profTable.Chains, ch)
	}

	return &driver.FirewallState{
		ManagedTable:   managed,
		ExternalTables: []driver.Table{extTable, profTable},
	}, nil
}

func (d *WinDriver) AddRule(chain, rule, comment string) error {
	d.mu.Lock()
	d.counter++
	handle := d.counter
	d.mu.Unlock()

	name := fmt.Sprintf("%s-%d", rulePrefix, handle)
	direction := normalizeDirection(chain)

	// Parse rule as JSON parameters
	var params ruleParams
	if err := json.Unmarshal([]byte(rule), &params); err != nil {
		return fmt.Errorf("rule must be JSON: %w", err)
	}

	if params.Action == "" {
		params.Action = "Block"
	}
	if params.Protocol == "" {
		params.Protocol = "Any"
	}

	displayName := fmt.Sprintf("%s: %s", rulePrefix, comment)
	if comment == "" {
		displayName = name
	}

	script := fmt.Sprintf(
		`New-NetFirewallRule -Name "%s" -DisplayName "%s" -Group "%s" -Direction %s -Action %s`,
		name, escapePSString(displayName), groupName, direction, params.Action,
	)

	if params.Protocol != "Any" {
		script += fmt.Sprintf(` -Protocol %s`, params.Protocol)
	}
	if params.LocalPort != "" {
		script += fmt.Sprintf(` -LocalPort %s`, params.LocalPort)
	}
	if params.RemoteAddress != "" {
		script += fmt.Sprintf(` -RemoteAddress "%s"`, params.RemoteAddress)
	}
	if params.RemotePort != "" {
		script += fmt.Sprintf(` -RemotePort %s`, params.RemotePort)
	}

	script += " | Out-Null"

	if _, err := d.ps(script); err != nil {
		return fmt.Errorf("add rule: %w", err)
	}
	return nil
}

func (d *WinDriver) DeleteRule(chain string, handle int) error {
	name := fmt.Sprintf("%s-%d", rulePrefix, handle)
	script := fmt.Sprintf(`Remove-NetFirewallRule -Name "%s" -ErrorAction Stop`, name)
	if _, err := d.ps(script); err != nil {
		return fmt.Errorf("delete rule %s: %w", name, err)
	}
	return nil
}

func (d *WinDriver) BlockIP(ip, comment string) error {
	d.mu.Lock()
	d.counter++
	handle := d.counter
	d.mu.Unlock()

	name := fmt.Sprintf("%s-%d", rulePrefix, handle)
	displayName := fmt.Sprintf("%s Block %s", rulePrefix, ip)
	if comment != "" {
		displayName = fmt.Sprintf("%s: %s", rulePrefix, comment)
	}

	// Block both inbound and outbound from/to this IP
	scriptIn := fmt.Sprintf(
		`New-NetFirewallRule -Name "%s-in" -DisplayName "%s (in)" -Group "%s" `+
			`-Direction Inbound -Action Block -RemoteAddress "%s" | Out-Null`,
		name, escapePSString(displayName), groupName, ip,
	)
	scriptOut := fmt.Sprintf(
		`New-NetFirewallRule -Name "%s-out" -DisplayName "%s (out)" -Group "%s" `+
			`-Direction Outbound -Action Block -RemoteAddress "%s" | Out-Null`,
		name, escapePSString(displayName), groupName, ip,
	)

	if _, err := d.ps(scriptIn + "\n" + scriptOut); err != nil {
		return fmt.Errorf("block ip %s: %w", ip, err)
	}
	return nil
}

func (d *WinDriver) UnblockIP(ip string) error {
	// Find and remove all BMW rules that block this IP
	rules, err := d.getManagedRules()
	if err != nil {
		return fmt.Errorf("list rules: %w", err)
	}

	found := false
	for _, r := range rules {
		if r.Action != "Block" {
			continue
		}
		for _, addr := range r.RemoteAddress {
			if addr == ip {
				script := fmt.Sprintf(`Remove-NetFirewallRule -Name "%s" -ErrorAction Stop`, r.Name)
				if _, err := d.ps(script); err != nil {
					return fmt.Errorf("remove rule %s: %w", r.Name, err)
				}
				found = true
				break
			}
		}
	}

	if !found {
		return fmt.Errorf("no matching block rule found for %s", ip)
	}
	return nil
}

func (d *WinDriver) Flush() error {
	script := fmt.Sprintf(
		`Get-NetFirewallRule -Group "%s" -ErrorAction SilentlyContinue | Remove-NetFirewallRule -ErrorAction SilentlyContinue`,
		groupName,
	)
	if _, err := d.ps(script); err != nil {
		return fmt.Errorf("flush rules: %w", err)
	}

	d.mu.Lock()
	d.counter = 0
	d.mu.Unlock()
	return nil
}

// --- internal helpers ---

// ps executes a PowerShell script and returns stdout only.
// Uses Output() instead of CombinedOutput() so stderr warnings don't corrupt JSON.
func (d *WinDriver) ps(script string) ([]byte, error) {
	wrapped := "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8\n" + script
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive",
		"-ExecutionPolicy", "Bypass", "-Command", wrapped)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("powershell: %w", err)
	}
	// Strip UTF-8 BOM if present
	if len(out) >= 3 && out[0] == 0xEF && out[1] == 0xBB && out[2] == 0xBF {
		out = out[3:]
	}
	return out, nil
}

// psRule is the structure for a managed rule (with filter details).
type psRule struct {
	Name          string   `json:"Name"`
	DisplayName   string   `json:"DisplayName"`
	Direction     string   `json:"Direction"`
	Action        string   `json:"Action"`
	Enabled       string   `json:"Enabled"`
	RemoteAddress []string `json:"RemoteAddress"`
	LocalPort     []string `json:"LocalPort"`
	Protocol      string   `json:"Protocol"`
}

// psRuleBasic is the structure for external rules (basic info only).
type psRuleBasic struct {
	Name        string `json:"Name"`
	DisplayName string `json:"DisplayName"`
	Direction   string `json:"Direction"`
	Action      string `json:"Action"`
	Enabled     string `json:"Enabled"`
	Group       string `json:"Group"`
}

type psProfile struct {
	Name           string `json:"Name"`
	Enabled        string `json:"Enabled"`
	InboundAction  string `json:"InboundAction"`
	OutboundAction string `json:"OutboundAction"`
}

type psFullState struct {
	Managed  []psRule      `json:"managed"`
	External []psRuleBasic `json:"external"`
	Profiles []psProfile   `json:"profiles"`
}

// ruleParams is the JSON structure for AddRule's rule parameter.
type ruleParams struct {
	Protocol      string `json:"Protocol"`
	LocalPort     string `json:"LocalPort"`
	RemoteAddress string `json:"RemoteAddress"`
	RemotePort    string `json:"RemotePort"`
	Action        string `json:"Action"`
}

// getManagedRules returns all rules in the BeakMeshWall group.
func (d *WinDriver) getManagedRules() ([]psRule, error) {
	script := `
$ErrorActionPreference = 'SilentlyContinue'
@(Get-NetFirewallRule -Group "` + groupName + `" | ForEach-Object {
    $af = $_ | Get-NetFirewallAddressFilter
    $pf = $_ | Get-NetFirewallPortFilter
    @{
        Name          = $_.Name
        DisplayName   = $_.DisplayName
        Direction     = "$($_.Direction)"
        Action        = "$($_.Action)"
        Enabled       = "$($_.Enabled)"
        RemoteAddress = @($af.RemoteAddress)
        LocalPort     = @($pf.LocalPort)
        Protocol      = "$($pf.Protocol)"
    }
}) | ConvertTo-Json -Depth 3 -Compress`

	out, err := d.ps(script)
	if err != nil {
		return nil, err
	}

	outStr := strings.TrimSpace(string(out))
	if outStr == "" || outStr == "null" {
		return nil, nil
	}

	// PowerShell returns a single object (not array) when there is only one result
	var rules []psRule
	if err := json.Unmarshal([]byte(outStr), &rules); err != nil {
		var single psRule
		if err2 := json.Unmarshal([]byte(outStr), &single); err2 != nil {
			return nil, fmt.Errorf("parse rules: %w", err)
		}
		rules = []psRule{single}
	}
	return rules, nil
}

// extractHandle parses "BMW-42" or "BMW-42-in" and returns 42.
func extractHandle(name string) int {
	name = strings.TrimPrefix(name, rulePrefix+"-")
	// Remove suffix like "-in" or "-out"
	if idx := strings.Index(name, "-"); idx > 0 {
		name = name[:idx]
	}
	n, _ := strconv.Atoi(name)
	return n
}

// normalizeDirection maps chain names to Windows Firewall direction.
func normalizeDirection(chain string) string {
	switch strings.ToLower(chain) {
	case "outbound", "output", "filter_output":
		return "Outbound"
	default:
		return "Inbound"
	}
}

// formatManagedExpr builds a human-readable expression from managed rule parameters.
func formatManagedExpr(r psRule) string {
	parts := []string{r.Action}
	if r.Protocol != "Any" && r.Protocol != "" {
		parts = append(parts, r.Protocol)
	}
	if len(r.RemoteAddress) > 0 && r.RemoteAddress[0] != "Any" {
		parts = append(parts, "from "+strings.Join(r.RemoteAddress, ","))
	}
	if len(r.LocalPort) > 0 && r.LocalPort[0] != "Any" {
		parts = append(parts, "port "+strings.Join(r.LocalPort, ","))
	}
	return strings.Join(parts, " ")
}

// escapePSString escapes double quotes for PowerShell string embedding.
func escapePSString(s string) string {
	return strings.ReplaceAll(s, `"`, "`\"")
}
