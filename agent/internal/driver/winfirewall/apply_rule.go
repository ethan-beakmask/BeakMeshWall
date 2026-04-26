// Package winfirewall, schema-driven Stage A rule support.
package winfirewall

import (
	"fmt"
	"strings"

	"github.com/anthropics/beakmeshwall-agent/internal/driver"
)

// schemaRulePrefix is the Name prefix used for schema-driven rules.
// Distinct from the legacy counter-based prefix ("BMW-<n>") used by BlockIP/AddRule.
const schemaRulePrefix = "BMW-S-"

// ApplyRule installs a Stage A schema rule. Idempotent: if a rule with the
// same BMW-ID fingerprint already exists in the BeakMeshWall group, it is a no-op.
func (d *WinDriver) ApplyRule(rule driver.SchemaRule) error {
	if err := validateForWindows(rule); err != nil {
		return err
	}

	fp := driver.Fingerprint(rule)
	name := schemaRulePrefix + fp

	exists, err := d.ruleExists(name)
	if err != nil {
		return fmt.Errorf("check existing: %w", err)
	}
	if exists {
		return nil
	}

	script, err := buildNewRuleScript(name, rule)
	if err != nil {
		return fmt.Errorf("build script: %w", err)
	}
	if _, err := d.ps(script); err != nil {
		return fmt.Errorf("apply rule: %w", err)
	}
	return nil
}

// RemoveRule deletes a previously applied schema rule, identified by its
// BMW-ID fingerprint. Idempotent: missing rule returns nil.
func (d *WinDriver) RemoveRule(rule driver.SchemaRule) error {
	fp := driver.Fingerprint(rule)
	name := schemaRulePrefix + fp

	exists, err := d.ruleExists(name)
	if err != nil {
		return fmt.Errorf("check existing: %w", err)
	}
	if !exists {
		return nil
	}

	script := fmt.Sprintf(`Remove-NetFirewallRule -Name "%s" -ErrorAction Stop`, name)
	if _, err := d.ps(script); err != nil {
		return fmt.Errorf("remove rule: %w", err)
	}
	return nil
}

// RemoveByFingerprint removes the schema-applied rule named BMW-S-<fp>.
// Idempotent: missing rule returns nil.
func (d *WinDriver) RemoveByFingerprint(fp string) error {
	name := schemaRulePrefix + fp
	exists, err := d.ruleExists(name)
	if err != nil {
		return fmt.Errorf("check existing: %w", err)
	}
	if !exists {
		return nil
	}
	script := fmt.Sprintf(`Remove-NetFirewallRule -Name "%s" -ErrorAction Stop`, name)
	if _, err := d.ps(script); err != nil {
		return fmt.Errorf("remove rule: %w", err)
	}
	return nil
}

func (d *WinDriver) ruleExists(name string) (bool, error) {
	script := fmt.Sprintf(
		`if (Get-NetFirewallRule -Name "%s" -ErrorAction SilentlyContinue) { 'yes' } else { 'no' }`,
		name,
	)
	out, err := d.ps(script)
	if err != nil {
		return false, err
	}
	return strings.TrimSpace(string(out)) == "yes", nil
}

// validateForWindows enforces the windows_firewall capability subset.
// Central should already have rejected unsupported values, but we duplicate
// the check here as a defense-in-depth measure.
func validateForWindows(rule driver.SchemaRule) error {
	switch rule.Action {
	case "allow", "drop":
	default:
		return fmt.Errorf("windows_firewall does not support action=%q", rule.Action)
	}
	switch rule.Direction {
	case "input", "output":
	default:
		return fmt.Errorf("windows_firewall does not support direction=%q", rule.Direction)
	}
	return nil
}

// buildNewRuleScript builds the New-NetFirewallRule script for a Stage A rule.
//
// Schema-to-Windows field mapping:
//   action allow → -Action Allow
//   action drop  → -Action Block
//   direction input  → Inbound,  src=Remote, dst=Local, sport=RemotePort, dport=LocalPort
//   direction output → Outbound, src=Local,  dst=Remote, sport=LocalPort, dport=RemotePort
//   proto tcp/udp/icmp/any → -Protocol TCP/UDP/ICMPv4/Any
//
// Comment-equivalent fields:
//   DisplayName: short human label including BMW-ID
//   Description: full ManagedComment + user comment + BMW-ID tag
func buildNewRuleScript(name string, rule driver.SchemaRule) (string, error) {
	action := "Block"
	if rule.Action == "allow" {
		action = "Allow"
	}

	var winDirection string
	var localAddr, remoteAddr, localPort, remotePort string

	src := defaultStr(rule.Src, "any")
	dst := defaultStr(rule.Dst, "any")
	sport := defaultStr(rule.Sport, "any")
	dport := defaultStr(rule.Dport, "any")

	switch rule.Direction {
	case "input":
		winDirection = "Inbound"
		remoteAddr = src
		localAddr = dst
		remotePort = sport
		localPort = dport
	case "output":
		winDirection = "Outbound"
		localAddr = src
		remoteAddr = dst
		localPort = sport
		remotePort = dport
	default:
		return "", fmt.Errorf("unsupported direction %q", rule.Direction)
	}

	proto := defaultStr(rule.Proto, "any")
	winProto := ""
	switch proto {
	case "tcp":
		winProto = "TCP"
	case "udp":
		winProto = "UDP"
	case "icmp":
		winProto = "ICMPv4"
	case "any":
		winProto = "Any"
	default:
		return "", fmt.Errorf("unsupported proto %q", proto)
	}

	if proto == "any" && (sport != "any" || dport != "any") {
		return "", fmt.Errorf("sport/dport require proto=tcp or udp")
	}
	if proto == "icmp" && (sport != "any" || dport != "any") {
		return "", fmt.Errorf("icmp does not support sport/dport")
	}

	displayName := name
	if rule.Comment != "" {
		displayName = name + ": " + rule.Comment
	}
	description := driver.ManagedComment + " :: BMW-ID=" + driver.Fingerprint(rule)
	if rule.Comment != "" {
		description += " :: " + rule.Comment
	}

	parts := []string{
		fmt.Sprintf(`New-NetFirewallRule -Name "%s"`, name),
		fmt.Sprintf(`-DisplayName "%s"`, escapePSString(displayName)),
		fmt.Sprintf(`-Group "%s"`, groupName),
		fmt.Sprintf(`-Direction %s`, winDirection),
		fmt.Sprintf(`-Action %s`, action),
		fmt.Sprintf(`-Description "%s"`, escapePSString(description)),
	}
	if winProto != "Any" {
		parts = append(parts, fmt.Sprintf(`-Protocol %s`, winProto))
	}
	if remoteAddr != "any" {
		parts = append(parts, fmt.Sprintf(`-RemoteAddress "%s"`, remoteAddr))
	}
	if localAddr != "any" {
		parts = append(parts, fmt.Sprintf(`-LocalAddress "%s"`, localAddr))
	}
	if remotePort != "any" {
		parts = append(parts, fmt.Sprintf(`-RemotePort %s`, normalizePortForPS(remotePort)))
	}
	if localPort != "any" {
		parts = append(parts, fmt.Sprintf(`-LocalPort %s`, normalizePortForPS(localPort)))
	}
	parts = append(parts, "| Out-Null")

	return strings.Join(parts, " "), nil
}

func defaultStr(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

// normalizePortForPS converts schema port format to PowerShell -RemotePort/-LocalPort
// argument. PowerShell accepts a single port, a range "X-Y", or a comma list.
// Stage A schema only emits single port or "X-Y", both pass through unchanged.
func normalizePortForPS(p string) string {
	return p
}
