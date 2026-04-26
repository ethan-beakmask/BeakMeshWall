package iptables

import (
	"fmt"
	"strings"

	"github.com/anthropics/beakmeshwall-agent/internal/driver"
)

// chainOf maps a schema direction to the BMW iptables chain name.
func chainOf(direction string) (string, error) {
	switch direction {
	case "input":
		return chainInput, nil
	case "output":
		return chainOutput, nil
	case "forward":
		return chainForward, nil
	default:
		return "", fmt.Errorf("invalid direction %q", direction)
	}
}

// targetOf maps a schema action to the iptables target (-j argument).
func targetOf(action string) (string, []string, error) {
	switch action {
	case "allow":
		return "ACCEPT", nil, nil
	case "drop":
		return "DROP", nil, nil
	case "reject":
		return "REJECT", []string{"--reject-with", "icmp-port-unreachable"}, nil
	default:
		return "", nil, fmt.Errorf("invalid action %q", action)
	}
}

func notAny(s string) bool {
	return s != "" && s != "any"
}

func defaultStr(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

// translate converts a Stage A+B schema rule into the iptables argv slice(s)
// (without the leading -A/-D and without the chain name).
//
// When log_enabled is true the schema rule maps to TWO iptables rules:
//
//   1. matchArgs + -j LOG --log-prefix ... --log-level ...
//   2. matchArgs + -j <ACCEPT/DROP/REJECT>
//
// The LOG jump does not stop processing, so the action rule still applies.
// Both rules carry the same BMW-ID in their comment so drift detection and
// RemoveByFingerprint locate them together.
//
// Determinism: same SchemaRule -> same argv, same order, so iptables-save
// output is byte-stable.
func translate(rule driver.SchemaRule) (chain string, ruleArgs [][]string, err error) {
	chain, err = chainOf(rule.Direction)
	if err != nil {
		return
	}

	target, targetArgs, err := targetOf(rule.Action)
	if err != nil {
		return
	}

	proto := defaultStr(rule.Proto, "any")
	src := defaultStr(rule.Src, "any")
	dst := defaultStr(rule.Dst, "any")
	sport := defaultStr(rule.Sport, "any")
	dport := defaultStr(rule.Dport, "any")

	if proto == "any" && (notAny(sport) || notAny(dport)) {
		err = fmt.Errorf("sport/dport require proto to be tcp or udp")
		return
	}
	if proto == "icmp" && (notAny(sport) || notAny(dport)) {
		err = fmt.Errorf("icmp does not support sport/dport")
		return
	}

	var matchArgs []string
	if notAny(src) {
		matchArgs = append(matchArgs, "-s", src)
	}
	if notAny(dst) {
		matchArgs = append(matchArgs, "-d", dst)
	}
	if proto != "any" {
		matchArgs = append(matchArgs, "-p", proto)
		if proto == "tcp" || proto == "udp" {
			matchArgs = append(matchArgs, "-m", proto)
			if notAny(sport) {
				matchArgs = append(matchArgs, "--sport", convertPortRange(sport))
			}
			if notAny(dport) {
				matchArgs = append(matchArgs, "--dport", convertPortRange(dport))
			}
		}
	}

	// Stage B: connection state.
	if len(rule.State) > 0 {
		matchArgs = append(matchArgs, "-m", "conntrack", "--ctstate", joinStateUpper(rule.State))
	}

	// Common comment carries BMW-ID for both log and action rules.
	commentArgs := []string{"-m", "comment", "--comment", buildComment(rule)}

	// Stage B: optional log rule, emitted before the action rule so it
	// fires first when iptables walks the chain.
	if rule.LogEnabled {
		logArgs := append([]string{}, matchArgs...)
		logArgs = append(logArgs, commentArgs...)
		logArgs = append(logArgs, "-j", "LOG",
			"--log-prefix", defaultStr(rule.LogPrefix, "BMW: "),
			"--log-level", defaultStr(rule.LogLevel, "info"))
		ruleArgs = append(ruleArgs, logArgs)
	}

	actionArgs := append([]string{}, matchArgs...)
	actionArgs = append(actionArgs, commentArgs...)
	actionArgs = append(actionArgs, "-j", target)
	actionArgs = append(actionArgs, targetArgs...)
	ruleArgs = append(ruleArgs, actionArgs)
	return
}

func joinStateUpper(states []string) string {
	upper := make([]string, 0, len(states))
	for _, s := range states {
		upper = append(upper, strings.ToUpper(s))
	}
	// Sort for deterministic output (matches central-side fingerprint canonicalization).
	for i := 0; i < len(upper); i++ {
		for j := i + 1; j < len(upper); j++ {
			if upper[i] > upper[j] {
				upper[i], upper[j] = upper[j], upper[i]
			}
		}
	}
	return strings.Join(upper, ",")
}

// convertPortRange turns the schema "X-Y" range into iptables "X:Y" syntax.
// Single ports pass through unchanged.
func convertPortRange(p string) string {
	return strings.ReplaceAll(p, "-", ":")
}

// buildComment composes the iptables comment string. iptables comments are
// limited to 256 bytes; we keep the warning + BMW-ID and truncate the user
// portion if needed.
func buildComment(rule driver.SchemaRule) string {
	const maxLen = 250
	prefix := driver.ManagedComment + " :: BMW-ID=" + driver.Fingerprint(rule)
	if rule.Comment == "" {
		return prefix
	}
	full := prefix + " :: " + rule.Comment
	if len(full) <= maxLen {
		return full
	}
	return full[:maxLen]
}

// ApplyRule installs a Stage A+B schema rule, idempotent against BMW-ID.
// Stage B log_enabled emits two rules (LOG + action); both carry the same
// fingerprint so RemoveRule can clean them up together.
func (d *IPTDriver) ApplyRule(rule driver.SchemaRule) error {
	chain, ruleArgs, err := translate(rule)
	if err != nil {
		return fmt.Errorf("translate: %w", err)
	}
	exists, _, err := d.findManagedRule(driver.Fingerprint(rule))
	if err != nil {
		return fmt.Errorf("scan existing: %w", err)
	}
	if exists {
		return nil
	}
	for _, args := range ruleArgs {
		if err := d.run(append([]string{"-A", chain}, args...)...); err != nil {
			return err
		}
	}
	return nil
}

// RemoveRule deletes every iptables rule that carries this schema's BMW-ID.
// Idempotent: missing rules return nil. Loops because line numbers shift
// after each delete.
func (d *IPTDriver) RemoveRule(rule driver.SchemaRule) error {
	return d.removeByFingerprintAll(driver.Fingerprint(rule))
}

// findManagedRule scans BMW-* chains for a rule whose comment contains
// BMW-ID=<fp>. Returns the 1-based line number within its chain.
func (d *IPTDriver) findManagedRule(fp string) (bool, int, error) {
	_, line, err := d.locateManagedRule(fp)
	return line > 0, line, err
}

// locateManagedRule additionally returns the BMW-* chain containing the rule.
func (d *IPTDriver) locateManagedRule(fp string) (string, int, error) {
	state, err := d.GetState()
	if err != nil {
		return "", 0, err
	}
	if state.ManagedTable == nil {
		return "", 0, nil
	}
	needle := "BMW-ID=" + fp
	for _, ch := range state.ManagedTable.Chains {
		for _, r := range ch.Rules {
			if strings.Contains(r.Comment, needle) {
				return ch.Name, r.Handle, nil
			}
		}
	}
	return "", 0, nil
}

// RemoveByFingerprint removes every managed rule with the given BMW-ID.
// Stage B may install multiple rules per fingerprint (LOG + action), so we
// loop until none remain.
func (d *IPTDriver) RemoveByFingerprint(fp string) error {
	return d.removeByFingerprintAll(fp)
}

func (d *IPTDriver) removeByFingerprintAll(fp string) error {
	for {
		chain, line, err := d.locateManagedRule(fp)
		if err != nil {
			return err
		}
		if line == 0 {
			return nil
		}
		if err := d.run("-D", chain, fmt.Sprint(line)); err != nil {
			return err
		}
	}
}
