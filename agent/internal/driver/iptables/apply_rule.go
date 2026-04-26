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

// translate converts a Stage A schema rule into the iptables argv slice
// (without the leading -A or -D, and without the chain name).
//
// Determinism: for the same SchemaRule the produced slice is identical;
// drift detection compares the resulting iptables-save line.
func translate(rule driver.SchemaRule) (chain string, args []string, err error) {
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

	if notAny(src) {
		args = append(args, "-s", src)
	}
	if notAny(dst) {
		args = append(args, "-d", dst)
	}
	if proto != "any" {
		args = append(args, "-p", proto)
		if proto == "tcp" || proto == "udp" {
			// `-m tcp/-m udp` is implicit when -p is set, but explicit form
			// is what iptables-save emits, so keep determinism with output.
			args = append(args, "-m", proto)
			if notAny(sport) {
				args = append(args, "--sport", convertPortRange(sport))
			}
			if notAny(dport) {
				args = append(args, "--dport", convertPortRange(dport))
			}
		}
	}

	args = append(args, "-m", "comment", "--comment", buildComment(rule))
	args = append(args, "-j", target)
	args = append(args, targetArgs...)
	return
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

// ApplyRule installs a Stage A schema rule, idempotent against BMW-ID.
func (d *IPTDriver) ApplyRule(rule driver.SchemaRule) error {
	chain, args, err := translate(rule)
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
	return d.run(append([]string{"-A", chain}, args...)...)
}

// RemoveRule deletes a previously applied schema rule by BMW-ID.
func (d *IPTDriver) RemoveRule(rule driver.SchemaRule) error {
	exists, line, err := d.findManagedRule(driver.Fingerprint(rule))
	if err != nil {
		return fmt.Errorf("scan existing: %w", err)
	}
	if !exists {
		return nil
	}
	chain, _, err := translate(rule)
	if err != nil {
		return err
	}
	return d.run("-D", chain, fmt.Sprint(line))
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

// RemoveByFingerprint removes the managed rule with the given BMW-ID.
func (d *IPTDriver) RemoveByFingerprint(fp string) error {
	chain, line, err := d.locateManagedRule(fp)
	if err != nil {
		return err
	}
	if line == 0 {
		return nil
	}
	return d.run("-D", chain, fmt.Sprint(line))
}
