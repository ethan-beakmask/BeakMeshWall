package nftables

import (
	"fmt"
	"sort"
	"strings"

	"github.com/anthropics/beakmeshwall-agent/internal/driver"
)

// chainOf maps schema direction to the nftables chain name.
// Init() ensures these chains exist.
func chainOf(direction string) (string, error) {
	switch direction {
	case "input":
		return "filter_input", nil
	case "output":
		return "filter_output", nil
	case "forward":
		return "filter_forward", nil
	default:
		return "", fmt.Errorf("invalid direction %q", direction)
	}
}

func actionOf(action string) (string, error) {
	switch action {
	case "allow":
		return "accept", nil
	case "drop":
		return "drop", nil
	case "reject":
		return "reject", nil
	default:
		return "", fmt.Errorf("invalid action %q", action)
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

// buildComment composes the comment string written to the nftables rule.
//
// nftables hard-caps comment length at 128 bytes. We use the short
// ManagedTagShort marker plus the BMW-ID, then append (and truncate) the
// user comment to fit. Full bilingual warning lives in
// docs/ROADMAP-CONFIG-MANAGEMENT.md and in the table-level documentation;
// individual rule comments only need to be unambiguously identifiable.
//
// Layout: "<ManagedTagShort> :: BMW-ID=<fp>[ :: <user>]"  (<= 128 bytes)
func buildComment(rule driver.SchemaRule) string {
	const nftCommentMax = 128
	prefix := driver.ManagedTagShort + " :: BMW-ID=" + driver.Fingerprint(rule)
	if rule.Comment == "" {
		return prefix
	}
	user := sanitizeComment(rule.Comment)
	full := prefix + " :: " + user
	if len(full) <= nftCommentMax {
		return full
	}
	// Truncate the user portion so the prefix and BMW-ID are always intact.
	avail := nftCommentMax - len(prefix) - len(" :: ")
	if avail <= 0 {
		return prefix
	}
	return prefix + " :: " + user[:avail]
}

// sanitizeComment escapes characters that would break the nft `comment "..."` syntax.
func sanitizeComment(c string) string {
	c = strings.ReplaceAll(c, `\`, `\\`)
	c = strings.ReplaceAll(c, `"`, `\"`)
	c = strings.ReplaceAll(c, "\n", " ")
	return c
}

// translate converts a Stage A SchemaRule into the matching chain name and the
// nft rule body (everything after `add rule <family> <table> <chain>`).
//
// Determinism: the same SchemaRule always produces the same body string,
// so drift detection can compare strings directly.
func translate(rule driver.SchemaRule) (chain, body string, err error) {
	chain, err = chainOf(rule.Direction)
	if err != nil {
		return
	}
	actionTok, err := actionOf(rule.Action)
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

	var parts []string
	if notAny(src) {
		parts = append(parts, "ip saddr "+src)
	}
	if rule.SrcSet != "" {
		parts = append(parts, "ip saddr @"+rule.SrcSet)
	}
	if notAny(dst) {
		parts = append(parts, "ip daddr "+dst)
	}
	if rule.DstSet != "" {
		parts = append(parts, "ip daddr @"+rule.DstSet)
	}
	switch proto {
	case "tcp", "udp":
		hasPort := false
		if notAny(sport) {
			parts = append(parts, fmt.Sprintf("%s sport %s", proto, sport))
			hasPort = true
		}
		if notAny(dport) {
			parts = append(parts, fmt.Sprintf("%s dport %s", proto, dport))
			hasPort = true
		}
		if !hasPort {
			parts = append(parts, "meta l4proto "+proto)
		}
	case "icmp":
		parts = append(parts, "meta l4proto icmp")
	}

	// Stage C: per-rule rate limit.
	if rule.RateLimit != nil {
		burst := ""
		if rule.RateLimit.Burst > 0 {
			burst = fmt.Sprintf(" burst %d packets", rule.RateLimit.Burst)
		}
		parts = append(parts, fmt.Sprintf("limit rate %d/%s%s",
			rule.RateLimit.Count, rule.RateLimit.Period, burst))
	}

	// Stage B: connection state matching.
	if len(rule.State) > 0 {
		states := append([]string(nil), rule.State...)
		sort.Strings(states)
		if len(states) == 1 {
			parts = append(parts, "ct state "+states[0])
		} else {
			parts = append(parts, "ct state { "+strings.Join(states, ", ")+" }")
		}
	}

	// Stage B: logging. nft places log before the verdict.
	if rule.LogEnabled {
		prefix := defaultStr(rule.LogPrefix, "BMW: ")
		level := defaultStr(rule.LogLevel, "info")
		parts = append(parts, fmt.Sprintf(`log prefix "%s" level %s`, sanitizeComment(prefix), level))
	}

	parts = append(parts, actionTok)
	body = strings.Join(parts, " ")
	return
}
