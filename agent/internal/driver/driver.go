package driver

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)


// ManagedComment is the full bilingual warning. Use this where the medium
// has no length limit (nginx config files, Windows Firewall Description,
// log records, central-side documentation).
//
// See docs/ROADMAP-CONFIG-MANAGEMENT.md sections 2.3 and 4.1.
const ManagedComment = "MANAGED BY BeakMeshWall - DO NOT EDIT MANUALLY / 由 BeakMeshWall 管理，請勿手動編輯"

// ManagedTagShort is the compact warning used inside fixed-width comment
// fields (notably nftables, where the per-rule comment is hard-capped at
// 128 bytes). Combined with BMW-ID and a short user note, this fits.
const ManagedTagShort = "BMW-DO-NOT-EDIT"

// SchemaRule is the unified Stage A+B+C firewall rule, translated by each driver
// into its native syntax (nftables / iptables / Windows Firewall).
//
// Stage A fields: Action, Direction, Proto, Src, Dst, Sport, Dport, Comment.
// Stage B fields: State, LogEnabled, LogPrefix, LogLevel.
// Stage C fields: RateLimit, SrcSet, DstSet.
//
// See docs/ROADMAP-CONFIG-MANAGEMENT.md section 3.1.
type SchemaRule struct {
	Stage      string     `json:"stage,omitempty"`
	Action     string     `json:"action"`
	Direction  string     `json:"direction"`
	Proto      string     `json:"proto,omitempty"`
	Src        string     `json:"src,omitempty"`
	Dst        string     `json:"dst,omitempty"`
	Sport      string     `json:"sport,omitempty"`
	Dport      string     `json:"dport,omitempty"`
	Comment    string     `json:"comment,omitempty"`
	State      []string   `json:"state,omitempty"`
	LogEnabled bool       `json:"log_enabled,omitempty"`
	LogPrefix  string     `json:"log_prefix,omitempty"`
	LogLevel   string     `json:"log_level,omitempty"`
	RateLimit  *RateLimit `json:"rate_limit,omitempty"`
	SrcSet     string     `json:"src_set,omitempty"`
	DstSet     string     `json:"dst_set,omitempty"`
}

// RateLimit configures a per-rule rate limit (Stage C). Period must be one
// of "second", "minute", "hour", "day"; central validates this against the
// JSON schema before sending.
type RateLimit struct {
	Count  int    `json:"count"`
	Period string `json:"period"`
	Burst  int    `json:"burst,omitempty"`
}

// Fingerprint produces a short stable id for a rule. Used to identify
// managed rules across ApplyRule/RemoveRule and during drift detection.
// Must stay byte-identical to schemas.fingerprint() in Python central.
//
// Canonical key order (Go struct declaration order): A, D, P, S, T, SP, DP,
// ST, LE, LP, LL, RL, SS, DS. Defaults are filled in for omitted fields so
// logically equivalent rules produce the same id. Comment is excluded.
func Fingerprint(rule SchemaRule) string {
	state := append([]string(nil), rule.State...)
	sort.Strings(state)
	rlCanon := ""
	if rule.RateLimit != nil {
		rlCanon = fmt.Sprintf("%d/%s/%d", rule.RateLimit.Count, rule.RateLimit.Period, rule.RateLimit.Burst)
	}
	canon := struct {
		A, D, P, S, T, SP, DP, ST string
		LE                        bool
		LP, LL, RL, SS, DS        string
	}{
		A:  rule.Action,
		D:  rule.Direction,
		P:  defaultStr(rule.Proto, "any"),
		S:  defaultStr(rule.Src, "any"),
		T:  defaultStr(rule.Dst, "any"),
		SP: defaultStr(rule.Sport, "any"),
		DP: defaultStr(rule.Dport, "any"),
		ST: strings.Join(state, ","),
		LE: rule.LogEnabled,
		LP: defaultStr(rule.LogPrefix, "BMW: "),
		LL: defaultStr(rule.LogLevel, "info"),
		RL: rlCanon,
		SS: rule.SrcSet,
		DS: rule.DstSet,
	}
	b, _ := json.Marshal(canon)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])[:8]
}

func defaultStr(s, d string) string {
	if s == "" {
		return d
	}
	return s
}

// Rule represents a single firewall rule.
type Rule struct {
	Chain    string `json:"chain"`
	Handle   int    `json:"handle,omitempty"`
	Expr     string `json:"expr"`     // Human-readable expression
	Packets  int64  `json:"packets"`
	Bytes    int64  `json:"bytes"`
	Comment  string `json:"comment,omitempty"`
}

// Table represents a firewall table.
type Table struct {
	Family string `json:"family"` // inet, ip, ip6
	Name   string `json:"name"`
	Chains []Chain `json:"chains"`
}

// Chain represents a chain within a table.
type Chain struct {
	Name     string `json:"name"`
	Type     string `json:"type,omitempty"`     // filter, nat, route
	Hook     string `json:"hook,omitempty"`     // input, output, forward
	Priority int    `json:"priority,omitempty"`
	Policy   string `json:"policy,omitempty"`   // accept, drop
	Rules    []Rule `json:"rules"`
}

// FirewallState is the full snapshot of firewall state.
type FirewallState struct {
	ManagedTable    *Table  `json:"managed_table,omitempty"`
	ExternalTables  []Table `json:"external_tables,omitempty"`
}

// Driver is the interface each OS firewall driver must implement.
type Driver interface {
	// Init sets up the managed table/chain if not exists.
	Init() error

	// GetState returns the current firewall state (managed + external).
	GetState() (*FirewallState, error)

	// AddRule adds a rule to the managed table.
	AddRule(chain, rule, comment string) error

	// DeleteRule removes a rule from the managed table by handle.
	DeleteRule(chain string, handle int) error

	// BlockIP adds a drop rule for the given IP/CIDR.
	BlockIP(ip, comment string) error

	// UnblockIP removes the drop rule for the given IP/CIDR.
	UnblockIP(ip string) error

	// Flush removes all rules from the managed table.
	Flush() error

	// ApplyRule installs a Stage A schema rule into the managed area.
	// Idempotent: if an equivalent rule exists, it is a no-op.
	ApplyRule(rule SchemaRule) error

	// RemoveRule deletes a previously applied schema rule from the managed
	// area, identified by content equivalence. Idempotent: missing rule
	// returns nil.
	RemoveRule(rule SchemaRule) error

	// RemoveByFingerprint deletes the managed rule whose comment carries
	// BMW-ID=<fingerprint>. Used by drift reconcile to evict managed-area
	// rules that are not in central's expected set. Idempotent.
	RemoveByFingerprint(fingerprint string) error

	// Stage C named-set operations. Drivers that don't support named sets
	// (e.g. windows_firewall) return an "unsupported" error.

	// CreateSet creates an empty named IP set in the managed area.
	// Idempotent: existing set is a no-op.
	CreateSet(name string) error

	// DeleteSet removes the named set. Idempotent.
	DeleteSet(name string) error

	// AddSetMember inserts an IP/CIDR into the named set. Idempotent.
	AddSetMember(name, addr string) error

	// RemoveSetMember removes an IP/CIDR from the named set. Idempotent.
	RemoveSetMember(name, addr string) error
}
