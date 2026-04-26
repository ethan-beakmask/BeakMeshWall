package driver

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)


// ManagedComment is the marker embedded in every BMW-managed rule's comment
// field. It serves as both the bilingual social-strength warning and the
// machine-readable tag used by drift detection to identify managed rules.
//
// See docs/ROADMAP-CONFIG-MANAGEMENT.md sections 2.3 and 4.1.
const ManagedComment = "MANAGED BY BeakMeshWall - DO NOT EDIT MANUALLY / 由 BeakMeshWall 管理，請勿手動編輯"

// SchemaRule is the unified Stage A firewall rule, translated by each driver
// into its native syntax (nftables / iptables / Windows Firewall).
//
// See docs/ROADMAP-CONFIG-MANAGEMENT.md section 3.1.
type SchemaRule struct {
	Stage     string `json:"stage,omitempty"`
	Action    string `json:"action"`              // allow / drop / reject
	Direction string `json:"direction"`           // input / output / forward
	Proto     string `json:"proto,omitempty"`     // tcp / udp / icmp / any
	Src       string `json:"src,omitempty"`       // IPv4 / CIDR / "any"
	Dst       string `json:"dst,omitempty"`       // IPv4 / CIDR / "any"
	Sport     string `json:"sport,omitempty"`     // port / "X-Y" / "any"
	Dport     string `json:"dport,omitempty"`     // port / "X-Y" / "any"
	Comment   string `json:"comment,omitempty"`
}

// Fingerprint produces a short stable id for a rule, derived from the
// matching fields only (action/direction/proto/src/dst/sport/dport).
// Comment is intentionally excluded so that re-comments do not change the id.
//
// Used to identify managed rules across ApplyRule/RemoveRule and during
// drift detection. All drivers must use this same function so a rule applied
// on one host can be located by id on another (or after a restart).
func Fingerprint(rule SchemaRule) string {
	canon := struct {
		A, D, P, S, T, SP, DP string
	}{
		A:  rule.Action,
		D:  rule.Direction,
		P:  defaultStr(rule.Proto, "any"),
		S:  defaultStr(rule.Src, "any"),
		T:  defaultStr(rule.Dst, "any"),
		SP: defaultStr(rule.Sport, "any"),
		DP: defaultStr(rule.Dport, "any"),
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
}
