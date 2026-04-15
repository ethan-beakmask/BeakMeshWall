package driver

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
}
