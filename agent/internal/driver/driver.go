// Package driver defines the interface for firewall backends.
package driver

// Driver defines the interface for firewall backends.
// Each implementation (nftables, iptables, pf) must satisfy this interface.
type Driver interface {
	// Name returns the driver name (e.g., "nftables", "iptables").
	Name() string

	// Init initializes the driver, creating the managed table if needed.
	Init() error

	// Close cleans up driver resources.
	Close() error

	// BlockIP adds a block rule for the given IP address or CIDR block.
	BlockIP(ip string, comment string) error

	// UnblockIP removes the block rule for the given IP address or CIDR block.
	UnblockIP(ip string) error

	// ListRules returns all rules in the managed table.
	ListRules() ([]Rule, error)

	// ListTables returns all nftables tables (managed + external).
	ListTables() ([]Table, error)
}

// Rule represents a single firewall rule.
type Rule struct {
	ID      string  `json:"id"`
	Chain   string  `json:"chain"`
	Expr    string  `json:"expr"`
	Comment string  `json:"comment"`
	Counter Counter `json:"counter"`
}

// Counter holds packet/byte counters for a rule.
type Counter struct {
	Packets uint64 `json:"packets"`
	Bytes   uint64 `json:"bytes"`
}

// Table represents an nftables table.
type Table struct {
	Name     string `json:"name"`
	Family   string `json:"family"`
	Managed  bool   `json:"managed"`  // true if managed by BeakMeshWall
	External string `json:"external"` // "docker", "lxc", "" if managed
}
