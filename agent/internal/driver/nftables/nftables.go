// Package nftables implements the driver.Driver interface for nftables-based firewalls.
package nftables

import (
	"fmt"
	"log/slog"
	"os/exec"
	"strings"

	"github.com/anthropics/BeakMeshWall/agent/internal/driver"
)

const (
	// ManagedTableName is the nftables table managed exclusively by BeakMeshWall.
	ManagedTableName = "beakmeshwall"

	// ManagedTableFamily is the address family for the managed table.
	ManagedTableFamily = "inet"

	// ManagedTablePriority is the nftables priority for the managed chains.
	ManagedTablePriority = -150
)

// NftDriver implements driver.Driver using nft CLI commands.
type NftDriver struct {
	logger *slog.Logger
}

// New creates a new NftDriver instance.
func New(logger *slog.Logger) *NftDriver {
	return &NftDriver{
		logger: logger,
	}
}

// Name returns the driver name.
func (d *NftDriver) Name() string {
	return "nftables"
}

// Init verifies that the nft command is available and creates the managed table
// if it does not exist yet.
func (d *NftDriver) Init() error {
	// Check if nft binary is available
	nftPath, err := exec.LookPath("nft")
	if err != nil {
		return fmt.Errorf("nft command not found in PATH: %w", err)
	}
	d.logger.Info("nft binary found", "path", nftPath)

	// Check if managed table already exists
	// Command: nft list tables
	out, err := exec.Command("nft", "list", "tables").CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to list nftables tables: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}

	tableIdentifier := fmt.Sprintf("table %s %s", ManagedTableFamily, ManagedTableName)
	if strings.Contains(string(out), tableIdentifier) {
		d.logger.Info("managed table already exists", "table", tableIdentifier)
		return nil
	}

	// Create the managed table with input and forward chains.
	// nft add table inet beakmeshwall
	// nft add chain inet beakmeshwall input { type filter hook input priority -150 \; policy accept \; }
	// nft add chain inet beakmeshwall forward { type filter hook forward priority -150 \; policy accept \; }
	nftCommands := fmt.Sprintf(`
		add table %s %s
		add chain %s %s input { type filter hook input priority %d ; policy accept ; }
		add chain %s %s forward { type filter hook forward priority %d ; policy accept ; }
	`, ManagedTableFamily, ManagedTableName,
		ManagedTableFamily, ManagedTableName, ManagedTablePriority,
		ManagedTableFamily, ManagedTableName, ManagedTablePriority,
	)

	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(nftCommands)
	out, err = cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to create managed table: %w (output: %s)", err, strings.TrimSpace(string(out)))
	}

	d.logger.Info("created managed table", "table", tableIdentifier)
	return nil
}

// Close cleans up driver resources. No-op for nftables CLI driver.
func (d *NftDriver) Close() error {
	return nil
}

// BlockIP adds a drop rule for the specified IP in the managed input chain.
// P1 stub: returns not-implemented error.
func (d *NftDriver) BlockIP(ip string, comment string) error {
	// Future implementation:
	// nft add rule inet beakmeshwall input ip saddr <ip> counter drop comment "<comment>"
	// nft add rule inet beakmeshwall input ip6 saddr <ip> counter drop comment "<comment>"
	return fmt.Errorf("BlockIP not implemented in P1")
}

// UnblockIP removes the drop rule for the specified IP from the managed input chain.
// P1 stub: returns not-implemented error.
func (d *NftDriver) UnblockIP(ip string) error {
	// Future implementation:
	// 1. nft -a list chain inet beakmeshwall input  (get handle numbers)
	// 2. Find rule matching ip
	// 3. nft delete rule inet beakmeshwall input handle <N>
	return fmt.Errorf("UnblockIP not implemented in P1")
}

// ListRules returns all rules in the managed table.
// P1 stub: returns not-implemented error.
func (d *NftDriver) ListRules() ([]driver.Rule, error) {
	// Future implementation:
	// nft -j list table inet beakmeshwall  (JSON output)
	// Parse rules from JSON response
	return nil, fmt.Errorf("ListRules not implemented in P1")
}

// ListTables returns all nftables tables with ownership classification.
// P1 stub: returns not-implemented error.
func (d *NftDriver) ListTables() ([]driver.Table, error) {
	// Future implementation:
	// nft list tables
	// Classify each table: managed (beakmeshwall), docker, lxc, or other
	return nil, fmt.Errorf("ListTables not implemented in P1")
}

// Ensure NftDriver satisfies the Driver interface at compile time.
var _ driver.Driver = (*NftDriver)(nil)
