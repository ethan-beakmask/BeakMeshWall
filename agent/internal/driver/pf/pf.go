// Package pf provides a stub driver.Driver implementation for BSD pf firewall.
// All methods except Name() and Close() return an error indicating that pf is
// not implemented. This driver exists as a placeholder for future BSD support.
package pf

import (
	"fmt"
	"log/slog"

	"github.com/anthropics/BeakMeshWall/agent/internal/driver"
)

// PfDriver is a stub implementation of driver.Driver for BSD pf.
type PfDriver struct {
	logger *slog.Logger
}

// New creates a new PfDriver instance.
func New(logger *slog.Logger) *PfDriver {
	return &PfDriver{logger: logger}
}

// Name returns the driver name.
func (d *PfDriver) Name() string {
	return "pf"
}

// Init returns an error because pf is only available on BSD systems.
func (d *PfDriver) Init() error {
	return fmt.Errorf("pf driver: not implemented (BSD only)")
}

// Close is a no-op for the stub driver.
func (d *PfDriver) Close() error {
	return nil
}

// BlockIP returns an error because pf is not implemented.
func (d *PfDriver) BlockIP(ip, comment string) error {
	return fmt.Errorf("pf driver: not implemented")
}

// UnblockIP returns an error because pf is not implemented.
func (d *PfDriver) UnblockIP(ip string) error {
	return fmt.Errorf("pf driver: not implemented")
}

// ListRules returns an error because pf is not implemented.
func (d *PfDriver) ListRules() ([]driver.Rule, error) {
	return nil, fmt.Errorf("pf driver: not implemented")
}

// ListTables returns an error because pf is not implemented.
func (d *PfDriver) ListTables() ([]driver.Table, error) {
	return nil, fmt.Errorf("pf driver: not implemented")
}

// Ensure PfDriver satisfies the Driver interface at compile time.
var _ driver.Driver = (*PfDriver)(nil)
