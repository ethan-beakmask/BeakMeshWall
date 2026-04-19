//go:build linux

package firewall

import (
	"fmt"

	"github.com/anthropics/beakmeshwall-agent/internal/driver"
	"github.com/anthropics/beakmeshwall-agent/internal/driver/nftables"
)

// New creates a firewall module with the specified driver (Linux).
func New(driverName, tableName string) (*Module, error) {
	var drv driver.Driver
	switch driverName {
	case "nftables", "":
		drv = nftables.New(tableName)
	default:
		return nil, fmt.Errorf("unsupported firewall driver on linux: %s", driverName)
	}

	if err := drv.Init(); err != nil {
		return nil, fmt.Errorf("init firewall driver: %w", err)
	}

	return &Module{drv: drv}, nil
}
