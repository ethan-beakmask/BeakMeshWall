//go:build windows

package firewall

import (
	"fmt"

	"github.com/anthropics/beakmeshwall-agent/internal/driver"
	"github.com/anthropics/beakmeshwall-agent/internal/driver/winfirewall"
)

// New creates a firewall module with the specified driver (Windows).
func New(driverName, tableName string) (*Module, error) {
	var drv driver.Driver
	switch driverName {
	case "windows_firewall", "":
		drv = winfirewall.New()
	default:
		return nil, fmt.Errorf("unsupported firewall driver on windows: %s", driverName)
	}

	if err := drv.Init(); err != nil {
		return nil, fmt.Errorf("init firewall driver: %w", err)
	}

	return &Module{drv: drv}, nil
}
