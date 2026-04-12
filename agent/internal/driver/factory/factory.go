// Package factory provides driver auto-detection and factory functions
// for creating firewall driver instances by name.
package factory

import (
	"fmt"
	"log/slog"
	"os/exec"

	"github.com/anthropics/BeakMeshWall/agent/internal/driver"
	"github.com/anthropics/BeakMeshWall/agent/internal/driver/iptables"
	"github.com/anthropics/BeakMeshWall/agent/internal/driver/nftables"
	"github.com/anthropics/BeakMeshWall/agent/internal/driver/pf"
)

// supportedDrivers lists all known driver names for error messages.
var supportedDrivers = []string{"auto", "nftables", "iptables", "pf"}

// Auto detects the best available firewall driver by checking for known
// firewall management binaries in PATH. Detection priority:
// nftables > iptables > pf.
func Auto(logger *slog.Logger) (driver.Driver, error) {
	if _, err := exec.LookPath("nft"); err == nil {
		logger.Info("auto-detected driver", "driver", "nftables")
		return nftables.New(logger), nil
	}

	if _, err := exec.LookPath("iptables"); err == nil {
		logger.Info("auto-detected driver", "driver", "iptables")
		return iptables.New(logger), nil
	}

	if _, err := exec.LookPath("pfctl"); err == nil {
		logger.Info("auto-detected driver", "driver", "pf")
		return pf.New(logger), nil
	}

	return nil, fmt.Errorf("no supported firewall backend found (checked: nft, iptables, pfctl)")
}

// New creates a specific driver by name. When name is "auto" or empty,
// it delegates to Auto for automatic detection.
func New(name string, logger *slog.Logger) (driver.Driver, error) {
	switch name {
	case "auto", "":
		return Auto(logger)
	case "nftables":
		return nftables.New(logger), nil
	case "iptables":
		return iptables.New(logger), nil
	case "pf":
		return pf.New(logger), nil
	default:
		return nil, fmt.Errorf("unknown driver: %q (supported: %v)", name, supportedDrivers)
	}
}
