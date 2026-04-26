package iptables

import (
	"fmt"
	"os/exec"
	"strings"
)

// setName prefixes user names with "BMW-" so the managed namespace is
// always identifiable inside `ipset list`.
func setName(name string) string {
	return "BMW-" + name
}

func ipsetRun(args ...string) error {
	out, err := exec.Command("ipset", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("ipset %s: %s", strings.Join(args, " "), strings.TrimSpace(string(out)))
	}
	return nil
}

// CreateSet creates a hash:net IPv4 set via ipset(8). Idempotent (-exist flag).
//
// Stage C, see docs/ROADMAP-CONFIG-MANAGEMENT.md section 3.1.
func (d *IPTDriver) CreateSet(name string) error {
	return ipsetRun("create", setName(name), "hash:net", "family", "inet", "-exist")
}

// DeleteSet destroys the set. Idempotent: missing set returns nil.
func (d *IPTDriver) DeleteSet(name string) error {
	err := ipsetRun("destroy", setName(name))
	if err != nil && strings.Contains(err.Error(), "does not exist") {
		return nil
	}
	return err
}

// AddSetMember inserts addr into the set. Idempotent.
func (d *IPTDriver) AddSetMember(name, addr string) error {
	return ipsetRun("add", setName(name), addr, "-exist")
}

// RemoveSetMember removes addr from the set. Idempotent.
func (d *IPTDriver) RemoveSetMember(name, addr string) error {
	err := ipsetRun("del", setName(name), addr)
	if err != nil && (strings.Contains(err.Error(), "not added") ||
		strings.Contains(err.Error(), "Element cannot be deleted") ||
		strings.Contains(err.Error(), "does not exist")) {
		return nil
	}
	return err
}
