package nftables

import (
	"fmt"
	"strings"
)

// CreateSet creates an empty IPv4 set inside the managed nftables table.
// nft "flags interval" allows CIDR members. Idempotent.
//
// Stage C, see docs/ROADMAP-CONFIG-MANAGEMENT.md section 3.1.
func (d *NFTDriver) CreateSet(name string) error {
	cmd := fmt.Sprintf("add set %s %s %s { type ipv4_addr ; flags interval ; }",
		d.family, d.table, name)
	if err := d.nft(cmd); err != nil {
		if strings.Contains(err.Error(), "File exists") {
			return nil
		}
		return err
	}
	return nil
}

// DeleteSet removes the named set. Idempotent (missing set returns nil).
func (d *NFTDriver) DeleteSet(name string) error {
	cmd := fmt.Sprintf("delete set %s %s %s", d.family, d.table, name)
	if err := d.nft(cmd); err != nil {
		if strings.Contains(err.Error(), "No such file") || strings.Contains(err.Error(), "does not exist") {
			return nil
		}
		return err
	}
	return nil
}

// AddSetMember inserts addr (single IP or CIDR) into the set. Idempotent.
func (d *NFTDriver) AddSetMember(name, addr string) error {
	cmd := fmt.Sprintf("add element %s %s %s { %s }", d.family, d.table, name, addr)
	if err := d.nft(cmd); err != nil {
		if strings.Contains(err.Error(), "File exists") {
			return nil
		}
		return err
	}
	return nil
}

// RemoveSetMember deletes addr from the set. Idempotent.
func (d *NFTDriver) RemoveSetMember(name, addr string) error {
	cmd := fmt.Sprintf("delete element %s %s %s { %s }", d.family, d.table, name, addr)
	if err := d.nft(cmd); err != nil {
		if strings.Contains(err.Error(), "No such file") || strings.Contains(err.Error(), "does not exist") {
			return nil
		}
		return err
	}
	return nil
}
