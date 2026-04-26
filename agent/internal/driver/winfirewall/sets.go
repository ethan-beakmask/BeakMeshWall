package winfirewall

import (
	"errors"
)

// errStageCUnsupported is returned by every named-set operation. The
// windows_firewall driver is frozen at Stage A and Windows Firewall has no
// equivalent of nftables sets / Linux ipset.
//
// See docs/ROADMAP-CONFIG-MANAGEMENT.md section 7 item 4.
var errStageCUnsupported = errors.New("windows_firewall driver does not support named sets (frozen at Stage A)")

func (d *WinDriver) CreateSet(name string) error          { return errStageCUnsupported }
func (d *WinDriver) DeleteSet(name string) error          { return errStageCUnsupported }
func (d *WinDriver) AddSetMember(name, addr string) error { return errStageCUnsupported }
func (d *WinDriver) RemoveSetMember(name, addr string) error {
	return errStageCUnsupported
}
