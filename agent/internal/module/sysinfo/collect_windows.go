//go:build windows

package sysinfo

// Collect is a placeholder on Windows. User account auditing is not yet implemented.
func (m *Module) Collect() (interface{}, error) {
	return &State{Users: []UserAccount{}}, nil
}
