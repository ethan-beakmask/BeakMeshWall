// Package sysinfo collects system information (user accounts, etc.)
// for asset inventory and compliance auditing (ISO 27001).
package sysinfo

// Module collects system information from the host.
type Module struct{}

// New creates a new sysinfo module.
func New() *Module {
	return &Module{}
}

// Name returns the module identifier.
func (m *Module) Name() string {
	return "sysinfo"
}

// UserAccount represents a local user account on the system.
type UserAccount struct {
	Username    string   `json:"username"`
	UID         int      `json:"uid"`
	GID         int      `json:"gid"`
	Comment     string   `json:"comment"`     // GECOS field
	HomeDir     string   `json:"home_dir"`
	Shell       string   `json:"shell"`
	Groups      []string `json:"groups"`       // all groups this user belongs to
	AccountType string   `json:"account_type"` // "human" or "system"
	CanLogin    bool     `json:"can_login"`    // shell is not nologin/false
	CanSudo     bool     `json:"can_sudo"`     // in sudo/wheel group or in sudoers
	CreatedDate string   `json:"created_date"` // from shadow or passwd mtime
	LastLogin   string   `json:"last_login"`   // from lastlog
}

// State is the top-level sysinfo state reported to Central.
type State struct {
	Users []UserAccount `json:"users"`
}
