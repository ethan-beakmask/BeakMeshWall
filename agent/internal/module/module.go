// Package module defines the interface for agent data collection modules.
package module

// Module collects state from one subsystem on the node.
type Module interface {
	// Name returns the module identifier (e.g. "firewall", "nginx", "service").
	Name() string

	// Collect gathers current state and returns a JSON-serializable value.
	Collect() (interface{}, error)
}

// Executor is optionally implemented by modules that can execute tasks.
type Executor interface {
	// Execute runs a task and returns a result.
	Execute(action string, payload map[string]interface{}) (success bool, detail string)
}
