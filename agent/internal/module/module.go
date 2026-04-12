// Package module defines the task dispatch framework for the BeakMeshWall Agent.
// Modules register themselves with a Registry, and the poll loop dispatches
// incoming tasks to the appropriate module by name.
package module

import "fmt"

// Task represents a task dispatched from Central Server.
type Task struct {
	ID     string                 `json:"id"`
	Module string                 `json:"module"`
	Action string                 `json:"action"`
	Params map[string]interface{} `json:"params"`
}

// TaskResult represents the result of executing a task.
type TaskResult struct {
	TaskID  string      `json:"task_id"`
	Status  string      `json:"status"` // "success", "error"
	Message string      `json:"message,omitempty"`
	Data    interface{} `json:"data,omitempty"`
}

// Module is the interface for agent capability modules.
// "firewall" is the first module. Future: "inventory", "audit".
type Module interface {
	// Name returns the module name (must match Task.Module field).
	Name() string
	// HandleTask processes a single task and returns the result.
	HandleTask(task Task) TaskResult
}

// Registry maps module names to Module implementations.
type Registry struct {
	modules map[string]Module
}

// NewRegistry creates a new empty module Registry.
func NewRegistry() *Registry {
	return &Registry{modules: make(map[string]Module)}
}

// Register adds a module to the registry, keyed by its Name().
func (r *Registry) Register(m Module) {
	r.modules[m.Name()] = m
}

// Dispatch routes a task to the appropriate module and returns the result.
// If no module matches the task's Module field, an error result is returned.
func (r *Registry) Dispatch(task Task) TaskResult {
	m, ok := r.modules[task.Module]
	if !ok {
		return TaskResult{
			TaskID:  task.ID,
			Status:  "error",
			Message: fmt.Sprintf("unknown module: %s", task.Module),
		}
	}
	return m.HandleTask(task)
}
