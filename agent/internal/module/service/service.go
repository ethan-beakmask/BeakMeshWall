// Package service collects listening socket information from the node.
package service

// Listener represents a single listening socket.
type Listener struct {
	Bind    string `json:"bind"`
	Port    int    `json:"port"`
	Process string `json:"process"`
	PID     int    `json:"pid"`
}

// State is the collected service state.
type State struct {
	Listeners []Listener `json:"listeners"`
}

// Module implements module.Module for service discovery.
type Module struct{}

func New() *Module {
	return &Module{}
}

func (m *Module) Name() string {
	return "service"
}
