//go:build windows

package service

import (
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"
)

// psListener is the JSON structure returned by PowerShell.
type psListener struct {
	Bind    string `json:"Bind"`
	Port    int    `json:"Port"`
	PID     int    `json:"PID"`
	Process string `json:"Process"`
}

// Collect uses PowerShell Get-NetTCPConnection to discover listening sockets.
func (m *Module) Collect() (interface{}, error) {
	script := `
$conns = Get-NetTCPConnection -State Listen -ErrorAction SilentlyContinue
$cache = @{}
$result = @()
foreach ($c in $conns) {
    $pid = $c.OwningProcess
    if (-not $cache.ContainsKey($pid)) {
        $p = Get-Process -Id $pid -ErrorAction SilentlyContinue
        $cache[$pid] = if ($p) { $p.ProcessName } else { "" }
    }
    $result += @{
        Bind    = $c.LocalAddress
        Port    = $c.LocalPort
        PID     = $pid
        Process = $cache[$pid]
    }
}
$result | ConvertTo-Json -Depth 2 -Compress`

	out, err := ps(script)
	if err != nil {
		return nil, fmt.Errorf("collect services: %w", err)
	}

	outStr := strings.TrimSpace(string(out))
	if outStr == "" || outStr == "null" {
		return &State{}, nil
	}

	var listeners []psListener
	if err := json.Unmarshal([]byte(outStr), &listeners); err != nil {
		// PowerShell returns single object (not array) for one result
		var single psListener
		if err2 := json.Unmarshal([]byte(outStr), &single); err2 != nil {
			return nil, fmt.Errorf("parse listeners: %w", err)
		}
		listeners = []psListener{single}
	}

	state := &State{}
	for _, l := range listeners {
		state.Listeners = append(state.Listeners, Listener{
			Bind:    l.Bind,
			Port:    l.Port,
			Process: l.Process,
			PID:     l.PID,
		})
	}

	return state, nil
}

// ps executes a PowerShell script and returns stdout only.
// Uses Output() instead of CombinedOutput() so stderr warnings don't corrupt JSON.
func ps(script string) ([]byte, error) {
	wrapped := "[Console]::OutputEncoding = [System.Text.Encoding]::UTF8\n" + script
	cmd := exec.Command("powershell", "-NoProfile", "-NonInteractive",
		"-ExecutionPolicy", "Bypass", "-Command", wrapped)
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("powershell: %w", err)
	}
	// Strip UTF-8 BOM if present
	if len(out) >= 3 && out[0] == 0xEF && out[1] == 0xBB && out[2] == 0xBF {
		out = out[3:]
	}
	return out, nil
}
