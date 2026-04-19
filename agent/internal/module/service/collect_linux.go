//go:build linux

package service

import (
	"bufio"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
)

// Collect runs ss -tlnp and parses the output.
func (m *Module) Collect() (interface{}, error) {
	out, err := exec.Command("ss", "-tlnp").Output()
	if err != nil {
		return nil, err
	}

	state := &State{}
	scanner := bufio.NewScanner(strings.NewReader(string(out)))

	// Skip header line
	if scanner.Scan() {
		// discard header
	}

	// Pattern to extract process name and pid from users field
	// e.g. users:(("gunicorn",pid=1839,fd=6))
	procRe := regexp.MustCompile(`"([^"]+)",pid=(\d+)`)

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}

		// fields[3] is Local Address:Port, e.g. 127.0.0.1:8000 or *:22 or [::]:22
		localAddr := fields[3]
		bind, port := parseLocalAddr(localAddr)
		if port == 0 {
			continue
		}

		// Extract process info from the users column (last field that contains "users:")
		var procName string
		var pid int
		if matches := procRe.FindStringSubmatch(line); len(matches) == 3 {
			procName = matches[1]
			pid, _ = strconv.Atoi(matches[2])
		}

		state.Listeners = append(state.Listeners, Listener{
			Bind:    bind,
			Port:    port,
			Process: procName,
			PID:     pid,
		})
	}

	return state, nil
}

// parseLocalAddr splits "127.0.0.1:8000" or "*:22" or "[::]:22" or "0.0.0.0:80"
// into bind address and port.
func parseLocalAddr(addr string) (string, int) {
	// Handle IPv6 bracket notation: [::1]:6379 or [::]:22
	if strings.HasPrefix(addr, "[") {
		idx := strings.LastIndex(addr, "]:")
		if idx < 0 {
			return "", 0
		}
		bind := addr[1:idx]
		port, err := strconv.Atoi(addr[idx+2:])
		if err != nil {
			return "", 0
		}
		return bind, port
	}

	// IPv4: split on last colon
	idx := strings.LastIndex(addr, ":")
	if idx < 0 {
		return "", 0
	}

	bind := addr[:idx]
	port, err := strconv.Atoi(addr[idx+1:])
	if err != nil {
		return "", 0
	}

	if bind == "*" {
		bind = "0.0.0.0"
	}

	return bind, port
}
