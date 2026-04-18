// Package nginx collects nginx server block configuration from BMW-compliant config files.
package nginx

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
)

// Location represents a single nginx location block.
type Location struct {
	Path   string `json:"path"`
	Action string `json:"action"`            // "proxy_pass" or "return 444" etc.
	Target string `json:"target,omitempty"`   // proxy_pass target if applicable
}

// Server represents a parsed nginx server block with BMW metadata.
type Server struct {
	File        string     `json:"file"`
	ServiceName string     `json:"service_name"`
	Project     string     `json:"project"`
	Type        string     `json:"type"`      // production, development, tool
	Backend     string     `json:"backend"`   // bmw:backend value
	ListenAddr  string     `json:"listen_addr"`
	ListenPort  int        `json:"listen_port"`
	ServerName  string     `json:"server_name"`
	Locations   []Location `json:"locations"`
}

// State is the collected nginx configuration state.
type State struct {
	ConfigPath       string   `json:"config_path"`
	Compliant        bool     `json:"compliant"`
	Servers          []Server `json:"servers"`
	NonCompliantFiles []string `json:"non_compliant_files"`
}

// Module implements module.Module for nginx config collection.
type Module struct {
	configPath string
}

func New(configPath string) *Module {
	if configPath == "" {
		configPath = "/etc/nginx/sites-enabled"
	}
	return &Module{configPath: configPath}
}

func (m *Module) Name() string {
	return "nginx"
}

// Collect reads all .conf files from the nginx config path and parses
// BMW-compliant server blocks.
func (m *Module) Collect() (interface{}, error) {
	state := &State{
		ConfigPath: m.configPath,
		Compliant:  true,
	}

	files, err := filepath.Glob(filepath.Join(m.configPath, "*.conf"))
	if err != nil {
		return nil, fmt.Errorf("glob nginx configs: %w", err)
	}

	for _, fpath := range files {
		server, compliant, err := parseConfFile(fpath)
		if err != nil {
			// Cannot read file -- report as non-compliant
			state.NonCompliantFiles = append(state.NonCompliantFiles, filepath.Base(fpath))
			state.Compliant = false
			continue
		}
		if !compliant {
			state.NonCompliantFiles = append(state.NonCompliantFiles, filepath.Base(fpath))
			state.Compliant = false
			continue
		}
		state.Servers = append(state.Servers, *server)
	}

	return state, nil
}

// BMW tag patterns
var (
	bmwTagRe    = regexp.MustCompile(`^\s*#\s*bmw:(\w+)\s*=\s*(.+)$`)
	listenRe    = regexp.MustCompile(`^\s*listen\s+(.+);`)
	serverNameRe = regexp.MustCompile(`^\s*server_name\s+(.+);`)
	locationRe  = regexp.MustCompile(`^\s*location\s+(.+?)\s*\{`)
	proxyPassRe = regexp.MustCompile(`^\s*proxy_pass\s+http://(.+);`)
	returnRe    = regexp.MustCompile(`^\s*return\s+(\d+);?`)
)

// parseConfFile reads a single .conf file and returns a parsed Server.
// Returns (nil, false, nil) if the file lacks bmw: tags (non-compliant).
func parseConfFile(path string) (*Server, bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()

	server := &Server{
		File: filepath.Base(path),
	}

	scanner := bufio.NewScanner(f)
	hasBMWTags := false
	var currentLocation string
	inLocation := false
	braceDepth := 0

	for scanner.Scan() {
		line := scanner.Text()
		trimmed := strings.TrimSpace(line)

		// Parse bmw: tags
		if matches := bmwTagRe.FindStringSubmatch(line); len(matches) == 3 {
			hasBMWTags = true
			key := matches[1]
			val := strings.TrimSpace(matches[2])
			switch key {
			case "service_name":
				server.ServiceName = val
			case "project":
				server.Project = val
			case "type":
				server.Type = val
			case "backend":
				server.Backend = val
			}
			continue
		}

		// Parse listen directive
		if matches := listenRe.FindStringSubmatch(line); len(matches) == 2 {
			addr, port := parseListenDirective(strings.TrimSpace(matches[1]))
			server.ListenAddr = addr
			server.ListenPort = port
			continue
		}

		// Parse server_name
		if matches := serverNameRe.FindStringSubmatch(line); len(matches) == 2 {
			server.ServerName = strings.TrimSpace(matches[1])
			continue
		}

		// Parse location blocks
		if matches := locationRe.FindStringSubmatch(line); len(matches) == 2 {
			currentLocation = strings.TrimSpace(matches[1])
			inLocation = true
			braceDepth = 1
			continue
		}

		if inLocation {
			// Track brace depth
			braceDepth += strings.Count(trimmed, "{") - strings.Count(trimmed, "}")
			if braceDepth <= 0 {
				inLocation = false
				currentLocation = ""
				continue
			}

			// Parse proxy_pass inside location
			if matches := proxyPassRe.FindStringSubmatch(line); len(matches) == 2 {
				server.Locations = append(server.Locations, Location{
					Path:   currentLocation,
					Action: "proxy_pass",
					Target: strings.TrimSpace(matches[1]),
				})
				continue
			}

			// Parse return inside location
			if matches := returnRe.FindStringSubmatch(line); len(matches) == 2 {
				server.Locations = append(server.Locations, Location{
					Path:   currentLocation,
					Action: "return " + matches[1],
				})
				continue
			}
		}
	}

	if !hasBMWTags {
		return nil, false, nil
	}

	return server, true, nil
}

// parseListenDirective parses nginx listen values like:
//   "192.168.0.16:8000" -> ("192.168.0.16", 8000)
//   "80" -> ("", 80)
//   "80 default_server" -> ("", 80)
func parseListenDirective(listen string) (string, int) {
	// Remove flags like "default_server"
	parts := strings.Fields(listen)
	addrPort := parts[0]

	// Check for addr:port format
	if idx := strings.LastIndex(addrPort, ":"); idx >= 0 {
		addr := addrPort[:idx]
		port, err := strconv.Atoi(addrPort[idx+1:])
		if err != nil {
			return addr, 0
		}
		return addr, port
	}

	// Port only
	port, err := strconv.Atoi(addrPort)
	if err != nil {
		return "", 0
	}
	return "", port
}
