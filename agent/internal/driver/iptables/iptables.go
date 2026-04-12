// Package iptables implements the driver.Driver interface for iptables/ip6tables-based firewalls.
package iptables

import (
	"bufio"
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/anthropics/BeakMeshWall/agent/internal/driver"
)

const (
	// ManagedChain is the iptables chain managed exclusively by BeakMeshWall.
	ManagedChain = "BEAKMESHWALL"

	// commentPrefix is the structured tag prefix used in rule comments
	// to identify rules managed by BeakMeshWall.
	commentPrefix = "bmw:"

	// defaultComment is used when the caller does not supply a comment.
	defaultComment = "BeakMeshWall block"
)

// lineNumRe matches the line number at the beginning of --line-numbers output.
var lineNumRe = regexp.MustCompile(`^(\d+)\s+`)

// IptablesDriver implements driver.Driver using iptables/ip6tables CLI commands.
type IptablesDriver struct {
	logger *slog.Logger
}

// New creates a new IptablesDriver instance.
func New(logger *slog.Logger) *IptablesDriver {
	return &IptablesDriver{
		logger: logger,
	}
}

// Name returns the driver name.
func (d *IptablesDriver) Name() string {
	return "iptables"
}

// Init verifies that iptables is available and sets up the managed chain.
// It creates the BEAKMESHWALL chain and inserts jump rules into INPUT and
// FORWARD for both iptables (IPv4) and ip6tables (IPv6).
func (d *IptablesDriver) Init() error {
	// Check if iptables binary is available
	iptPath, err := exec.LookPath("iptables")
	if err != nil {
		return fmt.Errorf("iptables command not found in PATH: %w", err)
	}
	d.logger.Info("iptables binary found", "path", iptPath)

	// Set up for IPv4
	if err := d.initChain("iptables"); err != nil {
		return fmt.Errorf("iptables IPv4 init: %w", err)
	}

	// Set up for IPv6 (best-effort; ip6tables may not be present)
	if _, err := exec.LookPath("ip6tables"); err == nil {
		if err := d.initChain("ip6tables"); err != nil {
			return fmt.Errorf("ip6tables IPv6 init: %w", err)
		}
	} else {
		d.logger.Warn("ip6tables not found, IPv6 support disabled")
	}

	return nil
}

// initChain creates the managed chain and inserts jump rules for the given
// iptables binary (either "iptables" or "ip6tables").
func (d *IptablesDriver) initChain(binary string) error {
	// Create the BEAKMESHWALL chain (ignore error if it already exists)
	_, err := runCmd(d.logger, binary, "-N", ManagedChain)
	if err != nil {
		// Check if the error is because the chain already exists
		// iptables returns "Chain already exists" in this case
		out, _ := runCmd(d.logger, binary, "-L", ManagedChain, "-n")
		if out == "" {
			return fmt.Errorf("create chain %s with %s: %w", ManagedChain, binary, err)
		}
		d.logger.Debug("chain already exists", "binary", binary, "chain", ManagedChain)
	}

	// Insert jump rule into INPUT if not already present
	if _, err := runCmd(d.logger, binary, "-C", "INPUT", "-j", ManagedChain); err != nil {
		if _, err := runCmd(d.logger, binary, "-I", "INPUT", "-j", ManagedChain); err != nil {
			return fmt.Errorf("insert INPUT jump to %s with %s: %w", ManagedChain, binary, err)
		}
	}

	// Insert jump rule into FORWARD if not already present
	if _, err := runCmd(d.logger, binary, "-C", "FORWARD", "-j", ManagedChain); err != nil {
		if _, err := runCmd(d.logger, binary, "-I", "FORWARD", "-j", ManagedChain); err != nil {
			return fmt.Errorf("insert FORWARD jump to %s with %s: %w", ManagedChain, binary, err)
		}
	}

	d.logger.Info("chain initialized", "binary", binary, "chain", ManagedChain)
	return nil
}

// Close cleans up driver resources. No-op for iptables CLI driver.
func (d *IptablesDriver) Close() error {
	return nil
}

// BlockIP adds a DROP rule for the given IP or CIDR block in the managed chain.
// It uses a structured comment tag "bmw:<ip> | <comment>" for identification.
// Duplicate rules are detected and skipped.
func (d *IptablesDriver) BlockIP(ip string, comment string) error {
	parsed, ok := parseIPOrCIDR(ip)
	if !ok {
		return fmt.Errorf("invalid IP address or CIDR: %q", ip)
	}

	if comment == "" {
		comment = defaultComment
	}

	binary := d.binaryForIP(parsed)
	tag := commentPrefix + ip
	fullComment := fmt.Sprintf("%s | %s", tag, comment)

	// Check for duplicate: use -C to test if an identical rule exists.
	// We only check the source+target since that is sufficient for dedup.
	_, err := runCmd(d.logger, binary, "-C", ManagedChain, "-s", ip, "-j", "DROP")
	if err == nil {
		d.logger.Info("block rule already exists, skipping", "ip", ip)
		return nil
	}

	// Add the rule with comment
	_, err = runCmd(d.logger, binary, "-A", ManagedChain,
		"-s", ip, "-j", "DROP",
		"-m", "comment", "--comment", fullComment)
	if err != nil {
		return fmt.Errorf("add block rule for %s: %w", ip, err)
	}

	d.logger.Info("blocked IP", "ip", ip, "comment", comment, "binary", binary)
	return nil
}

// UnblockIP removes all DROP rules matching the given IP or CIDR block from the
// managed chain. It is idempotent: returns nil if no matching rules are found.
// Rules are deleted from highest line number to lowest to avoid index shifting.
func (d *IptablesDriver) UnblockIP(ip string) error {
	parsed, ok := parseIPOrCIDR(ip)
	if !ok {
		return fmt.Errorf("invalid IP address or CIDR: %q", ip)
	}

	binary := d.binaryForIP(parsed)
	tag := commentPrefix + ip

	if err := d.deleteRulesByTag(binary, tag); err != nil {
		return err
	}

	d.logger.Info("unblocked IP", "ip", ip, "binary", binary)
	return nil
}

// deleteRulesByTag lists rules in the managed chain, finds those whose comment
// contains the given tag, and deletes them by line number (highest first).
func (d *IptablesDriver) deleteRulesByTag(binary, tag string) error {
	out, err := runCmd(d.logger, binary, "-L", ManagedChain, "-n", "--line-numbers",
		"-v")
	if err != nil {
		return fmt.Errorf("list chain %s: %w", ManagedChain, err)
	}

	// Collect line numbers of matching rules
	var lineNums []int

	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()

		// Only process lines that contain our tag.
		// Append " " to prevent false prefix matches (e.g. bmw:10.0.0.1 vs bmw:10.0.0.10).
		if !strings.Contains(line, tag+" ") {
			continue
		}

		// Extract line number from the beginning of the line
		match := lineNumRe.FindStringSubmatch(strings.TrimSpace(line))
		if match == nil {
			continue
		}

		num, err := strconv.Atoi(match[1])
		if err != nil {
			continue
		}
		lineNums = append(lineNums, num)
	}

	// Sort descending so we delete from bottom to top (avoids line number shifting)
	sort.Sort(sort.Reverse(sort.IntSlice(lineNums)))

	for _, num := range lineNums {
		_, err := runCmd(d.logger, binary, "-D", ManagedChain, strconv.Itoa(num))
		if err != nil {
			return fmt.Errorf("delete rule line %d in %s: %w", num, ManagedChain, err)
		}
		d.logger.Debug("deleted rule", "binary", binary, "chain", ManagedChain, "line", num)
	}

	return nil
}

// ListRules returns all rules in the managed chain as structured Rule objects.
// It queries both iptables (IPv4) and ip6tables (IPv6) and returns a combined list.
func (d *IptablesDriver) ListRules() ([]driver.Rule, error) {
	var rules []driver.Rule

	// Parse IPv4 rules
	ipv4Rules, err := d.parseChainRules("iptables", "ip")
	if err != nil {
		return nil, fmt.Errorf("list IPv4 rules: %w", err)
	}
	rules = append(rules, ipv4Rules...)

	// Parse IPv6 rules (best-effort)
	if _, lookErr := exec.LookPath("ip6tables"); lookErr == nil {
		ipv6Rules, err := d.parseChainRules("ip6tables", "ip6")
		if err != nil {
			d.logger.Warn("failed to list IPv6 rules", "error", err)
		} else {
			rules = append(rules, ipv6Rules...)
		}
	}

	return rules, nil
}

// parseChainRules parses the verbose output of iptables/ip6tables for the managed chain.
func (d *IptablesDriver) parseChainRules(binary, family string) ([]driver.Rule, error) {
	out, err := runCmd(d.logger, binary, "-L", ManagedChain, "-n", "-v", "--line-numbers")
	if err != nil {
		return nil, err
	}

	var rules []driver.Rule

	scanner := bufio.NewScanner(strings.NewReader(out))
	lineIdx := 0
	for scanner.Scan() {
		line := scanner.Text()
		lineIdx++

		// Skip the first two header lines (chain header + column titles)
		if lineIdx <= 2 {
			continue
		}

		trimmed := strings.TrimSpace(line)
		if trimmed == "" {
			continue
		}

		rule, ok := d.parseRuleLine(trimmed, family)
		if !ok {
			continue
		}

		rules = append(rules, rule)
	}

	return rules, nil
}

// parseRuleLine parses a single line from iptables -L -v --line-numbers output.
// Expected format (columns):
//
//	num   pkts bytes target  prot opt in  out  source    destination  <extras>
//
// Returns the parsed Rule and true if successful.
func (d *IptablesDriver) parseRuleLine(line, family string) (driver.Rule, bool) {
	fields := strings.Fields(line)
	// Minimum expected fields: num pkts bytes target prot opt in out source destination
	if len(fields) < 10 {
		return driver.Rule{}, false
	}

	lineNum := fields[0]
	pkts, _ := parseCount(fields[1])
	bytes, _ := parseCount(fields[2])
	target := fields[3]
	source := fields[8]

	// Build a human-readable expression
	expr := fmt.Sprintf("%s saddr %s %s", family, source, strings.ToLower(target))

	// Extract comment if present (everything after "/* ... */")
	ruleComment := ""
	commentStart := strings.Index(line, "/* ")
	commentEnd := strings.Index(line, " */")
	if commentStart >= 0 && commentEnd > commentStart {
		ruleComment = line[commentStart+3 : commentEnd]
	}

	return driver.Rule{
		ID:      fmt.Sprintf("%s-%s", family, lineNum),
		Chain:   ManagedChain,
		Expr:    expr,
		Comment: ruleComment,
		Counter: driver.Counter{
			Packets: pkts,
			Bytes:   bytes,
		},
	}, true
}

// ListTables returns a simplified table list for iptables environments.
// Since iptables does not have "tables" in the nftables sense, this returns
// the filter table, the managed chain, and any detected Docker/LXC chains.
func (d *IptablesDriver) ListTables() ([]driver.Table, error) {
	tables := []driver.Table{
		{
			Name:     "filter",
			Family:   "ip",
			Managed:  false,
			External: "",
		},
		{
			Name:     ManagedChain,
			Family:   "ip",
			Managed:  true,
			External: "",
		},
	}

	// Detect external chains (Docker, LXC, etc.)
	out, err := runCmd(d.logger, "iptables", "-L", "-n")
	if err != nil {
		return tables, nil // Return at least the basics
	}

	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()

		// Chain headers look like: "Chain DOCKER (1 references)"
		if !strings.HasPrefix(line, "Chain ") {
			continue
		}

		parts := strings.Fields(line)
		if len(parts) < 2 {
			continue
		}

		chainName := parts[1]

		// Skip chains we already know about
		if chainName == "INPUT" || chainName == "FORWARD" || chainName == "OUTPUT" ||
			chainName == ManagedChain || chainName == "filter" {
			continue
		}

		ext := classifyChain(chainName)
		if ext != "" {
			tables = append(tables, driver.Table{
				Name:     chainName,
				Family:   "ip",
				Managed:  false,
				External: ext,
			})
		}
	}

	return tables, nil
}

// classifyChain determines the origin of a chain based on its name.
// Returns "docker", "lxc", or empty string for unknown chains.
func classifyChain(name string) string {
	lower := strings.ToLower(name)

	if strings.Contains(lower, "docker") {
		return "docker"
	}
	if strings.Contains(lower, "lxc") {
		return "lxc"
	}

	return "other"
}

// binaryForIP returns "iptables" for IPv4 addresses and "ip6tables" for IPv6.
func (d *IptablesDriver) binaryForIP(ip net.IP) string {
	if ip.To4() != nil {
		return "iptables"
	}
	return "ip6tables"
}

// parseCount parses an iptables counter value which may use K/M/G suffixes.
func parseCount(s string) (uint64, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return 0, nil
	}

	multiplier := uint64(1)
	suffix := s[len(s)-1]

	switch suffix {
	case 'K':
		multiplier = 1000
		s = s[:len(s)-1]
	case 'M':
		multiplier = 1000000
		s = s[:len(s)-1]
	case 'G':
		multiplier = 1000000000
		s = s[:len(s)-1]
	}

	val, err := strconv.ParseUint(s, 10, 64)
	if err != nil {
		return 0, err
	}

	return val * multiplier, nil
}

// runCmd executes a command and returns its combined output as a string.
// It logs the command at debug level for troubleshooting.
func runCmd(logger *slog.Logger, name string, args ...string) (string, error) {
	logger.Debug("exec command", "cmd", name, "args", args)

	cmd := exec.Command(name, args...)
	out, err := cmd.CombinedOutput()
	output := strings.TrimSpace(string(out))

	if err != nil {
		return output, fmt.Errorf("%s %s: %w (output: %s)", name, strings.Join(args, " "), err, output)
	}

	return output, nil
}

// parseIPOrCIDR accepts a single IP address ("10.0.0.1") or a CIDR block
// ("10.0.0.0/24") and returns a net.IP suitable for address-family detection.
func parseIPOrCIDR(s string) (net.IP, bool) {
	if ip := net.ParseIP(s); ip != nil {
		return ip, true
	}
	_, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		return nil, false
	}
	return ipNet.IP, true
}

// Ensure IptablesDriver satisfies the Driver interface at compile time.
var _ driver.Driver = (*IptablesDriver)(nil)
