// Package nftables implements the driver.Driver interface for nftables-based firewalls.
package nftables

import (
	"bufio"
	"fmt"
	"log/slog"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"

	"github.com/anthropics/BeakMeshWall/agent/internal/driver"
)

const (
	// ManagedTableName is the nftables table managed exclusively by BeakMeshWall.
	ManagedTableName = "beakmeshwall"

	// ManagedTableFamily is the address family for the managed table.
	ManagedTableFamily = "inet"

	// ManagedTablePriority is the nftables priority for the managed chains.
	ManagedTablePriority = -150

	// commentPrefix is the structured tag prefix used in rule comments
	// to identify rules managed by BeakMeshWall.
	commentPrefix = "bmw:"

	// defaultComment is used when the caller does not supply a comment.
	defaultComment = "BeakMeshWall block"
)

// ruleLineRe matches a rule line from "nft -a list table" output.
// Example: `  ip saddr 10.0.0.1 counter packets 0 bytes 0 drop comment "bmw:10.0.0.1" # handle 5`
var ruleLineRe = regexp.MustCompile(`# handle (\d+)`)

// counterRe extracts packet and byte counts from rule output.
// Example: `counter packets 42 bytes 3360`
var counterRe = regexp.MustCompile(`counter packets (\d+) bytes (\d+)`)

// commentRe extracts comment content from a rule line.
// Example: `comment "bmw:10.0.0.1"`
var commentRe = regexp.MustCompile(`comment "([^"]*)"`)

// NftDriver implements driver.Driver using nft CLI commands.
type NftDriver struct {
	logger *slog.Logger
}

// New creates a new NftDriver instance.
func New(logger *slog.Logger) *NftDriver {
	return &NftDriver{
		logger: logger,
	}
}

// Name returns the driver name.
func (d *NftDriver) Name() string {
	return "nftables"
}

// Init verifies that the nft command is available and creates the managed table
// if it does not exist yet.
func (d *NftDriver) Init() error {
	// Check if nft binary is available
	nftPath, err := exec.LookPath("nft")
	if err != nil {
		return fmt.Errorf("nft command not found in PATH: %w", err)
	}
	d.logger.Info("nft binary found", "path", nftPath)

	// Check if managed table already exists
	out, err := d.runNft("list", "tables")
	if err != nil {
		return fmt.Errorf("failed to list nftables tables: %w (output: %s)", err, out)
	}

	tableIdentifier := fmt.Sprintf("table %s %s", ManagedTableFamily, ManagedTableName)
	if strings.Contains(out, tableIdentifier) {
		d.logger.Info("managed table already exists", "table", tableIdentifier)
		return nil
	}

	// Create the managed table with input and forward chains.
	nftCommands := fmt.Sprintf(`
		add table %s %s
		add chain %s %s input { type filter hook input priority %d ; policy accept ; }
		add chain %s %s forward { type filter hook forward priority %d ; policy accept ; }
	`, ManagedTableFamily, ManagedTableName,
		ManagedTableFamily, ManagedTableName, ManagedTablePriority,
		ManagedTableFamily, ManagedTableName, ManagedTablePriority,
	)

	cmd := exec.Command("nft", "-f", "-")
	cmd.Stdin = strings.NewReader(nftCommands)
	rawOut, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to create managed table: %w (output: %s)", err, strings.TrimSpace(string(rawOut)))
	}

	d.logger.Info("created managed table", "table", tableIdentifier)
	return nil
}

// Close cleans up driver resources. No-op for nftables CLI driver.
func (d *NftDriver) Close() error {
	return nil
}

// BlockIP adds drop rules for the specified IP in both the managed input and
// forward chains. It uses a structured comment tag "bmw:<ip>" so rules can be
// identified for later removal. Works with both IPv4 and IPv6 addresses.
func (d *NftDriver) BlockIP(ip string, comment string) error {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return fmt.Errorf("invalid IP address: %q", ip)
	}

	if comment == "" {
		comment = defaultComment
	}

	// Determine the nft selector based on address family
	addrSelector := "ip saddr"
	if parsed.To4() == nil {
		// IPv6
		addrSelector = "ip6 saddr"
	}

	// Build the structured comment tag for rule identification
	tag := commentPrefix + ip

	// Add rule to input chain
	_, err := d.runNft("add", "rule", ManagedTableFamily, ManagedTableName, "input",
		addrSelector, ip, "counter", "drop", "comment", fmt.Sprintf("%s | %s", tag, comment))
	if err != nil {
		return fmt.Errorf("add input rule for %s: %w", ip, err)
	}

	// Add rule to forward chain
	_, err = d.runNft("add", "rule", ManagedTableFamily, ManagedTableName, "forward",
		addrSelector, ip, "counter", "drop", "comment", fmt.Sprintf("%s | %s", tag, comment))
	if err != nil {
		return fmt.Errorf("add forward rule for %s: %w", ip, err)
	}

	d.logger.Info("blocked IP", "ip", ip, "comment", comment)
	return nil
}

// UnblockIP removes all drop rules matching the specified IP from both the
// managed input and forward chains. It is idempotent: returns nil if no
// matching rules are found.
func (d *NftDriver) UnblockIP(ip string) error {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return fmt.Errorf("invalid IP address: %q", ip)
	}

	tag := commentPrefix + ip

	// Remove from input chain
	if err := d.deleteRulesByTag("input", tag); err != nil {
		return fmt.Errorf("unblock from input chain: %w", err)
	}

	// Remove from forward chain
	if err := d.deleteRulesByTag("forward", tag); err != nil {
		return fmt.Errorf("unblock from forward chain: %w", err)
	}

	d.logger.Info("unblocked IP", "ip", ip)
	return nil
}

// deleteRulesByTag lists all rules in the given chain, finds those whose
// comment starts with the given tag, and deletes them by handle number.
func (d *NftDriver) deleteRulesByTag(chain, tag string) error {
	out, err := d.runNft("-a", "list", "chain", ManagedTableFamily, ManagedTableName, chain)
	if err != nil {
		return fmt.Errorf("list chain %s: %w", chain, err)
	}

	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := scanner.Text()

		// Check if the line contains our tag in the comment
		commentMatch := commentRe.FindStringSubmatch(line)
		if commentMatch == nil {
			continue
		}
		commentText := commentMatch[1]

		// The tag must be the prefix of the comment (before the " | " separator)
		if !strings.HasPrefix(commentText, tag) {
			continue
		}

		// Extract handle number
		handleMatch := ruleLineRe.FindStringSubmatch(line)
		if handleMatch == nil {
			continue
		}
		handle := handleMatch[1]

		_, err := d.runNft("delete", "rule", ManagedTableFamily, ManagedTableName, chain, "handle", handle)
		if err != nil {
			return fmt.Errorf("delete rule handle %s in chain %s: %w", handle, chain, err)
		}

		d.logger.Debug("deleted rule", "chain", chain, "handle", handle, "tag", tag)
	}

	return nil
}

// ListRules returns all rules in the managed table as structured Rule objects.
func (d *NftDriver) ListRules() ([]driver.Rule, error) {
	out, err := d.runNft("-a", "list", "table", ManagedTableFamily, ManagedTableName)
	if err != nil {
		return nil, fmt.Errorf("list managed table: %w", err)
	}

	var rules []driver.Rule
	var currentChain string

	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Detect chain context lines: "chain input {"
		if strings.HasPrefix(line, "chain ") && strings.HasSuffix(line, "{") {
			parts := strings.Fields(line)
			if len(parts) >= 2 {
				currentChain = parts[1]
			}
			continue
		}

		// Skip non-rule lines (closing braces, empty, table header, chain policy)
		if line == "}" || line == "" || strings.HasPrefix(line, "table ") || strings.HasPrefix(line, "type ") || strings.HasPrefix(line, "policy ") {
			continue
		}

		// Only parse lines that have a handle (actual rules)
		handleMatch := ruleLineRe.FindStringSubmatch(line)
		if handleMatch == nil {
			continue
		}
		handle := handleMatch[1]

		// Extract comment if present
		ruleComment := ""
		commentMatch := commentRe.FindStringSubmatch(line)
		if commentMatch != nil {
			ruleComment = commentMatch[1]
		}

		// Extract counters if present
		var counter driver.Counter
		counterMatch := counterRe.FindStringSubmatch(line)
		if counterMatch != nil {
			counter.Packets, _ = strconv.ParseUint(counterMatch[1], 10, 64)
			counter.Bytes, _ = strconv.ParseUint(counterMatch[2], 10, 64)
		}

		// Build expression string: everything before "# handle N"
		expr := strings.TrimSpace(ruleLineRe.ReplaceAllString(line, ""))

		rules = append(rules, driver.Rule{
			ID:      handle,
			Chain:   currentChain,
			Expr:    expr,
			Comment: ruleComment,
			Counter: counter,
		})
	}

	return rules, nil
}

// ListTables returns all nftables tables with ownership classification.
// Managed tables (beakmeshwall) are flagged as Managed=true. External tables
// are classified as "docker", "lxc", or "other".
func (d *NftDriver) ListTables() ([]driver.Table, error) {
	out, err := d.runNft("list", "tables")
	if err != nil {
		return nil, fmt.Errorf("list tables: %w", err)
	}

	var tables []driver.Table

	scanner := bufio.NewScanner(strings.NewReader(out))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		// Expected format: "table <family> <name>"
		parts := strings.Fields(line)
		if len(parts) < 3 || parts[0] != "table" {
			continue
		}

		family := parts[1]
		name := parts[2]

		t := driver.Table{
			Name:   name,
			Family: family,
		}

		if name == ManagedTableName {
			t.Managed = true
			t.External = ""
		} else {
			t.Managed = false
			t.External = classifyExternalTable(name)
		}

		tables = append(tables, t)
	}

	return tables, nil
}

// classifyExternalTable determines the origin of a non-managed table based on
// its name. Returns "docker", "lxc", or "other".
func classifyExternalTable(name string) string {
	lower := strings.ToLower(name)

	if strings.Contains(lower, "docker") {
		return "docker"
	}
	if strings.Contains(lower, "lxc") {
		return "lxc"
	}

	return "other"
}

// runNft executes the nft command with the given arguments and returns stdout.
// On failure, it returns an error containing stderr output.
func (d *NftDriver) runNft(args ...string) (string, error) {
	d.logger.Debug("nft command", "args", args)

	cmd := exec.Command("nft", args...)
	out, err := cmd.CombinedOutput()
	output := strings.TrimSpace(string(out))

	if err != nil {
		return output, fmt.Errorf("nft %s: %w (output: %s)", strings.Join(args, " "), err, output)
	}

	return output, nil
}

// Ensure NftDriver satisfies the Driver interface at compile time.
var _ driver.Driver = (*NftDriver)(nil)
