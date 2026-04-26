// Package iptables implements driver.Driver for iptables (legacy/nf_tables backend).
//
// Managed area: three custom chains BMW-INPUT / BMW-OUTPUT / BMW-FORWARD,
// each jumped into from the corresponding builtin chain at position 1
// (so BMW rules take priority, matching the nftables driver's priority -150).
//
// External rules (anything not inside the BMW-* chains) are read-only.
//
// Per docs/ROADMAP-CONFIG-MANAGEMENT.md section 2.1.
package iptables

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/anthropics/beakmeshwall-agent/internal/driver"
)

const (
	chainInput   = "BMW-INPUT"
	chainOutput  = "BMW-OUTPUT"
	chainForward = "BMW-FORWARD"
)

// IPTDriver implements driver.Driver for iptables.
type IPTDriver struct {
	binary string // "iptables" or "iptables-legacy"
}

func New() *IPTDriver {
	return &IPTDriver{binary: "iptables"}
}

func (d *IPTDriver) Init() error {
	for _, pair := range [][2]string{
		{chainInput, "INPUT"},
		{chainOutput, "OUTPUT"},
		{chainForward, "FORWARD"},
	} {
		bmwChain, builtin := pair[0], pair[1]
		if err := d.ensureChain(bmwChain); err != nil {
			return fmt.Errorf("create chain %s: %w", bmwChain, err)
		}
		if err := d.ensureJump(builtin, bmwChain); err != nil {
			return fmt.Errorf("link %s -> %s: %w", builtin, bmwChain, err)
		}
	}
	return nil
}

// ensureChain creates the named user chain if it does not yet exist.
func (d *IPTDriver) ensureChain(chain string) error {
	if err := d.run("-N", chain); err != nil {
		// iptables prints "Chain already exists" on retry; tolerate.
		if !strings.Contains(err.Error(), "already exists") {
			return err
		}
	}
	return nil
}

// ensureJump installs `<builtin> -j <bmwChain>` at position 1 if it does not
// exist. -C tests existence; we insert with -I builtin 1 to keep BMW first.
func (d *IPTDriver) ensureJump(builtin, bmwChain string) error {
	if err := d.run("-C", builtin, "-j", bmwChain); err == nil {
		return nil
	}
	return d.run("-I", builtin, "1", "-j", bmwChain)
}

func (d *IPTDriver) run(args ...string) error {
	out, err := exec.Command(d.binary, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s %s: %s", d.binary, strings.Join(args, " "), strings.TrimSpace(string(out)))
	}
	return nil
}

// runOutput runs and returns stdout. Used for iptables-save.
func runOutput(name string, args ...string) (string, error) {
	out, err := exec.Command(name, args...).Output()
	if err != nil {
		return "", fmt.Errorf("%s %s: %w", name, strings.Join(args, " "), err)
	}
	return string(out), nil
}

// GetState returns managed BMW-* chains plus a digest of external rules.
//
// External rules are summarized rather than fully parsed: the driver enforces
// the read-only contract (we never modify them), and drift detection only
// cares about our managed chains.
func (d *IPTDriver) GetState() (*driver.FirewallState, error) {
	out, err := runOutput("iptables-save", "-t", "filter")
	if err != nil {
		return nil, err
	}

	managed := &driver.Table{Family: "ip", Name: "filter (BMW)"}
	chains := map[string]*driver.Chain{
		chainInput:   {Name: chainInput, Type: "filter", Hook: "input"},
		chainOutput:  {Name: chainOutput, Type: "filter", Hook: "output"},
		chainForward: {Name: chainForward, Type: "filter", Hook: "forward"},
	}

	external := driver.Table{Family: "ip", Name: "filter (external)"}
	extByChain := map[string]*driver.Chain{}

	lineNoByChain := map[string]int{}

	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "-A ") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		chainName := fields[1]
		lineNoByChain[chainName]++

		if ch, ok := chains[chainName]; ok {
			ch.Rules = append(ch.Rules, driver.Rule{
				Chain:   chainName,
				Handle:  lineNoByChain[chainName],
				Expr:    line,
				Comment: extractComment(line),
			})
			continue
		}

		ec, ok := extByChain[chainName]
		if !ok {
			ec = &driver.Chain{Name: chainName, Type: "filter"}
			extByChain[chainName] = ec
		}
		ec.Rules = append(ec.Rules, driver.Rule{
			Chain: chainName,
			Expr:  line,
		})
	}

	for _, name := range []string{chainInput, chainOutput, chainForward} {
		managed.Chains = append(managed.Chains, *chains[name])
	}
	for _, ec := range extByChain {
		external.Chains = append(external.Chains, *ec)
	}

	return &driver.FirewallState{
		ManagedTable:   managed,
		ExternalTables: []driver.Table{external},
	}, nil
}

// extractComment pulls the value out of `-m comment --comment "..."`.
// Returns "" if not present.
func extractComment(line string) string {
	idx := strings.Index(line, `--comment "`)
	if idx < 0 {
		return ""
	}
	rest := line[idx+len(`--comment "`):]
	end := strings.Index(rest, `"`)
	if end < 0 {
		return ""
	}
	return rest[:end]
}

// AddRule (legacy free-text). Keeps backwards compatibility with the
// pass-through API. `chain` is the BMW chain name (e.g. "BMW-INPUT") or one
// of {input,output,forward}; `rule` is the iptables rule body without the
// `-A <chain>` prefix.
func (d *IPTDriver) AddRule(chain, rule, comment string) error {
	bmwChain := mapChain(chain)
	args := []string{"-A", bmwChain}
	args = append(args, strings.Fields(rule)...)
	if comment != "" {
		args = append(args, "-m", "comment", "--comment", comment)
	}
	return d.run(args...)
}

// DeleteRule by 1-based line number within the BMW chain.
func (d *IPTDriver) DeleteRule(chain string, handle int) error {
	bmwChain := mapChain(chain)
	return d.run("-D", bmwChain, fmt.Sprint(handle))
}

func (d *IPTDriver) BlockIP(ip, comment string) error {
	if comment == "" {
		comment = "bmw-block"
	}
	return d.run("-A", chainInput, "-s", ip, "-m", "comment", "--comment", comment, "-j", "DROP")
}

func (d *IPTDriver) UnblockIP(ip string) error {
	for {
		// Repeated -D removes one occurrence per call. Loop until iptables
		// reports no matching rule, so duplicates from manual edits are also
		// cleared.
		err := d.run("-D", chainInput, "-s", ip, "-j", "DROP")
		if err == nil {
			continue
		}
		if strings.Contains(err.Error(), "Bad rule") || strings.Contains(err.Error(), "does a matching rule exist") {
			return nil
		}
		return err
	}
}

func (d *IPTDriver) Flush() error {
	for _, ch := range []string{chainInput, chainOutput, chainForward} {
		if err := d.run("-F", ch); err != nil {
			return err
		}
	}
	return nil
}

// mapChain accepts either schema direction names or full BMW chain names.
func mapChain(chain string) string {
	switch strings.ToLower(chain) {
	case "input", "bmw-input":
		return chainInput
	case "output", "bmw-output":
		return chainOutput
	case "forward", "bmw-forward":
		return chainForward
	default:
		// Unknown chain; pass through and let iptables surface the error.
		return chain
	}
}
