package nftables

import (
	"fmt"
	"os/exec"
	"strings"

	"github.com/anthropics/beakmeshwall-agent/internal/driver"
)

// ApplyRule installs a Stage A schema rule. Idempotent: if a rule with the
// same BMW-ID fingerprint already exists in the managed table, it is a no-op.
func (d *NFTDriver) ApplyRule(rule driver.SchemaRule) error {
	chain, body, err := translate(rule)
	if err != nil {
		return fmt.Errorf("translate: %w", err)
	}

	fp := driver.Fingerprint(rule)
	handle, err := d.findManagedRule(fp)
	if err != nil {
		return fmt.Errorf("scan existing: %w", err)
	}
	if handle != 0 {
		return nil
	}

	comment := buildComment(rule)
	command := fmt.Sprintf(`add rule %s %s %s %s comment "%s"`,
		d.family, d.table, chain, body, escapeForScript(comment))
	return d.nftStdin(command)
}

// RemoveRule deletes a previously applied schema rule, identified by its
// BMW-ID fingerprint. Idempotent: missing rule returns nil.
func (d *NFTDriver) RemoveRule(rule driver.SchemaRule) error {
	chain, _, err := translate(rule)
	if err != nil {
		return fmt.Errorf("translate: %w", err)
	}
	fp := driver.Fingerprint(rule)
	handle, err := d.findManagedRule(fp)
	if err != nil {
		return fmt.Errorf("scan existing: %w", err)
	}
	if handle == 0 {
		return nil
	}
	return d.DeleteRule(chain, handle)
}

// findManagedRule scans the managed table for a rule whose comment contains
// BMW-ID=<fp>. Returns 0 if not found.
func (d *NFTDriver) findManagedRule(fp string) (int, error) {
	_, handle, err := d.locateManagedRule(fp)
	return handle, err
}

// locateManagedRule returns the chain and handle of the rule with BMW-ID=fp.
// (chain="", handle=0) means not found.
func (d *NFTDriver) locateManagedRule(fp string) (string, int, error) {
	state, err := d.GetState()
	if err != nil {
		return "", 0, err
	}
	if state.ManagedTable == nil {
		return "", 0, nil
	}
	needle := "BMW-ID=" + fp
	for _, ch := range state.ManagedTable.Chains {
		for _, r := range ch.Rules {
			if strings.Contains(r.Comment, needle) && r.Handle > 0 {
				return ch.Name, r.Handle, nil
			}
		}
	}
	return "", 0, nil
}

// RemoveByFingerprint removes the managed rule with the given BMW-ID.
// Idempotent: missing rule returns nil.
func (d *NFTDriver) RemoveByFingerprint(fp string) error {
	chain, handle, err := d.locateManagedRule(fp)
	if err != nil {
		return err
	}
	if handle == 0 {
		return nil
	}
	return d.DeleteRule(chain, handle)
}

// nftStdin runs nft commands via -f /dev/stdin, which is the only safe way
// to pass quoted strings (comments) without shell-escaping issues.
func (d *NFTDriver) nftStdin(commands ...string) error {
	script := strings.Join(commands, "\n") + "\n"
	cmd := exec.Command("nft", "-f", "/dev/stdin")
	cmd.Stdin = strings.NewReader(script)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft: %s: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

// escapeForScript escapes characters that have meaning inside an nft script
// `comment "..."` literal: backslash and double-quote.
// Newlines have already been stripped by sanitizeComment.
func escapeForScript(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	return s
}
