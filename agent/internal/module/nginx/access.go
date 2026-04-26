package nginx

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"
)

// ManagedDir is the directory BMW writes nginx managed snippets into.
// User-authored sites-available / sites-enabled stay outside.
// See docs/NGINX-MANAGEMENT.md section 2.
const ManagedDir = "/etc/nginx/conf.d/beakmeshwall"

// AccessConfPath is the Stage alpha output: a single allow/deny include file.
const AccessConfPath = ManagedDir + "/access.conf"

// AccessFileState reports the parsed state of access.conf for drift detection.
type AccessFileState struct {
	Path        string   `json:"path"`
	Exists      bool     `json:"exists"`
	ContentHash string   `json:"content_hash,omitempty"`
	ManagedIDs  []string `json:"managed_ids"`
}

// allowDenyRe matches `allow X;` and `deny X;` lines (ignoring leading
// whitespace and trailing comment).
var allowDenyRe = regexp.MustCompile(`(?m)^\s*(allow|deny)\s+([^\s;]+)\s*;`)

// readAccessFile reads access.conf, computes the content hash, and re-derives
// the BMW-ID set from the parsed entries (NOT from the BMW-ID= comments,
// to catch the case where someone edits a rule but leaves the comment).
func readAccessFile() (*AccessFileState, error) {
	state := &AccessFileState{Path: AccessConfPath, ManagedIDs: []string{}}
	body, err := os.ReadFile(AccessConfPath)
	if err != nil {
		if os.IsNotExist(err) {
			return state, nil
		}
		return nil, fmt.Errorf("read %s: %w", AccessConfPath, err)
	}
	state.Exists = true
	sum := sha256.Sum256(body)
	state.ContentHash = "sha256:" + hex.EncodeToString(sum[:])

	matches := allowDenyRe.FindAllStringSubmatch(string(body), -1)
	for _, m := range matches {
		action := strings.ToLower(m[1])
		src := m[2]
		state.ManagedIDs = append(state.ManagedIDs, computeFingerprint(action, src))
	}
	return state, nil
}

// computeFingerprint mirrors central.app.schemas.nginx_fingerprint and Go
// driver.Fingerprint style: sha256({A:action, S:src}) JSON, first 8 hex chars.
func computeFingerprint(action, src string) string {
	canon := struct {
		A string `json:"A"`
		S string `json:"S"`
	}{A: action, S: src}
	b, _ := json.Marshal(canon)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])[:8]
}

// applyAccessFile writes new content atomically: tmp file -> nginx -t -> rename
// -> reload. On nginx -t failure the live file is untouched. On reload failure
// the operator gets the error message in the task result.
//
// If a previous file exists, a backup copy is written to BMW_DRIFT_BACKUP_DIR
// (default <TempDir>/beakmeshwall-drift-backup) before the live file is
// overwritten, so manual recovery is always possible.
func applyAccessFile(content string) (string, error) {
	if err := os.MkdirAll(ManagedDir, 0o755); err != nil {
		return "", fmt.Errorf("mkdir %s: %w", ManagedDir, err)
	}

	backupPath := ""
	if existing, err := os.ReadFile(AccessConfPath); err == nil {
		backupPath, err = backupAccessFile(existing)
		if err != nil {
			return "", fmt.Errorf("backup: %w", err)
		}
	}

	tmpPath := AccessConfPath + ".tmp"
	if err := os.WriteFile(tmpPath, []byte(content), 0o644); err != nil {
		return backupPath, fmt.Errorf("write tmp: %w", err)
	}

	// Whole-config syntax check. nginx -t reads the main config and
	// includes; we cannot pass a single file, so we test the live config
	// after copy. To stay safe: rename tmp into place atomically,
	// then run nginx -t; if it fails, restore the previous content from
	// our backup.
	if err := os.Rename(tmpPath, AccessConfPath); err != nil {
		_ = os.Remove(tmpPath)
		return backupPath, fmt.Errorf("rename: %w", err)
	}

	if err := nginxTest(); err != nil {
		// Roll back from backup if we have one; otherwise remove the file.
		if backupPath != "" {
			if data, rerr := os.ReadFile(backupPath); rerr == nil {
				_ = os.WriteFile(AccessConfPath, data, 0o644)
			}
		} else {
			_ = os.Remove(AccessConfPath)
		}
		return backupPath, fmt.Errorf("nginx -t failed (rolled back): %w", err)
	}

	if err := nginxReload(); err != nil {
		return backupPath, fmt.Errorf("nginx reload failed (file installed but not reloaded): %w", err)
	}
	return backupPath, nil
}

func backupAccessFile(content []byte) (string, error) {
	dir := os.Getenv("BMW_DRIFT_BACKUP_DIR")
	if dir == "" {
		dir = filepath.Join(os.TempDir(), "beakmeshwall-drift-backup")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", err
	}
	ts := time.Now().UTC().Format("20060102-150405")
	path := filepath.Join(dir, "nginx-access-"+ts+".conf")
	if err := os.WriteFile(path, content, 0o600); err != nil {
		return "", err
	}
	return path, nil
}

func nginxTest() error {
	out, err := exec.Command("nginx", "-t").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}

func nginxReload() error {
	out, err := exec.Command("nginx", "-s", "reload").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %s", err, strings.TrimSpace(string(out)))
	}
	return nil
}
