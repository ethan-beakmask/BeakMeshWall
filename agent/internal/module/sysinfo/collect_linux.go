//go:build linux

package sysinfo

import (
	"bufio"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// nologinShells are shells that indicate the account cannot interactively login.
var nologinShells = map[string]bool{
	"/sbin/nologin":     true,
	"/usr/sbin/nologin": true,
	"/bin/false":        true,
	"/usr/bin/false":    true,
}

// Collect gathers local user account information for ISO 27001 auditing.
func (m *Module) Collect() (interface{}, error) {
	users, err := parsePasswd()
	if err != nil {
		return nil, err
	}

	groupMap := buildGroupMap()
	sudoers := getSudoUsers()
	shadowDates := parseShadowDates()
	lastLogins := getLastLogins()

	for i := range users {
		u := &users[i]

		// Classify account type
		if u.UID < 1000 || u.UID == 65534 {
			u.AccountType = "system"
		} else {
			u.AccountType = "human"
		}

		// Can login?
		u.CanLogin = !nologinShells[u.Shell]

		// Groups
		u.Groups = groupMap[u.Username]

		// Can sudo? Check group membership + explicit sudoers
		u.CanSudo = sudoers[u.Username]
		if !u.CanSudo {
			for _, g := range u.Groups {
				if g == "sudo" || g == "wheel" {
					u.CanSudo = true
					break
				}
			}
		}

		// Created date from shadow
		if d, ok := shadowDates[u.Username]; ok {
			u.CreatedDate = d
		}

		// Last login
		if ll, ok := lastLogins[u.Username]; ok {
			u.LastLogin = ll
		}
	}

	return &State{Users: users}, nil
}

// parsePasswd reads /etc/passwd and returns basic user info.
func parsePasswd() ([]UserAccount, error) {
	f, err := os.Open("/etc/passwd")
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var users []UserAccount
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.SplitN(line, ":", 7)
		if len(fields) < 7 {
			continue
		}
		uid, _ := strconv.Atoi(fields[2])
		gid, _ := strconv.Atoi(fields[3])
		users = append(users, UserAccount{
			Username: fields[0],
			UID:      uid,
			GID:      gid,
			Comment:  fields[4],
			HomeDir:  fields[5],
			Shell:    fields[6],
		})
	}
	return users, scanner.Err()
}

// buildGroupMap returns username -> list of group names.
func buildGroupMap() map[string][]string {
	result := make(map[string][]string)

	f, err := os.Open("/etc/group")
	if err != nil {
		return result
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.SplitN(line, ":", 4)
		if len(fields) < 4 {
			continue
		}
		groupName := fields[0]
		members := fields[3]
		if members == "" {
			continue
		}
		for _, user := range strings.Split(members, ",") {
			user = strings.TrimSpace(user)
			if user != "" {
				result[user] = append(result[user], groupName)
			}
		}
	}
	return result
}

// parseShadowDates extracts account creation dates from /etc/shadow.
// The 3rd field is "days since epoch of last password change" which
// approximates the account creation date for accounts that never
// changed their password.
func parseShadowDates() map[string]string {
	result := make(map[string]string)

	f, err := os.Open("/etc/shadow")
	if err != nil {
		return result
	}
	defer f.Close()

	epoch := time.Date(1970, 1, 1, 0, 0, 0, 0, time.UTC)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		fields := strings.SplitN(line, ":", 9)
		if len(fields) < 3 {
			continue
		}
		username := fields[0]
		daysStr := fields[2]
		if daysStr == "" {
			continue
		}
		days, err := strconv.Atoi(daysStr)
		if err != nil || days <= 0 {
			continue
		}
		t := epoch.AddDate(0, 0, days)
		result[username] = t.Format("2006-01-02")
	}
	return result
}

// getLastLogins parses `lastlog` command output.
func getLastLogins() map[string]string {
	result := make(map[string]string)

	out, err := exec.Command("lastlog").Output()
	if err != nil {
		return result
	}

	scanner := bufio.NewScanner(strings.NewReader(string(out)))
	// Skip header
	if scanner.Scan() {
		// discard header line
	}

	for scanner.Scan() {
		line := scanner.Text()
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		username := fields[0]
		// "**Never logged in**" means no login
		if strings.Contains(line, "**Never logged in**") {
			result[username] = "never"
			continue
		}
		// lastlog format: Username  Port  From  Latest
		// Latest is like "Sun Apr 19 12:34:56 +0800 2026"
		// Find the date portion after the third field (Port, From)
		if len(fields) >= 5 {
			// Try to find the date: everything after the From field
			// The From field can be an IP or hostname, followed by date fields
			// Format: username port from weekday month day time year
			// or:     username port from weekday month day time timezone year
			portIdx := strings.Index(line, fields[1])
			if portIdx > 0 {
				rest := strings.TrimSpace(line[portIdx+len(fields[1]):])
				// Skip "From" field (IP/hostname)
				restFields := strings.Fields(rest)
				if len(restFields) >= 2 {
					// restFields[0] is From, everything after is the date
					dateStr := strings.Join(restFields[1:], " ")
					// Try to parse to normalize
					for _, layout := range []string{
						"Mon Jan 2 15:04:05 -0700 2006",
						"Mon Jan 2 15:04:05 +0800 2006",
						"Mon Jan  2 15:04:05 -0700 2006",
						"Mon Jan  2 15:04:05 +0800 2006",
					} {
						if t, err := time.Parse(layout, dateStr); err == nil {
							result[username] = t.Format("2006-01-02 15:04:05")
							break
						}
					}
					// If parsing failed, store raw
					if _, exists := result[username]; !exists {
						result[username] = dateStr
					}
				}
			}
		}
	}
	return result
}

// getSudoUsers checks /etc/sudoers and /etc/sudoers.d/* for explicit user entries.
func getSudoUsers() map[string]bool {
	result := make(map[string]bool)

	// Parse main sudoers file
	parseSudoersFile("/etc/sudoers", result)

	// Parse sudoers.d directory
	entries, err := os.ReadDir("/etc/sudoers.d")
	if err != nil {
		return result
	}
	for _, entry := range entries {
		if entry.IsDir() || strings.HasPrefix(entry.Name(), ".") {
			continue
		}
		parseSudoersFile("/etc/sudoers.d/"+entry.Name(), result)
	}

	return result
}

// parseSudoersFile reads a sudoers file and extracts usernames.
func parseSudoersFile(path string, result map[string]bool) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "Defaults") {
			continue
		}
		// Lines like: username ALL=(ALL:ALL) ALL
		// or: %groupname ALL=(ALL) ALL  (skip groups, handled by group check)
		if strings.HasPrefix(line, "%") || strings.HasPrefix(line, "@") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 && strings.Contains(line, "ALL") {
			result[fields[0]] = true
		}
	}
}
