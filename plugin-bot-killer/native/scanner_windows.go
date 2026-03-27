//go:build windows

package main

import (
	"encoding/csv"
	"fmt"
	"hash/fnv"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"unsafe"
)

// ── Registry helpers ─────────────────────────────────────────────────────────

const (
	hkcu = syscall.Handle(0x80000001)
	hklm = syscall.Handle(0x80000002)
)

var (
	advapi32         = syscall.NewLazyDLL("advapi32.dll")
	procRegEnumValue = advapi32.NewProc("RegEnumValueW")
)

func regOpen(root syscall.Handle, path string) (syscall.Handle, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	var key syscall.Handle
	if err := syscall.RegOpenKeyEx(root, p, 0, syscall.KEY_READ, &key); err != nil {
		return 0, err
	}
	return key, nil
}

func regClose(key syscall.Handle) { syscall.RegCloseKey(key) }

func regReadStr(key syscall.Handle, name string) string {
	p, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return ""
	}
	var typ, size uint32
	syscall.RegQueryValueEx(key, p, nil, &typ, nil, &size)
	if size == 0 {
		return ""
	}
	buf := make([]uint16, (size+1)/2+1)
	if err := syscall.RegQueryValueEx(key, p, nil, &typ, (*byte)(unsafe.Pointer(&buf[0])), &size); err != nil {
		return ""
	}
	return syscall.UTF16ToString(buf)
}

func regReadDWORD(key syscall.Handle, name string) uint32 {
	p, err := syscall.UTF16PtrFromString(name)
	if err != nil {
		return 0
	}
	var typ, val, size uint32
	size = 4
	syscall.RegQueryValueEx(key, p, nil, &typ, (*byte)(unsafe.Pointer(&val)), &size)
	return val
}

func regEnumValues(key syscall.Handle) map[string]string {
	result := make(map[string]string)
	for i := uint32(0); ; i++ {
		var nameLen uint32 = 512
		nameBuf := make([]uint16, nameLen)
		var dataLen uint32 = 8192
		dataBuf := make([]byte, dataLen)
		var typ uint32
		r, _, _ := procRegEnumValue.Call(
			uintptr(key), uintptr(i),
			uintptr(unsafe.Pointer(&nameBuf[0])), uintptr(unsafe.Pointer(&nameLen)),
			0, uintptr(unsafe.Pointer(&typ)),
			uintptr(unsafe.Pointer(&dataBuf[0])), uintptr(unsafe.Pointer(&dataLen)),
		)
		if r != 0 {
			break
		}
		name := syscall.UTF16ToString(nameBuf[:nameLen])
		var val string
		if (typ == syscall.REG_SZ || typ == syscall.REG_EXPAND_SZ) && dataLen >= 2 {
			u16 := (*[1 << 28]uint16)(unsafe.Pointer(&dataBuf[0]))[:dataLen/2]
			val = syscall.UTF16ToString(u16)
		} else if typ == syscall.REG_MULTI_SZ && dataLen >= 2 {
			u16 := (*[1 << 28]uint16)(unsafe.Pointer(&dataBuf[0]))[:dataLen/2]
			val = strings.Join(strings.Split(syscall.UTF16ToString(u16), "\x00"), " ")
		}
		result[name] = val
	}
	return result
}

func regEnumSubkeys(key syscall.Handle) []string {
	var names []string
	for i := uint32(0); ; i++ {
		var nameLen uint32 = 512
		nameBuf := make([]uint16, nameLen)
		if err := syscall.RegEnumKeyEx(key, i, &nameBuf[0], &nameLen, nil, nil, nil, nil); err != nil {
			break
		}
		names = append(names, syscall.UTF16ToString(nameBuf[:nameLen]))
	}
	return names
}

// ── Utility ───────────────────────────────────────────────────────────────────

func entryID(typ, location, name string) string {
	h := fnv.New32a()
	h.Write([]byte(typ + "|" + location + "|" + name))
	return fmt.Sprintf("%08x", h.Sum32())
}

func containsAny(s string, subs ...string) bool {
	s = strings.ToLower(s)
	for _, sub := range subs {
		if strings.Contains(s, strings.ToLower(sub)) {
			return true
		}
	}
	return false
}

func nameEntropy(s string) float64 {
	if len(s) == 0 {
		return 0
	}
	freq := make(map[rune]float64)
	for _, c := range s {
		freq[c]++
	}
	n := float64(len(s))
	var e float64
	for _, count := range freq {
		p := count / n
		e -= p * math.Log2(p)
	}
	return e
}

// extractBinPath strips args and env vars to get just the executable path.
func extractBinPath(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" || cmd == "N/A" || cmd == "COM handler" {
		return ""
	}
	// Expand common env vars
	cmd = os.ExpandEnv(cmd)
	sysroot := os.Getenv("SystemRoot")
	cmd = strings.ReplaceAll(cmd, `\SystemRoot\`, sysroot+`\`)
	cmd = strings.ReplaceAll(cmd, `%SystemRoot%`, sysroot)

	if strings.HasPrefix(cmd, `"`) {
		end := strings.Index(cmd[1:], `"`)
		if end >= 0 {
			return cmd[1 : end+1]
		}
	}
	return strings.Fields(cmd)[0]
}

// isSystemPath returns true for known-good Windows binary locations.
func isSystemPath(p string) bool {
	p = strings.ToLower(p)
	return containsAny(p, `\windows\`, `\program files\`, `\program files (x86)\`)
}

// knownSystemProcs is a set of process names that malware often impersonates.
var knownSystemProcs = []string{
	"svchost.exe", "csrss.exe", "lsass.exe", "winlogon.exe",
	"services.exe", "explorer.exe", "taskhost.exe", "dllhost.exe",
	"rundll32.exe", "regsvr32.exe",
}

func scoreEntry(name, command, binPath string) (string, []string) {
	var reasons []string
	score := 0
	cmd := strings.ToLower(command)
	bin := strings.ToLower(binPath)

	if containsAny(cmd, "-enc ", "-encodedcommand", "frombase64string") {
		reasons = append(reasons, "base64 encoded command")
		score += 40
	}
	if containsAny(cmd, "-windowstyle hidden", "-w hidden", "-win hidden", "-nop ", "-noprofile") {
		reasons = append(reasons, "hidden/silent PowerShell flags")
		score += 25
	}
	if containsAny(cmd, "http://", "https://", "ftp://") {
		reasons = append(reasons, "network download in command")
		score += 35
	}
	if containsAny(cmd, "iex ", "invoke-expression", "invoke-webrequest", "downloadstring", "downloadfile") {
		reasons = append(reasons, "PowerShell download/exec pattern")
		score += 35
	}
	if containsAny(cmd, "^", "` ", "chr(", "char(") {
		reasons = append(reasons, "obfuscated command characters")
		score += 20
	}
	if containsAny(bin, os.TempDir(), `\temp\`, `\tmp\`) {
		reasons = append(reasons, "runs from temp folder")
		score += 40
	}
	if containsAny(bin, `\appdata\roaming\`, `\appdata\local\temp\`) {
		reasons = append(reasons, "runs from AppData")
		score += 20
	}
	if binPath != "" && binPath != "N/A" && !strings.HasPrefix(binPath, `\\`) {
		if _, err := os.Stat(binPath); os.IsNotExist(err) {
			reasons = append(reasons, "binary does not exist on disk")
			score += 25
		}
	}
	// Process name impersonation
	nm := strings.ToLower(filepath.Base(name))
	for _, sp := range knownSystemProcs {
		if nm == sp && !isSystemPath(bin) {
			reasons = append(reasons, "impersonates system process name")
			score += 50
			break
		}
	}
	// High-entropy random name
	if len(name) >= 8 && nameEntropy(name) > 3.8 {
		reasons = append(reasons, "high-entropy random-looking name")
		score += 15
	}
	// Script-based persistence
	if containsAny(bin, ".vbs", ".ps1", ".bat", ".cmd", ".js") {
		reasons = append(reasons, "script-based persistence")
		score += 15
	}

	switch {
	case score >= 40:
		return "high", reasons
	case score >= 15:
		return "medium", reasons
	default:
		if len(reasons) == 0 {
			reasons = append(reasons, "auto-start entry")
		}
		return "low", reasons
	}
}

// ── Run Keys ─────────────────────────────────────────────────────────────────

type regRunKey struct {
	root    syscall.Handle
	rootStr string
	path    string
}

var runKeys = []regRunKey{
	{hkcu, "hkcu", `Software\Microsoft\Windows\CurrentVersion\Run`},
	{hkcu, "hkcu", `Software\Microsoft\Windows\CurrentVersion\RunOnce`},
	{hklm, "hklm", `Software\Microsoft\Windows\CurrentVersion\Run`},
	{hklm, "hklm", `Software\Microsoft\Windows\CurrentVersion\RunOnce`},
	{hklm, "hklm", `Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`},
	{hkcu, "hkcu", `Software\WOW6432Node\Microsoft\Windows\CurrentVersion\Run`},
}

func scanRunKeys() ([]PersistenceEntry, []string) {
	var entries []PersistenceEntry
	for _, rk := range runKeys {
		key, err := regOpen(rk.root, rk.path)
		if err != nil {
			continue
		}
		vals := regEnumValues(key)
		regClose(key)
		for name, cmd := range vals {
			bin := extractBinPath(cmd)
			risk, reasons := scoreEntry(name, cmd, bin)
			entries = append(entries, PersistenceEntry{
				EntryView: EntryView{
					ID:       entryID("run_key", rk.rootStr+`\`+rk.path, name),
					Type:     "run_key",
					Name:     name,
					Command:  cmd,
					BinPath:  bin,
					Location: rk.rootStr + `\` + rk.path,
					Risk:     risk,
					Reasons:  reasons,
				},
				KillRegRoot:  rk.rootStr,
				KillRegPath:  rk.path,
				KillRegValue: name,
			})
		}
	}
	return entries, nil
}

// ── Winlogon ─────────────────────────────────────────────────────────────────

func scanWinlogon() ([]PersistenceEntry, []string) {
	var entries []PersistenceEntry
	path := `Software\Microsoft\Windows NT\CurrentVersion\Winlogon`
	key, err := regOpen(hklm, path)
	if err != nil {
		return nil, nil
	}
	defer regClose(key)

	checkVal := func(valName, expected string) {
		val := regReadStr(key, valName)
		if val == "" {
			return
		}
		if strings.EqualFold(strings.TrimSpace(val), expected) {
			return // normal
		}
		bin := extractBinPath(val)
		entries = append(entries, PersistenceEntry{
			EntryView: EntryView{
				ID:       entryID("winlogon", path, valName),
				Type:     "winlogon",
				Name:     valName,
				Command:  val,
				BinPath:  bin,
				Location: `hklm\` + path,
				Risk:     "high",
				Reasons:  []string{fmt.Sprintf("Winlogon %s hijacked (expected: %s)", valName, expected)},
			},
			KillRegRoot:  "hklm",
			KillRegPath:  path,
			KillRegValue: valName,
		})
	}

	sysroot := os.Getenv("SystemRoot")
	checkVal("Userinit", sysroot+`\system32\userinit.exe,`)
	checkVal("Shell", "explorer.exe")
	return entries, nil
}

// ── IFEO Debugger ─────────────────────────────────────────────────────────────

func scanIFEO() ([]PersistenceEntry, []string) {
	var entries []PersistenceEntry
	basePath := `Software\Microsoft\Windows NT\CurrentVersion\Image File Execution Options`
	baseKey, err := regOpen(hklm, basePath)
	if err != nil {
		return nil, nil
	}
	defer regClose(baseKey)

	subkeys := regEnumSubkeys(baseKey)
	for _, sub := range subkeys {
		subPath := basePath + `\` + sub
		subKey, err := regOpen(hklm, subPath)
		if err != nil {
			continue
		}
		debugger := regReadStr(subKey, "Debugger")
		regClose(subKey)
		if debugger == "" {
			continue
		}
		bin := extractBinPath(debugger)
		risk, reasons := scoreEntry(sub, debugger, bin)
		if risk == "low" {
			risk = "high" // any IFEO debugger is suspicious
		}
		reasons = append([]string{"IFEO debugger hijack on: " + sub}, reasons...)
		entries = append(entries, PersistenceEntry{
			EntryView: EntryView{
				ID:       entryID("ifeo", subPath, "Debugger"),
				Type:     "ifeo",
				Name:     sub,
				Command:  debugger,
				BinPath:  bin,
				Location: `hklm\` + subPath,
				Risk:     risk,
				Reasons:  reasons,
			},
			KillRegRoot:  "hklm",
			KillRegPath:  subPath,
			KillRegValue: "Debugger",
		})
	}
	return entries, nil
}

// ── AppInit_DLLs ──────────────────────────────────────────────────────────────

func scanAppInit() ([]PersistenceEntry, []string) {
	path := `Software\Microsoft\Windows NT\CurrentVersion\Windows`
	key, err := regOpen(hklm, path)
	if err != nil {
		return nil, nil
	}
	defer regClose(key)

	val := regReadStr(key, "AppInit_DLLs")
	if val == "" {
		return nil, nil
	}
	return []PersistenceEntry{{
		EntryView: EntryView{
			ID:       entryID("appinit", path, "AppInit_DLLs"),
			Type:     "appinit",
			Name:     "AppInit_DLLs",
			Command:  val,
			BinPath:  val,
			Location: `hklm\` + path,
			Risk:     "high",
			Reasons:  []string{"DLL injected into every GUI process"},
		},
		KillRegRoot:  "hklm",
		KillRegPath:  path,
		KillRegValue: "AppInit_DLLs",
	}}, nil
}

// ── LSA Providers ─────────────────────────────────────────────────────────────

var legitimateLSA = map[string]bool{
	"msv1_0": true, "wdigest": true, "tspkg": true, "pku2u": true,
	"kerberos": true, "schannel": true, "livessp": true, "cloudap": true,
	"negoexts": true, "credssp": true, "ntlm": true, "negotiate": true,
}

func scanLSA() ([]PersistenceEntry, []string) {
	var entries []PersistenceEntry
	path := `SYSTEM\CurrentControlSet\Control\Lsa`
	key, err := regOpen(hklm, path)
	if err != nil {
		return nil, nil
	}
	defer regClose(key)

	for _, valName := range []string{"Authentication Packages", "Security Packages", "Notification Packages"} {
		val := regReadStr(key, valName)
		for _, pkg := range strings.Fields(val) {
			pkg = strings.ToLower(strings.TrimSpace(pkg))
			if pkg == "" || legitimateLSA[pkg] {
				continue
			}
			entries = append(entries, PersistenceEntry{
				EntryView: EntryView{
					ID:       entryID("lsa", path, valName+"|"+pkg),
					Type:     "lsa",
					Name:     pkg,
					Command:  pkg,
					BinPath:  pkg,
					Location: `hklm\` + path + ` → ` + valName,
					Risk:     "high",
					Reasons:  []string{"Unknown LSA security package: " + valName},
				},
				KillRegRoot:  "hklm",
				KillRegPath:  path,
				KillRegValue: valName,
			})
		}
	}
	return entries, nil
}

// ── Boot Execute ──────────────────────────────────────────────────────────────

func scanBootExecute() ([]PersistenceEntry, []string) {
	path := `SYSTEM\CurrentControlSet\Control\Session Manager`
	key, err := regOpen(hklm, path)
	if err != nil {
		return nil, nil
	}
	defer regClose(key)

	val := strings.ToLower(strings.TrimSpace(regReadStr(key, "BootExecute")))
	if val == "" || val == "autocheck autochk *" || val == "autocheck autochk *\x00" {
		return nil, nil
	}
	return []PersistenceEntry{{
		EntryView: EntryView{
			ID:       entryID("boot_execute", path, "BootExecute"),
			Type:     "boot_execute",
			Name:     "BootExecute",
			Command:  val,
			BinPath:  val,
			Location: `hklm\` + path,
			Risk:     "high",
			Reasons:  []string{"Non-standard boot execute entry (runs before Windows loads)"},
		},
		KillRegRoot:  "hklm",
		KillRegPath:  path,
		KillRegValue: "BootExecute",
	}}, nil
}

// ── Startup Folders ───────────────────────────────────────────────────────────

func scanStartupFolders() ([]PersistenceEntry, []string) {
	var entries []PersistenceEntry
	dirs := []string{
		filepath.Join(os.Getenv("APPDATA"), `Microsoft\Windows\Start Menu\Programs\Startup`),
		`C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp`,
	}
	for _, dir := range dirs {
		files, err := os.ReadDir(dir)
		if err != nil {
			continue
		}
		for _, f := range files {
			if f.IsDir() || strings.ToLower(f.Name()) == "desktop.ini" {
				continue
			}
			fullPath := filepath.Join(dir, f.Name())
			risk, reasons := scoreEntry(f.Name(), fullPath, fullPath)
			entries = append(entries, PersistenceEntry{
				EntryView: EntryView{
					ID:       entryID("startup_file", dir, f.Name()),
					Type:     "startup_file",
					Name:     f.Name(),
					Command:  fullPath,
					BinPath:  fullPath,
					Location: dir,
					Risk:     risk,
					Reasons:  reasons,
				},
				KillFilePath: fullPath,
			})
		}
	}
	return entries, nil
}

// ── Scheduled Tasks ───────────────────────────────────────────────────────────

func scanScheduledTasks() ([]PersistenceEntry, []string) {
	out, err := exec.Command("schtasks", "/query", "/fo", "CSV", "/v", "/nh").Output()
	if err != nil {
		return nil, []string{"schtasks query failed: " + err.Error()}
	}

	r := csv.NewReader(strings.NewReader(string(out)))
	r.LazyQuotes = true
	r.FieldsPerRecord = -1
	records, err := r.ReadAll()
	if err != nil {
		return nil, []string{"schtasks CSV parse failed: " + err.Error()}
	}

	seen := make(map[string]bool)
	var entries []PersistenceEntry

	for _, rec := range records {
		// CSV columns: HostName[0] TaskName[1] ... Task To Run[8] ... Run As User[14]
		if len(rec) < 9 {
			continue
		}
		taskName := strings.TrimSpace(rec[1])
		taskCmd := strings.TrimSpace(rec[8])

		if taskName == "" || taskCmd == "" || taskCmd == "N/A" {
			continue
		}
		// Skip duplicate schedules for same task
		if seen[taskName] {
			continue
		}
		seen[taskName] = true

		// Skip Microsoft system tasks
		if strings.Contains(strings.ToLower(taskName), `\microsoft\`) {
			continue
		}

		bin := extractBinPath(taskCmd)
		risk, reasons := scoreEntry(filepath.Base(taskName), taskCmd, bin)
		entries = append(entries, PersistenceEntry{
			EntryView: EntryView{
				ID:       entryID("scheduled_task", "tasks", taskName),
				Type:     "scheduled_task",
				Name:     taskName,
				Command:  taskCmd,
				BinPath:  bin,
				Location: "Task Scheduler",
				Risk:     risk,
				Reasons:  reasons,
			},
			KillTaskName: taskName,
		})
	}
	return entries, nil
}

// ── Services ──────────────────────────────────────────────────────────────────

func scanServices() ([]PersistenceEntry, []string) {
	basePath := `SYSTEM\CurrentControlSet\Services`
	baseKey, err := regOpen(hklm, basePath)
	if err != nil {
		return nil, []string{"cannot open Services key: " + err.Error()}
	}
	defer regClose(baseKey)

	subkeys := regEnumSubkeys(baseKey)
	var entries []PersistenceEntry

	for _, svc := range subkeys {
		svcPath := basePath + `\` + svc
		svcKey, err := regOpen(hklm, svcPath)
		if err != nil {
			continue
		}
		start := regReadDWORD(svcKey, "Start")
		typ := regReadDWORD(svcKey, "Type")
		imagePath := regReadStr(svcKey, "ImagePath")
		regClose(svcKey)

		// Only auto-start (2) user-mode services (16=own, 32=shared)
		if start != 2 || (typ != 16 && typ != 32) {
			continue
		}
		if imagePath == "" {
			continue
		}
		// Skip obvious system services
		bin := extractBinPath(imagePath)
		if isSystemPath(bin) {
			continue
		}

		risk, reasons := scoreEntry(svc, imagePath, bin)
		entries = append(entries, PersistenceEntry{
			EntryView: EntryView{
				ID:       entryID("service", "services", svc),
				Type:     "service",
				Name:     svc,
				Command:  imagePath,
				BinPath:  bin,
				Location: "Windows Services (auto-start)",
				Risk:     risk,
				Reasons:  reasons,
			},
			KillSvcName: svc,
		})
	}
	return entries, nil
}

// ── WMI Subscriptions ────────────────────────────────────────────────────────

func scanWMI() ([]PersistenceEntry, []string) {
	script := `$ErrorActionPreference='SilentlyContinue'
$filters=Get-WMIObject -Namespace root\subscription -Class __EventFilter
foreach($f in $filters){if($f.Name){Write-Output("FILTER|"+$f.Name+"|"+$f.Query)}}
$consumers=Get-WMIObject -Namespace root\subscription -Class CommandLineEventConsumer
foreach($c in $consumers){if($c.Name){Write-Output("CONSUMER|"+$c.Name+"|"+$c.CommandLineTemplate)}}`

	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script).Output()
	if err != nil {
		return nil, nil // WMI query failure is non-fatal
	}

	var entries []PersistenceEntry
	seen := make(map[string]bool)

	for _, line := range strings.Split(string(out), "\n") {
		line = strings.TrimRight(line, "\r")
		parts := strings.SplitN(line, "|", 3)
		if len(parts) < 3 {
			continue
		}
		kind, name, cmd := parts[0], parts[1], parts[2]
		if seen[name] {
			continue
		}
		seen[name] = true

		bin := extractBinPath(cmd)
		risk, reasons := scoreEntry(name, cmd, bin)
		if risk == "low" {
			risk = "high" // any WMI subscription is suspicious
		}
		reasons = append([]string{"WMI " + kind + " subscription"}, reasons...)

		entries = append(entries, PersistenceEntry{
			EntryView: EntryView{
				ID:       entryID("wmi", "wmi", name),
				Type:     "wmi",
				Name:     name,
				Command:  cmd,
				BinPath:  bin,
				Location: "root\\subscription",
				Risk:     risk,
				Reasons:  reasons,
			},
			KillWMIName: name,
		})
	}
	return entries, nil
}

// ── scanAll ───────────────────────────────────────────────────────────────────

func scanAll() ([]PersistenceEntry, []string) {
	var all []PersistenceEntry
	var errs []string

	type scanFn func() ([]PersistenceEntry, []string)
	scanners := []scanFn{
		scanRunKeys,
		scanWinlogon,
		scanIFEO,
		scanAppInit,
		scanLSA,
		scanBootExecute,
		scanStartupFolders,
		scanScheduledTasks,
		scanServices,
		scanWMI,
	}

	for _, fn := range scanners {
		entries, e := fn()
		all = append(all, entries...)
		errs = append(errs, e...)
	}
	return all, errs
}
