//go:build windows

package main

import (
	"fmt"
	"os"
	"os/exec"
	"syscall"
	"unsafe"
)

var (
	advapi32kill         = syscall.NewLazyDLL("advapi32.dll")
	procRegDeleteValue   = advapi32kill.NewProc("RegDeleteValueW")
	procRegOpenKeyExWKill = advapi32kill.NewProc("RegOpenKeyExW")
)

func regOpenWrite(root syscall.Handle, path string) (syscall.Handle, error) {
	p, err := syscall.UTF16PtrFromString(path)
	if err != nil {
		return 0, err
	}
	var key syscall.Handle
	r, _, err := procRegOpenKeyExWKill.Call(
		uintptr(root), uintptr(unsafe.Pointer(p)),
		0, uintptr(syscall.KEY_WRITE),
		uintptr(unsafe.Pointer(&key)),
	)
	if r != 0 {
		return 0, fmt.Errorf("RegOpenKeyEx: %w", err)
	}
	return key, nil
}

func killRegValue(rootStr, keyPath, valueName string) error {
	root := hklm
	if rootStr == "hkcu" {
		root = hkcu
	}
	key, err := regOpenWrite(root, keyPath)
	if err != nil {
		return fmt.Errorf("open key: %w", err)
	}
	defer regClose(key)
	p, err := syscall.UTF16PtrFromString(valueName)
	if err != nil {
		return err
	}
	r, _, err := procRegDeleteValue.Call(uintptr(key), uintptr(unsafe.Pointer(p)))
	if r != 0 {
		return fmt.Errorf("RegDeleteValue: %w", err)
	}
	return nil
}

func killTask(taskName string) error {
	out, err := exec.Command("schtasks", "/delete", "/tn", taskName, "/f").CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, out)
	}
	return nil
}

func killService(svcName string) error {
	exec.Command("sc", "stop", svcName).Run() // best-effort stop
	out, err := exec.Command("sc", "delete", svcName).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, out)
	}
	return nil
}

func killFile(path string) error {
	return os.Remove(path)
}

func killWMI(name string) error {
	script := fmt.Sprintf(`$ErrorActionPreference='SilentlyContinue'
$n='%s'
Get-WMIObject -Namespace root\subscription -Class __FilterToConsumerBinding | Where-Object {$_.Filter -like "*$n*"} | ForEach-Object {$_.Delete()}
Get-WMIObject -Namespace root\subscription -Class __EventFilter -Filter "Name='$n'" | ForEach-Object {$_.Delete()}
Get-WMIObject -Namespace root\subscription -Class CommandLineEventConsumer -Filter "Name='$n'" | ForEach-Object {$_.Delete()}`, name)
	out, err := exec.Command("powershell", "-NoProfile", "-NonInteractive", "-Command", script).CombinedOutput()
	if err != nil {
		return fmt.Errorf("%w: %s", err, out)
	}
	return nil
}


func killEntries(ids []string) KillResult {
	mu.Lock()
	scan := lastScan
	mu.Unlock()

	var result KillResult

	for _, id := range ids {
		entry, ok := scan[id]
		if !ok {
			result.Failed = append(result.Failed, KillFail{ID: id, Name: "?", Error: "entry not found in last scan"})
			continue
		}
		if entry.Killed {
			result.Killed = append(result.Killed, id) // already done
			continue
		}

		var killErr error
		switch entry.Type {
		case "run_key", "winlogon", "ifeo", "appinit", "lsa", "boot_execute":
			killErr = killRegValue(entry.KillRegRoot, entry.KillRegPath, entry.KillRegValue)
		case "startup_file":
			killErr = killFile(entry.KillFilePath)
		case "scheduled_task":
			killErr = killTask(entry.KillTaskName)
		case "service":
			killErr = killService(entry.KillSvcName)
		case "wmi":
			killErr = killWMI(entry.KillWMIName)
		default:
			killErr = fmt.Errorf("unknown entry type: %s", entry.Type)
		}

		if killErr != nil {
			result.Failed = append(result.Failed, KillFail{ID: id, Name: entry.Name, Error: killErr.Error()})
			continue
		}

		// Mark as killed in lastScan
		mu.Lock()
		e := lastScan[id]
		e.Killed = true
		lastScan[id] = e
		mu.Unlock()

		result.Killed = append(result.Killed, id)
	}

	return result
}
