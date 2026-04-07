//go:build windows

package sysinfo

import "golang.org/x/sys/windows"

// check current process token to see if we're admin asf
func IsAdmin() bool {
	token := windows.GetCurrentProcessToken()
	return token.IsElevated()
}
