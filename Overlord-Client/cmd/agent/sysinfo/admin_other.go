//go:build !windows

package sysinfo

import "os"

// root == admin
func IsAdmin() bool {
	return os.Getuid() == 0
}

func Elevation() string {
	if os.Getuid() == 0 {
		return "admin"
	}
	return ""
}
