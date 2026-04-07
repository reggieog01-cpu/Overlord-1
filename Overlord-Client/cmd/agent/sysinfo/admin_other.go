//go:build !windows

package sysinfo

import "os"

// root == admin
func IsAdmin() bool {
	return os.Getuid() == 0
}
