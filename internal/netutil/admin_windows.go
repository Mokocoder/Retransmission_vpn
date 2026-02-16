//go:build windows

package netutil

import "os"

// IsAdmin checks whether the current process has administrator privileges
// by attempting to open a raw disk handle.
func IsAdmin() bool {
	f, err := os.Open("\\\\.\\PHYSICALDRIVE0")
	if err != nil {
		return false
	}
	f.Close()
	return true
}
