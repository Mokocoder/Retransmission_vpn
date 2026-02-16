//go:build windows

package netutil

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
	"syscall"
)

// GetOriginalGateway discovers the default gateway by inspecting active
// network interfaces and inferring the gateway from the local IP address.
func GetOriginalGateway() (string, error) {
	cmd := exec.Command("route", "print", "0.0.0.0")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	if out, err := cmd.Output(); err == nil {
		lines := strings.Split(string(out), "\n")
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) >= 3 && fields[0] == "0.0.0.0" && fields[1] == "0.0.0.0" {
				if gw := net.ParseIP(fields[2]); gw != nil {
					return gw.String(), nil
				}
			}
		}
	}

	interfaces, err := net.Interfaces()
	if err != nil {
		return "", fmt.Errorf("list interfaces: %w", err)
	}

	for _, ifi := range interfaces {
		if ifi.Flags&net.FlagUp == 0 || ifi.Flags&net.FlagLoopback != 0 {
			continue
		}
		addrs, err := ifi.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			if ipnet, ok := addr.(*net.IPNet); ok && ipnet.IP.To4() != nil {
				ip := ipnet.IP.To4()
				if ip[0] == 10 || (ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) || (ip[0] == 192 && ip[1] == 168) {
					return fmt.Sprintf("%d.%d.%d.1", ip[0], ip[1], ip[2]), nil
				}
			}
		}
	}
	return "", nil
}
