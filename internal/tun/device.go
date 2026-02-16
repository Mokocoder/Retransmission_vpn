package tun

import (
	"io"

	"retransmission-vpn/internal/config"
)

type Device interface {
	io.ReadWriteCloser
	Name() string
	MTU() int
}

type Config struct {
	Name            string
	Address         string
	Mask            string
	Gateway         string
	Address6        string
	Gateway6        string
	MTU             int
	ServerIP        string
	OriginalGateway string
}

func DefaultConfig() Config {
	return Config{
		Name:     config.TunNameWindows,
		Address:  config.VirtualClientIP,
		Mask:     config.VirtualMask,
		Gateway:  config.VirtualGatewayIP,
		Address6: config.VirtualClient6,
		Gateway6: config.VirtualGateway6,
		MTU:      config.DefaultMTU,
	}
}
