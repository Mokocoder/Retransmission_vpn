//go:build linux

package tun

import (
	"fmt"
	"os"
	"os/exec"
	"sync"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	tunDevice = "/dev/net/tun"
	ifnamsiz  = 16
	iffTun    = 0x0001
	iffNoPi   = 0x1000
)

type ifReq struct {
	name  [ifnamsiz]byte
	flags uint16
	_     [22]byte // padding
}

type LinuxTunDevice struct {
	fd     *os.File
	config Config

	closeOnce sync.Once
}

func New(cfg Config) (Device, error) {
	fd, err := os.OpenFile(tunDevice, os.O_RDWR, 0)
	if err != nil {
		return nil, fmt.Errorf("open %s: %w", tunDevice, err)
	}

	var req ifReq
	copy(req.name[:], cfg.Name)
	req.flags = iffTun | iffNoPi

	_, _, errno := unix.Syscall(unix.SYS_IOCTL, fd.Fd(), unix.TUNSETIFF, uintptr(unsafe.Pointer(&req)))
	if errno != 0 {
		fd.Close()
		return nil, fmt.Errorf("ioctl TUNSETIFF: %w", errno)
	}

	dev := &LinuxTunDevice{
		fd:     fd,
		config: cfg,
	}

	if err := dev.configure(); err != nil {
		fd.Close()
		return nil, err
	}

	return dev, nil
}

func (d *LinuxTunDevice) configure() error {
	commands := [][]string{
		{"ip", "addr", "add", fmt.Sprintf("%s/24", d.config.Address), "dev", d.config.Name},
		{"ip", "link", "set", d.config.Name, "up"},
		{"ip", "link", "set", d.config.Name, "mtu", fmt.Sprint(d.config.MTU)},
	}

	// IPv6 address configuration
	if d.config.Address6 != "" {
		commands = append(commands, []string{"ip", "-6", "addr", "add", fmt.Sprintf("%s/64", d.config.Address6), "dev", d.config.Name})
	}

	for _, args := range commands {
		if err := exec.Command(args[0], args[1:]...).Run(); err != nil {
			return fmt.Errorf("exec %v: %w", args, err)
		}
	}

	return nil
}

func (d *LinuxTunDevice) Read(buf []byte) (int, error) {
	return d.fd.Read(buf)
}

func (d *LinuxTunDevice) Write(buf []byte) (int, error) {
	return d.fd.Write(buf)
}

func (d *LinuxTunDevice) Close() error {
	var err error
	d.closeOnce.Do(func() {
		err = d.fd.Close()
	})
	return err
}

func (d *LinuxTunDevice) Name() string {
	return d.config.Name
}

func (d *LinuxTunDevice) MTU() int {
	return d.config.MTU
}

func (d *LinuxTunDevice) SetupNAT(network string) error {
	_ = exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING", "-s", network, "-j", "MASQUERADE").Run()
	_ = exec.Command("ip6tables", "-t", "nat", "-D", "POSTROUTING", "-s", "fd00::/64", "-j", "MASQUERADE").Run()

	commands := [][]string{
		// IPv4 forwarding and NAT
		{"sysctl", "-w", "net.ipv4.ip_forward=1"},
		{"iptables", "-t", "nat", "-A", "POSTROUTING", "-s", network, "-j", "MASQUERADE"},
		// IPv6 forwarding and NAT66
		{"sysctl", "-w", "net.ipv6.conf.all.forwarding=1"},
		{"ip6tables", "-t", "nat", "-A", "POSTROUTING", "-s", "fd00::/64", "-j", "MASQUERADE"},
	}

	for _, args := range commands {
		if err := exec.Command(args[0], args[1:]...).Run(); err != nil {
			// Ignore ip6tables failure (IPv6 unsupported environment)
			if args[0] == "ip6tables" {
				continue
			}
			return fmt.Errorf("exec %v: %w", args, err)
		}
	}
	return nil
}

func (d *LinuxTunDevice) BlockRST(port int) error {
	_ = exec.Command("iptables", "-D", "OUTPUT",
		"-p", "tcp", "--tcp-flags", "RST", "RST",
		"--sport", fmt.Sprint(port), "-j", "DROP").Run()

	return exec.Command("iptables", "-A", "OUTPUT",
		"-p", "tcp", "--tcp-flags", "RST", "RST",
		"--sport", fmt.Sprint(port), "-j", "DROP").Run()
}

func (d *LinuxTunDevice) Cleanup(port int, network string) {
	_ = exec.Command("iptables", "-t", "nat", "-D", "POSTROUTING", "-s", network, "-j", "MASQUERADE").Run()
	_ = exec.Command("iptables", "-D", "OUTPUT", "-p", "tcp", "--tcp-flags", "RST", "RST", "--sport", fmt.Sprint(port), "-j", "DROP").Run()
	_ = exec.Command("ip6tables", "-t", "nat", "-D", "POSTROUTING", "-s", "fd00::/64", "-j", "MASQUERADE").Run()
}

var _ Device = (*LinuxTunDevice)(nil)
