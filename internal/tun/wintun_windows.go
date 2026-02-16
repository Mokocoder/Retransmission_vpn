//go:build windows

package tun

import (
	"errors"
	"fmt"
	"os/exec"
	"strings"
	"sync"
	"syscall"

	"golang.org/x/sys/windows"
	"golang.zx2c4.com/wintun"
)

// runHidden executes a command with hidden console window.
func runHidden(name string, args ...string) *exec.Cmd {
	cmd := exec.Command(name, args...)
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	return cmd
}

const (
	ringCapacity  = 0x400000 // 4MB ring buffer
	maxPacketSize = 0xFFFF
)

type WinTunDevice struct {
	adapter  *wintun.Adapter
	session  wintun.Session
	config   Config
	readWait windows.Handle

	ipv6Disabled bool

	closeOnce sync.Once
	closed    chan struct{}
}

func New(cfg Config) (Device, error) {
	adapter, err := wintun.CreateAdapter(cfg.Name, "WireGuard", nil)
	if err != nil {
		return nil, fmt.Errorf("create adapter: %w", err)
	}

	session, err := adapter.StartSession(ringCapacity)
	if err != nil {
		adapter.Close()
		return nil, fmt.Errorf("start session: %w", err)
	}

	dev := &WinTunDevice{
		adapter:  adapter,
		session:  session,
		config:   cfg,
		readWait: session.ReadWaitEvent(),
		closed:   make(chan struct{}),
	}

	if err := dev.configure(); err != nil {
		dev.Close()
		return nil, fmt.Errorf("configure interface: %w", err)
	}

	return dev, nil
}

func (d *WinTunDevice) configure() error {
	// IPv4 configuration
	cmd := runHidden("netsh", "interface", "ip", "set", "address",
		d.config.Name, "static", d.config.Address, d.config.Mask, d.config.Gateway)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("netsh failed: %s: %w", out, err)
	}

	runHidden("netsh", "interface", "ipv4", "set", "subinterface",
		d.config.Name, fmt.Sprintf("mtu=%d", d.config.MTU), "store=active").Run()

	return nil
}

func (d *WinTunDevice) Read(buf []byte) (int, error) {
	for {
		select {
		case <-d.closed:
			return 0, errors.New("device closed")
		default:
		}

		packet, err := d.session.ReceivePacket()
		if err != nil {
			if err == windows.ERROR_NO_MORE_ITEMS {
				windows.WaitForSingleObject(d.readWait, windows.INFINITE)
				continue
			}
			return 0, fmt.Errorf("receive packet: %w", err)
		}

		n := copy(buf, packet)
		d.session.ReleaseReceivePacket(packet)
		return n, nil
	}
}

func (d *WinTunDevice) Write(buf []byte) (int, error) {
	select {
	case <-d.closed:
		return 0, errors.New("device closed")
	default:
	}

	packet, err := d.session.AllocateSendPacket(len(buf))
	if err != nil {
		return 0, fmt.Errorf("allocate send packet: %w", err)
	}

	copy(packet, buf)
	d.session.SendPacket(packet)
	return len(buf), nil
}

func (d *WinTunDevice) Close() error {
	d.closeOnce.Do(func() {
		close(d.closed)
		d.session.End()
		d.adapter.Close()
	})
	return nil
}

func (d *WinTunDevice) Name() string {
	return d.config.Name
}

func (d *WinTunDevice) MTU() int {
	return d.config.MTU
}

func (d *WinTunDevice) LUID() uint64 {
	return d.adapter.LUID()
}

func init() {
	// Load WinTun DLL from current directory
	windows.SetDllDirectory(".")
}

func (d *WinTunDevice) SetRoutes() error {
	if d.config.ServerIP != "" && d.config.OriginalGateway != "" {
		_ = runHidden("route", "delete", d.config.ServerIP, "mask", "255.255.255.255",
			d.config.OriginalGateway).Run()

		out, err := runHidden("route", "add", d.config.ServerIP, "mask", "255.255.255.255",
			d.config.OriginalGateway, "metric", "1").CombinedOutput()
		if err != nil && !isRouteExistsError(out) {
			return fmt.Errorf("add server route: %s: %w", strings.TrimSpace(string(out)), err)
		}
	}

	// IPv4 routes (interface-bound, auto-cleanup)
	routes4 := []string{"0.0.0.0/1", "128.0.0.0/1"}
	for _, r := range routes4 {
		out, err := runHidden("netsh", "interface", "ipv4", "add", "route",
			r, d.config.Name, d.config.Gateway, "metric=5", "store=active").CombinedOutput()
		if err != nil && !isRouteExistsError(out) {
			return fmt.Errorf("add IPv4 route %s: %s: %w", r, strings.TrimSpace(string(out)), err)
		}
	}

	// Blackhole IPv6 via loopback to prevent leaks.
	// The VPN only tunnels IPv4; without this, IPv6 traffic bypasses the tunnel.
	d.blockIPv6()

	return nil
}

func isRouteExistsError(out []byte) bool {
	msg := strings.ToLower(string(out))
	return strings.Contains(msg, "already exists") ||
		strings.Contains(msg, "object already exists") ||
		strings.Contains(msg, "이미") ||
		strings.Contains(msg, "존재")
}

func (d *WinTunDevice) ClearRoutes() {
	if d.config.ServerIP != "" && d.config.OriginalGateway != "" {
		runHidden("route", "delete", d.config.ServerIP, "mask", "255.255.255.255",
			d.config.OriginalGateway).Run()
	}
	d.unblockIPv6()
}

// blockIPv6 adds blackhole routes for all IPv6 traffic via the loopback
// interface (index 1), so IPv6 packets are dropped instead of leaking.
func (d *WinTunDevice) blockIPv6() {
	for _, r := range []string{"::/1", "8000::/1"} {
		runHidden("netsh", "interface", "ipv6", "add", "route",
			r, "interface=1", "store=active").Run()
	}
	d.ipv6Disabled = true
}

func (d *WinTunDevice) unblockIPv6() {
	if !d.ipv6Disabled {
		return
	}
	for _, r := range []string{"::/1", "8000::/1"} {
		runHidden("netsh", "interface", "ipv6", "delete", "route",
			r, "interface=1", "store=active").Run()
	}
	d.ipv6Disabled = false
}

var _ Device = (*WinTunDevice)(nil)
