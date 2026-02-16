//go:build windows

package client

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"

	"retransmission-vpn/internal/config"
	"retransmission-vpn/internal/netutil"
	"retransmission-vpn/internal/packet"
	"retransmission-vpn/internal/transport"
	"retransmission-vpn/internal/tun"
)

// StatusCallback is invoked when the client's connection status changes.
type StatusCallback func(status string)

// Option configures a VPNClient.
type Option func(*VPNClient)

// WithStatusCallback sets a callback for status change notifications.
func WithStatusCallback(cb StatusCallback) Option {
	return func(c *VPNClient) {
		c.onStatus = cb
	}
}

// VPNClient manages a VPN tunnel connection to a remote server.
type VPNClient struct {
	serverIP   net.IP
	serverPort uint16
	psk        []byte

	tunDev *tun.WinTunDevice
	conn   *transport.TCPConn

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup

	onStatus StatusCallback
}

// New creates a VPNClient with the given server address, port, and PSK.
func New(serverIP net.IP, serverPort uint16, psk []byte, opts ...Option) *VPNClient {
	c := &VPNClient{
		serverIP:   serverIP,
		serverPort: serverPort,
		psk:        psk,
		onStatus:   func(string) {},
	}
	for _, opt := range opts {
		opt(c)
	}
	return c
}

func (c *VPNClient) status(msg string) {
	c.onStatus(msg)
}

// Start establishes the VPN connection, sets up the TUN device, and begins
// forwarding traffic in background goroutines.
func (c *VPNClient) Start() error {
	c.ctx, c.cancel = context.WithCancel(context.Background())

	c.status("Connecting...")
	if err := c.connect(); err != nil {
		return fmt.Errorf("connect: %w", err)
	}

	c.status("Setting up TUN...")
	if err := c.setupTun(); err != nil {
		c.conn.Close()
		return fmt.Errorf("tun: %w", err)
	}

	c.wg.Add(2)
	go c.tunToServer()
	go c.serverToTun()

	c.status("Connected")
	return nil
}

// Stop gracefully shuts down the VPN connection and waits for goroutines.
func (c *VPNClient) Stop() {
	if c.cancel != nil {
		c.cancel()
	}
	if c.conn != nil {
		c.conn.Close()
	}
	if c.tunDev != nil {
		c.tunDev.ClearRoutes()
		c.tunDev.Close()
	}
	c.wg.Wait()
}

// Wait blocks until the context is cancelled (e.g. by Stop or signal).
func (c *VPNClient) Wait() {
	<-c.ctx.Done()
}

func (c *VPNClient) connect() error {
	var err error
	c.conn, err = transport.NewTCPConn(c.serverIP, c.serverPort, c.psk)
	if err != nil {
		return err
	}

	ctx, cancel := context.WithTimeout(c.ctx, config.ConnectTimeout)
	defer cancel()

	return c.conn.Connect(ctx)
}

func (c *VPNClient) setupTun() error {
	origGW, _ := netutil.GetOriginalGateway()

	cfg := tun.Config{
		Name:            config.TunNameWindows,
		Address:         config.VirtualClientIP,
		Mask:            config.VirtualMask,
		Gateway:         config.VirtualGatewayIP,
		Address6:        config.VirtualClient6,
		Gateway6:        config.VirtualGateway6,
		MTU:             config.DefaultMTU,
		ServerIP:        c.serverIP.String(),
		OriginalGateway: origGW,
	}

	dev, err := tun.New(cfg)
	if err != nil {
		return err
	}

	c.tunDev = dev.(*tun.WinTunDevice)

	log.Println("Setting up routes...")
	if err := c.tunDev.SetRoutes(); err != nil {
		c.tunDev.ClearRoutes()
		c.tunDev.Close()
		return fmt.Errorf("set routes: %w", err)
	}
	log.Println("Routes configured (IPv4: 0.0.0.0/1, 128.0.0.0/1 / IPv6: ::/1, 8000::/1)")

	return nil
}

func (c *VPNClient) tunToServer() {
	defer c.wg.Done()

	buf := make([]byte, config.DefaultMTU+100)

	for {
		select {
		case <-c.ctx.Done():
			return
		default:
		}

		n, err := c.tunDev.Read(buf)
		if err != nil {
			select {
			case <-c.ctx.Done():
				return
			default:
				continue
			}
		}

		if err := packet.ValidatePacket(buf[:n], config.DefaultMTU); err != nil {
			continue
		}

		dstIP := packet.GetDstIP(buf[:n])
		if dstIP == nil || dstIP.Equal(c.serverIP) {
			continue
		}

		if err := c.conn.Send(buf[:n], true); err != nil {
			log.Printf("Send error: %v", err)
		}
	}
}

func (c *VPNClient) serverToTun() {
	defer c.wg.Done()

	for {
		select {
		case <-c.ctx.Done():
			return
		case data := <-c.conn.RecvChan():
			if err := packet.ValidatePacket(data, 0); err != nil {
				continue
			}
			c.tunDev.Write(data)
		}
	}
}
