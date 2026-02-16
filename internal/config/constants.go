package config

import "time"

// Network defaults
const (
	DefaultPort   = 9999
	DefaultMTU    = 1280
	DefaultMSS    = 1200
	MaxPacketSize = 65535
)

// Virtual network addressing
const (
	VirtualSubnet    = "10.8.0"
	VirtualNetwork   = "10.8.0.0/24"
	VirtualGatewayIP = "10.8.0.1"
	VirtualClientIP  = "10.8.0.2"
	VirtualMask      = "255.255.255.0"
	VirtualGateway6  = "fd00::1"
	VirtualClient6   = "fd00::2"
	VirtualNetwork6  = "fd00::/64"
)

// IP pool range
const (
	ClientIPStart = 2
	ClientIPEnd   = 254
)

// Timeouts
const (
	ConnectTimeout        = 10 * time.Second
	HandshakeTimeout      = 5 * time.Second
	PendingSessionTimeout = 30 * time.Second
	SessionTimeout        = 5 * time.Minute
	CleanupInterval       = 60 * time.Second
	ReadTimeout           = 100 * time.Millisecond
)

// Handshake retry/backoff
const (
	HandshakeMaxRetries     = 3
	HandshakeRetryBaseDelay = 300 * time.Millisecond
	HandshakeRetryMaxDelay  = 2 * time.Second
)

// SYN-cookie rotation (server-side stateless handshake guard)
const (
	SyncookieInterval = 30 * time.Second
	SyncookieBuckets  = 2
)

// Session limits
const (
	MaxSessions = 1024
)

// TCP ephemeral port range for client connections
const (
	EphemeralPortBase  = 40000
	EphemeralPortRange = 20000
)

// Initial sequence number range
const (
	SeqNumBase  = 1000000
	SeqNumRange = 1000000
)

// Receive channel buffer sizes
const (
	RecvChanSize    = 256
	RecvChanSizeWin = 4096
)

// TUN device names
const (
	TunNameLinux   = "tun0"
	TunNameWindows = "VPNTunnel"
)
