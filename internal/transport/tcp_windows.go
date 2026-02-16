//go:build windows

package transport

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"os/exec"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"retransmission-vpn/internal/config"
	"retransmission-vpn/internal/crypto"
	"retransmission-vpn/internal/packet"
)

type TCPConn struct {
	localIP    net.IP
	localPort  uint16
	remoteIP   net.IP
	remotePort uint16

	seq       uint32
	ack       uint32
	lastSeq   uint32
	connected atomic.Bool

	handle   *pcap.Handle
	iface    string
	localMAC net.HardwareAddr
	gwMAC    net.HardwareAddr

	recvChan chan []byte

	keyPair *crypto.KeyPair
	cipher  *crypto.Cipher
	psk     []byte

	mu        sync.Mutex
	closeOnce sync.Once
	closed    chan struct{}
}

func NewTCPConn(remoteIP net.IP, remotePort uint16, psk []byte) (*TCPConn, error) {
	localIP, iface, err := getOutboundInterface(remoteIP)
	if err != nil {
		return nil, fmt.Errorf("get interface: %w", err)
	}

	localMAC, gwMAC, err := getMACAddresses(localIP)
	if err != nil {
		return nil, fmt.Errorf("get MAC: %w", err)
	}

	handle, err := pcap.OpenLive(iface, int32(config.MaxPacketSize), true, time.Millisecond)
	if err != nil {
		return nil, fmt.Errorf("open pcap: %w", err)
	}

	c := &TCPConn{
		localIP:    localIP,
		localPort:  cryptoRandUint16(config.EphemeralPortBase, config.EphemeralPortRange),
		remoteIP:   remoteIP,
		remotePort: remotePort,
		seq:        cryptoRandUint32(config.SeqNumBase, config.SeqNumRange),
		handle:     handle,
		iface:      iface,
		localMAC:   localMAC,
		gwMAC:      gwMAC,
		recvChan:   make(chan []byte, config.RecvChanSizeWin),
		closed:     make(chan struct{}),
		psk:        psk,
	}

	filter := fmt.Sprintf("tcp and src host %s and src port %d and dst port %d",
		remoteIP, remotePort, c.localPort)
	if err := handle.SetBPFFilter(filter); err != nil {
		handle.Close()
		return nil, fmt.Errorf("set filter: %w", err)
	}

	return c, nil
}

func (c *TCPConn) Connect(ctx context.Context) error {
	log.Printf("[TCP] Local: %s, MAC: %s", c.localIP, c.localMAC)
	log.Printf("[TCP] Interface: %s", c.iface)

	log.Println("[TCP] Sending SYN and waiting for SYN-ACK...")
	var synAck *layers.TCP
	var err error
	for attempt := 0; attempt < config.HandshakeMaxRetries; attempt++ {
		if err := c.sendPacket(packet.TCPFlagSYN, nil); err != nil {
			return fmt.Errorf("send SYN: %w", err)
		}

		synAck, err = c.waitPacket(ctx, func(tcp *layers.TCP) bool {
			return tcp.SYN && tcp.ACK
		})
		if err == nil {
			break
		}
		if !errors.Is(err, ErrTimeout) || attempt == config.HandshakeMaxRetries-1 {
			return fmt.Errorf("wait SYN-ACK: %w", err)
		}
		if err := sleepWithContext(ctx, handshakeBackoff(attempt)); err != nil {
			return err
		}
	}
	log.Println("[TCP] SYN-ACK received")

	c.seq++
	c.ack = synAck.Seq + 1
	c.lastSeq = c.seq

	log.Println("[TCP] Sending ACK...")
	if err := c.sendPacket(packet.TCPFlagACK, nil); err != nil {
		return fmt.Errorf("send ACK: %w", err)
	}

	log.Println("[TCP] Handshake complete, starting key exchange...")

	if err := c.performKeyExchange(ctx); err != nil {
		return fmt.Errorf("key exchange: %w", err)
	}
	log.Println("[TCP] Key exchange complete, encryption enabled")

	c.connected.Store(true)
	go c.recvLoop()

	return nil
}

func (c *TCPConn) performKeyExchange(ctx context.Context) error {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("generate key pair: %w", err)
	}
	c.keyPair = kp

	pubSeq := c.seq
	var serverPubKey []byte
	for attempt := 0; attempt < config.HandshakeMaxRetries; attempt++ {
		if err := c.sendPacketWithSeq(packet.TCPFlagPSH|packet.TCPFlagACK, pubSeq, kp.Public[:]); err != nil {
			return fmt.Errorf("send public key: %w", err)
		}

		serverPubKey, err = c.waitKeyExchange(ctx)
		if err == nil {
			break
		}
		if !errors.Is(err, ErrKeyExchange) || attempt == config.HandshakeMaxRetries-1 {
			return fmt.Errorf("receive server key: %w", err)
		}
		if err := sleepWithContext(ctx, handshakeBackoff(attempt)); err != nil {
			return err
		}
	}
	c.lastSeq = pubSeq
	c.seq = pubSeq + uint32(len(kp.Public))

	var serverKey [crypto.KeySize]byte
	copy(serverKey[:], serverPubKey)

	sharedSecret, err := crypto.ComputeSharedSecret(&kp.Private, &serverKey, c.psk)
	if err != nil {
		return fmt.Errorf("compute shared secret: %w", err)
	}

	c.cipher, err = crypto.NewCipher(sharedSecret, false)
	if err != nil {
		return fmt.Errorf("create cipher: %w", err)
	}

	verifyData := c.cipher.Encrypt(crypto.VerifyToken)
	verifySeq := c.seq
	for attempt := 0; attempt < config.HandshakeMaxRetries; attempt++ {
		if err := c.sendPacketWithSeq(packet.TCPFlagPSH|packet.TCPFlagACK, verifySeq, verifyData); err != nil {
			return fmt.Errorf("send verify token: %w", err)
		}

		if err := c.waitVerification(ctx); err == nil {
			c.lastSeq = verifySeq
			c.seq = verifySeq + uint32(len(verifyData))
			return nil
		} else if !errors.Is(err, ErrTimeout) || attempt == config.HandshakeMaxRetries-1 {
			return fmt.Errorf("key verification failed: %w", err)
		}

		if err := sleepWithContext(ctx, handshakeBackoff(attempt)); err != nil {
			return err
		}
	}

	return ErrTimeout
}

func (c *TCPConn) waitVerification(ctx context.Context) error {
	packetSource := gopacket.NewPacketSource(c.handle, c.handle.LinkType())
	timeout := time.After(config.HandshakeTimeout)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout:
			return ErrTimeout
		default:
		}

		pkt, err := packetSource.NextPacket()
		if err != nil {
			continue
		}

		tcpLayer := pkt.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			continue
		}

		tcp, ok := tcpLayer.(*layers.TCP)
		if !ok || len(tcp.Payload) == 0 {
			continue
		}

		decrypted, err := c.cipher.Decrypt(tcp.Payload)
		if err != nil {
			continue
		}

		if string(decrypted) == string(crypto.VerifyToken) {
			return nil
		}
		continue
	}
}

func (c *TCPConn) waitKeyExchange(ctx context.Context) ([]byte, error) {
	packetSource := gopacket.NewPacketSource(c.handle, c.handle.LinkType())
	timeout := time.After(config.HandshakeTimeout)

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timeout:
			return nil, ErrKeyExchange
		default:
		}

		pkt, err := packetSource.NextPacket()
		if err != nil {
			continue
		}

		tcpLayer := pkt.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			continue
		}

		tcp, ok := tcpLayer.(*layers.TCP)
		if !ok {
			continue
		}
		payload := tcp.Payload
		if len(payload) == crypto.KeySize {
			return payload, nil
		}
	}
}

func (c *TCPConn) recvLoop() {
	for {
		select {
		case <-c.closed:
			return
		default:
		}

		raw, _, err := c.handle.ReadPacketData()
		if err != nil {
			continue
		}

		if len(raw) < 54 {
			continue
		}

		ipStart := 14
		ihl := int(raw[ipStart]&0x0F) * 4
		if len(raw) < ipStart+ihl+20 {
			continue
		}

		tcpStart := ipStart + ihl
		dataOffset := int(raw[tcpStart+12]>>4) * 4

		payloadStart := tcpStart + dataOffset
		if payloadStart >= len(raw) {
			continue
		}

		payload := raw[payloadStart:]
		if len(payload) == 0 {
			continue
		}

		decrypted, err := c.cipher.Decrypt(payload)
		if err != nil {
			continue
		}

		select {
		case c.recvChan <- decrypted:
		default:
		}
	}
}

func (c *TCPConn) waitPacket(ctx context.Context, match func(*layers.TCP) bool) (*layers.TCP, error) {
	packetSource := gopacket.NewPacketSource(c.handle, c.handle.LinkType())
	timeout := time.After(config.HandshakeTimeout)

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timeout:
			return nil, ErrTimeout
		default:
		}

		pkt, err := packetSource.NextPacket()
		if err != nil {
			continue
		}

		tcpLayer := pkt.Layer(layers.LayerTypeTCP)
		if tcpLayer == nil {
			continue
		}

		tcp, ok := tcpLayer.(*layers.TCP)
		if !ok {
			continue
		}
		if match(tcp) {
			return tcp, nil
		}
	}
}

func (c *TCPConn) Send(data []byte, fakeRetrans bool) error {
	if !c.connected.Load() {
		return ErrNotConnected
	}

	encrypted := c.cipher.Encrypt(data)

	c.mu.Lock()
	seqToUse := c.seq
	if fakeRetrans {
		seqToUse = c.lastSeq
	} else {
		c.lastSeq = c.seq
		c.seq += uint32(len(encrypted))
	}
	c.mu.Unlock()

	return c.sendPacketWithSeq(packet.TCPFlagPSH|packet.TCPFlagACK, seqToUse, encrypted)
}

func (c *TCPConn) Recv(ctx context.Context) ([]byte, error) {
	if !c.connected.Load() {
		return nil, ErrNotConnected
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.closed:
		return nil, ErrClosed
	case data := <-c.recvChan:
		if len(data) == 0 {
			return nil, nil
		}
		return data, nil
	}
}

func (c *TCPConn) RecvChan() <-chan []byte {
	return c.recvChan
}

func (c *TCPConn) sendPacket(flags uint8, payload []byte) error {
	return c.sendPacketWithSeq(flags, c.seq, payload)
}

func (c *TCPConn) sendPacketWithSeq(flags uint8, seq uint32, payload []byte) error {
	totalLen := 14 + 20 + 20 + len(payload)
	buf := make([]byte, totalLen)

	copy(buf[0:6], c.gwMAC)
	copy(buf[6:12], c.localMAC)
	buf[12] = 0x08
	buf[13] = 0x00

	ipStart := 14
	buf[ipStart] = 0x45
	buf[ipStart+1] = 0
	ipLen := 20 + 20 + len(payload)
	buf[ipStart+2] = byte(ipLen >> 8)
	buf[ipStart+3] = byte(ipLen)
	buf[ipStart+6] = 0x40
	buf[ipStart+8] = 64
	buf[ipStart+9] = 6
	copy(buf[ipStart+12:ipStart+16], c.localIP.To4())
	copy(buf[ipStart+16:ipStart+20], c.remoteIP.To4())
	ipCsum := packet.Checksum(buf[ipStart : ipStart+20])
	buf[ipStart+10] = byte(ipCsum >> 8)
	buf[ipStart+11] = byte(ipCsum)

	tcpStart := 34
	buf[tcpStart] = byte(c.localPort >> 8)
	buf[tcpStart+1] = byte(c.localPort)
	buf[tcpStart+2] = byte(c.remotePort >> 8)
	buf[tcpStart+3] = byte(c.remotePort)
	buf[tcpStart+4] = byte(seq >> 24)
	buf[tcpStart+5] = byte(seq >> 16)
	buf[tcpStart+6] = byte(seq >> 8)
	buf[tcpStart+7] = byte(seq)
	buf[tcpStart+8] = byte(c.ack >> 24)
	buf[tcpStart+9] = byte(c.ack >> 16)
	buf[tcpStart+10] = byte(c.ack >> 8)
	buf[tcpStart+11] = byte(c.ack)
	buf[tcpStart+12] = 0x50
	buf[tcpStart+13] = flags
	buf[tcpStart+14] = 0xFF
	buf[tcpStart+15] = 0xFF

	if len(payload) > 0 {
		copy(buf[54:], payload)
	}

	tcpCsum := packet.TCPChecksum(c.localIP, c.remoteIP, buf[tcpStart:])
	buf[tcpStart+16] = byte(tcpCsum >> 8)
	buf[tcpStart+17] = byte(tcpCsum)

	return c.handle.WritePacketData(buf)
}

func (c *TCPConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
		c.connected.Store(false)

		c.sendPacket(packet.TCPFlagRST, nil)
		c.handle.Close()
	})
	return nil
}

func (c *TCPConn) LocalAddr() string {
	return fmt.Sprintf("%s:%d", c.localIP, c.localPort)
}

func (c *TCPConn) RemoteAddr() string {
	return fmt.Sprintf("%s:%d", c.remoteIP, c.remotePort)
}

func handshakeBackoff(attempt int) time.Duration {
	delay := config.HandshakeRetryBaseDelay * time.Duration(1<<attempt)
	if delay > config.HandshakeRetryMaxDelay {
		return config.HandshakeRetryMaxDelay
	}
	return delay
}

func sleepWithContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()

	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func getOutboundInterface(target net.IP) (net.IP, string, error) {
	conn, err := net.Dial("udp4", target.String()+":80")
	if err != nil {
		return nil, "", err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)
	localIP := localAddr.IP

	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, "", err
	}

	for _, dev := range devices {
		for _, addr := range dev.Addresses {
			if addr.IP.Equal(localIP) {
				return localIP, dev.Name, nil
			}
		}
	}

	return nil, "", errors.New("interface not found")
}

func getMACAddresses(localIP net.IP) (local, gw net.HardwareAddr, err error) {
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, nil, err
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
			ipnet, ok := addr.(*net.IPNet)
			if !ok {
				continue
			}

			if ipnet.IP.To4() != nil && ipnet.IP.Equal(localIP) {
				local = ifi.HardwareAddr
				gw, _ = getGatewayMAC()
				if gw == nil {
					gw = net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}
				}
				return local, gw, nil
			}
		}
	}

	return nil, nil, errors.New("interface not found for IP")
}

func getGatewayMAC() (net.HardwareAddr, error) {
	gwIP, err := getDefaultGateway()
	if err != nil {
		return nil, err
	}

	// Ping to populate ARP cache
	pingCmd := exec.Command("ping", "-n", "1", "-w", "500", gwIP.String())
	pingCmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	_ = pingCmd.Run()

	mac, err := lookupMAC(gwIP)
	if err != nil {
		log.Printf("[TCP] Gateway %s MAC lookup failed, using broadcast", gwIP)
		return net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff}, nil
	}

	log.Printf("[TCP] Gateway: %s -> %s", gwIP, mac)
	return mac, nil
}

func getDefaultGateway() (net.IP, error) {
	cmd := exec.Command("route", "print", "0.0.0.0")
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.Output()
	if err == nil {
		lines := strings.Split(string(out), "\n")
		for _, line := range lines {
			fields := strings.Fields(line)
			if len(fields) >= 3 && fields[0] == "0.0.0.0" && fields[1] == "0.0.0.0" {
				if gw := net.ParseIP(fields[2]); gw != nil {
					return gw.To4(), nil
				}
			}
		}
	}

	// Fallback: infer from interfaces
	interfaces, err := net.Interfaces()
	if err != nil {
		return nil, fmt.Errorf("list interfaces: %w", err)
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
				return net.IPv4(ip[0], ip[1], ip[2], 1), nil
			}
		}
	}
	return nil, errors.New("gateway not found")
}

func lookupMAC(ip net.IP) (net.HardwareAddr, error) {
	cmd := exec.Command("arp", "-a", ip.String())
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true}
	out, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	lines := strings.Split(string(out), "\n")
	for _, line := range lines {
		if strings.Contains(line, ip.String()) {
			fields := strings.Fields(line)
			for _, f := range fields {
				if mac, err := net.ParseMAC(strings.ReplaceAll(f, "-", ":")); err == nil {
					return mac, nil
				}
			}
		}
	}

	return nil, errors.New("MAC not found in ARP table")
}
