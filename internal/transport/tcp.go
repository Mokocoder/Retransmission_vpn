//go:build linux

package transport

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net"
	"sync"
	"sync/atomic"
	"time"

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

	rawConn    net.PacketConn
	recvChan   chan []byte
	recvBuffer []byte

	keyPair *crypto.KeyPair
	cipher  *crypto.Cipher
	psk     []byte

	mu        sync.Mutex
	closeOnce sync.Once
	closed    chan struct{}
}

func NewTCPConn(remoteIP net.IP, remotePort uint16, psk []byte) (*TCPConn, error) {
	localIP, err := getOutboundIP(remoteIP)
	if err != nil {
		return nil, fmt.Errorf("get local IP: %w", err)
	}

	rawConn, err := net.ListenPacket("ip4:tcp", localIP.String())
	if err != nil {
		return nil, fmt.Errorf("listen raw socket: %w", err)
	}

	c := &TCPConn{
		localIP:    localIP,
		localPort:  cryptoRandUint16(config.EphemeralPortBase, config.EphemeralPortRange),
		remoteIP:   remoteIP,
		remotePort: remotePort,
		seq:        cryptoRandUint32(config.SeqNumBase, config.SeqNumRange),
		recvChan:   make(chan []byte, config.RecvChanSize),
		recvBuffer: make([]byte, config.MaxPacketSize),
		rawConn:    rawConn,
		closed:     make(chan struct{}),
		psk:        psk,
	}

	return c, nil
}

func (c *TCPConn) Connect(ctx context.Context) error {
	go c.recvLoop()

	syn := packet.BuildTCPPacket(
		c.localIP, c.remoteIP,
		c.localPort, c.remotePort,
		c.seq, 0,
		packet.TCPFlagSYN,
		nil,
	)

	var synAck []byte
	var err error
	for attempt := 0; attempt < config.HandshakeMaxRetries; attempt++ {
		if err := c.sendRaw(syn); err != nil {
			return fmt.Errorf("send SYN: %w", err)
		}

		synAck, err = c.waitPacket(ctx, func(flags uint8) bool {
			return flags&packet.TCPFlagSYN != 0 && flags&packet.TCPFlagACK != 0
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

	tcpHdr, err := packet.ParseTCP(synAck[packet.IPv4HeaderLen:])
	if err != nil {
		return fmt.Errorf("parse SYN-ACK: %w", err)
	}
	c.seq++
	c.ack = tcpHdr.Seq + 1
	c.lastSeq = c.seq

	ack := packet.BuildTCPPacket(
		c.localIP, c.remoteIP,
		c.localPort, c.remotePort,
		c.seq, c.ack,
		packet.TCPFlagACK,
		nil,
	)

	if err := c.sendRaw(ack); err != nil {
		return fmt.Errorf("send ACK: %w", err)
	}

	log.Println("[TCP] Handshake complete, starting key exchange...")

	if err := c.performKeyExchange(ctx); err != nil {
		return fmt.Errorf("key exchange: %w", err)
	}
	log.Println("[TCP] Key exchange complete, encryption enabled")

	c.connected.Store(true)
	return nil
}

func (c *TCPConn) performKeyExchange(ctx context.Context) error {
	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		return fmt.Errorf("generate key pair: %w", err)
	}
	c.keyPair = kp

	pubSeq := c.seq
	pubPkt := packet.BuildTCPPacket(
		c.localIP, c.remoteIP,
		c.localPort, c.remotePort,
		pubSeq, c.ack,
		packet.TCPFlagPSH|packet.TCPFlagACK,
		kp.Public[:],
	)

	var serverPubKey []byte
	for attempt := 0; attempt < config.HandshakeMaxRetries; attempt++ {
		if err := c.sendRaw(pubPkt); err != nil {
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
	verifyPkt := packet.BuildTCPPacket(
		c.localIP, c.remoteIP,
		c.localPort, c.remotePort,
		verifySeq, c.ack,
		packet.TCPFlagPSH|packet.TCPFlagACK,
		verifyData,
	)

	for attempt := 0; attempt < config.HandshakeMaxRetries; attempt++ {
		if err := c.sendRaw(verifyPkt); err != nil {
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
	timeout := time.After(config.HandshakeTimeout)
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-timeout:
			return ErrTimeout
		case pkt := <-c.recvChan:
			if len(pkt) < packet.IPv4HeaderLen+packet.TCPHeaderLen {
				continue
			}
			tcpHdr, err := packet.ParseTCP(pkt[packet.IPv4HeaderLen:])
			if err != nil {
				continue
			}
			dataOffset := int(tcpHdr.DataOffset) * 4
			payload := pkt[packet.IPv4HeaderLen+dataOffset:]
			if len(payload) == 0 {
				continue
			}

			decrypted, err := c.cipher.Decrypt(payload)
			if err != nil {
				continue
			}

			if string(decrypted) == string(crypto.VerifyToken) {
				return nil
			}
			continue
		}
	}
}

func (c *TCPConn) waitKeyExchange(ctx context.Context) ([]byte, error) {
	timeout := time.After(config.HandshakeTimeout)
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timeout:
			return nil, ErrKeyExchange
		case pkt := <-c.recvChan:
			if len(pkt) < packet.IPv4HeaderLen+packet.TCPHeaderLen {
				continue
			}
			tcpHdr, err := packet.ParseTCP(pkt[packet.IPv4HeaderLen:])
			if err != nil {
				continue
			}
			dataOffset := int(tcpHdr.DataOffset) * 4
			payload := pkt[packet.IPv4HeaderLen+dataOffset:]
			if len(payload) == crypto.KeySize {
				return payload, nil
			}
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

		c.rawConn.SetReadDeadline(time.Now().Add(config.ReadTimeout))
		n, addr, err := c.rawConn.ReadFrom(c.recvBuffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			continue
		}

		srcIP := net.ParseIP(addr.String())
		if srcIP != nil && !srcIP.Equal(c.remoteIP) {
			continue
		}

		if n < packet.TCPHeaderLen {
			continue
		}

		tcpHdr, err := packet.ParseTCP(c.recvBuffer[:n])
		if err != nil {
			continue
		}

		if tcpHdr.SrcPort != c.remotePort || tcpHdr.DstPort != c.localPort {
			continue
		}

		pkt := make([]byte, packet.IPv4HeaderLen+n)
		copy(pkt[packet.IPv4HeaderLen:], c.recvBuffer[:n])

		select {
		case c.recvChan <- pkt:
		default:
		}
	}
}

func (c *TCPConn) waitPacket(ctx context.Context, match func(flags uint8) bool) ([]byte, error) {
	timeout := time.After(config.HandshakeTimeout)
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-timeout:
			return nil, ErrTimeout
		case pkt := <-c.recvChan:
			if len(pkt) < packet.IPv4HeaderLen+packet.TCPHeaderLen {
				continue
			}
			tcpHdr, err := packet.ParseTCP(pkt[packet.IPv4HeaderLen:])
			if err != nil {
				continue
			}
			if match(tcpHdr.Flags) {
				return pkt, nil
			}
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
	ack := c.ack
	c.mu.Unlock()

	pkt := packet.BuildTCPPacket(
		c.localIP, c.remoteIP,
		c.localPort, c.remotePort,
		seqToUse, ack,
		packet.TCPFlagPSH|packet.TCPFlagACK,
		encrypted,
	)

	return c.sendRaw(pkt)
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
	case pkt := <-c.recvChan:
		if len(pkt) < packet.IPv4HeaderLen+packet.TCPHeaderLen {
			return nil, nil
		}
		tcpHdr, err := packet.ParseTCP(pkt[packet.IPv4HeaderLen:])
		if err != nil {
			return nil, nil
		}
		dataOffset := int(tcpHdr.DataOffset) * 4
		payload := pkt[packet.IPv4HeaderLen+dataOffset:]
		if len(payload) == 0 {
			return nil, nil
		}
		decrypted, err := c.cipher.Decrypt(payload)
		if err != nil {
			return nil, nil
		}
		return decrypted, nil
	}
}

func (c *TCPConn) RecvChan() <-chan []byte {
	return c.recvChan
}

func (c *TCPConn) sendRaw(pkt []byte) error {
	_, err := c.rawConn.WriteTo(pkt[packet.IPv4HeaderLen:], &net.IPAddr{IP: c.remoteIP})
	return err
}

func (c *TCPConn) Close() error {
	c.closeOnce.Do(func() {
		close(c.closed)
		c.connected.Store(false)

		rst := packet.BuildTCPPacket(
			c.localIP, c.remoteIP,
			c.localPort, c.remotePort,
			c.seq, c.ack,
			packet.TCPFlagRST,
			nil,
		)
		c.sendRaw(rst)
		c.rawConn.Close()
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

func getOutboundIP(target net.IP) (net.IP, error) {
	conn, err := net.Dial("udp4", target.String()+":80")
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP, nil
}
