//go:build linux

package server

import (
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"log"
	"net"
	"sync"
	"time"

	"retransmission-vpn/internal/config"
	"retransmission-vpn/internal/packet"
	"retransmission-vpn/internal/transport"
	"retransmission-vpn/internal/tun"
)

type Server struct {
	port      uint16
	psk       []byte
	tunDev    *tun.LinuxTunDevice
	rawSck    *transport.RawSocket
	pool      *transport.IPPool
	cookieKey [32]byte

	sessions   map[string]*transport.Session
	sessionsMu sync.RWMutex

	ctx    context.Context
	cancel context.CancelFunc
	wg     sync.WaitGroup
}

func New(port uint16, psk []byte) *Server {
	s := &Server{
		port:     port,
		psk:      psk,
		pool:     transport.NewIPPool(config.VirtualSubnet, config.ClientIPStart, config.ClientIPEnd),
		sessions: make(map[string]*transport.Session),
	}

	if _, err := rand.Read(s.cookieKey[:]); err != nil {
		seed := make([]byte, len(psk)+8)
		copy(seed, psk)
		binary.BigEndian.PutUint64(seed[len(psk):], uint64(time.Now().UnixNano()))
		sum := sha256.Sum256(seed)
		copy(s.cookieKey[:], sum[:])
	}

	return s
}

func (s *Server) Run(ctx context.Context) error {
	s.ctx, s.cancel = context.WithCancel(ctx)
	defer s.cancel()

	log.Println("TCP Retransmission Tunnel - Server")
	log.Println("===================================")

	if err := s.setupTun(); err != nil {
		return fmt.Errorf("setup tun: %w", err)
	}
	defer s.cleanup()

	if err := s.setupRawSocket(); err != nil {
		return fmt.Errorf("setup socket: %w", err)
	}
	defer s.rawSck.Close()

	log.Printf("Listening on %s:%d", s.rawSck.LocalIP(), s.port)
	log.Printf("TUN: %s (%s)", s.tunDev.Name(), config.VirtualGatewayIP)
	log.Printf("Client pool: %s.%d-%s.%d", config.VirtualSubnet, config.ClientIPStart, config.VirtualSubnet, config.ClientIPEnd)
	log.Println("Waiting for connections...")

	s.wg.Add(3)
	go s.acceptLoop()
	go s.tunLoop()
	go s.cleanupLoop()

	<-s.ctx.Done()
	log.Println("Shutting down...")

	// Close socket/TUN first to unblock I/O
	s.rawSck.Close()
	s.tunDev.Close()

	s.wg.Wait()

	return nil
}

func (s *Server) setupTun() error {
	cfg := tun.Config{
		Name:     config.TunNameLinux,
		Address:  config.VirtualGatewayIP,
		Address6: config.VirtualGateway6,
		MTU:      config.DefaultMTU,
	}

	dev, err := tun.New(cfg)
	if err != nil {
		return err
	}

	s.tunDev = dev.(*tun.LinuxTunDevice)

	if err := s.tunDev.SetupNAT(config.VirtualNetwork); err != nil {
		log.Printf("Warning: NAT setup failed: %v", err)
	}

	if err := s.tunDev.BlockRST(int(s.port)); err != nil {
		log.Printf("Warning: RST block failed: %v", err)
	}

	return nil
}

func (s *Server) setupRawSocket() error {
	var err error
	s.rawSck, err = transport.NewRawSocket(s.port)
	return err
}

func (s *Server) acceptLoop() {
	defer s.wg.Done()

	buf := make([]byte, config.MaxPacketSize)

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		_, srcIP, tcpHdr, payload, err := s.rawSck.ReadPacket(buf)
		if err != nil {
			select {
			case <-s.ctx.Done():
				return
			default:
				continue
			}
		}

		s.handlePacket(srcIP, tcpHdr, payload)
	}
}

func (s *Server) handlePacket(srcIP net.IP, tcpHdr *packet.TCPHeader, payload []byte) {
	key := fmt.Sprintf("%s:%d", srcIP, tcpHdr.SrcPort)

	if tcpHdr.Flags&packet.TCPFlagSYN != 0 {
		s.handleSYN(key, srcIP, tcpHdr)
		return
	}

	s.sessionsMu.RLock()
	session, exists := s.sessions[key]
	s.sessionsMu.RUnlock()

	if !exists {
		// Stateless syncookie completion must arrive as a pure ACK.
		if tcpHdr.Flags != packet.TCPFlagACK || len(payload) != 0 {
			return
		}
		if !s.validateSyncookie(srcIP, tcpHdr.SrcPort, tcpHdr.Seq, tcpHdr.Ack) {
			return
		}

		var ok bool
		session, ok = s.getOrCreateSession(key, srcIP, tcpHdr.SrcPort, tcpHdr.Seq, tcpHdr.Ack)
		if !ok {
			return
		}
		return
	} else {
		session.UpdateSeq(tcpHdr.Seq, tcpHdr.Ack)
		session.Touch()
	}

	if len(payload) > 0 {
		s.handleData(session, payload)
	}
}

func (s *Server) handleSYN(key string, srcIP net.IP, tcpHdr *packet.TCPHeader) {
	s.sessionsMu.RLock()
	_, exists := s.sessions[key]
	s.sessionsMu.RUnlock()
	if exists {
		return
	}

	cookie := s.issueSyncookie(srcIP, tcpHdr.SrcPort, tcpHdr.Seq)
	if err := s.rawSck.SendSYNACK(srcIP, tcpHdr.SrcPort, tcpHdr.Seq, cookie); err != nil {
		log.Printf("Failed to send SYN-ACK to %s: %v", key, err)
		return
	}
}

func (s *Server) getOrCreateSession(key string, srcIP net.IP, srcPort uint16, seq, ack uint32) (*transport.Session, bool) {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()

	if session, exists := s.sessions[key]; exists {
		session.UpdateSeq(seq, ack)
		session.Touch()
		return session, true
	}

	if len(s.sessions) >= config.MaxSessions {
		log.Printf("Session limit reached (%d), rejecting %s", config.MaxSessions, key)
		return nil, false
	}

	session := transport.NewSession(srcIP, srcPort, nil, s.psk)
	session.UpdateSeq(seq, ack)
	session.InitPayloadSeq(seq)
	s.sessions[key] = session
	log.Printf("[+] %s pending auth", key)
	return session, true
}

func (s *Server) currentSyncookieBucket() uint64 {
	interval := int64(config.SyncookieInterval / time.Second)
	if interval <= 0 {
		return uint64(time.Now().Unix())
	}
	return uint64(time.Now().Unix() / interval)
}

func (s *Server) makeSyncookie(srcIP net.IP, srcPort uint16, clientSynSeq uint32, bucket uint64) uint32 {
	h := hmac.New(sha256.New, s.cookieKey[:])
	ip := srcIP.To4()
	if ip == nil {
		ip = srcIP
	}
	h.Write(ip)

	var meta [14]byte
	binary.BigEndian.PutUint16(meta[0:2], srcPort)
	binary.BigEndian.PutUint32(meta[2:6], clientSynSeq)
	binary.BigEndian.PutUint64(meta[6:14], bucket)
	h.Write(meta[:])

	cookie := binary.BigEndian.Uint32(h.Sum(nil)[:4])
	if cookie == ^uint32(0) {
		return cookie - 1
	}
	return cookie
}

func (s *Server) issueSyncookie(srcIP net.IP, srcPort uint16, clientSynSeq uint32) uint32 {
	return s.makeSyncookie(srcIP, srcPort, clientSynSeq, s.currentSyncookieBucket())
}

func (s *Server) validateSyncookie(srcIP net.IP, srcPort uint16, clientSeq, ack uint32) bool {
	if ack == 0 || clientSeq == 0 {
		return false
	}
	cookie := ack - 1
	clientSynSeq := clientSeq - 1
	now := s.currentSyncookieBucket()

	for i := 0; i < config.SyncookieBuckets; i++ {
		if now < uint64(i) {
			break
		}
		if cookie == s.makeSyncookie(srcIP, srcPort, clientSynSeq, now-uint64(i)) {
			return true
		}
	}

	return false
}

func (s *Server) handleData(session *transport.Session, payload []byte) {
	if !session.IsEncryptionReady() && !session.IsVerifying() && transport.IsKeyExchangePacket(payload) {
		serverPubKey, err := session.HandleKeyExchange(payload)
		if err != nil {
			log.Printf("[KeyExchange] %s: failed: %v", session.Key(), err)
			return
		}
		if serverPubKey != nil {
			if err := s.rawSck.SendKeyExchange(session, serverPubKey); err != nil {
				log.Printf("[KeyExchange] %s: send failed: %v", session.Key(), err)
				return
			}
			log.Printf("[KeyExchange] %s: waiting for verification", session.Key())
		}
		return
	}

	if session.IsVerifying() {
		response, err := session.VerifyClient(payload)
		if err != nil {
			log.Printf("[KeyExchange] %s: verification failed - %v", session.Key(), err)
			s.sessionsMu.Lock()
			delete(s.sessions, session.Key())
			s.pool.Release(session.Key())
			s.sessionsMu.Unlock()
			return
		}

		virtualIP, exists := session.GetVirtualIP()
		if !exists {
			assigned, ok := s.pool.Allocate(session.Key())
			if !ok {
				log.Printf("IP pool exhausted, rejecting %s", session.Key())
				s.sessionsMu.Lock()
				delete(s.sessions, session.Key())
				s.sessionsMu.Unlock()
				return
			}
			session.SetVirtualIP(assigned)
			virtualIP = assigned
		}

		if err := s.rawSck.SendKeyExchange(session, response); err != nil {
			log.Printf("[KeyExchange] %s: send response failed: %v", session.Key(), err)
			s.sessionsMu.Lock()
			delete(s.sessions, session.Key())
			s.pool.Release(session.Key())
			s.sessionsMu.Unlock()
			return
		}
		log.Printf("[KeyExchange] %s: verified, assigned %s", session.Key(), virtualIP)
		return
	}

	// If the final verify response was lost server->client, client will retransmit
	// the same verify token. Re-send cached response idempotently.
	if response, ok := session.VerifyReplayResponse(payload); ok {
		if err := s.rawSck.SendKeyExchange(session, response); err != nil {
			log.Printf("[KeyExchange] %s: resend response failed: %v", session.Key(), err)
		}
		return
	}

	if !session.IsEncryptionReady() {
		return
	}
	decrypted, err := session.Decrypt(payload)
	if err != nil {
		return
	}

	if err := packet.ValidatePacket(decrypted, config.DefaultMTU); err != nil {
		return
	}

	virtualIP, hasVirtualIP := session.GetVirtualIP()
	if !hasVirtualIP {
		return
	}

	srcIP := packet.GetSrcIP(decrypted)
	if srcIP != nil {
		if _, exists := session.GetClientVIP(); !exists {
			session.SetClientVIP(srcIP)
			log.Printf("[Session] %s: VIP %s -> %s", session.Key(), srcIP, virtualIP)
		}
	}

	decrypted = packet.ClampMSS(decrypted, config.DefaultMSS)
	decrypted = packet.RewriteSrcIP(decrypted, virtualIP)

	if _, err := s.tunDev.Write(decrypted); err != nil {
		log.Printf("TUN write error: %v", err)
	}
}

func (s *Server) tunLoop() {
	defer s.wg.Done()

	buf := make([]byte, config.DefaultMTU+100)

	for {
		select {
		case <-s.ctx.Done():
			return
		default:
		}

		n, err := s.tunDev.Read(buf)
		if err != nil {
			select {
			case <-s.ctx.Done():
				return
			default:
				continue
			}
		}

		if err := packet.ValidatePacket(buf[:n], 0); err != nil {
			continue
		}

		dstIP := packet.GetDstIP(buf[:n])
		if dstIP == nil {
			continue
		}

		key, ok := s.pool.GetKeyByIP(dstIP)
		if !ok {
			continue
		}

		s.sessionsMu.RLock()
		session, exists := s.sessions[key]
		s.sessionsMu.RUnlock()

		if !exists {
			continue
		}

		data := packet.ClampMSS(buf[:n], config.DefaultMSS)
		if clientVIP, ok := session.GetClientVIP(); ok {
			data = packet.RewriteDstIP(data, clientVIP)
		}

		if err := s.rawSck.SendTo(session, data, true); err != nil {
			log.Printf("Send error: %v", err)
		}
	}
}

func (s *Server) cleanupLoop() {
	defer s.wg.Done()

	ticker := time.NewTicker(config.CleanupInterval)
	defer ticker.Stop()

	for {
		select {
		case <-s.ctx.Done():
			return
		case <-ticker.C:
			s.cleanupSessions()
		}
	}
}

func (s *Server) cleanupSessions() {
	s.sessionsMu.Lock()
	defer s.sessionsMu.Unlock()

	for key, session := range s.sessions {
		timeout := config.SessionTimeout
		if !session.IsEncryptionReady() {
			timeout = config.PendingSessionTimeout
		}
		if session.IsExpired(timeout) {
			delete(s.sessions, key)
			s.pool.Release(key)
			log.Printf("[-] %s (timeout)", key)
		}
	}
}

func (s *Server) cleanup() {
	if s.tunDev != nil {
		s.tunDev.Cleanup(int(s.port), config.VirtualNetwork)
	}
}
