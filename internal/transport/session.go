package transport

import (
	"bytes"
	"errors"
	"fmt"
	"net"
	"sync"
	"time"

	"retransmission-vpn/internal/config"
	"retransmission-vpn/internal/crypto"
)

// KeyExchangeState represents the stage of the ECDH key exchange.
type KeyExchangeState int

const (
	KeyExchangePending   KeyExchangeState = 0
	KeyExchangeVerifying KeyExchangeState = 1
	KeyExchangeComplete  KeyExchangeState = 2
)

type Session struct {
	ClientIP           net.IP
	ClientPort         uint16
	VirtualIP          net.IP
	ClientVIP          net.IP
	ClientSeq          uint32
	ClientAck          uint32
	ExpectedPayloadSeq uint32
	ServerSeq          uint32
	LastDataSeq        uint32
	LastActive         time.Time
	FirstSent          bool
	ClientVIPSet       bool
	PayloadSeqInit     bool

	KeyExchangeState KeyExchangeState
	KeyPair          *crypto.KeyPair
	Cipher           *crypto.Cipher
	PSK              []byte
	lastVerifyToken  []byte
	verifyResponse   []byte

	mu sync.RWMutex
}

func NewSession(clientIP net.IP, clientPort uint16, virtualIP net.IP, psk []byte) *Session {
	return &Session{
		ClientIP:   clientIP,
		ClientPort: clientPort,
		VirtualIP:  virtualIP,
		ServerSeq:  cryptoRandUint32(config.SeqNumBase, config.SeqNumRange),
		LastActive: time.Now(),
		PSK:        psk,
	}
}

func (s *Session) Key() string {
	return fmt.Sprintf("%s:%d", s.ClientIP, s.ClientPort)
}

func (s *Session) IsExpired(timeout time.Duration) bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return time.Since(s.LastActive) > timeout
}

func (s *Session) Touch() {
	s.mu.Lock()
	s.LastActive = time.Now()
	s.mu.Unlock()
}

func (s *Session) SetClientVIP(vip net.IP) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.ClientVIPSet {
		s.ClientVIP = make(net.IP, len(vip))
		copy(s.ClientVIP, vip)
		s.ClientVIPSet = true
	}
}

func (s *Session) SetVirtualIP(vip net.IP) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.VirtualIP == nil && vip != nil {
		s.VirtualIP = make(net.IP, len(vip))
		copy(s.VirtualIP, vip)
	}
}

func (s *Session) GetVirtualIP() (net.IP, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.VirtualIP == nil {
		return nil, false
	}
	vip := make(net.IP, len(s.VirtualIP))
	copy(vip, s.VirtualIP)
	return vip, true
}

func (s *Session) GetClientVIP() (net.IP, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.ClientVIPSet && s.ClientVIP != nil {
		vip := make(net.IP, len(s.ClientVIP))
		copy(vip, s.ClientVIP)
		return vip, true
	}
	return nil, false
}

func (s *Session) UpdateSeq(clientSeq, clientAck uint32) {
	s.mu.Lock()
	s.ClientSeq = clientSeq
	s.ClientAck = clientAck
	s.mu.Unlock()
}

// InitPayloadSeq seeds expected payload sequence for this session.
func (s *Session) InitPayloadSeq(seq uint32) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.ExpectedPayloadSeq = seq
	s.PayloadSeqInit = true
}

// AcceptPayloadSeq allows strictly in-order payload or exact retransmission.
func (s *Session) AcceptPayloadSeq(seq uint32, payloadLen int) bool {
	if payloadLen <= 0 {
		return true
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	plen := uint32(payloadLen)
	if !s.PayloadSeqInit {
		s.ExpectedPayloadSeq = seq
		s.PayloadSeqInit = true
	}

	// In-order payload.
	if seq == s.ExpectedPayloadSeq {
		s.ExpectedPayloadSeq += plen
		return true
	}

	// Exact retransmission of the immediately previous payload.
	if seq+plen == s.ExpectedPayloadSeq {
		return true
	}

	return false
}

func (s *Session) HandleKeyExchange(clientPubKey []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.KeyExchangeState == KeyExchangeComplete {
		return nil, nil
	}

	if len(clientPubKey) != crypto.KeySize {
		return nil, ErrKeyExchange
	}

	kp, err := crypto.GenerateKeyPair()
	if err != nil {
		return nil, err
	}
	s.KeyPair = kp

	var clientKey [crypto.KeySize]byte
	copy(clientKey[:], clientPubKey)

	sharedSecret, err := crypto.ComputeSharedSecret(&kp.Private, &clientKey, s.PSK)
	if err != nil {
		return nil, err
	}

	s.Cipher, err = crypto.NewCipher(sharedSecret, true)
	if err != nil {
		return nil, err
	}

	s.KeyExchangeState = KeyExchangeVerifying
	return kp.Public[:], nil
}

func (s *Session) VerifyClient(encryptedToken []byte) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Idempotent handling: if client retransmits the same verify token after
	// server-side success (response loss case), resend cached response.
	if s.KeyExchangeState == KeyExchangeComplete && len(s.lastVerifyToken) > 0 {
		if bytes.Equal(encryptedToken, s.lastVerifyToken) && len(s.verifyResponse) > 0 {
			resp := make([]byte, len(s.verifyResponse))
			copy(resp, s.verifyResponse)
			return resp, nil
		}
	}

	if s.KeyExchangeState != KeyExchangeVerifying || s.Cipher == nil {
		return nil, ErrKeyExchange
	}

	decrypted, err := s.Cipher.Decrypt(encryptedToken)
	if err != nil {
		s.KeyExchangeState = KeyExchangePending
		return nil, errors.New("invalid key")
	}

	if string(decrypted) != string(crypto.VerifyToken) {
		s.KeyExchangeState = KeyExchangePending
		return nil, errors.New("verification failed")
	}

	s.KeyExchangeState = KeyExchangeComplete
	s.lastVerifyToken = append(s.lastVerifyToken[:0], encryptedToken...)
	s.verifyResponse = s.Cipher.Encrypt(crypto.VerifyToken)

	resp := make([]byte, len(s.verifyResponse))
	copy(resp, s.verifyResponse)
	return resp, nil
}

// VerifyReplayResponse returns cached verify response when the same verify
// token is retransmitted after key exchange completion.
func (s *Session) VerifyReplayResponse(encryptedToken []byte) ([]byte, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.KeyExchangeState != KeyExchangeComplete || len(s.lastVerifyToken) == 0 {
		return nil, false
	}
	if !bytes.Equal(encryptedToken, s.lastVerifyToken) || len(s.verifyResponse) == 0 {
		return nil, false
	}

	resp := make([]byte, len(s.verifyResponse))
	copy(resp, s.verifyResponse)
	return resp, true
}

func (s *Session) IsEncryptionReady() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.KeyExchangeState == KeyExchangeComplete && s.Cipher != nil
}

func (s *Session) IsVerifying() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.KeyExchangeState == KeyExchangeVerifying
}

func (s *Session) Encrypt(data []byte) []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.Cipher == nil {
		return data
	}
	return s.Cipher.Encrypt(data)
}

func (s *Session) Decrypt(data []byte) ([]byte, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if s.Cipher == nil {
		return data, nil
	}
	return s.Cipher.Decrypt(data)
}
