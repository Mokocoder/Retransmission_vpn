package crypto

import (
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"sync"
	"sync/atomic"

	"golang.org/x/crypto/chacha20poly1305"
	"golang.org/x/crypto/curve25519"
)

var (
	ErrDecryptFailed  = errors.New("crypto: decryption failed")
	ErrInvalidKey     = errors.New("crypto: invalid key")
	ErrReplayDetected = errors.New("crypto: replay detected")
)

const (
	KeySize      = 32
	NonceSize    = 12
	OverheadSize = chacha20poly1305.Overhead // 16 bytes (Poly1305 tag)
	replayWindow = 64
)

type KeyPair struct {
	Private [KeySize]byte
	Public  [KeySize]byte
}

func GenerateKeyPair() (*KeyPair, error) {
	kp := &KeyPair{}

	if _, err := rand.Read(kp.Private[:]); err != nil {
		return nil, err
	}

	kp.Private[0] &= 248
	kp.Private[31] &= 127
	kp.Private[31] |= 64

	curve25519.ScalarBaseMult(&kp.Public, &kp.Private)
	return kp, nil
}

func ComputeSharedSecret(privateKey, peerPublicKey *[KeySize]byte, psk []byte) ([]byte, error) {
	var shared [KeySize]byte
	curve25519.ScalarMult(&shared, privateKey, peerPublicKey)

	var zero [KeySize]byte
	if shared == zero {
		return nil, ErrInvalidKey
	}

	// Mix PSK: SHA256(DH_shared || PSK)
	if len(psk) > 0 {
		h := sha256.New()
		h.Write(shared[:])
		h.Write(psk)
		return h.Sum(nil), nil
	}

	return shared[:], nil
}

type Cipher struct {
	aeadSend  cipher.AEAD
	aeadRecv  cipher.AEAD
	nonceSend uint64
	recvHigh  uint64
	recvMask  uint64
	recvMu    sync.Mutex
}

func deriveKey(secret []byte, label string) []byte {
	h := sha256.New()
	h.Write(secret)
	h.Write([]byte(label))
	return h.Sum(nil)
}

// NewCipher creates a directional cipher pair from a shared secret.
// isServer determines which derived key is used for send vs recv.
func NewCipher(sharedSecret []byte, isServer bool) (*Cipher, error) {
	if len(sharedSecret) != KeySize {
		return nil, ErrInvalidKey
	}

	c2sKey := deriveKey(sharedSecret, "c2s")
	s2cKey := deriveKey(sharedSecret, "s2c")

	var sendKey, recvKey []byte
	if isServer {
		sendKey, recvKey = s2cKey, c2sKey
	} else {
		sendKey, recvKey = c2sKey, s2cKey
	}

	aeadSend, err := chacha20poly1305.New(sendKey)
	if err != nil {
		return nil, err
	}
	aeadRecv, err := chacha20poly1305.New(recvKey)
	if err != nil {
		return nil, err
	}

	return &Cipher{aeadSend: aeadSend, aeadRecv: aeadRecv}, nil
}

// [8-byte nonce][ciphertext+tag]
func (c *Cipher) Encrypt(plaintext []byte) []byte {
	nonceVal := atomic.AddUint64(&c.nonceSend, 1)

	nonce := make([]byte, NonceSize)
	binary.LittleEndian.PutUint64(nonce, nonceVal)

	output := make([]byte, 8+len(plaintext)+OverheadSize)
	binary.LittleEndian.PutUint64(output[:8], nonceVal)

	c.aeadSend.Seal(output[8:8], nonce, plaintext, nil)
	return output
}

func (c *Cipher) Decrypt(ciphertext []byte) ([]byte, error) {
	if len(ciphertext) < 8+OverheadSize {
		return nil, ErrDecryptFailed
	}

	nonceVal := binary.LittleEndian.Uint64(ciphertext[:8])
	c.recvMu.Lock()
	defer c.recvMu.Unlock()

	// Fast reject replay/too-old nonces while allowing limited out-of-order packets.
	if c.recvHigh > 0 && nonceVal <= c.recvHigh {
		diff := c.recvHigh - nonceVal
		if diff >= replayWindow {
			return nil, ErrReplayDetected
		}
		if c.recvMask&(uint64(1)<<diff) != 0 {
			return nil, ErrReplayDetected
		}
	}

	if nonceVal == 0 {
		return nil, ErrReplayDetected
	}

	nonce := make([]byte, NonceSize)
	binary.LittleEndian.PutUint64(nonce, nonceVal)

	plaintext, err := c.aeadRecv.Open(nil, nonce, ciphertext[8:], nil)
	if err != nil {
		return nil, ErrDecryptFailed
	}

	// Mark nonce as seen only after successful authentication.
	if c.recvHigh == 0 {
		c.recvHigh = nonceVal
		c.recvMask = 1
	} else if nonceVal > c.recvHigh {
		shift := nonceVal - c.recvHigh
		if shift >= replayWindow {
			c.recvMask = 1
		} else {
			c.recvMask = (c.recvMask << shift) | 1
		}
		c.recvHigh = nonceVal
	} else {
		diff := c.recvHigh - nonceVal
		c.recvMask |= uint64(1) << diff
	}

	return plaintext, nil
}

func EncryptedOverhead() int {
	return 8 + OverheadSize
}

var VerifyToken = []byte("VPN_KEY_VERIFY_OK")
