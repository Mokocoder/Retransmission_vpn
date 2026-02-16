package transport

import (
	crand "crypto/rand"
	"encoding/binary"
	"errors"
)

var (
	ErrNotConnected = errors.New("transport: not connected")
	ErrTimeout      = errors.New("transport: connection timeout")
	ErrClosed       = errors.New("transport: connection closed")
	ErrKeyExchange  = errors.New("transport: key exchange failed")
)

// cryptoRandUint32 generates a cryptographically random uint32 in [base, base+rangeSize).
func cryptoRandUint32(base, rangeSize uint32) uint32 {
	var buf [4]byte
	crand.Read(buf[:])
	return base + binary.LittleEndian.Uint32(buf[:])%rangeSize
}

// cryptoRandUint16 generates a cryptographically random uint16 in [base, base+rangeSize).
func cryptoRandUint16(base, rangeSize uint16) uint16 {
	var buf [2]byte
	crand.Read(buf[:])
	return base + binary.LittleEndian.Uint16(buf[:])%rangeSize
}
