package packet

import (
	"errors"
	"net"
)

const (
	IPv4HeaderLen = 20
	IPv6HeaderLen = 40
	TCPHeaderLen  = 20
	UDPHeaderLen  = 8
	ICMPHeaderLen = 8
	MaxPacketSize = 65535
	MinMTU        = 576

	ProtoICMP   = 1
	ProtoTCP    = 6
	ProtoUDP    = 17
	ProtoICMPv6 = 58

	IPv4Version = 4
	IPv6Version = 6
)

const (
	TCPFlagFIN = 0x01
	TCPFlagSYN = 0x02
	TCPFlagRST = 0x04
	TCPFlagPSH = 0x08
	TCPFlagACK = 0x10
)

var (
	ErrPacketTooShort  = errors.New("packet too short")
	ErrInvalidVersion  = errors.New("invalid IP version")
	ErrIPv6NotSupport  = errors.New("IPv6 not supported")
	ErrInvalidChecksum = errors.New("invalid IPv4 header checksum")
	ErrIPv4Fragmented  = errors.New("IPv4 fragments not supported")
	ErrPacketTooLarge  = errors.New("packet exceeds MTU")
	ErrMalformedPacket = errors.New("malformed packet")
)

type IPv4Header struct {
	Version    uint8
	IHL        uint8
	TOS        uint8
	TotalLen   uint16
	ID         uint16
	Flags      uint8
	FragOffset uint16
	TTL        uint8
	Protocol   uint8
	Checksum   uint16
	SrcIP      net.IP
	DstIP      net.IP
}

type TCPHeader struct {
	SrcPort    uint16
	DstPort    uint16
	Seq        uint32
	Ack        uint32
	DataOffset uint8
	Flags      uint8
	Window     uint16
	Checksum   uint16
	Urgent     uint16
}

func GetIPVersion(packet []byte) uint8 {
	if len(packet) < 1 {
		return 0
	}
	return packet[0] >> 4
}

func IsIPv4(packet []byte) bool {
	return GetIPVersion(packet) == IPv4Version
}

func IsIPv6(packet []byte) bool {
	return GetIPVersion(packet) == IPv6Version
}
