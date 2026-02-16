package packet

import (
	"encoding/binary"
	"net"
)

func ParseIPv4(data []byte) (*IPv4Header, error) {
	if len(data) < IPv4HeaderLen {
		return nil, ErrPacketTooShort
	}

	version := data[0] >> 4
	if version != 4 {
		return nil, ErrInvalidVersion
	}

	ihl := data[0] & 0x0F
	flagsAndOffset := binary.BigEndian.Uint16(data[6:8])

	return &IPv4Header{
		Version:    version,
		IHL:        ihl,
		TOS:        data[1],
		TotalLen:   binary.BigEndian.Uint16(data[2:4]),
		ID:         binary.BigEndian.Uint16(data[4:6]),
		Flags:      uint8(flagsAndOffset >> 13),
		FragOffset: flagsAndOffset & 0x1FFF,
		TTL:        data[8],
		Protocol:   data[9],
		Checksum:   binary.BigEndian.Uint16(data[10:12]),
		SrcIP:      net.IP(data[12:16]),
		DstIP:      net.IP(data[16:20]),
	}, nil
}

func ParseTCP(data []byte) (*TCPHeader, error) {
	if len(data) < TCPHeaderLen {
		return nil, ErrPacketTooShort
	}

	offsetAndFlags := binary.BigEndian.Uint16(data[12:14])

	return &TCPHeader{
		SrcPort:    binary.BigEndian.Uint16(data[0:2]),
		DstPort:    binary.BigEndian.Uint16(data[2:4]),
		Seq:        binary.BigEndian.Uint32(data[4:8]),
		Ack:        binary.BigEndian.Uint32(data[8:12]),
		DataOffset: uint8(offsetAndFlags>>12) & 0x0F,
		Flags:      uint8(offsetAndFlags) & 0x3F,
		Window:     binary.BigEndian.Uint16(data[14:16]),
		Checksum:   binary.BigEndian.Uint16(data[16:18]),
		Urgent:     binary.BigEndian.Uint16(data[18:20]),
	}, nil
}

func ValidatePacket(packet []byte, mtu int) error {
	if len(packet) < IPv4HeaderLen {
		return ErrPacketTooShort
	}

	version := GetIPVersion(packet)
	if version == IPv6Version {
		return ErrIPv6NotSupport
	}
	if version != IPv4Version {
		return ErrInvalidVersion
	}

	ihl := int(packet[0]&0x0F) * 4
	if ihl < IPv4HeaderLen || ihl > len(packet) {
		return ErrMalformedPacket
	}

	totalLen := int(packet[2])<<8 | int(packet[3])
	if totalLen < ihl || totalLen > len(packet) {
		return ErrMalformedPacket
	}

	flagsAndOffset := binary.BigEndian.Uint16(packet[6:8])
	if flagsAndOffset&0x2000 != 0 || flagsAndOffset&0x1FFF != 0 {
		return ErrIPv4Fragmented
	}

	expectedCsum := binary.BigEndian.Uint16(packet[10:12])
	header := make([]byte, ihl)
	copy(header, packet[:ihl])
	header[10] = 0
	header[11] = 0
	if Checksum(header) != expectedCsum {
		return ErrInvalidChecksum
	}

	if mtu > 0 && totalLen > mtu {
		return ErrPacketTooLarge
	}

	return nil
}

func GetTotalLength(packet []byte) int {
	if len(packet) < 4 {
		return 0
	}
	return int(packet[2])<<8 | int(packet[3])
}

func GetProtocol(packet []byte) uint8 {
	if len(packet) < 10 {
		return 0
	}
	return packet[9]
}

func GetSrcIP(packet []byte) net.IP {
	if len(packet) < 16 {
		return nil
	}
	return net.IP(packet[12:16])
}

func GetDstIP(packet []byte) net.IP {
	if len(packet) < 20 {
		return nil
	}
	return net.IP(packet[16:20])
}
