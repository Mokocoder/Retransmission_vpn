package packet

import (
	"encoding/binary"
	"net"
	"sync/atomic"
)

var idCounter uint32

func randomID() uint16 {
	return uint16(atomic.AddUint32(&idCounter, 1))
}

type IPPacketBuilder struct {
	buf []byte
}

func NewIPPacketBuilder(size int) *IPPacketBuilder {
	return &IPPacketBuilder{
		buf: make([]byte, 0, size),
	}
}

func (b *IPPacketBuilder) BuildIPv4(srcIP, dstIP net.IP, proto uint8, payload []byte) []byte {
	totalLen := IPv4HeaderLen + len(payload)
	b.buf = b.buf[:totalLen]

	b.buf[0] = 0x45 // version=4, IHL=5
	b.buf[1] = 0    // TOS
	binary.BigEndian.PutUint16(b.buf[2:4], uint16(totalLen))
	binary.BigEndian.PutUint16(b.buf[4:6], uint16(randomID()))
	binary.BigEndian.PutUint16(b.buf[6:8], 0x4000) // Don't Fragment
	b.buf[8] = 64                                   // TTL
	b.buf[9] = proto
	binary.BigEndian.PutUint16(b.buf[10:12], 0) // checksum placeholder
	copy(b.buf[12:16], srcIP.To4())
	copy(b.buf[16:20], dstIP.To4())

	binary.BigEndian.PutUint16(b.buf[10:12], Checksum(b.buf[:IPv4HeaderLen]))

	copy(b.buf[IPv4HeaderLen:], payload)
	return b.buf
}

func BuildTCPHeader(srcPort, dstPort uint16, seq, ack uint32, flags uint8, payload []byte) []byte {
	tcpLen := TCPHeaderLen + len(payload)
	buf := make([]byte, tcpLen)

	binary.BigEndian.PutUint16(buf[0:2], srcPort)
	binary.BigEndian.PutUint16(buf[2:4], dstPort)
	binary.BigEndian.PutUint32(buf[4:8], seq)
	binary.BigEndian.PutUint32(buf[8:12], ack)
	binary.BigEndian.PutUint16(buf[12:14], uint16(5<<12)|uint16(flags)) // offset=5, flags
	binary.BigEndian.PutUint16(buf[14:16], 65535)                       // window
	binary.BigEndian.PutUint16(buf[16:18], 0)                           // checksum placeholder
	binary.BigEndian.PutUint16(buf[18:20], 0)                           // urgent

	copy(buf[TCPHeaderLen:], payload)
	return buf
}

func BuildTCPPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, seq, ack uint32, flags uint8, payload []byte) []byte {
	tcp := BuildTCPHeader(srcPort, dstPort, seq, ack, flags, payload)
	csum := TCPChecksum(srcIP, dstIP, tcp)
	binary.BigEndian.PutUint16(tcp[16:18], csum)

	builder := NewIPPacketBuilder(IPv4HeaderLen + len(tcp))
	return builder.BuildIPv4(srcIP, dstIP, ProtoTCP, tcp)
}
