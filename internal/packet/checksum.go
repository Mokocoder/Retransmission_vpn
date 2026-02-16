package packet

import (
	"encoding/binary"
	"net"
)

func Checksum(data []byte) uint16 {
	var sum uint32

	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i : i+2]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}

	for sum > 0xFFFF {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}

	return ^uint16(sum)
}

func TCPChecksum(srcIP, dstIP net.IP, tcpData []byte) uint16 {
	pseudo := make([]byte, 12+len(tcpData))
	copy(pseudo[0:4], srcIP.To4())
	copy(pseudo[4:8], dstIP.To4())
	pseudo[8] = 0
	pseudo[9] = ProtoTCP
	binary.BigEndian.PutUint16(pseudo[10:12], uint16(len(tcpData)))
	copy(pseudo[12:], tcpData)
	pseudo[12+16] = 0
	pseudo[12+17] = 0

	return Checksum(pseudo)
}
