package packet

import (
	"encoding/binary"
	"net"
)

func RewriteSrcIP(packet []byte, newSrc net.IP) []byte {
	if len(packet) < IPv4HeaderLen {
		return packet
	}

	ihl := int(packet[0]&0x0F) * 4
	if ihl < IPv4HeaderLen || ihl > len(packet) {
		return packet
	}

	copy(packet[12:16], newSrc.To4())

	binary.BigEndian.PutUint16(packet[10:12], 0)
	binary.BigEndian.PutUint16(packet[10:12], Checksum(packet[:ihl]))
	proto := packet[9]

	if proto == ProtoTCP && len(packet) >= ihl+TCPHeaderLen {
		recalcTCPChecksum(packet, ihl)
	} else if proto == ProtoUDP && len(packet) >= ihl+UDPHeaderLen {
		binary.BigEndian.PutUint16(packet[ihl+6:ihl+8], 0)
	}

	return packet
}

func RewriteDstIP(packet []byte, newDst net.IP) []byte {
	if len(packet) < IPv4HeaderLen {
		return packet
	}

	ihl := int(packet[0]&0x0F) * 4
	if ihl < IPv4HeaderLen || ihl > len(packet) {
		return packet
	}

	copy(packet[16:20], newDst.To4())

	binary.BigEndian.PutUint16(packet[10:12], 0)
	binary.BigEndian.PutUint16(packet[10:12], Checksum(packet[:ihl]))
	proto := packet[9]

	if proto == ProtoTCP && len(packet) >= ihl+TCPHeaderLen {
		recalcTCPChecksum(packet, ihl)
	} else if proto == ProtoUDP && len(packet) >= ihl+UDPHeaderLen {
		binary.BigEndian.PutUint16(packet[ihl+6:ihl+8], 0)
	} else if proto == ProtoICMP && len(packet) >= ihl+8 {
		binary.BigEndian.PutUint16(packet[ihl+2:ihl+4], 0)
		icmpCsum := Checksum(packet[ihl:])
		binary.BigEndian.PutUint16(packet[ihl+2:ihl+4], icmpCsum)
	}

	return packet
}

func recalcTCPChecksum(packet []byte, ihl int) {
	binary.BigEndian.PutUint16(packet[ihl+16:ihl+18], 0)
	srcIP := net.IP(packet[12:16])
	dstIP := net.IP(packet[16:20])
	csum := TCPChecksum(srcIP, dstIP, packet[ihl:])
	binary.BigEndian.PutUint16(packet[ihl+16:ihl+18], csum)
}

func ClampMSS(packet []byte, maxMSS uint16) []byte {
	pktLen := len(packet)
	if pktLen < IPv4HeaderLen+TCPHeaderLen {
		return packet
	}

	if !IsIPv4(packet) || packet[9] != ProtoTCP {
		return packet
	}

	ihl := int(packet[0]&0x0F) * 4
	if ihl < IPv4HeaderLen || ihl > pktLen {
		return packet
	}

	tcpStart := ihl
	if tcpStart+TCPHeaderLen > pktLen {
		return packet
	}

	flags := packet[tcpStart+13]
	if flags&TCPFlagSYN == 0 {
		return packet
	}

	dataOffset := int(packet[tcpStart+12]>>4) * 4
	if dataOffset <= TCPHeaderLen || tcpStart+dataOffset > pktLen {
		return packet
	}

	modified := false
	i := tcpStart + TCPHeaderLen
	optEnd := tcpStart + dataOffset

	for i < optEnd && i < pktLen {
		kind := packet[i]
		switch kind {
		case 0: // End
			i = optEnd
		case 1: // NOP
			i++
		case 2: // MSS
			if i+4 <= optEnd && i+4 <= pktLen {
				currentMSS := binary.BigEndian.Uint16(packet[i+2 : i+4])
				if currentMSS > maxMSS {
					binary.BigEndian.PutUint16(packet[i+2:i+4], maxMSS)
					modified = true
				}
			}
			i += 4
		default:
			if i+1 < optEnd && i+1 < pktLen && packet[i+1] >= 2 {
				i += int(packet[i+1])
			} else {
				i = optEnd
			}
		}
	}

	if modified {
		recalcTCPChecksum(packet, ihl)
	}

	return packet
}
