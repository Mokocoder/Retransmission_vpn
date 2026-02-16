//go:build linux

package transport

import (
	"fmt"
	"net"

	"retransmission-vpn/internal/crypto"
	"retransmission-vpn/internal/packet"
)

type RawSocket struct {
	conn    *net.IPConn
	localIP net.IP
	port    uint16
}

func NewRawSocket(port uint16) (*RawSocket, error) {
	localIP, err := getDefaultIP()
	if err != nil {
		return nil, err
	}

	conn, err := net.ListenIP("ip4:tcp", &net.IPAddr{IP: localIP})
	if err != nil {
		return nil, fmt.Errorf("listen raw: %w", err)
	}

	return &RawSocket{
		conn:    conn,
		localIP: localIP,
		port:    port,
	}, nil
}

func (r *RawSocket) ReadPacket(buf []byte) (int, net.IP, *packet.TCPHeader, []byte, error) {
	for {
		n, addr, err := r.conn.ReadFrom(buf)
		if err != nil {
			return 0, nil, nil, nil, err
		}

		if n < packet.TCPHeaderLen {
			continue
		}

		tcpHdr, err := packet.ParseTCP(buf[:n])
		if err != nil || tcpHdr.DstPort != r.port {
			continue
		}

		srcIP := addr.(*net.IPAddr).IP
		dataOffset := int(tcpHdr.DataOffset) * 4
		var payload []byte
		if dataOffset < n {
			payload = buf[dataOffset:n]
		}

		return n, srcIP, tcpHdr, payload, nil
	}
}

func (r *RawSocket) SendSYNACK(clientIP net.IP, clientPort uint16, clientSeq, serverSeq uint32) error {
	pkt := packet.BuildTCPPacket(
		r.localIP, clientIP,
		r.port, clientPort,
		serverSeq, clientSeq+1,
		packet.TCPFlagSYN|packet.TCPFlagACK,
		nil,
	)

	_, err := r.conn.WriteTo(pkt[packet.IPv4HeaderLen:], &net.IPAddr{IP: clientIP})
	return err
}

func (r *RawSocket) SendTo(session *Session, payload []byte, fakeRetrans bool) error {
	var dataToSend []byte
	if session.IsEncryptionReady() {
		dataToSend = session.Encrypt(payload)
	} else {
		dataToSend = payload
	}

	session.mu.Lock()
	seqToUse := session.ServerSeq
	if fakeRetrans && session.FirstSent {
		seqToUse = session.LastDataSeq
	} else {
		if !session.FirstSent {
			session.LastDataSeq = session.ServerSeq
			session.FirstSent = true
		}
	}
	clientAck := session.ClientSeq + 1
	clientIP := session.ClientIP
	clientPort := session.ClientPort
	session.mu.Unlock()

	pkt := packet.BuildTCPPacket(
		r.localIP, clientIP,
		r.port, clientPort,
		seqToUse, clientAck,
		packet.TCPFlagPSH|packet.TCPFlagACK,
		dataToSend,
	)

	_, err := r.conn.WriteTo(pkt[packet.IPv4HeaderLen:], &net.IPAddr{IP: clientIP})
	return err
}

func (r *RawSocket) SendKeyExchange(session *Session, serverPubKey []byte) error {
	session.mu.Lock()
	serverSeq := session.ServerSeq
	clientAck := session.ClientSeq + 1
	clientIP := session.ClientIP
	clientPort := session.ClientPort
	session.ServerSeq += uint32(len(serverPubKey))
	session.mu.Unlock()

	pkt := packet.BuildTCPPacket(
		r.localIP, clientIP,
		r.port, clientPort,
		serverSeq, clientAck,
		packet.TCPFlagPSH|packet.TCPFlagACK,
		serverPubKey,
	)

	_, err := r.conn.WriteTo(pkt[packet.IPv4HeaderLen:], &net.IPAddr{IP: clientIP})
	return err
}

func IsKeyExchangePacket(payload []byte) bool {
	return len(payload) == crypto.KeySize
}

func (r *RawSocket) LocalIP() net.IP {
	return r.localIP
}

func (r *RawSocket) Close() error {
	return r.conn.Close()
}

func getDefaultIP() (net.IP, error) {
	conn, err := net.Dial("udp4", "8.8.8.8:80")
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP, nil
}
