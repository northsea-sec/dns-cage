// DNS Cage is a loopback-only DNS policy responder.
//
// Built-in provider domains receive REFUSED so callers cannot resolve them
// directly instead of using the separately governed egress path. Every other
// valid standard query receives NXDOMAIN. DNS Cage never performs upstream
// resolution.
package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"os"
	"strings"
	"time"
)

const (
	bindAddressEnv    = "DNS_CAGE_BIND_ADDR"
	defaultBindAddr   = "127.0.0.1:53"
	maxDNSMessageSize = 4096
	connectionTimeout = 5 * time.Second
)

// allowedDomains is the built-in policy list. Matching is case-insensitive.
var allowedDomains = []string{
	"api.anthropic.com",
	"claude.ai",
	"api.openai.com",
	"chatgpt.com",
	"generativelanguage.googleapis.com",
	"gemini.google.com",
	"api.mistral.ai",
	"dashscope.aliyuncs.com",
	"openrouter.ai",
}

type dnsQuestion struct {
	domain      string
	qtype       uint16
	questionEnd int
}

func main() {
	bindAddr, err := configuredBindAddress()
	if err != nil {
		log.Fatalf("[DNS-CAGE] configuration: %v", err)
	}

	log.Printf("[DNS-CAGE] policy responder on %s (UDP+TCP)", bindAddr)
	log.Printf("[DNS-CAGE] built-in provider domains: %v", allowedDomains)
	log.Printf("[DNS-CAGE] policy: provider domains -> REFUSED, all others -> NXDOMAIN")

	if err := runServer(bindAddr); err != nil {
		log.Fatalf("[DNS-CAGE] server: %v", err)
	}
}

func configuredBindAddress() (string, error) {
	bindAddr := strings.TrimSpace(os.Getenv(bindAddressEnv))
	if bindAddr == "" {
		bindAddr = defaultBindAddr
	}

	addrPort, err := netip.ParseAddrPort(bindAddr)
	if err != nil {
		return "", fmt.Errorf("%s must be a literal IP address and port: %w", bindAddressEnv, err)
	}
	if !addrPort.Addr().IsLoopback() {
		return "", fmt.Errorf("%s must use a loopback IP address", bindAddressEnv)
	}
	if addrPort.Port() == 0 {
		return "", fmt.Errorf("%s must use a non-zero port", bindAddressEnv)
	}
	return addrPort.String(), nil
}

func runServer(bindAddr string) error {
	udpAddr, err := net.ResolveUDPAddr("udp", bindAddr)
	if err != nil {
		return fmt.Errorf("resolve UDP address: %w", err)
	}
	udpConn, err := net.ListenUDP("udp", udpAddr)
	if err != nil {
		return fmt.Errorf("listen UDP: %w", err)
	}
	defer udpConn.Close()

	tcpListener, err := net.Listen("tcp", bindAddr)
	if err != nil {
		return fmt.Errorf("listen TCP: %w", err)
	}
	defer tcpListener.Close()

	errCh := make(chan error, 2)
	go func() {
		errCh <- serveTCP(tcpListener)
	}()
	go func() {
		errCh <- serveUDP(udpConn)
	}()

	return <-errCh
}

func serveUDP(conn *net.UDPConn) error {
	buf := make([]byte, maxDNSMessageSize)
	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			return err
		}

		// Query processing is intentionally synchronous. It is bounded work and
		// keeps the reusable receive buffer owned by this loop.
		handleUDP(conn, addr, buf[:n])
	}
}

func serveTCP(listener net.Listener) error {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return err
		}
		go handleTCP(conn)
	}
}

func handleUDP(conn *net.UDPConn, addr *net.UDPAddr, query []byte) {
	resp := processQuery(query)
	if resp == nil {
		return
	}
	if _, err := conn.WriteToUDP(resp, addr); err != nil {
		log.Printf("[DNS-CAGE] UDP write to %s: %v", addr, err)
	}
}

func handleTCP(conn net.Conn) {
	defer conn.Close()

	for {
		if err := conn.SetDeadline(time.Now().Add(connectionTimeout)); err != nil {
			log.Printf("[DNS-CAGE] TCP deadline: %v", err)
			return
		}

		var lenBuf [2]byte
		if _, err := io.ReadFull(conn, lenBuf[:]); err != nil {
			if !errors.Is(err, io.EOF) && !errors.Is(err, io.ErrUnexpectedEOF) {
				if netErr, ok := err.(net.Error); !ok || !netErr.Timeout() {
					log.Printf("[DNS-CAGE] TCP frame length: %v", err)
				}
			}
			return
		}

		msgLen := int(binary.BigEndian.Uint16(lenBuf[:]))
		if msgLen < 12 || msgLen > maxDNSMessageSize {
			return
		}

		query := make([]byte, msgLen)
		if _, err := io.ReadFull(conn, query); err != nil {
			return
		}
		resp := processQuery(query)
		if resp == nil {
			continue
		}

		frame := make([]byte, 2+len(resp))
		binary.BigEndian.PutUint16(frame[:2], uint16(len(resp)))
		copy(frame[2:], resp)
		if err := writeAll(conn, frame); err != nil {
			log.Printf("[DNS-CAGE] TCP write: %v", err)
			return
		}
	}
}

func writeAll(writer io.Writer, payload []byte) error {
	for len(payload) > 0 {
		n, err := writer.Write(payload)
		if err != nil {
			return err
		}
		if n == 0 {
			return io.ErrShortWrite
		}
		payload = payload[n:]
	}
	return nil
}

// processQuery applies the complete DNS Cage policy to one standard question.
func processQuery(query []byte) []byte {
	question, ok := parseQuestion(query)
	if !ok {
		return nil
	}

	if isAllowed(question.domain) {
		log.Printf("[DNS-CAGE] REFUSED: %q (type=%d, direct_provider_dns_disabled)", question.domain, question.qtype)
		return buildResponse(query, question.questionEnd, 5)
	}

	log.Printf("[DNS-CAGE] BLOCKED: %q (type=%d)", question.domain, question.qtype)
	return buildResponse(query, question.questionEnd, 3)
}

func parseQuestion(query []byte) (dnsQuestion, bool) {
	if len(query) < 12 {
		return dnsQuestion{}, false
	}

	flags := binary.BigEndian.Uint16(query[2:4])
	if flags&0x8000 != 0 || flags&0x7800 != 0 {
		return dnsQuestion{}, false
	}
	if binary.BigEndian.Uint16(query[4:6]) != 1 ||
		binary.BigEndian.Uint16(query[6:8]) != 0 ||
		binary.BigEndian.Uint16(query[8:10]) != 0 ||
		binary.BigEndian.Uint16(query[10:12]) != 0 {
		return dnsQuestion{}, false
	}

	offset := 12
	nameWireLength := 1 // terminating root label
	labels := make([]string, 0, 4)
	for {
		if offset >= len(query) {
			return dnsQuestion{}, false
		}
		labelLen := int(query[offset])
		offset++
		if labelLen == 0 {
			break
		}
		if labelLen > 63 || offset+labelLen > len(query) || nameWireLength+1+labelLen > 255 {
			return dnsQuestion{}, false
		}
		nameWireLength += 1 + labelLen
		labels = append(labels, string(query[offset:offset+labelLen]))
		offset += labelLen
	}

	if len(labels) == 0 || offset+4 != len(query) {
		return dnsQuestion{}, false
	}
	qtype := binary.BigEndian.Uint16(query[offset : offset+2])
	qclass := binary.BigEndian.Uint16(query[offset+2 : offset+4])
	if qtype == 0 || qclass != 1 {
		return dnsQuestion{}, false
	}

	return dnsQuestion{
		domain:      strings.ToLower(strings.Join(labels, ".")),
		qtype:       qtype,
		questionEnd: offset + 4,
	}, true
}

func isAllowed(domain string) bool {
	domain = strings.TrimSuffix(strings.ToLower(domain), ".")
	for _, allowed := range allowedDomains {
		if domain == allowed {
			return true
		}
	}
	return false
}

func buildResponse(query []byte, questionEnd int, rcode uint16) []byte {
	resp := make([]byte, questionEnd)
	copy(resp, query[:questionEnd])

	requestFlags := binary.BigEndian.Uint16(query[2:4])
	responseFlags := uint16(0x8000) | requestFlags&0x0100 | rcode
	binary.BigEndian.PutUint16(resp[2:4], responseFlags)
	binary.BigEndian.PutUint16(resp[4:6], 1)
	binary.BigEndian.PutUint16(resp[6:8], 0)
	binary.BigEndian.PutUint16(resp[8:10], 0)
	binary.BigEndian.PutUint16(resp[10:12], 0)
	return resp
}
