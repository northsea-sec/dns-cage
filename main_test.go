package main

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"
)

func dnsQuery(domain string) []byte {
	return dnsQueryWith(domain, 0xbeef, 0x0100, 1, 1)
}

func dnsQueryWith(domain string, id, flags, qtype, qclass uint16) []byte {
	query := make([]byte, 12)
	binary.BigEndian.PutUint16(query[0:2], id)
	binary.BigEndian.PutUint16(query[2:4], flags)
	binary.BigEndian.PutUint16(query[4:6], 1)

	for _, label := range strings.Split(domain, ".") {
		query = append(query, byte(len(label)))
		query = append(query, label...)
	}
	query = append(query, 0, 0, 0, 0, 0)
	binary.BigEndian.PutUint16(query[len(query)-4:len(query)-2], qtype)
	binary.BigEndian.PutUint16(query[len(query)-2:], qclass)
	return query
}

func cloneBytes(value []byte) []byte {
	return append([]byte(nil), value...)
}

func responseError(query, response []byte, wantRCode uint16) error {
	if len(response) != len(query) {
		return fmt.Errorf("response length = %d, want %d", len(response), len(query))
	}
	if binary.BigEndian.Uint16(response[0:2]) != binary.BigEndian.Uint16(query[0:2]) {
		return fmt.Errorf("transaction ID changed")
	}

	requestFlags := binary.BigEndian.Uint16(query[2:4])
	wantFlags := uint16(0x8000) | requestFlags&0x0100 | wantRCode
	if got := binary.BigEndian.Uint16(response[2:4]); got != wantFlags {
		return fmt.Errorf("response flags = %#04x, want %#04x", got, wantFlags)
	}
	if got := binary.BigEndian.Uint16(response[4:6]); got != 1 {
		return fmt.Errorf("QDCOUNT = %d, want 1", got)
	}
	for _, countOffset := range []int{6, 8, 10} {
		if got := binary.BigEndian.Uint16(response[countOffset : countOffset+2]); got != 0 {
			return fmt.Errorf("response count at offset %d = %d, want 0", countOffset, got)
		}
	}
	if !bytes.Equal(response[12:], query[12:]) {
		return fmt.Errorf("question bytes changed")
	}
	return nil
}

func requireResponse(t *testing.T, query, response []byte, wantRCode uint16) {
	t.Helper()
	if err := responseError(query, response, wantRCode); err != nil {
		t.Fatal(err)
	}
}

func TestProcessQueryPolicyAndResponseHeader(t *testing.T) {
	for index, domain := range allowedDomains {
		query := dnsQueryWith(strings.ToUpper(domain), uint16(index+1), 0x0100, 1, 1)
		response := processQuery(query)
		if response == nil {
			t.Fatalf("provider %q returned no response", domain)
		}
		requireResponse(t, query, response, 5)
	}

	query := dnsQueryWith("example.test", 0xcafe, 0, 28, 1)
	response := processQuery(query)
	if response == nil {
		t.Fatal("non-provider returned no response")
	}
	requireResponse(t, query, response, 3)
}

func TestProcessQueryRejectsMalformedInput(t *testing.T) {
	valid := dnsQuery("example.test")

	responsePacket := cloneBytes(valid)
	binary.BigEndian.PutUint16(responsePacket[2:4], 0x8100)

	unsupportedOpcode := cloneBytes(valid)
	binary.BigEndian.PutUint16(unsupportedOpcode[2:4], 0x0900)

	noQuestions := cloneBytes(valid)
	binary.BigEndian.PutUint16(noQuestions[4:6], 0)

	twoQuestions := cloneBytes(valid)
	binary.BigEndian.PutUint16(twoQuestions[4:6], 2)

	answerCount := cloneBytes(valid)
	binary.BigEndian.PutUint16(answerCount[6:8], 1)

	authorityCount := cloneBytes(valid)
	binary.BigEndian.PutUint16(authorityCount[8:10], 1)

	additionalCount := cloneBytes(valid)
	binary.BigEndian.PutUint16(additionalCount[10:12], 1)

	compressedName := append(cloneBytes(valid[:12]), 0xc0, 0x0c, 0, 1, 0, 1)

	oversizedLabel := cloneBytes(valid)
	oversizedLabel[12] = 64

	unterminatedName := append(cloneBytes(valid[:12]), 3, 'b', 'a', 'd')

	missingClass := cloneBytes(valid[:len(valid)-2])

	zeroType := cloneBytes(valid)
	binary.BigEndian.PutUint16(zeroType[len(zeroType)-4:len(zeroType)-2], 0)

	nonInternetClass := cloneBytes(valid)
	binary.BigEndian.PutUint16(nonInternetClass[len(nonInternetClass)-2:], 3)

	trailingData := append(cloneBytes(valid), 0)

	emptyRoot := append(cloneBytes(valid[:12]), 0, 0, 1, 0, 1)

	tooLongName := dnsQuery(strings.Join([]string{
		strings.Repeat("a", 63),
		strings.Repeat("b", 63),
		strings.Repeat("c", 63),
		strings.Repeat("d", 62),
	}, "."))

	tests := map[string][]byte{
		"short header":        {0, 1, 2},
		"response packet":     responsePacket,
		"unsupported opcode":  unsupportedOpcode,
		"zero questions":      noQuestions,
		"multiple questions":  twoQuestions,
		"answer count":        answerCount,
		"authority count":     authorityCount,
		"additional count":    additionalCount,
		"compressed name":     compressedName,
		"oversized label":     oversizedLabel,
		"unterminated name":   unterminatedName,
		"missing class":       missingClass,
		"zero query type":     zeroType,
		"non-IN class":        nonInternetClass,
		"trailing data":       trailingData,
		"empty root name":     emptyRoot,
		"name over 255 bytes": tooLongName,
	}

	for name, query := range tests {
		t.Run(name, func(t *testing.T) {
			if response := processQuery(query); response != nil {
				t.Fatalf("malformed query returned a response: %x", response)
			}
		})
	}
}

func TestParseQuestionAcceptsMaximumLengthName(t *testing.T) {
	domain := strings.Join([]string{
		strings.Repeat("a", 63),
		strings.Repeat("b", 63),
		strings.Repeat("c", 63),
		strings.Repeat("d", 61),
	}, ".")
	question, ok := parseQuestion(dnsQuery(domain))
	if !ok {
		t.Fatal("255-byte wire-format name was rejected")
	}
	if question.domain != domain {
		t.Fatalf("domain = %q, want %q", question.domain, domain)
	}
}

func TestConfiguredBindAddress(t *testing.T) {
	tests := []struct {
		name    string
		value   string
		want    string
		wantErr bool
	}{
		{name: "default", value: "", want: defaultBindAddr},
		{name: "IPv4 loopback", value: "127.0.0.1:15353", want: "127.0.0.1:15353"},
		{name: "IPv6 loopback", value: "[::1]:15353", want: "[::1]:15353"},
		{name: "non-loopback", value: "0.0.0.0:15353", wantErr: true},
		{name: "hostname", value: "localhost:15353", wantErr: true},
		{name: "zero port", value: "127.0.0.1:0", wantErr: true},
		{name: "missing port", value: "127.0.0.1", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Setenv(bindAddressEnv, test.value)
			got, err := configuredBindAddress()
			if test.wantErr {
				if err == nil {
					t.Fatalf("configuredBindAddress() = %q, want error", got)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if got != test.want {
				t.Fatalf("configuredBindAddress() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestServeUDPConcurrentQueries(t *testing.T) {
	server, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.ParseIP("127.0.0.1")})
	if err != nil {
		t.Fatal(err)
	}
	serveDone := make(chan error, 1)
	go func() {
		serveDone <- serveUDP(server)
	}()

	const queryCount = 64
	errCh := make(chan error, queryCount)
	var group sync.WaitGroup
	for index := range queryCount {
		group.Add(1)
		go func() {
			defer group.Done()
			client, err := net.DialUDP("udp", nil, server.LocalAddr().(*net.UDPAddr))
			if err != nil {
				errCh <- err
				return
			}
			defer client.Close()

			domain := fmt.Sprintf("query-%d.example.test", index)
			wantRCode := uint16(3)
			if index%2 == 0 {
				domain = "api.openai.com"
				wantRCode = 5
			}
			query := dnsQueryWith(domain, uint16(index+1), 0x0100, 1, 1)
			if err := client.SetDeadline(time.Now().Add(3 * time.Second)); err != nil {
				errCh <- err
				return
			}
			if _, err := client.Write(query); err != nil {
				errCh <- err
				return
			}
			response := make([]byte, maxDNSMessageSize)
			n, err := client.Read(response)
			if err != nil {
				errCh <- err
				return
			}
			if err := responseError(query, response[:n], wantRCode); err != nil {
				errCh <- fmt.Errorf("query %d: %w", index, err)
			}
		}()
	}
	group.Wait()
	close(errCh)
	for err := range errCh {
		t.Error(err)
	}

	if err := server.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-serveDone:
		if !errors.Is(err, net.ErrClosed) {
			t.Fatalf("serveUDP stopped with %v, want net.ErrClosed", err)
		}
	case <-time.After(time.Second):
		t.Fatal("serveUDP did not stop after closing its listener")
	}
}

func TestHandleTCPServesMultipleFrames(t *testing.T) {
	server, client := net.Pipe()
	done := make(chan struct{})
	go func() {
		handleTCP(server)
		close(done)
	}()

	queries := []struct {
		query     []byte
		wantRCode uint16
	}{
		{query: dnsQueryWith("api.openai.com", 10, 0x0100, 1, 1), wantRCode: 5},
		{query: dnsQueryWith("example.test", 11, 0, 28, 1), wantRCode: 3},
	}
	for _, test := range queries {
		frame := make([]byte, 2+len(test.query))
		binary.BigEndian.PutUint16(frame[:2], uint16(len(test.query)))
		copy(frame[2:], test.query)
		if err := writeAll(client, frame); err != nil {
			t.Fatal(err)
		}

		var length [2]byte
		if _, err := io.ReadFull(client, length[:]); err != nil {
			t.Fatal(err)
		}
		response := make([]byte, binary.BigEndian.Uint16(length[:]))
		if _, err := io.ReadFull(client, response); err != nil {
			t.Fatal(err)
		}
		requireResponse(t, test.query, response, test.wantRCode)
	}

	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("TCP handler did not exit")
	}
}

type shortWriter struct {
	bytes.Buffer
	max int
}

func (writer *shortWriter) Write(payload []byte) (int, error) {
	if len(payload) > writer.max {
		payload = payload[:writer.max]
	}
	return writer.Buffer.Write(payload)
}

type zeroWriter struct{}

func (zeroWriter) Write([]byte) (int, error) {
	return 0, nil
}

func TestWriteAllHandlesShortWrites(t *testing.T) {
	writer := &shortWriter{max: 3}
	payload := []byte("complete frame")
	if err := writeAll(writer, payload); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(writer.Bytes(), payload) {
		t.Fatalf("written payload = %q, want %q", writer.Bytes(), payload)
	}

	if err := writeAll(zeroWriter{}, payload); !errors.Is(err, io.ErrShortWrite) {
		t.Fatalf("zero-byte write error = %v, want io.ErrShortWrite", err)
	}
}
