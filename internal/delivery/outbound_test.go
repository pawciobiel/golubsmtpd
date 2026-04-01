package delivery

import (
	"bufio"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/google/go-cmp/cmp"
	"github.com/pawciobiel/golubsmtpd/internal/config"
)

// defaultTestCfg returns an OutboundDeliveryConfig with short timeouts for tests.
func defaultTestCfg() *config.OutboundDeliveryConfig {
	return &config.OutboundDeliveryConfig{
		Timeouts: config.OutboundTimeouts{
			Dial:         2 * time.Second,
			Greeting:     2 * time.Second,
			Command:      2 * time.Second,
			TLSHandshake: 2 * time.Second,
			DataTransfer: 5 * time.Second,
		},
		TLS: config.OutboundTLSConfig{
			Policy:     "opportunistic",
			MinVersion: "tls12",
			SkipVerify: false,
		},
	}
}

// --- readSMTPResponse unit tests ---

func TestReadSMTPResponse_SingleLine(t *testing.T) {
	input := "220 mail.example.com ESMTP ready\r\n"
	r := bufio.NewReader(strings.NewReader(input))

	code, lines, err := readSMTPResponse(r, maxResponseContinuations)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != 220 {
		t.Errorf("want code 220, got %d", code)
	}
	if diff := cmp.Diff([]string{"mail.example.com ESMTP ready"}, lines); diff != "" {
		t.Errorf("lines mismatch (-want +got):\n%s", diff)
	}
}

func TestReadSMTPResponse_MultiLine(t *testing.T) {
	input := "250-mail.example.com Hello\r\n250-SIZE 10240000\r\n250-STARTTLS\r\n250 OK\r\n"
	r := bufio.NewReader(strings.NewReader(input))

	code, lines, err := readSMTPResponse(r, maxResponseContinuations)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if code != 250 {
		t.Errorf("want code 250, got %d", code)
	}
	want := []string{"mail.example.com Hello", "SIZE 10240000", "STARTTLS", "OK"}
	if diff := cmp.Diff(want, lines); diff != "" {
		t.Errorf("lines mismatch (-want +got):\n%s", diff)
	}
}

func TestReadSMTPResponse_LineTooLong(t *testing.T) {
	// Craft a line of 511 payload bytes + "220 " prefix + CRLF = 517 bytes total
	longMsg := strings.Repeat("A", maxResponseLineBytes+1)
	input := "220 " + longMsg + "\r\n"
	r := bufio.NewReaderSize(strings.NewReader(input), maxResponseLineBytes+2)

	_, _, err := readSMTPResponse(r, maxResponseContinuations)
	if err == nil {
		t.Error("expected error for line exceeding maxResponseLineBytes, got nil")
	}
}

func TestReadSMTPResponse_TooManyContinuations(t *testing.T) {
	var sb strings.Builder
	// Write maxResponseContinuations+1 continuation lines then a final line
	for i := 0; i <= maxResponseContinuations; i++ {
		sb.WriteString(fmt.Sprintf("250-line%d\r\n", i))
	}
	sb.WriteString("250 done\r\n")
	r := bufio.NewReader(strings.NewReader(sb.String()))

	_, _, err := readSMTPResponse(r, maxResponseContinuations)
	if err == nil {
		t.Error("expected error for too many continuation lines, got nil")
	}
}

func TestReadSMTPResponse_EmbeddedCRInMessage(t *testing.T) {
	input := "220 hello\rworld\r\n"
	r := bufio.NewReader(strings.NewReader(input))

	_, _, err := readSMTPResponse(r, maxResponseContinuations)
	if err == nil {
		t.Error("expected error for embedded CR in response message, got nil")
	}
}

func TestReadSMTPResponse_MalformedCode(t *testing.T) {
	input := "XYZ hello\r\n"
	r := bufio.NewReader(strings.NewReader(input))

	_, _, err := readSMTPResponse(r, maxResponseContinuations)
	if err == nil {
		t.Error("expected error for non-numeric SMTP code, got nil")
	}
}

func TestReadSMTPResponse_InvalidSeparator(t *testing.T) {
	// Code followed by something other than space or hyphen
	input := "220/hello world\r\n"
	r := bufio.NewReader(strings.NewReader(input))

	_, _, err := readSMTPResponse(r, maxResponseContinuations)
	if err == nil {
		t.Error("expected error for invalid separator, got nil")
	}
}

func TestReadSMTPResponse_LineTooShort(t *testing.T) {
	input := "220\r\n"
	r := bufio.NewReader(strings.NewReader(input))

	_, _, err := readSMTPResponse(r, maxResponseContinuations)
	if err == nil {
		t.Error("expected error for line shorter than 4 chars, got nil")
	}
}

// --- ehloAdvertisesSTARTTLS tests ---

func TestEhloAdvertisesSTARTTLS(t *testing.T) {
	cases := []struct {
		lines []string
		want  bool
	}{
		{[]string{"mail.example.com Hello", "SIZE 10240000", "STARTTLS", "OK"}, true},
		{[]string{"mail.example.com Hello", "starttls", "OK"}, true}, // case-insensitive
		{[]string{"mail.example.com Hello", "SIZE 10240000", "OK"}, false},
		{[]string{}, false},
	}
	for _, tc := range cases {
		got := ehloAdvertisesSTARTTLS(tc.lines)
		if got != tc.want {
			t.Errorf("ehloAdvertisesSTARTTLS(%v) = %v, want %v", tc.lines, got, tc.want)
		}
	}
}

// --- dialMX integration tests using net.Pipe ---

// fakeMTA runs a scripted fake MTA on one end of a net.Pipe.
// script is a slice of func(conn net.Conn) steps executed sequentially.
type fakeMTA struct {
	steps []func(conn net.Conn)
}

func (f *fakeMTA) run(conn net.Conn) {
	defer conn.Close()
	for _, step := range f.steps {
		step(conn)
	}
}

func writeLines(conn net.Conn, lines ...string) {
	for _, l := range lines {
		conn.Write([]byte(l + "\r\n")) //nolint:errcheck
	}
}

func readLine(conn net.Conn) string {
	buf := make([]byte, 512)
	n, _ := conn.Read(buf)
	return strings.TrimRight(string(buf[:n]), "\r\n")
}

// dialMXWithConn bypasses DNS/TCP dial and feeds an existing net.Conn directly
// into the dialMX logic for testing. We test via net.Pipe by calling dialMX's
// internal steps manually instead of the full function (which dials TCP port 25).
// Instead we test the core parsing/handshake via runDialLogic which does the
// greeting+EHLO+STARTTLS negotiation on a given conn.
func runDialLogic(conn net.Conn, cfg *config.OutboundDeliveryConfig) (*bufio.Reader, bool, error) {
	r := bufio.NewReaderSize(conn, maxResponseLineBytes+2)

	// Read greeting
	if err := conn.SetDeadline(time.Now().Add(cfg.Timeouts.Greeting)); err != nil {
		return nil, false, err
	}
	if _, _, err := readSMTPResponse(r, maxResponseContinuations); err != nil {
		return nil, false, fmt.Errorf("greeting read failed: %w", err)
	}
	conn.SetDeadline(time.Time{}) //nolint:errcheck

	// EHLO
	if err := conn.SetDeadline(time.Now().Add(cfg.Timeouts.Command)); err != nil {
		return nil, false, err
	}
	fmt.Fprintf(conn, "EHLO golubsmtpd\r\n") //nolint:errcheck
	_, ehloLines, err := readSMTPResponse(r, maxResponseContinuations)
	if err != nil {
		return nil, false, fmt.Errorf("EHLO failed: %w", err)
	}
	conn.SetDeadline(time.Time{}) //nolint:errcheck

	starttlsAdvertised := ehloAdvertisesSTARTTLS(ehloLines)

	if !starttlsAdvertised {
		if cfg.TLS.Policy == "required" {
			return nil, false, errSTARTTLSRequired
		}
		return r, false, nil
	}

	// Send STARTTLS
	if err := conn.SetDeadline(time.Now().Add(cfg.Timeouts.Command)); err != nil {
		return nil, false, err
	}
	fmt.Fprintf(conn, "STARTTLS\r\n") //nolint:errcheck
	code, _, err := readSMTPResponse(r, maxResponseContinuations)
	conn.SetDeadline(time.Time{}) //nolint:errcheck
	if err != nil {
		return nil, false, err
	}
	if code != 220 {
		return nil, false, errSTARTTLSFailed
	}

	// In tests we don't do the actual TLS handshake since net.Pipe won't have certs.
	// Return success with plain=true for pipe-based tests.
	return r, true, nil
}

func TestDialLogic_PlainOpportunistic(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	go func() {
		defer server.Close()
		writeLines(server, "220 mail.example.com ESMTP")
		readLine(server) // consume EHLO
		writeLines(server,
			"250-mail.example.com Hello",
			"250 OK",
		)
	}()

	cfg := defaultTestCfg()
	cfg.TLS.Policy = "opportunistic"

	r, tlsActive, err := runDialLogic(client, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tlsActive {
		t.Error("expected tlsActive=false for no-STARTTLS opportunistic")
	}
	if r == nil {
		t.Error("expected non-nil reader")
	}
}

func TestDialLogic_RequiredPolicyNoSTARTTLS(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	go func() {
		defer server.Close()
		writeLines(server, "220 mail.example.com ESMTP")
		readLine(server) // consume EHLO
		writeLines(server,
			"250-mail.example.com Hello",
			"250 OK",
		)
	}()

	cfg := defaultTestCfg()
	cfg.TLS.Policy = "required"

	_, _, err := runDialLogic(client, cfg)
	if err == nil {
		t.Fatal("expected errSTARTTLSRequired, got nil")
	}
	if err != errSTARTTLSRequired {
		t.Errorf("want errSTARTTLSRequired, got: %v", err)
	}
}

func TestDialLogic_STARTTLSAdvertisedThenRejected(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	go func() {
		defer server.Close()
		writeLines(server, "220 mail.example.com ESMTP")
		readLine(server) // consume EHLO
		writeLines(server,
			"250-mail.example.com Hello",
			"250-STARTTLS",
			"250 OK",
		)
		readLine(server) // consume STARTTLS command
		writeLines(server, "503 TLS not available")
	}()

	cfg := defaultTestCfg()
	cfg.TLS.Policy = "opportunistic" // even opportunistic should fail on advertised-then-rejected

	_, _, err := runDialLogic(client, cfg)
	if err == nil {
		t.Fatal("expected errSTARTTLSFailed, got nil")
	}
	if err != errSTARTTLSFailed {
		t.Errorf("want errSTARTTLSFailed, got: %v", err)
	}
}

func TestDialLogic_RequiredPolicySTARTTLSAdvertisedThenRejected(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	go func() {
		defer server.Close()
		writeLines(server, "220 mail.example.com ESMTP")
		readLine(server) // consume EHLO
		writeLines(server,
			"250-mail.example.com Hello",
			"250-STARTTLS",
			"250 OK",
		)
		readLine(server) // consume STARTTLS command
		writeLines(server, "503 TLS not available")
	}()

	cfg := defaultTestCfg()
	cfg.TLS.Policy = "required"

	_, _, err := runDialLogic(client, cfg)
	if err == nil {
		t.Fatal("expected errSTARTTLSFailed, got nil")
	}
	if err != errSTARTTLSFailed {
		t.Errorf("want errSTARTTLSFailed, got: %v", err)
	}
}

func TestDialLogic_STARTTLSSucceeds(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	go func() {
		defer server.Close()
		writeLines(server, "220 mail.example.com ESMTP")
		readLine(server) // consume EHLO
		writeLines(server,
			"250-mail.example.com Hello",
			"250-STARTTLS",
			"250 OK",
		)
		readLine(server) // consume STARTTLS command
		writeLines(server, "220 Ready to start TLS")
		// In real life TLS handshake would happen here.
		// Test stops here — we just verify code 220 is accepted.
	}()

	cfg := defaultTestCfg()

	_, tlsActive, err := runDialLogic(client, cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !tlsActive {
		t.Error("expected tlsActive=true after STARTTLS 220")
	}
}

func TestDialLogic_SlowGreeting_Timeout(t *testing.T) {
	client, server := net.Pipe()
	defer client.Close()

	go func() {
		defer server.Close()
		// Write banner one byte at a time with delays to simulate slow MTA
		banner := "220 slow.example.com ESMTP\r\n"
		for _, b := range []byte(banner) {
			time.Sleep(50 * time.Millisecond)
			server.Write([]byte{b}) //nolint:errcheck
		}
	}()

	cfg := defaultTestCfg()
	cfg.Timeouts.Greeting = 100 * time.Millisecond // shorter than the drip delay

	_, _, err := runDialLogic(client, cfg)
	if err == nil {
		t.Error("expected timeout error for slow banner drip, got nil")
	}
}

func TestReadSMTPResponse_MismatchedCodes(t *testing.T) {
	// Multi-line response where second line has different code
	input := "250-first\r\n251-second\r\n250 done\r\n"
	r := bufio.NewReader(strings.NewReader(input))

	_, _, err := readSMTPResponse(r, maxResponseContinuations)
	if err == nil {
		t.Error("expected error for mismatched codes in multi-line response, got nil")
	}
}
