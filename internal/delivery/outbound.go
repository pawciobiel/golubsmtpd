package delivery

import (
	"bufio"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/textproto"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/pawciobiel/golubsmtpd/internal/config"
	"github.com/pawciobiel/golubsmtpd/internal/types"
)

const (
	// RFC 5321 §4.5.3.1: max SMTP reply line is 512 bytes including CRLF.
	// We strip CRLF before returning so limit the stripped line to 510.
	maxResponseLineBytes = 510

	// Cap on continuation lines in a multi-line SMTP response (e.g. EHLO extensions).
	// A legitimate MTA will never advertise more than ~20 extensions.
	maxResponseContinuations = 50

	outboundSMTPPort = "25"
)

var (
	errSTARTTLSRequired = errors.New("STARTTLS required but not advertised by remote MTA")
	errSTARTTLSFailed   = errors.New("STARTTLS advertised but rejected by remote MTA — possible stripping attack")
)

// domainResult holds per-recipient outcomes for one domain delivery attempt.
type domainResult struct {
	domain     string
	successful []string
	tempFailed []string
	permFailed []string
}

// DeliverOutboundWithWorkers delivers msg to all outbound recipients via direct MX.
// Recipients are grouped by domain; maxWorkers limits concurrent domain connections.
// signer may be nil when DKIM signing is disabled.
func DeliverOutboundWithWorkers(
	ctx context.Context,
	recipients map[string]struct{},
	maxWorkers int,
	msg *types.Message,
	messagePath string,
	cfg *config.OutboundDeliveryConfig,
	signer *DKIMSigner,
) DeliveryResult {
	result := DeliveryResult{
		Type:       RecipientExternal,
		Successful: make([]string, 0),
		TempFailed: make([]string, 0),
		PermFailed: make([]string, 0),
	}

	if len(recipients) == 0 {
		return result
	}

	byDomain := groupByDomain(recipients)

	if maxWorkers <= 0 {
		maxWorkers = 10
	}
	if maxWorkers > len(byDomain) {
		maxWorkers = len(byDomain)
	}

	sem := make(chan struct{}, maxWorkers)
	resultChan := make(chan domainResult, len(byDomain))

	for domain, addrs := range byDomain {
		domain, addrs := domain, addrs
		sem <- struct{}{}
		go func() {
			defer func() { <-sem }()
			resultChan <- deliverToDomain(ctx, msg, messagePath, domain, addrs, cfg, signer)
		}()
	}

	for range byDomain {
		dr := <-resultChan
		result.Successful = append(result.Successful, dr.successful...)
		result.TempFailed = append(result.TempFailed, dr.tempFailed...)
		result.PermFailed = append(result.PermFailed, dr.permFailed...)
	}

	return result
}

// groupByDomain groups email addresses by their domain part.
func groupByDomain(recipients map[string]struct{}) map[string][]string {
	byDomain := make(map[string][]string)
	for addr := range recipients {
		parts := strings.SplitN(addr, "@", 2)
		if len(parts) != 2 {
			continue
		}
		domain := strings.ToLower(parts[1])
		byDomain[domain] = append(byDomain[domain], addr)
	}
	return byDomain
}

// deliverToDomain attempts delivery to all recipients at a single domain via MX.
func deliverToDomain(ctx context.Context, msg *types.Message, messagePath, domain string, recipients []string, cfg *config.OutboundDeliveryConfig, signer *DKIMSigner) domainResult {
	result := domainResult{domain: domain}

	mxHosts, err := lookupMX(ctx, domain)
	if err != nil {
		slog.Warn("MX lookup failed", "domain", domain, "error", err)
		result.tempFailed = append(result.tempFailed, recipients...)
		return result
	}

	for _, mx := range mxHosts {
		conn, r, _, err := dialMX(ctx, mx, cfg)
		if err != nil {
			slog.Debug("outbound connect failed", "host", mx, "error", err)
			continue
		}

		outcomes := sendViaSMTP(ctx, conn, r, mx, msg, messagePath, recipients, cfg, signer)
		conn.Close()

		for _, o := range outcomes {
			switch o.category {
			case smtpSuccess:
				result.successful = append(result.successful, o.recipient)
			case smtpTempFail:
				result.tempFailed = append(result.tempFailed, o.recipient)
			case smtpPermFail:
				result.permFailed = append(result.permFailed, o.recipient)
			}
		}
		return result
	}

	// All MX hosts unreachable — tempfail all
	result.tempFailed = append(result.tempFailed, recipients...)
	return result
}

// lookupMX returns MX hostnames for domain sorted by priority.
func lookupMX(ctx context.Context, domain string) ([]string, error) {
	resolver := &net.Resolver{PreferGo: true}
	mxRecords, err := resolver.LookupMX(ctx, domain)
	if err != nil {
		return nil, fmt.Errorf("MX lookup failed for %s: %w", domain, err)
	}
	if len(mxRecords) == 0 {
		return nil, fmt.Errorf("no MX records for %s", domain)
	}
	sort.Slice(mxRecords, func(i, j int) bool {
		return mxRecords[i].Pref < mxRecords[j].Pref
	})
	hosts := make([]string, len(mxRecords))
	for i, mx := range mxRecords {
		hosts[i] = strings.TrimSuffix(mx.Host, ".")
	}
	return hosts, nil
}

// dialMX connects to host:25, reads the greeting, sends EHLO, and performs
// STARTTLS according to cfg.TLS.Policy. Returns conn, a bounded reader
// positioned after the post-EHLO exchange, and whether TLS is active.
//
// All network operations use per-operation deadlines to defend against slow/rogue MTAs.
func dialMX(ctx context.Context, host string, cfg *config.OutboundDeliveryConfig) (net.Conn, *bufio.Reader, bool, error) {
	slog.Debug("outbound connect attempt", "host", host, "port", outboundSMTPPort)

	dialCtx, cancel := context.WithTimeout(ctx, cfg.Timeouts.Dial)
	defer cancel()

	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", net.JoinHostPort(host, outboundSMTPPort))
	if err != nil {
		return nil, nil, false, err
	}

	r := bufio.NewReaderSize(conn, maxResponseLineBytes+2)

	// Read greeting (220)
	if err := conn.SetDeadline(time.Now().Add(cfg.Timeouts.Greeting)); err != nil {
		conn.Close()
		return nil, nil, false, err
	}
	if _, _, err := readSMTPResponse(r, maxResponseContinuations); err != nil {
		conn.Close()
		return nil, nil, false, fmt.Errorf("greeting read failed: %w", err)
	}
	conn.SetDeadline(time.Time{}) //nolint:errcheck

	// Send EHLO, read capabilities
	if err := conn.SetDeadline(time.Now().Add(cfg.Timeouts.Command)); err != nil {
		conn.Close()
		return nil, nil, false, err
	}
	if _, err := fmt.Fprintf(conn, "EHLO golubsmtpd\r\n"); err != nil {
		conn.Close()
		return nil, nil, false, fmt.Errorf("EHLO write failed: %w", err)
	}
	_, ehloLines, err := readSMTPResponse(r, maxResponseContinuations)
	if err != nil {
		conn.Close()
		return nil, nil, false, fmt.Errorf("EHLO response failed: %w", err)
	}
	conn.SetDeadline(time.Time{}) //nolint:errcheck

	starttlsAdvertised := ehloAdvertisesSTARTTLS(ehloLines)

	if !starttlsAdvertised {
		if cfg.TLS.Policy == "required" {
			conn.Close()
			return nil, nil, false, errSTARTTLSRequired
		}
		slog.Info("STARTTLS not advertised, proceeding plain", "host", host)
		return conn, r, false, nil
	}

	// STARTTLS advertised — negotiate it regardless of policy.
	// Advertised-then-rejected is always an error (STARTTLS stripping signal).
	if err := conn.SetDeadline(time.Now().Add(cfg.Timeouts.Command)); err != nil {
		conn.Close()
		return nil, nil, false, err
	}
	if _, err := fmt.Fprintf(conn, "STARTTLS\r\n"); err != nil {
		conn.Close()
		return nil, nil, false, fmt.Errorf("STARTTLS write failed: %w", err)
	}
	code, _, err := readSMTPResponse(r, maxResponseContinuations)
	if err != nil {
		conn.Close()
		return nil, nil, false, fmt.Errorf("STARTTLS response failed: %w", err)
	}
	conn.SetDeadline(time.Time{}) //nolint:errcheck

	if code != 220 {
		conn.Close()
		return nil, nil, false, errSTARTTLSFailed
	}

	// TLS handshake with dedicated deadline
	tlsCfg := &tls.Config{
		ServerName:         host,
		MinVersion:         resolveMinTLSVersion(cfg.TLS.MinVersion),
		InsecureSkipVerify: cfg.TLS.SkipVerify, //nolint:gosec — controlled by config
	}
	tlsConn := tls.Client(conn, tlsCfg)

	if err := tlsConn.SetDeadline(time.Now().Add(cfg.Timeouts.TLSHandshake)); err != nil {
		tlsConn.Close()
		return nil, nil, false, err
	}
	if err := tlsConn.Handshake(); err != nil {
		tlsConn.Close()
		return nil, nil, false, fmt.Errorf("TLS handshake failed: %w", err)
	}
	tlsConn.SetDeadline(time.Time{}) //nolint:errcheck

	state := tlsConn.ConnectionState()
	slog.Info("outbound TLS established",
		"host", host,
		"version", tls.VersionName(state.Version),
		"cipher_suite", tls.CipherSuiteName(state.CipherSuite),
		"verified", !cfg.TLS.SkipVerify,
	)

	// Re-wrap TLS conn with fresh bounded reader (RFC 3207 §4: re-EHLO required)
	tlsR := bufio.NewReaderSize(tlsConn, maxResponseLineBytes+2)

	if err := tlsConn.SetDeadline(time.Now().Add(cfg.Timeouts.Command)); err != nil {
		tlsConn.Close()
		return nil, nil, false, err
	}
	if _, err := fmt.Fprintf(tlsConn, "EHLO golubsmtpd\r\n"); err != nil {
		tlsConn.Close()
		return nil, nil, false, fmt.Errorf("post-TLS EHLO write failed: %w", err)
	}
	if _, _, err := readSMTPResponse(tlsR, maxResponseContinuations); err != nil {
		tlsConn.Close()
		return nil, nil, false, fmt.Errorf("post-TLS EHLO response failed: %w", err)
	}
	tlsConn.SetDeadline(time.Time{}) //nolint:errcheck

	return tlsConn, tlsR, true, nil
}

// ehloAdvertisesSTARTTLS checks EHLO response lines for the STARTTLS extension.
func ehloAdvertisesSTARTTLS(lines []string) bool {
	for _, line := range lines {
		if strings.EqualFold(strings.TrimSpace(line), "STARTTLS") {
			return true
		}
	}
	return false
}

// resolveMinTLSVersion maps config string to crypto/tls constant.
func resolveMinTLSVersion(s string) uint16 {
	if s == "tls13" {
		return tls.VersionTLS13
	}
	return tls.VersionTLS12
}

// readSMTPResponse reads a complete SMTP response (single or multi-line) from r.
// It enforces line-length limits, continuation-count limits, strict code validation,
// and embedded-CRLF detection to protect against rogue MTA attacks.
//
// Returns the numeric code, the message lines (code prefix stripped), and any error.
func readSMTPResponse(r *bufio.Reader, maxLines int) (int, []string, error) {
	var lines []string
	var code int
	continuations := 0

	for {
		line, err := r.ReadString('\n')
		if err != nil {
			return 0, nil, fmt.Errorf("response read error: %w", err)
		}

		// Strip CRLF
		line = strings.TrimRight(line, "\r\n")

		// Line-length enforcement (after stripping CRLF)
		if len(line) > maxResponseLineBytes {
			return 0, nil, fmt.Errorf("response line exceeds %d bytes", maxResponseLineBytes)
		}

		// Must be at least 4 chars: "NNN " or "NNN-"
		if len(line) < 4 {
			return 0, nil, fmt.Errorf("response line too short: %q", line)
		}

		// Strict 3-digit code validation
		codeStr := line[:3]
		lineCode, convErr := strconv.Atoi(codeStr)
		if convErr != nil || lineCode < 100 || lineCode > 599 {
			return 0, nil, fmt.Errorf("invalid SMTP response code: %q", codeStr)
		}

		// Separator must be space (final) or hyphen (continuation)
		sep := line[3]
		if sep != ' ' && sep != '-' {
			return 0, nil, fmt.Errorf("invalid SMTP response separator %q in: %q", sep, line)
		}

		msg := line[4:]

		// Embedded CR or LF in message text — response injection attempt
		if strings.ContainsAny(msg, "\r\n") {
			return 0, nil, fmt.Errorf("embedded CRLF in SMTP response message")
		}

		if code == 0 {
			code = lineCode
		} else if lineCode != code {
			return 0, nil, fmt.Errorf("mismatched response codes in multi-line response: %d vs %d", code, lineCode)
		}

		lines = append(lines, msg)

		if sep == ' ' {
			// Final line
			break
		}

		// Continuation line
		continuations++
		if continuations >= maxLines {
			return 0, nil, fmt.Errorf("response has too many continuation lines (max %d)", maxLines)
		}
	}

	return code, lines, nil
}

type smtpCategory int

const (
	smtpSuccess  smtpCategory = iota
	smtpTempFail              // 4xx
	smtpPermFail              // 5xx
)

type recipientOutcome struct {
	recipient string
	category  smtpCategory
}

// sendViaSMTP executes the SMTP envelope exchange on conn using the bounded reader r.
// conn and r must already be positioned after the post-EHLO exchange (dialMX handles this).
func sendViaSMTP(
	ctx context.Context,
	conn net.Conn,
	r *bufio.Reader,
	host string,
	msg *types.Message,
	messagePath string,
	recipients []string,
	cfg *config.OutboundDeliveryConfig,
	signer *DKIMSigner,
) []recipientOutcome {
	_, isTLS := conn.(*tls.Conn)

	failAll := func(cat smtpCategory) []recipientOutcome {
		out := make([]recipientOutcome, len(recipients))
		for i, rec := range recipients {
			out[i] = recipientOutcome{rec, cat}
		}
		return out
	}

	smtpCmd := func(cmd string) (int, []string, error) {
		if err := conn.SetDeadline(time.Now().Add(cfg.Timeouts.Command)); err != nil {
			return 0, nil, err
		}
		if _, err := fmt.Fprintf(conn, "%s\r\n", cmd); err != nil {
			return 0, nil, err
		}
		code, lines, err := readSMTPResponse(r, maxResponseContinuations)
		conn.SetDeadline(time.Time{}) //nolint:errcheck
		return code, lines, err
	}

	// MAIL FROM
	mailCmd := fmt.Sprintf("MAIL FROM:<%s>", msg.From)
	code, _, err := smtpCmd(mailCmd)
	if err != nil || code/100 != 2 {
		slog.Warn("outbound MAIL FROM rejected", "host", host, "code", code, "error", err)
		return failAll(smtpTempFail)
	}

	// RCPT TO (per-recipient)
	var outcomes []recipientOutcome
	var accepted []string
	for _, rec := range recipients {
		rcptCmd := fmt.Sprintf("RCPT TO:<%s>", rec)
		code, _, err := smtpCmd(rcptCmd)
		if err != nil || code/100 != 2 {
			cat := smtpTempFail
			if code/100 == 5 {
				cat = smtpPermFail
			}
			outcomes = append(outcomes, recipientOutcome{rec, cat})
			slog.Debug("outbound RCPT TO rejected", "recipient", rec, "host", host, "code", code)
		} else {
			accepted = append(accepted, rec)
		}
	}

	if len(accepted) == 0 {
		return outcomes
	}

	// DATA
	code, _, err = smtpCmd("DATA")
	if err != nil || code != 354 {
		slog.Warn("outbound DATA rejected", "host", host, "code", code, "error", err)
		for _, rec := range accepted {
			outcomes = append(outcomes, recipientOutcome{rec, smtpTempFail})
		}
		return outcomes
	}

	// Stream message body with DataTransfer deadline
	if err := conn.SetDeadline(time.Now().Add(cfg.Timeouts.DataTransfer)); err != nil {
		for _, rec := range accepted {
			outcomes = append(outcomes, recipientOutcome{rec, smtpTempFail})
		}
		return outcomes
	}

	f, err := os.Open(messagePath)
	if err != nil {
		conn.SetDeadline(time.Time{}) //nolint:errcheck
		for _, rec := range accepted {
			outcomes = append(outcomes, recipientOutcome{rec, smtpTempFail})
		}
		return outcomes
	}
	defer f.Close()

	w := textproto.NewWriter(bufio.NewWriter(conn)).DotWriter()
	writeErr := false

	if signer != nil {
		sig, sigErr := signer.SignFile(f)
		if sigErr != nil {
			slog.Warn("DKIM signing failed, sending unsigned", "host", host, "error", sigErr)
			if _, seekErr := f.Seek(0, 0); seekErr != nil {
				writeErr = true
			}
		} else {
			if _, werr := fmt.Fprint(w, sig); werr != nil {
				writeErr = true
			}
		}
	}

	if !writeErr {
		buf := make([]byte, 32*1024)
		for {
			n, readErr := f.Read(buf)
			if n > 0 {
				if _, werr := w.Write(buf[:n]); werr != nil {
					writeErr = true
					break
				}
			}
			if readErr != nil {
				break
			}
		}
	}
	w.Close()

	conn.SetDeadline(time.Time{}) //nolint:errcheck

	if writeErr {
		for _, rec := range accepted {
			outcomes = append(outcomes, recipientOutcome{rec, smtpTempFail})
		}
		return outcomes
	}

	// Read final 250 after dot terminator
	if err := conn.SetDeadline(time.Now().Add(cfg.Timeouts.Command)); err != nil {
		for _, rec := range accepted {
			outcomes = append(outcomes, recipientOutcome{rec, smtpTempFail})
		}
		return outcomes
	}
	code, _, err = readSMTPResponse(r, maxResponseContinuations)
	conn.SetDeadline(time.Time{}) //nolint:errcheck

	if err != nil || code/100 != 2 {
		slog.Warn("outbound DATA final response rejected", "host", host, "code", code, "error", err)
		for _, rec := range accepted {
			outcomes = append(outcomes, recipientOutcome{rec, smtpTempFail})
		}
		return outcomes
	}

	for _, rec := range accepted {
		slog.Info("outbound delivery", "recipient", rec, "host", host, "tls", isTLS, "code", code)
		outcomes = append(outcomes, recipientOutcome{rec, smtpSuccess})
	}

	// Best-effort QUIT — do not wait for response
	conn.SetDeadline(time.Now().Add(cfg.Timeouts.Command)) //nolint:errcheck
	fmt.Fprintf(conn, "QUIT\r\n")                          //nolint:errcheck
	conn.SetDeadline(time.Time{})                          //nolint:errcheck

	// suppress unused ctx warning — ctx cancellation propagates via conn deadlines
	_ = ctx

	return outcomes
}

// categorizeSMTPError maps an SMTP error to a delivery category.
func categorizeSMTPError(err error) smtpCategory {
	if err == nil {
		return smtpSuccess
	}
	if textErr, ok := err.(*textproto.Error); ok {
		if textErr.Code >= 500 {
			return smtpPermFail
		}
		return smtpTempFail
	}
	return smtpTempFail
}
