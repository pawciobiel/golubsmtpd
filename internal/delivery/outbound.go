package delivery

import (
	"context"
	"crypto/tls"
	"fmt"
	"net"
	"net/smtp"
	"net/textproto"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/pawciobiel/golubsmtpd/internal/types"
)

const (
	outboundConnectTimeout = 30 * time.Second
	outboundDialTimeout    = 10 * time.Second
	outboundSMTPPort       = "25"
)

// domainResult holds per-recipient outcomes for one domain delivery attempt.
type domainResult struct {
	domain     string
	successful []string
	tempFailed []string
	permFailed []string
}

// DeliverOutboundWithWorkers delivers msg to all outbound recipients via direct MX.
// Recipients are grouped by domain internally; maxWorkers limits concurrent domain connections.
// Returns a DeliveryResult with Successful/TempFailed/PermFailed populated.
func DeliverOutboundWithWorkers(
	ctx context.Context,
	recipients map[string]struct{},
	maxWorkers int,
	msg *types.Message,
	messagePath string,
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
			resultChan <- deliverToDomain(ctx, msg, messagePath, domain, addrs)
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
func deliverToDomain(ctx context.Context, msg *types.Message, messagePath, domain string, recipients []string) domainResult {
	result := domainResult{domain: domain}

	mxHosts, err := lookupMX(ctx, domain)
	if err != nil {
		result.tempFailed = append(result.tempFailed, recipients...)
		return result
	}

	for _, mx := range mxHosts {
		conn, tlsActive, err := dialMX(ctx, mx)
		if err != nil {
			continue
		}

		outcomes := sendViaSMTP(ctx, conn, tlsActive, mx, msg, messagePath, recipients)
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

// dialMX connects to host:25 and attempts a STARTTLS upgrade.
// Returns the connection (upgraded or plain) and whether TLS is active.
func dialMX(ctx context.Context, host string) (net.Conn, bool, error) {
	dialCtx, cancel := context.WithTimeout(ctx, outboundDialTimeout)
	defer cancel()

	conn, err := (&net.Dialer{}).DialContext(dialCtx, "tcp", net.JoinHostPort(host, outboundSMTPPort))
	if err != nil {
		return nil, false, err
	}

	tlsConn, err := upgradeToTLS(conn, host)
	if err != nil {
		// STARTTLS not supported or failed — continue plain
		return conn, false, nil
	}
	return tlsConn, true, nil
}

// upgradeToTLS negotiates STARTTLS on a plain connection.
func upgradeToTLS(conn net.Conn, host string) (net.Conn, error) {
	tp := textproto.NewConn(conn)

	if _, _, err := tp.ReadResponse(220); err != nil {
		return nil, fmt.Errorf("greeting failed: %w", err)
	}
	if err := tp.PrintfLine("EHLO golubsmtpd"); err != nil {
		return nil, err
	}
	_, msg, err := tp.ReadResponse(250)
	if err != nil {
		return nil, fmt.Errorf("EHLO failed: %w", err)
	}
	if !strings.Contains(strings.ToUpper(msg), "STARTTLS") {
		return nil, fmt.Errorf("STARTTLS not advertised")
	}
	if err := tp.PrintfLine("STARTTLS"); err != nil {
		return nil, err
	}
	if _, _, err := tp.ReadResponse(220); err != nil {
		return nil, fmt.Errorf("STARTTLS rejected: %w", err)
	}

	tlsConn := tls.Client(conn, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
	if err := tlsConn.Handshake(); err != nil {
		return nil, fmt.Errorf("TLS handshake failed: %w", err)
	}
	return tlsConn, nil
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

// sendViaSMTP opens an SMTP session on conn and delivers msg to all recipients.
func sendViaSMTP(ctx context.Context, conn net.Conn, _ bool, host string, msg *types.Message, messagePath string, recipients []string) []recipientOutcome {
	conn.SetDeadline(time.Now().Add(outboundConnectTimeout))

	failAll := func(cat smtpCategory) []recipientOutcome {
		out := make([]recipientOutcome, len(recipients))
		for i, r := range recipients {
			out[i] = recipientOutcome{r, cat}
		}
		return out
	}

	client, err := smtp.NewClient(conn, host)
	if err != nil {
		return failAll(smtpTempFail)
	}
	defer client.Quit() //nolint:errcheck

	if err := client.Hello("golubsmtpd"); err != nil {
		return failAll(smtpTempFail)
	}
	if err := client.Mail(msg.From); err != nil {
		return failAll(smtpTempFail)
	}

	var outcomes []recipientOutcome
	var accepted []string
	for _, r := range recipients {
		if err := client.Rcpt(r); err != nil {
			outcomes = append(outcomes, recipientOutcome{r, categorizeSMTPError(err)})
		} else {
			accepted = append(accepted, r)
		}
	}

	if len(accepted) == 0 {
		return outcomes
	}

	wc, err := client.Data()
	if err != nil {
		for _, r := range accepted {
			outcomes = append(outcomes, recipientOutcome{r, smtpTempFail})
		}
		return outcomes
	}

	f, err := os.Open(messagePath)
	if err != nil {
		wc.Close()
		for _, r := range accepted {
			outcomes = append(outcomes, recipientOutcome{r, smtpTempFail})
		}
		return outcomes
	}
	defer f.Close()

	buf := make([]byte, 32*1024)
	writeErr := false
	for {
		n, readErr := f.Read(buf)
		if n > 0 {
			if _, err := wc.Write(buf[:n]); err != nil {
				writeErr = true
				break
			}
		}
		if readErr != nil {
			break
		}
	}
	wc.Close()

	if writeErr {
		for _, r := range accepted {
			outcomes = append(outcomes, recipientOutcome{r, smtpTempFail})
		}
		return outcomes
	}

	for _, r := range accepted {
		outcomes = append(outcomes, recipientOutcome{r, smtpSuccess})
	}
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
