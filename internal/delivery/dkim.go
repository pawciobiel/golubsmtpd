package delivery

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
	"time"

	"github.com/pawciobiel/golubsmtpd/internal/config"
)

// headersToSign lists the headers included in the DKIM signature, in order.
// Only headers present in the message are included in the h= tag.
var headersToSign = []string{
	"from", "to", "subject", "date", "message-id", "mime-version", "content-type",
}

// whitespaceRun matches one or more whitespace characters (CRLF-aware).
var whitespaceRun = regexp.MustCompile(`[ \t]+`)

// DKIMSigner holds the RSA private key and signing config, loaded once at startup.
type DKIMSigner struct {
	privateKey *rsa.PrivateKey
	cfg        *config.DKIMConfig
}

// NewDKIMSigner loads the RSA private key from cfg.PrivateKeyFile and returns a Signer.
func NewDKIMSigner(cfg *config.DKIMConfig) (*DKIMSigner, error) {
	data, err := os.ReadFile(cfg.PrivateKeyFile)
	if err != nil {
		return nil, fmt.Errorf("dkim: read private key: %w", err)
	}

	block, _ := pem.Decode(data)
	if block == nil {
		return nil, fmt.Errorf("dkim: no PEM block found in %s", cfg.PrivateKeyFile)
	}

	var key *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("dkim: parse PKCS#1 key: %w", err)
		}
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("dkim: parse PKCS#8 key: %w", err)
		}
		var ok bool
		key, ok = parsed.(*rsa.PrivateKey)
		if !ok {
			return nil, fmt.Errorf("dkim: PKCS#8 key is not RSA")
		}
	default:
		return nil, fmt.Errorf("dkim: unsupported PEM block type %q", block.Type)
	}

	return &DKIMSigner{privateKey: key, cfg: cfg}, nil
}

// SignFile reads the message from f, computes a DKIM-Signature header, then seeks
// f back to the beginning so the caller can stream the full message after prepending
// the returned header line.
//
// The returned string is the complete header line including the "DKIM-Signature: "
// prefix, RFC 5322-folded at 72 chars, terminated with CRLF (suitable for
// fmt.Fprintf(w, "%s\r\n", sig) ... no, the CRLF is already included).
func (s *DKIMSigner) SignFile(f *os.File) (string, error) {
	raw, err := io.ReadAll(f)
	if err != nil {
		return "", fmt.Errorf("dkim: read message: %w", err)
	}
	if _, err := f.Seek(0, io.SeekStart); err != nil {
		return "", fmt.Errorf("dkim: seek message: %w", err)
	}

	// Split headers from body on the first blank line (CRLF CRLF or LF LF).
	headerSection, bodySection := splitHeadersBody(raw)

	// --- Body hash (relaxed canonicalization) ---
	bodyHash := canonicalBodyHash(bodySection)

	// --- Identify which headers to sign (only those present) ---
	parsedHeaders := parseHeaders(headerSection)
	signedHeaderNames := selectSignedHeaders(parsedHeaders)

	// --- Build the partial DKIM-Signature header (b= empty) ---
	ts := time.Now().Unix()
	partial := buildPartialSig(s.cfg.Domain, s.cfg.Selector, ts, bodyHash, signedHeaderNames)

	// --- Header hash (relaxed canonicalization) ---
	headerHash := canonicalHeaderHash(parsedHeaders, signedHeaderNames, partial)

	// --- RSA-SHA256 signature ---
	sig, err := rsa.SignPKCS1v15(rand.Reader, s.privateKey, crypto.SHA256, headerHash[:])
	if err != nil {
		return "", fmt.Errorf("dkim: sign: %w", err)
	}

	// --- Assemble final DKIM-Signature header ---
	full := partial + base64.StdEncoding.EncodeToString(sig)
	return foldHeader("DKIM-Signature", full), nil
}

// splitHeadersBody splits a raw message into (headers, body).
// Headers end at the first blank line (\r\n\r\n or \n\n).
func splitHeadersBody(raw []byte) ([]byte, []byte) {
	msg := string(raw)
	if idx := strings.Index(msg, "\r\n\r\n"); idx >= 0 {
		return []byte(msg[:idx+2]), []byte(msg[idx+4:]) // header section includes trailing CRLF
	}
	if idx := strings.Index(msg, "\n\n"); idx >= 0 {
		return []byte(msg[:idx+1]), []byte(msg[idx+2:])
	}
	// No body — treat entire message as headers
	return raw, nil
}

// canonicalBodyHash applies relaxed body canonicalization and returns SHA-256.
func canonicalBodyHash(body []byte) []byte {
	lines := splitLines(string(body))

	var sb strings.Builder
	for _, line := range lines {
		// Reduce runs of whitespace to single space; strip trailing whitespace.
		line = whitespaceRun.ReplaceAllString(line, " ")
		line = strings.TrimRight(line, " \t")
		sb.WriteString(line)
		sb.WriteString("\r\n")
	}

	// Strip trailing empty lines, then ensure single terminating CRLF.
	result := strings.TrimRight(sb.String(), "\r\n")
	result += "\r\n"

	h := sha256.Sum256([]byte(result))
	return h[:]
}

// splitLines splits text on CRLF or LF boundaries without using bufio.Scanner
// to avoid issues with long lines.
func splitLines(s string) []string {
	s = strings.ReplaceAll(s, "\r\n", "\n")
	lines := strings.Split(s, "\n")
	// Drop the final empty element from a trailing newline.
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	return lines
}

// headerEntry is a single header field with its original name and value.
type headerEntry struct {
	name  string // original case
	value string // everything after "name: " (may include folded continuation lines)
}

// parseHeaders parses the header section into ordered header entries.
// Folded headers (continuation lines starting with whitespace) are joined.
func parseHeaders(headerSection []byte) []headerEntry {
	text := strings.ReplaceAll(string(headerSection), "\r\n", "\n")
	rawLines := strings.Split(text, "\n")

	var entries []headerEntry
	for _, line := range rawLines {
		if line == "" {
			continue
		}
		if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
			// Continuation of previous header.
			if len(entries) > 0 {
				entries[len(entries)-1].value += " " + strings.TrimSpace(line)
			}
			continue
		}
		colon := strings.IndexByte(line, ':')
		if colon < 0 {
			continue
		}
		entries = append(entries, headerEntry{
			name:  line[:colon],
			value: strings.TrimSpace(line[colon+1:]),
		})
	}
	return entries
}

// selectSignedHeaders returns the lowercased header names to include in h=,
// in the order they appear in headersToSign, skipping those not present.
func selectSignedHeaders(entries []headerEntry) []string {
	present := make(map[string]bool, len(entries))
	for _, e := range entries {
		present[strings.ToLower(e.name)] = true
	}
	var selected []string
	for _, h := range headersToSign {
		if present[h] {
			selected = append(selected, h)
		}
	}
	return selected
}

// buildPartialSig returns the DKIM-Signature field value up to "b=" (empty b=).
// The caller appends the base64 signature to complete the value.
func buildPartialSig(domain, selector string, ts int64, bodyHash []byte, signedHeaders []string) string {
	bh := base64.StdEncoding.EncodeToString(bodyHash)
	h := strings.Join(signedHeaders, ":")
	return fmt.Sprintf(
		"v=1; a=rsa-sha256; c=relaxed/relaxed; d=%s; s=%s; t=%d; bh=%s; h=%s; b=",
		domain, selector, ts, bh, h,
	)
}

// canonicalHeaderHash builds the canonicalized header input for signing and
// returns its SHA-256 hash.
//
// Per RFC 6376 §3.7: for each signed header name, take the last occurrence
// in the message (or skip if absent), apply relaxed canonicalization, then
// append the DKIM-Signature header itself (with b= empty).
func canonicalHeaderHash(entries []headerEntry, signedHeaderNames []string, partialSig string) [32]byte {
	// Build index: name (lowercase) → last occurrence index in entries.
	lastIdx := make(map[string]int, len(entries))
	for i, e := range entries {
		lastIdx[strings.ToLower(e.name)] = i
	}

	var sb strings.Builder
	for _, name := range signedHeaderNames {
		idx, ok := lastIdx[name]
		if !ok {
			continue
		}
		e := entries[idx]
		// Relaxed header canonicalization: lowercase name, compress whitespace in value.
		canonName := strings.ToLower(e.name)
		canonValue := whitespaceRun.ReplaceAllString(e.value, " ")
		canonValue = strings.TrimSpace(canonValue)
		sb.WriteString(canonName)
		sb.WriteString(":")
		sb.WriteString(canonValue)
		sb.WriteString("\r\n")
	}

	// Append the partial DKIM-Signature header (relaxed canonicalization, b= empty).
	sb.WriteString("dkim-signature:")
	sb.WriteString(strings.TrimSpace(whitespaceRun.ReplaceAllString(partialSig, " ")))

	return sha256.Sum256([]byte(sb.String()))
}

// foldHeader folds a header field value at 72 chars using CRLF+TAB continuation.
// Returns the full folded header line including the terminating CRLF.
func foldHeader(name, value string) string {
	line := name + ": " + value
	if len(line) <= 72 {
		return line + "\r\n"
	}

	var sb strings.Builder
	remaining := line

	// Write the first chunk up to 72 chars at a semicolon boundary.
	for len(remaining) > 72 {
		cut := 72
		// Find last "; " at or before cut to break cleanly.
		if idx := strings.LastIndex(remaining[:cut], "; "); idx >= 0 {
			cut = idx + 1 // break after the semicolon, before the space
		}
		sb.WriteString(remaining[:cut])
		sb.WriteString("\r\n\t")
		remaining = strings.TrimLeft(remaining[cut:], " ")
	}
	sb.WriteString(remaining)
	sb.WriteString("\r\n")
	return sb.String()
}
