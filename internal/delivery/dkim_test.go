package delivery

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/pawciobiel/golubsmtpd/internal/config"
)

// generateTestKey writes a PKCS#1 RSA private key PEM to a temp file and returns the path.
func generateTestKey(t *testing.T) (string, *rsa.PrivateKey) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	f, err := os.CreateTemp(t.TempDir(), "dkim-*.pem")
	if err != nil {
		t.Fatalf("create temp key file: %v", err)
	}
	defer f.Close()
	if err := pem.Encode(f, &pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(key),
	}); err != nil {
		t.Fatalf("encode PEM: %v", err)
	}
	return f.Name(), key
}

func testDKIMConfig(t *testing.T) (*config.DKIMConfig, *rsa.PrivateKey) {
	t.Helper()
	keyPath, key := generateTestKey(t)
	return &config.DKIMConfig{
		Enabled:        true,
		Domain:         "example.com",
		Selector:       "default",
		PrivateKeyFile: keyPath,
	}, key
}

func TestNewDKIMSigner_LoadsKey(t *testing.T) {
	cfg, _ := testDKIMConfig(t)
	signer, err := NewDKIMSigner(cfg)
	if err != nil {
		t.Fatalf("NewDKIMSigner: %v", err)
	}
	if signer == nil {
		t.Fatal("expected non-nil signer")
	}
}

func TestNewDKIMSigner_MissingFile(t *testing.T) {
	cfg := &config.DKIMConfig{
		PrivateKeyFile: "/nonexistent/path/key.pem",
	}
	_, err := NewDKIMSigner(cfg)
	if err == nil {
		t.Fatal("expected error for missing key file")
	}
}

func TestNewDKIMSigner_InvalidPEM(t *testing.T) {
	f, err := os.CreateTemp(t.TempDir(), "bad-*.pem")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	f.WriteString("not a pem file\n")
	f.Close()

	cfg := &config.DKIMConfig{PrivateKeyFile: f.Name()}
	_, err = NewDKIMSigner(cfg)
	if err == nil {
		t.Fatal("expected error for invalid PEM")
	}
}

func TestCanonicalBodyHash_Basic(t *testing.T) {
	body := []byte("Hello  World\r\nThis is a test.\r\n")
	hash := canonicalBodyHash(body)
	if len(hash) != 32 {
		t.Fatalf("expected 32-byte SHA-256 hash, got %d", len(hash))
	}

	// Same input must produce same hash.
	hash2 := canonicalBodyHash(body)
	if string(hash) != string(hash2) {
		t.Error("canonicalBodyHash is not deterministic")
	}
}

func TestCanonicalBodyHash_TrailingEmptyLines(t *testing.T) {
	// RFC 6376: trailing empty lines are stripped before hashing.
	body1 := []byte("Hello\r\n")
	body2 := []byte("Hello\r\n\r\n\r\n")
	h1 := canonicalBodyHash(body1)
	h2 := canonicalBodyHash(body2)
	if string(h1) != string(h2) {
		t.Error("trailing empty lines should produce the same body hash")
	}
}

func TestCanonicalBodyHash_EmptyBody(t *testing.T) {
	// RFC 6376 §3.4.3: empty body canonical form is a single CRLF; hash must match.
	expected := sha256.Sum256([]byte("\r\n"))
	hash := canonicalBodyHash(nil)
	if len(hash) != 32 {
		t.Fatalf("expected 32-byte hash for empty body, got %d", len(hash))
	}
	if string(hash) != string(expected[:]) {
		t.Errorf("empty body hash mismatch: got %x, want %x", hash, expected)
	}
}

func TestParseHeaders_Basic(t *testing.T) {
	raw := []byte("From: sender@example.com\r\nTo: rec@example.com\r\nSubject: Hello\r\n")
	entries := parseHeaders(raw)

	if len(entries) != 3 {
		t.Fatalf("expected 3 headers, got %d", len(entries))
	}
	if entries[0].name != "From" || entries[0].value != "sender@example.com" {
		t.Errorf("unexpected first header: %+v", entries[0])
	}
	if entries[2].name != "Subject" || entries[2].value != "Hello" {
		t.Errorf("unexpected third header: %+v", entries[2])
	}
}

func TestParseHeaders_FoldedHeader(t *testing.T) {
	raw := []byte("Subject: Long\r\n\t folded subject\r\nFrom: x@y.com\r\n")
	entries := parseHeaders(raw)

	if len(entries) != 2 {
		t.Fatalf("expected 2 headers, got %d", len(entries))
	}
	if !strings.Contains(entries[0].value, "folded subject") {
		t.Errorf("folded header value not joined: %q", entries[0].value)
	}
}

func TestSelectSignedHeaders(t *testing.T) {
	entries := []headerEntry{
		{name: "From", value: "a@b.com"},
		{name: "Subject", value: "Hi"},
		{name: "X-Custom", value: "custom"},
	}
	selected := selectSignedHeaders(entries)

	// Should include from and subject, not x-custom.
	for _, h := range selected {
		if h == "x-custom" {
			t.Error("x-custom should not be in signed headers")
		}
	}
	found := make(map[string]bool)
	for _, h := range selected {
		found[h] = true
	}
	if !found["from"] {
		t.Error("from must be in signed headers")
	}
	if !found["subject"] {
		t.Error("subject should be in signed headers when present")
	}
}

func TestFoldHeader_Short(t *testing.T) {
	result := foldHeader("X-Test", "short value")
	if result != "X-Test: short value\r\n" {
		t.Errorf("unexpected folded header: %q", result)
	}
}

func TestFoldHeader_Long(t *testing.T) {
	value := "v=1; a=rsa-sha256; c=relaxed/relaxed; d=example.com; s=default; t=1234567890; bh=abc123; h=from:to:subject; b=" + strings.Repeat("X", 200)
	result := foldHeader("DKIM-Signature", value)

	// Must not have a line longer than 998 chars (RFC 5322).
	for _, line := range strings.Split(result, "\n") {
		line = strings.TrimRight(line, "\r")
		if len(line) > 998 {
			t.Errorf("line too long (%d chars): %q", len(line), line)
		}
	}
	// Must end with CRLF.
	if !strings.HasSuffix(result, "\r\n") {
		t.Error("folded header must end with CRLF")
	}
}

func TestSplitHeadersBody(t *testing.T) {
	raw := []byte("From: a@b.com\r\n\r\nHello body\r\n")
	headers, body := splitHeadersBody(raw)

	if !strings.Contains(string(headers), "From:") {
		t.Error("headers should contain From")
	}
	if !strings.Contains(string(body), "Hello body") {
		t.Error("body should contain message body")
	}
}

func TestSignFile_ProducesValidHeader(t *testing.T) {
	cfg, _ := testDKIMConfig(t)
	signer, err := NewDKIMSigner(cfg)
	if err != nil {
		t.Fatalf("NewDKIMSigner: %v", err)
	}

	// Write a minimal RFC 5322 message to a temp file.
	msg := "From: sender@example.com\r\n" +
		"To: rec@example.com\r\n" +
		"Subject: Test\r\n" +
		"Date: Mon, 01 Apr 2024 12:00:00 +0000\r\n" +
		"\r\n" +
		"Hello, world!\r\n"

	f, err := os.CreateTemp(t.TempDir(), "msg-*.eml")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer f.Close()
	if _, err := f.WriteString(msg); err != nil {
		t.Fatalf("write message: %v", err)
	}
	if _, err := f.Seek(0, 0); err != nil {
		t.Fatalf("seek: %v", err)
	}

	sig, err := signer.SignFile(f)
	if err != nil {
		t.Fatalf("SignFile: %v", err)
	}

	// Validate structural requirements.
	if !strings.HasPrefix(sig, "DKIM-Signature:") {
		t.Errorf("signature header must start with 'DKIM-Signature:', got: %q", sig[:min(50, len(sig))])
	}
	if !strings.HasSuffix(sig, "\r\n") {
		t.Error("signature header must end with CRLF")
	}
	if !strings.Contains(sig, "a=rsa-sha256") {
		t.Error("signature must declare rsa-sha256 algorithm")
	}
	if !strings.Contains(sig, "d=example.com") {
		t.Error("signature must contain domain")
	}
	if !strings.Contains(sig, "s=default") {
		t.Error("signature must contain selector")
	}
	if !strings.Contains(sig, "bh=") {
		t.Error("signature must contain body hash")
	}
	if !strings.Contains(sig, "b=") {
		t.Error("signature must contain signature value")
	}

	// After SignFile, f must be seeked back to start.
	pos, err := f.Seek(0, 1)
	if err != nil {
		t.Fatalf("tell: %v", err)
	}
	if pos != 0 {
		t.Errorf("SignFile must seek f back to 0, current pos=%d", pos)
	}
}

func TestSignFile_DeterministicBodyHash(t *testing.T) {
	cfg, _ := testDKIMConfig(t)
	signer, err := NewDKIMSigner(cfg)
	if err != nil {
		t.Fatalf("NewDKIMSigner: %v", err)
	}

	msg := "From: a@b.com\r\n\r\nBody text.\r\n"

	writeMsg := func() *os.File {
		f, err := os.CreateTemp(t.TempDir(), "msg-*.eml")
		if err != nil {
			t.Fatalf("create temp file: %v", err)
		}
		f.WriteString(msg)
		f.Seek(0, 0)
		return f
	}

	sig1, err := signer.SignFile(writeMsg())
	if err != nil {
		t.Fatalf("SignFile 1: %v", err)
	}
	// Extract bh= value from both signatures for comparison.
	bh1 := extractTag(sig1, "bh")

	sig2, err := signer.SignFile(writeMsg())
	if err != nil {
		t.Fatalf("SignFile 2: %v", err)
	}
	bh2 := extractTag(sig2, "bh")

	if bh1 == "" || bh2 == "" {
		t.Fatal("could not extract bh= tag")
	}
	if bh1 != bh2 {
		t.Errorf("body hash must be deterministic: got %q and %q", bh1, bh2)
	}
}

func TestSignFile_TimestampIsRecent(t *testing.T) {
	cfg, _ := testDKIMConfig(t)
	signer, err := NewDKIMSigner(cfg)
	if err != nil {
		t.Fatalf("NewDKIMSigner: %v", err)
	}

	msg := "From: a@b.com\r\n\r\nBody.\r\n"
	f, err := os.CreateTemp(t.TempDir(), "msg-*.eml")
	if err != nil {
		t.Fatalf("create temp: %v", err)
	}
	defer f.Close()
	before := time.Now().Unix()
	f.WriteString(msg)
	f.Seek(0, 0)

	sig, err := signer.SignFile(f)
	after := time.Now().Unix()
	if err != nil {
		t.Fatalf("SignFile: %v", err)
	}

	tStr := extractTag(sig, "t")
	if tStr == "" {
		t.Fatal("could not extract t= tag from signature")
	}
	var ts int64
	if _, err := parseint64(tStr, &ts); err != nil || ts < before || ts > after {
		t.Errorf("t= timestamp %q out of expected range [%d, %d]", tStr, before, after)
	}
}

// extractTag extracts the value of a tag (e.g. "bh", "t") from a DKIM-Signature header.
// Tags are separated by semicolons. Returns "" if not found.
func extractTag(header, tag string) string {
	header = strings.ReplaceAll(header, "\r\n\t", "")
	for _, part := range strings.Split(header, ";") {
		part = strings.TrimSpace(part)
		kv := strings.SplitN(part, "=", 2)
		if len(kv) == 2 && strings.TrimSpace(kv[0]) == tag {
			return strings.TrimSpace(kv[1])
		}
	}
	return ""
}

// parseint64 parses a decimal int64 from s, stopping at the first non-digit.
func parseint64(s string, v *int64) (int, error) {
	var x int64
	n := 0
	neg := false
	if len(s) > 0 && s[0] == '-' {
		neg = true
		s = s[1:]
		n++
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			break
		}
		x = x*10 + int64(c-'0')
		n++
	}
	if neg {
		x = -x
	}
	*v = x
	return n, nil
}

// TestBuildPartialSig checks the format of the partial signature string.
func TestBuildPartialSig(t *testing.T) {
	bh := make([]byte, 32)
	for i := range bh {
		bh[i] = byte(i)
	}
	result := buildPartialSig("example.com", "sel", 1234567890, bh, []string{"from", "to"})

	if !strings.HasPrefix(result, "v=1;") {
		t.Errorf("must start with v=1;, got %q", result[:min(20, len(result))])
	}
	if !strings.Contains(result, "d=example.com") {
		t.Error("must contain domain")
	}
	if !strings.Contains(result, "s=sel") {
		t.Error("must contain selector")
	}
	if !strings.Contains(result, "h=from:to") {
		t.Error("must contain h= tag with signed headers")
	}
	if !strings.HasSuffix(result, "b=") {
		t.Error("must end with b= (empty)")
	}
	// bh= must be valid base64.
	bhVal := extractTag(result+";", "bh")
	if _, err := base64.StdEncoding.DecodeString(bhVal); err != nil {
		t.Errorf("bh= is not valid base64: %v", err)
	}
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
