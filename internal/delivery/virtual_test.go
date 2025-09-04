package delivery

import (
	"context"
	"path/filepath"
	"testing"
)

func TestDeliverToVirtualUser(t *testing.T) {
	ts := newTestSetup(t, "virtual-msg-789")
	virtualRoot := ts.setupVirtualDelivery(t)
	recipient := "testuser@testdomain.com"

	err := DeliverToVirtualUser(context.Background(), ts.msg, ts.testMessagePath, recipient, virtualRoot)
	if err != nil {
		t.Fatalf("DeliverToVirtualUser failed: %v", err)
	}

	// Verify virtual-specific path structure: virtualRoot/domain/username/Maildir
	maildirBase := filepath.Join(virtualRoot, "testdomain.com", "testuser", "Maildir")
	verifyMaildirStructure(t, maildirBase)
	verifyDeliveredMessage(t, filepath.Join(maildirBase, "new"), ts.testContent, ts.msg.ID)
}

func TestDeliverToVirtualUser_MultipleDomains(t *testing.T) {
	ts := newTestSetup(t, "multi-domain-123")
	virtualRoot := ts.setupVirtualDelivery(t)

	recipients := []string{
		"alice@company.com",
		"bob@company.com",
		"charlie@different.org",
	}

	// Deliver to multiple virtual users across different domains
	for _, recipient := range recipients {
		err := DeliverToVirtualUser(context.Background(), ts.msg, ts.testMessagePath, recipient, virtualRoot)
		if err != nil {
			t.Fatalf("DeliverToVirtualUser failed for %s: %v", recipient, err)
		}
	}

	// Verify domain-specific directory structure was created
	expectedPaths := map[string]string{
		"alice@company.com":     "company.com/alice/Maildir",
		"bob@company.com":       "company.com/bob/Maildir",
		"charlie@different.org": "different.org/charlie/Maildir",
	}

	for email, relativePath := range expectedPaths {
		maildirBase := filepath.Join(virtualRoot, relativePath)
		verifyMaildirStructure(t, maildirBase)
		verifyDeliveredMessage(t, filepath.Join(maildirBase, "new"), ts.testContent, ts.msg.ID)
		t.Logf("Verified delivery for %s", email)
	}
}

func TestGetVirtualMaildirPath(t *testing.T) {
	tests := []struct {
		email       string
		virtualRoot string
		expected    string
	}{
		{
			email:       "user@domain.com",
			virtualRoot: "/var/mail/virtual",
			expected:    "/var/mail/virtual/domain.com/user/Maildir/new",
		},
		{
			email:       "test.user@sub.example.org",
			virtualRoot: "/tmp/mail",
			expected:    "/tmp/mail/sub.example.org/test.user/Maildir/new",
		},
		{
			email:       "special+tag@multi-word.co.uk",
			virtualRoot: "/custom/path",
			expected:    "/custom/path/multi-word.co.uk/special+tag/Maildir/new",
		},
	}

	for _, tt := range tests {
		got := GetVirtualMaildirPath(tt.email, tt.virtualRoot)
		if got != tt.expected {
			t.Errorf("GetVirtualMaildirPath(%q, %q) = %q, want %q",
				tt.email, tt.virtualRoot, got, tt.expected)
		}
	}
}
