package delivery

import (
	"fmt"
	"strings"
	"time"

	"github.com/pawciobiel/golubsmtpd/internal/types"
)

// GenerateDSN creates an RFC 3464 delivery status notification addressed to the
// original sender. Returns a Message with RawBody set, ready to be written to spool.
// The bounce uses a null reverse-path (<>) per RFC 5321 §4.5.5.
func GenerateDSN(original *types.Message, failedRecipients []string, reason, localHostname string) *types.Message {
	now := time.Now().UTC()
	msgID := types.GenerateID()
	timestamp := now.Format("Mon, 02 Jan 2006 15:04:05 -0000")
	boundary := msgID

	var sb strings.Builder

	// RFC 2822 headers
	fmt.Fprintf(&sb, "From: Mail Delivery Subsystem <mailer-daemon@%s>\r\n", localHostname)
	fmt.Fprintf(&sb, "To: %s\r\n", original.From)
	fmt.Fprintf(&sb, "Subject: Delivery Status Notification (Failure)\r\n")
	fmt.Fprintf(&sb, "Date: %s\r\n", timestamp)
	fmt.Fprintf(&sb, "Message-ID: <%s@%s>\r\n", msgID, localHostname)
	fmt.Fprintf(&sb, "MIME-Version: 1.0\r\n")
	fmt.Fprintf(&sb, "Content-Type: multipart/report; report-type=delivery-status;\r\n\tboundary=%q\r\n", boundary)
	fmt.Fprintf(&sb, "Auto-Submitted: auto-replied\r\n")
	fmt.Fprintf(&sb, "\r\n")

	// Part 1: human-readable explanation
	fmt.Fprintf(&sb, "--%s\r\n", boundary)
	fmt.Fprintf(&sb, "Content-Type: text/plain; charset=utf-8\r\n\r\n")
	fmt.Fprintf(&sb, "This is the mail delivery agent at %s.\r\n\r\n", localHostname)
	fmt.Fprintf(&sb, "Your message could not be delivered to the following recipients:\r\n\r\n")
	for _, r := range failedRecipients {
		fmt.Fprintf(&sb, "  <%s>\r\n", r)
	}
	fmt.Fprintf(&sb, "\r\nReason: %s\r\n\r\n", reason)

	// Part 2: RFC 3464 machine-readable delivery status
	fmt.Fprintf(&sb, "--%s\r\n", boundary)
	fmt.Fprintf(&sb, "Content-Type: message/delivery-status\r\n\r\n")
	fmt.Fprintf(&sb, "Reporting-MTA: dns; %s\r\n", localHostname)
	fmt.Fprintf(&sb, "Arrival-Date: %s\r\n\r\n", original.Created.UTC().Format("Mon, 02 Jan 2006 15:04:05 -0000"))
	for _, r := range failedRecipients {
		fmt.Fprintf(&sb, "Final-Recipient: rfc822; %s\r\n", r)
		fmt.Fprintf(&sb, "Action: failed\r\n")
		fmt.Fprintf(&sb, "Status: 5.0.0\r\n")
		fmt.Fprintf(&sb, "Diagnostic-Code: smtp; %s\r\n\r\n", reason)
	}

	// Part 3: original message headers only (not the full body per RFC 3464 §5)
	fmt.Fprintf(&sb, "--%s\r\n", boundary)
	fmt.Fprintf(&sb, "Content-Type: message/rfc822\r\n\r\n")
	fmt.Fprintf(&sb, "From: %s\r\n", original.From)
	fmt.Fprintf(&sb, "Message-ID: <%s@%s>\r\n", original.ID, localHostname)
	fmt.Fprintf(&sb, "Date: %s\r\n\r\n", original.Created.UTC().Format("Mon, 02 Jan 2006 15:04:05 -0000"))

	fmt.Fprintf(&sb, "--%s--\r\n", boundary)

	bounce := &types.Message{
		ID:      msgID,
		From:    "", // null reverse-path per RFC 5321 §4.5.5
		Created: now,
		// DSN is delivered locally to the original sender
		LocalRecipients: map[string]struct{}{original.From: {}},
		RawBody:         sb.String(),
	}
	return bounce
}
