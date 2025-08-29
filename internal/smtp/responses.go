package smtp

import "fmt"

// SMTP response codes and messages following RFC 5321
const (
	// Positive completion replies (2xx)
	StatusReady       = 220
	StatusClosing     = 221
	StatusOK          = 250
	StatusAuthSuccess = 235

	// Positive intermediate replies (3xx)
	StatusStartMailInput = 354
	StatusAuthChallenge  = 334

	// Transient negative completion replies (4xx)
	StatusTempFailure         = 421
	StatusMailboxBusy         = 450
	StatusLocalError          = 451
	StatusInsufficientStorage = 452

	// Permanent negative completion replies (5xx)
	StatusSyntaxError       = 500
	StatusParamError        = 501
	StatusCommandNotImpl    = 502
	StatusBadSequence       = 503
	StatusParamNotImpl      = 504
	StatusNotAuthorized     = 530
	StatusAuthRequired      = 535
	StatusMailboxUnavailable = 550
	StatusUserNotLocal      = 551
	StatusExceededStorage   = 552
	StatusMailboxName       = 553
	StatusTransactionFailed = 554
)

// Standard SMTP response messages
var ResponseMessages = map[int]string{
	StatusReady:               "Service ready",
	StatusClosing:             "Service closing transmission channel",
	StatusOK:                  "Requested mail action okay, completed",
	StatusAuthSuccess:         "Authentication successful",
	StatusStartMailInput:      "Start mail input; end with <CRLF>.<CRLF>",
	StatusAuthChallenge:       "Auth challenge",
	StatusTempFailure:         "Service not available, closing transmission channel",
	StatusMailboxBusy:         "Requested mail action not taken: mailbox unavailable",
	StatusLocalError:          "Requested action aborted: local error in processing",
	StatusInsufficientStorage: "Requested action not taken: insufficient system storage",
	StatusSyntaxError:         "Syntax error, command unrecognized",
	StatusParamError:          "Syntax error in parameters or arguments",
	StatusCommandNotImpl:      "Command not implemented",
	StatusBadSequence:         "Bad sequence of commands",
	StatusParamNotImpl:        "Command parameter not implemented",
	StatusNotAuthorized:       "Access denied",
	StatusAuthRequired:        "Authentication credentials invalid",
	StatusMailboxUnavailable:  "Requested action not taken: mailbox unavailable",
	StatusUserNotLocal:        "User not local",
	StatusExceededStorage:     "Requested mail action aborted: exceeded storage allocation",
	StatusMailboxName:         "Requested action not taken: mailbox name not allowed",
	StatusTransactionFailed:   "Transaction failed",
}

// Response builds a properly formatted SMTP response
func Response(code int, message string) string {
	if message == "" {
		if msg, ok := ResponseMessages[code]; ok {
			message = msg
		} else {
			message = "Unknown response"
		}
	}
	return fmt.Sprintf("%d %s", code, message)
}

// ResponseWithHostname builds a response including hostname (for greeting)
func ResponseWithHostname(code int, hostname, message string) string {
	if message == "" {
		message = ResponseMessages[code]
	}
	return fmt.Sprintf("%d %s %s", code, hostname, message)
}
