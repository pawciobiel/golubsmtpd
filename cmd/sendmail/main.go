package main

import (
	"bufio"
	"flag"
	"fmt"
	"io"
	"net"
	"net/textproto"
	"os"
	"strings"
	"time"
)

const (
	defaultSocketPath = "/var/run/golubsmtpd/golubsmtpd.sock"
)

// SendmailArgs represents parsed command line arguments
type SendmailArgs struct {
	SocketPath string
	From       string
	To         []string
	ReadTo     bool
	Verbose    bool
}

func main() {
	args, err := parseArgs()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	if args.Verbose {
		fmt.Fprintf(os.Stderr, "sendmail: connecting to %s\n", args.SocketPath)
	}

	// Read message from stdin
	message, err := readMessage(os.Stdin)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error reading message: %v\n", err)
		os.Exit(1)
	}

	// Parse recipients from message if -t flag is used
	if args.ReadTo {
		recipients, cleanMessage := extractRecipients(message)
		args.To = append(args.To, recipients...)
		message = cleanMessage
	}

	if len(args.To) == 0 {
		fmt.Fprintf(os.Stderr, "Error: No recipients specified\n")
		os.Exit(1)
	}

	// Connect to socket and send message
	if err := sendMessage(args, message); err != nil {
		fmt.Fprintf(os.Stderr, "Error sending message: %v\n", err)
		os.Exit(1)
	}

	if args.Verbose {
		fmt.Fprintf(os.Stderr, "sendmail: message sent successfully\n")
	}
}

// parseArgs parses command line arguments in sendmail-compatible format
func parseArgs() (*SendmailArgs, error) {
	args := &SendmailArgs{
		SocketPath: defaultSocketPath,
		To:         make([]string, 0),
	}

	// Define flags
	flag.StringVar(&args.SocketPath, "socket", defaultSocketPath, "Path to golubsmtpd socket")
	flag.StringVar(&args.From, "f", "", "Set sender address")
	flag.StringVar(&args.From, "from", "", "Set sender address (alias for -f)")
	flag.BoolVar(&args.ReadTo, "t", false, "Read recipients from message headers")
	flag.BoolVar(&args.Verbose, "v", false, "Verbose output")

	// Custom usage
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Usage: %s [options] recipient...\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "\nOptions:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExample:\n")
		fmt.Fprintf(os.Stderr, "  echo 'Hello World' | %s user@example.com\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "  %s -f sender@example.com -t < message.txt\n", os.Args[0])
	}

	flag.Parse()

	// Remaining arguments are recipients
	args.To = append(args.To, flag.Args()...)

	// Set default sender if not specified
	if args.From == "" {
		// Get current user as default sender
		if user := os.Getenv("USER"); user != "" {
			hostname, _ := os.Hostname()
			if hostname == "" {
				hostname = "localhost"
			}
			args.From = user + "@" + hostname
		}
	}

	return args, nil
}

// readMessage reads the entire message from stdin
func readMessage(reader io.Reader) (string, error) {
	var builder strings.Builder
	scanner := bufio.NewScanner(reader)

	for scanner.Scan() {
		builder.WriteString(scanner.Text())
		builder.WriteString("\r\n") // SMTP requires CRLF
	}

	if err := scanner.Err(); err != nil {
		return "", fmt.Errorf("error reading input: %w", err)
	}

	return builder.String(), nil
}

// extractRecipients parses To:, Cc:, Bcc: headers from message and returns recipients and cleaned message
func extractRecipients(message string) ([]string, string) {
	lines := strings.Split(message, "\r\n")
	recipients := make([]string, 0)
	cleanLines := make([]string, 0)
	inHeaders := true

	for _, line := range lines {
		// Empty line indicates end of headers
		if inHeaders && line == "" {
			inHeaders = false
			cleanLines = append(cleanLines, line)
			continue
		}

		if inHeaders {
			// Parse recipient headers
			if strings.HasPrefix(strings.ToLower(line), "to:") {
				recipients = append(recipients, parseAddressLine(line[3:])...)
			} else if strings.HasPrefix(strings.ToLower(line), "cc:") {
				recipients = append(recipients, parseAddressLine(line[3:])...)
			} else if strings.HasPrefix(strings.ToLower(line), "bcc:") {
				recipients = append(recipients, parseAddressLine(line[4:])...)
				continue // Remove Bcc: header from message
			}
		}

		cleanLines = append(cleanLines, line)
	}

	return recipients, strings.Join(cleanLines, "\r\n")
}

// parseAddressLine parses email addresses from a header line
func parseAddressLine(line string) []string {
	addresses := make([]string, 0)
	// Simple parsing - split by comma and clean up
	parts := strings.Split(line, ",")
	for _, part := range parts {
		addr := strings.TrimSpace(part)
		// Extract email from "Name <email>" format
		if idx := strings.LastIndex(addr, "<"); idx != -1 {
			if endIdx := strings.Index(addr[idx:], ">"); endIdx != -1 {
				addr = addr[idx+1 : idx+endIdx]
			}
		}
		addr = strings.TrimSpace(addr)
		if addr != "" {
			addresses = append(addresses, addr)
		}
	}
	return addresses
}

// sendMessage connects to the socket and sends the message using simplified SMTP
func sendMessage(args *SendmailArgs, message string) error {
	// Connect to Unix domain socket
	conn, err := net.DialTimeout("unix", args.SocketPath, 10*time.Second)
	if err != nil {
		return fmt.Errorf("failed to connect to socket %s: %w", args.SocketPath, err)
	}
	defer conn.Close()

	// Set timeouts
	conn.SetDeadline(time.Now().Add(30 * time.Second))

	// Create textproto connection for SMTP communication
	textConn := textproto.NewConn(conn)
	defer textConn.Close()

	if args.Verbose {
		fmt.Fprintf(os.Stderr, "sendmail: connected to socket\n")
	}

	// Send MAIL FROM command
	mailCmd := fmt.Sprintf("MAIL FROM:<%s>", args.From)
	if args.Verbose {
		fmt.Fprintf(os.Stderr, "sendmail: > %s\n", mailCmd)
	}

	if err := textConn.PrintfLine("%s", mailCmd); err != nil {
		return fmt.Errorf("failed to send MAIL command: %w", err)
	}

	// Read response
	if _, err := readResponse(textConn, args.Verbose); err != nil {
		return fmt.Errorf("MAIL FROM failed: %w", err)
	}

	// Send RCPT TO commands for each recipient
	for _, recipient := range args.To {
		rcptCmd := fmt.Sprintf("RCPT TO:<%s>", recipient)
		if args.Verbose {
			fmt.Fprintf(os.Stderr, "sendmail: > %s\n", rcptCmd)
		}

		if err := textConn.PrintfLine("%s", rcptCmd); err != nil {
			return fmt.Errorf("failed to send RCPT command: %w", err)
		}

		if _, err := readResponse(textConn, args.Verbose); err != nil {
			return fmt.Errorf("RCPT TO failed for %s: %w", recipient, err)
		}
	}

	// Send DATA command
	if args.Verbose {
		fmt.Fprintf(os.Stderr, "sendmail: > DATA\n")
	}

	if err := textConn.PrintfLine("DATA"); err != nil {
		return fmt.Errorf("failed to send DATA command: %w", err)
	}

	// Read 354 response
	response, err := readResponse(textConn, args.Verbose)
	if err != nil {
		return fmt.Errorf("DATA command failed: %w", err)
	}
	if !strings.HasPrefix(response, "354") {
		return fmt.Errorf("unexpected DATA response: %s", response)
	}

	// Send message data
	if args.Verbose {
		fmt.Fprintf(os.Stderr, "sendmail: sending message data (%d bytes)\n", len(message))
	}

	// Send message followed by termination sequence
	if err := textConn.PrintfLine("%s", message); err != nil {
		return fmt.Errorf("failed to send message data: %w", err)
	}

	if err := textConn.PrintfLine("."); err != nil {
		return fmt.Errorf("failed to send message termination: %w", err)
	}

	// Read final response
	if _, err := readResponse(textConn, args.Verbose); err != nil {
		return fmt.Errorf("message transmission failed: %w", err)
	}

	// Send QUIT
	if args.Verbose {
		fmt.Fprintf(os.Stderr, "sendmail: > QUIT\n")
	}

	textConn.PrintfLine("QUIT")
	readResponse(textConn, args.Verbose) // Don't fail on QUIT response

	return nil
}

// readResponse reads and validates SMTP response
func readResponse(conn *textproto.Conn, verbose bool) (string, error) {
	response, err := conn.ReadLine()
	if err != nil {
		return "", err
	}

	if verbose {
		fmt.Fprintf(os.Stderr, "sendmail: < %s\n", response)
	}

	// Check if response indicates success (2xx or 3xx)
	if len(response) >= 3 {
		code := response[:3]
		if strings.HasPrefix(code, "2") || strings.HasPrefix(code, "3") {
			return response, nil
		}
	}

	return response, fmt.Errorf("SMTP error: %s", response)
}
