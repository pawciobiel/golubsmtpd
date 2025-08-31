package storage

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"

	"github.com/pawciobiel/golubsmtpd/internal/config"
	"github.com/pawciobiel/golubsmtpd/internal/queue"
)

// InitializeSpoolDirectories creates all required spool directories with secure permissions
func InitializeSpoolDirectories(spoolDir string) error {
	for _, state := range queue.GetRequiredSpoolDirectories() {
		dir := filepath.Join(spoolDir, string(state))
		if err := os.MkdirAll(dir, 0700); err != nil {
			return fmt.Errorf("failed to create spool directory %s: %w", dir, err)
		}
	}
	return nil
}

// StreamEmailContent streams email content directly to disk using chunked reading
//
// Storage layer responsibilities:
// - Stream raw email data to disk atomically (no MIME parsing)
// - Handle SMTP protocol (dot-stuffing, DATA termination)
// - Validate file integrity and proper CRLF endings
// - Secure file permissions and cleanup on errors
//
// # MIME parsing and content validation are handled in the message processing phase
//
// Returns the total bytes written
// Message.ID must already be set by the caller
func StreamEmailContent(ctx context.Context, cfg *config.Config, message *queue.Message, reader io.Reader) (int64, error) {
	// Use message's standardized filename
	filename := message.Filename()

	incomingDir := filepath.Join(cfg.Server.SpoolDir, string(queue.MessageStateIncoming))
	tempFile := filepath.Join(incomingDir, filename+".tmp")
	finalFile := filepath.Join(incomingDir, filename)

	// Check for context cancellation before starting
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	default:
	}

	// Create temporary file with secure permissions (0600 = rw-------)
	file, err := os.OpenFile(tempFile, os.O_CREATE|os.O_RDWR|os.O_EXCL, 0600)
	if err != nil {
		return 0, fmt.Errorf("failed to create temporary file %s: %w", tempFile, err)
	}

	// Ensure cleanup of temporary file on error
	defer func() {
		file.Close()
		// If final file doesn't exist, we failed - clean up temp file
		if _, err := os.Stat(finalFile); os.IsNotExist(err) {
			os.Remove(tempFile)
		}
	}()

	// Stream SMTP DATA with chunked reading and SMTP protocol handling
	totalSize, err := streamSMTPData(ctx, file, reader, cfg.Server.MaxMessageSize)
	if err != nil {
		return totalSize, fmt.Errorf("failed to stream SMTP data: %w", err)
	}

	// TODO: Add line length validation if needed for security

	// Check for completely empty message file
	if totalSize == 0 {
		return 0, fmt.Errorf("empty message file")
	}

	// Force data to disk (critical for atomicity)
	if err := file.Sync(); err != nil {
		return totalSize, fmt.Errorf("failed to sync file to disk: %w", err)
	}

	// Close file before rename
	if err := file.Close(); err != nil {
		return totalSize, fmt.Errorf("failed to close file: %w", err)
	}

	// Check for context cancellation before final rename
	select {
	case <-ctx.Done():
		return totalSize, ctx.Err()
	default:
	}

	// Atomic rename - this is the critical moment of persistence
	if err := os.Rename(tempFile, finalFile); err != nil {
		return totalSize, fmt.Errorf("failed to atomically rename file: %w", err)
	}

	return totalSize, nil
}

// streamSMTPData handles SMTP DATA protocol with chunked reading
func streamSMTPData(ctx context.Context, file *os.File, ioreader io.Reader, maxSize int) (int64, error) {
	terminator := []byte("\r\n.\r\n")
	maxMessageSize := int64(maxSize)
	tail := []byte{}
	buf := make([]byte, 1024)
	reader := bufio.NewReader(ioreader)
	var totalWritten int64

	for {
		// Check for context cancellation
		select {
		case <-ctx.Done():
			return totalWritten, ctx.Err()
		default:
		}
		n, err := reader.Read(buf)
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			return totalWritten, fmt.Errorf("timeout waiting for terminator")
		}
		if n > 0 {
			chunk := buf[:n]
			searchBuf := append(tail, chunk...)
			if idx := bytes.Index(searchBuf, terminator); idx != -1 {
				// Found terminator \r\n.\r\n → write message data up to it
				messageData := searchBuf[:idx]

				// Check message size limit before writing final chunk
				if maxMessageSize > 0 && totalWritten+int64(len(messageData))+2 > maxMessageSize {
					return totalWritten, fmt.Errorf("message size exceeds limit of %d bytes", maxMessageSize)
				}

				written, err := file.Write(messageData)
				if err != nil {
					return totalWritten, fmt.Errorf("failed to write to file: %w", err)
				}
				totalWritten += int64(written)

				// Append CRLF since searchBuf[:idx] excludes the \r\n before the dot
				// This ensures proper SMTP message termination
				crlfWritten, err := file.Write([]byte("\r\n"))
				if err != nil {
					return totalWritten, fmt.Errorf("failed to write CRLF: %w", err)
				}
				totalWritten += int64(crlfWritten)
				break
			}
			if len(searchBuf) > len(terminator) {
				flushUpto := len(searchBuf) - len(terminator)

				// Check message size limit before writing
				lineData := searchBuf[:flushUpto]
				if maxMessageSize > 0 && totalWritten+int64(len(lineData)) > maxMessageSize {
					return totalWritten, fmt.Errorf("message size exceeds limit of %d bytes", maxMessageSize)
				}

				written, err := file.Write(lineData)
				if err != nil {
					return totalWritten, fmt.Errorf("failed to write to file: %w %s", err, file.Name())
				}
				totalWritten += int64(written)
				tail = searchBuf[flushUpto:]
			} else {
				tail = searchBuf
			}
		}
		if err != nil {
			if err == io.EOF {
				err = nil
				break
			} else {
				return totalWritten, err
			}
		}
	}
	return totalWritten, nil
}
