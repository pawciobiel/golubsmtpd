package smtp

import (
	"github.com/pawciobiel/golubsmtpd/internal/aliases"
	"github.com/pawciobiel/golubsmtpd/internal/auth"
	"github.com/pawciobiel/golubsmtpd/internal/queue"
)

type Dependencies struct {
	Authenticator    auth.Authenticator
	Queue            *queue.Queue
	LocalAliasesMaps *aliases.LocalAliasesMaps
}