package config

import "time"

type Config struct {
	Server   ServerConfig   `yaml:"server"`
	TLS      TLSConfig      `yaml:"tls"`
	Relay    RelayConfig    `yaml:"relay"`
	Maildir  MaildirConfig  `yaml:"maildir"`
	Auth     AuthConfig     `yaml:"auth"`
	Security SecurityConfig `yaml:"security"`
	Logging  LoggingConfig  `yaml:"logging"`
	Queue    QueueConfig    `yaml:"queue"`
	Delivery DeliveryConfig `yaml:"delivery"`
	Cache    CacheConfig    `yaml:"cache"`
}

// ListenerMode defines how a port handles TLS
type ListenerMode string

const (
	ListenerModePlain    ListenerMode = "plain"     // no TLS (port 25)
	ListenerModeSTARTTLS ListenerMode = "starttls"  // plain + STARTTLS upgrade (port 587)
	ListenerModeTLS      ListenerMode = "tls"       // implicit TLS (port 465)
)

// ListenerConfig defines a single TCP listener
type ListenerConfig struct {
	Port int          `yaml:"port"`
	Mode ListenerMode `yaml:"mode"`
}

type ServerConfig struct {
	Bind                string           `yaml:"bind"`
	Port                int              `yaml:"port"`      // legacy single-port (used if Listeners is empty)
	Listeners           []ListenerConfig `yaml:"listeners"` // multi-port listeners
	Hostname            string           `yaml:"hostname"`
	MaxConnections      int           `yaml:"max_connections"`
	MaxConnectionsPerIP int           `yaml:"max_connections_per_ip"`
	MaxRecipients       int           `yaml:"max_recipients"`
	MaxMessageSize      int           `yaml:"max_message_size"`
	ReadTimeout         time.Duration `yaml:"read_timeout"`
	WriteTimeout        time.Duration `yaml:"write_timeout"`
	EmailValidation     []string      `yaml:"email_validation"`
	LocalDomains        []string      `yaml:"local_domains"`
	VirtualDomains      []string      `yaml:"virtual_domains"`
	RelayDomains        []string      `yaml:"relay_domains"`
	SpoolDir            string        `yaml:"spool_dir"`
	SocketPath          string        `yaml:"socket_path"`
	LocalAliasesFilePath string       `yaml:"local_aliases_file_path"`
	TrustedUsers        []string      `yaml:"trusted_users"`
}

// RelayConfig controls inbound MTA-to-MTA relay behaviour on port 25.
// TODO: add Networks ([]string, trusted CIDRs) and migrate RelayDomains here.
type RelayConfig struct {
	Enabled bool `yaml:"enabled"` // false = reject all relay-domain recipients (deny-by-default)
}

type TLSConfig struct {
	Enabled  bool   `yaml:"enabled"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

type MaildirConfig struct {
	BasePath string `yaml:"base_path"`
}

type AuthConfig struct {
	PluginChain []string                          `yaml:"plugin_chain"` // Ordered plugin chain
	Plugins     map[string]map[string]interface{} `yaml:"plugins"`
}

type SecurityConfig struct {
	ReverseDNS ReverseDNSConfig `yaml:"reverse_dns"`
	DNSBL      DNSBLConfig      `yaml:"dnsbl"`
}

type ReverseDNSConfig struct {
	Enabled      bool `yaml:"enabled"`
	RejectOnFail bool `yaml:"reject_on_fail"`
}

type DNSBLConfig struct {
	Enabled           bool     `yaml:"enabled"`
	CheckIP           bool     `yaml:"check_ip"`
	CheckSenderDomain bool     `yaml:"check_sender_domain"`
	Providers         []string `yaml:"providers"`
	Action            string   `yaml:"action"` // "reject" or "log"
}

type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

type QueueConfig struct {
	BufferSize     int           `yaml:"buffer_size"`
	MaxConsumers   int           `yaml:"max_consumers"`
	PublishTimeout time.Duration `yaml:"publish_timeout"`
	RetryDelay     time.Duration `yaml:"retry_delay"`
	MaxRetryDelay  time.Duration `yaml:"max_retry_delay"`
}

type DeliveryConfig struct {
	Local    LocalDeliveryConfig    `yaml:"local"`
	Virtual  VirtualDeliveryConfig  `yaml:"virtual"`
	Outbound OutboundDeliveryConfig `yaml:"outbound"`
}

type OutboundDeliveryConfig struct {
	MaxWorkers    int                  `yaml:"max_workers"`
	RetryInterval time.Duration        `yaml:"retry_interval"`
	RetryMaxAge   time.Duration        `yaml:"retry_max_age"`
	Timeouts      OutboundTimeouts     `yaml:"timeouts"`
	TLS           OutboundTLSConfig    `yaml:"tls"`
	DKIM          DKIMConfig           `yaml:"dkim"`
}

type DKIMConfig struct {
	Enabled        bool   `yaml:"enabled"`
	Domain         string `yaml:"domain"`
	Selector       string `yaml:"selector"`
	PrivateKeyFile string `yaml:"private_key_file"`
}

type OutboundTimeouts struct {
	Dial         time.Duration `yaml:"dial"`
	Greeting     time.Duration `yaml:"greeting"`
	Command      time.Duration `yaml:"command"`
	TLSHandshake time.Duration `yaml:"tls_handshake"`
	DataTransfer time.Duration `yaml:"data_transfer"`
}

type OutboundTLSConfig struct {
	Policy     string `yaml:"policy"`      // "opportunistic" | "required"
	MinVersion string `yaml:"min_version"` // "tls12" | "tls13"
	SkipVerify bool   `yaml:"skip_verify"` // false by default; test environments only
}

type LocalDeliveryConfig struct {
	BaseDirPath string `yaml:"base_dir_path"`
	MaxWorkers  int    `yaml:"max_workers"`
}

type VirtualDeliveryConfig struct {
	BaseDirPath string `yaml:"base_dir_path"`
	MaxWorkers  int    `yaml:"max_workers"`
}

type CacheConfig struct {
	SystemUsers  UserCacheConfig `yaml:"system_users"`
	VirtualUsers UserCacheConfig `yaml:"virtual_users"`
}

type UserCacheConfig struct {
	Capacity int           `yaml:"capacity"`
	TTL      time.Duration `yaml:"ttl"`
}

type UserConfig struct {
	Username string   `yaml:"username"`
	Password string   `yaml:"password"`
	Aliases  []string `yaml:"aliases,omitempty"`
}

func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Bind: "127.0.0.1",
			Port: 2525, // legacy fallback
			Listeners: []ListenerConfig{
				{Port: 2525, Mode: ListenerModePlain},
			},
			Hostname:            "localhost",
			MaxConnections:      10000,
			MaxConnectionsPerIP: 1000,
			MaxRecipients:       1000,             // RFC 5321 recommends 1000+ for production
			MaxMessageSize:      10 * 1024 * 1024, // 10MB
			ReadTimeout:         30 * time.Second,
			WriteTimeout:        30 * time.Second,
			EmailValidation:     []string{"basic"},
			LocalDomains:        []string{"localhost"},      // System users
			VirtualDomains:      []string{"mail.localhost"}, // Virtual users
			RelayDomains:        []string{},                 // No relay by default
			SpoolDir:            "/var/spool/golubsmtpd",
			SocketPath:          "/var/run/golubsmtpd/golubsmtpd.sock",
			LocalAliasesFilePath: "/etc/aliases",
			TrustedUsers:        []string{"root", "mail", "daemon"},
		},
		TLS: TLSConfig{
			Enabled: false,
		},
		Relay: RelayConfig{
			Enabled: false,
		},
		Maildir: MaildirConfig{
			BasePath: "/var/mail",
		},
		Auth: AuthConfig{
			PluginChain: []string{"memory"}, // Default single plugin
			Plugins:     make(map[string]map[string]interface{}),
		},
		Security: SecurityConfig{
			ReverseDNS: ReverseDNSConfig{
				Enabled:      true,
				RejectOnFail: false,
			},
			DNSBL: DNSBLConfig{
				Enabled:           true,
				CheckIP:           true,
				CheckSenderDomain: true,
				Providers: []string{
					"zen.spamhaus.org",
					"bl.spamcop.net",
					"dnsbl.sorbs.net",
				},
				Action: "log",
			},
		},
		Logging: LoggingConfig{
			Level:  "info",
			Format: "text",
		},
		Queue: QueueConfig{
			BufferSize:   1000,
			MaxConsumers: 10,
		},
		Delivery: DeliveryConfig{
			Local: LocalDeliveryConfig{
				MaxWorkers: 10,
			},
			Outbound: OutboundDeliveryConfig{
				MaxWorkers:    10,
				RetryInterval: 30 * time.Minute,
				RetryMaxAge:   5 * 24 * time.Hour,
				Timeouts: OutboundTimeouts{
					Dial:         10 * time.Second,
					Greeting:     30 * time.Second,
					Command:      30 * time.Second,
					TLSHandshake: 15 * time.Second,
					DataTransfer: 5 * time.Minute,
				},
				TLS: OutboundTLSConfig{
					Policy:     "opportunistic",
					MinVersion: "tls12",
					SkipVerify: false,
				},
			},
			Virtual: VirtualDeliveryConfig{
				BaseDirPath: "/var/mail/virtual",
				MaxWorkers:  10,
			},
		},
		Cache: CacheConfig{
			SystemUsers: UserCacheConfig{
				Capacity: 100,
				TTL:      2 * time.Minute,
			},
			VirtualUsers: UserCacheConfig{
				Capacity: 10000,
				TTL:      2 * time.Minute,
			},
		},
	}
}
