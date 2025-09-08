package config

import "time"

type Config struct {
	Server   ServerConfig   `yaml:"server"`
	TLS      TLSConfig      `yaml:"tls"`
	Maildir  MaildirConfig  `yaml:"maildir"`
	Auth     AuthConfig     `yaml:"auth"`
	Security SecurityConfig `yaml:"security"`
	Logging  LoggingConfig  `yaml:"logging"`
	Queue    QueueConfig    `yaml:"queue"`
	Delivery DeliveryConfig `yaml:"delivery"`
	Cache    CacheConfig    `yaml:"cache"`
}

type ServerConfig struct {
	Bind                string        `yaml:"bind"`
	Port                int           `yaml:"port"`
	Hostname            string        `yaml:"hostname"`
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
	BufferSize   int `yaml:"buffer_size"`
	MaxConsumers int `yaml:"max_consumers"`
}

type DeliveryConfig struct {
	Local   LocalDeliveryConfig   `yaml:"local"`
	Virtual VirtualDeliveryConfig `yaml:"virtual"`
}

type LocalDeliveryConfig struct {
	MaxWorkers int `yaml:"max_workers"`
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
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Bind:                "127.0.0.1",
			Port:                2525,
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
		},
		TLS: TLSConfig{
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
