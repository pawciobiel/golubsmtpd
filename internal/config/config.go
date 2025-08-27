package config

import "time"

type Config struct {
	Server   ServerConfig            `yaml:"server"`
	TLS      TLSConfig              `yaml:"tls"`
	Maildir  MaildirConfig          `yaml:"maildir"`
	Auth     AuthConfig             `yaml:"auth"`
	Security SecurityConfig         `yaml:"security"`
	Logging  LoggingConfig          `yaml:"logging"`
}

type ServerConfig struct {
	Bind                string        `yaml:"bind"`
	Port                int           `yaml:"port"`
	Hostname            string        `yaml:"hostname"`
	MaxConnections      int           `yaml:"max_connections"`
	MaxConnectionsPerIP int           `yaml:"max_connections_per_ip"`
	ReadTimeout         time.Duration `yaml:"read_timeout"`
	WriteTimeout        time.Duration `yaml:"write_timeout"`
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
	Plugin  string                            `yaml:"plugin"`
	Plugins map[string]map[string]interface{} `yaml:"plugins"`
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

func DefaultConfig() *Config {
	return &Config{
		Server: ServerConfig{
			Bind:                "127.0.0.1",
			Port:                2525,
			Hostname:            "localhost",
			MaxConnections:      10000,
			MaxConnectionsPerIP: 1000,
			ReadTimeout:         30 * time.Second,
			WriteTimeout:        30 * time.Second,
		},
		TLS: TLSConfig{
			Enabled: false,
		},
		Maildir: MaildirConfig{
			BasePath: "/var/mail",
		},
		Auth: AuthConfig{
			Plugin:  "file",
			Plugins: make(map[string]map[string]interface{}),
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
	}
}