package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	SMTP     SMTPConfig     `yaml:"smtp"`
	Delivery DeliveryConfig `yaml:"delivery"`
	Queue    QueueConfig    `yaml:"queue"`
	API      APIConfig      `yaml:"api"`
	Logging  LoggingConfig  `yaml:"logging"`
}

type SMTPConfig struct {
	ListenAddr     string     `yaml:"listen_addr"`
	Domain         string     `yaml:"domain"`
	TLS            TLSConfig  `yaml:"tls"`
	Auth           AuthConfig `yaml:"auth"`
	MaxMessageSize int64      `yaml:"max_message_size"`
}

type TLSConfig struct {
	Enabled  bool   `yaml:"enabled"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
}

type AuthConfig struct {
	Users []UserConfig `yaml:"users"`
}

type UserConfig struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type DeliveryConfig struct {
	Workers        int        `yaml:"workers"`
	MaxRetries     int        `yaml:"max_retries"`
	RetryInterval  string     `yaml:"retry_interval"`
	ConnectTimeout string     `yaml:"connect_timeout"`
	SendTimeout    string     `yaml:"send_timeout"`
	HeloName       string     `yaml:"helo_name"`
	DKIM           DKIMConfig `yaml:"dkim"`
}

type DKIMConfig struct {
	Enabled        bool   `yaml:"enabled"`
	Selector       string `yaml:"selector"`
	PrivateKeyFile string `yaml:"private_key_file"`
	Domain         string `yaml:"domain"`
}

type QueueConfig struct {
	Dir string `yaml:"dir"`
}

type APIConfig struct {
	ListenAddr string `yaml:"listen_addr"`
	AuthToken  string `yaml:"auth_token"`
}

type LoggingConfig struct {
	Level string `yaml:"level"`
}

// Load reads and parses the YAML config file at path.
func Load(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := &Config{}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		return nil, err
	}
	applyDefaults(cfg)
	return cfg, nil
}

// Default returns a configuration with sensible defaults (no file needed).
func Default() *Config {
	cfg := &Config{}
	applyDefaults(cfg)
	return cfg
}

func applyDefaults(cfg *Config) {
	if cfg.SMTP.ListenAddr == "" {
		cfg.SMTP.ListenAddr = ":587"
	}
	if cfg.SMTP.Domain == "" {
		cfg.SMTP.Domain = "localhost"
	}
	if cfg.SMTP.MaxMessageSize == 0 {
		cfg.SMTP.MaxMessageSize = 26214400
	}
	if cfg.Delivery.Workers == 0 {
		cfg.Delivery.Workers = 5
	}
	if cfg.Delivery.MaxRetries == 0 {
		cfg.Delivery.MaxRetries = 5
	}
	if cfg.Delivery.RetryInterval == "" {
		cfg.Delivery.RetryInterval = "5m"
	}
	if cfg.Delivery.ConnectTimeout == "" {
		cfg.Delivery.ConnectTimeout = "30s"
	}
	if cfg.Delivery.SendTimeout == "" {
		cfg.Delivery.SendTimeout = "5m"
	}
	if cfg.Delivery.HeloName == "" {
		cfg.Delivery.HeloName = cfg.SMTP.Domain
	}
	if cfg.Queue.Dir == "" {
		cfg.Queue.Dir = "queue"
	}
	if cfg.API.ListenAddr == "" {
		cfg.API.ListenAddr = ":8080"
	}
}
