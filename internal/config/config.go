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
	Admin    AdminConfig    `yaml:"admin"`
	Web      WebConfig      `yaml:"web"`
	Database DatabaseConfig `yaml:"database"`
	Logging  LoggingConfig  `yaml:"logging"`
}

// DatabaseConfig supports SQLite (default) or MySQL.
type DatabaseConfig struct {
	Driver   string `yaml:"driver"`   // "sqlite" or "mysql"
	Path     string `yaml:"path"`     // SQLite: file path (e.g. smtp-server.db)
	Host     string `yaml:"host"`     // MySQL: host
	Port     int    `yaml:"port"`     // MySQL: port (default 3306)
	User     string `yaml:"user"`     // MySQL: username
	Password string `yaml:"password"`  // MySQL: password
	Database string `yaml:"database"` // MySQL: database name
	Charset  string `yaml:"charset"`  // MySQL: charset (default utf8mb4)
}

type AdminConfig struct {
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type WebConfig struct {
	ListenAddr string `yaml:"listen_addr"`
	SecretKey  string `yaml:"secret_key"`
	DBPath     string `yaml:"db_path"`
}

type SMTPConfig struct {
	ListenAddr     string     `yaml:"listen_addr"`
	Domain         string     `yaml:"domain"`
	TLS            TLSConfig  `yaml:"tls"`
	Auth           AuthConfig `yaml:"auth"`
	MaxMessageSize int64      `yaml:"max_message_size"`
	VerboseLog     bool       `yaml:"verbose_log"` // when true, log every MAIL/RCPT/DATA; when false, only errors
}

type TLSConfig struct {
	Enabled  bool   `yaml:"enabled"`
	CertFile string `yaml:"cert_file"`
	KeyFile  string `yaml:"key_file"`
	// Mode: "starttls" (plain SMTP + STARTTLS upgrade, port 587) or
	//       "implicit"  (SSL/TLS from first byte, port 465)
	// Default is "starttls".
	Mode string `yaml:"mode"`
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
	VerboseLog     bool       `yaml:"verbose_log"` // when true, log every delivery step; when false, only errors
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
	if cfg.Admin.Username == "" {
		cfg.Admin.Username = "admin"
	}
	if cfg.Admin.Password == "" {
		cfg.Admin.Password = "admin123"
	}
	if cfg.Web.ListenAddr == "" {
		cfg.Web.ListenAddr = ":8090"
	}
	if cfg.Web.SecretKey == "" {
		cfg.Web.SecretKey = "change-this-32-char-secret-key!!"
	}
	if cfg.Web.DBPath == "" {
		cfg.Web.DBPath = "smtp-server.db"
	}
	if cfg.Database.Driver == "" {
		cfg.Database.Driver = "sqlite"
	}
	if cfg.Database.Path == "" && cfg.Database.Driver == "sqlite" {
		cfg.Database.Path = cfg.Web.DBPath
	}
	if cfg.Database.Driver == "mysql" {
		if cfg.Database.Host == "" {
			cfg.Database.Host = "localhost"
		}
		if cfg.Database.Port == 0 {
			cfg.Database.Port = 3306
		}
		if cfg.Database.Charset == "" {
			cfg.Database.Charset = "utf8mb4"
		}
	}
	// Verbose logging: level "debug" or "verbose" = full per-message logs; "info" (default) = quiet (errors only)
	if cfg.Logging.Level == "" {
		cfg.Logging.Level = "info"
	}
	if cfg.Logging.Level == "debug" || cfg.Logging.Level == "verbose" {
		cfg.SMTP.VerboseLog = true
		cfg.Delivery.VerboseLog = true
	}
}
