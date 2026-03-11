package db

import (
	"time"

	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Username      string `gorm:"uniqueIndex;not null"`
	Email         string
	Password      string `gorm:"not null"`      // bcrypt hash
	Role          string `gorm:"default:user"`  // admin | user
	QuotaPerDay   int    `gorm:"default:0"`     // 0 = unlimited
	Active        bool   `gorm:"default:true"`
	// SMTP delivery mode: system_only | custom_only | system_and_custom
	SMTPMode      string `gorm:"default:'system_only'"`
	SMTPRotation  bool   `gorm:"default:false"` // rotate across all custom SMTPs
	MaxCustomSMTP int    `gorm:"default:5"`     // max custom SMTP servers allowed
}

// UserSMTP stores a user's custom outbound SMTP relay credentials.
type UserSMTP struct {
	gorm.Model
	OwnerUsername string `gorm:"index;not null"`
	Label         string // friendly name, e.g. "SendGrid", "Mailgun"
	Host          string `gorm:"not null"`
	Port          int    `gorm:"default:587"`
	Username      string `gorm:"not null"`
	Password      string `gorm:"type:text;not null"`
	UseTLS        bool   `gorm:"default:true"`  // try STARTTLS
	IsDefault     bool   `gorm:"default:false"` // preferred relay when rotation is off
	Active        bool   `gorm:"default:true"`
}

type EmailLog struct {
	gorm.Model
	Username  string
	MessageID string
	From      string
	Recipient string // 'to' renamed to avoid SQL reserved-word conflict
	Status    string // queued | delivered | failed | deferred
	Error     string
	MXHost    string
	SentAt    time.Time
}

type ThrottleRule struct {
	gorm.Model
	Username string // empty = global master rule
	Domain   string // empty = applies to all domains
	PerSec   int    `gorm:"default:0"`
	PerMin   int    `gorm:"default:0"`
	PerHour  int    `gorm:"default:0"`
	PerDay   int    `gorm:"default:0"`
	PerMonth int    `gorm:"default:0"`
}

type UpstreamSMTP struct {
	gorm.Model
	Username string // empty = global; user-level otherwise
	Name     string
	Host     string
	Port     int
	SMTPUser string
	SMTPPass string
	Active   bool `gorm:"default:true"`
	Priority int  `gorm:"default:10"`
}

type Setting struct {
	gorm.Model
	Key   string `gorm:"uniqueIndex"`
	Value string
}

// BounceList records permanently invalid email addresses (hard bounces).
// Addresses in this list are rejected at RCPT TO time.
type BounceList struct {
	gorm.Model
	Email       string `gorm:"uniqueIndex;not null"`
	Reason      string
	BounceCount int
	LastSeenAt  time.Time
}

// IPPool holds outbound IP addresses with optional per-IP send rate limits.
type IPPool struct {
	gorm.Model
	IP       string `gorm:"uniqueIndex;not null"`
	Hostname string // optional label / rDNS name
	Active   bool   `gorm:"default:true"`
	PerMin   int    `gorm:"default:0"` // 0 = unlimited
	PerHour  int    `gorm:"default:0"`
	PerDay   int    `gorm:"default:0"`
	Note     string

	// Warmup: gradually increase sending volume over N days.
	WarmupEnabled   bool      `gorm:"default:false"`
	WarmupStartedAt time.Time // when warmup began (zero = not started)
	WarmupDays      int       `gorm:"default:14"` // total warmup period
}

// WarmupDayLimit returns the maximum emails/day this IP may send today based on
// its warmup schedule.  Returns 0 (unlimited) when warmup is inactive or complete.
// Schedule doubles each day: 50 → 100 → 200 → 400 → ... capped at PerDay.
func (ip *IPPool) WarmupDayLimit() int {
	if !ip.WarmupEnabled || ip.WarmupStartedAt.IsZero() {
		return 0
	}
	day := int(time.Since(ip.WarmupStartedAt).Hours()/24) + 1 // day 1, 2, ...
	if day > ip.WarmupDays {
		return 0 // warmup complete, use PerDay (or unlimited)
	}
	// Doubling schedule starting at 50/day.
	limit := 50
	for i := 1; i < day; i++ {
		limit *= 2
	}
	// Cap at user-configured PerDay if set.
	if ip.PerDay > 0 && limit > ip.PerDay {
		limit = ip.PerDay
	}
	return limit
}

// Suppression records email addresses that have opted out of receiving mail
// from a specific user's account. Checked at delivery time.
type Suppression struct {
	gorm.Model
	Username string `gorm:"index;not null"` // the sending user's username
	Email    string `gorm:"not null"`       // suppressed address (stored lowercase)
	Reason   string                          // "unsubscribed" | "manual" | "bounce"
	Source   string                          // "link" | "user" | "admin" | "api"
}

// Domain represents a verified sending domain with its DKIM keys and DNS records.
type Domain struct {
	gorm.Model
	OwnerUsername string `gorm:"index"`           // empty = global/admin domain
	Name          string `gorm:"uniqueIndex;not null"` // e.g. "example.com"
	DKIMSelector  string                          // e.g. "mail"
	DKIMPrivKey   string `gorm:"type:text"`        // PEM PKCS1 RSA private key
	DKIMPubKeyDNS string `gorm:"type:text"`        // "v=DKIM1; k=rsa; p=..." for DNS TXT
}
