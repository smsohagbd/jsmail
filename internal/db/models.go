package db

import (
	"time"

	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Username    string `gorm:"uniqueIndex;not null"`
	Email       string
	Password    string `gorm:"not null"` // bcrypt hash
	Role        string `gorm:"default:user"` // admin | user
	QuotaPerDay int    `gorm:"default:0"`    // 0 = unlimited
	Active      bool   `gorm:"default:true"`
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
	Email      string `gorm:"uniqueIndex;not null"`
	Reason     string
	BounceCount int
	LastSeenAt time.Time
}
