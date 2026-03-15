package db

import (
	"time"

	"gorm.io/gorm"
)

type User struct {
	gorm.Model
	Username      string `gorm:"uniqueIndex;size:191;not null"`
	Email         string
	Password      string `gorm:"not null"`      // bcrypt hash
	Role          string `gorm:"default:user"`   // admin | user
	QuotaPerDay   int    `gorm:"default:0"`     // 0 = unlimited
	Active        bool   `gorm:"default:true"`
	// SMTP delivery mode: system_only | custom_only | system_and_custom
	SMTPMode      string `gorm:"default:'system_only'"`
	SMTPRotation  bool   `gorm:"default:false"` // rotate across all custom SMTPs
	MaxCustomSMTP int    `gorm:"default:5"`     // max custom SMTP servers allowed
	// Campaign/automation hard limits (0 = unlimited). Admin sets per user.
	MaxCampaigns   int `gorm:"default:0"` // max campaigns (draft+sent)
	MaxAutomations int `gorm:"default:0"` // max automations
	MaxLists       int `gorm:"default:0"` // max contact lists
	MaxTemplates   int `gorm:"default:0"` // max email templates
}

// UserSMTP stores a user's custom outbound SMTP relay credentials.
type UserSMTP struct {
	gorm.Model
	OwnerUsername string `gorm:"index;size:191;not null"`
	Label         string // friendly name, e.g. "SendGrid", "Mailgun"
	Host          string `gorm:"not null"`
	Port          int    `gorm:"default:587"`
	Username      string `gorm:"not null"`
	Password      string `gorm:"type:text;not null"`
	TLSMode       string `gorm:"size:20;default:starttls"` // "none" | "starttls" | "ssl"
	UseTLS        bool   `gorm:"default:true"`              // deprecated; TLSMode preferred
	IsDefault     bool   `gorm:"default:false"`             // preferred relay when rotation is off
	Active        bool   `gorm:"default:true"`
	FromAddress   string `gorm:"size:191"` // override From when using this relay (rotation: use per-relay; no rotation: use default's)
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

// DailyStats stores aggregated send/delivery counts per day for statistics.
// Used when EmailLog is purged ("delete logs only") so dashboard/reports still show totals.
// Username empty = admin/system-wide.
type DailyStats struct {
	gorm.Model
	StatDate   string `gorm:"uniqueIndex:idx_daily_stats_date_user;size:10;not null"` // YYYY-MM-DD
	Username  string `gorm:"uniqueIndex:idx_daily_stats_date_user;size:191;default:''"`
	Sent      int64  `gorm:"default:0"`
	Delivered int64  `gorm:"default:0"`
	Failed    int64  `gorm:"default:0"`
	Deferred  int64  `gorm:"default:0"`
	HardBounce int64 `gorm:"default:0"`
	SoftBounce int64 `gorm:"default:0"`
	Suppressed int64 `gorm:"default:0"`
}

type ThrottleRule struct {
	gorm.Model
	Username    string // empty = global master rule
	Domain      string // empty = applies to all domains
	PerSec      int    `gorm:"default:0"`
	PerMin      int    `gorm:"default:0"`
	PerHour     int    `gorm:"default:0"`
	PerDay      int    `gorm:"default:0"`
	PerMonth    int    `gorm:"default:0"`
	IntervalSec int    `gorm:"default:0"` // min seconds between emails (e.g. 5 = 1 email every 5 sec)
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
	Key   string `gorm:"column:setting_key;uniqueIndex;size:191"`   // avoids MySQL reserved 'key'
	Value string `gorm:"column:setting_value;type:text"`           // avoids MySQL reserved 'value'
}

// BounceList records permanently invalid email addresses (hard bounces).
// Addresses in this list are rejected at RCPT TO time.
type BounceList struct {
	gorm.Model
	Email       string `gorm:"uniqueIndex;size:191;not null"`
	Reason      string
	BounceCount int
	LastSeenAt  time.Time
}

// IPPool holds outbound IP addresses with optional per-IP send rate limits.
type IPPool struct {
	gorm.Model
	IP          string `gorm:"uniqueIndex;size:45;not null"`
	Hostname    string // optional label / rDNS name
	Active      bool   `gorm:"default:true"`
	PerMin      int    `gorm:"default:0"` // 0 = unlimited (base limits; overridden by domain rules)
	PerHour     int    `gorm:"default:0"`
	PerDay      int    `gorm:"default:0"`
	IntervalSec int    `gorm:"default:0"` // min seconds between emails from this IP (0 = no delay)
	Note        string

	// Warmup: gradually increase sending volume over N days.
	WarmupEnabled   bool       `gorm:"default:false"`
	WarmupStartedAt *time.Time // when warmup began (nil = not started); avoids MySQL '0000-00-00' error
	WarmupDays      int        `gorm:"default:14"` // total warmup period
}

// IPPoolDomainRule holds per-domain rate limits for a specific IP.
// When sending to domain X, use this rule if it matches; else use IP base limits.
type IPPoolDomainRule struct {
	gorm.Model
	IPPoolID   uint   `gorm:"index;not null"`
	Domain     string `gorm:"size:191;not null"` // e.g. gmail.com, yahoo.com
	PerMin     int    `gorm:"default:0"`
	PerHour    int    `gorm:"default:0"`
	PerDay     int    `gorm:"default:0"`
	IntervalSec int   `gorm:"default:0"` // min seconds between emails to this domain from this IP
}

// IPPoolMasterDomainRule holds per-domain rate limits that apply to ALL IPs when no IP-specific domain rule exists.
// Each domain has its own rule; there is no default/fixed master rule.
type IPPoolMasterDomainRule struct {
	gorm.Model
	Domain     string `gorm:"uniqueIndex;size:191;not null"` // e.g. gmail.com, yahoo.com
	PerMin     int    `gorm:"default:0"`
	PerHour    int    `gorm:"default:0"`
	PerDay     int    `gorm:"default:0"`
	IntervalSec int   `gorm:"default:0"`
}

// WarmupDayLimit returns the maximum emails/day this IP may send today based on
// its warmup schedule.  Returns 0 (unlimited) when warmup is inactive or complete.
// Schedule doubles each day: 50 → 100 → 200 → 400 → ... capped at PerDay.
func (ip *IPPool) WarmupDayLimit() int {
	if !ip.WarmupEnabled || ip.WarmupStartedAt == nil || ip.WarmupStartedAt.IsZero() {
		return 0
	}
	day := int(time.Since(*ip.WarmupStartedAt).Hours()/24) + 1 // day 1, 2, ...
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
	Username string `gorm:"index;size:191;not null"` // the sending user's username
	Email    string `gorm:"size:191;not null"`       // suppressed address (stored lowercase)
	Reason   string                          // "unsubscribed" | "manual" | "bounce"
	Source   string                          // "link" | "user" | "admin" | "api"
}

// ─── Campaign & Automation (Mailchimp-style) ───────────────────────────────────

// ContactList holds contacts for a user (audience/segment).
type ContactList struct {
	gorm.Model
	OwnerUsername string `gorm:"index;size:191;not null"`
	Name          string `gorm:"size:191;not null"`
	Description   string `gorm:"type:text"`
}

// Contact is a single email in a list.
type Contact struct {
	gorm.Model
	ListID    uint   `gorm:"index;not null"`
	Email     string `gorm:"size:191;not null"`
	FirstName string `gorm:"size:191"`
	LastName  string `gorm:"size:191"`
	CustomFields string `gorm:"type:text"` // JSON: {"company":"Acme","phone":"123"}
	Status    string `gorm:"size:20;default:subscribed"` // subscribed | unsubscribed | bounced
}

// CampaignTemplate stores reusable HTML email templates with merge tags.
type CampaignTemplate struct {
	gorm.Model
	OwnerUsername string `gorm:"index;size:191;not null"`
	Name          string `gorm:"size:191;not null"`
	Subject       string `gorm:"size:500"` // default subject line
	HTMLBody      string `gorm:"type:text;not null"`
	TextBody      string `gorm:"type:text"`
}

// Campaign represents a send to a list.
type Campaign struct {
	gorm.Model
	OwnerUsername string     `gorm:"index;size:191;not null"`
	Name         string     `gorm:"size:191;not null"`
	Subject      string     `gorm:"size:500;not null"`
	FromEmail    string     `gorm:"size:191;not null"`
	ReplyTo      string     `gorm:"size:191"`
	TemplateID   uint       `gorm:"index"`
	ListID       uint       `gorm:"index;not null"`
	Status       string     `gorm:"size:20;default:draft"` // draft | scheduled | sending | sent
	ScheduledAt  *time.Time
	SentAt       *time.Time
	TotalSent    int        `gorm:"default:0"`
	Opens        int        `gorm:"default:0"`
	Clicks       int        `gorm:"default:0"`
}

// CampaignSend tracks each recipient in a campaign (for open/click tracking).
type CampaignSend struct {
	gorm.Model
	CampaignID uint       `gorm:"index;not null"`
	ContactID  uint       `gorm:"index;not null"`
	Email      string     `gorm:"size:191;not null"`
	Status     string     `gorm:"size:20;default:queued"` // queued | sent | failed
	SentAt     *time.Time
	OpenedAt   *time.Time
	ClickedAt  *time.Time
	TrackToken string     `gorm:"uniqueIndex;size:64;not null"` // for /t/o/{token} pixel
}

// TrackEvent logs opens and clicks for analytics.
type TrackEvent struct {
	gorm.Model
	SendID    uint      `gorm:"index;not null"`
	EventType string    `gorm:"size:20;not null"` // open | click
	URL       string    `gorm:"size:1024"`      // original URL for clicks
	IP        string    `gorm:"size:45"`
	UserAgent string    `gorm:"size:512"`
	EventAt   time.Time `gorm:"index"`
}

// Automation is a workflow (e.g. welcome series, abandoned cart).
type Automation struct {
	gorm.Model
	OwnerUsername string `gorm:"index;size:191;not null"`
	Name          string `gorm:"size:191;not null"`
	TriggerType   string `gorm:"size:50;not null"` // subscribe | tag_added | email_opened | email_clicked | delay
	TriggerListID uint  `gorm:"index"`            // for subscribe: which list
	TriggerSendID  uint  `gorm:"index"`           // for email_opened/clicked: which campaign send
	Status        string `gorm:"size:20;default:active"` // active | paused
}

// AutomationStep is one action in an automation (send email, wait, add tag).
type AutomationStep struct {
	gorm.Model
	AutomationID uint   `gorm:"index;not null"`
	StepOrder    int    `gorm:"not null"`
	ActionType   string `gorm:"size:30;not null"` // send_email | delay | add_tag
	TemplateID   uint  `gorm:"index"`
	DelayMinutes int    `gorm:"default:0"`
	TagName      string `gorm:"size:191"`
}

// Domain represents a verified sending domain with its DKIM keys and DNS records.
type Domain struct {
	gorm.Model
	OwnerUsername string `gorm:"index;size:191"`        // empty = global/admin domain
	Name          string `gorm:"uniqueIndex;size:191;not null"` // e.g. "example.com"
	DKIMSelector  string                          // e.g. "mail"
	DKIMPrivKey   string `gorm:"type:text"`        // PEM PKCS1 RSA private key
	DKIMPubKeyDNS string `gorm:"type:text"`        // "v=DKIM1; k=rsa; p=..." for DNS TXT
}
