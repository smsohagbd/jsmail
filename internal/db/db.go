package db

import (
	"crypto/hmac"
	"crypto/rand"
	"errors"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/glebarez/sqlite"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var DB *gorm.DB

// Init opens the database (SQLite or MySQL), runs migrations, and seeds the admin user.
// cfg must have Driver set ("sqlite" or "mysql") and the appropriate connection fields.
func Init(driver, dsnOrPath, adminUser, adminPass string) error {
	var err error
	var dialector gorm.Dialector

	switch driver {
	case "mysql":
		dialector = mysql.Open(dsnOrPath)
	default:
		dialector = sqlite.Open(dsnOrPath)
	}

	DB, err = gorm.Open(dialector, &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return err
	}

	// Drop email_logs if it has the old 'to' column (pre-rename migration).
	var colExists int64
	if DB.Dialector.Name() == "sqlite" {
		DB.Raw("SELECT COUNT(*) FROM pragma_table_info('email_logs') WHERE name='to'").Scan(&colExists)
	} else {
		DB.Raw("SELECT COUNT(*) FROM information_schema.columns WHERE table_schema = DATABASE() AND table_name = ? AND column_name = ?", "email_logs", "to").Scan(&colExists)
	}
	if colExists > 0 {
		log.Printf("db: migrating email_logs table (renaming 'to' → 'recipient')")
		DB.Exec("DROP TABLE IF EXISTS email_logs")
	}

	if err := DB.AutoMigrate(
		&User{},
		&EmailLog{},
		&DailyStats{},
		&ThrottleRule{},
		&UpstreamSMTP{},
		&Setting{},
		&BounceList{},
		&Domain{},
		&IPPool{},
		&IPPoolDomainRule{},
		&IPPoolMasterDomainRule{},
		&UserSMTP{},
		&Suppression{},
		&ContactList{},
		&Contact{},
		&CampaignTemplate{},
		&Campaign{},
		&CampaignSend{},
		&TrackEvent{},
		&Automation{},
		&AutomationStep{},
		&AutomationSend{},
	); err != nil {
		return err
	}

	ensureAdmin(adminUser, adminPass)
	log.Printf("db: %s opened successfully", driver)
	return nil
}

func ensureAdmin(username, password string) {
	var user User
	result := DB.Where("username = ?", username).First(&user)
	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)

	if result.Error != nil {
		DB.Create(&User{
			Username: username,
			Password: string(hash),
			Role:     "admin",
			Active:   true,
		})
		log.Printf("db: admin user %q created", username)
	} else {
		DB.Model(&user).Updates(map[string]interface{}{
			"password": string(hash),
			"role":     "admin",
			"active":   true,
		})
	}
}

// incrementDailyStat atomically increments a counter in DailyStats for the given date and username.
func incrementDailyStat(statDate, username, field string, delta int64) {
	if statDate == "" {
		return
	}
	var existing DailyStats
	err := DB.Where("stat_date = ? AND username = ?", statDate, username).First(&existing).Error
	if err != nil {
		row := DailyStats{StatDate: statDate, Username: username}
		switch field {
		case "sent":
			row.Sent = delta
		case "delivered":
			row.Delivered = delta
		case "failed":
			row.Failed = delta
		case "deferred":
			row.Deferred = delta
		case "hard_bounce":
			row.HardBounce = delta
		case "soft_bounce":
			row.SoftBounce = delta
		case "suppressed":
			row.Suppressed = delta
		default:
			return
		}
		DB.Create(&row)
		return
	}
	col := "sent"
	switch field {
	case "delivered":
		col = "delivered"
	case "failed":
		col = "failed"
	case "deferred":
		col = "deferred"
	case "hard_bounce":
		col = "hard_bounce"
	case "soft_bounce":
		col = "soft_bounce"
	case "suppressed":
		col = "suppressed"
	}
	DB.Model(&DailyStats{}).Where("stat_date = ? AND username = ?", statDate, username).
		UpdateColumn(col, gorm.Expr("COALESCE("+col+",0) + ?", delta))
}

// LogQueued writes a queued log entry for every recipient.
func LogQueued(username, msgID, from string, recipients []string) {
	now := time.Now()
	statDate := now.Format("2006-01-02")
	for _, rcpt := range recipients {
		DB.Create(&EmailLog{
			Username:  username,
			MessageID: msgID,
			From:      from,
			Recipient: rcpt,
			Status:    "queued",
			SentAt:    now,
		})
	}
	incrementDailyStat(statDate, username, "sent", int64(len(recipients)))
	incrementDailyStat(statDate, "", "sent", int64(len(recipients))) // admin-wide
}

// LogDelivered updates a log entry to delivered.
func LogDelivered(username, msgID, recipient, mxHost string) {
	statDate := time.Now().Format("2006-01-02")
	DB.Model(&EmailLog{}).
		Where("message_id = ? AND recipient = ?", msgID, recipient).
		Updates(map[string]interface{}{
			"status":  "delivered",
			"error":   "", // clear any previous defer/throttle error
			"mx_host": mxHost,
			"sent_at": time.Now(),
		})
	incrementDailyStat(statDate, username, "delivered", 1)
	incrementDailyStat(statDate, "", "delivered", 1)
}

// LogFailed updates a log entry to failed.
func LogFailed(username, msgID, recipient, errMsg string) {
	statDate := time.Now().Format("2006-01-02")
	DB.Model(&EmailLog{}).
		Where("message_id = ? AND recipient = ?", msgID, recipient).
		Updates(map[string]interface{}{
			"status": "failed",
			"error":  errMsg,
		})
	incrementDailyStat(statDate, username, "failed", 1)
	incrementDailyStat(statDate, "", "failed", 1)
}

// LogDeferred updates a log entry to deferred.
func LogDeferred(username, msgID, recipient, errMsg string) {
	statDate := time.Now().Format("2006-01-02")
	DB.Model(&EmailLog{}).
		Where("message_id = ? AND recipient = ?", msgID, recipient).
		Updates(map[string]interface{}{
			"status": "deferred",
			"error":  errMsg,
		})
	incrementDailyStat(statDate, username, "deferred", 1)
	incrementDailyStat(statDate, "", "deferred", 1)
}

// LogHardBounce marks a log entry as hard_bounce and adds address to bounce list.
func LogHardBounce(username, msgID, recipient, errMsg string) {
	statDate := time.Now().Format("2006-01-02")
	DB.Model(&EmailLog{}).
		Where("message_id = ? AND recipient = ?", msgID, recipient).
		Updates(map[string]interface{}{
			"status": "hard_bounce",
			"error":  errMsg,
		})
	incrementDailyStat(statDate, username, "hard_bounce", 1)
	incrementDailyStat(statDate, "", "hard_bounce", 1)

	// Upsert into bounce list.
	var entry BounceList
	if err := DB.Where("email = ?", recipient).First(&entry).Error; err != nil {
		DB.Create(&BounceList{Email: recipient, Reason: errMsg, BounceCount: 1, LastSeenAt: time.Now()})
	} else {
		DB.Model(&entry).Updates(map[string]interface{}{
			"reason":       errMsg,
			"bounce_count": entry.BounceCount + 1,
			"last_seen_at": time.Now(),
		})
	}
}

// IsHardBounced returns true if the address is in the bounce suppression list.
func IsHardBounced(email string) bool {
	var count int64
	DB.Model(&BounceList{}).Where("email = ?", strings.ToLower(email)).Count(&count)
	return count > 0
}

// RemoveFromBounceList removes an address from the suppression list.
func RemoveFromBounceList(email string) {
	DB.Unscoped().Where("email = ?", strings.ToLower(email)).Delete(&BounceList{})
}

// ──────────────────────────── Domains ────────────────────────────────────────

// CreateDomain generates a DKIM RSA-2048 key pair and stores the domain.
func CreateDomain(ownerUsername, name, selector string) (*Domain, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if selector == "" {
		selector = "sm"
	}
	// Permanently purge any soft-deleted record with the same name so the
	// unique index doesn't block re-creation.
	DB.Unscoped().Where("name = ?", name).Delete(&Domain{})

	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate DKIM key: %w", err)
	}

	privKeyPEM := string(pem.EncodeToMemory(&pem.Block{
		Type:  "RSA PRIVATE KEY",
		Bytes: x509.MarshalPKCS1PrivateKey(privKey),
	}))

	pubDER, err := x509.MarshalPKIXPublicKey(&privKey.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("marshal public key: %w", err)
	}
	dkimDNS := "v=DKIM1; k=rsa; p=" + base64.StdEncoding.EncodeToString(pubDER)

	d := &Domain{
		OwnerUsername: ownerUsername,
		Name:          name,
		DKIMSelector:  selector,
		DKIMPrivKey:   privKeyPEM,
		DKIMPubKeyDNS: dkimDNS,
	}
	if err := DB.Create(d).Error; err != nil {
		return nil, err
	}
	return d, nil
}

// GetAllDomains returns all domains ordered by name.
func GetAllDomains() []Domain {
	var domains []Domain
	DB.Order("name asc").Find(&domains)
	return domains
}

// GetDomainsByOwner returns domains owned by a specific user.
func GetDomainsByOwner(owner string) []Domain {
	var domains []Domain
	DB.Where("owner_username = ?", owner).Order("name asc").Find(&domains)
	return domains
}

// GetDomainByName looks up a domain by name.
func GetDomainByName(name string) (*Domain, bool) {
	var d Domain
	if err := DB.Where("name = ?", strings.ToLower(name)).First(&d).Error; err != nil {
		return nil, false
	}
	return &d, true
}

func GetDomainByID(id uint) (*Domain, bool) {
	var d Domain
	if err := DB.First(&d, id).Error; err != nil {
		return nil, false
	}
	return &d, true
}

// DeleteDomain permanently removes a domain record.
// Hard-delete is required because the unique index on `name` would block
// re-adding the same domain after a soft-delete.
func DeleteDomain(id uint) {
	DB.Unscoped().Delete(&Domain{}, id)
}

// ──────────────────────────── IP Pool ────────────────────────────────────────

func GetActiveIPPool() []IPPool {
	var entries []IPPool
	DB.Where("active = ?", true).Order("ip asc").Find(&entries)
	return entries
}

func GetAllIPPool() []IPPool {
	var entries []IPPool
	DB.Order("ip asc").Find(&entries)
	return entries
}

func SaveIPPoolEntry(e *IPPool) error {
	if e.ID == 0 {
		return DB.Create(e).Error
	}
	return DB.Save(e).Error
}

func DeleteIPPoolEntry(id uint) {
	DB.Unscoped().Where("ip_pool_id = ?", id).Delete(&IPPoolDomainRule{})
	DB.Unscoped().Delete(&IPPool{}, id)
}

// GetAllIPPoolMasterDomainRules returns all master domain rules (per-domain limits for all IPs).
func GetAllIPPoolMasterDomainRules() []IPPoolMasterDomainRule {
	var rules []IPPoolMasterDomainRule
	DB.Order("domain asc").Find(&rules)
	return rules
}

// GetIPPoolMasterDomainRule returns the master rule for a domain, or nil if none.
func GetIPPoolMasterDomainRule(domain string) *IPPoolMasterDomainRule {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return nil
	}
	var r IPPoolMasterDomainRule
	if err := DB.Where("domain = ?", domain).First(&r).Error; err != nil {
		return nil
	}
	return &r
}

// AddIPPoolMasterDomainRule adds a master domain rule.
func AddIPPoolMasterDomainRule(domain string, perMin, perHour, perDay, intervalSec int) error {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return fmt.Errorf("domain required")
	}
	return DB.Create(&IPPoolMasterDomainRule{
		Domain:     domain,
		PerMin:     perMin,
		PerHour:    perHour,
		PerDay:     perDay,
		IntervalSec: intervalSec,
	}).Error
}

// UpdateIPPoolMasterDomainRule updates a master domain rule.
func UpdateIPPoolMasterDomainRule(id uint, domain string, perMin, perHour, perDay, intervalSec int) error {
	domain = strings.ToLower(strings.TrimSpace(domain))
	return DB.Model(&IPPoolMasterDomainRule{}).Where("id = ?", id).
		Updates(map[string]interface{}{
			"domain":       domain,
			"per_min":      perMin,
			"per_hour":     perHour,
			"per_day":      perDay,
			"interval_sec": intervalSec,
		}).Error
}

// DeleteIPPoolMasterDomainRule deletes a master domain rule.
func DeleteIPPoolMasterDomainRule(id uint) {
	DB.Where("id = ?", id).Delete(&IPPoolMasterDomainRule{})
}

// GetIPPoolDomainRules returns all domain rules for an IP.
func GetIPPoolDomainRules(ipPoolID uint) []IPPoolDomainRule {
	var rules []IPPoolDomainRule
	DB.Where("ip_pool_id = ?", ipPoolID).Order("domain asc").Find(&rules)
	return rules
}

func AddIPPoolDomainRule(ipPoolID uint, domain string, perMin, perHour, perDay, intervalSec int) error {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return fmt.Errorf("domain required")
	}
	return DB.Create(&IPPoolDomainRule{
		IPPoolID:   ipPoolID,
		Domain:     domain,
		PerMin:     perMin,
		PerHour:    perHour,
		PerDay:     perDay,
		IntervalSec: intervalSec,
	}).Error
}

func UpdateIPPoolDomainRule(id, ipPoolID uint, domain string, perMin, perHour, perDay, intervalSec int) error {
	domain = strings.ToLower(strings.TrimSpace(domain))
	return DB.Model(&IPPoolDomainRule{}).Where("id = ? AND ip_pool_id = ?", id, ipPoolID).
		Updates(map[string]interface{}{
			"domain":       domain,
			"per_min":      perMin,
			"per_hour":     perHour,
			"per_day":      perDay,
			"interval_sec": intervalSec,
		}).Error
}

func DeleteIPPoolDomainRule(id, ipPoolID uint) {
	DB.Where("id = ? AND ip_pool_id = ?", id, ipPoolID).Delete(&IPPoolDomainRule{})
}

// ──────────────────────────── Force From Address ──────────────────────────────

// GetForceFromEnabled returns true if force-from is enabled.
func GetForceFromEnabled() bool {
	return GetSetting("force_from_enabled", "false") == "true"
}

// GetForceFromDomainsRaw returns the raw domains string (newline-separated) for editing.
func GetForceFromDomainsRaw() string {
	return GetSetting("force_from_domains", "")
}

// GetForceFromDomains returns the list of domains for rotation (one per line, trimmed, non-empty).
func GetForceFromDomains() []string {
	raw := GetSetting("force_from_domains", "")
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		d := strings.ToLower(strings.TrimSpace(line))
		if d != "" && !strings.HasPrefix(d, "#") {
			out = append(out, d)
		}
	}
	return out
}

// SetForceFromConfig saves the force-from enabled flag and domains (newline-separated).
func SetForceFromConfig(enabled bool, domains string) error {
	val := "false"
	if enabled {
		val = "true"
	}
	if err := SetSetting("force_from_enabled", val); err != nil {
		return err
	}
	return SetSetting("force_from_domains", domains)
}

// ──────────────────────────── Settings ───────────────────────────────────────

// GetSetting retrieves a setting value by key, returning def if not set.
func GetSetting(key, def string) string {
	var s Setting
	if err := DB.Where("setting_key = ?", key).First(&s).Error; err != nil {
		return def
	}
	return s.Value
}

// SetSetting upserts a setting. Returns error on DB failure.
// Uses Unscoped so we find soft-deleted rows and update them instead of hitting "duplicate key".
func SetSetting(key, value string) error {
	var s Setting
	err := DB.Unscoped().Where("setting_key = ?", key).First(&s).Error
	if err != nil {
		if errors.Is(err, gorm.ErrRecordNotFound) {
			return DB.Create(&Setting{Key: key, Value: value}).Error
		}
		return err
	}
	// Found (including soft-deleted) — update value and restore if deleted
	return DB.Unscoped().Model(&s).Updates(map[string]interface{}{"setting_value": value, "deleted_at": nil}).Error
}

// ──────────────────────────── UserSMTP ───────────────────────────────────────

// GetUserSMTPs returns all custom SMTP entries for a user.
func GetUserSMTPs(username string) []UserSMTP {
	var list []UserSMTP
	DB.Where("owner_username = ?", username).Order("is_default desc, created_at asc").Find(&list)
	return list
}

// GetActiveUserSMTPs returns only active custom SMTP entries for a user.
func GetActiveUserSMTPs(username string) []UserSMTP {
	var list []UserSMTP
	DB.Where("owner_username = ? AND active = ?", username, true).
		Order("is_default desc, created_at asc").Find(&list)
	return list
}

// AddUserSMTP inserts a new custom SMTP entry. If it's the first one, marks it default.
func AddUserSMTP(entry *UserSMTP) error {
	var count int64
	DB.Model(&UserSMTP{}).Where("owner_username = ?", entry.OwnerUsername).Count(&count)
	if count == 0 {
		entry.IsDefault = true
	}
	return DB.Create(entry).Error
}

// DeleteUserSMTP removes a custom SMTP entry.
func DeleteUserSMTP(id uint, username string) {
	var entry UserSMTP
	if err := DB.Where("id = ? AND owner_username = ?", id, username).First(&entry).Error; err != nil {
		return
	}
	DB.Delete(&entry)
	// If the deleted entry was the default, promote the first remaining one.
	if entry.IsDefault {
		var next UserSMTP
		if err := DB.Where("owner_username = ? AND active = ?", username, true).
			Order("created_at asc").First(&next).Error; err == nil {
			DB.Model(&next).Update("is_default", true)
		}
	}
}

// SetDefaultUserSMTP sets one entry as default and clears all others for the user.
func SetDefaultUserSMTP(id uint, username string) {
	DB.Model(&UserSMTP{}).Where("owner_username = ?", username).
		Update("is_default", false)
	DB.Model(&UserSMTP{}).Where("id = ? AND owner_username = ?", id, username).
		Update("is_default", true)
}

// ToggleUserSMTP flips the active flag for an entry.
func ToggleUserSMTP(id uint, username string) {
	var entry UserSMTP
	if err := DB.Where("id = ? AND owner_username = ?", id, username).First(&entry).Error; err != nil {
		return
	}
	DB.Model(&entry).Update("active", !entry.Active)
}

// UpdateUserSMTPFromAddress updates the FromAddress for an SMTP entry.
func UpdateUserSMTPFromAddress(id uint, username, fromAddress string) error {
	return DB.Model(&UserSMTP{}).
		Where("id = ? AND owner_username = ?", id, username).
		Update("from_address", strings.TrimSpace(fromAddress)).Error
}

// GetUserSMTPMode returns a user's SMTP delivery mode and rotation preference.
func GetUserSMTPMode(username string) (mode string, rotation bool) {
	var u User
	if err := DB.Select("smtp_mode", "smtp_rotation").
		Where("username = ?", username).First(&u).Error; err != nil {
		return "system_only", false
	}
	if u.SMTPMode == "" {
		return "system_only", false
	}
	return u.SMTPMode, u.SMTPRotation
}

// SetUserSMTPMode updates a user's SMTP mode and rotation flag.
func SetUserSMTPMode(username, mode string, rotation bool, maxSMTP int) {
	DB.Model(&User{}).Where("username = ?", username).Updates(map[string]interface{}{
		"smtp_mode":       mode,
		"smtp_rotation":   rotation,
		"max_custom_smtp": maxSMTP,
	})
}

// ──────────────────────────── Throttle ───────────────────────────────────────

// ThrottleLimit holds effective send-rate limits for one user+domain combination.
type ThrottleLimit struct {
	PerSec      int
	PerMin      int
	PerHour     int
	PerDay      int
	PerMonth    int
	IntervalSec int // min seconds between emails (e.g. 5 = 1 every 5 sec)
}

// GetEffectiveThrottle returns the most restrictive applicable throttle rule for
// a user sending to a given recipient domain.
// Priority: user+domain > user (all domains) > global+domain > global (all domains).
func GetEffectiveThrottle(username, domain string) ThrottleLimit {
	var rules []ThrottleRule
	DB.Where("(username = ? OR username = '') AND (domain = ? OR domain = '')",
		username, domain).Find(&rules)

	// Score each rule: user-specific wins over global, domain-specific wins over wildcard.
	best := ThrottleLimit{}
	bestScore := -1
	for _, r := range rules {
		score := 0
		if r.Username == username {
			score += 2
		}
		if r.Domain == domain {
			score += 1
		}
		if score > bestScore {
			bestScore = score
			best = ThrottleLimit{
				PerSec:      r.PerSec,
				PerMin:      r.PerMin,
				PerHour:     r.PerHour,
				PerDay:      r.PerDay,
				PerMonth:    r.PerMonth,
				IntervalSec: r.IntervalSec,
			}
		}
	}
	return best
}

// CheckPassword verifies a user's password and returns the user if valid.
func CheckPassword(username, password string) (*User, bool) {
	var user User
	if err := DB.Where("username = ? AND active = ?", username, true).First(&user).Error; err != nil {
		return nil, false
	}
	if err := bcrypt.CompareHashAndPassword([]byte(user.Password), []byte(password)); err != nil {
		return nil, false
	}
	return &user, true
}

// ─────────────────────────── Unsubscribe / Suppression ───────────────────────

// getUnsubSecret returns the HMAC secret for unsubscribe tokens, generating and
// persisting one on first call.
func getUnsubSecret() string {
	s := GetSetting("unsub_secret", "")
	if s != "" {
		return s
	}
	b := make([]byte, 32)
	rand.Read(b)
	s = hex.EncodeToString(b)
	_ = SetSetting("unsub_secret", s)
	return s
}

// GenerateUnsubToken creates a tamper-proof, URL-safe token that encodes username.
// Format: base64url(username) + "." + base64url(HMAC-SHA256(username, secret))
func GenerateUnsubToken(username string) string {
	secret := getUnsubSecret()
	payload := base64.RawURLEncoding.EncodeToString([]byte(username))
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	sig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	return payload + "." + sig
}

// ValidateUnsubToken validates the token and returns the username if valid.
func ValidateUnsubToken(token string) (username string, ok bool) {
	idx := strings.LastIndex(token, ".")
	if idx < 0 {
		return "", false
	}
	payload, sig := token[:idx], token[idx+1:]
	secret := getUnsubSecret()
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(payload))
	expectedSig := base64.RawURLEncoding.EncodeToString(mac.Sum(nil))
	if !hmac.Equal([]byte(sig), []byte(expectedSig)) {
		return "", false
	}
	decoded, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return "", false
	}
	return string(decoded), true
}

// AddSuppression adds an email to a user's suppression list (idempotent).
func AddSuppression(username, email, reason, source string) {
	email = strings.ToLower(strings.TrimSpace(email))
	if email == "" {
		return
	}
	var existing Suppression
	if DB.Where("username = ? AND email = ?", username, email).First(&existing).Error != nil {
		DB.Create(&Suppression{Username: username, Email: email, Reason: reason, Source: source})
	}
}

// IsSuppressed returns true if the address is on the user's suppression list.
func IsSuppressed(username, email string) bool {
	var count int64
	DB.Model(&Suppression{}).
		Where("username = ? AND email = ?", username, strings.ToLower(strings.TrimSpace(email))).
		Count(&count)
	return count > 0
}

// GetSuppressionsByUser returns all suppression entries for a user, newest first.
func GetSuppressionsByUser(username string) []Suppression {
	var list []Suppression
	DB.Where("username = ?", username).Order("created_at desc").Find(&list)
	return list
}

// GetAllSuppressions returns all suppression entries across all users with pagination.
func GetAllSuppressions(page, perPage int) ([]Suppression, int64) {
	var list []Suppression
	var total int64
	DB.Model(&Suppression{}).Count(&total)
	DB.Order("created_at desc").Offset((page - 1) * perPage).Limit(perPage).Find(&list)
	return list, total
}

// RemoveSuppression deletes an entry by ID, restricted to the owning user.
func RemoveSuppression(id uint, username string) {
	DB.Where("id = ? AND username = ?", id, username).Delete(&Suppression{})
}

// RemoveSuppressionAdmin deletes any entry by ID (admin use).
func RemoveSuppressionAdmin(id uint) {
	DB.Delete(&Suppression{}, id)
}

// ─────────────────────────── Cloudflare token storage ────────────────────────

// GetCFToken returns the Cloudflare API token stored for a user.
// Falls back to the global admin token if the user has none set.
func GetCFToken(username string) string {
	if t := GetSetting("cf_token:"+username, ""); t != "" {
		return t
	}
	return GetSetting("cf_token:__global", "")
}

// SetCFToken persists a Cloudflare API token for a user.
// Pass username = "__global" to set the platform-wide fallback token.
func SetCFToken(username, token string) error {
	return SetSetting("cf_token:"+username, token)
}

// ─────────────────────────── Suppression ────────────────────────────────────

// LogSuppressed updates an email log entry status to "suppressed".
func LogSuppressed(username, msgID, recipient, reason string) {
	statDate := time.Now().Format("2006-01-02")
	DB.Model(&EmailLog{}).
		Where("message_id = ? AND recipient = ?", msgID, recipient).
		Updates(map[string]interface{}{
			"status": "suppressed",
			"error":  reason,
		})
	incrementDailyStat(statDate, username, "suppressed", 1)
	incrementDailyStat(statDate, "", "suppressed", 1)
}

// ─────────────────────────── Data Management ───────────────────────────────────

// AggregateStats holds totals for dashboard/reports.
type AggregateStats struct {
	Sent       int64
	Delivered  int64
	Failed     int64
	Deferred   int64
	HardBounce int64
	SoftBounce int64
	Suppressed int64
	Queued     int64
}

// GetAggregateStatsAdmin returns system-wide stats, preferring DailyStats when available.
func GetAggregateStatsAdmin() AggregateStats {
	var s AggregateStats
	// Prefer admin-wide (username="") rows; fallback to SUM of all usernames
	DB.Model(&DailyStats{}).Where("username = ?", "").
		Select("COALESCE(SUM(sent),0) as sent, COALESCE(SUM(delivered),0) as delivered, COALESCE(SUM(failed),0) as failed, COALESCE(SUM(deferred),0) as deferred, COALESCE(SUM(hard_bounce),0) as hard_bounce, COALESCE(SUM(soft_bounce),0) as soft_bounce, COALESCE(SUM(suppressed),0) as suppressed").
		Scan(&s)
	if s.Sent == 0 && s.Delivered == 0 {
		// Fallback: sum across all usernames (for when only per-user rows exist)
		DB.Model(&DailyStats{}).
			Select("COALESCE(SUM(sent),0) as sent, COALESCE(SUM(delivered),0) as delivered, COALESCE(SUM(failed),0) as failed, COALESCE(SUM(deferred),0) as deferred, COALESCE(SUM(hard_bounce),0) as hard_bounce, COALESCE(SUM(soft_bounce),0) as soft_bounce, COALESCE(SUM(suppressed),0) as suppressed").
			Scan(&s)
	}
	if s.Sent == 0 && s.Delivered == 0 {
		DB.Model(&EmailLog{}).Count(&s.Sent)
		DB.Model(&EmailLog{}).Where("status = ?", "delivered").Count(&s.Delivered)
		DB.Model(&EmailLog{}).Where("status = ?", "failed").Count(&s.Failed)
		DB.Model(&EmailLog{}).Where("status = ?", "deferred").Count(&s.Deferred)
		DB.Model(&EmailLog{}).Where("status = ?", "hard_bounce").Count(&s.HardBounce)
		DB.Model(&EmailLog{}).Where("status IN ?", []string{"soft_bounce", "deferred"}).Count(&s.SoftBounce)
		DB.Model(&EmailLog{}).Where("status = ?", "suppressed").Count(&s.Suppressed)
		DB.Model(&EmailLog{}).Where("status = ?", "queued").Count(&s.Queued)
	} else {
		DB.Model(&EmailLog{}).Where("status IN ?", []string{"queued", "deferred"}).Count(&s.Queued)
	}
	return s
}

// GetAggregateStatsUser returns stats for a user, preferring DailyStats when available.
func GetAggregateStatsUser(username string) AggregateStats {
	var s AggregateStats
	DB.Model(&DailyStats{}).Where("username = ?", username).
		Select("COALESCE(SUM(sent),0) as sent, COALESCE(SUM(delivered),0) as delivered, COALESCE(SUM(failed),0) as failed, COALESCE(SUM(deferred),0) as deferred, COALESCE(SUM(hard_bounce),0) as hard_bounce, COALESCE(SUM(soft_bounce),0) as soft_bounce, COALESCE(SUM(suppressed),0) as suppressed").
		Scan(&s)
	if s.Sent == 0 && s.Delivered == 0 {
		DB.Model(&EmailLog{}).Where("username = ?", username).Count(&s.Sent)
		DB.Model(&EmailLog{}).Where("username = ? AND status = ?", username, "delivered").Count(&s.Delivered)
		DB.Model(&EmailLog{}).Where("username = ? AND status = ?", username, "failed").Count(&s.Failed)
		DB.Model(&EmailLog{}).Where("username = ? AND status = ?", username, "deferred").Count(&s.Deferred)
		DB.Model(&EmailLog{}).Where("username = ? AND status = ?", username, "hard_bounce").Count(&s.HardBounce)
		DB.Model(&EmailLog{}).Where("username = ? AND status IN ?", username, []string{"soft_bounce", "deferred"}).Count(&s.SoftBounce)
		DB.Model(&EmailLog{}).Where("username = ? AND status = ?", username, "suppressed").Count(&s.Suppressed)
		DB.Model(&EmailLog{}).Where("username = ? AND status = ?", username, "queued").Count(&s.Queued)
	} else {
		DB.Model(&EmailLog{}).Where("username = ? AND status IN ?", username, []string{"queued", "deferred"}).Count(&s.Queued)
	}
	return s
}

// GetTodayYesterdayMonthAdmin returns sent counts for today, yesterday, and this month.
func GetTodayYesterdayMonthAdmin() (today, yesterday, month int64) {
	t := time.Now().Truncate(24 * time.Hour)
	todayStr := t.Format("2006-01-02")
	yesterdayStr := t.AddDate(0, 0, -1).Format("2006-01-02")
	monthStart := t.AddDate(0, -1, 0).Format("2006-01-02")
	var d DailyStats
	if err := DB.Model(&DailyStats{}).Where("stat_date = ? AND username = ?", todayStr, "").First(&d).Error; err == nil {
		today = d.Sent
	} else {
		DB.Model(&EmailLog{}).Where("sent_at >= ?", t).Count(&today)
	}
	if err := DB.Model(&DailyStats{}).Where("stat_date = ? AND username = ?", yesterdayStr, "").First(&d).Error; err == nil {
		yesterday = d.Sent
	} else {
		DB.Model(&EmailLog{}).Where("sent_at >= ? AND sent_at < ?", t.AddDate(0, 0, -1), t).Count(&yesterday)
	}
	DB.Model(&DailyStats{}).Where("username = ? AND stat_date >= ?", "", monthStart).Select("COALESCE(SUM(sent),0)").Scan(&month)
	if month == 0 {
		DB.Model(&EmailLog{}).Where("sent_at >= ?", t.AddDate(0, -1, 0)).Count(&month)
	}
	return today, yesterday, month
}

// GetTodayYesterdayMonthUser returns sent counts for a user.
func GetTodayYesterdayMonthUser(username string) (today, yesterday, month int64) {
	t := time.Now().Truncate(24 * time.Hour)
	todayStr := t.Format("2006-01-02")
	yesterdayStr := t.AddDate(0, 0, -1).Format("2006-01-02")
	monthStart := t.AddDate(0, -1, 0).Format("2006-01-02")
	var d DailyStats
	if err := DB.Model(&DailyStats{}).Where("stat_date = ? AND username = ?", todayStr, username).First(&d).Error; err == nil {
		today = d.Sent
	} else {
		DB.Model(&EmailLog{}).Where("username = ? AND sent_at >= ?", username, t).Count(&today)
	}
	if err := DB.Model(&DailyStats{}).Where("stat_date = ? AND username = ?", yesterdayStr, username).First(&d).Error; err == nil {
		yesterday = d.Sent
	} else {
		DB.Model(&EmailLog{}).Where("username = ? AND sent_at >= ? AND sent_at < ?", username, t.AddDate(0, 0, -1), t).Count(&yesterday)
	}
	DB.Model(&DailyStats{}).Where("username = ? AND stat_date >= ?", username, monthStart).Select("COALESCE(SUM(sent),0)").Scan(&month)
	if month == 0 {
		DB.Model(&EmailLog{}).Where("username = ? AND sent_at >= ?", username, t.AddDate(0, -1, 0)).Count(&month)
	}
	return today, yesterday, month
}

// GetDailyCountsAdmin returns delivered and hard_bounce counts per day for chart (admin).
func GetDailyCountsAdmin(days int) (labels []string, delivered, bounced []int64) {
	today := time.Now().Truncate(24 * time.Hour)
	labels = make([]string, days)
	delivered = make([]int64, days)
	bounced = make([]int64, days)
	for i := days - 1; i >= 0; i-- {
		day := today.AddDate(0, 0, -i)
		dateStr := day.Format("2006-01-02")
		labels[days-1-i] = day.Format("Jan 2")
		var d DailyStats
		if err := DB.Model(&DailyStats{}).Where("stat_date = ? AND username = ?", dateStr, "").First(&d).Error; err == nil {
			delivered[days-1-i] = d.Delivered
			bounced[days-1-i] = d.HardBounce
		} else {
			// Fallback: sum across all usernames for this date
			var sumD, sumB int64
			DB.Raw("SELECT COALESCE(SUM(delivered),0), COALESCE(SUM(hard_bounce),0) FROM daily_stats WHERE stat_date = ? AND deleted_at IS NULL", dateStr).
				Row().Scan(&sumD, &sumB)
			delivered[days-1-i], bounced[days-1-i] = sumD, sumB
			if delivered[days-1-i] == 0 && bounced[days-1-i] == 0 {
				DB.Model(&EmailLog{}).Where("sent_at >= ? AND sent_at < ? AND status = ?", day, day.Add(24*time.Hour), "delivered").Count(&delivered[days-1-i])
				DB.Model(&EmailLog{}).Where("sent_at >= ? AND sent_at < ? AND status = ?", day, day.Add(24*time.Hour), "hard_bounce").Count(&bounced[days-1-i])
			}
		}
	}
	return labels, delivered, bounced
}

// GetLast60MinuteBuckets returns per-minute incoming (queued) and outgoing (delivered) for the last 60 minutes.
// Labels are like "14:32", incoming/outgoing are counts per minute.
func GetLast60MinuteBuckets() (labels []string, incoming, outgoing []int64) {
	now := time.Now()
	labels = make([]string, 60)
	incoming = make([]int64, 60)
	outgoing = make([]int64, 60)
	since := now.Add(-60 * time.Minute).Truncate(time.Minute)

	for i := 0; i < 60; i++ {
		bucketStart := since.Add(time.Duration(i) * time.Minute)
		bucketEnd := bucketStart.Add(time.Minute)
		labels[i] = bucketStart.Format("15:04")
		DB.Model(&EmailLog{}).Where("created_at >= ? AND created_at < ?", bucketStart, bucketEnd).Count(&incoming[i])
		DB.Model(&EmailLog{}).Where("status = ? AND sent_at >= ? AND sent_at < ?", "delivered", bucketStart, bucketEnd).Count(&outgoing[i])
	}
	return labels, incoming, outgoing
}

// GetSummaryStats returns today delivered, yesterday delivered, and last 7 days total delivered.
func GetSummaryStats() (today, yesterday, last7Days int64) {
	t := time.Now().Truncate(24 * time.Hour)
	todayStr := t.Format("2006-01-02")
	yesterdayStr := t.AddDate(0, 0, -1).Format("2006-01-02")
	var d DailyStats
	if err := DB.Model(&DailyStats{}).Where("stat_date = ? AND username = ?", todayStr, "").First(&d).Error; err == nil {
		today = d.Delivered
	} else {
		DB.Model(&EmailLog{}).Where("sent_at >= ? AND status = ?", t, "delivered").Count(&today)
	}
	if err := DB.Model(&DailyStats{}).Where("stat_date = ? AND username = ?", yesterdayStr, "").First(&d).Error; err == nil {
		yesterday = d.Delivered
	} else {
		DB.Model(&EmailLog{}).Where("sent_at >= ? AND sent_at < ? AND status = ?", t.AddDate(0, 0, -1), t, "delivered").Count(&yesterday)
	}
	sevenDaysAgo := t.AddDate(0, 0, -7)
	DB.Model(&DailyStats{}).Where("username = ? AND stat_date >= ?", "", sevenDaysAgo.Format("2006-01-02")).Select("COALESCE(SUM(delivered),0)").Scan(&last7Days)
	if last7Days == 0 {
		DB.Model(&EmailLog{}).Where("sent_at >= ? AND status = ?", sevenDaysAgo, "delivered").Count(&last7Days)
	}
	return today, yesterday, last7Days
}

// GetDailyCountsUser returns delivered and hard_bounce counts per day for chart (user).
func GetDailyCountsUser(username string, days int) (labels []string, delivered, bounced []int64) {
	today := time.Now().Truncate(24 * time.Hour)
	labels = make([]string, days)
	delivered = make([]int64, days)
	bounced = make([]int64, days)
	for i := days - 1; i >= 0; i-- {
		day := today.AddDate(0, 0, -i)
		dateStr := day.Format("2006-01-02")
		labels[days-1-i] = day.Format("Jan 2")
		var d DailyStats
		if err := DB.Model(&DailyStats{}).Where("stat_date = ? AND username = ?", dateStr, username).First(&d).Error; err == nil {
			delivered[days-1-i] = d.Delivered
			bounced[days-1-i] = d.HardBounce
		} else {
			DB.Model(&EmailLog{}).Where("username = ? AND sent_at >= ? AND sent_at < ? AND status = ?", username, day, day.Add(24*time.Hour), "delivered").Count(&delivered[days-1-i])
			DB.Model(&EmailLog{}).Where("username = ? AND sent_at >= ? AND sent_at < ? AND status = ?", username, day, day.Add(24*time.Hour), "hard_bounce").Count(&bounced[days-1-i])
		}
	}
	return labels, delivered, bounced
}

// AggregateEmailLogToDailyStats aggregates all EmailLog rows into DailyStats.
// Merges with existing DailyStats (we write to both on each log), so we add EmailLog
// counts to any dates not yet in DailyStats, or use max to avoid double-count.
// For "delete logs only": we replace DailyStats from EmailLog to capture final state.
func AggregateEmailLogToDailyStats() error {
	type row struct {
		StatDate   string
		Username   string
		Sent       int64
		Delivered  int64
		Failed     int64
		Deferred   int64
		HardBounce int64
		SoftBounce int64
		Suppressed int64
	}
	var rows []row
	dateFn := "DATE(sent_at)"
	if DB.Dialector.Name() == "sqlite" {
		dateFn = "date(sent_at)"
	}
	DB.Raw(`SELECT `+dateFn+` as stat_date, COALESCE(username,'') as username,
		COUNT(*) as sent,
		SUM(CASE WHEN status='delivered' THEN 1 ELSE 0 END) as delivered,
		SUM(CASE WHEN status='failed' THEN 1 ELSE 0 END) as failed,
		SUM(CASE WHEN status='deferred' THEN 1 ELSE 0 END) as deferred,
		SUM(CASE WHEN status='hard_bounce' THEN 1 ELSE 0 END) as hard_bounce,
		SUM(CASE WHEN status='soft_bounce' THEN 1 ELSE 0 END) as soft_bounce,
		SUM(CASE WHEN status='suppressed' THEN 1 ELSE 0 END) as suppressed
		FROM email_logs WHERE deleted_at IS NULL
		GROUP BY `+dateFn+`, username`).Scan(&rows)

	// Replace DailyStats for these (date,username) with aggregated values from EmailLog.
	for _, r := range rows {
		if r.StatDate == "" {
			continue
		}
		var d DailyStats
		err := DB.Where("stat_date = ? AND username = ?", r.StatDate, r.Username).First(&d).Error
		if err != nil {
			DB.Create(&DailyStats{
				StatDate:   r.StatDate,
				Username:   r.Username,
				Sent:       r.Sent,
				Delivered:  r.Delivered,
				Failed:     r.Failed,
				Deferred:   r.Deferred,
				HardBounce: r.HardBounce,
				SoftBounce: r.SoftBounce,
				Suppressed: r.Suppressed,
			})
		} else {
			DB.Model(&d).Updates(map[string]interface{}{
				"sent":        maxInt64(d.Sent, r.Sent),
				"delivered":   maxInt64(d.Delivered, r.Delivered),
				"failed":      maxInt64(d.Failed, r.Failed),
				"deferred":    maxInt64(d.Deferred, r.Deferred),
				"hard_bounce": maxInt64(d.HardBounce, r.HardBounce),
				"soft_bounce": maxInt64(d.SoftBounce, r.SoftBounce),
				"suppressed":  maxInt64(d.Suppressed, r.Suppressed),
			})
		}
	}

	// Create admin-wide rows (username="") by summing all users per date.
	type adminRow struct {
		StatDate   string
		Sent       int64
		Delivered  int64
		Failed     int64
		Deferred   int64
		HardBounce int64
		SoftBounce int64
		Suppressed int64
	}
	var adminRows []adminRow
	DB.Raw(`SELECT stat_date,
		COALESCE(SUM(sent),0) as sent,
		COALESCE(SUM(delivered),0) as delivered,
		COALESCE(SUM(failed),0) as failed,
		COALESCE(SUM(deferred),0) as deferred,
		COALESCE(SUM(hard_bounce),0) as hard_bounce,
		COALESCE(SUM(soft_bounce),0) as soft_bounce,
		COALESCE(SUM(suppressed),0) as suppressed
		FROM daily_stats WHERE deleted_at IS NULL
		GROUP BY stat_date`).Scan(&adminRows)
	for _, ar := range adminRows {
		if ar.StatDate == "" {
			continue
		}
		var d DailyStats
		err := DB.Where("stat_date = ? AND username = ?", ar.StatDate, "").First(&d).Error
		if err != nil {
			DB.Create(&DailyStats{
				StatDate:   ar.StatDate,
				Username:   "",
				Sent:       ar.Sent,
				Delivered:  ar.Delivered,
				Failed:     ar.Failed,
				Deferred:   ar.Deferred,
				HardBounce: ar.HardBounce,
				SoftBounce: ar.SoftBounce,
				Suppressed: ar.Suppressed,
			})
		} else {
			DB.Model(&d).Updates(map[string]interface{}{
				"sent":        ar.Sent,
				"delivered":   ar.Delivered,
				"failed":      ar.Failed,
				"deferred":    ar.Deferred,
				"hard_bounce": ar.HardBounce,
				"soft_bounce": ar.SoftBounce,
				"suppressed":  ar.Suppressed,
			})
		}
	}
	return nil
}

func maxInt64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

// DeleteAllEmailLogs permanently removes all email log rows.
func DeleteAllEmailLogs() int64 {
	res := DB.Unscoped().Where("1=1").Delete(&EmailLog{})
	return res.RowsAffected
}

// DeleteLogsKeepStats aggregates EmailLog into DailyStats, then deletes all logs.
func DeleteLogsKeepStats() (int64, error) {
	if err := AggregateEmailLogToDailyStats(); err != nil {
		return 0, err
	}
	return DeleteAllEmailLogs(), nil
}

// DeleteAllData removes EmailLog and DailyStats. Statistics will be reset.
func DeleteAllData() (emailLogs int64, dailyStats int64) {
	emailLogs = DeleteAllEmailLogs()
	res := DB.Unscoped().Where("1=1").Delete(&DailyStats{})
	return emailLogs, res.RowsAffected
}

// ─── Contact Lists ───────────────────────────────────────────────────────────

func GetContactLists(username string) []ContactList {
	var lists []ContactList
	DB.Where("owner_username = ?", username).Order("name").Find(&lists)
	return lists
}

func GetContactListByID(id uint, username string) *ContactList {
	var c ContactList
	if err := DB.Where("id = ? AND owner_username = ?", id, username).First(&c).Error; err != nil {
		return nil
	}
	return &c
}

func CreateContactList(username, name, desc string) (*ContactList, error) {
	maxLists, _, _, _ := GetUserLimits(username)
	if maxLists > 0 {
		n := CountContactLists(username)
		if n >= int64(maxLists) {
			return nil, errors.New("contact list limit reached")
		}
	}
	c := &ContactList{OwnerUsername: username, Name: name, Description: desc}
	return c, DB.Create(c).Error
}

func UpdateContactList(id uint, username, name, desc string) error {
	return DB.Model(&ContactList{}).Where("id = ? AND owner_username = ?", id, username).
		Updates(map[string]interface{}{"name": name, "description": desc}).Error
}

func DeleteContactList(id uint, username string) error {
	return DB.Where("id = ? AND owner_username = ?", id, username).Delete(&ContactList{}).Error
}

// ─── Contacts ─────────────────────────────────────────────────────────────────

func GetContacts(listID uint, username string) []Contact {
	var list ContactList
	if DB.Where("id = ? AND owner_username = ?", listID, username).First(&list).Error != nil {
		return nil
	}
	var contacts []Contact
	DB.Where("list_id = ?", listID).Order("email").Find(&contacts)
	return contacts
}

func AddContact(listID uint, username, email, firstName, lastName, customFields string) error {
	var list ContactList
	if DB.Where("id = ? AND owner_username = ?", listID, username).First(&list).Error != nil {
		return errors.New("list not found")
	}
	email = strings.ToLower(strings.TrimSpace(email))
	var c Contact
	if err := DB.Where("list_id = ? AND email = ?", listID, email).First(&c).Error; err == nil {
		DB.Model(&c).Updates(map[string]interface{}{
			"first_name": firstName, "last_name": lastName, "custom_fields": customFields,
			"status": "subscribed",
		})
		return nil
	}
	return DB.Create(&Contact{
		ListID: listID, Email: email, FirstName: firstName, LastName: lastName,
		CustomFields: customFields, Status: "subscribed",
	}).Error
}

func DeleteContact(id uint, username string) error {
	var c Contact
	if DB.First(&c, id).Error != nil {
		return errors.New("contact not found")
	}
	var list ContactList
	if DB.Where("id = ? AND owner_username = ?", c.ListID, username).First(&list).Error != nil {
		return errors.New("list not found")
	}
	return DB.Delete(&c).Error
}

func CountContactsInList(listID uint) int64 {
	var n int64
	DB.Model(&Contact{}).Where("list_id = ? AND status = ?", listID, "subscribed").Count(&n)
	return n
}

func GetContactByListAndEmail(listID uint, email string) *Contact {
	email = strings.ToLower(strings.TrimSpace(email))
	var c Contact
	if DB.Where("list_id = ? AND email = ?", listID, email).First(&c).Error != nil {
		return nil
	}
	return &c
}

// ─── Campaign Templates ──────────────────────────────────────────────────────

func GetTemplates(username string) []CampaignTemplate {
	var t []CampaignTemplate
	DB.Where("owner_username = ?", username).Order("name").Find(&t)
	return t
}

func GetTemplateByID(id uint, username string) *CampaignTemplate {
	var t CampaignTemplate
	if DB.Where("id = ? AND owner_username = ?", id, username).First(&t).Error != nil {
		return nil
	}
	return &t
}

func CreateTemplate(username, name, subject, fromName, fromEmail, replyTo, htmlBody, textBody, designJSON string) (*CampaignTemplate, error) {
	_, _, _, maxTmpl := GetUserLimits(username)
	if maxTmpl > 0 {
		n := CountTemplates(username)
		if n >= int64(maxTmpl) {
			return nil, errors.New("template limit reached")
		}
	}
	t := &CampaignTemplate{
		OwnerUsername: username, Name: name, Subject: subject,
		FromName: fromName, FromEmail: fromEmail, ReplyTo: replyTo,
		HTMLBody: htmlBody, TextBody: textBody, DesignJSON: designJSON,
	}
	return t, DB.Create(t).Error
}

func UpdateTemplate(id uint, username, name, subject, fromName, fromEmail, replyTo, htmlBody, textBody, designJSON string) error {
	updates := map[string]interface{}{
		"name": name, "subject": subject,
		"from_name": fromName, "from_email": fromEmail, "reply_to": replyTo,
		"html_body": htmlBody, "text_body": textBody,
	}
	if designJSON != "" {
		updates["design_json"] = designJSON
	}
	return DB.Model(&CampaignTemplate{}).Where("id = ? AND owner_username = ?", id, username).Updates(updates).Error
}

func DeleteTemplate(id uint, username string) error {
	return DB.Where("id = ? AND owner_username = ?", id, username).Delete(&CampaignTemplate{}).Error
}

// ─── Campaigns ───────────────────────────────────────────────────────────────

func GetCampaigns(username string) []Campaign {
	var c []Campaign
	DB.Where("owner_username = ?", username).Order("created_at desc").Find(&c)
	return c
}

func GetCampaignByID(id uint, username string) *Campaign {
	var c Campaign
	if DB.Where("id = ? AND owner_username = ?", id, username).First(&c).Error != nil {
		return nil
	}
	return &c
}

func CreateCampaign(username string, camp *Campaign) error {
	maxCamp, _, _, _ := GetUserLimits(username)
	if maxCamp > 0 {
		n := CountCampaigns(username)
		if n >= int64(maxCamp) {
			return errors.New("campaign limit reached")
		}
	}
	camp.OwnerUsername = username
	return DB.Create(camp).Error
}

func UpdateCampaign(id uint, username string, updates map[string]interface{}) error {
	return DB.Model(&Campaign{}).Where("id = ? AND owner_username = ?", id, username).Updates(updates).Error
}

func DeleteCampaign(id uint, username string) error {
	return DB.Where("id = ? AND owner_username = ?", id, username).Delete(&Campaign{}).Error
}

// CreateCampaignSend creates a send record with a unique tracking token. Returns (token, sendID, error).
func CreateCampaignSend(campaignID, contactID uint, email string) (string, uint, error) {
	token, err := generateTrackToken()
	if err != nil {
		return "", 0, err
	}
	s := &CampaignSend{CampaignID: campaignID, ContactID: contactID, Email: email, TrackToken: token, Status: "queued"}
	if err := DB.Create(s).Error; err != nil {
		return "", 0, err
	}
	return token, s.ID, nil
}

// UpdateCampaignSendMessageID stores the queue message ID for delivery status lookup.
func UpdateCampaignSendMessageID(sendID uint, messageID string) {
	DB.Model(&CampaignSend{}).Where("id = ?", sendID).Update("message_id", messageID)
}

// UpdateCampaignSendByMessageID updates status and sent_at when delivery completes.
func UpdateCampaignSendByMessageID(messageID, status string) {
	updates := map[string]interface{}{"status": status}
	if status == "sent" {
		updates["sent_at"] = time.Now()
	}
	DB.Model(&CampaignSend{}).Where("message_id = ?", messageID).Updates(updates)
}

func generateTrackToken() (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}

// CampaignSendByToken finds a send by its tracking token (for pixel/click).
func CampaignSendByToken(token string) *CampaignSend {
	var s CampaignSend
	if DB.Where("track_token = ?", token).First(&s).Error != nil {
		return nil
	}
	return &s
}

func RecordOpen(token string, ip, ua string) bool {
	s := CampaignSendByToken(token)
	if s == nil {
		return false
	}
	now := time.Now()
	if s.OpenedAt == nil {
		DB.Model(s).Updates(map[string]interface{}{"opened_at": now})
		DB.Model(&Campaign{}).Where("id = ?", s.CampaignID).UpdateColumn("opens", gorm.Expr("opens + 1"))
	}
	DB.Create(&TrackEvent{SendID: s.ID, EventType: "open", IP: ip, UserAgent: ua, EventAt: now})
	return true
}

// GetCampaignSends returns all sends for a campaign. Caller must verify campaign ownership.
func GetCampaignSends(campaignID uint) []CampaignSend {
	var sends []CampaignSend
	DB.Where("campaign_id = ?", campaignID).Order("created_at desc").Find(&sends)
	return sends
}

func RecordClick(token string, url string, ip, ua string) bool {
	s := CampaignSendByToken(token)
	if s == nil {
		return false
	}
	now := time.Now()
	if s.ClickedAt == nil {
		DB.Model(s).Updates(map[string]interface{}{"clicked_at": now})
		DB.Model(&Campaign{}).Where("id = ?", s.CampaignID).UpdateColumn("clicks", gorm.Expr("clicks + 1"))
	}
	DB.Create(&TrackEvent{SendID: s.ID, EventType: "click", URL: url, IP: ip, UserAgent: ua, EventAt: now})
	return true
}

// ─── Automations ─────────────────────────────────────────────────────────────

func GetAutomations(username string) []Automation {
	var a []Automation
	DB.Where("owner_username = ?", username).Order("created_at desc").Find(&a)
	return a
}

func GetAutomationByID(id uint, username string) *Automation {
	var a Automation
	if DB.Where("id = ? AND owner_username = ?", id, username).First(&a).Error != nil {
		return nil
	}
	return &a
}

func CreateAutomation(username string, a *Automation) error {
	_, maxAuto, _, _ := GetUserLimits(username)
	if maxAuto > 0 {
		n := CountAutomations(username)
		if n >= int64(maxAuto) {
			return errors.New("automation limit reached")
		}
	}
	a.OwnerUsername = username
	return DB.Create(a).Error
}

func UpdateAutomation(id uint, username string, updates map[string]interface{}) error {
	return DB.Model(&Automation{}).Where("id = ? AND owner_username = ?", id, username).Updates(updates).Error
}

func DeleteAutomation(id uint, username string) error {
	return DB.Where("id = ? AND owner_username = ?", id, username).Delete(&Automation{}).Error
}

func GetAutomationSteps(automationID uint) []AutomationStep {
	var s []AutomationStep
	DB.Where("automation_id = ?", automationID).Order("step_order").Find(&s)
	return s
}

func AddAutomationStep(automationID uint, order int, actionType string, templateID uint, delayMin int, tag string) error {
	return DB.Create(&AutomationStep{
		AutomationID: automationID, StepOrder: order, ActionType: actionType,
		TemplateID: templateID, DelayMinutes: delayMin, TagName: tag,
	}).Error
}

func DeleteAutomationStep(id uint) error {
	return DB.Delete(&AutomationStep{}, id).Error
}

// CreateAutomationSend records an automation email send.
func CreateAutomationSend(automationID, contactID uint, email string) error {
	now := time.Now()
	return DB.Create(&AutomationSend{AutomationID: automationID, ContactID: contactID, Email: email, Status: "sent", SentAt: &now}).Error
}

// GetAutomationSends returns all sends for an automation. Caller must verify automation ownership.
func GetAutomationSends(automationID uint) []AutomationSend {
	var sends []AutomationSend
	DB.Where("automation_id = ?", automationID).Order("created_at desc").Find(&sends)
	return sends
}

// CountAutomationSends returns total sends for an automation.
func CountAutomationSends(automationID uint) int64 {
	var n int64
	DB.Model(&AutomationSend{}).Where("automation_id = ?", automationID).Count(&n)
	return n
}

// CountCampaigns returns the number of campaigns for a user.
func CountCampaigns(username string) int64 {
	var n int64
	DB.Model(&Campaign{}).Where("owner_username = ?", username).Count(&n)
	return n
}

// CountAutomations returns the number of automations for a user.
func CountAutomations(username string) int64 {
	var n int64
	DB.Model(&Automation{}).Where("owner_username = ?", username).Count(&n)
	return n
}

// CountContactLists returns the number of contact lists for a user.
func CountContactLists(username string) int64 {
	var n int64
	DB.Model(&ContactList{}).Where("owner_username = ?", username).Count(&n)
	return n
}

// CountTemplates returns the number of templates for a user.
func CountTemplates(username string) int64 {
	var n int64
	DB.Model(&CampaignTemplate{}).Where("owner_username = ?", username).Count(&n)
	return n
}

// GetUserLimits returns MaxCampaigns, MaxAutomations, MaxLists, MaxTemplates for a user. 0 = unlimited.
func GetUserLimits(username string) (maxCamp, maxAuto, maxLists, maxTmpl int) {
	var u User
	if DB.Where("username = ?", username).First(&u).Error != nil {
		return 0, 0, 0, 0
	}
	return u.MaxCampaigns, u.MaxAutomations, u.MaxLists, u.MaxTemplates
}

// GetCampaignStatsUser returns total sent, opens, clicks for a user's campaigns.
func GetCampaignStatsUser(username string) (sent, opens, clicks int) {
	var s, o, c int64
	DB.Model(&Campaign{}).Where("owner_username = ? AND status = ?", username, "sent").Select("COALESCE(SUM(total_sent),0)").Scan(&s)
	DB.Model(&Campaign{}).Where("owner_username = ? AND status = ?", username, "sent").Select("COALESCE(SUM(opens),0)").Scan(&o)
	DB.Model(&Campaign{}).Where("owner_username = ? AND status = ?", username, "sent").Select("COALESCE(SUM(clicks),0)").Scan(&c)
	return int(s), int(o), int(c)
}

// Admin: all campaigns across users
func GetAllCampaigns() []Campaign {
	var c []Campaign
	DB.Order("created_at desc").Find(&c)
	return c
}

// Admin: all automations across users
func GetAllAutomations() []Automation {
	var a []Automation
	DB.Order("created_at desc").Find(&a)
	return a
}
