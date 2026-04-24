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
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/glebarez/sqlite"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var DB *gorm.DB

// forceEmailRotate is the round-robin index for force-email address rotation.
var forceEmailRotate atomic.Uint64

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

	// Configure connection pool and SQLite-specific performance settings.
	if sqlDB, err2 := DB.DB(); err2 == nil {
		if driver == "sqlite" {
			// WAL mode: readers don't block writers and writers don't block readers.
			// This eliminates the "database is locked" stalls that slow the UI under
			// concurrent delivery + dashboard polling.
			DB.Exec("PRAGMA journal_mode=WAL;")
			// NORMAL is safe with WAL (only loses the last committed transaction on
			// a power-cut, not the whole database).
			DB.Exec("PRAGMA synchronous=NORMAL;")
			// 32 MB in-process page cache (negative value = KiB).
			DB.Exec("PRAGMA cache_size=-32000;")
			// Wait up to 10 s instead of immediately returning SQLITE_BUSY when
			// another connection holds the write lock.
			DB.Exec("PRAGMA busy_timeout=10000;")
			// temp_store=MEMORY keeps temp tables / sort buffers in RAM.
			DB.Exec("PRAGMA temp_store=MEMORY;")

			// Keep a modest pool; WAL allows concurrent reads.
			sqlDB.SetMaxOpenConns(25)
			sqlDB.SetMaxIdleConns(5)
		} else {
			// MySQL: allow a generous pool for concurrent delivery workers.
			sqlDB.SetMaxOpenConns(100)
			sqlDB.SetMaxIdleConns(25)
		}
		sqlDB.SetConnMaxLifetime(10 * time.Minute)
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
		&UserIPAssignment{},
		&UserForceFrom{},
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
		&SkipDomain{},
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

// LogQueued writes a queued log entry for every recipient using a batch insert
// so large campaigns (thousands of recipients) only need one round-trip per 500 rows.
func LogQueued(username, msgID, from string, recipients []string) {
	if len(recipients) == 0 {
		return
	}
	now := time.Now()
	statDate := now.Format("2006-01-02")
	rows := make([]EmailLog, len(recipients))
	for i, rcpt := range recipients {
		rows[i] = EmailLog{
			Username:  username,
			MessageID: msgID,
			From:      from,
			Recipient: rcpt,
			Status:    "queued",
			SentAt:    now,
		}
	}
	DB.CreateInBatches(rows, 500)
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
	now := time.Now()
	statDate := now.Format("2006-01-02")
	DB.Model(&EmailLog{}).
		Where("message_id = ? AND recipient = ?", msgID, recipient).
		Updates(map[string]interface{}{
			"status":  "failed",
			"error":   errMsg,
			"sent_at": now, // outcome time (was missing — table/banner used queue time)
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
	now := time.Now()
	statDate := now.Format("2006-01-02")
	DB.Model(&EmailLog{}).
		Where("message_id = ? AND recipient = ?", msgID, recipient).
		Updates(map[string]interface{}{
			"status":  "hard_bounce",
			"error":   errMsg,
			"sent_at": now, // bounce time (was missing — UI showed queue time)
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

// ──────────────────────────── User IP Assignments ────────────────────────────

// GetUserIPAssignments returns all IP pool entries assigned to a specific user.
func GetUserIPAssignments(username string) []IPPool {
	var assignments []UserIPAssignment
	DB.Preload("IPPool").Where("username = ?", username).Find(&assignments)
	pools := make([]IPPool, 0, len(assignments))
	for _, a := range assignments {
		pools = append(pools, a.IPPool)
	}
	return pools
}

// GetAllUserIPAssignments returns every assignment row for the admin overview.
func GetAllUserIPAssignments() []UserIPAssignment {
	var rows []UserIPAssignment
	DB.Preload("IPPool").Order("username asc").Find(&rows)
	return rows
}

// AssignIPToUser creates an exclusive assignment of an IP to a user.
// Returns an error if the IP is already assigned to any user (including the same user),
// enforcing IP exclusivity at the database level as well as the engine level.
func AssignIPToUser(username string, ipPoolID uint) error {
	// Check whether this IP pool entry is already assigned to anyone.
	var count int64
	DB.Model(&UserIPAssignment{}).Where("ip_pool_id = ?", ipPoolID).Count(&count)
	if count > 0 {
		// If it's already assigned to the same user it's a no-op conflict; if
		// it's another user it's an exclusivity violation — either way reject.
		var existing UserIPAssignment
		DB.Where("ip_pool_id = ?", ipPoolID).First(&existing)
		if existing.Username == username {
			return fmt.Errorf("this IP is already assigned to %s", username)
		}
		return fmt.Errorf("this IP is already assigned to user %q — unassign it first", existing.Username)
	}
	row := UserIPAssignment{Username: username, IPPoolID: ipPoolID}
	return DB.Create(&row).Error
}

// UnassignIPFromUser removes a specific IP assignment from a user.
func UnassignIPFromUser(id uint) error {
	return DB.Unscoped().Where("id = ?", id).Delete(&UserIPAssignment{}).Error
}

// GetUserAssignedIPSet returns the set of IP strings assigned to a user.
// Returns nil (empty map) when the user has no assignments (use full pool).
func GetUserAssignedIPSet(username string) map[string]bool {
	pools := GetUserIPAssignments(username)
	if len(pools) == 0 {
		return nil
	}
	set := make(map[string]bool, len(pools))
	for _, p := range pools {
		set[p.IP] = true
	}
	return set
}

// GetAllAssignedIPs returns the set of every IP address that is assigned to
// at least one user. Used to exclude these IPs from the shared pool so that
// unassigned users cannot accidentally consume IPs reserved for specific users.
func GetAllAssignedIPs() map[string]bool {
	var assignments []UserIPAssignment
	DB.Preload("IPPool").Find(&assignments)
	if len(assignments) == 0 {
		return nil
	}
	set := make(map[string]bool, len(assignments))
	for _, a := range assignments {
		if a.IPPool.IP != "" {
			set[a.IPPool.IP] = true
		}
	}
	return set
}

// GetUnassignedActiveIPPool returns active IP pool entries that are NOT yet
// assigned to any user. Use this to populate the assignment dropdown so that
// already-exclusive IPs cannot be accidentally assigned again.
func GetUnassignedActiveIPPool() []IPPool {
	// Collect all IPPool IDs that already have at least one assignment.
	var assigned []UserIPAssignment
	DB.Select("ip_pool_id").Find(&assigned)
	assignedIDs := make([]uint, 0, len(assigned))
	for _, a := range assigned {
		assignedIDs = append(assignedIDs, a.IPPoolID)
	}
	var entries []IPPool
	q := DB.Where("active = ?", true)
	if len(assignedIDs) > 0 {
		q = q.Not("id IN ?", assignedIDs)
	}
	q.Order("ip asc").Find(&entries)
	return entries
}

// ──────────────────────────── Per-User Force From ─────────────────────────────

// userForceFromRotate stores per-username round-robin counters for From address rotation.
var userForceFromRotate sync.Map // username -> *atomic.Uint64

func userForceFromCounter(username string) *atomic.Uint64 {
	val, _ := userForceFromRotate.LoadOrStore(username, new(atomic.Uint64))
	return val.(*atomic.Uint64)
}

// GetAllUserForceFroms returns every configured user Force From record.
func GetAllUserForceFroms() []UserForceFrom {
	var rows []UserForceFrom
	DB.Order("username asc").Find(&rows)
	return rows
}

// GetUserForceFrom returns the Force From config for a specific user, or nil if none exists.
func GetUserForceFrom(username string) *UserForceFrom {
	var row UserForceFrom
	if err := DB.Where("username = ?", username).First(&row).Error; err != nil {
		return nil
	}
	return &row
}

// SetUserForceFrom upserts the Force From / Force Email From config for a user.
// domains and addresses are newline-separated; templateEnabled controls template rotation.
func SetUserForceFrom(username string, enabled bool, domains, addresses string, templateEnabled bool) error {
	var row UserForceFrom
	err := DB.Where("username = ?", username).First(&row).Error
	if err != nil {
		return DB.Create(&UserForceFrom{
			Username:        username,
			Enabled:         enabled,
			Domains:         domains,
			Addresses:       addresses,
			TemplateEnabled: templateEnabled,
		}).Error
	}
	return DB.Model(&row).Updates(map[string]interface{}{
		"enabled":          enabled,
		"domains":          domains,
		"addresses":        addresses,
		"template_enabled": templateEnabled,
	}).Error
}

// DeleteUserForceFrom removes the Force From config for a user.
func DeleteUserForceFrom(username string) error {
	return DB.Where("username = ?", username).Delete(&UserForceFrom{}).Error
}

// GetUserForceFromTemplates returns the subject/body template list for a user.
func GetUserForceFromTemplates(username string) []ForceEmailTemplate {
	cfg := GetUserForceFrom(username)
	if cfg == nil || cfg.Templates == "" {
		return nil
	}
	var out []ForceEmailTemplate
	if err := json.Unmarshal([]byte(cfg.Templates), &out); err != nil {
		return nil
	}
	return out
}

// SetUserForceFromTemplates saves the template list for a user.
func SetUserForceFromTemplates(username string, templates []ForceEmailTemplate) error {
	raw, err := json.Marshal(templates)
	if err != nil {
		return err
	}
	cfg := GetUserForceFrom(username)
	if cfg == nil {
		return DB.Create(&UserForceFrom{Username: username, Templates: string(raw)}).Error
	}
	return DB.Model(cfg).Update("templates", string(raw)).Error
}

// SetUserForceFromTemplateEnabled sets the template-enabled flag for a user.
func SetUserForceFromTemplateEnabled(username string, enabled bool) error {
	cfg := GetUserForceFrom(username)
	if cfg == nil {
		return DB.Create(&UserForceFrom{Username: username, TemplateEnabled: enabled}).Error
	}
	return DB.Model(cfg).Update("template_enabled", enabled).Error
}

// GetNextUserForceEmail applies the per-user Force From / Force Email From / Force Template
// config for username and returns the rewritten From address plus optional subject and body.
// Returns (originalFrom, "", "", false) if the user has no active config.
func GetNextUserForceEmail(username, originalFrom string) (from, subject, body string, applied bool) {
	cfg := GetUserForceFrom(username)
	if cfg == nil {
		return originalFrom, "", "", false
	}

	from = originalFrom
	idx := userForceFromCounter(username).Add(1) - 1

	// From address rewriting (only when Enabled).
	if cfg.Enabled {
		// Full address list takes precedence over domain rotation.
		if addrs := parseLines(cfg.Addresses, true); len(addrs) > 0 {
			addr := addrs[int(idx)%len(addrs)]
			if !strings.Contains(addr, "<") {
				if dn := extractDisplayNameFromAddr(originalFrom); dn != "" {
					addr = dn + " <" + strings.TrimSpace(addr) + ">"
				}
			}
			from = addr
			applied = true
		} else if domains := parseLines(cfg.Domains, false); len(domains) > 0 {
			local := extractLocalPartFromAddr(originalFrom)
			if local == "" {
				local = "noreply"
			}
			domain := strings.ToLower(domains[int(idx)%len(domains)])
			dn := extractDisplayNameFromAddr(originalFrom)
			if dn != "" {
				from = dn + " <" + local + "@" + domain + ">"
			} else {
				from = local + "@" + domain
			}
			applied = true
		}
	}

	// Template rotation (independent of From rewriting, controlled by TemplateEnabled).
	if cfg.TemplateEnabled {
		templates := GetUserForceFromTemplates(username)
		if len(templates) > 0 {
			t := templates[int(idx)%len(templates)]
			subject = t.Subject
			body = t.Body
			applied = true
		}
	}

	return from, subject, body, applied
}

// parseLines splits text into trimmed, non-empty, non-comment lines.
// If requireAt is true only lines containing "@" are kept (for addresses).
// Values are returned as-is (no case transformation) so display names are preserved.
func parseLines(raw string, requireAt bool) []string {
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		s := strings.TrimSpace(line)
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		if requireAt && !strings.Contains(s, "@") {
			continue
		}
		out = append(out, s)
	}
	return out
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

// ──────────────────────────── Force Email Templates ────────────────────────────

// ForceEmailTemplate is one template in the rotation (Subject + Body only).
type ForceEmailTemplate struct {
	Subject string `json:"subject"`
	Body    string `json:"body"`
}

// GetForceEmailEnabled returns the legacy master switch (force_email_enabled).
// Prefer GetForceRewriteShouldRun for the pipeline and GetForceTemplateEnabled / GetForceEmailFromEnabled for UI.
func GetForceEmailEnabled() bool {
	return GetSetting("force_email_enabled", "false") == "true"
}

// GetForceTemplateEnabled returns true when subject/body template rotation is enabled.
// If force_template_enabled was never set, falls back to legacy force_email_enabled so existing installs keep behavior.
func GetForceTemplateEnabled() bool {
	switch GetSetting("force_template_enabled", "") {
	case "true":
		return true
	case "false":
		return false
	default:
		return GetForceEmailEnabled()
	}
}

// SetForceTemplateEnabled persists the Force Template toggle.
func SetForceTemplateEnabled(enabled bool) error {
	val := "false"
	if enabled {
		val = "true"
	}
	return SetSetting("force_template_enabled", val)
}

// GetForceRewriteShouldRun is true when at least one force feature can apply (has data and is enabled).
func GetForceRewriteShouldRun() bool {
	if GetForceFromEnabled() && len(GetForceFromDomains()) > 0 {
		return true
	}
	if GetForceEmailFromEnabled() && len(GetForceEmailAddresses()) > 0 {
		return true
	}
	if GetForceTemplateEnabled() && len(GetForceEmailTemplates()) > 0 {
		return true
	}
	return false
}

// GetForceEmailFromEnabled returns true if force-email From address override is enabled.
func GetForceEmailFromEnabled() bool {
	return GetSetting("force_email_from_enabled", "false") == "true"
}

// GetForceEmailAddressesRaw returns the raw addresses string (newline-separated) for the text box.
func GetForceEmailAddressesRaw() string {
	return GetSetting("force_email_addresses", "")
}

// GetForceEmailAddresses returns the list of From addresses for rotation.
func GetForceEmailAddresses() []string {
	raw := GetForceEmailAddressesRaw()
	if raw == "" {
		// Migrate from old format (addresses were in each template)
		rawTpl := GetSetting("force_email_templates", "")
		if rawTpl != "" && strings.Contains(rawTpl, "address") {
			var old []struct {
				Address string `json:"address"`
			}
			if json.Unmarshal([]byte(rawTpl), &old) == nil {
				var out []string
				for _, t := range old {
					if s := strings.TrimSpace(t.Address); s != "" && strings.Contains(s, "@") {
						out = append(out, s)
					}
				}
				return out
			}
		}
		return nil
	}
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		s := strings.TrimSpace(line)
		if s != "" && !strings.HasPrefix(s, "#") && strings.Contains(s, "@") {
			out = append(out, s)
		}
	}
	return out
}

// GetForceEmailTemplates returns the list of templates (Subject + Body) for rotation.
func GetForceEmailTemplates() []ForceEmailTemplate {
	raw := GetSetting("force_email_templates", "")
	if raw == "" {
		return nil
	}
	var out []ForceEmailTemplate
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil
	}
	return out
}

// SetForceEmailConfig saves template toggle, from-address config, and templates.
func SetForceEmailConfig(templateEnabled bool, fromEnabled bool, addressesRaw string, templates []ForceEmailTemplate) error {
	if err := SetForceTemplateEnabled(templateEnabled); err != nil {
		return err
	}
	if err := SetForceEmailFromConfig(fromEnabled, addressesRaw); err != nil {
		return err
	}
	return SetForceEmailTemplates(templates)
}

// SetForceEmailFromConfig saves from-address enable flag and address list (not templates).
func SetForceEmailFromConfig(fromEnabled bool, addressesRaw string) error {
	fromVal := "false"
	if fromEnabled {
		fromVal = "true"
	}
	if err := SetSetting("force_email_from_enabled", fromVal); err != nil {
		return err
	}
	return SetSetting("force_email_addresses", addressesRaw)
}

// SetForceEmailBasicConfig saves template toggle, from-enabled, and addresses (legacy name kept for callers that used "master" + from).
func SetForceEmailBasicConfig(templateEnabled bool, fromEnabled bool, addressesRaw string) error {
	if err := SetForceTemplateEnabled(templateEnabled); err != nil {
		return err
	}
	return SetForceEmailFromConfig(fromEnabled, addressesRaw)
}

// SetForceEmailTemplates saves only the templates list.
func SetForceEmailTemplates(templates []ForceEmailTemplate) error {
	js, _ := json.Marshal(templates)
	return SetSetting("force_email_templates", string(js))
}

// LinkTrackingMapping maps a destination URL to its Mautic tracking ID.
// When Force Template body overrides content, we replace template URLs with full tracking URLs from the original.
type LinkTrackingMapping struct {
	URL        string `json:"url"`         // destination URL (e.g. https://cashpilots.com/)
	TrackingID string `json:"tracking_id"`  // Mautic tracking ID (e.g. e6fb3960ba7c2db48103e8249)
}

// GetLinkTrackingMappings returns URL → Tracking ID mappings for link tracking preservation.
func GetLinkTrackingMappings() []LinkTrackingMapping {
	raw := GetSetting("link_tracking_mappings", "")
	if raw == "" {
		return nil
	}
	var out []LinkTrackingMapping
	if err := json.Unmarshal([]byte(raw), &out); err != nil {
		return nil
	}
	return out
}

// SetLinkTrackingMappings saves the link tracking mappings.
func SetLinkTrackingMappings(mappings []LinkTrackingMapping) error {
	js, _ := json.Marshal(mappings)
	return SetSetting("link_tracking_mappings", string(js))
}

// GetLinkTrackingMappingsRaw returns mappings as "URL|TrackingID" per line for the admin textarea.
func GetLinkTrackingMappingsRaw() string {
	m := GetLinkTrackingMappings()
	if len(m) == 0 {
		return ""
	}
	var b strings.Builder
	for i, x := range m {
		if i > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(strings.TrimSpace(x.URL))
		b.WriteString("|")
		b.WriteString(strings.TrimSpace(x.TrackingID))
	}
	return b.String()
}

// GetLinkTrackingRedirectBase returns the Mautic redirect base URL (e.g. https://email.inboxdailyapp.com).
// When the original email has no tracking links, we use {base}/r/{tracking_id} as fallback.
func GetLinkTrackingRedirectBase() string {
	return GetSetting("link_tracking_redirect_base", "")
}

// SetLinkTrackingRedirectBase saves the redirect base URL.
func SetLinkTrackingRedirectBase(base string) error {
	return SetSetting("link_tracking_redirect_base", strings.TrimSpace(base))
}

// SetLinkTrackingMappingsFromRaw parses "URL|TrackingID" per line and saves.
func SetLinkTrackingMappingsFromRaw(raw string) error {
	var mappings []LinkTrackingMapping
	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, "|", 2)
		if len(parts) != 2 {
			continue
		}
		u := strings.TrimSpace(parts[0])
		tid := strings.TrimSpace(parts[1])
		if u != "" && tid != "" {
			mappings = append(mappings, LinkTrackingMapping{URL: u, TrackingID: tid})
		}
	}
	return SetLinkTrackingMappings(mappings)
}

// GetNextForceEmail returns the next From address and template.
// Force Template, Force Email From, and Force From each have their own enable flag.
// Force Email From address takes precedence over Force From domain when both apply.
func GetNextForceEmail(originalFrom string) (from string, subject, body string, applied bool) {
	templates := GetForceEmailTemplates()
	hasTemplates := len(templates) > 0
	forceTemplateOn := GetForceTemplateEnabled()
	forceEmailFromOn := GetForceEmailFromEnabled()
	forceFromOn := GetForceFromEnabled()

	if !GetForceRewriteShouldRun() {
		return originalFrom, "", "", false
	}

	idx := forceEmailRotate.Add(1) - 1
	from = originalFrom

	// From address: configured list takes precedence; else Force From domain rotation
	if forceEmailFromOn {
		addrs := GetForceEmailAddresses()
		if len(addrs) > 0 {
			addr := addrs[int(idx)%len(addrs)]
			if !strings.Contains(addr, "<") {
				displayName := extractDisplayNameFromAddr(originalFrom)
				if displayName != "" {
					addr = displayName + " <" + strings.TrimSpace(addr) + ">"
				}
			}
			from = addr
			applied = true
		}
	} else if forceFromOn {
		domains := GetForceFromDomains()
		if len(domains) > 0 {
			local := extractLocalPartFromAddr(originalFrom)
			if local == "" {
				local = "noreply"
			}
			domainIdx := forceFromRotate.Add(1) - 1
			domain := domains[int(domainIdx)%len(domains)]
			displayName := extractDisplayNameFromAddr(originalFrom)
			if displayName != "" {
				from = displayName + " <" + local + "@" + domain + ">"
			} else {
				from = local + "@" + domain
			}
			applied = true
		}
	}

	// Templates: only when Force Template is ON
	if forceTemplateOn && hasTemplates {
		t := templates[int(idx)%len(templates)]
		subject = t.Subject
		body = t.Body
		applied = true
	}
	return from, subject, body, applied
}

// ApplyForceAddress returns the From address when Force From is enabled. Used when GetNextForceEmail is not called.
func ApplyForceAddress(originalFrom string) (newFrom string, applied bool) {
	if GetForceFromEnabled() {
		domains := GetForceFromDomains()
		if len(domains) > 0 {
			local := extractLocalPartFromAddr(originalFrom)
			if local == "" {
				local = "noreply"
			}
			idx := forceFromRotate.Add(1) - 1
			domain := domains[int(idx)%len(domains)]
			displayName := extractDisplayNameFromAddr(originalFrom)
			if displayName != "" {
				return displayName + " <" + local + "@" + domain + ">", true
			}
			return local + "@" + domain, true
		}
	}
	return originalFrom, false
}

var forceFromRotate atomic.Uint64

func extractLocalPartFromAddr(addr string) string {
	addr = strings.TrimSpace(addr)
	if start := strings.LastIndex(addr, "<"); start >= 0 {
		if end := strings.Index(addr[start:], ">"); end >= 0 {
			addr = addr[start+1 : start+end]
		}
	}
	if at := strings.Index(addr, "@"); at > 0 {
		return strings.TrimSpace(addr[:at])
	}
	return ""
}

// extractDisplayNameFromAddr returns the display name from "Name <email@domain.com>" or "" if none.
func extractDisplayNameFromAddr(addr string) string {
	addr = strings.TrimSpace(addr)
	start := strings.LastIndex(addr, "<")
	if start <= 0 {
		return ""
	}
	name := strings.TrimSpace(addr[:start])
	if name == "" {
		return ""
	}
	// Remove surrounding quotes if present
	if len(name) >= 2 && name[0] == '"' && name[len(name)-1] == '"' {
		name = strings.TrimSpace(name[1 : len(name)-1])
	}
	return name
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

// ──────────────────────────── Skip Domains ───────────────────────────────────

// GetAllSkipDomains returns every domain on the skip list, newest first.
func GetAllSkipDomains() []SkipDomain {
	var list []SkipDomain
	DB.Order("domain asc").Find(&list)
	return list
}

// AddSkipDomain adds a domain to the skip list (idempotent on duplicate).
func AddSkipDomain(domain, note string) error {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return fmt.Errorf("domain required")
	}
	// Soft-delete safe upsert: restore if previously deleted.
	var s SkipDomain
	err := DB.Unscoped().Where("domain = ?", domain).First(&s).Error
	var dbErr error
	if err != nil {
		dbErr = DB.Create(&SkipDomain{Domain: domain, Note: note}).Error
	} else {
		dbErr = DB.Unscoped().Model(&s).Updates(map[string]interface{}{
			"note": note, "deleted_at": nil,
		}).Error
	}
	if dbErr == nil {
		invalidateSkipDomainsCache()
	}
	return dbErr
}

// DeleteSkipDomain permanently removes a domain from the skip list.
func DeleteSkipDomain(id uint) {
	DB.Unscoped().Delete(&SkipDomain{}, id)
	invalidateSkipDomainsCache()
}

// skipDomainCache is an in-process cache of the skip-domain set.
// The delivery engine calls IsDomainSkipped for every unique recipient domain on
// every message; caching avoids N DB round-trips under high-volume sending.
var (
	skipDomainsMu     sync.RWMutex
	skipDomainsSet    map[string]struct{}
	skipDomainsExpiry time.Time
)

const skipDomainsCacheTTL = 60 * time.Second

func invalidateSkipDomainsCache() {
	skipDomainsMu.Lock()
	skipDomainsSet = nil
	skipDomainsMu.Unlock()
}

func loadSkipDomainsCache() map[string]struct{} {
	var list []SkipDomain
	DB.Select("domain").Find(&list)
	m := make(map[string]struct{}, len(list))
	for _, d := range list {
		m[d.Domain] = struct{}{}
	}
	return m
}

// IsDomainSkipped returns true when the lowercase recipient domain is on the skip list.
// Results are cached for 60 seconds to avoid a DB round-trip on every message.
func IsDomainSkipped(domain string) bool {
	domain = strings.ToLower(strings.TrimSpace(domain))
	if domain == "" {
		return false
	}
	skipDomainsMu.RLock()
	if skipDomainsSet != nil && time.Now().Before(skipDomainsExpiry) {
		_, ok := skipDomainsSet[domain]
		skipDomainsMu.RUnlock()
		return ok
	}
	skipDomainsMu.RUnlock()

	// Refresh cache under write lock (double-check to avoid thundering herd).
	skipDomainsMu.Lock()
	defer skipDomainsMu.Unlock()
	if skipDomainsSet != nil && time.Now().Before(skipDomainsExpiry) {
		_, ok := skipDomainsSet[domain]
		return ok
	}
	skipDomainsSet = loadSkipDomainsCache()
	skipDomainsExpiry = time.Now().Add(skipDomainsCacheTTL)
	_, ok := skipDomainsSet[domain]
	return ok
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

// UpdateUserSMTP updates the from_address, sending rate limits, and verify flag for an SMTP entry.
func UpdateUserSMTP(id uint, username, fromAddress string, limitPerMin, limitPerHour, limitPerDay int, verifyBeforeSend bool) error {
	if limitPerMin < 0 {
		limitPerMin = 0
	}
	if limitPerHour < 0 {
		limitPerHour = 0
	}
	if limitPerDay < 0 {
		limitPerDay = 0
	}
	// Select() forces GORM to write every listed column, including zero/false values.
	// Without it, GORM silently skips boolean false when using Updates(map{...}).
	// We use DB.Table("user_smtps") to ensure we are targeting the right table and avoiding model hooks if any.
	return DB.Table("user_smtps").
		Where("id = ? AND owner_username = ?", id, username).
		Updates(map[string]interface{}{
			"from_address":       strings.TrimSpace(fromAddress),
			"limit_per_min":      limitPerMin,
			"limit_per_hour":     limitPerHour,
			"limit_per_day":      limitPerDay,
			"verify_before_send": verifyBeforeSend,
		}).Error
}

// RelayStats holds delivery counters for one custom SMTP relay.
type RelayStats struct {
	TodaySent     int64
	YesterdaySent int64
	TotalSent     int64
}

// GetUserRelayStats returns delivered-email counters grouped by relay label for a user.
// Map key is the relay label as stored in UserSMTP.Label.
// Counts are taken from email_logs.mx_host which is set to "via relay: <label>"
// for every message delivered through a custom relay.
func GetUserRelayStats(username string) map[string]RelayStats {
	type row struct {
		MXHost    string
		Total     int64
		TodayN    int64
		YesterdayN int64
	}

	now := time.Now()
	todayStart := now.Truncate(24 * time.Hour)
	yesterdayStart := todayStart.Add(-24 * time.Hour)

	var rows []row
	DB.Model(&EmailLog{}).
		Select(`mx_host,
			COUNT(*) AS total,
			SUM(CASE WHEN sent_at >= ? THEN 1 ELSE 0 END) AS today_n,
			SUM(CASE WHEN sent_at >= ? AND sent_at < ? THEN 1 ELSE 0 END) AS yesterday_n`,
			todayStart, yesterdayStart, todayStart).
		Where("username = ? AND mx_host LIKE ? AND status = ?", username, "via relay: %", "delivered").
		Group("mx_host").
		Scan(&rows)

	out := make(map[string]RelayStats, len(rows))
	const prefix = "via relay: "
	for _, r := range rows {
		label := r.MXHost
		if strings.HasPrefix(label, prefix) {
			label = label[len(prefix):]
		}
		out[label] = RelayStats{
			TodaySent:     r.TodayN,
			YesterdaySent: r.YesterdayN,
			TotalSent:     r.Total,
		}
	}
	return out
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
// ──────────────────────────── Priority User Permission ────────────────────────

// IsUserPriority returns true if the user has the priority-send permission.
// Priority users bypass all IP pool throttling and admin throttle rules and
// their messages are dequeued before normal messages.
func IsUserPriority(username string) bool {
	if username == "" {
		return false
	}
	var u User
	if err := DB.Select("priority_user").Where("username = ?", username).First(&u).Error; err != nil {
		return false
	}
	return u.PriorityUser
}

// SetUserPriority enables or disables the priority-send permission for a user.
func SetUserPriority(username string, enabled bool) error {
	return DB.Model(&User{}).Where("username = ?", username).Update("priority_user", enabled).Error
}

// GetPriorityUsers returns all users that have the priority-send permission enabled.
func GetPriorityUsers() []User {
	var users []User
	DB.Where("priority_user = ?", true).Order("username asc").Find(&users)
	return users
}

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
	now := time.Now()
	statDate := now.Format("2006-01-02")
	DB.Model(&EmailLog{}).
		Where("message_id = ? AND recipient = ?", msgID, recipient).
		Updates(map[string]interface{}{
			"status":  "suppressed",
			"error":   reason,
			"sent_at": now,
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
		// Fallback: count by created_at (queued/sent), not sent_at — matches DailyStats "sent" from LogQueued
		DB.Model(&EmailLog{}).Where("created_at >= ?", t).Count(&today)
	}
	if err := DB.Model(&DailyStats{}).Where("stat_date = ? AND username = ?", yesterdayStr, "").First(&d).Error; err == nil {
		yesterday = d.Sent
	} else {
		DB.Model(&EmailLog{}).Where("created_at >= ? AND created_at < ?", t.AddDate(0, 0, -1), t).Count(&yesterday)
	}
	DB.Model(&DailyStats{}).Where("username = ? AND stat_date >= ?", "", monthStart).Select("COALESCE(SUM(sent),0)").Scan(&month)
	if month == 0 {
		DB.Model(&EmailLog{}).Where("created_at >= ?", t.AddDate(0, -1, 0)).Count(&month)
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
		DB.Model(&EmailLog{}).Where("username = ? AND created_at >= ?", username, t).Count(&today)
	}
	if err := DB.Model(&DailyStats{}).Where("stat_date = ? AND username = ?", yesterdayStr, username).First(&d).Error; err == nil {
		yesterday = d.Sent
	} else {
		DB.Model(&EmailLog{}).Where("username = ? AND created_at >= ? AND created_at < ?", username, t.AddDate(0, 0, -1), t).Count(&yesterday)
	}
	DB.Model(&DailyStats{}).Where("username = ? AND stat_date >= ?", username, monthStart).Select("COALESCE(SUM(sent),0)").Scan(&month)
	if month == 0 {
		DB.Model(&EmailLog{}).Where("username = ? AND created_at >= ?", username, t.AddDate(0, -1, 0)).Count(&month)
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

// minuteBucketRow is one GROUP BY bucket from aggregated minute queries (lm = Unix minute id).
type minuteBucketRow struct {
	LM int64 `gorm:"column:lm"`
	N  int64 `gorm:"column:n"`
}

// GetLast60MinuteBuckets returns per-minute incoming (created) and outgoing (delivered) for the last 60 minutes.
// Buckets by Unix minute so SQLite/MySQL match regardless of session timezone (wall-clock labels use local TZ).
func GetLast60MinuteBuckets() (labels []string, incoming, outgoing []int64) {
	if DB == nil {
		return nil, nil, nil
	}
	now := time.Now()
	since := now.Add(-60 * time.Minute).Truncate(time.Minute)
	windowEnd := since.Add(60 * time.Minute)
	baseMin := since.Unix() / 60

	labels = make([]string, 60)
	incoming = make([]int64, 60)
	outgoing = make([]int64, 60)
	inMap := make(map[int64]int64, 72)
	outMap := make(map[int64]int64, 72)

	for i := 0; i < 60; i++ {
		bid := baseMin + int64(i)
		labels[i] = time.Unix(bid*60, 0).In(time.Local).Format("15:04")
	}

	switch DB.Dialector.Name() {
	case "sqlite":
		var inRows, outRows []minuteBucketRow
		DB.Raw(`
			SELECT (CAST(strftime('%s', created_at) AS INTEGER) / 60) AS lm, COUNT(*) AS n
			FROM email_logs
			WHERE created_at >= ? AND created_at < ? AND deleted_at IS NULL
			GROUP BY lm
		`, since, windowEnd).Scan(&inRows)
		for _, r := range inRows {
			inMap[r.LM] = r.N
		}
		DB.Raw(`
			SELECT (CAST(strftime('%s', sent_at) AS INTEGER) / 60) AS lm, COUNT(*) AS n
			FROM email_logs
			WHERE status = ? AND sent_at IS NOT NULL AND sent_at >= ? AND sent_at < ? AND deleted_at IS NULL
			GROUP BY lm
		`, "delivered", since, windowEnd).Scan(&outRows)
		for _, r := range outRows {
			outMap[r.LM] = r.N
		}
	case "mysql":
		var inRows, outRows []minuteBucketRow
		DB.Raw(`
			SELECT FLOOR(UNIX_TIMESTAMP(created_at)/60) AS lm, COUNT(*) AS n
			FROM email_logs
			WHERE created_at >= ? AND created_at < ? AND deleted_at IS NULL
			GROUP BY FLOOR(UNIX_TIMESTAMP(created_at)/60)
		`, since, windowEnd).Scan(&inRows)
		for _, r := range inRows {
			inMap[r.LM] = r.N
		}
		DB.Raw(`
			SELECT FLOOR(UNIX_TIMESTAMP(sent_at)/60) AS lm, COUNT(*) AS n
			FROM email_logs
			WHERE status = ? AND sent_at IS NOT NULL AND sent_at >= ? AND sent_at < ? AND deleted_at IS NULL
			GROUP BY FLOOR(UNIX_TIMESTAMP(sent_at)/60)
		`, "delivered", since, windowEnd).Scan(&outRows)
		for _, r := range outRows {
			outMap[r.LM] = r.N
		}
	default:
		for i := 0; i < 60; i++ {
			bucketStart := since.Add(time.Duration(i) * time.Minute)
			bucketEnd := bucketStart.Add(time.Minute)
			DB.Model(&EmailLog{}).Where("created_at >= ? AND created_at < ?", bucketStart, bucketEnd).Count(&incoming[i])
			DB.Model(&EmailLog{}).Where("status = ? AND sent_at IS NOT NULL AND sent_at >= ? AND sent_at < ?", "delivered", bucketStart, bucketEnd).Count(&outgoing[i])
		}
		return labels, incoming, outgoing
	}

	for i := 0; i < 60; i++ {
		bid := baseMin + int64(i)
		incoming[i] = inMap[bid]
		outgoing[i] = outMap[bid]
	}
	return labels, incoming, outgoing
}

// GetSummaryStats returns today delivered, yesterday delivered, and sum of delivered for the same
// 7 calendar days as GetDailyCountsAdmin(7) / the dashboard chart (today through today-6).
// Previously today/yesterday could come from DailyStats while "last 7" summed 8 days from a different
// query, so cards disagreed with each other and with the chart.
func GetSummaryStats() (today, yesterday, last7Days int64) {
	if DB == nil {
		return 0, 0, 0
	}
	_, delivered, _ := GetDailyCountsAdmin(7)
	if n := len(delivered); n >= 2 {
		today = delivered[n-1]
		yesterday = delivered[n-2]
		for _, v := range delivered {
			last7Days += v
		}
	} else if n == 1 {
		today = delivered[0]
		last7Days = delivered[0]
	}
	return today, yesterday, last7Days
}

// RecentDeliveryForLogs is the newest terminal outcome row (for send-log banner).
type RecentDeliveryForLogs struct {
	HasLast    bool
	LastSentAt time.Time
	Status     string // delivered | failed | hard_bounce | suppressed
}

// RecentDeliverySnapshotAdmin returns delivery stats across all users (admin send logs).
func RecentDeliverySnapshotAdmin() RecentDeliveryForLogs {
	return recentDeliverySnapshot("")
}

// RecentDeliverySnapshotUser returns delivery stats for one user (user send logs).
func RecentDeliverySnapshotUser(username string) RecentDeliveryForLogs {
	return recentDeliverySnapshot(username)
}

func recentDeliverySnapshot(username string) RecentDeliveryForLogs {
	var out RecentDeliveryForLogs
	if DB == nil {
		return out
	}
	user := strings.TrimSpace(username)

	terminal := []string{"delivered", "failed", "hard_bounce", "suppressed"}
	qLast := DB.Model(&EmailLog{}).Where("status IN ?", terminal)
	if user != "" {
		qLast = qLast.Where("username = ?", user)
	}
	// sent_at is always set for terminal-status rows; ORDER BY sent_at is served by
	// idx_el_status_sent (status, sent_at) so this never does a full-table filesort.
	var row EmailLog
	if err := qLast.Order("sent_at DESC, id DESC").Limit(1).First(&row).Error; err == nil {
		out.HasLast = true
		ts := row.SentAt
		if ts.IsZero() {
			ts = row.CreatedAt
		}
		out.LastSentAt = ts
		out.Status = row.Status
	}
	return out
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

// CampaignSendMessageIDs returns distinct non-empty queue message IDs for a campaign
// (used to cancel pending/deferred mail when the campaign is deleted).
func CampaignSendMessageIDs(campaignID uint) []string {
	var raw []string
	_ = DB.Model(&CampaignSend{}).
		Where("campaign_id = ? AND message_id != '' AND message_id IS NOT NULL", campaignID).
		Pluck("message_id", &raw)
	seen := make(map[string]bool)
	var out []string
	for _, id := range raw {
		id = strings.TrimSpace(id)
		if id == "" || seen[id] {
			continue
		}
		seen[id] = true
		out = append(out, id)
	}
	return out
}

// DeleteCampaign removes the campaign and related sends/track events.
// Callers should cancel queue files for CampaignSendMessageIDs first so delivery stops.
func DeleteCampaign(id uint, username string) error {
	return DB.Transaction(func(tx *gorm.DB) error {
		var sendIDs []uint
		if err := tx.Model(&CampaignSend{}).Where("campaign_id = ?", id).Pluck("id", &sendIDs).Error; err != nil {
			return err
		}
		if len(sendIDs) > 0 {
			if err := tx.Where("send_id IN ?", sendIDs).Delete(&TrackEvent{}).Error; err != nil {
				return err
			}
			if err := tx.Where("campaign_id = ?", id).Delete(&CampaignSend{}).Error; err != nil {
				return err
			}
		}
		return tx.Where("id = ? AND owner_username = ?", id, username).Delete(&Campaign{}).Error
	})
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
