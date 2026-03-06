package db

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/glebarez/sqlite"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

var DB *gorm.DB

// Init opens the SQLite database, runs migrations, and seeds the admin user.
func Init(path, adminUser, adminPass string) error {
	var err error
	DB, err = gorm.Open(sqlite.Open(path), &gorm.Config{
		Logger: logger.Default.LogMode(logger.Silent),
	})
	if err != nil {
		return err
	}

	// Drop email_logs if it has the old 'to' column (pre-rename migration).
	var colExists int64
	DB.Raw("SELECT COUNT(*) FROM pragma_table_info('email_logs') WHERE name='to'").Scan(&colExists)
	if colExists > 0 {
		log.Printf("db: migrating email_logs table (renaming 'to' → 'recipient')")
		DB.Exec("DROP TABLE IF EXISTS email_logs")
	}

	if err := DB.AutoMigrate(
		&User{},
		&EmailLog{},
		&ThrottleRule{},
		&UpstreamSMTP{},
		&Setting{},
		&BounceList{},
		&Domain{},
	); err != nil {
		return err
	}

	ensureAdmin(adminUser, adminPass)
	log.Printf("db: SQLite opened at %s", path)
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

// LogQueued writes a queued log entry for every recipient.
func LogQueued(username, msgID, from string, recipients []string) {
	for _, rcpt := range recipients {
		DB.Create(&EmailLog{
			Username:  username,
			MessageID: msgID,
			From:      from,
			Recipient: rcpt,
			Status:    "queued",
			SentAt:    time.Now(),
		})
	}
}

// LogDelivered updates a log entry to delivered.
func LogDelivered(msgID, recipient, mxHost string) {
	DB.Model(&EmailLog{}).
		Where("message_id = ? AND recipient = ?", msgID, recipient).
		Updates(map[string]interface{}{
			"status":  "delivered",
			"mx_host": mxHost,
			"sent_at": time.Now(),
		})
}

// LogFailed updates a log entry to failed.
func LogFailed(msgID, recipient, errMsg string) {
	DB.Model(&EmailLog{}).
		Where("message_id = ? AND recipient = ?", msgID, recipient).
		Updates(map[string]interface{}{
			"status": "failed",
			"error":  errMsg,
		})
}

// LogDeferred updates a log entry to deferred.
func LogDeferred(msgID, recipient, errMsg string) {
	DB.Model(&EmailLog{}).
		Where("message_id = ? AND recipient = ?", msgID, recipient).
		Updates(map[string]interface{}{
			"status": "deferred",
			"error":  errMsg,
		})
}

// LogHardBounce marks a log entry as hard_bounce and adds address to bounce list.
func LogHardBounce(msgID, recipient, errMsg string) {
	DB.Model(&EmailLog{}).
		Where("message_id = ? AND recipient = ?", msgID, recipient).
		Updates(map[string]interface{}{
			"status": "hard_bounce",
			"error":  errMsg,
		})

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
	DB.Where("email = ?", strings.ToLower(email)).Delete(&BounceList{})
}

// ──────────────────────────── Domains ────────────────────────────────────────

// CreateDomain generates a DKIM RSA-2048 key pair and stores the domain.
func CreateDomain(ownerUsername, name, selector string) (*Domain, error) {
	name = strings.ToLower(strings.TrimSpace(name))
	if selector == "" {
		selector = "mail"
	}

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

// DeleteDomain removes a domain record.
func DeleteDomain(id uint) {
	DB.Delete(&Domain{}, id)
}

// ──────────────────────────── Settings ───────────────────────────────────────

// GetSetting retrieves a setting value by key, returning def if not set.
func GetSetting(key, def string) string {
	var s Setting
	if err := DB.Where("key = ?", key).First(&s).Error; err != nil {
		return def
	}
	return s.Value
}

// SetSetting upserts a setting.
func SetSetting(key, value string) {
	var s Setting
	if err := DB.Where("key = ?", key).First(&s).Error; err != nil {
		DB.Create(&Setting{Key: key, Value: value})
	} else {
		DB.Model(&s).Update("value", value)
	}
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
