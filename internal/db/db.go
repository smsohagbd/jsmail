package db

import (
	"log"
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

	if err := DB.AutoMigrate(
		&User{},
		&EmailLog{},
		&ThrottleRule{},
		&UpstreamSMTP{},
		&Setting{},
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

// LogQueued writes a queued log entry.
func LogQueued(username, msgID, from string, recipients []string) {
	for _, to := range recipients {
		DB.Create(&EmailLog{
			Username:  username,
			MessageID: msgID,
			From:      from,
			To:        to,
			Status:    "queued",
			SentAt:    time.Now(),
		})
	}
}

// LogDelivered updates log entry to delivered.
func LogDelivered(msgID, to, mxHost string) {
	DB.Model(&EmailLog{}).
		Where("message_id = ? AND to = ?", msgID, to).
		Updates(map[string]interface{}{
			"status":  "delivered",
			"mx_host": mxHost,
			"sent_at": time.Now(),
		})
}

// LogFailed updates log entry to failed.
func LogFailed(msgID, to, errMsg string) {
	DB.Model(&EmailLog{}).
		Where("message_id = ? AND to = ?", msgID, to).
		Updates(map[string]interface{}{
			"status": "failed",
			"error":  errMsg,
		})
}

// LogDeferred updates log entry to deferred.
func LogDeferred(msgID, to, errMsg string) {
	DB.Model(&EmailLog{}).
		Where("message_id = ? AND to = ?", msgID, to).
		Updates(map[string]interface{}{
			"status": "deferred",
			"error":  errMsg,
		})
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
