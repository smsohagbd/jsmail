package admin

import (
	"encoding/json"
	"net/http"
	"strconv"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	appdb "smtp-server/internal/db"
	"smtp-server/internal/queue"
	webauth "smtp-server/internal/web/auth"
)


type Handler struct {
	DB             *gorm.DB
	Queue          *queue.Queue
	Tmpl           TemplateRenderer
	ConfigSnapshot map[string]string
}

type TemplateRenderer interface {
	Render(w http.ResponseWriter, name string, data map[string]interface{})
}

// ──────────────────────────── Dashboard ──────────────────────────────────────

func (h *Handler) Dashboard(w http.ResponseWriter, r *http.Request) {
	claims, _ := webauth.GetClaims(r)

	var totalToday, totalYesterday, totalMonth, pending int64
	today := time.Now().Truncate(24 * time.Hour)
	yesterday := today.AddDate(0, 0, -1)

	h.DB.Model(&appdb.EmailLog{}).Where("sent_at >= ?", today).Count(&totalToday)
	h.DB.Model(&appdb.EmailLog{}).Where("sent_at >= ? AND sent_at < ?", yesterday, today).Count(&totalYesterday)
	h.DB.Model(&appdb.EmailLog{}).Where("sent_at >= ?", today.AddDate(0, -1, 0)).Count(&totalMonth)
	h.DB.Model(&appdb.EmailLog{}).Where("status IN ?", []string{"queued", "deferred"}).Count(&pending)

	var totalUsers int64
	h.DB.Model(&appdb.User{}).Where("role = ?", "user").Count(&totalUsers)

	// Last 7 days chart data
	labels := make([]string, 7)
	counts := make([]int64, 7)
	for i := 6; i >= 0; i-- {
		day := today.AddDate(0, 0, -i)
		labels[6-i] = day.Format("Jan 2")
		h.DB.Model(&appdb.EmailLog{}).
			Where("sent_at >= ? AND sent_at < ? AND status = ?", day, day.Add(24*time.Hour), "delivered").
			Count(&counts[6-i])
	}
	labelsJSON, _ := json.Marshal(labels)
	countsJSON, _ := json.Marshal(counts)

	// Recent logs
	var recentLogs []appdb.EmailLog
	h.DB.Order("created_at desc").Limit(10).Find(&recentLogs)

	qStats := h.Queue.Stats()

	h.Tmpl.Render(w, "admin/dashboard", map[string]interface{}{
		"Page":           "dashboard",
		"ActiveUser":     claims.Username,
		"TotalToday":     totalToday,
		"TotalYesterday": totalYesterday,
		"TotalMonth":     totalMonth,
		"Pending":        pending,
		"TotalUsers":     totalUsers,
		"ChartLabels":    string(labelsJSON),
		"ChartCounts":    string(countsJSON),
		"RecentLogs":     recentLogs,
		"QueueStats":     qStats,
	})
}

// ──────────────────────────── Users ──────────────────────────────────────────

func (h *Handler) Users(w http.ResponseWriter, r *http.Request) {
	claims, _ := webauth.GetClaims(r)
	var users []appdb.User
	h.DB.Where("role = ?", "user").Order("created_at desc").Find(&users)
	h.Tmpl.Render(w, "admin/users", map[string]interface{}{
		"Page":       "users",
		"ActiveUser": claims.Username,
		"Users":      users,
	})
}

func (h *Handler) CreateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/users", http.StatusFound)
		return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")
	email := r.FormValue("email")
	quota, _ := strconv.Atoi(r.FormValue("quota"))

	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	h.DB.Create(&appdb.User{
		Username:    username,
		Password:    string(hash),
		Email:       email,
		Role:        "user",
		QuotaPerDay: quota,
		Active:      true,
	})
	http.Redirect(w, r, "/admin/users", http.StatusFound)
}

func (h *Handler) UpdateUser(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/users", http.StatusFound)
		return
	}
	id, _ := strconv.Atoi(r.FormValue("id"))
	quota, _ := strconv.Atoi(r.FormValue("quota"))
	active := r.FormValue("active") == "1"

	updates := map[string]interface{}{
		"quota_per_day": quota,
		"active":        active,
	}
	if pw := r.FormValue("password"); pw != "" {
		hash, _ := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
		updates["password"] = string(hash)
	}
	h.DB.Model(&appdb.User{}).Where("id = ?", id).Updates(updates)
	http.Redirect(w, r, "/admin/users", http.StatusFound)
}

func (h *Handler) DeleteUser(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(r.FormValue("id"))
	h.DB.Delete(&appdb.User{}, id)
	http.Redirect(w, r, "/admin/users", http.StatusFound)
}

// ──────────────────────────── Logs ───────────────────────────────────────────

func (h *Handler) Logs(w http.ResponseWriter, r *http.Request) {
	claims, _ := webauth.GetClaims(r)

	q := h.DB.Model(&appdb.EmailLog{})
	q, dateLabel := applyLogFilters(q, r)

	if search := r.URL.Query().Get("search"); search != "" {
		like := "%" + search + "%"
		q = q.Where("\"from\" LIKE ? OR \"to\" LIKE ? OR username LIKE ?", like, like, like)
	}
	if status := r.URL.Query().Get("status"); status != "" {
		q = q.Where("status = ?", status)
	}

	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	const perPage = 50
	var total int64
	q.Count(&total)

	var logs []appdb.EmailLog
	q.Order("created_at desc").Offset((page - 1) * perPage).Limit(perPage).Find(&logs)

	h.Tmpl.Render(w, "admin/logs", map[string]interface{}{
		"Page":      "logs",
		"ActiveUser": claims.Username,
		"Logs":      logs,
		"Total":     total,
		"PageNum":   page,
		"PerPage":   perPage,
		"DateLabel": dateLabel,
		"Query":     r.URL.Query(),
	})
}

func (h *Handler) DeleteLogs(w http.ResponseWriter, r *http.Request) {
	scope := r.FormValue("scope") // today | yesterday | 7days | all | id
	if scope == "id" {
		id, _ := strconv.Atoi(r.FormValue("id"))
		h.DB.Delete(&appdb.EmailLog{}, id)
	} else {
		q := h.DB.Model(&appdb.EmailLog{})
		q, _ = applyLogFilters(q, r)
		q.Delete(&appdb.EmailLog{})
	}
	http.Redirect(w, r, r.Header.Get("Referer"), http.StatusFound)
}

func applyLogFilters(q *gorm.DB, r *http.Request) (*gorm.DB, string) {
	today := time.Now().Truncate(24 * time.Hour)
	rangeParam := r.URL.Query().Get("range")
	switch rangeParam {
	case "today":
		return q.Where("sent_at >= ?", today), "Today"
	case "yesterday":
		return q.Where("sent_at >= ? AND sent_at < ?", today.AddDate(0, 0, -1), today), "Yesterday"
	case "7days":
		return q.Where("sent_at >= ?", today.AddDate(0, 0, -7)), "Last 7 Days"
	case "30days":
		return q.Where("sent_at >= ?", today.AddDate(0, -1, 0)), "Last 30 Days"
	case "custom":
		from := r.URL.Query().Get("from_date")
		to := r.URL.Query().Get("to_date")
		if from != "" && to != "" {
			fromT, _ := time.Parse("2006-01-02", from)
			toT, _ := time.Parse("2006-01-02", to)
			return q.Where("sent_at >= ? AND sent_at <= ?", fromT, toT.Add(24*time.Hour)), from + " – " + to
		}
	}
	return q, "All Time"
}

// ──────────────────────────── Queue ──────────────────────────────────────────

func (h *Handler) QueuePage(w http.ResponseWriter, r *http.Request) {
	claims, _ := webauth.GetClaims(r)
	qStats := h.Queue.Stats()

	var logs []appdb.EmailLog
	h.DB.Where("status IN ?", []string{"queued", "deferred"}).Order("created_at desc").Limit(100).Find(&logs)

	h.Tmpl.Render(w, "admin/queue", map[string]interface{}{
		"Page":       "queue",
		"ActiveUser": claims.Username,
		"QueueStats": qStats,
		"Logs":       logs,
	})
}

func (h *Handler) DeleteQueueItem(w http.ResponseWriter, r *http.Request) {
	msgID := r.FormValue("message_id")
	if msgID != "" {
		h.Queue.CancelByMessageID(msgID)
		h.DB.Where("message_id = ?", msgID).Delete(&appdb.EmailLog{})
	}
	http.Redirect(w, r, "/admin/queue", http.StatusFound)
}

// ──────────────────────────── Throttle ───────────────────────────────────────

func (h *Handler) Throttle(w http.ResponseWriter, r *http.Request) {
	claims, _ := webauth.GetClaims(r)
	var rules []appdb.ThrottleRule
	h.DB.Order("username, domain").Find(&rules)
	h.Tmpl.Render(w, "admin/throttle", map[string]interface{}{
		"Page":       "throttle",
		"ActiveUser": claims.Username,
		"Rules":      rules,
	})
}

func (h *Handler) SaveThrottle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/throttle", http.StatusFound)
		return
	}
	id, _ := strconv.Atoi(r.FormValue("id"))
	perSec, _ := strconv.Atoi(r.FormValue("per_sec"))
	perMin, _ := strconv.Atoi(r.FormValue("per_min"))
	perHour, _ := strconv.Atoi(r.FormValue("per_hour"))
	perDay, _ := strconv.Atoi(r.FormValue("per_day"))
	perMonth, _ := strconv.Atoi(r.FormValue("per_month"))

	rule := appdb.ThrottleRule{
		Username: r.FormValue("username"),
		Domain:   r.FormValue("domain"),
		PerSec:   perSec, PerMin: perMin, PerHour: perHour,
		PerDay: perDay, PerMonth: perMonth,
	}
	if id > 0 {
		h.DB.Model(&appdb.ThrottleRule{}).Where("id = ?", id).Updates(rule)
	} else {
		h.DB.Create(&rule)
	}
	http.Redirect(w, r, "/admin/throttle", http.StatusFound)
}

func (h *Handler) DeleteThrottle(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.Atoi(r.FormValue("id"))
	h.DB.Delete(&appdb.ThrottleRule{}, id)
	http.Redirect(w, r, "/admin/throttle", http.StatusFound)
}

// ──────────────────────────── Settings ───────────────────────────────────────

func (h *Handler) Settings(w http.ResponseWriter, r *http.Request) {
	claims, _ := webauth.GetClaims(r)
	h.Tmpl.Render(w, "admin/settings", map[string]interface{}{
		"Page":       "settings",
		"ActiveUser": claims.Username,
		"Settings":   h.ConfigSnapshot,
	})
}
