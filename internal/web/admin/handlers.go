package admin

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	appdb "smtp-server/internal/db"
	"smtp-server/internal/queue"
	webauth "smtp-server/internal/web/auth"
)

// flatQuery converts url.Values (map[string][]string) to map[string]string
// so Go templates can compare values with eq without type errors.
// jsonStr returns a JSON-encoded string literal (with quotes).
func jsonStr(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func flatQuery(v url.Values) map[string]string {
	m := make(map[string]string, len(v))
	for k, vals := range v {
		if len(vals) > 0 {
			m[k] = vals[0]
		}
	}
	return m
}


type Handler struct {
	DB             *gorm.DB
	Queue          *queue.Queue
	Tmpl           TemplateRenderer
	ConfigSnapshot map[string]string
	ConfigPath     string // path to config.yaml for the editor
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
	smtpMode := r.FormValue("smtp_mode")
	if smtpMode == "" {
		smtpMode = "system_only"
	}
	maxCustomSMTP, _ := strconv.Atoi(r.FormValue("max_custom_smtp"))
	if maxCustomSMTP == 0 {
		maxCustomSMTP = 5
	}

	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	h.DB.Create(&appdb.User{
		Username:      username,
		Password:      string(hash),
		Email:         email,
		Role:          "user",
		QuotaPerDay:   quota,
		Active:        true,
		SMTPMode:      smtpMode,
		MaxCustomSMTP: maxCustomSMTP,
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
	smtpMode := r.FormValue("smtp_mode")
	if smtpMode == "" {
		smtpMode = "system_only"
	}
	maxCustomSMTP, _ := strconv.Atoi(r.FormValue("max_custom_smtp"))
	if maxCustomSMTP == 0 {
		maxCustomSMTP = 5
	}

	updates := map[string]interface{}{
		"quota_per_day":   quota,
		"active":          active,
		"smtp_mode":       smtpMode,
		"max_custom_smtp": maxCustomSMTP,
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
	tab := r.URL.Query().Get("tab") // "" | "bounces"

	// ── Send Logs tab ────────────────────────────────────────────────────────
	q := h.DB.Model(&appdb.EmailLog{})
	q, dateLabel := applyLogFilters(q, r)

	if search := r.URL.Query().Get("search"); search != "" {
		like := "%" + search + "%"
		q = q.Where(`"from" LIKE ? OR recipient LIKE ? OR username LIKE ?`, like, like, like)
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

	// ── Hard Bounce tab ──────────────────────────────────────────────────────
	bounceSearch := r.URL.Query().Get("bsearch")
	bouncePage, _ := strconv.Atoi(r.URL.Query().Get("bpage"))
	if bouncePage < 1 {
		bouncePage = 1
	}
	bq := h.DB.Model(&appdb.BounceList{})
	if bounceSearch != "" {
		bq = bq.Where("email LIKE ?", "%"+bounceSearch+"%")
	}
	var bounceTotal int64
	bq.Count(&bounceTotal)
	var bounces []appdb.BounceList
	bq.Order("last_seen_at desc").Offset((bouncePage - 1) * perPage).Limit(perPage).Find(&bounces)

	h.Tmpl.Render(w, "admin/logs", map[string]interface{}{
		"Page":         "logs",
		"ActiveUser":   claims.Username,
		"Tab":          tab,
		"Logs":         logs,
		"Total":        total,
		"PageNum":      page,
		"PerPage":      perPage,
		"DateLabel":    dateLabel,
		"Query":        flatQuery(r.URL.Query()),
		"Bounces":      bounces,
		"BounceTotal":  bounceTotal,
		"BouncePage":   bouncePage,
		"BounceSearch": bounceSearch,
		"FlashOK":      r.URL.Query().Get("ok"),
	})
}

func (h *Handler) DeleteLogs(w http.ResponseWriter, r *http.Request) {
	scope := r.FormValue("scope") // today | yesterday | 7days | all | id
	if scope == "id" {
		id, _ := strconv.Atoi(r.FormValue("id"))
		var log appdb.EmailLog
		if err := h.DB.First(&log, id).Error; err == nil {
			// Cancel the queue entry so delivery stops.
			if log.Status == "queued" || log.Status == "deferred" {
				h.Queue.CancelByMessageID(log.MessageID)
			}
		}
		h.DB.Delete(&appdb.EmailLog{}, id)
	} else {
		// Collect message IDs that are still in-flight before deleting.
		var pending []appdb.EmailLog
		pq := h.DB.Model(&appdb.EmailLog{}).Where("status IN ?", []string{"queued", "deferred"})
		pq, _ = applyLogFilters(pq, r)
		pq.Find(&pending)
		for _, l := range pending {
			h.Queue.CancelByMessageID(l.MessageID)
		}
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

// ──────────────────────────── Reports ────────────────────────────────────────

type domainStat struct {
	Domain string
	Count  int64
}

type senderStat struct {
	Username string
	Count    int64
}

func (h *Handler) Reports(w http.ResponseWriter, r *http.Request) {
	claims, _ := webauth.GetClaims(r)

	// Overall totals.
	var totalSent, delivered, hardBounce, softBounce, failed, deferred, queued, bounceListTotal int64
	h.DB.Model(&appdb.EmailLog{}).Count(&totalSent)
	h.DB.Model(&appdb.EmailLog{}).Where("status = ?", "delivered").Count(&delivered)
	h.DB.Model(&appdb.EmailLog{}).Where("status = ?", "hard_bounce").Count(&hardBounce)
	h.DB.Model(&appdb.EmailLog{}).Where("status IN ?", []string{"soft_bounce", "deferred"}).Count(&softBounce)
	h.DB.Model(&appdb.EmailLog{}).Where("status = ?", "failed").Count(&failed)
	h.DB.Model(&appdb.EmailLog{}).Where("status = ?", "deferred").Count(&deferred)
	h.DB.Model(&appdb.EmailLog{}).Where("status = ?", "queued").Count(&queued)
	h.DB.Model(&appdb.BounceList{}).Count(&bounceListTotal)

	// Delivery rate (non-queued/deferred attempts).
	attempted := totalSent - queued - deferred
	var deliveryRate float64
	if attempted > 0 {
		deliveryRate = float64(delivered) / float64(attempted) * 100
	}

	// Top 10 recipient domains.
	type domainRow struct {
		Domain string
		Count  int64
	}
	var topDomains []domainRow
	h.DB.Raw(`SELECT substr(recipient, instr(recipient,'@')+1) AS domain, COUNT(*) AS count
		FROM email_logs WHERE deleted_at IS NULL
		GROUP BY domain ORDER BY count DESC LIMIT 10`).Scan(&topDomains)

	// Top 10 senders.
	var topSenders []struct {
		Username string
		Count    int64
	}
	h.DB.Model(&appdb.EmailLog{}).
		Select("username, COUNT(*) as count").
		Group("username").Order("count DESC").Limit(10).Scan(&topSenders)

	// Last 30 days delivery chart.
	today := time.Now().Truncate(24 * time.Hour)
	days := 30
	chartLabels := make([]string, days)
	chartDelivered := make([]int64, days)
	chartBounced := make([]int64, days)
	for i := days - 1; i >= 0; i-- {
		day := today.AddDate(0, 0, -i)
		idx := days - 1 - i
		chartLabels[idx] = day.Format("Jan 2")
		h.DB.Model(&appdb.EmailLog{}).
			Where("sent_at >= ? AND sent_at < ? AND status = ?", day, day.Add(24*time.Hour), "delivered").
			Count(&chartDelivered[idx])
		h.DB.Model(&appdb.EmailLog{}).
			Where("sent_at >= ? AND sent_at < ? AND status = ?", day, day.Add(24*time.Hour), "hard_bounce").
			Count(&chartBounced[idx])
	}
	labelsJSON, _ := json.Marshal(chartLabels)
	deliveredJSON, _ := json.Marshal(chartDelivered)
	bouncedJSON, _ := json.Marshal(chartBounced)

	// Recent hard bounces.
	var recentBounces []appdb.BounceList
	h.DB.Order("last_seen_at DESC").Limit(20).Find(&recentBounces)

	h.Tmpl.Render(w, "admin/reports", map[string]interface{}{
		"Page":             "reports",
		"ActiveUser":       claims.Username,
		"TotalSent":        totalSent,
		"Delivered":        delivered,
		"HardBounce":       hardBounce,
		"SoftBounce":       softBounce,
		"Failed":           failed,
		"Deferred":         deferred,
		"Queued":           queued,
		"BounceListTotal":  bounceListTotal,
		"DeliveryRate":     deliveryRate,
		"TopDomains":       topDomains,
		"TopSenders":       topSenders,
		"ChartLabels":      string(labelsJSON),
		"ChartDelivered":   string(deliveredJSON),
		"ChartBounced":     string(bouncedJSON),
		"RecentBounces":    recentBounces,
	})
}

// ──────────────────────────── Hard Bounce Management ─────────────────────────

// Bounces redirects legacy /admin/bounces URL to the logs page bounce tab.
func (h *Handler) Bounces(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/admin/logs?tab=bounces", http.StatusFound)
}

// RemoveBounce removes one address from the suppression list.
func (h *Handler) RemoveBounce(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/logs?tab=bounces", http.StatusFound)
		return
	}
	email := r.FormValue("email")
	if email != "" {
		appdb.RemoveFromBounceList(email)
		http.Redirect(w, r, "/admin/logs?tab=bounces&ok="+url.QueryEscape(email+" removed"), http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/logs?tab=bounces", http.StatusFound)
}

// BulkRemoveBounces removes all addresses (or by search) from the suppression list.
func (h *Handler) BulkRemoveBounces(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/logs?tab=bounces", http.StatusFound)
		return
	}
	scope := r.FormValue("scope")
	switch scope {
	case "all":
		h.DB.Where("1 = 1").Delete(&appdb.BounceList{})
		http.Redirect(w, r, "/admin/logs?tab=bounces&ok=All+hard+bounces+cleared", http.StatusFound)
	case "search":
		search := r.FormValue("search")
		if search != "" {
			h.DB.Where("email LIKE ?", "%"+search+"%").Delete(&appdb.BounceList{})
		}
		http.Redirect(w, r, "/admin/logs?tab=bounces&ok=Matching+addresses+removed", http.StatusFound)
	default:
		http.Redirect(w, r, "/admin/logs?tab=bounces", http.StatusFound)
	}
}

// ──────────────────────────── Domains ────────────────────────────────────────

func (h *Handler) Domains(w http.ResponseWriter, r *http.Request) {
	claims, _ := webauth.GetClaims(r)
	domains := appdb.GetAllDomains()
	serverIP := getOutboundIP()
	heloName := h.ConfigSnapshot["smtp_domain"]
	h.Tmpl.Render(w, "admin/domains", map[string]interface{}{
		"Page":       "domains",
		"ActiveUser": claims.Username,
		"Domains":    domains,
		"ServerIP":   serverIP,
		"HeloName":   heloName,
		"FlashOK":    r.URL.Query().Get("ok"),
		"FlashErr":   r.URL.Query().Get("err"),
	})
}

func (h *Handler) AddDomain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/domains", http.StatusFound)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	selector := strings.TrimSpace(r.FormValue("selector"))
	if name == "" {
		http.Redirect(w, r, "/admin/domains?err=domain+name+required", http.StatusFound)
		return
	}
	if _, err := appdb.CreateDomain("", name, selector); err != nil {
		http.Redirect(w, r, "/admin/domains?err="+url.QueryEscape(err.Error()), http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/domains?ok=domain+added", http.StatusFound)
}

func (h *Handler) DeleteDomain(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseUint(r.FormValue("id"), 10, 64)
	appdb.DeleteDomain(uint(id))
	http.Redirect(w, r, "/admin/domains", http.StatusFound)
}

// getOutboundIP returns the preferred outbound IP of this machine.
func getOutboundIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "unknown"
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}

// ──────────────────────────── IP Pool ────────────────────────────────────────

func (h *Handler) IPPool(w http.ResponseWriter, r *http.Request) {
	claims, _ := webauth.GetClaims(r)
	h.Tmpl.Render(w, "admin/ippool", map[string]interface{}{
		"Page":       "ippool",
		"ActiveUser": claims.Username,
		"Enabled":    appdb.GetSetting("ip_pool_enabled", "false") == "true",
		"Entries":    appdb.GetAllIPPool(),
		"FlashOK":    r.URL.Query().Get("ok"),
		"FlashErr":   r.URL.Query().Get("err"),
	})
}

func (h *Handler) ToggleIPPool(w http.ResponseWriter, r *http.Request) {
	enabled := r.FormValue("enabled") == "on"
	if enabled {
		appdb.SetSetting("ip_pool_enabled", "true")
	} else {
		appdb.SetSetting("ip_pool_enabled", "false")
	}
	http.Redirect(w, r, "/admin/ippool?ok=updated", http.StatusFound)
}

func (h *Handler) AddIPPoolEntry(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/ippool", http.StatusFound)
		return
	}
	ip := strings.TrimSpace(r.FormValue("ip"))
	if ip == "" {
		http.Redirect(w, r, "/admin/ippool?err=IP+required", http.StatusFound)
		return
	}
	perMin, _ := strconv.Atoi(r.FormValue("per_min"))
	perHour, _ := strconv.Atoi(r.FormValue("per_hour"))
	perDay, _ := strconv.Atoi(r.FormValue("per_day"))
	warmupEnabled := r.FormValue("warmup_enabled") == "on"
	warmupDays, _ := strconv.Atoi(r.FormValue("warmup_days"))
	if warmupDays == 0 {
		warmupDays = 14
	}
	entry := &appdb.IPPool{
		IP:            ip,
		Hostname:      strings.TrimSpace(r.FormValue("hostname")),
		Active:        r.FormValue("active") != "off",
		PerMin:        perMin,
		PerHour:       perHour,
		PerDay:        perDay,
		Note:          strings.TrimSpace(r.FormValue("note")),
		WarmupEnabled: warmupEnabled,
		WarmupDays:    warmupDays,
	}
	if warmupEnabled {
		entry.WarmupStartedAt = time.Now()
	}
	if err := appdb.SaveIPPoolEntry(entry); err != nil {
		http.Redirect(w, r, "/admin/ippool?err="+url.QueryEscape(err.Error()), http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/ippool?ok=IP+added", http.StatusFound)
}

func (h *Handler) UpdateIPPoolEntry(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/ippool", http.StatusFound)
		return
	}
	id, _ := strconv.ParseUint(r.FormValue("id"), 10, 64)
	perMin, _ := strconv.Atoi(r.FormValue("per_min"))
	perHour, _ := strconv.Atoi(r.FormValue("per_hour"))
	perDay, _ := strconv.Atoi(r.FormValue("per_day"))
	entry := &appdb.IPPool{}
	if err := h.DB.First(entry, id).Error; err != nil {
		http.Redirect(w, r, "/admin/ippool?err=not+found", http.StatusFound)
		return
	}
	warmupEnabled := r.FormValue("warmup_enabled") == "on"
	warmupDays, _ := strconv.Atoi(r.FormValue("warmup_days"))
	if warmupDays == 0 {
		warmupDays = 14
	}
	entry.IP = strings.TrimSpace(r.FormValue("ip"))
	entry.Hostname = strings.TrimSpace(r.FormValue("hostname"))
	entry.Active = r.FormValue("active") == "on"
	entry.PerMin = perMin
	entry.PerHour = perHour
	entry.PerDay = perDay
	entry.Note = strings.TrimSpace(r.FormValue("note"))
	entry.WarmupDays = warmupDays
	// Only reset warmup start time if toggling warmup on.
	if warmupEnabled && !entry.WarmupEnabled {
		entry.WarmupStartedAt = time.Now()
	}
	entry.WarmupEnabled = warmupEnabled
	if err := appdb.SaveIPPoolEntry(entry); err != nil {
		http.Redirect(w, r, "/admin/ippool?err="+url.QueryEscape(err.Error()), http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/ippool?ok=updated", http.StatusFound)
}

func (h *Handler) DeleteIPPoolEntry(w http.ResponseWriter, r *http.Request) {
	id, _ := strconv.ParseUint(r.FormValue("id"), 10, 64)
	appdb.DeleteIPPoolEntry(uint(id))
	http.Redirect(w, r, "/admin/ippool?ok=deleted", http.StatusFound)
}

func (h *Handler) SaveIPPool(w http.ResponseWriter, r *http.Request) {
	h.ToggleIPPool(w, r)
}

// TestIPBinding tries to bind a TCP listener on the given IP to verify it is
// assigned to a network interface on this server. Returns JSON.
func (h *Handler) TestIPBinding(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimSpace(r.FormValue("ip"))
	w.Header().Set("Content-Type", "application/json")
	if ip == "" {
		w.Write([]byte(`{"ok":false,"msg":"IP required"}`))
		return
	}
	ln, err := net.Listen("tcp4", ip+":0")
	if err != nil {
		msg := err.Error()
		w.Write([]byte(`{"ok":false,"msg":` + jsonStr(msg) + `}`))
		return
	}
	ln.Close()
	w.Write([]byte(`{"ok":true,"msg":"IP is bound to this server's network interface"}`))
}

// ──────────────────────────── Config Editor ───────────────────────────────────

func (h *Handler) ConfigEditor(w http.ResponseWriter, r *http.Request) {
	claims, _ := webauth.GetClaims(r)
	var content, errMsg string
	if r.Method == http.MethodPost {
		content = r.FormValue("content")
		if err := os.WriteFile(h.ConfigPath, []byte(content), 0644); err != nil {
			errMsg = "Save failed: " + err.Error()
		} else {
			http.Redirect(w, r, "/admin/config?ok=saved", http.StatusFound)
			return
		}
	} else {
		raw, err := os.ReadFile(h.ConfigPath)
		if err != nil {
			errMsg = "Cannot read config: " + err.Error()
		} else {
			content = string(raw)
		}
	}
	h.Tmpl.Render(w, "admin/configeditor", map[string]interface{}{
		"Page":       "config",
		"ActiveUser": claims.Username,
		"Content":    content,
		"FlashOK":    r.URL.Query().Get("ok"),
		"FlashErr":   errMsg,
	})
}

// ──────────────────────────── SSL / TLS ──────────────────────────────────────

type certInfo struct {
	Subject   string
	NotBefore string
	NotAfter  string
	DNSNames  []string
	IsCA      bool
}

func loadCertInfo(certPath string) *certInfo {
	raw, err := os.ReadFile(certPath)
	if err != nil {
		return nil
	}
	block, _ := pem.Decode(raw)
	if block == nil {
		return nil
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil
	}
	return &certInfo{
		Subject:   cert.Subject.CommonName,
		NotBefore: cert.NotBefore.Format("Jan 2 2006"),
		NotAfter:  cert.NotAfter.Format("Jan 2 2006"),
		DNSNames:  cert.DNSNames,
		IsCA:      cert.IsCA,
	}
}

type certCandidate struct {
	Label    string
	CertFile string
	KeyFile  string
}

// panelCertPattern describes where a control panel stores its TLS certificates.
type panelCertPattern struct {
	Panel   string // human-readable panel name
	CertGlob string
	KeyGlob  string // relative to cert dir if empty
	KeyName  string // filename of key relative to cert directory
}

var knownPanelPatterns = []panelCertPattern{
	// Standard certbot / Let's Encrypt (Webmin, Virtualmin, CyberPanel, ISPConfig, Plesk, cPanel all use this)
	{"Let's Encrypt (certbot)", "/etc/letsencrypt/live/*/fullchain.pem", "", "privkey.pem"},
	// acme.sh (alternative ACME client)
	{"acme.sh", "/root/.acme.sh/*/*.cer", "", "*.key"},
	// CyberPanel custom path
	{"CyberPanel", "/home/*/public_html/ssl/ssl.crt", "", "ssl.key"},
	// Plesk
	{"Plesk", "/opt/psa/var/certificates/*.pem", "", ""},
	// DirectAdmin
	{"DirectAdmin", "/usr/local/directadmin/data/users/*/domains/*.cert", "", "*.key"},
	// cPanel WHM
	{"cPanel", "/var/cpanel/ssl/apache_tls/*.crt", "", "*.key"},
	// Local generated
	{"Generated (this server)", "certs/server.crt", "", ""},
}

func findExistingCerts() []certCandidate {
	var out []certCandidate
	seen := map[string]bool{}

	addPair := func(label, cert, key string) {
		if seen[cert] {
			return
		}
		if _, err := tls.LoadX509KeyPair(cert, key); err != nil {
			return // invalid pair
		}
		seen[cert] = true
		out = append(out, certCandidate{Label: label, CertFile: cert, KeyFile: key})
	}

	// Let's Encrypt (used by virtually all panels + bare certbot)
	if matches, _ := filepath.Glob("/etc/letsencrypt/live/*/fullchain.pem"); len(matches) > 0 {
		for _, cert := range matches {
			key := filepath.Join(filepath.Dir(cert), "privkey.pem")
			domain := filepath.Base(filepath.Dir(cert))
			addPair("Let's Encrypt — "+domain, cert, key)
		}
	}

	// acme.sh
	if matches, _ := filepath.Glob("/root/.acme.sh/*/*.cer"); len(matches) > 0 {
		for _, cert := range matches {
			dir := filepath.Dir(cert)
			// acme.sh key file has same base name as dir
			domain := filepath.Base(dir)
			key := filepath.Join(dir, domain+".key")
			addPair("acme.sh — "+domain, cert, key)
		}
	}

	// CyberPanel
	if matches, _ := filepath.Glob("/etc/cyberpanel/ssl/*/fullchain.pem"); len(matches) > 0 {
		for _, cert := range matches {
			key := filepath.Join(filepath.Dir(cert), "privkey.pem")
			domain := filepath.Base(filepath.Dir(cert))
			addPair("CyberPanel — "+domain, cert, key)
		}
	}

	// cPanel / WHM
	if matches, _ := filepath.Glob("/etc/letsencrypt/live/*/cert.pem"); len(matches) > 0 {
		for _, cert := range matches {
			key := filepath.Join(filepath.Dir(cert), "privkey.pem")
			domain := filepath.Base(filepath.Dir(cert))
			addPair("cPanel/WHM — "+domain, cert, key)
		}
	}

	// DirectAdmin
	if matches, _ := filepath.Glob("/usr/local/directadmin/data/users/*/domains/*.cert"); len(matches) > 0 {
		for _, cert := range matches {
			base := strings.TrimSuffix(cert, ".cert")
			key := base + ".key"
			domain := filepath.Base(base)
			addPair("DirectAdmin — "+domain, cert, key)
		}
	}

	// Our own generated cert
	if _, err := os.Stat("certs/server.crt"); err == nil {
		if _, err2 := os.Stat("certs/server.key"); err2 == nil {
			addPair("Generated (this server) — certs/server.crt", "certs/server.crt", "certs/server.key")
		}
	}

	return out
}

func (h *Handler) SSL(w http.ResponseWriter, r *http.Request) {
	claims, _ := webauth.GetClaims(r)
	certPath := h.ConfigSnapshot["tls_cert_file"]
	keyPath := h.ConfigSnapshot["tls_key_file"]
	tlsMode := h.ConfigSnapshot["tls_mode"]
	if certPath == "" {
		certPath = "certs/server.crt"
	}
	if keyPath == "" {
		keyPath = "certs/server.key"
	}
	if tlsMode == "" {
		tlsMode = "starttls"
	}

	// Warn if the cert is cert.pem (no chain) instead of fullchain.pem.
	certWarning := ""
	if strings.HasSuffix(certPath, "/cert.pem") {
		suggested := strings.TrimSuffix(certPath, "/cert.pem") + "/fullchain.pem"
		certWarning = "You are using cert.pem which does not include the intermediate CA chain. Most clients will reject this. Use fullchain.pem instead: " + suggested
	}

	h.Tmpl.Render(w, "admin/ssl", map[string]interface{}{
		"Page":        "ssl",
		"ActiveUser":  claims.Username,
		"TLSEnabled":  h.ConfigSnapshot["tls_enabled"] == "true",
		"TLSMode":     tlsMode,
		"CertPath":    certPath,
		"KeyPath":     keyPath,
		"CertInfo":    loadCertInfo(certPath),
		"CertWarning": certWarning,
		"Candidates":  findExistingCerts(),
		"FlashOK":     r.URL.Query().Get("ok"),
		"FlashErr":    r.URL.Query().Get("err"),
		"HeloName":    h.ConfigSnapshot["smtp_domain"],
	})
}

// ScanCerts returns JSON of auto-detected cert candidates (called via AJAX on the SSL page).
func (h *Handler) ScanCerts(w http.ResponseWriter, r *http.Request) {
	candidates := findExistingCerts()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(candidates)
}

// SaveTLSConfig validates the cert/key pair, then writes the TLS settings
// directly into config.yaml without requiring a terminal.
func (h *Handler) SaveTLSConfig(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/ssl", http.StatusFound)
		return
	}
	certFile := strings.TrimSpace(r.FormValue("cert_file"))
	keyFile := strings.TrimSpace(r.FormValue("key_file"))
	tlsMode := r.FormValue("tls_mode")
	if tlsMode != "implicit" {
		tlsMode = "starttls"
	}
	enabled := r.FormValue("tls_enabled") == "on"

	// Auto-fix: if user chose cert.pem, silently upgrade to fullchain.pem if it exists.
	if strings.HasSuffix(certFile, "/cert.pem") {
		full := strings.TrimSuffix(certFile, "/cert.pem") + "/fullchain.pem"
		if _, err := os.Stat(full); err == nil {
			certFile = full
		}
	}

	// Validate cert + key pair before touching the config.
	if _, err := tls.LoadX509KeyPair(certFile, keyFile); err != nil {
		http.Redirect(w, r, "/admin/ssl?err="+url.QueryEscape("cert/key validation failed: "+err.Error()), http.StatusFound)
		return
	}

	// Update config.yaml in-place (preserves comments and all other settings).
	if err := patchConfigTLS(h.ConfigPath, enabled, certFile, keyFile, tlsMode); err != nil {
		http.Redirect(w, r, "/admin/ssl?err="+url.QueryEscape("failed to save config: "+err.Error()), http.StatusFound)
		return
	}

	// Keep snapshot in sync so the page reflects the new values immediately.
	h.ConfigSnapshot["tls_enabled"] = boolStr(enabled)
	h.ConfigSnapshot["tls_cert_file"] = certFile
	h.ConfigSnapshot["tls_key_file"] = keyFile
	h.ConfigSnapshot["tls_mode"] = tlsMode

	http.Redirect(w, r, "/admin/ssl?ok=TLS+config+saved+—+restart+the+server+to+apply", http.StatusFound)
}

// patchConfigTLS rewrites only the smtp.tls.* lines in config.yaml while
// preserving every other line, comment, and indentation.
func patchConfigTLS(configPath string, enabled bool, certFile, keyFile, mode string) error {
	raw, err := os.ReadFile(configPath)
	if err != nil {
		return err
	}

	lines := strings.Split(string(raw), "\n")
	inSMTP, inTLS := false, false
	modePatched := false

	for i, line := range lines {
		trimmed := strings.TrimSpace(line)
		indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]

		if trimmed == "smtp:" {
			inSMTP, inTLS = true, false
			continue
		}
		if inSMTP && trimmed == "tls:" {
			inTLS = true
			continue
		}
		if inTLS && len(line) > 0 && line[0] != ' ' && line[0] != '\t' {
			inTLS, inSMTP = false, false
		}

		if inTLS {
			switch {
			case strings.HasPrefix(trimmed, "enabled:"):
				lines[i] = indent + "enabled: " + boolStr(enabled)
			case strings.HasPrefix(trimmed, "cert_file:"):
				lines[i] = indent + `cert_file: "` + certFile + `"`
			case strings.HasPrefix(trimmed, "key_file:"):
				lines[i] = indent + `key_file: "` + keyFile + `"`
			case strings.HasPrefix(trimmed, "mode:"):
				lines[i] = indent + `mode: "` + mode + `"`
				modePatched = true
			}
		}
	}

	// If mode: line doesn't exist yet, insert it after key_file: inside the tls block.
	if !modePatched {
		inSMTP2, inTLS2 := false, false
		for i, line := range lines {
			trimmed := strings.TrimSpace(line)
			if trimmed == "smtp:" {
				inSMTP2, inTLS2 = true, false
				continue
			}
			if inSMTP2 && trimmed == "tls:" {
				inTLS2 = true
				continue
			}
			if inTLS2 && strings.HasPrefix(trimmed, "key_file:") {
				indent := line[:len(line)-len(strings.TrimLeft(line, " \t"))]
				lines = append(lines[:i+1], append([]string{indent + `mode: "` + mode + `"`}, lines[i+1:]...)...)
				break
			}
			if inTLS2 && len(line) > 0 && line[0] != ' ' && line[0] != '\t' {
				inTLS2, inSMTP2 = false, false
			}
		}
	}

	return os.WriteFile(configPath, []byte(strings.Join(lines, "\n")), 0644)
}

func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func (h *Handler) GenerateSelfSigned(w http.ResponseWriter, r *http.Request) {
	hostname := strings.TrimSpace(r.FormValue("hostname"))
	if hostname == "" {
		hostname = h.ConfigSnapshot["smtp_domain"]
	}
	if hostname == "" {
		hostname = "mail.example.com"
	}

	certPath, keyPath, err := generateSelfSignedCert(hostname)
	if err != nil {
		http.Redirect(w, r, "/admin/ssl?err="+url.QueryEscape(err.Error()), http.StatusFound)
		return
	}
	// Update config snapshot so the page reflects new paths.
	h.ConfigSnapshot["tls_cert_file"] = certPath
	h.ConfigSnapshot["tls_key_file"] = keyPath
	h.ConfigSnapshot["tls_enabled"] = "true"
	http.Redirect(w, r, "/admin/ssl?ok=cert+generated+at+"+url.QueryEscape(certPath), http.StatusFound)
}

func generateSelfSignedCert(hostname string) (certPath, keyPath string, err error) {
	os.MkdirAll("certs", 0700)

	privKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", "", err
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: hostname},
		DNSNames:     []string{hostname},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &privKey.PublicKey, privKey)
	if err != nil {
		return "", "", err
	}

	certPath = "certs/server.crt"
	keyPath = "certs/server.key"

	cf, err := os.OpenFile(certPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0644)
	if err != nil {
		return "", "", err
	}
	pem.Encode(cf, &pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	cf.Close()

	keyDER, _ := x509.MarshalECPrivateKey(privKey)
	kf, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
	if err != nil {
		return "", "", err
	}
	pem.Encode(kf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})
	kf.Close()

	return certPath, keyPath, nil
}

// VerifyCert checks that the cert and key are a matching pair.
func (h *Handler) VerifyCert(w http.ResponseWriter, r *http.Request) {
	certPath := strings.TrimSpace(r.FormValue("cert_path"))
	keyPath := strings.TrimSpace(r.FormValue("key_path"))
	_, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		http.Redirect(w, r, "/admin/ssl?err="+url.QueryEscape("cert/key mismatch: "+err.Error()), http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/ssl?ok=cert+and+key+match+✓", http.StatusFound)
}
