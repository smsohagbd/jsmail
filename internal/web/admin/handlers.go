package admin

import (
	"context"
	"crypto/ecdsa"
	cf "smtp-server/internal/cloudflare"
	"crypto/elliptic"
	"log"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	appdb "smtp-server/internal/db"
	delivery "smtp-server/internal/delivery"
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
	// IPStatsProvider returns the current in-memory send counters per pool IP.
	IPStatsProvider func() map[string]delivery.IPCounterSnapshot
}

// ipEntryView combines a DB pool entry with live send counters and domain rules.
type ipEntryView struct {
	appdb.IPPool
	MinSent      int
	HourSent     int
	DaySent      int
	DomainRules  []appdb.IPPoolDomainRule
}

type TemplateRenderer interface {
	Render(w http.ResponseWriter, name string, data map[string]interface{})
}

// ──────────────────────────── Dashboard ──────────────────────────────────────

func (h *Handler) Dashboard(w http.ResponseWriter, r *http.Request) {
	claims, _ := webauth.GetClaims(r)

	totalToday, totalYesterday, totalMonth := appdb.GetTodayYesterdayMonthAdmin()
	var pending int64
	h.DB.Model(&appdb.EmailLog{}).Where("status IN ?", []string{"queued", "deferred"}).Count(&pending)

	var totalUsers int64
	h.DB.Model(&appdb.User{}).Where("role = ?", "user").Count(&totalUsers)

	// Last 7 days chart data
	labels, delivered, _ := appdb.GetDailyCountsAdmin(7)
	labelsJSON, _ := json.Marshal(labels)
	countsJSON, _ := json.Marshal(delivered)

	// Recent logs
	var recentLogs []appdb.EmailLog
	h.DB.Order("created_at desc").Limit(10).Find(&recentLogs)

	qStats := h.Queue.Stats()

	todayDelivered, yesterdayDelivered, last7Delivered := appdb.GetSummaryStats()
	rtLabels, rtIncoming, rtOutgoing := appdb.GetLast60MinuteBuckets()
	rtLabelsJSON, _ := json.Marshal(rtLabels)
	rtIncomingJSON, _ := json.Marshal(rtIncoming)
	rtOutgoingJSON, _ := json.Marshal(rtOutgoing)

	h.Tmpl.Render(w, "admin/dashboard", map[string]interface{}{
		"Page":             "dashboard",
		"ActiveUser":       claims.Username,
		"TotalToday":       totalToday,
		"TotalYesterday":   totalYesterday,
		"TotalMonth":       totalMonth,
		"TodayDelivered":   todayDelivered,
		"YesterdayDelivered": yesterdayDelivered,
		"Last7Delivered":   last7Delivered,
		"Pending":          pending,
		"TotalUsers":       totalUsers,
		"ChartLabels":      string(labelsJSON),
		"ChartCounts":      string(countsJSON),
		"RealtimeLabels":   string(rtLabelsJSON),
		"RealtimeIncoming": string(rtIncomingJSON),
		"RealtimeOutgoing": string(rtOutgoingJSON),
		"RecentLogs":       recentLogs,
		"QueueStats":       qStats,
	})
}

// DashboardRealtime returns JSON for the last 60 minutes (incoming/outgoing) and summary stats.
// Used for real-time chart updates.
func (h *Handler) DashboardRealtime(w http.ResponseWriter, r *http.Request) {
	labels, incoming, outgoing := appdb.GetLast60MinuteBuckets()
	today, yesterday, last7 := appdb.GetSummaryStats()
	qStats := h.Queue.Stats()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"labels":       labels,
		"incoming":     incoming,
		"outgoing":     outgoing,
		"today":        today,
		"yesterday":    yesterday,
		"last7":        last7,
		"queue_pending": qStats.Pending,
		"queue_deferred": qStats.Deferred,
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
	maxCampaigns, _ := strconv.Atoi(r.FormValue("max_campaigns"))
	maxAutomations, _ := strconv.Atoi(r.FormValue("max_automations"))
	maxLists, _ := strconv.Atoi(r.FormValue("max_lists"))
	maxTemplates, _ := strconv.Atoi(r.FormValue("max_templates"))

	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	h.DB.Create(&appdb.User{
		Username:       username,
		Password:       string(hash),
		Email:          email,
		Role:           "user",
		QuotaPerDay:    quota,
		Active:         true,
		SMTPMode:       smtpMode,
		MaxCustomSMTP:  maxCustomSMTP,
		MaxCampaigns:   maxCampaigns,
		MaxAutomations: maxAutomations,
		MaxLists:       maxLists,
		MaxTemplates:   maxTemplates,
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
	maxCampaigns, _ := strconv.Atoi(r.FormValue("max_campaigns"))
	maxAutomations, _ := strconv.Atoi(r.FormValue("max_automations"))
	maxLists, _ := strconv.Atoi(r.FormValue("max_lists"))
	maxTemplates, _ := strconv.Atoi(r.FormValue("max_templates"))

	updates := map[string]interface{}{
		"quota_per_day":    quota,
		"active":           active,
		"smtp_mode":        smtpMode,
		"max_custom_smtp":  maxCustomSMTP,
		"max_campaigns":    maxCampaigns,
		"max_automations":  maxAutomations,
		"max_lists":        maxLists,
		"max_templates":    maxTemplates,
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

	data := map[string]interface{}{
		"Page":       "queue",
		"ActiveUser": claims.Username,
		"QueueStats": qStats,
		"Logs":       logs,
	}
	if ok := r.URL.Query().Get("ok"); ok != "" {
		data["FlashOK"] = ok
	}
	h.Tmpl.Render(w, "admin/queue", data)
}

func (h *Handler) DeleteQueueItem(w http.ResponseWriter, r *http.Request) {
	msgID := r.FormValue("message_id")
	if msgID != "" {
		h.Queue.CancelByMessageID(msgID)
		h.DB.Where("message_id = ?", msgID).Delete(&appdb.EmailLog{})
	}
	http.Redirect(w, r, "/admin/queue", http.StatusFound)
}

func (h *Handler) DeleteQueueAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/queue", http.StatusFound)
		return
	}
	count := h.Queue.ClearAll()
	h.DB.Where("status IN ?", []string{"queued", "deferred"}).Delete(&appdb.EmailLog{})
	http.Redirect(w, r, "/admin/queue?ok="+url.QueryEscape(fmt.Sprintf("Cleared %d messages from queue", count)), http.StatusFound)
}

// ──────────────────────────── Data Management ─────────────────────────────────

func (h *Handler) DataManagement(w http.ResponseWriter, r *http.Request) {
	claims, _ := webauth.GetClaims(r)
	var logCount, statsCount int64
	h.DB.Model(&appdb.EmailLog{}).Count(&logCount)
	h.DB.Model(&appdb.DailyStats{}).Count(&statsCount)
	data := map[string]interface{}{
		"Page":       "data",
		"ActiveUser": claims.Username,
		"LogCount":   logCount,
		"StatsCount": statsCount,
	}
	if ok := r.URL.Query().Get("ok"); ok != "" {
		data["FlashOK"] = ok
	}
	if err := r.URL.Query().Get("err"); err != "" {
		data["FlashErr"] = err
	}
	h.Tmpl.Render(w, "admin/data", data)
}

func (h *Handler) DataManagementDeleteLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/data", http.StatusFound)
		return
	}
	deleted, err := appdb.DeleteLogsKeepStats()
	if err != nil {
		http.Redirect(w, r, "/admin/data?err="+url.QueryEscape(err.Error()), http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/data?ok="+url.QueryEscape(fmt.Sprintf("Deleted %d log rows. Statistics preserved.", deleted)), http.StatusFound)
}

func (h *Handler) DataManagementDeleteAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/data", http.StatusFound)
		return
	}
	logs, stats := appdb.DeleteAllData()
	http.Redirect(w, r, "/admin/data?ok="+url.QueryEscape(fmt.Sprintf("Deleted %d log rows and %d stat rows. All data cleared.", logs, stats)), http.StatusFound)
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
	intervalSec, _ := strconv.Atoi(r.FormValue("interval_sec"))

	rule := appdb.ThrottleRule{
		Username:    r.FormValue("username"),
		Domain:      r.FormValue("domain"),
		PerSec:      perSec, PerMin: perMin, PerHour: perHour,
		PerDay: perDay, PerMonth: perMonth,
		IntervalSec: intervalSec,
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
	cfToken := appdb.GetCFToken(claims.Username)
	hasCFToken := cfToken != ""
	h.Tmpl.Render(w, "admin/settings", map[string]interface{}{
		"Page":       "settings",
		"ActiveUser": claims.Username,
		"Settings":   h.ConfigSnapshot,
		"HasCFToken": hasCFToken,
		"FlashOK":    r.URL.Query().Get("ok"),
		"FlashErr":   r.URL.Query().Get("err"),
	})
}

// SaveCloudflareToken saves the Cloudflare API token from the Settings page.
func (h *Handler) SaveCloudflareToken(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/settings", http.StatusFound)
		return
	}
	claims, _ := webauth.GetClaims(r)
	token := strings.TrimSpace(r.FormValue("cf_token"))
	if err := appdb.SetCFToken(claims.Username, token); err != nil {
		log.Printf("cloudflare: failed to save token: %v", err)
		http.Redirect(w, r, "/admin/settings?err=Failed+to+save+token", http.StatusFound)
		return
	}
	if token == "" {
		http.Redirect(w, r, "/admin/settings?ok=cloudflare+token+cleared", http.StatusFound)
	} else {
		http.Redirect(w, r, "/admin/settings?ok=cloudflare+token+saved", http.StatusFound)
	}
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

	s := appdb.GetAggregateStatsAdmin()
	totalSent, delivered, hardBounce, failed, deferred, queued := s.Sent, s.Delivered, s.HardBounce, s.Failed, s.Deferred, s.Queued
	softBounce := s.SoftBounce + s.Deferred // combined for "Soft Bounce / Deferred" display
	var bounceListTotal int64
	h.DB.Model(&appdb.BounceList{}).Count(&bounceListTotal)

	attempted := totalSent - queued - deferred
	var deliveryRate float64
	if attempted > 0 {
		deliveryRate = float64(delivered) / float64(attempted) * 100
	}

	type domainRow struct {
		Domain string
		Count  int64
	}
	var topDomains []domainRow
	h.DB.Raw(`SELECT substr(recipient, instr(recipient,'@')+1) AS domain, COUNT(*) AS count
		FROM email_logs WHERE deleted_at IS NULL
		GROUP BY domain ORDER BY count DESC LIMIT 10`).Scan(&topDomains)

	var topSenders []struct {
		Username string
		Count    int64
	}
	h.DB.Model(&appdb.EmailLog{}).
		Select("username, COUNT(*) as count").
		Group("username").Order("count DESC").Limit(10).Scan(&topSenders)

	chartLabels, chartDelivered, chartBounced := appdb.GetDailyCountsAdmin(30)
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

	entries := appdb.GetAllIPPool()
	stats := map[string]delivery.IPCounterSnapshot{}
	if h.IPStatsProvider != nil {
		stats = h.IPStatsProvider()
	}
	views := make([]ipEntryView, len(entries))
	for i, e := range entries {
		s := stats[e.IP]
		views[i] = ipEntryView{
			IPPool:      e,
			MinSent:     s.MinCount,
			HourSent:    s.HourCount,
			DaySent:     s.DayCount,
			DomainRules: appdb.GetIPPoolDomainRules(e.ID),
		}
	}

	masterRules := appdb.GetAllIPPoolMasterDomainRules()
	h.Tmpl.Render(w, "admin/ippool", map[string]interface{}{
		"Page":           "ippool",
		"ActiveUser":     claims.Username,
		"Enabled":        appdb.GetSetting("ip_pool_enabled", "false") == "true",
		"Entries":        views,
		"MasterRules":    masterRules,
		"FlashOK":        r.URL.Query().Get("ok"),
		"FlashErr":       r.URL.Query().Get("err"),
	})
}

func (h *Handler) ToggleIPPool(w http.ResponseWriter, r *http.Request) {
	enabled := r.FormValue("enabled") == "on"
	val := "false"
	if enabled {
		val = "true"
	}
	if err := appdb.SetSetting("ip_pool_enabled", val); err != nil {
		log.Printf("ippool: failed to save setting: %v", err)
		http.Redirect(w, r, "/admin/ippool?err=Failed+to+save", http.StatusFound)
		return
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
	intervalSec, _ := strconv.Atoi(r.FormValue("interval_sec"))
	entry := &appdb.IPPool{
		IP:            ip,
		Hostname:      strings.TrimSpace(r.FormValue("hostname")),
		Active:        r.FormValue("active") != "off",
		PerMin:        perMin,
		PerHour:       perHour,
		PerDay:        perDay,
		IntervalSec:   intervalSec,
		Note:          strings.TrimSpace(r.FormValue("note")),
		WarmupEnabled: warmupEnabled,
		WarmupDays:    warmupDays,
	}
	if warmupEnabled {
		t := time.Now()
		entry.WarmupStartedAt = &t
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
	entry.IntervalSec, _ = strconv.Atoi(r.FormValue("interval_sec"))
	entry.Note = strings.TrimSpace(r.FormValue("note"))
	entry.WarmupDays = warmupDays
	// Only reset warmup start time if toggling warmup on.
	if warmupEnabled && !entry.WarmupEnabled {
		t := time.Now()
		entry.WarmupStartedAt = &t
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

func (h *Handler) AddIPPoolDomainRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/ippool", http.StatusFound)
		return
	}
	ipPoolID, _ := strconv.ParseUint(r.FormValue("ip_pool_id"), 10, 64)
	domain := strings.TrimSpace(r.FormValue("domain"))
	perMin, _ := strconv.Atoi(r.FormValue("per_min"))
	perHour, _ := strconv.Atoi(r.FormValue("per_hour"))
	perDay, _ := strconv.Atoi(r.FormValue("per_day"))
	intervalSec, _ := strconv.Atoi(r.FormValue("interval_sec"))
	if err := appdb.AddIPPoolDomainRule(uint(ipPoolID), domain, perMin, perHour, perDay, intervalSec); err != nil {
		http.Redirect(w, r, "/admin/ippool?err="+url.QueryEscape(err.Error()), http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/ippool?ok=Domain+rule+added", http.StatusFound)
}

func (h *Handler) UpdateIPPoolDomainRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/ippool", http.StatusFound)
		return
	}
	id, _ := strconv.ParseUint(r.FormValue("id"), 10, 64)
	ipPoolID, _ := strconv.ParseUint(r.FormValue("ip_pool_id"), 10, 64)
	domain := strings.TrimSpace(r.FormValue("domain"))
	perMin, _ := strconv.Atoi(r.FormValue("per_min"))
	perHour, _ := strconv.Atoi(r.FormValue("per_hour"))
	perDay, _ := strconv.Atoi(r.FormValue("per_day"))
	intervalSec, _ := strconv.Atoi(r.FormValue("interval_sec"))
	if err := appdb.UpdateIPPoolDomainRule(uint(id), uint(ipPoolID), domain, perMin, perHour, perDay, intervalSec); err != nil {
		http.Redirect(w, r, "/admin/ippool?err="+url.QueryEscape(err.Error()), http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/ippool?ok=Domain+rule+updated", http.StatusFound)
}

func (h *Handler) DeleteIPPoolDomainRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/ippool", http.StatusFound)
		return
	}
	id, _ := strconv.ParseUint(r.FormValue("id"), 10, 64)
	ipPoolID, _ := strconv.ParseUint(r.FormValue("ip_pool_id"), 10, 64)
	appdb.DeleteIPPoolDomainRule(uint(id), uint(ipPoolID))
	http.Redirect(w, r, "/admin/ippool?ok=Domain+rule+removed", http.StatusFound)
}

func (h *Handler) SaveIPPool(w http.ResponseWriter, r *http.Request) {
	h.ToggleIPPool(w, r)
}

// ──────────────────────────── Force From Address ──────────────────────────────

func (h *Handler) ForceFrom(w http.ResponseWriter, r *http.Request) {
	claims, _ := webauth.GetClaims(r)
	templates := appdb.GetForceEmailTemplates()
	h.Tmpl.Render(w, "admin/forcefrom", map[string]interface{}{
		"Page":                   "forcefrom",
		"ActiveUser":             claims.Username,
		"Enabled":                appdb.GetForceFromEnabled(),
		"Domains":                appdb.GetForceFromDomainsRaw(),
		"ForceEmailEnabled":      appdb.GetForceEmailEnabled(),
		"ForceEmailFromEnabled":  appdb.GetForceEmailFromEnabled(),
		"ForceEmailAddressesRaw": appdb.GetForceEmailAddressesRaw(),
		"ForceTemplateCount":     len(templates),
		"FlashOK":                r.URL.Query().Get("ok"),
		"FlashErr":               r.URL.Query().Get("err"),
	})
}

func (h *Handler) SaveForceFrom(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/forcefrom", http.StatusFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/admin/forcefrom?err=Invalid+form", http.StatusFound)
		return
	}
	enabled := r.FormValue("enabled") == "on"
	domains := strings.TrimSpace(r.FormValue("domains"))
	if err := appdb.SetForceFromConfig(enabled, domains); err != nil {
		log.Printf("forcefrom: failed to save: %v", err)
		http.Redirect(w, r, "/admin/forcefrom?err=Failed+to+save", http.StatusFound)
		return
	}
	forceEmailEnabled := r.FormValue("force_email_enabled") == "on"
	forceEmailFromEnabled := r.FormValue("force_email_from_enabled") == "on"
	addressesRaw := r.FormValue("force_email_addresses")
	if err := appdb.SetForceEmailBasicConfig(forceEmailEnabled, forceEmailFromEnabled, addressesRaw); err != nil {
		log.Printf("forceemail: failed to save: %v", err)
		http.Redirect(w, r, "/admin/forcefrom?err=Failed+to+save+Force+Email", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/forcefrom?ok=Config+updated", http.StatusFound)
}

// ──────────────────────────── Force Template ────────────────────────────────────

func (h *Handler) ForceTemplate(w http.ResponseWriter, r *http.Request) {
	claims, _ := webauth.GetClaims(r)
	h.Tmpl.Render(w, "admin/forcetemplate", map[string]interface{}{
		"Page":       "forcetemplate",
		"ActiveUser": claims.Username,
		"Templates":  appdb.GetForceEmailTemplates(),
		"FlashOK":   r.URL.Query().Get("ok"),
		"FlashErr":  r.URL.Query().Get("err"),
	})
}

func (h *Handler) AddForceTemplate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/forcetemplate", http.StatusFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/admin/forcetemplate?err=Invalid+form", http.StatusFound)
		return
	}
	subject := strings.TrimSpace(r.FormValue("subject"))
	body := r.FormValue("body")
	templates := appdb.GetForceEmailTemplates()
	templates = append(templates, appdb.ForceEmailTemplate{Subject: subject, Body: body})
	if err := appdb.SetForceEmailTemplates(templates); err != nil {
		log.Printf("forcetemplate: failed to add: %v", err)
		http.Redirect(w, r, "/admin/forcetemplate?err=Failed+to+save", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/forcetemplate?ok=Template+added", http.StatusFound)
}

func (h *Handler) DeleteForceTemplate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/forcetemplate", http.StatusFound)
		return
	}
	if err := r.ParseForm(); err != nil {
		http.Redirect(w, r, "/admin/forcetemplate?err=Invalid+form", http.StatusFound)
		return
	}
	idx, _ := strconv.Atoi(r.FormValue("index"))
	templates := appdb.GetForceEmailTemplates()
	if idx < 0 || idx >= len(templates) {
		http.Redirect(w, r, "/admin/forcetemplate?err=Invalid+index", http.StatusFound)
		return
	}
	templates = append(templates[:idx], templates[idx+1:]...)
	if err := appdb.SetForceEmailTemplates(templates); err != nil {
		log.Printf("forcetemplate: failed to delete: %v", err)
		http.Redirect(w, r, "/admin/forcetemplate?err=Failed+to+save", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/forcetemplate?ok=Template+removed", http.StatusFound)
}

func (h *Handler) AddIPPoolMasterDomainRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/ippool", http.StatusFound)
		return
	}
	domain := strings.TrimSpace(r.FormValue("domain"))
	perMin, _ := strconv.Atoi(r.FormValue("per_min"))
	perHour, _ := strconv.Atoi(r.FormValue("per_hour"))
	perDay, _ := strconv.Atoi(r.FormValue("per_day"))
	intervalSec, _ := strconv.Atoi(r.FormValue("interval_sec"))
	if err := appdb.AddIPPoolMasterDomainRule(domain, perMin, perHour, perDay, intervalSec); err != nil {
		http.Redirect(w, r, "/admin/ippool?err="+url.QueryEscape(err.Error()), http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/ippool?ok=Master+rule+added", http.StatusFound)
}

func (h *Handler) UpdateIPPoolMasterDomainRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/ippool", http.StatusFound)
		return
	}
	id, _ := strconv.ParseUint(r.FormValue("id"), 10, 64)
	domain := strings.TrimSpace(r.FormValue("domain"))
	perMin, _ := strconv.Atoi(r.FormValue("per_min"))
	perHour, _ := strconv.Atoi(r.FormValue("per_hour"))
	perDay, _ := strconv.Atoi(r.FormValue("per_day"))
	intervalSec, _ := strconv.Atoi(r.FormValue("interval_sec"))
	if err := appdb.UpdateIPPoolMasterDomainRule(uint(id), domain, perMin, perHour, perDay, intervalSec); err != nil {
		http.Redirect(w, r, "/admin/ippool?err="+url.QueryEscape(err.Error()), http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/ippool?ok=Master+rule+updated", http.StatusFound)
}

func (h *Handler) DeleteIPPoolMasterDomainRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/ippool", http.StatusFound)
		return
	}
	id, _ := strconv.ParseUint(r.FormValue("id"), 10, 64)
	appdb.DeleteIPPoolMasterDomainRule(uint(id))
	http.Redirect(w, r, "/admin/ippool?ok=Master+rule+removed", http.StatusFound)
}

// BulkAddIPPool imports multiple IPs from a textarea in "ip:hostname" format.
// Lines starting with # are treated as comments and skipped.
// Existing IPs are updated with the new hostname (if provided); new IPs are created.
func (h *Handler) BulkAddIPPool(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/ippool", http.StatusFound)
		return
	}
	text := r.FormValue("ips")
	// Normalize line endings and Unicode colons (full-width, etc.) to ASCII colon
	text = strings.ReplaceAll(text, "\r\n", "\n")
	text = strings.ReplaceAll(text, "\uff1a", ":") // full-width colon
	text = strings.ReplaceAll(text, "\u2236", ":") // ratio
	lines := strings.Split(text, "\n")
	added, updated, skipped := 0, 0, 0
	for _, raw := range lines {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		parts := strings.SplitN(line, ":", 2)
		ip := strings.TrimSpace(parts[0])
		hostname := ""
		if len(parts) == 2 {
			hostname = strings.TrimSpace(parts[1])
		}
		// Strip any invisible/control chars that can break IP parsing (e.g. from copy-paste)
		ip = strings.Map(func(r rune) rune {
			if r < 32 || r == 127 || r == '\ufffd' {
				return -1
			}
			return r
		}, ip)
		if ip == "" || net.ParseIP(ip) == nil {
			log.Printf("ippool bulk: invalid IP %q (line: %q)", ip, line)
			skipped++
			continue
		}
		var existing appdb.IPPool
		if err := h.DB.Where("ip = ?", ip).First(&existing).Error; err != nil {
			// New entry — active, no rate limits.
			entry := &appdb.IPPool{IP: ip, Hostname: hostname, Active: true}
			if err := appdb.SaveIPPoolEntry(entry); err == nil {
				added++
			} else {
				log.Printf("ippool bulk: failed to save %s: %v", ip, err)
				skipped++
			}
		} else {
			if hostname != "" {
				existing.Hostname = hostname
				appdb.SaveIPPoolEntry(&existing)
			}
			updated++
		}
	}
	msg := fmt.Sprintf("Imported %d new, %d updated", added, updated)
	if skipped > 0 {
		msg += fmt.Sprintf(", %d skipped (invalid)", skipped)
	}
	http.Redirect(w, r, "/admin/ippool?ok="+url.QueryEscape(msg), http.StatusFound)
}

// RequestLetsEncrypt issues a free Let's Encrypt certificate via certbot (preferred)
// or acme.sh. Both tools use the HTTP-01 standalone challenge on port 80.
func (h *Handler) RequestLetsEncrypt(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/ssl", http.StatusFound)
		return
	}
	hostname := strings.TrimSpace(r.FormValue("le_hostname"))
	email := strings.TrimSpace(r.FormValue("le_email"))
	if hostname == "" || email == "" {
		http.Redirect(w, r, "/admin/ssl?err=Hostname+and+email+are+required", http.StatusFound)
		return
	}

	// Try certbot first (most common on Linux servers).
	certPath, keyPath, out, err := issueCertbot(hostname, email)
	if err != nil {
		// Fall back to acme.sh.
		certPath, keyPath, out, err = issueAcmeSh(hostname, email)
	}
	if err != nil {
		errMsg := "Certificate issuance failed. Make sure port 80 is open and not in use.\n\n" + out
		http.Redirect(w, r, "/admin/ssl?err="+url.QueryEscape(errMsg), http.StatusFound)
		return
	}

	// Auto-update config.yaml to use the new cert.
	if perr := patchConfigTLS(h.ConfigPath, true, certPath, keyPath, "starttls"); perr != nil {
		http.Redirect(w, r, "/admin/ssl?err="+url.QueryEscape("Cert issued but config update failed: "+perr.Error()), http.StatusFound)
		return
	}
	http.Redirect(w, r, "/admin/ssl?ok="+url.QueryEscape("Certificate issued for "+hostname+"! Restart the server to apply."), http.StatusFound)
}

func issueCertbot(hostname, email string) (certFile, keyFile, output string, err error) {
	cmd := exec.Command("certbot", "certonly",
		"--standalone", "--non-interactive", "--agree-tos",
		"--email", email, "-d", hostname,
	)
	out, runErr := cmd.CombinedOutput()
	output = string(out)
	if runErr != nil {
		err = runErr
		return
	}
	certFile = "/etc/letsencrypt/live/" + hostname + "/fullchain.pem"
	keyFile = "/etc/letsencrypt/live/" + hostname + "/privkey.pem"
	return
}

func issueAcmeSh(hostname, email string) (certFile, keyFile, output string, err error) {
	home := os.Getenv("HOME")
	if home == "" {
		home = "/root"
	}
	acmeBin := filepath.Join(home, ".acme.sh/acme.sh")
	if _, statErr := os.Stat(acmeBin); statErr != nil {
		err = fmt.Errorf("acme.sh not found at %s and certbot failed", acmeBin)
		return
	}
	cmd := exec.Command(acmeBin, "--issue", "--standalone",
		"--domain", hostname, "--accountemail", email,
	)
	out, runErr := cmd.CombinedOutput()
	output = string(out)
	if runErr != nil {
		err = runErr
		return
	}
	certFile = filepath.Join(home, ".acme.sh", hostname, "fullchain.cer")
	keyFile = filepath.Join(home, ".acme.sh", hostname, hostname+".key")
	return
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

// ─────────────────────────── Cloudflare DNS push ─────────────────────────────

// CloudflareSetToken saves (or clears) the CF API token for the admin user.
func (h *Handler) CloudflareSetToken(w http.ResponseWriter, r *http.Request) {
	claims, _ := webauth.GetClaims(r)
	token := strings.TrimSpace(r.FormValue("token"))
	w.Header().Set("Content-Type", "application/json")
	if err := appdb.SetCFToken(claims.Username, token); err != nil {
		log.Printf("cloudflare: failed to save token: %v", err)
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"error":"Failed to save token","code":"DB_ERROR"}`)
		return
	}
	fmt.Fprintf(w, `{"ok":true}`)
}

// CloudflarePushDNS pushes SPF/DKIM/MX/DMARC records for a domain to Cloudflare.
// Returns JSON so the browser can render results without a page reload.
func (h *Handler) CloudflarePushDNS(w http.ResponseWriter, r *http.Request) {
	claims, _ := webauth.GetClaims(r)
	w.Header().Set("Content-Type", "application/json")

	// Check token.
	apiToken := appdb.GetCFToken(claims.Username)
	if apiToken == "" {
		fmt.Fprintf(w, `{"need_token":true}`)
		return
	}

	domainID, _ := strconv.ParseUint(r.FormValue("domain_id"), 10, 64)
	d, ok := appdb.GetDomainByID(uint(domainID))
	if !ok {
		fmt.Fprintf(w, `{"error":"domain not found"}`)
		return
	}

	heloName := h.ConfigSnapshot["smtp_domain"]
	spfInclude := "spf." + heloName

	opts := cf.PushOptions{
		Domain:      d.Name,
		DKIMName:    d.DKIMSelector + "._domainkey." + d.Name,
		DKIMContent: d.DKIMPubKeyDNS,
		SPFInclude:  spfInclude,
		MXTarget:    heloName,
		MXPriority:  10,
	}

	client := cf.New(apiToken)
	records, err := client.PushDNS(opts)
	if err != nil {
		ce, ok := err.(*cf.ClassifiedError)
		if ok {
			b, _ := json.Marshal(map[string]string{
				"error":   ce.Message,
				"code":    ce.Code,
				"detail":  ce.Detail,
			})
			w.Write(b)
		} else {
			b, _ := json.Marshal(map[string]string{"error": err.Error(), "code": "UNKNOWN"})
			w.Write(b)
		}
		return
	}
	b, _ := json.Marshal(map[string]interface{}{"records": records})
	w.Write(b)
}

// ─────────────────────────── Suppression (admin) ─────────────────────────────

// Suppression shows all suppression entries across all users.
func (h *Handler) Suppression(w http.ResponseWriter, r *http.Request) {
	page, _ := strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	const perPage = 50
	list, total := appdb.GetAllSuppressions(page, perPage)
	h.Tmpl.Render(w, "admin/suppression", map[string]interface{}{
		"Page":     "suppression",
		"List":     list,
		"Total":    total,
		"PageNum":  page,
		"PerPage":  perPage,
		"HasPrev":  page > 1,
		"HasNext":  int64(page*perPage) < total,
	})
}

// DeleteSuppression removes a suppression entry (admin can remove any).
func (h *Handler) DeleteSuppression(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/suppression", http.StatusFound)
		return
	}
	id, _ := strconv.ParseUint(r.FormValue("id"), 10, 64)
	if id > 0 {
		appdb.RemoveSuppressionAdmin(uint(id))
	}
	http.Redirect(w, r, "/admin/suppression", http.StatusFound)
}

// AddSuppressionAdmin allows admin to manually suppress an address for a user.
func (h *Handler) AddSuppressionAdmin(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/admin/suppression", http.StatusFound)
		return
	}
	username := strings.TrimSpace(r.FormValue("username"))
	email := strings.TrimSpace(r.FormValue("email"))
	if username != "" && email != "" {
		appdb.AddSuppression(username, email, "manual", "admin")
	}
	http.Redirect(w, r, "/admin/suppression", http.StatusFound)
}

// ─────────────────────────── Blacklist Checker ───────────────────────────────

var ipDNSBLs = []struct{ Name, Zone string }{
	{"Spamhaus ZEN", "zen.spamhaus.org"},
	{"SpamCop", "bl.spamcop.net"},
	{"Barracuda", "b.barracuda.com"},
	{"SORBS", "dnsbl.sorbs.net"},
	{"Abusix", "combined.mail.abusix.zone"},
}

var domainDNSBLs = []struct{ Name, Zone string }{
	{"Spamhaus DBL", "dbl.spamhaus.org"},
	{"SURBL", "multi.surbl.org"},
	{"URIBL", "multi.uribl.com"},
}

// isValidDNSBLHit returns true only when the response address represents a genuine
// listing. It filters out the special error / quota-exceeded codes that Spamhaus,
// URIBL and others return when they reject a query (e.g. from a public resolver):
//
//   127.255.x.x  – Spamhaus "blocked / error" range  (252=blocked, 254=temp, 255=bad)
//   127.0.0.255  – URIBL / SURBL test/error sentinel
//
// A real listing is always 127.0.x.x or 127.0.1.x with a small last-octet.
func isValidDNSBLHit(addr string) bool {
	ip := net.ParseIP(addr)
	if ip == nil {
		return false
	}
	ip4 := ip.To4()
	if ip4 == nil || ip4[0] != 127 {
		return false
	}
	// 127.255.x.x → Spamhaus error / query-blocked codes; not a real listing.
	if ip4[1] == 255 {
		return false
	}
	// 127.0.0.255 → test/sentinel record used by URIBL and SURBL.
	if ip4[1] == 0 && ip4[2] == 0 && ip4[3] == 255 {
		return false
	}
	return true
}

func checkIPOnDNSBL(ctx context.Context, ip, zone string) (listed bool, detail string) {
	parts := strings.Split(ip, ".")
	if len(parts) != 4 {
		return false, ""
	}
	reversed := parts[3] + "." + parts[2] + "." + parts[1] + "." + parts[0]
	addrs, err := net.DefaultResolver.LookupHost(ctx, reversed+"."+zone)
	if err != nil {
		return false, "" // NXDOMAIN = not listed
	}
	var valid []string
	for _, a := range addrs {
		if isValidDNSBLHit(a) {
			valid = append(valid, a)
		}
	}
	if len(valid) == 0 {
		return false, ""
	}
	return true, strings.Join(valid, ",")
}

func checkDomainOnDNSBL(ctx context.Context, domain, zone string) (listed bool, detail string) {
	addrs, err := net.DefaultResolver.LookupHost(ctx, domain+"."+zone)
	if err != nil {
		return false, "" // NXDOMAIN = not listed
	}
	var valid []string
	for _, a := range addrs {
		if isValidDNSBLHit(a) {
			valid = append(valid, a)
		}
	}
	if len(valid) == 0 {
		return false, ""
	}
	return true, strings.Join(valid, ",")
}

type blResult struct {
	Name   string `json:"name"`
	Zone   string `json:"zone"`
	Listed bool   `json:"listed"`
	Detail string `json:"detail,omitempty"`
}

type blSubject struct {
	Value   string     `json:"value"`
	Type    string     `json:"type"`  // "ip" or "domain"
	Extra   string     `json:"extra"` // hostname for IPs, "(manual)" for custom entries
	Results []blResult `json:"results"`
	Score   int        `json:"score"`
}

// BlacklistCheck renders the blacklist status page.
func (h *Handler) BlacklistCheck(w http.ResponseWriter, r *http.Request) {
	poolEntries := appdb.GetAllIPPool()
	domains := appdb.GetAllDomains()

	// Ensure the HELO/server domain is also checked even if not in domains table.
	helo := h.ConfigSnapshot["smtp_domain"]
	if helo != "" {
		found := false
		for _, d := range domains {
			if d.Name == helo {
				found = true
				break
			}
		}
		if !found {
			domains = append(domains, appdb.Domain{Name: helo})
		}
	}

	h.Tmpl.Render(w, "admin/blacklist", map[string]interface{}{
		"Page":         "blacklist",
		"PoolIPs":      poolEntries,
		"Domains":      domains,
		"IPDNSBLs":     ipDNSBLs,
		"DomainDNSBLs": domainDNSBLs,
	})
}

// BlacklistScan performs DNS-based blacklist checks and returns JSON results.
func (h *Handler) BlacklistScan(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()

	poolEntries := appdb.GetAllIPPool()
	domains := appdb.GetAllDomains()

	helo := h.ConfigSnapshot["smtp_domain"]
	if helo != "" {
		found := false
		for _, d := range domains {
			if d.Name == helo {
				found = true
				break
			}
		}
		if !found {
			domains = append(domains, appdb.Domain{Name: helo})
		}
	}

	// Accept extra IPs/domains for ad-hoc checks.
	for _, ip := range strings.Fields(r.URL.Query().Get("ips")) {
		if ip = strings.TrimSpace(ip); ip != "" {
			poolEntries = append(poolEntries, appdb.IPPool{IP: ip, Hostname: "(manual)"})
		}
	}
	for _, d := range strings.Fields(r.URL.Query().Get("domains")) {
		if d = strings.TrimSpace(d); d != "" {
			domains = append(domains, appdb.Domain{Name: d})
		}
	}

	var (
		results []blSubject
		mu      sync.Mutex
		wg      sync.WaitGroup
	)

	for _, entry := range poolEntries {
		entry := entry
		wg.Add(1)
		go func() {
			defer wg.Done()
			sub := blSubject{Value: entry.IP, Type: "ip", Extra: entry.Hostname}
			for _, bl := range ipDNSBLs {
				listed, detail := checkIPOnDNSBL(ctx, entry.IP, bl.Zone)
				sub.Results = append(sub.Results, blResult{Name: bl.Name, Zone: bl.Zone, Listed: listed, Detail: detail})
				if listed {
					sub.Score++
				}
			}
			mu.Lock()
			results = append(results, sub)
			mu.Unlock()
		}()
	}

	for _, d := range domains {
		d := d
		wg.Add(1)
		go func() {
			defer wg.Done()
			sub := blSubject{Value: d.Name, Type: "domain"}
			for _, bl := range domainDNSBLs {
				listed, detail := checkDomainOnDNSBL(ctx, d.Name, bl.Zone)
				sub.Results = append(sub.Results, blResult{Name: bl.Name, Zone: bl.Zone, Listed: listed, Detail: detail})
				if listed {
					sub.Score++
				}
			}
			mu.Lock()
			results = append(results, sub)
			mu.Unlock()
		}()
	}

	wg.Wait()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(results)
}
