package user

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"gorm.io/gorm"

	cf "smtp-server/internal/cloudflare"
	appdb "smtp-server/internal/db"
	"smtp-server/internal/queue"
	"smtp-server/internal/smtprelay"
	webauth "smtp-server/internal/web/auth"
	"smtp-server/internal/verifier"
)

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
	Verifier       *verifier.Verifier
	Tmpl           TemplateRenderer
	ConfigSnapshot map[string]string // for HeloName, smtp_domain, etc.
}

type TemplateRenderer interface {
	Render(w http.ResponseWriter, name string, data map[string]interface{})
}

// base returns common fields needed by every page (layout sidebar, etc.).
func (h *Handler) base(username string) map[string]interface{} {
	mode, rotation := appdb.GetUserSMTPMode(username)
	return map[string]interface{}{
		"ActiveUser":   username,
		"SMTPMode":     mode,
		"SMTPRotation": rotation,
	}
}

// merge combines base data with page-specific data (page data wins on conflict).
func merge(base, page map[string]interface{}) map[string]interface{} {
	for k, v := range page {
		base[k] = v
	}
	return base
}

// ──────────────────────────── Dashboard ──────────────────────────────────────

func (h *Handler) Dashboard(w http.ResponseWriter, r *http.Request) {
	claims, _ := webauth.GetClaims(r)

	totalToday, totalYesterday, totalMonth := appdb.GetTodayYesterdayMonthUser(claims.Username)
	var pending int64
	h.DB.Model(&appdb.EmailLog{}).Where("username = ? AND status IN ?",
		claims.Username, []string{"queued", "deferred"}).Count(&pending)

	var recentLogs []appdb.EmailLog
	h.DB.Where("username = ?", claims.Username).Order("created_at desc").Limit(10).Find(&recentLogs)

	var user appdb.User
	h.DB.Where("username = ?", claims.Username).First(&user)

	h.Tmpl.Render(w, "user/dashboard", merge(h.base(claims.Username), map[string]interface{}{
		"Page":           "dashboard",
		"User":           user,
		"TotalToday":     totalToday,
		"TotalYesterday": totalYesterday,
		"TotalMonth":     totalMonth,
		"Pending":        pending,
		"RecentLogs":     recentLogs,
	}))
}

// ──────────────────────────── Logs ───────────────────────────────────────────

func (h *Handler) Logs(w http.ResponseWriter, r *http.Request) {
	claims, _ := webauth.GetClaims(r)
	q := h.DB.Model(&appdb.EmailLog{}).Where("username = ?", claims.Username)
	q, dateLabel := applyFilters(q, r)

	if search := r.URL.Query().Get("search"); search != "" {
		like := "%" + search + "%"
		q = q.Where(`"from" LIKE ? OR recipient LIKE ?`, like, like)
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

	h.Tmpl.Render(w, "user/logs", merge(h.base(claims.Username), map[string]interface{}{
		"Page":      "logs",
		"Logs":      logs,
		"Total":     total,
		"PageNum":   page,
		"PerPage":   perPage,
		"DateLabel": dateLabel,
		"Query":     flatQuery(r.URL.Query()),
	}))
}

// ──────────────────────────── Queue ──────────────────────────────────────────

func (h *Handler) QueuePage(w http.ResponseWriter, r *http.Request) {
	claims, _ := webauth.GetClaims(r)
	var logs []appdb.EmailLog
	h.DB.Where("username = ? AND status IN ?",
		claims.Username, []string{"queued", "deferred"}).
		Order("created_at desc").Limit(100).Find(&logs)

	data := map[string]interface{}{"Page": "queue", "Logs": logs}
	if ok := r.URL.Query().Get("ok"); ok != "" {
		data["FlashOK"] = ok
	}
	h.Tmpl.Render(w, "user/queue", merge(h.base(claims.Username), data))
}

func (h *Handler) DeleteQueueAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/user/queue", http.StatusFound)
		return
	}
	claims, _ := webauth.GetClaims(r)
	count := h.Queue.ClearByUser(claims.Username)
	h.DB.Where("username = ? AND status IN ?", claims.Username, []string{"queued", "deferred"}).Delete(&appdb.EmailLog{})
	http.Redirect(w, r, "/user/queue?ok="+url.QueryEscape(fmt.Sprintf("Cleared %d messages from your queue", count)), http.StatusFound)
}

func (h *Handler) DeleteQueueItem(w http.ResponseWriter, r *http.Request) {
	claims, _ := webauth.GetClaims(r)
	msgID := r.FormValue("message_id")
	if msgID != "" {
		var log appdb.EmailLog
		// Only allow deletion if it belongs to this user
		if err := h.DB.Where("message_id = ? AND username = ?", msgID, claims.Username).First(&log).Error; err == nil {
			h.Queue.CancelByMessageID(msgID)
			h.DB.Where("message_id = ? AND username = ?", msgID, claims.Username).Delete(&appdb.EmailLog{})
		}
	}
	http.Redirect(w, r, "/user/queue", http.StatusFound)
}

// ──────────────────────────── Verify ─────────────────────────────────────────

func (h *Handler) Verify(w http.ResponseWriter, r *http.Request) {
	claims, _ := webauth.GetClaims(r)
	h.Tmpl.Render(w, "user/verify", merge(h.base(claims.Username), map[string]interface{}{
		"Page": "verify",
	}))
}

func (h *Handler) VerifySingle(w http.ResponseWriter, r *http.Request) {
	email := r.URL.Query().Get("email")
	if email == "" && r.Method == http.MethodPost {
		r.ParseForm()
		email = r.FormValue("email")
	}
	result := h.Verifier.Verify(email)
	w.Header().Set("Content-Type", "application/json")
	b, _ := json.Marshal(result)
	w.Write(b)
}

func (h *Handler) VerifyBulk(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST only", 405)
		return
	}
	r.ParseMultipartForm(10 << 20)
	raw := r.FormValue("emails")
	emails := splitEmails(raw)
	results := h.Verifier.VerifyBulk(emails, 5)

	valid := []string{}
	invalid := []string{}
	for _, res := range results {
		if res.Valid {
			valid = append(valid, res.Email)
		} else {
			invalid = append(invalid, res.Email)
		}
	}

	claims, _ := webauth.GetClaims(r)
	h.Tmpl.Render(w, "user/verify", merge(h.base(claims.Username), map[string]interface{}{
		"Page":         "verify",
		"Results":      results,
		"ValidCount":   len(valid),
		"InvalidCount": len(invalid),
		"ValidList":    joinLines(valid),
		"InvalidList":  joinLines(invalid),
	}))
}

// ─── helpers ─────────────────────────────────────────────────────────────────

func applyFilters(q *gorm.DB, r *http.Request) (*gorm.DB, string) {
	today := time.Now().Truncate(24 * time.Hour)
	switch r.URL.Query().Get("range") {
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

func splitEmails(raw string) []string {
	var out []string
	for _, line := range splitLines(raw) {
		e := trimSpace(line)
		if e != "" {
			out = append(out, e)
		}
	}
	return out
}

func splitLines(s string) []string {
	var lines []string
	start := 0
	for i, c := range s {
		if c == '\n' || c == ',' {
			lines = append(lines, s[start:i])
			start = i + 1
		}
	}
	lines = append(lines, s[start:])
	return lines
}

func trimSpace(s string) string {
	for len(s) > 0 && (s[0] == ' ' || s[0] == '\t' || s[0] == '\r') {
		s = s[1:]
	}
	for len(s) > 0 && (s[len(s)-1] == ' ' || s[len(s)-1] == '\t' || s[len(s)-1] == '\r') {
		s = s[:len(s)-1]
	}
	return s
}

func joinLines(ss []string) string {
	result := ""
	for i, s := range ss {
		if i > 0 {
			result += "\n"
		}
		result += s
	}
	return result
}

// ──────────────────────────── Domains ────────────────────────────────────────

func (h *Handler) Domains(w http.ResponseWriter, r *http.Request) {
	claims, _ := webauth.GetClaims(r)
	serverIP := userOutboundIP()
	h.Tmpl.Render(w, "user/domains", merge(h.base(claims.Username), map[string]interface{}{
		"Page":     "domains",
		"Domains":  appdb.GetDomainsByOwner(claims.Username),
		"ServerIP": serverIP,
		"FlashOK":  r.URL.Query().Get("ok"),
		"FlashErr": r.URL.Query().Get("err"),
	}))
}

func (h *Handler) AddDomain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/user/domains", http.StatusFound)
		return
	}
	claims, _ := webauth.GetClaims(r)
	name := strings.TrimSpace(r.FormValue("name"))
	selector := strings.TrimSpace(r.FormValue("selector"))
	if name == "" {
		http.Redirect(w, r, "/user/domains?err=domain+name+required", http.StatusFound)
		return
	}
	if _, err := appdb.CreateDomain(claims.Username, name, selector); err != nil {
		http.Redirect(w, r, "/user/domains?err="+url.QueryEscape(err.Error()), http.StatusFound)
		return
	}
	http.Redirect(w, r, "/user/domains?ok=domain+added", http.StatusFound)
}

func (h *Handler) DeleteDomain(w http.ResponseWriter, r *http.Request) {
	claims, _ := webauth.GetClaims(r)
	id, _ := strconv.ParseUint(r.FormValue("id"), 10, 64)
	// Only delete if owned by this user.
	var d appdb.Domain
	if err := h.DB.Where("id = ? AND owner_username = ?", id, claims.Username).First(&d).Error; err == nil {
		appdb.DeleteDomain(uint(id))
	}
	http.Redirect(w, r, "/user/domains", http.StatusFound)
}

func userOutboundIP() string {
	conn, err := net.Dial("udp", "8.8.8.8:80")
	if err != nil {
		return "unknown"
	}
	defer conn.Close()
	return conn.LocalAddr().(*net.UDPAddr).IP.String()
}

// ──────────────────────────── Custom SMTP ────────────────────────────────────

func (h *Handler) SMTPPage(w http.ResponseWriter, r *http.Request) {
	claims, _ := webauth.GetClaims(r)
	var u appdb.User
	h.DB.Where("username = ?", claims.Username).First(&u)

	smtps := appdb.GetUserSMTPs(claims.Username)
	h.Tmpl.Render(w, "user/smtp", merge(h.base(claims.Username), map[string]interface{}{
		"Page":          "smtp",
		"SMTPs":         smtps,
		"SMTPMode":      u.SMTPMode,
		"SMTPRotation":  u.SMTPRotation,
		"MaxCustomSMTP": u.MaxCustomSMTP,
		"FlashOK":       r.URL.Query().Get("ok"),
		"FlashErr":      r.URL.Query().Get("err"),
	}))
}

func (h *Handler) AddSMTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/user/smtp", http.StatusFound)
		return
	}
	claims, _ := webauth.GetClaims(r)

	var u appdb.User
	h.DB.Where("username = ?", claims.Username).First(&u)

	existing := appdb.GetUserSMTPs(claims.Username)
	if u.MaxCustomSMTP > 0 && len(existing) >= u.MaxCustomSMTP {
		http.Redirect(w, r, "/user/smtp?err="+url.QueryEscape(
			fmt.Sprintf("limit reached: maximum %d custom SMTP servers allowed", u.MaxCustomSMTP)), http.StatusFound)
		return
	}

	host := strings.TrimSpace(r.FormValue("host"))
	portStr := strings.TrimSpace(r.FormValue("port"))
	username := strings.TrimSpace(r.FormValue("smtp_user"))
	password := r.FormValue("smtp_pass")
	label := strings.TrimSpace(r.FormValue("label"))
	fromAddress := strings.TrimSpace(r.FormValue("from_address"))
	tlsMode := strings.TrimSpace(r.FormValue("tls_mode"))
	if tlsMode != "none" && tlsMode != "starttls" && tlsMode != "ssl" && tlsMode != "auto" {
		tlsMode = "auto"
	}
	port, _ := strconv.Atoi(portStr)
	if port == 0 {
		port = 587
	}
	if label == "" {
		label = host
	}

	// Test the connection before saving.
	if err := testSMTPConn(host, port, username, password, tlsMode); err != nil {
		http.Redirect(w, r, "/user/smtp?err="+url.QueryEscape("connection failed: "+err.Error()), http.StatusFound)
		return
	}

	entry := &appdb.UserSMTP{
		OwnerUsername: claims.Username,
		Label:         label,
		Host:          host,
		Port:          port,
		Username:      username,
		Password:      password,
		FromAddress:   fromAddress,
		TLSMode:       tlsMode,
		UseTLS:        tlsMode != "none",
		Active:        true,
	}
	if err := appdb.AddUserSMTP(entry); err != nil {
		http.Redirect(w, r, "/user/smtp?err="+url.QueryEscape("save failed: "+err.Error()), http.StatusFound)
		return
	}
	http.Redirect(w, r, "/user/smtp?ok=SMTP+server+added+and+verified", http.StatusFound)
}

func (h *Handler) DeleteSMTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/user/smtp", http.StatusFound)
		return
	}
	claims, _ := webauth.GetClaims(r)
	id, _ := strconv.ParseUint(r.FormValue("id"), 10, 64)
	appdb.DeleteUserSMTP(uint(id), claims.Username)
	http.Redirect(w, r, "/user/smtp?ok=SMTP+server+removed", http.StatusFound)
}

func (h *Handler) SetDefaultSMTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/user/smtp", http.StatusFound)
		return
	}
	claims, _ := webauth.GetClaims(r)
	id, _ := strconv.ParseUint(r.FormValue("id"), 10, 64)
	appdb.SetDefaultUserSMTP(uint(id), claims.Username)
	http.Redirect(w, r, "/user/smtp?ok=Default+SMTP+updated", http.StatusFound)
}

func (h *Handler) ToggleSMTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/user/smtp", http.StatusFound)
		return
	}
	claims, _ := webauth.GetClaims(r)
	id, _ := strconv.ParseUint(r.FormValue("id"), 10, 64)
	appdb.ToggleUserSMTP(uint(id), claims.Username)
	http.Redirect(w, r, "/user/smtp?ok=SMTP+status+toggled", http.StatusFound)
}

func (h *Handler) UpdateSMTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/user/smtp", http.StatusFound)
		return
	}
	claims, _ := webauth.GetClaims(r)
	id, _ := strconv.ParseUint(r.FormValue("id"), 10, 64)
	fromAddress := strings.TrimSpace(r.FormValue("from_address"))
	if err := appdb.UpdateUserSMTPFromAddress(uint(id), claims.Username, fromAddress); err != nil {
		http.Redirect(w, r, "/user/smtp?err="+url.QueryEscape("update failed: "+err.Error()), http.StatusFound)
		return
	}
	http.Redirect(w, r, "/user/smtp?ok=From+address+updated", http.StatusFound)
}

func (h *Handler) ToggleSMTPRotation(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/user/smtp", http.StatusFound)
		return
	}
	claims, _ := webauth.GetClaims(r)
	var u appdb.User
	h.DB.Where("username = ?", claims.Username).First(&u)
	appdb.SetUserSMTPMode(claims.Username, u.SMTPMode, !u.SMTPRotation, u.MaxCustomSMTP)
	http.Redirect(w, r, "/user/smtp?ok=Rotation+setting+updated", http.StatusFound)
}

// BulkAddSMTP parses multiple lines in "host:port:user:pass:tls" format and adds them.
func (h *Handler) BulkAddSMTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/user/smtp", http.StatusFound)
		return
	}
	claims, _ := webauth.GetClaims(r)
	var u appdb.User
	h.DB.Where("username = ?", claims.Username).First(&u)

	raw := r.FormValue("lines")
	testAll := r.FormValue("test_all") == "on"

	added, skipped, errs := 0, 0, []string{}

	for _, line := range strings.Split(raw, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Check limit before each entry.
		existing := appdb.GetUserSMTPs(claims.Username)
		if u.MaxCustomSMTP > 0 && len(existing) >= u.MaxCustomSMTP {
			errs = append(errs, fmt.Sprintf("limit reached (%d) — stopped at line: %s", u.MaxCustomSMTP, line))
			break
		}

		// Parse: host:port:user:pass:tls[:from@domain.com]  (port, tls, from optional)
		parts := strings.SplitN(line, ":", 6)
		if len(parts) < 3 {
			errs = append(errs, "bad format (need host:port:user:pass:tls): "+line)
			skipped++
			continue
		}

		host := strings.TrimSpace(parts[0])
		port := 587
		userIdx, passIdx, tlsIdx := 1, 2, -1

		// Detect if second field is a port number.
		if p, err := strconv.Atoi(strings.TrimSpace(parts[1])); err == nil {
			port = p
			userIdx, passIdx = 2, 3
			if len(parts) > 4 {
				tlsIdx = 4
			}
		} else {
			// No port field: host:user:pass[:tls]
			if len(parts) > 3 {
				tlsIdx = 3
			}
		}

		if passIdx >= len(parts) {
			errs = append(errs, "missing password: "+line)
			skipped++
			continue
		}
		smtpUser := strings.TrimSpace(parts[userIdx])
		smtpPass := strings.TrimSpace(parts[passIdx])
		tlsMode := "auto"
		if tlsIdx >= 0 && tlsIdx < len(parts) {
			v := strings.TrimSpace(strings.ToLower(parts[tlsIdx]))
			switch v {
			case "0", "none", "no", "false":
				tlsMode = "none"
			case "1", "starttls", "yes", "true":
				tlsMode = "starttls"
			case "2", "ssl", "tls":
				tlsMode = "ssl"
			case "3", "auto", "a":
				tlsMode = "auto"
			}
		}

		if testAll {
			if err := testSMTPConn(host, port, smtpUser, smtpPass, tlsMode); err != nil {
				errs = append(errs, fmt.Sprintf("%s:%d — test failed: %v", host, port, err))
				skipped++
				continue
			}
		}

		fromAddr := ""
		if len(parts) > 5 {
			fromAddr = strings.TrimSpace(parts[5])
		}
		entry := &appdb.UserSMTP{
			OwnerUsername: claims.Username,
			Label:         host,
			Host:          host,
			Port:          port,
			Username:      smtpUser,
			Password:      smtpPass,
			FromAddress:   fromAddr,
			TLSMode:       tlsMode,
			UseTLS:        tlsMode != "none",
			Active:        true,
		}
		if err := appdb.AddUserSMTP(entry); err != nil {
			errs = append(errs, fmt.Sprintf("%s — db error: %v", host, err))
			skipped++
		} else {
			added++
		}
	}

	msg := fmt.Sprintf("%d added", added)
	if skipped > 0 {
		msg += fmt.Sprintf(", %d skipped", skipped)
	}
	if len(errs) > 0 {
		msg += ": " + strings.Join(errs, "; ")
		http.Redirect(w, r, "/user/smtp?err="+url.QueryEscape(msg), http.StatusFound)
		return
	}
	http.Redirect(w, r, "/user/smtp?ok="+url.QueryEscape(msg), http.StatusFound)
}

// TestSMTP validates an SMTP connection (called via JSON API for live feedback).
func (h *Handler) TestSMTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", 405)
		return
	}
	host := strings.TrimSpace(r.FormValue("host"))
	portStr := strings.TrimSpace(r.FormValue("port"))
	username := strings.TrimSpace(r.FormValue("smtp_user"))
	password := r.FormValue("smtp_pass")
	tlsMode := r.FormValue("tls_mode")
	if tlsMode != "none" && tlsMode != "starttls" && tlsMode != "ssl" && tlsMode != "auto" {
		tlsMode = "auto"
	}
	port, _ := strconv.Atoi(portStr)
	if port == 0 {
		port = 587
	}

	w.Header().Set("Content-Type", "application/json")
	if err := testSMTPConn(host, port, username, password, tlsMode); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
}

// testSMTPConn tries to connect and authenticate to an SMTP server.
func testSMTPConn(host string, port int, username, password, tlsMode string) error {
	client, err := smtprelay.DialAndAuthenticate(smtprelay.Config{
		Host: host, Port: port, Username: username, Password: password, TLSMode: tlsMode,
		DialTimeout: 10 * time.Second, Helo: "test.localhost",
	})
	if err != nil {
		return err
	}
	defer client.Close()
	_ = client.Quit()
	return nil
}

// ──────────────────────────── Reports ────────────────────────────────────────

func (h *Handler) Reports(w http.ResponseWriter, r *http.Request) {
	claims, _ := webauth.GetClaims(r)
	uname := claims.Username

	s := appdb.GetAggregateStatsUser(uname)
	totalSent, delivered, hardBounce, failed, deferred, queued := s.Sent, s.Delivered, s.HardBounce, s.Failed, s.Deferred, s.Queued
	softBounce := s.SoftBounce + s.Deferred // combined for display

	campSent, campOpens, campClicks := appdb.GetCampaignStatsUser(uname)
	recentCampaigns := appdb.GetCampaigns(uname)
	if len(recentCampaigns) > 10 {
		recentCampaigns = recentCampaigns[:10]
	}

	attempted := totalSent - queued - deferred
	var deliveryRate float64
	if attempted > 0 {
		deliveryRate = float64(delivered) / float64(attempted) * 100
	}

	var topDomains []struct {
		Domain string
		Count  int64
	}
	h.DB.Raw(`SELECT substr(recipient, instr(recipient,'@')+1) AS domain, COUNT(*) AS count
		FROM email_logs WHERE deleted_at IS NULL AND username = ?
		GROUP BY domain ORDER BY count DESC LIMIT 10`, uname).Scan(&topDomains)

	chartLabels, chartDelivered, chartBounced := appdb.GetDailyCountsUser(uname, 30)
	labelsJSON, _ := json.Marshal(chartLabels)
	deliveredJSON, _ := json.Marshal(chartDelivered)
	bouncedJSON, _ := json.Marshal(chartBounced)

	h.Tmpl.Render(w, "user/reports", merge(h.base(uname), map[string]interface{}{
		"Page":            "reports",
		"TotalSent":       totalSent,
		"Delivered":       delivered,
		"HardBounce":      hardBounce,
		"SoftBounce":      softBounce,
		"Failed":          failed,
		"Deferred":        deferred,
		"Queued":          queued,
		"DeliveryRate":    deliveryRate,
		"TopDomains":      topDomains,
		"ChartLabels":     string(labelsJSON),
		"ChartDelivered":  string(deliveredJSON),
		"ChartBounced":    string(bouncedJSON),
		"CampaignSent":    campSent,
		"CampaignOpens":   campOpens,
		"CampaignClicks":  campClicks,
		"RecentCampaigns": recentCampaigns,
	}))
}

// ─────────────────────── Suppression list (user) ─────────────────────────────

func (h *Handler) SuppressionPage(w http.ResponseWriter, r *http.Request) {
	claims, _ := webauth.GetClaims(r)
	list := appdb.GetSuppressionsByUser(claims.Username)
	h.Tmpl.Render(w, "user/suppression", merge(h.base(claims.Username), map[string]interface{}{
		"Page": "suppression",
		"List": list,
	}))
}

func (h *Handler) AddUserSuppression(w http.ResponseWriter, r *http.Request) {
	claims, _ := webauth.GetClaims(r)
	if r.Method == http.MethodPost {
		email := strings.TrimSpace(r.FormValue("email"))
		if email != "" {
			appdb.AddSuppression(claims.Username, email, "manual", "user")
		}
	}
	http.Redirect(w, r, "/user/suppression", http.StatusFound)
}

func (h *Handler) RemoveUserSuppression(w http.ResponseWriter, r *http.Request) {
	claims, _ := webauth.GetClaims(r)
	if r.Method == http.MethodPost {
		id, _ := strconv.ParseUint(r.FormValue("id"), 10, 64)
		if id > 0 {
			appdb.RemoveSuppression(uint(id), claims.Username)
		}
	}
	http.Redirect(w, r, "/user/suppression", http.StatusFound)
}

// ─────────────────────────── Cloudflare DNS push (user) ──────────────────────

// CloudflareSetToken saves the user's Cloudflare API token.
func (h *Handler) CloudflareSetToken(w http.ResponseWriter, r *http.Request) {
	claims, _ := webauth.GetClaims(r)
	token := strings.TrimSpace(r.FormValue("token"))
	w.Header().Set("Content-Type", "application/json")
	if err := appdb.SetCFToken(claims.Username, token); err != nil {
		w.WriteHeader(http.StatusInternalServerError)
		fmt.Fprintf(w, `{"error":"Failed to save token","code":"DB_ERROR"}`)
		return
	}
	fmt.Fprintf(w, `{"ok":true}`)
}

// CloudflarePushDNS pushes DNS records for a user domain to Cloudflare.
func (h *Handler) CloudflarePushDNS(w http.ResponseWriter, r *http.Request) {
	claims, _ := webauth.GetClaims(r)
	w.Header().Set("Content-Type", "application/json")

	apiToken := appdb.GetCFToken(claims.Username)
	if apiToken == "" {
		fmt.Fprintf(w, `{"need_token":true}`)
		return
	}

	domainID, _ := strconv.ParseUint(r.FormValue("domain_id"), 10, 64)
	d, ok := appdb.GetDomainByID(uint(domainID))
	if !ok || (d.OwnerUsername != "" && d.OwnerUsername != claims.Username) {
		fmt.Fprintf(w, `{"error":"domain not found"}`)
		return
	}

	heloName := ""
	if h.ConfigSnapshot != nil {
		heloName = h.ConfigSnapshot["smtp_domain"]
	}
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
				"error":  ce.Message,
				"code":   ce.Code,
				"detail": ce.Detail,
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
