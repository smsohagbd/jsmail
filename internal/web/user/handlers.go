package user

import (
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/smtp"
	"net/url"
	"strconv"
	"strings"
	"time"

	"gorm.io/gorm"

	appdb "smtp-server/internal/db"
	"smtp-server/internal/queue"
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
	DB       *gorm.DB
	Queue    *queue.Queue
	Verifier *verifier.Verifier
	Tmpl     TemplateRenderer
}

type TemplateRenderer interface {
	Render(w http.ResponseWriter, name string, data map[string]interface{})
}

// ──────────────────────────── Dashboard ──────────────────────────────────────

func (h *Handler) Dashboard(w http.ResponseWriter, r *http.Request) {
	claims, _ := webauth.GetClaims(r)
	today := time.Now().Truncate(24 * time.Hour)

	var totalToday, totalYesterday, totalMonth, pending int64
	base := h.DB.Model(&appdb.EmailLog{}).Where("username = ?", claims.Username)
	base.Where("sent_at >= ?", today).Count(&totalToday)
	h.DB.Model(&appdb.EmailLog{}).Where("username = ? AND sent_at >= ? AND sent_at < ?",
		claims.Username, today.AddDate(0, 0, -1), today).Count(&totalYesterday)
	h.DB.Model(&appdb.EmailLog{}).Where("username = ? AND sent_at >= ?",
		claims.Username, today.AddDate(0, -1, 0)).Count(&totalMonth)
	h.DB.Model(&appdb.EmailLog{}).Where("username = ? AND status IN ?",
		claims.Username, []string{"queued", "deferred"}).Count(&pending)

	var recentLogs []appdb.EmailLog
	h.DB.Where("username = ?", claims.Username).Order("created_at desc").Limit(10).Find(&recentLogs)

	var user appdb.User
	h.DB.Where("username = ?", claims.Username).First(&user)

	h.Tmpl.Render(w, "user/dashboard", map[string]interface{}{
		"Page":           "dashboard",
		"ActiveUser":     claims.Username,
		"User":           user,
		"TotalToday":     totalToday,
		"TotalYesterday": totalYesterday,
		"TotalMonth":     totalMonth,
		"Pending":        pending,
		"RecentLogs":     recentLogs,
	})
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

	h.Tmpl.Render(w, "user/logs", map[string]interface{}{
		"Page":      "logs",
		"ActiveUser": claims.Username,
		"Logs":      logs,
		"Total":     total,
		"PageNum":   page,
		"PerPage":   perPage,
		"DateLabel": dateLabel,
		"Query":     flatQuery(r.URL.Query()),
	})
}

// ──────────────────────────── Queue ──────────────────────────────────────────

func (h *Handler) QueuePage(w http.ResponseWriter, r *http.Request) {
	claims, _ := webauth.GetClaims(r)
	var logs []appdb.EmailLog
	h.DB.Where("username = ? AND status IN ?",
		claims.Username, []string{"queued", "deferred"}).
		Order("created_at desc").Limit(100).Find(&logs)

	h.Tmpl.Render(w, "user/queue", map[string]interface{}{
		"Page":       "queue",
		"ActiveUser": claims.Username,
		"Logs":       logs,
	})
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
	h.Tmpl.Render(w, "user/verify", map[string]interface{}{
		"Page":       "verify",
		"ActiveUser": claims.Username,
	})
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
	h.Tmpl.Render(w, "user/verify", map[string]interface{}{
		"Page":         "verify",
		"ActiveUser":   claims.Username,
		"Results":      results,
		"ValidCount":   len(valid),
		"InvalidCount": len(invalid),
		"ValidList":    joinLines(valid),
		"InvalidList":  joinLines(invalid),
	})
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
	h.Tmpl.Render(w, "user/domains", map[string]interface{}{
		"Page":       "domains",
		"ActiveUser": claims.Username,
		"Domains":    appdb.GetDomainsByOwner(claims.Username),
		"ServerIP":   serverIP,
		"FlashOK":    r.URL.Query().Get("ok"),
		"FlashErr":   r.URL.Query().Get("err"),
	})
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
	h.Tmpl.Render(w, "user/smtp", map[string]interface{}{
		"Page":          "smtp",
		"ActiveUser":    claims.Username,
		"SMTPs":         smtps,
		"SMTPMode":      u.SMTPMode,
		"SMTPRotation":  u.SMTPRotation,
		"MaxCustomSMTP": u.MaxCustomSMTP,
		"FlashOK":       r.URL.Query().Get("ok"),
		"FlashErr":      r.URL.Query().Get("err"),
	})
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
	useTLS := r.FormValue("use_tls") == "on"
	port, _ := strconv.Atoi(portStr)
	if port == 0 {
		port = 587
	}
	if label == "" {
		label = host
	}

	// Test the connection before saving.
	if err := testSMTPConn(host, port, username, password, useTLS); err != nil {
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
		UseTLS:        useTLS,
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

		// Parse: host:port:user:pass:tls  (port and tls optional)
		parts := strings.SplitN(line, ":", 5)
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
		useTLS := true // default on
		if tlsIdx >= 0 && tlsIdx < len(parts) {
			v := strings.TrimSpace(parts[tlsIdx])
			useTLS = v == "1" || strings.EqualFold(v, "true") || strings.EqualFold(v, "yes")
		}

		if testAll {
			if err := testSMTPConn(host, port, smtpUser, smtpPass, useTLS); err != nil {
				errs = append(errs, fmt.Sprintf("%s:%d — test failed: %v", host, port, err))
				skipped++
				continue
			}
		}

		entry := &appdb.UserSMTP{
			OwnerUsername: claims.Username,
			Label:         host,
			Host:          host,
			Port:          port,
			Username:      smtpUser,
			Password:      smtpPass,
			UseTLS:        useTLS,
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
	useTLS := r.FormValue("use_tls") == "true"
	port, _ := strconv.Atoi(portStr)
	if port == 0 {
		port = 587
	}

	w.Header().Set("Content-Type", "application/json")
	if err := testSMTPConn(host, port, username, password, useTLS); err != nil {
		json.NewEncoder(w).Encode(map[string]interface{}{"ok": false, "error": err.Error()})
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{"ok": true})
}

// testSMTPConn tries to connect and authenticate to an SMTP server.
func testSMTPConn(host string, port int, username, password string, useTLS bool) error {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := net.DialTimeout("tcp4", addr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("connect: %w", err)
	}

	client, err := smtp.NewClient(conn, host)
	if err != nil {
		conn.Close()
		return fmt.Errorf("SMTP handshake: %w", err)
	}
	defer client.Close()

	if err := client.Hello("test.localhost"); err != nil {
		return fmt.Errorf("EHLO: %w", err)
	}

	if useTLS {
		if ok, _ := client.Extension("STARTTLS"); ok {
			tlsCfg := &tls.Config{ServerName: host, InsecureSkipVerify: false}
			if err := client.StartTLS(tlsCfg); err != nil {
				// Not fatal — some servers require STARTTLS, some don't. Try auth anyway.
				_ = err
			}
		}
	}

	if username != "" {
		auth := smtp.PlainAuth("", username, password, host)
		if err := client.Auth(auth); err != nil {
			return fmt.Errorf("AUTH failed (wrong credentials?): %w", err)
		}
	}
	client.Quit()
	return nil
}

// ──────────────────────────── Reports ────────────────────────────────────────

func (h *Handler) Reports(w http.ResponseWriter, r *http.Request) {
	claims, _ := webauth.GetClaims(r)
	uname := claims.Username

	var totalSent, delivered, hardBounce, softBounce, failed, deferred, queued int64
	h.DB.Model(&appdb.EmailLog{}).Where("username = ?", uname).Count(&totalSent)
	h.DB.Model(&appdb.EmailLog{}).Where("username = ? AND status = ?", uname, "delivered").Count(&delivered)
	h.DB.Model(&appdb.EmailLog{}).Where("username = ? AND status = ?", uname, "hard_bounce").Count(&hardBounce)
	h.DB.Model(&appdb.EmailLog{}).Where("username = ? AND status IN ?", uname, []string{"soft_bounce", "deferred"}).Count(&softBounce)
	h.DB.Model(&appdb.EmailLog{}).Where("username = ? AND status = ?", uname, "failed").Count(&failed)
	h.DB.Model(&appdb.EmailLog{}).Where("username = ? AND status = ?", uname, "deferred").Count(&deferred)
	h.DB.Model(&appdb.EmailLog{}).Where("username = ? AND status = ?", uname, "queued").Count(&queued)

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
			Where("username = ? AND sent_at >= ? AND sent_at < ? AND status = ?", uname, day, day.Add(24*time.Hour), "delivered").
			Count(&chartDelivered[idx])
		h.DB.Model(&appdb.EmailLog{}).
			Where("username = ? AND sent_at >= ? AND sent_at < ? AND status = ?", uname, day, day.Add(24*time.Hour), "hard_bounce").
			Count(&chartBounced[idx])
	}
	labelsJSON, _ := json.Marshal(chartLabels)
	deliveredJSON, _ := json.Marshal(chartDelivered)
	bouncedJSON, _ := json.Marshal(chartBounced)

	h.Tmpl.Render(w, "user/reports", map[string]interface{}{
		"Page":           "reports",
		"ActiveUser":     uname,
		"TotalSent":      totalSent,
		"Delivered":      delivered,
		"HardBounce":     hardBounce,
		"SoftBounce":     softBounce,
		"Failed":         failed,
		"Deferred":       deferred,
		"Queued":         queued,
		"DeliveryRate":   deliveryRate,
		"TopDomains":     topDomains,
		"ChartLabels":    string(labelsJSON),
		"ChartDelivered": string(deliveredJSON),
		"ChartBounced":   string(bouncedJSON),
	})
}
