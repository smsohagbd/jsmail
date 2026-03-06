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

	h.Tmpl.Render(w, "admin/logs", map[string]interface{}{
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

// RemoveBounce removes an address from the suppression list.
func (h *Handler) RemoveBounce(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	if email != "" {
		appdb.RemoveFromBounceList(email)
	}
	http.Redirect(w, r, "/admin/reports", http.StatusFound)
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
		"IPs":        appdb.GetSetting("ip_pool_ips", ""),
		"FlashOK":    r.URL.Query().Get("ok"),
	})
}

func (h *Handler) SaveIPPool(w http.ResponseWriter, r *http.Request) {
	enabled := r.FormValue("enabled") == "on"
	ips := strings.TrimSpace(r.FormValue("ips"))
	if enabled {
		appdb.SetSetting("ip_pool_enabled", "true")
	} else {
		appdb.SetSetting("ip_pool_enabled", "false")
	}
	appdb.SetSetting("ip_pool_ips", ips)
	http.Redirect(w, r, "/admin/ippool?ok=saved", http.StatusFound)
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

func (h *Handler) SSL(w http.ResponseWriter, r *http.Request) {
	claims, _ := webauth.GetClaims(r)
	certPath := h.ConfigSnapshot["tls_cert_file"]
	keyPath := h.ConfigSnapshot["tls_key_file"]
	if certPath == "" {
		certPath = "certs/server.crt"
	}
	if keyPath == "" {
		keyPath = "certs/server.key"
	}
	h.Tmpl.Render(w, "admin/ssl", map[string]interface{}{
		"Page":         "ssl",
		"ActiveUser":   claims.Username,
		"TLSEnabled":   h.ConfigSnapshot["tls_enabled"] == "true",
		"CertPath":     certPath,
		"KeyPath":      keyPath,
		"CertInfo":     loadCertInfo(certPath),
		"FlashOK":      r.URL.Query().Get("ok"),
		"FlashErr":     r.URL.Query().Get("err"),
		"HeloName":     h.ConfigSnapshot["smtp_domain"],
	})
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
