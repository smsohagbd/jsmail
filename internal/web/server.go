package web

import (
	"embed"
	"html/template"
	"log"
	"net/http"
	"strings"

	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"

	appdb "smtp-server/internal/db"
	delivery "smtp-server/internal/delivery"
	"smtp-server/internal/queue"
	"smtp-server/internal/verifier"
	webadmin "smtp-server/internal/web/admin"
	webauth "smtp-server/internal/web/auth"
	webuser "smtp-server/internal/web/user"
)

//go:embed templates
var templateFS embed.FS

// tmplRenderer implements the TemplateRenderer interface used by handlers.
type tmplRenderer struct {
	fs embed.FS
}

func (r *tmplRenderer) Render(w http.ResponseWriter, name string, data map[string]interface{}) {
	// Build list of template files: shared base + optional namespace layout + page
	files := []string{"templates/base.html"}

	parts := strings.SplitN(name, "/", 2)
	if len(parts) == 2 {
		files = append(files, "templates/"+parts[0]+"/layout.html")
	}
	files = append(files, "templates/"+name+".html")

	// Root template is always "base.html" — page-level {{define "body"/"content"}} override its blocks.
	t, err := template.New("base.html").
		Funcs(template.FuncMap{
			"add":   func(a, b int) int { return a + b },
			"sub":   func(a, b int) int { return a - b },
			"mul":   func(a, b int) int { return a * b },
			"int64": func(n int) int64 { return int64(n) },
			"min": func(a, b int64) int64 {
				if a < b {
					return a
				}
				return b
			},
		}).
		ParseFS(r.fs, files...)
	if err != nil {
		log.Printf("template error (%s): %v", name, err)
		http.Error(w, "template error: "+err.Error(), 500)
		return
	}
	if err := t.Execute(w, data); err != nil {
		log.Printf("template execute error (%s): %v", name, err)
	}
}

// Server is the web UI server.
type Server struct {
	addr       string
	db         *gorm.DB
	queue      *queue.Queue
	engine     *delivery.Engine
	verifier   *verifier.Verifier
	renderer   *tmplRenderer
	cfg        map[string]string // snapshot of config values for settings page
	configPath string            // path to config.yaml for the editor
}

func NewServer(addr string, db *gorm.DB, q *queue.Queue, eng *delivery.Engine, v *verifier.Verifier, cfgSnapshot map[string]string, configPath string) *Server {
	return &Server{
		addr:       addr,
		db:         db,
		queue:      q,
		engine:     eng,
		verifier:   v,
		renderer:   &tmplRenderer{fs: templateFS},
		cfg:        cfgSnapshot,
		configPath: configPath,
	}
}

func (s *Server) Start() {
	mux := http.NewServeMux()

	// Auth routes
	mux.HandleFunc("/login", s.handleLogin)
	mux.HandleFunc("/logout", s.handleLogout)
	mux.HandleFunc("/register", s.handleRegister)
	mux.HandleFunc("/unsub", s.handleUnsub)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		claims, ok := webauth.GetClaims(r)
		if !ok {
			http.Redirect(w, r, "/login", http.StatusFound)
			return
		}
		if claims.Role == "admin" {
			http.Redirect(w, r, "/admin", http.StatusFound)
		} else {
			http.Redirect(w, r, "/user", http.StatusFound)
		}
	})

	// Admin routes
	ah := &webadmin.Handler{
		DB:             s.db,
		Queue:          s.queue,
		Tmpl:           s.renderer,
		ConfigSnapshot: s.cfg,
		ConfigPath:     s.configPath,
		IPStatsProvider: func() map[string]delivery.IPCounterSnapshot {
			if s.engine == nil {
				return nil
			}
			return s.engine.GetIPStats()
		},
	}
	mux.HandleFunc("/admin", webauth.RequireAdmin(ah.Dashboard))
	mux.HandleFunc("/admin/users", webauth.RequireAdmin(ah.Users))
	mux.HandleFunc("/admin/users/create", webauth.RequireAdmin(ah.CreateUser))
	mux.HandleFunc("/admin/users/update", webauth.RequireAdmin(ah.UpdateUser))
	mux.HandleFunc("/admin/users/delete", webauth.RequireAdmin(ah.DeleteUser))
	mux.HandleFunc("/admin/logs", webauth.RequireAdmin(ah.Logs))
	mux.HandleFunc("/admin/logs/delete", webauth.RequireAdmin(ah.DeleteLogs))
	mux.HandleFunc("/admin/queue", webauth.RequireAdmin(ah.QueuePage))
	mux.HandleFunc("/admin/queue/delete", webauth.RequireAdmin(ah.DeleteQueueItem))
	mux.HandleFunc("/admin/queue/delete-all", webauth.RequireAdmin(ah.DeleteQueueAll))
	mux.HandleFunc("/admin/throttle", webauth.RequireAdmin(ah.Throttle))
	mux.HandleFunc("/admin/throttle/save", webauth.RequireAdmin(ah.SaveThrottle))
	mux.HandleFunc("/admin/throttle/delete", webauth.RequireAdmin(ah.DeleteThrottle))
	mux.HandleFunc("/admin/settings", webauth.RequireAdmin(ah.Settings))
	mux.HandleFunc("/admin/settings/cloudflare-token", webauth.RequireAdmin(ah.SaveCloudflareToken))
	mux.HandleFunc("/admin/reports", webauth.RequireAdmin(ah.Reports))
	mux.HandleFunc("/admin/bounces", webauth.RequireAdmin(ah.Bounces))
	mux.HandleFunc("/admin/bounces/remove", webauth.RequireAdmin(ah.RemoveBounce))
	mux.HandleFunc("/admin/bounces/bulk-remove", webauth.RequireAdmin(ah.BulkRemoveBounces))
	mux.HandleFunc("/admin/bounce/remove", webauth.RequireAdmin(ah.RemoveBounce)) // legacy
	mux.HandleFunc("/admin/domains", webauth.RequireAdmin(ah.Domains))
	mux.HandleFunc("/admin/domains/add", webauth.RequireAdmin(ah.AddDomain))
	mux.HandleFunc("/admin/domains/delete", webauth.RequireAdmin(ah.DeleteDomain))
	mux.HandleFunc("/admin/domains/cloudflare/token", webauth.RequireAdmin(ah.CloudflareSetToken))
	mux.HandleFunc("/admin/domains/cloudflare", webauth.RequireAdmin(ah.CloudflarePushDNS))
	mux.HandleFunc("/admin/ippool", webauth.RequireAdmin(ah.IPPool))
	mux.HandleFunc("/admin/ippool/toggle", webauth.RequireAdmin(ah.ToggleIPPool))
	mux.HandleFunc("/admin/ippool/add", webauth.RequireAdmin(ah.AddIPPoolEntry))
	mux.HandleFunc("/admin/ippool/update", webauth.RequireAdmin(ah.UpdateIPPoolEntry))
	mux.HandleFunc("/admin/ippool/delete", webauth.RequireAdmin(ah.DeleteIPPoolEntry))
	mux.HandleFunc("/admin/ippool/domain-rule/add", webauth.RequireAdmin(ah.AddIPPoolDomainRule))
	mux.HandleFunc("/admin/ippool/domain-rule/update", webauth.RequireAdmin(ah.UpdateIPPoolDomainRule))
	mux.HandleFunc("/admin/ippool/domain-rule/delete", webauth.RequireAdmin(ah.DeleteIPPoolDomainRule))
	mux.HandleFunc("/admin/ippool/test-ip", webauth.RequireAdmin(ah.TestIPBinding))
	mux.HandleFunc("/admin/ippool/bulk-add", webauth.RequireAdmin(ah.BulkAddIPPool))
	mux.HandleFunc("/admin/ippool/master/save", webauth.RequireAdmin(ah.SaveIPPoolMaster))
	mux.HandleFunc("/admin/forcefrom", webauth.RequireAdmin(ah.ForceFrom))
	mux.HandleFunc("/admin/forcefrom/save", webauth.RequireAdmin(ah.SaveForceFrom))
	mux.HandleFunc("/admin/config", webauth.RequireAdmin(ah.ConfigEditor))
	mux.HandleFunc("/admin/ssl", webauth.RequireAdmin(ah.SSL))
	mux.HandleFunc("/admin/ssl/save", webauth.RequireAdmin(ah.SaveTLSConfig))
	mux.HandleFunc("/admin/ssl/scan", webauth.RequireAdmin(ah.ScanCerts))
	mux.HandleFunc("/admin/ssl/generate", webauth.RequireAdmin(ah.GenerateSelfSigned))
	mux.HandleFunc("/admin/ssl/verify", webauth.RequireAdmin(ah.VerifyCert))
	mux.HandleFunc("/admin/ssl/letsencrypt", webauth.RequireAdmin(ah.RequestLetsEncrypt))
	mux.HandleFunc("/admin/blacklist", webauth.RequireAdmin(ah.BlacklistCheck))
	mux.HandleFunc("/admin/blacklist/scan", webauth.RequireAdmin(ah.BlacklistScan))
	mux.HandleFunc("/admin/suppression", webauth.RequireAdmin(ah.Suppression))
	mux.HandleFunc("/admin/suppression/delete", webauth.RequireAdmin(ah.DeleteSuppression))
	mux.HandleFunc("/admin/suppression/add", webauth.RequireAdmin(ah.AddSuppressionAdmin))
	mux.HandleFunc("/admin/data", webauth.RequireAdmin(ah.DataManagement))
	mux.HandleFunc("/admin/data/delete-logs", webauth.RequireAdmin(ah.DataManagementDeleteLogs))
	mux.HandleFunc("/admin/data/delete-all", webauth.RequireAdmin(ah.DataManagementDeleteAll))

	// User routes
	uh := &webuser.Handler{DB: s.db, Queue: s.queue, Verifier: s.verifier, Tmpl: s.renderer, ConfigSnapshot: s.cfg}
	mux.HandleFunc("/user", webauth.RequireUser(uh.Dashboard))
	mux.HandleFunc("/user/logs", webauth.RequireUser(uh.Logs))
	mux.HandleFunc("/user/queue", webauth.RequireUser(uh.QueuePage))
	mux.HandleFunc("/user/queue/delete", webauth.RequireUser(uh.DeleteQueueItem))
	mux.HandleFunc("/user/queue/delete-all", webauth.RequireUser(uh.DeleteQueueAll))
	mux.HandleFunc("/user/verify", webauth.RequireUser(uh.Verify))
	mux.HandleFunc("/user/verify/single", webauth.RequireUser(uh.VerifySingle))
	mux.HandleFunc("/user/verify/bulk", webauth.RequireUser(uh.VerifyBulk))
	mux.HandleFunc("/user/reports", webauth.RequireUser(uh.Reports))
	mux.HandleFunc("/user/domains", webauth.RequireUser(uh.Domains))
	mux.HandleFunc("/user/domains/add", webauth.RequireUser(uh.AddDomain))
	mux.HandleFunc("/user/domains/delete", webauth.RequireUser(uh.DeleteDomain))
	mux.HandleFunc("/user/domains/cloudflare/token", webauth.RequireUser(uh.CloudflareSetToken))
	mux.HandleFunc("/user/domains/cloudflare", webauth.RequireUser(uh.CloudflarePushDNS))
	mux.HandleFunc("/user/smtp", webauth.RequireUser(uh.SMTPPage))
	mux.HandleFunc("/user/smtp/add", webauth.RequireUser(uh.AddSMTP))
	mux.HandleFunc("/user/smtp/delete", webauth.RequireUser(uh.DeleteSMTP))
	mux.HandleFunc("/user/smtp/default", webauth.RequireUser(uh.SetDefaultSMTP))
	mux.HandleFunc("/user/smtp/toggle", webauth.RequireUser(uh.ToggleSMTP))
	mux.HandleFunc("/user/smtp/update", webauth.RequireUser(uh.UpdateSMTP))
	mux.HandleFunc("/user/smtp/rotation", webauth.RequireUser(uh.ToggleSMTPRotation))
	mux.HandleFunc("/user/smtp/test", webauth.RequireUser(uh.TestSMTP))
	mux.HandleFunc("/user/smtp/bulk", webauth.RequireUser(uh.BulkAddSMTP))
	mux.HandleFunc("/user/suppression", webauth.RequireUser(uh.SuppressionPage))
	mux.HandleFunc("/user/suppression/add", webauth.RequireUser(uh.AddUserSuppression))
	mux.HandleFunc("/user/suppression/remove", webauth.RequireUser(uh.RemoveUserSuppression))

	log.Printf("web: UI server listening on %s", s.addr)
	if err := http.ListenAndServe(s.addr, mux); err != nil {
		log.Fatalf("web: server failed: %v", err)
	}
}

// ──────────────────────────── Auth handlers ───────────────────────────────────

func (s *Server) handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		s.renderer.Render(w, "login", map[string]interface{}{})
		return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")

	user, ok := appdb.CheckPassword(username, password)
	if !ok {
		s.renderer.Render(w, "login", map[string]interface{}{
			"Error": "Invalid username or password",
		})
		return
	}

	token, err := webauth.CreateToken(user.Username, user.Role)
	if err != nil {
		http.Error(w, "auth error", 500)
		return
	}
	webauth.SetCookie(w, token)

	if user.Role == "admin" {
		http.Redirect(w, r, "/admin", http.StatusFound)
	} else {
		http.Redirect(w, r, "/user", http.StatusFound)
	}
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	webauth.ClearCookie(w)
	http.Redirect(w, r, "/login", http.StatusFound)
}

// handleUnsub is a public (no-auth) endpoint that processes unsubscribe requests.
// GET  /unsub?t=TOKEN          → show confirmation form
// POST /unsub  (t + email)     → add to suppression list, show success page
func (s *Server) handleUnsub(w http.ResponseWriter, r *http.Request) {
	token := r.FormValue("t")
	if token == "" {
		token = r.URL.Query().Get("t")
	}
	if token == "" {
		s.renderer.Render(w, "unsub", map[string]interface{}{
			"Error": "Invalid or missing unsubscribe link.",
		})
		return
	}
	username, ok := appdb.ValidateUnsubToken(token)
	if !ok {
		s.renderer.Render(w, "unsub", map[string]interface{}{
			"Error": "This unsubscribe link is invalid or has expired.",
		})
		return
	}
	if r.Method == http.MethodPost {
		email := strings.ToLower(strings.TrimSpace(r.FormValue("email")))
		if email == "" {
			s.renderer.Render(w, "unsub", map[string]interface{}{
				"Token": token, "Username": username,
				"Error": "Please enter your email address.",
			})
			return
		}
		appdb.AddSuppression(username, email, "unsubscribed", "link")
		s.renderer.Render(w, "unsub", map[string]interface{}{
			"Success": true,
			"Email":   email,
		})
		return
	}
	s.renderer.Render(w, "unsub", map[string]interface{}{
		"Token":    token,
		"Username": username,
	})
}

func (s *Server) handleRegister(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		s.renderer.Render(w, "register", map[string]interface{}{})
		return
	}
	username := r.FormValue("username")
	password := r.FormValue("password")
	email := r.FormValue("email")

	if username == "" || password == "" {
		s.renderer.Render(w, "register", map[string]interface{}{
			"Error": "Username and password are required",
		})
		return
	}

	var existing appdb.User
	if err := s.db.Where("username = ?", username).First(&existing).Error; err == nil {
		s.renderer.Render(w, "register", map[string]interface{}{
			"Error": "Username already exists",
		})
		return
	}

	hash, _ := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	s.db.Create(&appdb.User{
		Username: username,
		Password: string(hash),
		Email:    email,
		Role:     "user",
		Active:   true,
	})
	http.Redirect(w, r, "/login", http.StatusFound)
}
