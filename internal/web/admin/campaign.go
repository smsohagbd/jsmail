package admin

import (
	"net/http"

	appdb "smtp-server/internal/db"
	webauth "smtp-server/internal/web/auth"
)

func (h *Handler) Campaigns(w http.ResponseWriter, r *http.Request) {
	claims, _ := webauth.GetClaims(r)
	camps := appdb.GetAllCampaigns()
	h.Tmpl.Render(w, "admin/campaigns", map[string]interface{}{
		"ActiveUser": claims.Username,
		"Page":       "campaigns",
		"Campaigns":  camps,
	})
}

func (h *Handler) Automation(w http.ResponseWriter, r *http.Request) {
	claims, _ := webauth.GetClaims(r)
	autos := appdb.GetAllAutomations()
	h.Tmpl.Render(w, "admin/automation", map[string]interface{}{
		"ActiveUser":  claims.Username,
		"Page":        "automation",
		"Automations": autos,
	})
}
