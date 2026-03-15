package user

import (
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	appdb "smtp-server/internal/db"
	"smtp-server/internal/web/campaign"
	webauth "smtp-server/internal/web/auth"
)

// ─── Contact Lists ───────────────────────────────────────────────────────────

func (h *Handler) Lists(w http.ResponseWriter, r *http.Request) {
	claims, _ := webauth.GetClaims(r)
	lists := appdb.GetContactLists(claims.Username)
	counts := make(map[string]int64)
	for _, l := range lists {
		counts[strconv.FormatUint(uint64(l.ID), 10)] = appdb.CountContactsInList(l.ID)
	}
	data := map[string]interface{}{"Page": "lists", "Lists": lists, "ContactCounts": counts}
	if err := r.URL.Query().Get("err"); err != "" {
		data["Error"] = err
	}
	h.Tmpl.Render(w, "user/lists", merge(h.base(claims.Username), data))
}

func (h *Handler) ListCreate(w http.ResponseWriter, r *http.Request) {
	claims, _ := webauth.GetClaims(r)
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/user/lists", http.StatusFound)
		return
	}
	name := strings.TrimSpace(r.FormValue("name"))
	desc := strings.TrimSpace(r.FormValue("description"))
	if name == "" {
		http.Redirect(w, r, "/user/lists?err=name", http.StatusFound)
		return
	}
	if _, err := appdb.CreateContactList(claims.Username, name, desc); err != nil {
		http.Redirect(w, r, "/user/lists?err="+url.QueryEscape(err.Error()), http.StatusFound)
		return
	}
	http.Redirect(w, r, "/user/lists", http.StatusFound)
}

func (h *Handler) ListDelete(w http.ResponseWriter, r *http.Request) {
	claims, _ := webauth.GetClaims(r)
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/user/lists", http.StatusFound)
		return
	}
	id, _ := strconv.ParseUint(r.FormValue("id"), 10, 64)
	appdb.DeleteContactList(uint(id), claims.Username)
	http.Redirect(w, r, "/user/lists", http.StatusFound)
}

func (h *Handler) ListContacts(w http.ResponseWriter, r *http.Request) {
	claims, _ := webauth.GetClaims(r)
	id, _ := strconv.ParseUint(r.URL.Query().Get("id"), 10, 64)
	list := appdb.GetContactListByID(uint(id), claims.Username)
	if list == nil {
		http.Redirect(w, r, "/user/lists", http.StatusFound)
		return
	}
	contacts := appdb.GetContacts(uint(id), claims.Username)
	h.Tmpl.Render(w, "user/list-contacts", merge(h.base(claims.Username), map[string]interface{}{
		"Page": "lists", "List": list, "Contacts": contacts,
	}))
}

func (h *Handler) ContactAdd(w http.ResponseWriter, r *http.Request) {
	claims, _ := webauth.GetClaims(r)
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/user/lists", http.StatusFound)
		return
	}
	listID, _ := strconv.ParseUint(r.FormValue("list_id"), 10, 64)
	email := strings.TrimSpace(r.FormValue("email"))
	firstName := strings.TrimSpace(r.FormValue("first_name"))
	lastName := strings.TrimSpace(r.FormValue("last_name"))
	if email == "" {
		http.Redirect(w, r, "/user/lists/contacts?id="+r.FormValue("list_id")+"&err=email", http.StatusFound)
		return
	}
	appdb.AddContact(uint(listID), claims.Username, email, firstName, lastName, "")
	http.Redirect(w, r, "/user/lists/contacts?id="+r.FormValue("list_id"), http.StatusFound)
}

func (h *Handler) ContactDelete(w http.ResponseWriter, r *http.Request) {
	claims, _ := webauth.GetClaims(r)
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/user/lists", http.StatusFound)
		return
	}
	id, _ := strconv.ParseUint(r.FormValue("id"), 10, 64)
	listID := r.FormValue("list_id")
	appdb.DeleteContact(uint(id), claims.Username)
	http.Redirect(w, r, "/user/lists/contacts?id="+listID, http.StatusFound)
}

// ─── Templates ──────────────────────────────────────────────────────────────

func (h *Handler) Templates(w http.ResponseWriter, r *http.Request) {
	claims, _ := webauth.GetClaims(r)
	tmpls := appdb.GetTemplates(claims.Username)
	h.Tmpl.Render(w, "user/templates", merge(h.base(claims.Username), map[string]interface{}{
		"Page": "templates", "Templates": tmpls,
	}))
}

func (h *Handler) TemplateEdit(w http.ResponseWriter, r *http.Request) {
	claims, _ := webauth.GetClaims(r)
	idStr := r.URL.Query().Get("id")
	if idStr == "" {
		idStr = r.FormValue("id")
	}
	var t *appdb.CampaignTemplate
	if idStr != "" {
		id, _ := strconv.ParseUint(idStr, 10, 64)
		t = appdb.GetTemplateByID(uint(id), claims.Username)
	}
	if r.Method == http.MethodPost {
		name := strings.TrimSpace(r.FormValue("name"))
		subject := strings.TrimSpace(r.FormValue("subject"))
		htmlBody := r.FormValue("html_body")
		textBody := r.FormValue("text_body")
		if name == "" || htmlBody == "" {
			h.Tmpl.Render(w, "user/template-edit", merge(h.base(claims.Username), map[string]interface{}{
				"Page": "templates", "Template": t, "Error": "Name and HTML body required",
			}))
			return
		}
		if t != nil {
			appdb.UpdateTemplate(t.ID, claims.Username, name, subject, htmlBody, textBody)
		} else {
			if _, err := appdb.CreateTemplate(claims.Username, name, subject, htmlBody, textBody); err != nil {
				h.Tmpl.Render(w, "user/template-edit", merge(h.base(claims.Username), map[string]interface{}{
					"Page": "templates", "Template": t, "Error": err.Error(),
				}))
				return
			}
		}
		http.Redirect(w, r, "/user/templates", http.StatusFound)
		return
	}
	h.Tmpl.Render(w, "user/template-edit", merge(h.base(claims.Username), map[string]interface{}{
		"Page": "templates", "Template": t,
	}))
}

func (h *Handler) TemplateDelete(w http.ResponseWriter, r *http.Request) {
	claims, _ := webauth.GetClaims(r)
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/user/templates", http.StatusFound)
		return
	}
	id, _ := strconv.ParseUint(r.FormValue("id"), 10, 64)
	appdb.DeleteTemplate(uint(id), claims.Username)
	http.Redirect(w, r, "/user/templates", http.StatusFound)
}

// ─── Campaigns ───────────────────────────────────────────────────────────────

func (h *Handler) Campaigns(w http.ResponseWriter, r *http.Request) {
	claims, _ := webauth.GetClaims(r)
	camps := appdb.GetCampaigns(claims.Username)
	h.Tmpl.Render(w, "user/campaigns", merge(h.base(claims.Username), map[string]interface{}{
		"Page": "campaigns", "Campaigns": camps,
	}))
}

func (h *Handler) CampaignCreate(w http.ResponseWriter, r *http.Request) {
	claims, _ := webauth.GetClaims(r)
	lists := appdb.GetContactLists(claims.Username)
	tmpls := appdb.GetTemplates(claims.Username)
	if r.Method == http.MethodPost {
		name := strings.TrimSpace(r.FormValue("name"))
		subject := strings.TrimSpace(r.FormValue("subject"))
		fromEmail := strings.TrimSpace(r.FormValue("from_email"))
		replyTo := strings.TrimSpace(r.FormValue("reply_to"))
		templateID, _ := strconv.ParseUint(r.FormValue("template_id"), 10, 64)
		listID, _ := strconv.ParseUint(r.FormValue("list_id"), 10, 64)
		if name == "" || subject == "" || fromEmail == "" || templateID == 0 || listID == 0 {
			h.Tmpl.Render(w, "user/campaign-create", merge(h.base(claims.Username), map[string]interface{}{
				"Page": "campaigns", "Lists": lists, "Templates": tmpls, "Error": "All fields required",
			}))
			return
		}
		camp := &appdb.Campaign{
			Name: name, Subject: subject, FromEmail: fromEmail, ReplyTo: replyTo,
			TemplateID: uint(templateID), ListID: uint(listID), Status: "draft",
		}
		if err := appdb.CreateCampaign(claims.Username, camp); err != nil {
			h.Tmpl.Render(w, "user/campaign-create", merge(h.base(claims.Username), map[string]interface{}{
				"Page": "campaigns", "Lists": lists, "Templates": tmpls, "Error": err.Error(),
			}))
			return
		}
		http.Redirect(w, r, "/user/campaigns", http.StatusFound)
		return
	}
	h.Tmpl.Render(w, "user/campaign-create", merge(h.base(claims.Username), map[string]interface{}{
		"Page": "campaigns", "Lists": lists, "Templates": tmpls,
	}))
}

func (h *Handler) CampaignSend(w http.ResponseWriter, r *http.Request) {
	claims, _ := webauth.GetClaims(r)
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/user/campaigns", http.StatusFound)
		return
	}
	id, _ := strconv.ParseUint(r.FormValue("id"), 10, 64)
	camp := appdb.GetCampaignByID(uint(id), claims.Username)
	if camp == nil || camp.Status != "draft" {
		http.Redirect(w, r, "/user/campaigns", http.StatusFound)
		return
	}
	tmpl := appdb.GetTemplateByID(camp.TemplateID, claims.Username)
	if tmpl == nil {
		http.Redirect(w, r, "/user/campaigns", http.StatusFound)
		return
	}
	contacts := appdb.GetContacts(camp.ListID, claims.Username)
	baseURL := h.ConfigSnapshot["web_base_url"]
	if baseURL == "" {
		baseURL = "https://" + h.ConfigSnapshot["smtp_domain"]
	}
	count, _ := campaign.EnqueueCampaignSends(camp, contacts, tmpl, baseURL, claims.Username, camp.FromEmail, h.Queue)
	now := time.Now()
	appdb.UpdateCampaign(uint(id), claims.Username, map[string]interface{}{
		"status": "sent", "total_sent": count, "sent_at": now,
	})
	http.Redirect(w, r, "/user/campaigns", http.StatusFound)
}

func (h *Handler) CampaignDelete(w http.ResponseWriter, r *http.Request) {
	claims, _ := webauth.GetClaims(r)
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/user/campaigns", http.StatusFound)
		return
	}
	id, _ := strconv.ParseUint(r.FormValue("id"), 10, 64)
	appdb.DeleteCampaign(uint(id), claims.Username)
	http.Redirect(w, r, "/user/campaigns", http.StatusFound)
}

// ─── Automation ──────────────────────────────────────────────────────────────

func (h *Handler) Automation(w http.ResponseWriter, r *http.Request) {
	claims, _ := webauth.GetClaims(r)
	autos := appdb.GetAutomations(claims.Username)
	lists := appdb.GetContactLists(claims.Username)
	tmpls := appdb.GetTemplates(claims.Username)
	data := map[string]interface{}{"Page": "automation", "Automations": autos, "Lists": lists, "Templates": tmpls}
	if err := r.URL.Query().Get("err"); err != "" {
		data["Error"] = err
	}
	h.Tmpl.Render(w, "user/automation", merge(h.base(claims.Username), data))
}

func (h *Handler) AutomationCreate(w http.ResponseWriter, r *http.Request) {
	claims, _ := webauth.GetClaims(r)
	lists := appdb.GetContactLists(claims.Username)
	tmpls := appdb.GetTemplates(claims.Username)
	if r.Method == http.MethodPost {
		name := strings.TrimSpace(r.FormValue("name"))
		triggerType := r.FormValue("trigger_type")
		triggerListID, _ := strconv.ParseUint(r.FormValue("trigger_list_id"), 10, 64)
		if name == "" || triggerType == "" {
			http.Redirect(w, r, "/user/automation?err=fields", http.StatusFound)
			return
		}
		a := &appdb.Automation{
			Name: name, TriggerType: triggerType, TriggerListID: uint(triggerListID),
			Status: "active",
		}
		if err := appdb.CreateAutomation(claims.Username, a); err != nil {
			http.Redirect(w, r, "/user/automation?err="+url.QueryEscape(err.Error()), http.StatusFound)
			return
		}
		// Add first step if provided
		templateID, _ := strconv.ParseUint(r.FormValue("step_template_id"), 10, 64)
		delayMin, _ := strconv.Atoi(r.FormValue("step_delay"))
		if templateID > 0 {
			appdb.AddAutomationStep(a.ID, 1, "send_email", uint(templateID), delayMin, "")
		}
		http.Redirect(w, r, "/user/automation", http.StatusFound)
		return
	}
	h.Tmpl.Render(w, "user/automation-create", merge(h.base(claims.Username), map[string]interface{}{
		"Page": "automation", "Lists": lists, "Templates": tmpls,
	}))
}

func (h *Handler) AutomationDelete(w http.ResponseWriter, r *http.Request) {
	claims, _ := webauth.GetClaims(r)
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/user/automation", http.StatusFound)
		return
	}
	id, _ := strconv.ParseUint(r.FormValue("id"), 10, 64)
	appdb.DeleteAutomation(uint(id), claims.Username)
	http.Redirect(w, r, "/user/automation", http.StatusFound)
}
