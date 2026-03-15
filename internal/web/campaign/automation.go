package campaign

import (
	"strings"

	appdb "smtp-server/internal/db"
	"smtp-server/internal/queue"
)

// TriggerSubscribeAutomations runs when a contact is added to a list.
// Finds active automations with trigger_type=subscribe and trigger_list_id=listID,
// sends the first send_email step to the new contact.
// fromEmail: e.g. noreply@yourdomain.com (from config)
func TriggerSubscribeAutomations(listID uint, contact appdb.Contact, username, fromEmail string, q *queue.Queue) int {
	autos := getSubscribeAutomations(listID, username)
	count := 0
	for _, a := range autos {
		steps := appdb.GetAutomationSteps(a.ID)
		for _, s := range steps {
			if s.ActionType == "send_email" && s.TemplateID > 0 {
				tmpl := appdb.GetTemplateByID(s.TemplateID, username)
				if tmpl == nil {
					continue
				}
				fromName := strings.TrimSpace(a.FromName)
				mergeVars := map[string]string{
					"Email":     contact.Email,
					"FirstName": contact.FirstName,
					"LastName":  contact.LastName,
					"Name":      strings.TrimSpace(contact.FirstName + " " + contact.LastName),
				}
				if mergeVars["Name"] == "" {
					mergeVars["Name"] = contact.Email
				}
				// No tracking for automation (or we could add it - skip for simplicity)
				htmlBody := tmpl.HTMLBody
				for k, v := range mergeVars {
					htmlBody = strings.ReplaceAll(htmlBody, "{{."+k+"}}", v)
					htmlBody = strings.ReplaceAll(htmlBody, "{{"+k+"}}", v)
				}
				subject := tmpl.Subject
				if subject == "" {
					subject = "Welcome"
				}
				fromHeader := formatFrom(fromName, fromEmail)
				msg := buildRFC2822(fromHeader, contact.Email, subject, htmlBody)
				qmsg := &queue.Message{
					Username: username,
					From:     fromEmail,
					To:       []string{contact.Email},
					Data:     []byte(msg),
				}
				if q.Enqueue(qmsg) == nil {
					appdb.LogQueued(username, qmsg.ID, fromEmail, []string{contact.Email})
					count++
				}
				break // only first send_email step
			}
		}
	}
	return count
}

func getSubscribeAutomations(listID uint, username string) []appdb.Automation {
	var autos []appdb.Automation
	appdb.DB.Where("owner_username = ? AND trigger_type = ? AND trigger_list_id = ? AND status = ?",
		username, "subscribe", listID, "active").Find(&autos)
	return autos
}

