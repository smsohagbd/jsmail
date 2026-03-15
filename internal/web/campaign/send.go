package campaign

import (
	"encoding/base64"
	"fmt"
	"regexp"
	"strings"

	appdb "smtp-server/internal/db"
	"smtp-server/internal/queue"
)

// BuildCampaignEmail renders template with merge vars, injects tracking pixel, wraps links.
// baseURL e.g. https://mail.example.com
func BuildCampaignEmail(htmlBody, baseURL, trackToken string, mergeVars map[string]string) string {
	body := htmlBody
	for k, v := range mergeVars {
		body = strings.ReplaceAll(body, "{{."+k+"}}", v)
		body = strings.ReplaceAll(body, "{{"+k+"}}", v)
	}

	// Wrap links with click tracking
	body = wrapLinksWithTracking(body, baseURL, trackToken)

	// Inject open tracking pixel before </body>
	pixelURL := baseURL + "/t/o/" + trackToken
	pixel := fmt.Sprintf(`<img src="%s" width="1" height="1" alt="" style="display:none"/>`, pixelURL)
	if idx := strings.LastIndex(strings.ToLower(body), "</body>"); idx >= 0 {
		body = body[:idx] + pixel + body[idx:]
	} else {
		body += pixel
	}
	return body
}

var hrefRe = regexp.MustCompile(`(?i)<a\s+([^>]*?)href\s*=\s*["']([^"']+)["']([^>]*)>`)

func wrapLinksWithTracking(html, baseURL, token string) string {
	return hrefRe.ReplaceAllStringFunc(html, func(match string) string {
		subs := hrefRe.FindStringSubmatch(match)
		if len(subs) < 4 {
			return match
		}
		before, url, after := subs[1], subs[2], subs[3]
		urlLower := strings.ToLower(strings.TrimSpace(url))
		if strings.HasPrefix(urlLower, "mailto:") || strings.HasPrefix(urlLower, "tel:") ||
			strings.HasPrefix(urlLower, "#") || strings.Contains(urlLower, "/t/c") {
			return match
		}
		if strings.HasPrefix(urlLower, "http://") || strings.HasPrefix(urlLower, "https://") {
			b64 := base64.URLEncoding.EncodeToString([]byte(url))
			url = baseURL + "/t/c?t=" + token + "&u=" + b64
		}
		return `<a ` + before + `href="` + url + `"` + after + `>`
	})
}

// EnqueueCampaignSends creates CampaignSend records, builds emails, and enqueues for each contact.
// LogQueuedFn is called for each enqueued message (for send logs). Can be nil.
func EnqueueCampaignSends(camp *appdb.Campaign, contacts []appdb.Contact, tmpl *appdb.CampaignTemplate,
	baseURL, username, fromEmail, fromName string, q *queue.Queue, logQueuedFn func(username, msgID, from string, to []string)) (int, error) {
	count := 0
	for _, c := range contacts {
		if c.Status != "subscribed" {
			continue
		}
		token, err := appdb.CreateCampaignSend(camp.ID, c.ID, c.Email)
		if err != nil {
			continue
		}
		mergeVars := map[string]string{
			"Email":     c.Email,
			"FirstName": c.FirstName,
			"LastName":  c.LastName,
			"Name":      strings.TrimSpace(c.FirstName + " " + c.LastName),
		}
		if mergeVars["Name"] == "" {
			mergeVars["Name"] = c.Email
		}
		htmlBody := BuildCampaignEmail(tmpl.HTMLBody, baseURL, token, mergeVars)
		subject := camp.Subject
		if subject == "" {
			subject = tmpl.Subject
		}
		fromHeader := formatFrom(fromName, fromEmail)
		msg := buildRFC2822(fromHeader, c.Email, subject, htmlBody)
		qmsg := &queue.Message{
			Username: username,
			From:     fromEmail,
			To:       []string{c.Email},
			Data:     []byte(msg),
		}
		if err := q.Enqueue(qmsg); err != nil {
			continue
		}
		if logQueuedFn != nil {
			logQueuedFn(username, qmsg.ID, fromEmail, []string{c.Email})
		}
		count++
	}
	return count, nil
}

func formatFrom(name, email string) string {
	if name != "" {
		return name + " <" + email + ">"
	}
	return email
}

func buildRFC2822(from, to, subject, htmlBody string) string {
	var b strings.Builder
	b.WriteString("From: " + from + "\r\n")
	b.WriteString("To: " + to + "\r\n")
	b.WriteString("Subject: " + subject + "\r\n")
	b.WriteString("MIME-Version: 1.0\r\n")
	b.WriteString("Content-Type: text/html; charset=UTF-8\r\n")
	b.WriteString("\r\n")
	b.WriteString(htmlBody)
	return b.String()
}
