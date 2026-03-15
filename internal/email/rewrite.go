package email

import (
	"bytes"
	"regexp"
	"strings"
)

// trackingPixelPattern matches img tags that look like tracking pixels (Mautic, etc.).
// Handles quoted-printable encoding: src=3D" (decodes to src=")
var trackingPixelPattern = regexp.MustCompile(`(?i)<img\s[^>]*?src\s*(?:=\s*|=3[Dd]\s*)["']([^"']*(?:/email/|/mtc/|tracking|beacon|/pixel|/open)[^"']*)["'][^>]*>`)

// qpEncodedPattern matches same but with =2F for / in URL (quoted-printable)
var trackingPixelQPPattern = regexp.MustCompile(`(?i)<img[^>]*src\s*(?:=\s*|=3[Dd]\s*)["'][^"']*\/email\/[^"']*["'][^>]*>`)

// decodeQuotedPrintable decodes common QP sequences in extracted img tag (e.g. =3D -> =).
func decodeQuotedPrintable(s string) string {
	s = strings.ReplaceAll(s, "=3D", "=")
	s = strings.ReplaceAll(s, "=3d", "=")
	s = strings.ReplaceAll(s, "=2F", "/")
	s = strings.ReplaceAll(s, "=2f", "/")
	return s
}

// removeQPSoftBreaks removes quoted-printable soft line breaks (= at EOL) so we can match across lines.
func removeQPSoftBreaks(b []byte) []byte {
	b = bytes.ReplaceAll(b, []byte("=\r\n"), nil)
	b = bytes.ReplaceAll(b, []byte("=\n"), nil)
	return b
}

// extractTrackingPixels returns img tags from body that look like tracking pixels (Mautic, etc.).
// Handles multipart and quoted-printable encoded bodies.
func extractTrackingPixels(body []byte) string {
	// Remove QP soft breaks so img tag is contiguous for regex
	body = removeQPSoftBreaks(body)
	matches := trackingPixelPattern.FindAll(body, -1)
	if len(matches) == 0 && bytes.Contains(bytes.ToLower(body), []byte("/email/")) {
		matches = trackingPixelQPPattern.FindAll(body, -1)
	}
	if len(matches) == 0 {
		return ""
	}
	var out []string
	seen := make(map[string]bool)
	for _, m := range matches {
		s := string(m)
		// Decode quoted-printable so injected pixel is valid HTML
		s = decodeQuotedPrintable(s)
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return strings.Join(out, "")
}

// injectTrackingPixels appends tracking pixels into body before </body> or at end.
// If body is plain text and we have pixels, wrap in HTML so the pixel loads (tracking only works in HTML).
func injectTrackingPixels(body, pixels string) string {
	if pixels == "" {
		return body
	}
	// Prefer before </body> when body is HTML
	if idx := strings.LastIndex(strings.ToLower(body), "</body>"); idx >= 0 {
		return body[:idx] + pixels + body[idx:]
	}
	// Plain text body: wrap in HTML so tracking pixel works (pixels need HTML to load)
	escaped := strings.ReplaceAll(body, "&", "&amp;")
	escaped = strings.ReplaceAll(escaped, "<", "&lt;")
	escaped = strings.ReplaceAll(escaped, ">", "&gt;")
	escaped = strings.ReplaceAll(escaped, "\n", "<br>\n")
	return "<html><body><div style=\"font-family:sans-serif;white-space:pre-wrap;\">" + escaped + "</div>" + pixels + "</body></html>"
}

// looksLikeHTML returns true if s appears to be HTML content.
func looksLikeHTML(s string) bool {
	lower := strings.ToLower(strings.TrimSpace(s))
	return strings.HasPrefix(lower, "<") ||
		strings.Contains(lower, "<html") ||
		strings.Contains(lower, "<div") ||
		strings.Contains(lower, "<p>")
}

// RewriteSubjectAndBody replaces Subject header and/or body in raw RFC 5322 data.
// If subject is non-empty, the Subject header is replaced.
// If body is non-empty, the body is replaced. Content-Type is set to text/html or text/plain based on content.
func RewriteSubjectAndBody(data []byte, subject, body string) []byte {
	if subject == "" && body == "" {
		return data
	}
	header, origBody, found := bytes.Cut(data, []byte("\r\n\r\n"))
	if !found {
		header, origBody, found = bytes.Cut(data, []byte("\n\n"))
		if !found {
			return data
		}
	}
	sep := "\r\n\r\n"
	if !bytes.Contains(data, []byte("\r\n\r\n")) {
		sep = "\n\n"
	}
	// Determine Content-Type: use text/html when body is HTML or when we'll wrap plain text for tracking
	pixels := extractTrackingPixels(origBody)
	useHTML := looksLikeHTML(body) || (body != "" && pixels != "")
	ct := "Content-Type: text/plain; charset=utf-8"
	if useHTML {
		ct = "Content-Type: text/html; charset=utf-8"
	}
	lines := strings.Split(strings.ReplaceAll(string(header), "\r\n", "\n"), "\n")
	var out []string
	skipUntilNextHeader := false
	replacedSubject := false
	for _, line := range lines {
		if line == "" {
			out = append(out, line)
			break
		}
		if skipUntilNextHeader {
			if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
				continue
			}
			skipUntilNextHeader = false
		}
		lower := strings.ToLower(strings.TrimSpace(line))
		if subject != "" && strings.HasPrefix(lower, "subject:") {
			out = append(out, "Subject: "+subject)
			skipUntilNextHeader = true
			replacedSubject = true
			continue
		}
		if body != "" && strings.HasPrefix(lower, "content-type:") {
			out = append(out, ct)
			skipUntilNextHeader = true
			continue
		}
		out = append(out, line)
	}
	if subject != "" && !replacedSubject {
		out = append([]string{"Subject: " + subject}, out...)
	}
	if body != "" {
		hasCT := false
		for _, l := range out {
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(l)), "content-type:") {
				hasCT = true
				break
			}
		}
		if !hasCT {
			var inserted []string
			for i, l := range out {
				if l == "" {
					inserted = append(inserted, ct, "")
					inserted = append(inserted, out[i+1:]...)
					break
				}
				inserted = append(inserted, l)
			}
			if len(inserted) > 0 {
				out = inserted
			}
		}
	}
	newBody := origBody
	if body != "" {
		finalBody := injectTrackingPixels(body, pixels)
		newBody = []byte(finalBody)
	}
	return []byte(strings.ReplaceAll(strings.Join(out, "\n"), "\n", "\r\n") + sep + string(newBody))
}

// RewriteFromHeader replaces the From header in raw RFC 5322 data with the given address.
func RewriteFromHeader(data []byte, fromAddr string) []byte {
	header, body, found := bytes.Cut(data, []byte("\r\n\r\n"))
	if !found {
		header, body, found = bytes.Cut(data, []byte("\n\n"))
		if !found {
			return data
		}
	}
	sep := "\r\n\r\n"
	if !bytes.Contains(data, []byte("\r\n\r\n")) {
		sep = "\n\n"
	}
	fromLine := "From: <" + fromAddr + ">"
	if strings.Contains(fromAddr, "<") {
		fromLine = "From: " + fromAddr
	}
	lines := strings.Split(strings.ReplaceAll(string(header), "\r\n", "\n"), "\n")
	var out []string
	skipUntilNextHeader := false
	replaced := false
	for _, line := range lines {
		if line == "" {
			out = append(out, line)
			break
		}
		if skipUntilNextHeader {
			if len(line) > 0 && (line[0] == ' ' || line[0] == '\t') {
				continue // skip folded continuation
			}
			skipUntilNextHeader = false
		}
		lower := strings.ToLower(strings.TrimSpace(line))
		if strings.HasPrefix(lower, "from:") {
			out = append(out, fromLine)
			skipUntilNextHeader = true
			replaced = true
			continue
		}
		out = append(out, line)
	}
	if !replaced {
		out = append([]string{fromLine}, out...)
	}
	return []byte(strings.ReplaceAll(strings.Join(out, "\n"), "\n", "\r\n") + sep + string(body))
}
