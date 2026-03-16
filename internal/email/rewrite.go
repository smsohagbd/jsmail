package email

import (
	"bytes"
	"encoding/base64"
	"regexp"
	"strings"
)

// LinkMapping maps a destination URL to its Mautic tracking ID for link tracking preservation.
type LinkMapping struct {
	URL        string
	TrackingID string
}

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

// Mautic link tracking format (from Mautic docs and source):
//   https://{mautic-domain}/r/{redirect_id}?ct={base64_encoded_data}
// - redirect_id: 24 hex chars (Mautic page_redirects / MongoDB ObjectId)
// - ct: base64-encoded PHP serialized data (source, email_id, stat, lead_id, channel)
// - ct is per-contact per-send — never reuse across emails
// - /r/ is the only path Mautic uses for trackable email links
// - Other paths: /email/ (pixel, unsubscribe) — we do NOT match those
var mauticTrackingLinkPattern = regexp.MustCompile(`(?i)/r/([a-f0-9]{24})\?ct=([^"'\s&#]+)`)

// decodeBodyForSearch returns body content suitable for regex search.
// Handles: raw, quoted-printable (soft breaks removed), base64-encoded parts in multipart.
func decodeBodyForSearch(body []byte) []byte {
	body = removeQPSoftBreaks(body)
	decoded := decodeMultipartParts(body)
	if len(decoded) > 0 {
		return decoded
	}
	return body
}

// decodeMultipartParts parses multipart body and returns concatenated decoded text/html parts.
// Body may start with --boundary; we extract boundary from first line.
func decodeMultipartParts(body []byte) []byte {
	body = bytes.TrimLeft(body, "\r\n")
	if len(body) < 3 || !bytes.HasPrefix(body, []byte("--")) {
		return nil
	}
	// First line is --boundary, extract it
	lineEnd := bytes.Index(body, []byte("\r\n"))
	if lineEnd < 0 {
		lineEnd = bytes.Index(body, []byte("\n"))
	}
	if lineEnd < 0 {
		return nil
	}
	boundary := strings.TrimSpace(string(body[2:lineEnd]))
	boundary = strings.Trim(boundary, `"`)
	if boundary == "" {
		return nil
	}
	rest := body[lineEnd+2:]
	if bytes.HasPrefix(rest, []byte("\r\n")) {
		rest = rest[2:]
	} else if bytes.HasPrefix(rest, []byte("\n")) {
		rest = rest[1:]
	}
	sep := []byte("\r\n--" + boundary)
	if !bytes.Contains(rest, sep) {
		sep = []byte("\n--" + boundary)
	}
	parts := bytes.Split(rest, sep)
	var out []byte
	for _, part := range parts {
		if len(part) == 0 || bytes.HasPrefix(part, []byte("--")) {
			continue
		}
		pidx := bytes.Index(part, []byte("\r\n\r\n"))
		if pidx < 0 {
			pidx = bytes.Index(part, []byte("\n\n"))
		}
		if pidx < 0 {
			continue
		}
		pheader := bytes.ToLower(part[:pidx])
		pbody := bytes.TrimSpace(part[pidx+4:])
		pbody = bytes.TrimRight(pbody, "\r\n")
		if bytes.Contains(pheader, []byte("text/html")) || bytes.Contains(pheader, []byte("text/plain")) {
			if bytes.Contains(pheader, []byte("base64")) {
				decoded, err := base64.StdEncoding.DecodeString(string(pbody))
				if err == nil && len(decoded) > 0 {
					out = append(out, decoded...)
					out = append(out, '\n')
				}
			} else {
				out = append(out, pbody...)
				out = append(out, '\n')
			}
		}
	}
	if len(out) > 0 {
		return out
	}
	return nil
}

func extractFromBytes(body []byte) map[string]string {
	tidToFull := make(map[string]string)
	// Find href="...full tracking url..." - most reliable
	hrefPattern := regexp.MustCompile(`(?i)href\s*(?:=\s*|=3[Dd]\s*)["']([^"']*?/r/[a-f0-9]{24}\?ct=[^"'\s&#]+)["']`)
	hrefMatches := hrefPattern.FindAllSubmatch(body, -1)
	for _, m := range hrefMatches {
		if len(m) < 2 {
			continue
		}
		href := decodeQuotedPrintable(string(m[1]))
		if subm := mauticTrackingLinkPattern.FindStringSubmatch(href); len(subm) >= 3 {
			tid := strings.ToLower(subm[1])
			tidToFull[tid] = href
		}
	}
	// Fallback: find /r/ID?ct= in body and capture full URL
	if len(tidToFull) == 0 {
		fullPattern := regexp.MustCompile(`(https?://[^"'\s<>]*?/r/[a-f0-9]{24}\?ct=[^"'\s&#]+)`)
		matches := fullPattern.FindAll(body, -1)
		for _, m := range matches {
			s := decodeQuotedPrintable(string(m))
			if subm := mauticTrackingLinkPattern.FindStringSubmatch(s); len(subm) >= 3 {
				tid := strings.ToLower(subm[1])
				tidToFull[tid] = s
			}
		}
	}
	return tidToFull
}

// extractTrackingLinksFromOriginal finds all Mautic tracking links in origBody.
// Handles QP-encoded and base64-encoded multipart bodies.
func extractTrackingLinksFromOriginal(origBody []byte) map[string]string {
	body := decodeBodyForSearch(origBody)
	return extractFromBytes(body)
}

// applyLinkTrackingToBody replaces URLs in templateBody with Mautic tracking URLs.
// 1) Extract from current original only (full link with ct) — ct is per-contact, so we never use cache.
// 2) If original has no tracking links, use redirectBase fallback ({base}/r/{id} without ct).
func applyLinkTrackingToBody(templateBody string, origBody []byte, mappings []LinkMapping, redirectBase string) string {
	if len(mappings) == 0 {
		return templateBody
	}
	tidToFull := extractTrackingLinksFromOriginal(origBody)
	redirectBase = strings.TrimSuffix(strings.TrimSpace(redirectBase), "/")
	useRedirectFallback := redirectBase != ""
	if len(tidToFull) == 0 && !useRedirectFallback {
		return templateBody
	}
	type pair struct {
		from string
		to   string
	}
	var replacements []pair
	for _, m := range mappings {
		u := strings.TrimSpace(m.URL)
		if u == "" || m.TrackingID == "" {
			continue
		}
		tid := strings.ToLower(strings.TrimSpace(m.TrackingID))
		full, ok := tidToFull[tid]
		if !ok && useRedirectFallback {
			full = redirectBase + "/r/" + m.TrackingID
		}
		if full == "" {
			continue
		}
		replacements = append(replacements, pair{u, full})
		if !strings.HasSuffix(u, "/") {
			replacements = append(replacements, pair{u + "/", full})
		} else if len(u) > 1 {
			replacements = append(replacements, pair{strings.TrimSuffix(u, "/"), full})
		}
	}
	if len(replacements) == 0 {
		return templateBody
	}
	// Sort by from length descending
	for i := 0; i < len(replacements); i++ {
		for j := i + 1; j < len(replacements); j++ {
			if len(replacements[j].from) > len(replacements[i].from) {
				replacements[i], replacements[j] = replacements[j], replacements[i]
			}
		}
	}
	result := templateBody
	for _, r := range replacements {
		result = strings.ReplaceAll(result, r.from, r.to)
	}
	return result
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
// When body is replaced and linkMappings is non-empty, URLs are replaced with Mautic tracking URLs.
// Only from current original (ct is per-contact) or redirectBase fallback — no cache.
func RewriteSubjectAndBody(data []byte, subject, body string, linkMappings []LinkMapping, redirectBase string) []byte {
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
		// Apply link tracking: replace template URLs with Mautic tracking URLs
		if len(linkMappings) > 0 {
			body = applyLinkTrackingToBody(body, origBody, linkMappings, redirectBase)
		}
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
