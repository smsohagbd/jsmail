package email

import (
	"bytes"
	"strings"
)

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
			// Replace Content-Type when we're replacing body
			ct := "Content-Type: text/plain; charset=utf-8"
			if looksLikeHTML(body) {
				ct = "Content-Type: text/html; charset=utf-8"
			}
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
		// Ensure Content-Type exists when replacing body (insert before blank line)
		hasCT := false
		for _, l := range out {
			if strings.HasPrefix(strings.ToLower(strings.TrimSpace(l)), "content-type:") {
				hasCT = true
				break
			}
		}
		if !hasCT {
			ct := "Content-Type: text/plain; charset=utf-8"
			if looksLikeHTML(body) {
				ct = "Content-Type: text/html; charset=utf-8"
			}
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
		newBody = []byte(body)
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
