package email

import (
	"bytes"
	"strings"
)

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
