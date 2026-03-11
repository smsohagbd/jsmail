// Package cloudflare provides a minimal Cloudflare DNS API client for
// automatically pushing SPF, DKIM, MX, and DMARC records to a zone.
package cloudflare

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const apiBase = "https://api.cloudflare.com/client/v4"

// Client is a minimal Cloudflare API v4 client authenticated by a Bearer token.
type Client struct {
	token string
	http  *http.Client
}

// New creates a new Client using the provided API token.
func New(token string) *Client {
	return &Client{
		token: token,
		http:  &http.Client{Timeout: 30 * time.Second},
	}
}

// ─────────────────────────────── raw types ───────────────────────────────────

type cfResp struct {
	Success bool            `json:"success"`
	Errors  []cfErr         `json:"errors"`
	Result  json.RawMessage `json:"result"`
}

type cfErr struct {
	Code    int    `json:"code"`
	Message string `json:"message"`
}

// DNSRecord represents a Cloudflare DNS record (used for both read and write).
type DNSRecord struct {
	ID       string  `json:"id,omitempty"`
	Type     string  `json:"type"`
	Name     string  `json:"name"`
	Content  string  `json:"content"`
	TTL      int     `json:"ttl"`
	Priority *uint16 `json:"priority,omitempty"`
	Proxied  bool    `json:"proxied"`
}

// RecordResult is returned to the caller to show what happened per record.
type RecordResult struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Content string `json:"content"`
	Action  string `json:"action"` // "created" | "updated" | "skipped" | "error"
	Error   string `json:"error,omitempty"`
}

// ─────────────────────────────── Error classification ────────────────────────

// ErrCode describes why the Cloudflare request failed.
const (
	ErrCodeTimeout       = "TIMEOUT"
	ErrCodeNoConnection  = "NO_CONNECTION"
	ErrCodeDNS           = "DNS_FAILED"
	ErrCodeTLS           = "TLS_ERROR"
	ErrCodeAuth          = "AUTH_FAILED"
	ErrCodeForbidden     = "FORBIDDEN"
	ErrCodeRateLimit     = "RATE_LIMIT"
	ErrCodeNotFound      = "NOT_FOUND"
	ErrCodeCloudflare    = "CLOUDFLARE_API"
	ErrCodeUnknown       = "UNKNOWN"
)

// ClassifiedError holds a user-friendly error code and message.
type ClassifiedError struct {
	Code    string
	Message string
	Detail  string
}

func (e *ClassifiedError) Error() string {
	if e.Detail != "" {
		return fmt.Sprintf("[%s] %s — %s", e.Code, e.Message, e.Detail)
	}
	return fmt.Sprintf("[%s] %s", e.Code, e.Message)
}

// classifyError turns raw errors into user-friendly codes and messages.
func classifyError(err error) *ClassifiedError {
	if err == nil {
		return nil
	}
	detail := err.Error()

	// Timeout
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return &ClassifiedError{
			Code:    ErrCodeTimeout,
			Message: "Connection to Cloudflare timed out (30s)",
			Detail:  "Your server cannot reach api.cloudflare.com. Check firewall allows outbound HTTPS (port 443).",
		}
	}

	// Connection refused, no route, etc.
	if strings.Contains(detail, "connection refused") ||
		strings.Contains(detail, "connection reset") ||
		strings.Contains(detail, "no such host") ||
		strings.Contains(detail, "network is unreachable") {
		return &ClassifiedError{
			Code:    ErrCodeNoConnection,
			Message: "Cannot connect to Cloudflare API",
			Detail:  detail + " — Check firewall/DNS. Server must reach api.cloudflare.com:443.",
		}
	}

	// DNS
	if strings.Contains(detail, "no such host") || strings.Contains(detail, "Temporary failure in name resolution") {
		return &ClassifiedError{
			Code:    ErrCodeDNS,
			Message: "DNS lookup failed for api.cloudflare.com",
			Detail:  "Server cannot resolve Cloudflare. Check /etc/resolv.conf or network DNS.",
		}
	}

	// TLS
	if strings.Contains(detail, "x509") || strings.Contains(detail, "tls:") || strings.Contains(detail, "certificate") {
		return &ClassifiedError{
			Code:    ErrCodeTLS,
			Message: "TLS/SSL error connecting to Cloudflare",
			Detail:  detail,
		}
	}

	// Cloudflare API errors (from our do() - these come as "message (code N)")
	if strings.Contains(detail, "Invalid request") || strings.Contains(detail, "code 6003") {
		return &ClassifiedError{Code: ErrCodeAuth, Message: "Invalid API token", Detail: detail}
	}
	if strings.Contains(detail, "code 9103") || strings.Contains(detail, "Unknown X-Auth-Key") {
		return &ClassifiedError{Code: ErrCodeAuth, Message: "Invalid or expired API token", Detail: detail}
	}
	if strings.Contains(detail, "code 9109") || strings.Contains(detail, "Missing X-Auth") {
		return &ClassifiedError{Code: ErrCodeAuth, Message: "API token required", Detail: detail}
	}
	if strings.Contains(detail, "code 9100") || strings.Contains(detail, "Unknown X-Auth-Key") {
		return &ClassifiedError{Code: ErrCodeAuth, Message: "Invalid API token", Detail: detail}
	}
	if strings.Contains(detail, "code 9101") {
		return &ClassifiedError{Code: ErrCodeForbidden, Message: "Token lacks Zone:DNS:Edit permission", Detail: detail}
	}
	if strings.Contains(detail, "code 429") || strings.Contains(detail, "rate limit") {
		return &ClassifiedError{Code: ErrCodeRateLimit, Message: "Cloudflare rate limit exceeded", Detail: "Wait a few minutes and try again."}
	}
	if strings.Contains(detail, "code 404") || strings.Contains(detail, "not found") {
		return &ClassifiedError{Code: ErrCodeNotFound, Message: "Zone or record not found", Detail: detail}
	}

	// Generic
	return &ClassifiedError{Code: ErrCodeUnknown, Message: "Cloudflare request failed", Detail: detail}
}

// ─────────────────────────────── HTTP helpers ─────────────────────────────────

func (c *Client) do(method, path string, body interface{}) (*cfResp, error) {
	var bodyReader io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			return nil, err
		}
		bodyReader = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, apiBase+path, bodyReader)
	if err != nil {
		return nil, classifyError(err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		if ce := classifyError(err); ce != nil {
			return nil, ce
		}
		return nil, err
	}
	defer resp.Body.Close()

	bodyBytes, _ := io.ReadAll(resp.Body)
	var cfr cfResp
	if err := json.Unmarshal(bodyBytes, &cfr); err != nil {
		return nil, &ClassifiedError{Code: ErrCodeUnknown, Message: "Invalid response from Cloudflare", Detail: err.Error()}
	}

	if !cfr.Success {
		if len(cfr.Errors) > 0 {
			e := cfr.Errors[0]
			msg := e.Message
			// Map common Cloudflare error codes
			switch e.Code {
			case 6003:
				msg = "Invalid request — check API token"
			case 9100, 9103:
				msg = "Invalid or expired API token"
			case 9101:
				msg = "Token lacks Zone:DNS:Edit permission"
			case 9109:
				msg = "API token missing"
			case 1049:
				msg = "Rate limit exceeded — wait and retry"
			}
			return nil, &ClassifiedError{
				Code:    ErrCodeCloudflare,
				Message: msg,
				Detail:  fmt.Sprintf("Cloudflare error %d: %s", e.Code, e.Message),
			}
		}
		// Non-2xx without JSON errors
		if resp.StatusCode == 401 {
			return nil, &ClassifiedError{Code: ErrCodeAuth, Message: "Unauthorized — invalid API token", Detail: fmt.Sprintf("HTTP %d", resp.StatusCode)}
		}
		if resp.StatusCode == 403 {
			return nil, &ClassifiedError{Code: ErrCodeForbidden, Message: "Forbidden — token lacks permission", Detail: fmt.Sprintf("HTTP %d", resp.StatusCode)}
		}
		if resp.StatusCode == 429 {
			return nil, &ClassifiedError{Code: ErrCodeRateLimit, Message: "Rate limit exceeded", Detail: fmt.Sprintf("HTTP %d", resp.StatusCode)}
		}
		return nil, &ClassifiedError{Code: ErrCodeCloudflare, Message: "Cloudflare API error", Detail: fmt.Sprintf("HTTP %d: %s", resp.StatusCode, string(bodyBytes))}
	}
	return &cfr, nil
}

// ─────────────────────────────── Zone lookup ─────────────────────────────────

// FindZoneID returns the Cloudflare zone ID for a domain. It tries progressively
// shorter domain names (e.g. sub.example.com → example.com) until it finds the zone.
func (c *Client) FindZoneID(domain string) (string, error) {
	parts := strings.Split(strings.ToLower(domain), ".")
	for i := 0; i < len(parts)-1; i++ {
		candidate := strings.Join(parts[i:], ".")
		r, err := c.do("GET", "/zones?name="+url.QueryEscape(candidate)+"&status=active&per_page=1", nil)
		if err != nil {
			continue
		}
		var zones []struct {
			ID string `json:"id"`
		}
		if err := json.Unmarshal(r.Result, &zones); err == nil && len(zones) > 0 {
			return zones[0].ID, nil
		}
	}
	return "", fmt.Errorf("no active Cloudflare zone found for %q — make sure the domain is in your Cloudflare account", domain)
}

// ────────────────────────────── DNS record CRUD ───────────────────────────────

// ListDNSRecords returns all records of the given type with the given name in a zone.
func (c *Client) ListDNSRecords(zoneID, recType, name string) ([]DNSRecord, error) {
	path := fmt.Sprintf("/zones/%s/dns_records?type=%s&name=%s",
		zoneID, url.QueryEscape(recType), url.QueryEscape(name))
	r, err := c.do("GET", path, nil)
	if err != nil {
		return nil, err
	}
	var records []DNSRecord
	json.Unmarshal(r.Result, &records)
	return records, nil
}

// ListAllTXTRecords returns all TXT records in a zone (no name filter).
func (c *Client) ListAllTXTRecords(zoneID string) ([]DNSRecord, error) {
	path := fmt.Sprintf("/zones/%s/dns_records?type=TXT&per_page=100", zoneID)
	r, err := c.do("GET", path, nil)
	if err != nil {
		return nil, err
	}
	var records []DNSRecord
	json.Unmarshal(r.Result, &records)
	return records, nil
}

// nameMatchesApex returns true if the record name is the zone apex (root).
func nameMatchesApex(recordName, domain string) bool {
	n := strings.TrimSuffix(strings.ToLower(recordName), ".")
	d := strings.ToLower(domain)
	return n == d || n == "" || n == "@"
}

// CreateDNSRecord adds a new DNS record to a zone.
func (c *Client) CreateDNSRecord(zoneID string, rec DNSRecord) error {
	_, err := c.do("POST", "/zones/"+zoneID+"/dns_records", rec)
	return err
}

// UpdateDNSRecord overwrites an existing DNS record by ID.
func (c *Client) UpdateDNSRecord(zoneID, recordID string, rec DNSRecord) error {
	_, err := c.do("PUT", "/zones/"+zoneID+"/dns_records/"+recordID, rec)
	return err
}

// DeleteDNSRecord removes a DNS record by ID.
func (c *Client) DeleteDNSRecord(zoneID, recordID string) error {
	_, err := c.do("DELETE", "/zones/"+zoneID+"/dns_records/"+recordID, nil)
	return err
}

// ─────────────────────────── TXT content formatting ────────────────────────────

// quoteTXTContent wraps TXT content in double quotes for Cloudflare API.
// Cloudflare requires TXT record content to be in quotation marks.
func quoteTXTContent(s string) string {
	s = strings.TrimSpace(s)
	if s == "" {
		return `""`
	}
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s
	}
	return `"` + s + `"`
}

// unquoteTXTContent strips surrounding quotes for comparison (Cloudflare may return quoted).
func unquoteTXTContent(s string) string {
	s = strings.TrimSpace(s)
	if len(s) >= 2 && s[0] == '"' && s[len(s)-1] == '"' {
		return s[1 : len(s)-1]
	}
	return s
}

// ─────────────────────────── SPF merge helper ────────────────────────────────

// MergeSPF returns an SPF record string that includes the given include host.
// If existing is empty a fresh record is created.
// If include is already present the existing record is returned unchanged.
// Otherwise the include is inserted before the terminating "all" mechanism.
func MergeSPF(existing, includeHost string) string {
	include := "include:" + includeHost
	if existing == "" {
		return "v=spf1 " + include + " ~all"
	}
	if strings.Contains(existing, include) {
		return existing // already present
	}
	for _, qualifier := range []string{"~all", "-all", "+all", "?all"} {
		if idx := strings.LastIndex(existing, qualifier); idx >= 0 {
			return existing[:idx] + include + " " + existing[idx:]
		}
	}
	return strings.TrimRight(existing, " ") + " " + include + " ~all"
}

// ──────────────────────────── Push all records ────────────────────────────────

// PushOptions controls what gets written when PushDNS is called.
type PushOptions struct {
	Domain      string // sending domain e.g. "example.com"
	DKIMName    string // e.g. "sm._domainkey.example.com"
	DKIMContent string // full DKIM TXT value "v=DKIM1; k=rsa; p=…"
	SPFInclude  string // hostname to include, e.g. "spf.server.feddatabase.com"
	MXTarget    string // server hostname for MX record
	MXPriority  uint16
}

// PushDNS pushes SPF, DKIM, MX, and DMARC records to the Cloudflare zone.
// It returns a slice of RecordResult describing what was done for each record.
func (c *Client) PushDNS(opts PushOptions) ([]RecordResult, error) {
	zoneID, err := c.FindZoneID(opts.Domain)
	if err != nil {
		return nil, err
	}

	var results []RecordResult

	// ── DKIM ─────────────────────────────────────────────────────────────────
	results = append(results, c.upsertTXT(zoneID, opts.DKIMName, opts.DKIMContent))

	// ── SPF ──────────────────────────────────────────────────────────────────
	// Find ANY existing TXT record at the zone apex that starts with v=spf1.
	// Prefer the one that doesn't already have our include (the "original" to merge into).
	// Update that record (merge our include). Never create a second SPF record.
	{
		allTXT, _ := c.ListAllTXTRecords(zoneID)
		var spfRecord *DNSRecord
		var fallback *DNSRecord
		ourInclude := "include:" + opts.SPFInclude
		for i := range allTXT {
			if !nameMatchesApex(allTXT[i].Name, opts.Domain) {
				continue
			}
			raw := unquoteTXTContent(allTXT[i].Content)
			if !strings.HasPrefix(strings.ToLower(raw), "v=spf1") {
				continue
			}
			if !strings.Contains(raw, ourInclude) {
				spfRecord = &allTXT[i]
				break
			}
			fallback = &allTXT[i]
		}
		if spfRecord == nil && fallback != nil {
			spfRecord = fallback
		}
		merged := MergeSPF("", opts.SPFInclude)
		if spfRecord != nil {
			merged = MergeSPF(unquoteTXTContent(spfRecord.Content), opts.SPFInclude)
		}
		if spfRecord != nil && unquoteTXTContent(spfRecord.Content) == merged {
			results = append(results, RecordResult{Type: "TXT (SPF)", Name: opts.Domain, Content: merged, Action: "skipped"})
		} else if spfRecord != nil {
			// Update existing SPF — use original record name (e.g. gettonstrategy.com or @)
			err := c.UpdateDNSRecord(zoneID, spfRecord.ID, DNSRecord{
				Type: "TXT", Name: spfRecord.Name, Content: quoteTXTContent(merged), TTL: 300,
			})
			action := "updated"
			errStr := ""
			if err != nil {
				action = "error"
				errStr = err.Error()
			}
			results = append(results, RecordResult{Type: "TXT (SPF)", Name: opts.Domain, Content: merged, Action: action, Error: errStr})
			// Remove any duplicate SPF we may have created earlier (standalone with only our include)
			standalone := "v=spf1 include:" + opts.SPFInclude + " ~all"
			for i := range allTXT {
				if allTXT[i].ID == spfRecord.ID {
					continue
				}
				if !nameMatchesApex(allTXT[i].Name, opts.Domain) {
					continue
				}
				raw := unquoteTXTContent(allTXT[i].Content)
				if strings.HasPrefix(strings.ToLower(raw), "v=spf1") && raw == standalone {
					_ = c.DeleteDNSRecord(zoneID, allTXT[i].ID)
					break
				}
			}
		} else {
			err := c.CreateDNSRecord(zoneID, DNSRecord{
				Type: "TXT", Name: opts.Domain, Content: quoteTXTContent(merged), TTL: 300,
			})
			action := "created"
			errStr := ""
			if err != nil {
				action = "error"
				errStr = err.Error()
			}
			results = append(results, RecordResult{Type: "TXT (SPF)", Name: opts.Domain, Content: merged, Action: action, Error: errStr})
		}
	}

	// ── MX — only add if none exists ─────────────────────────────────────────
	{
		existing, _ := c.ListDNSRecords(zoneID, "MX", opts.Domain)
		if len(existing) > 0 {
			results = append(results, RecordResult{Type: "MX", Name: opts.Domain,
				Content: fmt.Sprintf("(kept existing: %s)", existing[0].Content),
				Action:  "skipped"})
		} else {
			prio := opts.MXPriority
			err := c.CreateDNSRecord(zoneID, DNSRecord{
				Type: "MX", Name: opts.Domain, Content: opts.MXTarget, TTL: 300, Priority: &prio,
			})
			action := "created"
			errStr := ""
			if err != nil {
				action = "error"
				errStr = err.Error()
			}
			results = append(results, RecordResult{Type: "MX", Name: opts.Domain,
				Content: fmt.Sprintf("%d %s", prio, opts.MXTarget), Action: action, Error: errStr})
		}
	}

	// ── DMARC — always overwrite ──────────────────────────────────────────────
	dmarcName := "_dmarc." + opts.Domain
	dmarcContent := fmt.Sprintf("v=DMARC1; p=none; rua=mailto:dmarc@%s; pct=100", opts.Domain)
	results = append(results, c.upsertTXT(zoneID, dmarcName, dmarcContent))

	return results, nil
}

// upsertTXT creates or updates a TXT record (always overwrites the value).
// Content is sent to Cloudflare with quotation marks as required for TXT records.
func (c *Client) upsertTXT(zoneID, name, content string) RecordResult {
	existing, _ := c.ListDNSRecords(zoneID, "TXT", name)
	quoted := quoteTXTContent(content)
	rec := DNSRecord{Type: "TXT", Name: name, Content: quoted, TTL: 300}

	if len(existing) > 0 {
		if unquoteTXTContent(existing[0].Content) == content {
			return RecordResult{Type: "TXT", Name: name, Content: content, Action: "skipped"}
		}
		err := c.UpdateDNSRecord(zoneID, existing[0].ID, rec)
		if err != nil {
			return RecordResult{Type: "TXT", Name: name, Content: content, Action: "error", Error: err.Error()}
		}
		return RecordResult{Type: "TXT", Name: name, Content: content, Action: "updated"}
	}

	err := c.CreateDNSRecord(zoneID, rec)
	if err != nil {
		return RecordResult{Type: "TXT", Name: name, Content: content, Action: "error", Error: err.Error()}
	}
	return RecordResult{Type: "TXT", Name: name, Content: content, Action: "created"}
}
