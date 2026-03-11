// Package cloudflare provides a minimal Cloudflare DNS API client for
// automatically pushing SPF, DKIM, MX, and DMARC records to a zone.
package cloudflare

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
)

const apiBase = "https://api.cloudflare.com/client/v4"

// Client is a minimal Cloudflare API v4 client authenticated by a Bearer token.
type Client struct {
	token string
	http  *http.Client
}

// New creates a new Client using the provided API token.
func New(token string) *Client {
	return &Client{token: token, http: &http.Client{}}
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
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("http: %w", err)
	}
	defer resp.Body.Close()

	var cfr cfResp
	if err := json.NewDecoder(resp.Body).Decode(&cfr); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	if !cfr.Success {
		if len(cfr.Errors) > 0 {
			return nil, fmt.Errorf("%s (code %d)", cfr.Errors[0].Message, cfr.Errors[0].Code)
		}
		return nil, fmt.Errorf("cloudflare: unknown error")
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
	{
		existing, _ := c.ListDNSRecords(zoneID, "TXT", opts.Domain)
		var spfRecord *DNSRecord
		for i := range existing {
			if strings.HasPrefix(strings.ToLower(existing[i].Content), "v=spf1") {
				spfRecord = &existing[i]
				break
			}
		}
		merged := MergeSPF("", opts.SPFInclude)
		if spfRecord != nil {
			merged = MergeSPF(spfRecord.Content, opts.SPFInclude)
		}
		if spfRecord != nil && spfRecord.Content == merged {
			results = append(results, RecordResult{Type: "TXT (SPF)", Name: opts.Domain, Content: merged, Action: "skipped"})
		} else if spfRecord != nil {
			err := c.UpdateDNSRecord(zoneID, spfRecord.ID, DNSRecord{
				Type: "TXT", Name: opts.Domain, Content: merged, TTL: 300,
			})
			action := "updated"
			errStr := ""
			if err != nil {
				action = "error"
				errStr = err.Error()
			}
			results = append(results, RecordResult{Type: "TXT (SPF)", Name: opts.Domain, Content: merged, Action: action, Error: errStr})
		} else {
			err := c.CreateDNSRecord(zoneID, DNSRecord{
				Type: "TXT", Name: opts.Domain, Content: merged, TTL: 300,
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
func (c *Client) upsertTXT(zoneID, name, content string) RecordResult {
	existing, _ := c.ListDNSRecords(zoneID, "TXT", name)

	rec := DNSRecord{Type: "TXT", Name: name, Content: content, TTL: 300}

	if len(existing) > 0 {
		if existing[0].Content == content {
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
