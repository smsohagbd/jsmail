package campaign

import (
	"encoding/base64"
	"net/http"
	"strings"

	appdb "smtp-server/internal/db"
)

// 1x1 transparent GIF for open tracking
var pixelGIF = []byte{
	0x47, 0x49, 0x46, 0x38, 0x39, 0x61, 0x01, 0x00, 0x01, 0x00, 0x80, 0x00, 0x00,
	0xff, 0xff, 0xff, 0x00, 0x00, 0x00, 0x21, 0xf9, 0x04, 0x01, 0x00, 0x00, 0x00,
	0x00, 0x2c, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x02, 0x02,
	0x44, 0x01, 0x00, 0x3b,
}

// HandleTrackOpen serves GET /t/o/{token} — 1x1 pixel for open tracking.
func HandleTrackOpen(w http.ResponseWriter, r *http.Request) {
	token := strings.TrimPrefix(r.URL.Path, "/t/o/")
	token = strings.TrimSuffix(token, "/")
	if token == "" {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	ip := r.RemoteAddr
	if i := strings.LastIndex(ip, ":"); i >= 0 {
		ip = ip[:i]
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.Index(xff, ","); i >= 0 {
			ip = strings.TrimSpace(xff[:i])
		} else {
			ip = strings.TrimSpace(xff)
		}
	}
	ua := r.Header.Get("User-Agent")
	appdb.RecordOpen(token, ip, ua)

	w.Header().Set("Content-Type", "image/gif")
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Write(pixelGIF)
}

// HandleTrackClick serves GET /t/c?t=TOKEN&u=BASE64URL — redirect to original URL after logging click.
func HandleTrackClick(w http.ResponseWriter, r *http.Request) {
	token := r.URL.Query().Get("t")
	b64 := r.URL.Query().Get("u")
	if token == "" || b64 == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	decoded, err := base64.URLEncoding.DecodeString(b64)
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	destURL := string(decoded)
	if destURL == "" || !strings.HasPrefix(destURL, "http") {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	ip := r.RemoteAddr
	if i := strings.LastIndex(ip, ":"); i >= 0 {
		ip = ip[:i]
	}
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		if i := strings.Index(xff, ","); i >= 0 {
			ip = strings.TrimSpace(xff[:i])
		} else {
			ip = strings.TrimSpace(xff)
		}
	}
	ua := r.Header.Get("User-Agent")
	appdb.RecordClick(token, destURL, ip, ua)

	http.Redirect(w, r, destURL, http.StatusFound)
}
