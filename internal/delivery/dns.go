package delivery

import (
	"fmt"
	"net"
	"sort"
	"strings"
)

type mxRecord struct {
	Host string
	Pref uint16
}

// lookupMX returns MX records for the domain sorted by preference (lowest first).
// Falls back to a direct A record lookup if no MX records exist.
func lookupMX(domain string) ([]mxRecord, error) {
	mxs, err := net.LookupMX(domain)
	if err != nil {
		// If DNS lookup fails entirely, try delivering directly to the domain.
		return []mxRecord{{Host: domain, Pref: 0}}, nil
	}
	if len(mxs) == 0 {
		return []mxRecord{{Host: domain, Pref: 0}}, nil
	}

	records := make([]mxRecord, 0, len(mxs))
	for _, mx := range mxs {
		host := strings.TrimSuffix(mx.Host, ".")
		if host == "" {
			continue
		}
		records = append(records, mxRecord{Host: host, Pref: mx.Pref})
	}

	if len(records) == 0 {
		return nil, fmt.Errorf("no usable MX records for %s", domain)
	}

	sort.Slice(records, func(i, j int) bool {
		return records[i].Pref < records[j].Pref
	})
	return records, nil
}
