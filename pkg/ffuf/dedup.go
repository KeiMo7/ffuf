package ffuf

import (
	"fmt"
	"strings"
)

// dedupFieldOrder is the canonical order in which fingerprint dimensions are
// written. ParseDedupFields always returns its result in this order, regardless
// of the order the fields were given on the command line.
var dedupFieldOrder = []string{"url", "status", "length", "words", "lines", "redirect", "content-type"}

// DefaultDedupFields is the fingerprint dimension set used when -dedup-fields is
// not given: the URL plus the four response-shape counters ffuf already prints.
var DefaultDedupFields = []string{"url", "status", "length", "words", "lines"}

// knownDedupField reports whether name is a valid fingerprint dimension.
func knownDedupField(name string) bool {
	for _, f := range dedupFieldOrder {
		if f == name {
			return true
		}
	}
	return false
}

// ParseDedupFields parses a comma-separated -dedup-fields value. It trims and
// lower-cases each entry, ignores empty entries, and returns the selected
// dimensions in canonical order. Duplicates collapse. The result must include
// "url", and every name must be one of url, status, length, words, lines,
// redirect or content-type; otherwise an error is returned.
func ParseDedupFields(spec string) ([]string, error) {
	seen := make(map[string]bool)
	for _, raw := range strings.Split(spec, ",") {
		name := strings.ToLower(strings.TrimSpace(raw))
		if name == "" {
			continue
		}
		if !knownDedupField(name) {
			return nil, fmt.Errorf("-dedup-fields: unknown field %q (valid: %s)", name, strings.Join(dedupFieldOrder, ", "))
		}
		seen[name] = true
	}
	if !seen["url"] {
		return nil, fmt.Errorf("-dedup-fields must include \"url\"")
	}
	out := make([]string, 0, len(seen))
	for _, name := range dedupFieldOrder {
		if seen[name] {
			out = append(out, name)
		}
	}
	return out, nil
}
