// Package fingerprint computes bounded-memory response-body fingerprints for
// de-duplicating scan results.
package fingerprint

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"regexp"
	"strings"
)

const (
	// Algorithm identifies the fingerprint construction. Bump it whenever the
	// normalized byte stream fed to SHA-256 changes.
	Algorithm = "ffuf-dedup-sha256-v1"

	// DefaultThreshold is the largest body portion kept for exact normalization.
	// Bodies above it are fingerprinted from deterministic head/tail samples.
	DefaultThreshold = 64 * 1024

	// DefaultMaxEntries bounds the unique fingerprints tracked by one scan.
	DefaultMaxEntries = 100000
)

const (
	SourceComputed    = "computed"
	SourceReused      = "reused"
	SourceUnavailable = "unavailable"
)

// Result describes the fingerprint outcome for one response. Valid=false and
// Empty=true are deliberately distinct: an empty body has a real hash, while an
// unreadable body must never participate in folding.
type Result struct {
	Valid   bool
	Empty   bool
	Digest  string
	Source  string
	Sampled bool
	Error   string
}

// Rule is one configured volatile-field expression.
type Rule struct {
	Pattern string
	Regexp  *regexp.Regexp
	Line    int
	Column  int
}

// Rules is an ordered volatile-field normalizer.
type Rules struct {
	Items  []Rule
	Hash   string
	Source string
}

// EmptyRules returns a normalizer that hashes the body verbatim.
func EmptyRules() *Rules {
	return &Rules{Items: []Rule{}, Hash: hashPatterns(nil), Source: "(none)"}
}

// LoadRules reads one Go regular expression per line. Blank lines and lines
// whose first non-space byte is '#' are ignored.
func LoadRules(path string) (*Rules, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("dedup rules %q: %w", path, err)
	}
	return ParseRules(path, data)
}

// ParseRules compiles a rules document and reports the exact line and starting
// column of an invalid expression.
func ParseRules(name string, data []byte) (*Rules, error) {
	rules := &Rules{Items: make([]Rule, 0), Source: name}
	patterns := make([]string, 0)
	lines := strings.Split(string(data), "\n")
	for i, raw := range lines {
		trimmed := strings.TrimSpace(strings.TrimSuffix(raw, "\r"))
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		column := strings.Index(raw, trimmed) + 1
		if column < 1 {
			column = 1
		}
		re, err := regexp.Compile(trimmed)
		if err != nil {
			return nil, fmt.Errorf("%s:%d:%d: invalid ignore regex %q: %w", name, i+1, column, trimmed, err)
		}
		rules.Items = append(rules.Items, Rule{
			Pattern: trimmed,
			Regexp:  re,
			Line:    i + 1,
			Column:  column,
		})
		patterns = append(patterns, trimmed)
	}
	rules.Hash = hashPatterns(patterns)
	return rules, nil
}

func hashPatterns(patterns []string) string {
	h := sha256.New()
	h.Write([]byte(Algorithm))
	for _, pattern := range patterns {
		fmt.Fprintf(h, "\n%d:", len(pattern))
		h.Write([]byte(pattern))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// Normalize replaces every configured volatile field with a stable marker.
// Rules are applied in file order so overlapping expressions are deterministic.
func (r *Rules) Normalize(body []byte) []byte {
	if r == nil || len(r.Items) == 0 || len(body) == 0 {
		return body
	}
	out := body
	for i, rule := range r.Items {
		out = rule.Regexp.ReplaceAll(out, []byte(fmt.Sprintf("[ffuf-volatile:%d]", i)))
	}
	return out
}

// Stream consumes a body incrementally. At most roughly Threshold+one write
// chunk is retained, regardless of the response size.
type Stream struct {
	rules     *Rules
	threshold int
	sample    int

	total   int64
	small   []byte
	head    []byte
	ring    []byte
	ringPos int
	ringLen int
	sampled bool
	closed  bool
	out     Result
}

// NewStream creates an accumulator. Non-positive thresholds select the default.
func NewStream(rules *Rules, threshold int) *Stream {
	if rules == nil {
		rules = EmptyRules()
	}
	if threshold <= 0 {
		threshold = DefaultThreshold
	}
	sample := threshold / 2
	if sample < 1 {
		sample = 1
	}
	return &Stream{rules: rules, threshold: threshold, sample: sample}
}

// Write implements io.Writer. It never retains the complete body once the
// threshold is crossed.
func (s *Stream) Write(p []byte) (int, error) {
	if s.closed {
		return 0, fmt.Errorf("fingerprint stream is already closed")
	}
	if len(p) == 0 {
		return 0, nil
	}
	s.total += int64(len(p))
	if !s.sampled {
		if len(s.small)+len(p) <= s.threshold {
			s.small = append(s.small, p...)
			return len(p), nil
		}
		combined := make([]byte, 0, len(s.small)+len(p))
		combined = append(combined, s.small...)
		combined = append(combined, p...)
		s.head = append([]byte(nil), combined[:s.sample]...)
		s.ring = make([]byte, s.sample)
		s.appendRing(combined[len(combined)-s.sample:])
		s.small = nil
		s.sampled = true
		return len(p), nil
	}
	s.appendRing(p)
	return len(p), nil
}

func (s *Stream) appendRing(p []byte) {
	for _, b := range p {
		s.ring[s.ringPos] = b
		s.ringPos = (s.ringPos + 1) % len(s.ring)
		if s.ringLen < len(s.ring) {
			s.ringLen++
		}
	}
}

func (s *Stream) tail() []byte {
	if s.ringLen == 0 {
		return nil
	}
	if s.ringLen < len(s.ring) {
		return append([]byte(nil), s.ring[:s.ringLen]...)
	}
	out := make([]byte, 0, len(s.ring))
	out = append(out, s.ring[s.ringPos:]...)
	out = append(out, s.ring[:s.ringPos]...)
	return out
}

// Finish returns the result exactly once.
func (s *Stream) Finish() Result {
	if s.closed {
		return s.out
	}
	s.closed = true

	h := sha256.New()
	fmt.Fprintf(h, "%s\nrules=%s\nthreshold=%d\nlength=%d\n", Algorithm, s.rules.Hash, s.threshold, s.total)
	if s.sampled {
		head := s.rules.Normalize(s.head)
		tail := s.rules.Normalize(s.tail())
		h.Write([]byte("sample\nhead:"))
		h.Write(head)
		h.Write([]byte("\ntail:"))
		h.Write(tail)
	} else {
		body := s.rules.Normalize(s.small)
		h.Write([]byte("full\nbody:"))
		h.Write(body)
	}
	s.out = Result{
		Valid:   true,
		Empty:   s.total == 0,
		Digest:  hex.EncodeToString(h.Sum(nil)),
		Source:  SourceComputed,
		Sampled: s.sampled,
	}
	return s.out
}

// RetainedBytes reports the current fingerprint buffer size. It is exposed so
// tests can assert that large bodies stay bounded.
func (s *Stream) RetainedBytes() int {
	return len(s.small) + len(s.head) + len(s.ring)
}
