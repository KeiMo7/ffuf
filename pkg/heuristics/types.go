// Package heuristics implements multi-dimensional hit determination on top of
// ffuf's legacy status-code matcher.
//
// The legacy MatcherManager remains the single source of truth in the default
// mode: nothing in this package runs unless -heuristics is enabled. When it is,
// every response is evaluated against a baseline of known-nonexistent paths
// across four dimensions (status code, response length, response time, body
// similarity) and the verdict carries per-dimension evidence so a reviewer can
// see WHY each result was reported instead of only seeing a bare "found".
//
// Degradation is local and explicit:
//   - if baseline collection for a path-pattern group fails, that group falls
//     back to status-code-only decisions and the verdict is marked Degraded;
//   - if the similarity computation exceeds its budget, the similarity
//     dimension is skipped (evidence recorded with an error) rather than the
//     whole response being dropped.
//
// Response time is deliberately weak: network jitter makes it unusable on its
// own, so its weight is low and a timing-only deviation can never constitute a
// hit by itself.
package heuristics

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Dimension names. These are the stable identifiers used in evidence records,
// JSON output and evaluation reports — do not rename.
const (
	DimStatus     = "status"
	DimLength     = "length"
	DimTime       = "time"
	DimSimilarity = "similarity"
)

// GroupDefault is the baseline group used when no path-pattern specific group
// applies (paths without a recognized file extension).
const GroupDefault = "default"

// ErrSimilarityTimeout is returned by Similarity when the computation did not
// finish within its budget. Callers treat it as "skip this dimension", never as
// a hard failure of the whole verdict.
var ErrSimilarityTimeout = errors.New("similarity computation timed out")

// Config controls the heuristic decision engine. Zero values are filled with
// sane defaults by NewEngine.
type Config struct {
	// LengthRelThreshold is the minimum relative length difference
	// (|observed-baseline|/baseline) that makes the length dimension fire.
	LengthRelThreshold float64
	// LengthAbsFloor is an absolute byte margin below which a length difference
	// is ignored even if the relative threshold is exceeded; it keeps tiny
	// baseline bodies (a 10-byte soft-404 page) from producing noise.
	LengthAbsFloor int64
	// SimilarityThreshold: a body whose normalized similarity to the baseline
	// is at or below this value is considered different content.
	SimilarityThreshold float64
	// SimilarityTimeout bounds the work spent on a single similarity
	// computation. On timeout the dimension is skipped, not the response.
	SimilarityTimeout time.Duration
	// ShingleSize is the token window used for the Jaccard similarity.
	ShingleSize int
	// TimeRelThreshold is the minimum relative latency deviation from the
	// baseline median that makes the timing dimension fire.
	TimeRelThreshold float64
	// Weights per dimension. The timing weight should stay well below 1.
	Weights map[string]float64
	// ScoreThreshold is the weighted score at/above which a response is a hit
	// when no single dimension fires hard.
	ScoreThreshold float64
	// BaselineSamples is how many nonexistent-path probes are collected per
	// path-pattern group.
	BaselineSamples int
	// BaselineProbePrefix is prepended to random probe paths.
	BaselineProbePrefix string
}

// DefaultConfig returns the conservative default tuning. Every threshold here
// only takes effect when -heuristics is enabled; the default scan mode still
// uses pure status-code matching.
func DefaultConfig() Config {
	return Config{
		LengthRelThreshold:  0.15,
		LengthAbsFloor:      16,
		SimilarityThreshold: 0.85,
		SimilarityTimeout:   250 * time.Millisecond,
		ShingleSize:         3,
		TimeRelThreshold:    1.0, // observed latency must be >=2x baseline
		Weights: map[string]float64{
			DimStatus:     1.0,
			DimLength:     1.0,
			DimSimilarity: 1.0,
			DimTime:       0.3,
		},
		ScoreThreshold:      1.0,
		BaselineSamples:     3,
		BaselineProbePrefix: ".ffuf-nonexistent-",
	}
}

// Evidence is the per-dimension explanation attached to every verdict. It
// answers, for one dimension, "what did we measure, against what baseline, and
// did it fire?"
type Evidence struct {
	Dimension string  `json:"dimension"`
	Fired     bool    `json:"fired"`
	Score     float64 `json:"score"`
	Weight    float64 `json:"weight"`
	// Observed is the measured value of the response under test.
	Observed string `json:"observed"`
	// Baseline is the reference value(s) from the group's baseline probes.
	Baseline string `json:"baseline,omitempty"`
	// Reason is a human-readable explanation in the reviewer's language.
	Reason string `json:"reason"`
	// Skipped records that the dimension did not participate (e.g. similarity
	// timeout or missing baseline). A skipped dimension never fires.
	Skipped bool `json:"skipped,omitempty"`
}

// Verdict is the full, explainable decision for one response.
type Verdict struct {
	Hit          bool       `json:"hit"`
	Soft404      bool       `json:"soft404"`
	Suppressed   bool       `json:"suppressed"`
	Degraded     bool       `json:"degraded"`
	Group        string     `json:"group"`
	LegacyMatch  bool       `json:"legacy_match"`
	Reasons      []string   `json:"reasons"`
	Evidence     []Evidence `json:"evidence"`
	Score        float64    `json:"score"`
	BodyHash     string     `json:"body_hash"`
	SuppressorID string     `json:"suppressor_id,omitempty"`
	// thresholds carries the engine tuning the evidence methods read. It is
	// unexported so it is never serialized; one Verdict is always produced by one
	// Engine's Decide.
	thresholds Config
}

// BaselinePoint is one probe response retained for a path-pattern group.
type BaselinePoint struct {
	StatusCode    int64     `json:"status_code"`
	ContentLength int64     `json:"content_length"`
	ContentWords  int64     `json:"content_words"`
	ContentLines  int64     `json:"content_lines"`
	Duration      Duration  `json:"duration"`
	BodyHash      string    `json:"body_hash"`
	CollectedAt   time.Time `json:"collected_at"`
}

// BaselineGroup holds the reference responses for one path pattern. Groups are
// keyed by file extension (".php", ".bak", ...) plus the sentinel GroupDefault,
// because the same wordlist entry can behave completely differently under
// different extensions and one global baseline would misclassify them.
type BaselineGroup struct {
	Key      string          `json:"key"`
	Pattern  string          `json:"pattern"`
	Points   []BaselinePoint `json:"points"`
	Ready    bool            `json:"ready"`
	Degraded bool            `json:"degraded"`
	// Failure is recorded when collection failed and the group must fall back to
	// status-code-only decisions.
	Failure string `json:"failure,omitempty"`
}

// StatusSet returns the distinct status codes observed across baseline probes.
func (g *BaselineGroup) StatusSet() map[int64]bool {
	out := make(map[int64]bool)
	for _, p := range g.Points {
		out[p.StatusCode] = true
	}
	return out
}

// MedianLength is the median baseline ContentLength (0 for an empty group).
func (g *BaselineGroup) MedianLength() int64 {
	vals := make([]int64, 0, len(g.Points))
	for _, p := range g.Points {
		vals = append(vals, p.ContentLength)
	}
	sort.Slice(vals, func(i, j int) bool { return vals[i] < vals[j] })
	if len(vals) == 0 {
		return 0
	}
	return vals[len(vals)/2]
}

// MedianDuration is the median baseline response duration.
func (g *BaselineGroup) MedianDuration() time.Duration {
	vals := make([]time.Duration, 0, len(g.Points))
	for _, p := range g.Points {
		vals = append(vals, p.Duration.Duration)
	}
	sort.Slice(vals, func(i, j int) bool { return vals[i] < vals[j] })
	if len(vals) == 0 {
		return 0
	}
	return vals[len(vals)/2]
}

// DominantHash returns the most common body hash among baseline probes and how
// many probes share it. It is the basis for soft-404 detection: when all
// nonexistent-path probes return the same body, that body IS the soft-404
// template.
func (g *BaselineGroup) DominantHash() (string, int) {
	counts := make(map[string]int)
	for _, p := range g.Points {
		counts[p.BodyHash]++
	}
	var best string
	n := 0
	for h, c := range counts {
		if c > n {
			best, n = h, c
		}
	}
	return best, n
}

// Duration is a time.Duration that JSON-marshals as milliseconds, so evidence
// and checkpoint files stay human-readable.
type Duration struct {
	time.Duration
}

func (d Duration) MarshalJSON() ([]byte, error) {
	return []byte(fmt.Sprintf("%d", d.Milliseconds())), nil
}

// UnmarshalJSON accepts the millisecond integer written by MarshalJSON (and
// plain numbers), so checkpointed baselines round-trip.
func (d *Duration) UnmarshalJSON(data []byte) error {
	var ms int64
	if err := json.Unmarshal(data, &ms); err != nil {
		return err
	}
	d.Duration = time.Duration(ms) * time.Millisecond
	return nil
}

// stripTags removes HTML tags and script/style blocks before normalization.
// Token-level comparison is robust against tag soup differences; we only need
// the visible-text token stream.
var (
	scriptBlockRE = regexp.MustCompile(`(?is)<(script|style)[^>]*>.*?</(script|style)>`)
	tagRE         = regexp.MustCompile(`(?s)<[^>]*>`)
	spaceRE       = regexp.MustCompile(`\s+`)
)

// NormalizeBody turns a response body into the canonical token slice used for
// similarity comparison: scripts/styles and markup removed, whitespace
// collapsed, lowercased. Random tokens (CSRF nonces, timestamps) embedded in an
// otherwise identical page therefore only perturb a few shingles instead of
// making two soft-404 pages look wholly different.
func NormalizeBody(body []byte) []string {
	s := string(body)
	s = scriptBlockRE.ReplaceAllString(s, " ")
	s = tagRE.ReplaceAllString(s, " ")
	s = strings.ToLower(s)
	s = spaceRE.ReplaceAllString(s, " ")
	s = strings.TrimSpace(s)
	if s == "" {
		return []string{}
	}
	return strings.Split(s, " ")
}

// HashBody returns a stable short hash of the normalized token stream. Two
// responses whose visible text is identical get the same hash even if their
// raw byte lengths differ (e.g. varying header-less markup whitespace).
func HashBody(body []byte) string {
	tokens := NormalizeBody(body)
	sum := sha256.Sum256([]byte(strings.Join(tokens, " ")))
	return fmt.Sprintf("%x", sum[:12])
}

// shingleSet builds the set of k-token shingles for a token slice.
func shingleSet(tokens []string, k int) map[string]struct{} {
	set := make(map[string]struct{})
	if len(tokens) < k {
		// Short bodies: fall back to whole-text identity rather than producing
		// an empty set, which would make two empty pages "100% different".
		if len(tokens) > 0 {
			set[strings.Join(tokens, "|")] = struct{}{}
		}
		return set
	}
	for i := 0; i+k <= len(tokens); i++ {
		set[strings.Join(tokens[i:i+k], "|")] = struct{}{}
	}
	return set
}

// Similarity returns the Jaccard similarity (0..1) between two bodies over
// their normalized k-token shingle sets. It is bounded by ctx: exceeding the
// budget returns ErrSimilarityTimeout with whatever partial state exists, and
// the caller skips the dimension instead of dropping the response.
func Similarity(ctx context.Context, a, b []byte, k int) (float64, error) {
	tokA := NormalizeBody(a)
	tokB := NormalizeBody(b)
	if len(tokA) == 0 && len(tokB) == 0 {
		return 1.0, nil
	}
	setA := shingleSet(tokA, k)
	setB := shingleSet(tokB, k)
	if len(setA) == 0 || len(setB) == 0 {
		return 0.0, nil
	}
	intersection := 0
	// Iterate the smaller set for the intersection count, and bail out on
	// context cancellation between map accesses.
	small, large := setA, setB
	if len(setB) < len(setA) {
		small, large = setB, setA
	}
	for sh := range small {
		select {
		case <-ctx.Done():
			return 0, ErrSimilarityTimeout
		default:
		}
		if _, ok := large[sh]; ok {
			intersection++
		}
	}
	union := len(setA) + len(setB) - intersection
	if union == 0 {
		return 1.0, nil
	}
	return float64(intersection) / float64(union), nil
}
