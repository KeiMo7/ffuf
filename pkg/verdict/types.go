// Package verdict implements the attributed decision layer: every response is
// classified with a conclusion (keep / drop / undecidable) AND an attribution
// naming the rule that decided it, its raw definition and the actual values that
// participated in the evaluation. It is strictly opt-in: unless the user supplies
// an ordered rule set, the engine keeps using the legacy filter.MatcherManager
// boolean path and observable behavior is byte-for-byte unchanged.
//
// The package deliberately depends only on pkg/ffuf (the shared data types), so
// it can be imported by the engine without an import cycle.
package verdict

import (
	"fmt"
	"time"

	"github.com/ffuf/ffuf/v2/pkg/ffuf"
)

// Outcome is the three-valued conclusion of evaluating a single rule, a rule
// group, or a whole response.
type Outcome string

const (
	// OutcomeKeep means the response passed the rule set and is emitted as a
	// result.
	OutcomeKeep Outcome = "keep"
	// OutcomeDrop means the response was discarded by a decisive filter rule.
	OutcomeDrop Outcome = "drop"
	// OutcomeUndecidable means no rule could reach a firm conclusion: every
	// rule that could have decided the response was itself unable to evaluate
	// (missing comparable value, negative value, truncated body, evaluation
	// error or timeout). It is never silently treated as "not matched".
	OutcomeUndecidable Outcome = "undecidable"
)

// Side identifies which rule family a trace or decision belongs to.
type Side string

const (
	SideMatcher Side = "matcher"
	SideFilter  Side = "filter"
)

// Combine is the set operator used within one rule family.
type Combine string

const (
	// CombineAny ("or"): the first satisfied rule terminates evaluation.
	CombineAny Combine = "or"
	// CombineAll ("and"): every rule must be satisfied; the first failure
	// terminates evaluation.
	CombineAll Combine = "all"
)

// RuleTrace is the per-rule evaluation record. One is produced for every rule
// that was actually evaluated, in declaration order, so the trace doubles as
// proof of which short-circuit branches were never taken.
type RuleTrace struct {
	// RuleID is the stable identifier of the rule within the loaded rule set.
	RuleID string `json:"rule_id"`
	// Side is "matcher" or "filter".
	Side Side `json:"side"`
	// Kind is the rule type (status/size/word/line/regexp/time).
	Kind string `json:"kind"`
	// Raw is the rule's verbatim declaration (e.g. "status:200-299").
	Raw string `json:"raw"`
	// Order is the rule's zero-based position within its side, after priority
	// sorting. It makes the evaluation order explicit in the recorded trace.
	Order int `json:"order"`
	// Result is the rule's three-valued result: true / false / undecidable.
	// A nil pointer means the rule was never evaluated (a preceding rule
	// short-circuited the group), so no trace entry is emitted for it at all.
	Result *bool `json:"result,omitempty"`
	// Undecidable is set instead of Result when the rule could not evaluate.
	Undecidable bool `json:"undecidable,omitempty"`
	// Reason explains why a rule was undecidable or why evaluation errored.
	Reason string `json:"reason,omitempty"`
	// ActualValues holds the response-derived values the rule compared
	// against, keyed by value name (e.g. "status_code", "content_length").
	ActualValues map[string]string `json:"actual_values,omitempty"`
	// Duration is how long the rule evaluation took.
	Duration time.Duration `json:"duration_ns,omitempty"`
}

// Decision is the full "conclusion + attribution" for one response.
type Decision struct {
	// Outcome is the final conclusion.
	Outcome Outcome `json:"outcome"`
	// BlockedSide names the side that blocked the response: "matcher" when
	// the matchers failed/undecided, "filter" when a filter dropped it. Empty
	// for a kept response.
	BlockedSide Side `json:"blocked_side,omitempty"`
	// DecisiveRule points at the single rule whose result determined the
	// outcome. Nil when the outcome is undecidable with no decisive rule.
	DecisiveRule *RuleTrace `json:"decisive_rule,omitempty"`
	// Traces is the ordered, complete record of every rule that was
	// evaluated (matchers first, then filters when the matchers passed).
	Traces []RuleTrace `json:"traces"`
	// UndecidableCount is the number of evaluated rules that returned
	// undecidable, surfaced separately so callers don't rescan Traces.
	UndecidableCount int `json:"undecidable_count"`
	// EvaluatedAt is the wall-clock time the decision was produced.
	EvaluatedAt time.Time `json:"evaluated_at"`
}

// Kept reports whether the engine should emit the response as a result. An
// undecidable response is kept only when the caller's policy says so; this
// method only encodes the verdict itself.
func (d *Decision) Kept(keepUndecidable bool) bool {
	switch d.Outcome {
	case OutcomeKeep:
		return true
	case OutcomeUndecidable:
		return keepUndecidable
	default:
		return false
	}
}

// formatRequestID renders the engine position alongside the URL. Position alone
// is unique within one run but opaque, so the URL is kept for human review.
func formatRequestID(position int, url string) string {
	return fmt.Sprintf("#%d %s", position, url)
}

// RequestID derives a stable identifier for a response's request for the review
// records. It uses the engine's per-request position when available and falls
// back to the URL.
func RequestID(resp *ffuf.Response) string {
	if resp != nil && resp.Request != nil {
		if resp.Request.Position > 0 {
			return formatRequestID(resp.Request.Position, resp.Request.Url)
		}
		return resp.Request.Url
	}
	return ""
}
