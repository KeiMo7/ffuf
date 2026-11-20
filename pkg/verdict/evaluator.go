package verdict

import (
	"fmt"
	"time"

	"github.com/ffuf/ffuf/v2/pkg/ffuf"
)

// Evaluator evaluates responses against immutable rule snapshots. It holds no
// per-response state, so a single Evaluator is shared by every worker.
type Evaluator struct {
	// Timeout, when > 0, bounds each individual rule evaluation. A rule that
	// exceeds it is recorded as undecidable and the remaining rules proceed.
	// Zero (the default) means no timeout and no extra goroutine per rule.
	Timeout time.Duration
}

// NewEvaluator returns an Evaluator with per-rule timeouts disabled.
func NewEvaluator() *Evaluator { return &Evaluator{} }

// triState is a rule's three-valued result.
type triState int

const (
	tsFalse triState = iota
	tsTrue
	tsUndecidable
)

// Evaluate produces the full attributed Decision for resp under snap. The
// semantics:
//
// Matchers are evaluated first. Filters are never touched when the matcher side
// does not produce a firm "matched" conclusion, and the trace shows which side
// blocked the response.
//
// Any-match ("or"): the first satisfied rule terminates the group; later rules
// are not evaluated (and absent from the trace). All-match ("all"): the first
// firm failure terminates; an undecidable rule does not terminate by itself —
// evaluation continues so a later firm result can still decide the group.
func (e *Evaluator) Evaluate(resp *ffuf.Response, snap *Snapshot) *Decision {
	dec := &Decision{Outcome: OutcomeUndecidable, EvaluatedAt: time.Now()}

	matcherState, decisive := e.evaluateSide(resp, asEvaluables(snap.Matchers), snap.MatcherOp, dec)
	if matcherState != tsTrue {
		// The matcher side did not produce a firm match. Filters do not
		// participate (spec: 命中不成立则过滤不参与).
		dec.BlockedSide = SideMatcher
		if matcherState == tsFalse {
			dec.Outcome = OutcomeDrop
			// decisive is nil when an OR group's rules all returned
			// undecidable; the last trace still explains why in that case.
			dec.DecisiveRule = decisive
		} else {
			dec.Outcome = OutcomeUndecidable
		}
		return dec
	}

	filterState, fdecisive := e.evaluateSide(resp, asEvaluables(snap.Filters), snap.FilterOp, dec)
	if len(snap.Filters) == 0 {
		// No filters configured: the matcher's firm match stands, and the
		// decisive matcher rule is the attribution. Must not fall through to
		// the undecidable default below.
		dec.Outcome = OutcomeKeep
		dec.DecisiveRule = decisive
		return dec
	}
	switch filterState {
	case tsTrue:
		// A filter matched, i.e. the filter side decided to discard the
		// response. In "all" mode this means every filter was satisfied; in
		// "or" mode the first satisfied filter terminated and is decisive.
		dec.Outcome = OutcomeDrop
		dec.BlockedSide = SideFilter
		dec.DecisiveRule = fdecisive
	case tsFalse:
		// A filter firmly did not match: in "all" mode that already
		// short-circuited (not all filters can hold), and in "or" mode every
		// filter was evaluated and none matched. Either way the response is
		// kept.
		dec.Outcome = OutcomeKeep
		dec.DecisiveRule = fdecisive
	default:
		// The filter side could not reach a firm conclusion. Keep the matcher's
		// firm match but mark the whole response undecidable rather than
		// silently guessing a filter result.
		dec.Outcome = OutcomeUndecidable
		dec.BlockedSide = SideFilter
	}
	return dec
}

// EvaluateRules is Evaluate with explicit rule slices instead of a Snapshot.
// Production code uses Evaluate; tests use this to inject counting or
// panic/timeout stubs without rebuilding a RuleBook.
func (e *Evaluator) EvaluateRules(resp *ffuf.Response, matcherOp, filterOp Combine, matchers, filters []evaluable) *Decision {
	dec := &Decision{Outcome: OutcomeUndecidable, EvaluatedAt: time.Now()}

	matcherState, decisive := e.evaluateSide(resp, matchers, matcherOp, dec)
	if matcherState != tsTrue {
		dec.BlockedSide = SideMatcher
		if matcherState == tsFalse {
			dec.Outcome = OutcomeDrop
			dec.DecisiveRule = decisive
		}
		return dec
	}
	filterState, fdecisive := e.evaluateSide(resp, filters, filterOp, dec)
	if len(filters) == 0 {
		dec.Outcome = OutcomeKeep
		dec.DecisiveRule = decisive
		return dec
	}
	switch filterState {
	case tsTrue:
		dec.Outcome, dec.BlockedSide, dec.DecisiveRule = OutcomeDrop, SideFilter, fdecisive
	case tsFalse:
		dec.Outcome, dec.DecisiveRule = OutcomeKeep, fdecisive
	default:
		dec.Outcome, dec.BlockedSide = OutcomeUndecidable, SideFilter
	}
	return dec
}

// evaluateSide evaluates one rule family and returns the group's three-valued
// result and the trace of the decisive rule (nil when undecidable). Traces are
// appended to dec in evaluation order.
func (e *Evaluator) evaluateSide(resp *ffuf.Response, rules []evaluable, op Combine, dec *Decision) (triState, *RuleTrace) {
	if len(rules) == 0 {
		// An empty side is vacuously neutral. An empty matcher side means the
		// legacy "no matcher configured" case — treat as matched so filters can
		// still run; an empty filter side means nothing filters out.
		return tsTrue, nil
	}

	sawUndecidable := false
	for i, rule := range rules {
		// Allocate the trace on the heap per rule: returning &tr from a loop
		// variable would alias storage reused by the next iteration, so a
		// decisive-rule pointer handed back to the caller could observe the
		// wrong rule's data.
		tr := rule.trace(i)
		state := e.evalOne(resp, rule, &tr)
		dec.Traces = append(dec.Traces, tr)
		if tr.Undecidable {
			dec.UndecidableCount++
		}

		switch state {
		case tsUndecidable:
			sawUndecidable = true
			// Do not short-circuit: another rule may still decide the group
			// firmly. Only if every rule ends up undecidable does the group.
			continue
		case tsTrue:
			if op == CombineAny {
				// First satisfied rule terminates; rules after it are never
				// evaluated (and therefore never appear in the trace).
				last := dec.Traces[len(dec.Traces)-1]
				return tsTrue, &last
			}
			// "all" mode: keep evaluating the remaining rules.
		case tsFalse:
			if op == CombineAll {
				// First firm failure terminates an all-group immediately.
				last := dec.Traces[len(dec.Traces)-1]
				return tsFalse, &last
			}
		}
	}

	if sawUndecidable {
		return tsUndecidable, nil
	}
	// The decisive trace is always read back from the slice (heap-allocated),
	// never from a loop-local address.
	last := dec.Traces[len(dec.Traces)-1]
	if op == CombineAll {
		// No early failure and no undecidable rule: every rule held.
		return tsTrue, &last
	}
	// "or" mode, no rule satisfied and none undecidable: the group firmly fails.
	return tsFalse, &last
}

// evaluable is the surface the guarded per-rule evaluation needs. *Rule
// satisfies it; tests substitute counting/panic stubs implementing the same
// two methods.
type evaluable interface {
	trace(order int) RuleTrace
	evaluate(resp *ffuf.Response) (bool, map[string]string, error)
}

// asEvaluables widens a *Rule slice to the evaluable interface slice the
// guarded runner works on.
func asEvaluables(rules []*Rule) []evaluable {
	out := make([]evaluable, len(rules))
	for i, r := range rules {
		out[i] = r
	}
	return out
}

// evalOne evaluates a single rule with the panic/timeout guard. Any panic or
// timeout becomes "undecidable" with the reason recorded in the trace — it is
// never swallowed as a plain false.
func (e *Evaluator) evalOne(resp *ffuf.Response, rule evaluable, tr *RuleTrace) triState {
	start := time.Now()
	var (
		matched  bool
		values   map[string]string
		evalErr  error
		panicked interface{}
	)

	if e.Timeout > 0 {
		done := make(chan struct{})
		go func() {
			defer func() {
				panicked = recover()
				close(done)
			}()
			matched, values, evalErr = rule.evaluate(resp)
		}()
		select {
		case <-done:
		case <-time.After(e.Timeout):
			tr.Duration = time.Since(start)
			tr.Undecidable = true
			tr.Reason = fmt.Sprintf("rule evaluation timed out after %s", e.Timeout)
			return tsUndecidable
		}
	} else {
		func() {
			defer func() {
				panicked = recover()
			}()
			matched, values, evalErr = rule.evaluate(resp)
		}()
	}

	tr.Duration = time.Since(start)
	tr.ActualValues = values
	if panicked != nil {
		tr.Undecidable = true
		tr.Reason = fmt.Sprintf("rule evaluation panicked: %v", panicked)
		return tsUndecidable
	}
	if evalErr != nil {
		tr.Undecidable = true
		tr.Reason = evalErr.Error()
		return tsUndecidable
	}
	tr.Result = &matched
	if matched {
		return tsTrue
	}
	return tsFalse
}
