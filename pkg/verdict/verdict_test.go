package verdict

import (
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ffuf/ffuf/v2/pkg/ffuf"
)

func mustRule(t *testing.T, id string, side Side, kind, value string, priority int) *Rule {
	t.Helper()
	r := &Rule{ID: id, Side: side, Kind: kind, Priority: priority, rawValue: value}
	r.Raw = r.canonicalRaw()
	if errs := r.Validate(); len(errs) > 0 {
		t.Fatalf("rule %s validate: %v", id, errs)
	}
	return r
}

func testResp(status int64, size, words, lines int64, cancelled bool) *ffuf.Response {
	return &ffuf.Response{
		StatusCode:    status,
		ContentLength: size,
		ContentWords:  words,
		ContentLines:  lines,
		Cancelled:     cancelled,
		Data:          []byte("a b c"),
		Headers:       map[string][]string{},
		Request:       &ffuf.Request{Url: "http://x/FUZZ", Host: "x", Position: 7, Input: map[string][]byte{"FUZZ": []byte("abc")}},
		Duration:      25 * time.Millisecond,
	}
}

func installBook(t *testing.T, matcherOp, filterOp Combine, rules ...*Rule) *RuleBook {
	t.Helper()
	book := NewRuleBook(matcherOp, filterOp)
	if err := book.Install(rules); err != nil {
		t.Fatalf("Install: %v", err)
	}
	return book
}

// 形态1: two overlapping status matchers; the first in declaration/priority
// order is always the decisive one, and repeated runs give the same answer.
func TestOverlappingStatusRules_DecisiveIsStable(t *testing.T) {
	r1 := mustRule(t, "broad", SideMatcher, KindStatus, "200-299", 0)
	r2 := mustRule(t, "narrow", SideMatcher, KindStatus, "200,204", 1)
	book := installBook(t, CombineAny, CombineAny, r1, r2)
	snap := book.SnapshotForHost("x")
	ev := NewEvaluator()

	var first *Decision
	for i := 0; i < 50; i++ {
		dec := ev.Evaluate(testResp(200, 10, 3, 1, false), snap)
		if dec.Outcome != OutcomeKeep {
			t.Fatalf("run %d: outcome = %s, want keep", i, dec.Outcome)
		}
		if dec.DecisiveRule == nil || dec.DecisiveRule.RuleID != "broad" {
			t.Fatalf("run %d: decisive = %v, want broad", i, dec.DecisiveRule)
		}
		// The second rule must never have been evaluated (OR short-circuit).
		if len(dec.Traces) != 1 || dec.Traces[0].RuleID != "broad" {
			t.Fatalf("run %d: traces = %v, want only broad", i, dec.Traces)
		}
		if first != nil && first.DecisiveRule.RuleID != dec.DecisiveRule.RuleID {
			t.Fatalf("nondeterministic decisive rule across runs")
		}
		first = dec
	}
}

// Priority overrides declaration order deterministically.
func TestPriorityOverridesDeclarationOrder(t *testing.T) {
	r1 := mustRule(t, "broad", SideMatcher, KindStatus, "200-299", 5)
	r2 := mustRule(t, "narrow", SideMatcher, KindStatus, "200", 0)
	book := installBook(t, CombineAny, CombineAny, r1, r2)
	dec := NewEvaluator().Evaluate(testResp(200, 10, 3, 1, false), book.SnapshotForHost("x"))
	if dec.DecisiveRule == nil || dec.DecisiveRule.RuleID != "narrow" {
		t.Fatalf("decisive = %v, want narrow (lower priority number)", dec.DecisiveRule)
	}
}

// 形态2: two overlapping filters; declaration order decides which one drops.
func TestFilterOrder_DeclarationDecides(t *testing.T) {
	m := mustRule(t, "m", SideMatcher, KindStatus, "all", 0)
	f1 := mustRule(t, "f-first", SideFilter, KindSize, "10", 0)
	f2 := mustRule(t, "f-second", SideFilter, KindSize, "10,20", 1)
	book := installBook(t, CombineAny, CombineAny, m, f1, f2)
	dec := NewEvaluator().Evaluate(testResp(200, 10, 3, 1, false), book.SnapshotForHost("x"))
	if dec.Outcome != OutcomeDrop || dec.BlockedSide != SideFilter {
		t.Fatalf("outcome=%s side=%s, want filter drop", dec.Outcome, dec.BlockedSide)
	}
	if dec.DecisiveRule.RuleID != "f-first" {
		t.Fatalf("decisive filter = %s, want f-first", dec.DecisiveRule.RuleID)
	}
	for i := 0; i < 20; i++ {
		d := NewEvaluator().Evaluate(testResp(200, 10, 3, 1, false), book.SnapshotForHost("x"))
		if d.DecisiveRule.RuleID != "f-first" {
			t.Fatalf("iteration %d unstable: %s", i, d.DecisiveRule.RuleID)
		}
	}
}

// countingRule wraps a Rule and counts evaluations; optionally panics or sleeps.
type countingRule struct {
	*Rule
	calls  int
	panicV interface{}
	delay  time.Duration
}

func (c *countingRule) evaluate(resp *ffuf.Response) (bool, map[string]string, error) {
	c.calls++
	if c.panicV != nil {
		panic(c.panicV)
	}
	if c.delay > 0 {
		time.Sleep(c.delay)
	}
	return c.Rule.evaluate(resp)
}

func stubs(rules ...evaluable) []evaluable { return rules }

// 形态3: OR first satisfied rule terminates; later rules are not evaluated.
func TestOrShortCircuit_LaterRulesNotEvaluated(t *testing.T) {
	c1 := &countingRule{Rule: mustRule(t, "c1", SideMatcher, KindStatus, "200", 0)}
	c2 := &countingRule{Rule: mustRule(t, "c2", SideMatcher, KindStatus, "200", 1)}
	c3 := &countingRule{Rule: mustRule(t, "c3", SideMatcher, KindSize, "10", 2)}
	dec := NewEvaluator().EvaluateRules(testResp(200, 10, 3, 1, false),
		CombineAny, CombineAny, stubs(c1, c2, c3), nil)
	if c1.calls != 1 || c2.calls != 0 || c3.calls != 0 {
		t.Fatalf("calls = %d/%d/%d, want 1/0/0", c1.calls, c2.calls, c3.calls)
	}
	if dec.DecisiveRule.RuleID != "c1" {
		t.Fatalf("decisive = %s", dec.DecisiveRule.RuleID)
	}
}

// 形态4: AND first firm failure terminates; remaining rules are not evaluated.
func TestAndShortCircuit_FailureStops(t *testing.T) {
	c1 := &countingRule{Rule: mustRule(t, "c1", SideMatcher, KindStatus, "200", 0)}
	c2 := &countingRule{Rule: mustRule(t, "c2", SideMatcher, KindStatus, "404", 1)}
	c3 := &countingRule{Rule: mustRule(t, "c3", SideMatcher, KindSize, "10", 2)}
	dec := NewEvaluator().EvaluateRules(testResp(200, 10, 3, 1, false),
		CombineAll, CombineAny, stubs(c1, c2, c3), nil)
	if c1.calls != 1 || c2.calls != 1 || c3.calls != 0 {
		t.Fatalf("calls = %d/%d/%d, want 1/1/0", c1.calls, c2.calls, c3.calls)
	}
	if dec.Outcome != OutcomeDrop || dec.BlockedSide != SideMatcher {
		t.Fatalf("outcome=%s side=%s", dec.Outcome, dec.BlockedSide)
	}
}

// AND: an undecidable rule does not stop evaluation; a later firm rule can
// still decide, but if everything is undecidable the group is undecidable.
func TestAndMode_UndecidableDoesNotShortCircuit(t *testing.T) {
	good := mustRule(t, "good", SideMatcher, KindStatus, "200", 0)
	trunc := mustRule(t, "trunc", SideMatcher, KindSize, "10", 1)
	book := installBook(t, CombineAll, CombineAny, good, trunc)
	dec := NewEvaluator().Evaluate(testResp(200, 10, 3, 1, true), book.SnapshotForHost("x"))
	if dec.Outcome != OutcomeUndecidable || dec.UndecidableCount != 1 {
		t.Fatalf("outcome=%s undec=%d", dec.Outcome, dec.UndecidableCount)
	}
	// Both rules were evaluated: undecidable did not terminate the AND group.
	if len(dec.Traces) != 2 {
		t.Fatalf("traces=%d, want 2", len(dec.Traces))
	}
}

// 形态5: filter "all" keeps partially-matching responses; "or" drops on one.
func TestFilterModes_PartialMatch(t *testing.T) {
	m := mustRule(t, "m", SideMatcher, KindStatus, "all", 0)
	fSize := mustRule(t, "fs", SideFilter, KindSize, "10", 0)
	fWord := mustRule(t, "fw", SideFilter, KindWord, "99", 1) // words=3, won't match

	bookAll := installBook(t, CombineAny, CombineAll, m, fSize, fWord)
	decAll := NewEvaluator().Evaluate(testResp(200, 10, 3, 1, false), bookAll.SnapshotForHost("x"))
	if decAll.Outcome != OutcomeKeep {
		t.Fatalf("all-mode partial filter match: outcome=%s, want keep", decAll.Outcome)
	}

	bookOr := installBook(t, CombineAny, CombineAny, m, fSize, fWord)
	decOr := NewEvaluator().Evaluate(testResp(200, 10, 3, 1, false), bookOr.SnapshotForHost("x"))
	if decOr.Outcome != OutcomeDrop || decOr.DecisiveRule.RuleID != "fs" {
		t.Fatalf("or-mode: outcome=%s decisive=%v, want drop by fs", decOr.Outcome, decOr.DecisiveRule)
	}
}

// 形态6: matcher failure means filters never run; attribution names the side.
func TestMatcherBlocksFiltersNotEvaluated(t *testing.T) {
	m := mustRule(t, "m", SideMatcher, KindStatus, "404", 0)
	fc := &countingRule{Rule: mustRule(t, "f", SideFilter, KindSize, "10", 0)}
	dec := NewEvaluator().EvaluateRules(testResp(200, 10, 3, 1, false),
		CombineAny, CombineAny, stubs(m), stubs(fc))
	if dec.Outcome != OutcomeDrop || dec.BlockedSide != SideMatcher {
		t.Fatalf("outcome=%s side=%s, want matcher-side drop", dec.Outcome, dec.BlockedSide)
	}
	if fc.calls != 0 {
		t.Fatalf("filter was evaluated %d times despite matcher failure", fc.calls)
	}
	for _, tr := range dec.Traces {
		if tr.Side == SideFilter {
			t.Fatalf("filter trace present despite matcher failure: %+v", tr)
		}
	}
}

// 形态7: missing comparable values are undecidable, never silent false.
func TestUndecidableConditions(t *testing.T) {
	cases := []struct {
		name  string
		kind  string
		resp  *ffuf.Response
		value string
	}{
		{"truncated body / size", KindSize, testResp(200, 10, 3, 1, true), "10"},
		{"truncated body / word", KindWord, testResp(200, 10, 3, 1, true), "10"},
		{"truncated body / line", KindLine, testResp(200, 10, 3, 1, true), "10"},
		{"negative length", KindSize, testResp(200, -1, 3, 1, false), "10"},
		{"negative words", KindWord, testResp(200, 10, -1, 1, false), "10"},
		{"negative duration", KindTime, func() *ffuf.Response {
			r := testResp(200, 10, 3, 1, false)
			r.Duration = -5
			return r
		}(), ">5"},
		{"negative status", KindStatus, testResp(-1, 10, 3, 1, false), "200"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := mustRule(t, "r", SideMatcher, tc.kind, tc.value, 0)
			book := installBook(t, CombineAny, CombineAny, r)
			dec := NewEvaluator().Evaluate(tc.resp, book.SnapshotForHost("x"))
			if dec.Outcome != OutcomeUndecidable {
				t.Fatalf("outcome=%s, want undecidable", dec.Outcome)
			}
			if len(dec.Traces) != 1 || !dec.Traces[0].Undecidable || dec.Traces[0].Reason == "" {
				t.Fatalf("trace must be marked undecidable with reason: %+v", dec.Traces)
			}
		})
	}
}

// 形态8 (startup): all rule errors are reported in one pass.
func TestStartupCollectsAllRuleErrors(t *testing.T) {
	bad := []*Rule{
		{ID: "b1", Side: SideMatcher, Kind: KindStatus, rawValue: "abc", Raw: "status:abc"},
		{ID: "b2", Side: SideFilter, Kind: KindSize, rawValue: "-5", Raw: "size:-5"},
		{ID: "b3", Side: SideMatcher, Kind: "nope", rawValue: "1", Raw: "nope:1"},
		{ID: "b4", Side: Side("weird"), Kind: KindLine, rawValue: "1", Raw: "line:1"},
	}
	book := NewRuleBook(CombineAny, CombineAny)
	err := book.Install(bad)
	if err == nil {
		t.Fatal("expected validation errors, got nil")
	}
	msg := err.Error()
	for _, id := range []string{"b1", "b2", "b3", "b4"} {
		if !strings.Contains(msg, id) {
			t.Errorf("error report missing rule %s:\n%s", id, msg)
		}
	}
}

func TestLoader_BadFileReportsAllErrors(t *testing.T) {
	body := []byte(`
combine_matchers = "maybe"
[[rules]]
id = "x"
side = "matcher"
kind = "status"
value = "not-a-code"
[[rules]]
id = "y"
side = "filter"
kind = "regexp"
value = "[a-z"
`)
	_, err := ParseRuleSet(body)
	if err == nil {
		t.Fatal("expected parse/validation errors")
	}
	msg := err.Error()
	for _, want := range []string{"combine_matchers", "x", "y", "invalid expression"} {
		if !strings.Contains(msg, want) {
			t.Errorf("report missing %q:\n%s", want, msg)
		}
	}
}

// 降级2: a panicking rule is undecidable; the other rules still participate.
func TestPanickingRuleIsUndecidableOthersProceed(t *testing.T) {
	boom := &countingRule{Rule: mustRule(t, "boom", SideMatcher, KindStatus, "200", 0), panicV: "kaboom"}
	good := mustRule(t, "good", SideMatcher, KindStatus, "200", 1)
	dec := NewEvaluator().EvaluateRules(testResp(200, 10, 3, 1, false),
		CombineAny, CombineAny, stubs(boom, good), nil)
	if boom.calls != 1 {
		t.Fatalf("panic rule calls=%d", boom.calls)
	}
	if dec.Outcome != OutcomeKeep {
		t.Fatalf("outcome=%s, want keep via good rule", dec.Outcome)
	}
	if dec.UndecidableCount != 1 || !dec.Traces[0].Undecidable {
		t.Fatalf("panic rule not recorded undecidable: %+v", dec.Traces)
	}
	if !strings.Contains(dec.Traces[0].Reason, "kaboom") {
		t.Fatalf("panic reason lost: %q", dec.Traces[0].Reason)
	}
	if dec.DecisiveRule.RuleID != "good" {
		t.Fatalf("decisive = %v, want good", dec.DecisiveRule)
	}
}

// 降级3: every rule undecidable -> explicit undecidable verdict, not keep.
func TestAllUndecidableIsExplicit(t *testing.T) {
	r1 := mustRule(t, "r1", SideMatcher, KindSize, "10", 0)
	r2 := mustRule(t, "r2", SideMatcher, KindWord, "3", 1)
	book := installBook(t, CombineAll, CombineAny, r1, r2)
	dec := NewEvaluator().Evaluate(testResp(200, 10, 3, 1, true), book.SnapshotForHost("x"))
	if dec.Outcome != OutcomeUndecidable {
		t.Fatalf("outcome=%s, want undecidable", dec.Outcome)
	}
	if dec.UndecidableCount != 2 {
		t.Fatalf("undecidable count=%d, want 2", dec.UndecidableCount)
	}
}

// 形态10: concurrent evaluation of the same response yields identical
// conclusions and decisive rules.
func TestConcurrentDecisionsAreStable(t *testing.T) {
	book := installBook(t, CombineAny, CombineAny,
		mustRule(t, "m1", SideMatcher, KindStatus, "200-299", 0),
		mustRule(t, "m2", SideMatcher, KindStatus, "200", 1),
		mustRule(t, "f1", SideFilter, KindSize, "999", 0), // never matches (size=10)
	)
	ev := NewEvaluator()
	snap := book.SnapshotForHost("x")
	resp := testResp(200, 10, 3, 1, false)

	var wg sync.WaitGroup
	var firstKey string
	var mu sync.Mutex
	for w := 0; w < 16; w++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for i := 0; i < 200; i++ {
				d := ev.Evaluate(resp, snap)
				// m1 short-circuits the OR matchers; the non-matching filter
				// f1 is evaluated and its firm "no match" decides keep, so it
				// is the recorded decisive rule for this side.
				if d.Outcome != OutcomeKeep || d.DecisiveRule == nil || d.DecisiveRule.RuleID != "f1" {
					t.Errorf("bad decision: %s %v", d.Outcome, d.DecisiveRule)
					return
				}
				key := fmt.Sprintf("%s|%s|%d", d.Outcome, d.DecisiveRule.RuleID, len(d.Traces))
				mu.Lock()
				if firstKey == "" {
					firstKey = key
				} else if firstKey != key {
					t.Errorf("unstable decision key: %s vs %s", firstKey, key)
				}
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
}

// Hard constraint 1: attribution always carries type, raw text and actual value.
func TestAttributionContents(t *testing.T) {
	r := mustRule(t, "m", SideMatcher, KindStatus, "200", 0)
	book := installBook(t, CombineAny, CombineAny, r)
	dec := NewEvaluator().Evaluate(testResp(200, 10, 3, 1, false), book.SnapshotForHost("x"))
	tr := dec.Traces[0]
	if tr.Kind != "status" || tr.Raw != "status:200" {
		t.Fatalf("type/raw missing: %+v", tr)
	}
	if tr.ActualValues["status_code"] != "200" {
		t.Fatalf("actual value missing: %+v", tr.ActualValues)
	}
}

func TestTimeoutRuleMarkedUndecidable(t *testing.T) {
	slow := &countingRule{Rule: mustRule(t, "slow", SideMatcher, KindStatus, "200", 0), delay: 40 * time.Millisecond}
	ev := NewEvaluator()
	ev.Timeout = 5 * time.Millisecond
	dec := ev.EvaluateRules(testResp(200, 10, 3, 1, false), CombineAny, CombineAny, stubs(slow), nil)
	if dec.Outcome != OutcomeUndecidable || !dec.Traces[0].Undecidable {
		t.Fatalf("timeout rule not undecidable: %+v", dec.Traces)
	}
	if !strings.Contains(dec.Traces[0].Reason, "timed out") {
		t.Fatalf("timeout reason lost: %q", dec.Traces[0].Reason)
	}
}

// Per-host rule sets: host-specific rules extend the global set, and an unknown
// host falls back to globals (visibility boundary unchanged).
func TestPerHostRuleSetVisibility(t *testing.T) {
	gm := mustRule(t, "gm", SideMatcher, KindStatus, "all", 0)
	gf := mustRule(t, "gf", SideFilter, KindSize, "10", 0)
	hf := &Rule{ID: "hf", Side: SideFilter, Kind: KindWord, Priority: 1, rawValue: "3", Host: "special"}
	hf.Raw = hf.canonicalRaw()
	book := installBook(t, CombineAny, CombineAny, gm, gf, hf)

	special := book.SnapshotForHost("special")
	if len(special.Filters) != 2 {
		t.Fatalf("special host filters=%d, want 2 (global + host)", len(special.Filters))
	}
	other := book.SnapshotForHost("other")
	if len(other.Filters) != 1 || other.Filters[0].ID != "gf" {
		t.Fatalf("other host must only see global filters, got %+v", other.Filters)
	}
}
