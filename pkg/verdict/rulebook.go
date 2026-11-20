package verdict

import (
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/ffuf/ffuf/v2/pkg/ffuf"
)

// RuleBook holds the validated, ordered rule sets. It is the concurrency seam:
// workers take an immutable *Snapshot under RLock and evaluate it without any
// further locking, so a request's conclusion is decided solely by the snapshot
// that existed when its evaluation began — no intermediate states under
// concurrency.
type RuleBook struct {
	mu      sync.RWMutex
	version atomic.Uint64

	global    []*Rule
	perHost   map[string][]*Rule
	matcherOp Combine
	filterOp  Combine
}

// Snapshot is an immutable point-in-time view of the rules. Everything a worker
// needs is copied (slice headers into new arrays; the Rule pointers themselves
// are immutable after validation), so later RuleBook mutations cannot affect an
// in-flight decision.
type Snapshot struct {
	Version   uint64
	Matchers  []*Rule
	Filters   []*Rule
	MatcherOp Combine
	FilterOp  Combine
}

// NewRuleBook creates an empty rule book with the given combination operators.
func NewRuleBook(matcherOp, filterOp Combine) *RuleBook {
	return &RuleBook{
		perHost:   make(map[string][]*Rule),
		matcherOp: matcherOp,
		filterOp:  filterOp,
	}
}

// Install replaces the whole rule set atomically and returns every validation
// error found across ALL rules in one pass — startup reports the complete error
// list instead of bailing at the first bad rule. On error the book is left
// untouched, so a failed reload can never expose partial rules.
func (b *RuleBook) Install(rules []*Rule) error {
	errs := ffuf.NewMultierror()
	seenIDs := make(map[string]bool)
	globals := make([]*Rule, 0, len(rules))
	hosts := make(map[string][]*Rule)

	for i, r := range rules {
		if r == nil {
			errs.Add(fmt.Errorf("rule #%d: nil rule", i+1))
			continue
		}
		if r.ID == "" {
			r.ID = fmt.Sprintf("rule-%d", i+1)
		}
		if seenIDs[r.ID] {
			errs.Add(fmt.Errorf("rule %q: duplicate rule id", r.ID))
		}
		seenIDs[r.ID] = true
		if r.Raw == "" {
			r.Raw = r.canonicalRaw()
		}
		for _, err := range r.Validate() {
			errs.Add(err)
		}
		if r.Host == "" {
			globals = append(globals, r)
		} else {
			hosts[r.Host] = append(hosts[r.Host], r)
		}
	}
	if err := errs.ErrorOrNil(); err != nil {
		return err
	}

	orderRules(globals)
	for h := range hosts {
		// Per-host sets inherit the global rules by value (the same immutable
		// pointers), mirroring the legacy PerDomainFilter copy semantics: the
		// visibility boundary between global and per-host sets is unchanged.
		combined := append(append([]*Rule(nil), globals...), hosts[h]...)
		orderRules(combined)
		hosts[h] = combined
	}

	b.mu.Lock()
	b.global = globals
	b.perHost = hosts
	b.mu.Unlock()
	b.version.Add(1)
	return nil
}

// orderRules sorts by (Priority, declaration order). The stable sort guarantees
// equal-priority rules keep declaration order, so evaluation never depends on
// map traversal.
func orderRules(rules []*Rule) {
	sort.SliceStable(rules, func(i, j int) bool {
		if rules[i].Priority != rules[j].Priority {
			return rules[i].Priority < rules[j].Priority
		}
		return false
	})
}

// SnapshotForHost returns the immutable rule view applicable to host. An unknown
// host gets the global set — the same fallback as FiltersForDomain.
func (b *RuleBook) SnapshotForHost(host string) *Snapshot {
	b.mu.RLock()
	defer b.mu.RUnlock()

	// The filter side is host-scoped (global rules inherited by per-host
	// copies); the matcher side is always the global matcher list. This mirrors
	// the legacy PerDomainFilter structure, which only carried filters.
	filterSource := b.global
	if hf, ok := b.perHost[host]; ok {
		filterSource = hf
	}
	matchers := make([]*Rule, 0, len(b.global))
	filters := make([]*Rule, 0, len(filterSource))
	for _, r := range b.global {
		if r.Side == SideMatcher {
			matchers = append(matchers, r)
		}
	}
	for _, r := range filterSource {
		if r.Side == SideFilter {
			filters = append(filters, r)
		}
	}
	return &Snapshot{
		Version:   b.version.Load(),
		Matchers:  matchers,
		Filters:   filters,
		MatcherOp: b.matcherOp,
		FilterOp:  b.filterOp,
	}
}

// Empty reports whether any rules are installed.
func (b *RuleBook) Empty() bool {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return len(b.global) == 0 && len(b.perHost) == 0
}

// String renders a compact, deterministic summary for diagnostics.
func (s *Snapshot) String() string {
	parts := []string{
		fmt.Sprintf("v%d matchers(%s):%s", s.Version, s.MatcherOp, ruleNames(s.Matchers)),
		fmt.Sprintf("filters(%s):%s", s.FilterOp, ruleNames(s.Filters)),
	}
	return strings.Join(parts, " ")
}

func ruleNames(rules []*Rule) string {
	names := make([]string, 0, len(rules))
	for _, r := range rules {
		names = append(names, r.ID)
	}
	return "[" + strings.Join(names, ",") + "]"
}
