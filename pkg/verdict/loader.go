package verdict

import (
	"fmt"
	"os"
	"strings"

	"github.com/pelletier/go-toml"
)

// ruleFile is the on-disk rule set schema (TOML). Example:
//
//	combine_matchers = "or"      # or "all"
//	combine_filters  = "or"      # or "all"
//
//	[[rules]]
//	id = "m1"
//	side = "matcher"              # or "filter"
//	kind = "status"               # status|size|word|line|regexp|time
//	value = "200-299"
//	priority = 0                  # optional; lower runs first, ties keep file order
//	host = ""                     # optional; empty = global
//
// [[rules]]
//
//	id = "f1"
//	side = "filter"
//	kind = "size"
//	value = "0"
type ruleFile struct {
	CombineMatchers string      `toml:"combine_matchers"`
	CombineFilters  string      `toml:"combine_filters"`
	Rules           []ruleEntry `toml:"rules"`
}

type ruleEntry struct {
	ID       string `toml:"id"`
	Side     string `toml:"side"`
	Kind     string `toml:"kind"`
	Value    string `toml:"value"`
	Priority int    `toml:"priority"`
	Host     string `toml:"host"`
}

// LoadRuleFile reads, parses and validates a rule file and returns an
// installed RuleBook. Every parse/validation error across every rule is
// accumulated and returned together — startup fails once with the complete
// list rather than at the first bad rule.
func LoadRuleFile(path string) (*RuleBook, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("rule file %q: %s", path, err)
	}
	return ParseRuleSet(data)
}

// ParseRuleSet parses rule-set TOML content. Split out from LoadRuleFile so the
// parser is unit-testable without touching the filesystem.
func ParseRuleSet(data []byte) (*RuleBook, error) {
	var rf ruleFile
	if err := toml.Unmarshal(data, &rf); err != nil {
		return nil, fmt.Errorf("rule file parse error: %s", err)
	}

	matcherOp, opErr1 := parseCombine("combine_matchers", rf.CombineMatchers)
	filterOp, opErr2 := parseCombine("combine_filters", rf.CombineFilters)
	errs := multierr{}
	if opErr1 != "" {
		errs.add(fmt.Errorf("%s", opErr1))
	}
	if opErr2 != "" {
		errs.add(fmt.Errorf("%s", opErr2))
	}

	rules := make([]*Rule, 0, len(rf.Rules))
	for i, re := range rf.Rules {
		r := &Rule{
			ID:       strings.TrimSpace(re.ID),
			Kind:     strings.TrimSpace(re.Kind),
			Host:     strings.TrimSpace(re.Host),
			Priority: re.Priority,
			rawValue: strings.TrimSpace(re.Value),
		}
		switch strings.TrimSpace(re.Side) {
		case string(SideMatcher):
			r.Side = SideMatcher
		case string(SideFilter):
			r.Side = SideFilter
		default:
			errs.add(fmt.Errorf("rule #%d %q: side must be %q or %q, got %q",
				i+1, re.ID, SideMatcher, SideFilter, re.Side))
		}
		// Raw is rendered canonically during Install if left empty; do it here
		// so validation errors still show a useful declaration.
		r.Raw = r.Kind + ":" + r.rawValue
		rules = append(rules, r)
	}
	if len(rf.Rules) == 0 {
		errs.add(fmt.Errorf("rule file contains no [[rules]] entries"))
	}

	book := NewRuleBook(matcherOp, filterOp)
	if err := book.Install(rules); err != nil {
		// Fold structural errors (already accumulated) and per-rule validation
		// errors into one report so startup prints everything in a single pass.
		errs.add(err)
	}
	if len(errs.items) > 0 {
		return nil, errs.err()
	}
	return book, nil
}

func parseCombine(name, v string) (Combine, string) {
	switch strings.TrimSpace(v) {
	case "", "or", "any":
		return CombineAny, ""
	case "and", "all":
		return CombineAll, ""
	default:
		return CombineAny, fmt.Sprintf("%s must be \"or\" or \"all\", got %q", name, v)
	}
}

// multierr is a tiny local accumulator so the loader does not depend on
// pkg/ffuf's presentation-oriented Multierror.
type multierr struct{ items []error }

func (m *multierr) add(e error) { m.items = append(m.items, e) }

func (m *multierr) err() error {
	if len(m.items) == 0 {
		return nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d error(s) in rule set:\n", len(m.items))
	for _, e := range m.items {
		b.WriteString("\t* " + e.Error() + "\n")
	}
	// Rule validation errors from Install are themselves multierror-formatted;
	// append them as a block.
	return fmt.Errorf("%s", strings.TrimRight(b.String(), "\n"))
}
