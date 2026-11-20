package verdict

import (
	"bytes"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	"github.com/ffuf/ffuf/v2/pkg/ffuf"
)

// Rule kinds. They mirror the legacy filter types so a rule file uses the same
// vocabulary as -mc/-fs and friends.
const (
	KindStatus = "status"
	KindSize   = "size"
	KindWord   = "word"
	KindLine   = "line"
	KindRegexp = "regexp"
	KindTime   = "time"
)

var validKinds = map[string]bool{
	KindStatus: true,
	KindSize:   true,
	KindWord:   true,
	KindLine:   true,
	KindRegexp: true,
	KindTime:   true,
}

// Rule is one ordered, attributed rule. Rules are immutable after the rule set
// has been validated at startup, which is what lets worker goroutines evaluate
// them without any locking.
type Rule struct {
	// ID is the user-supplied (or loader-generated) stable identifier used in
	// attribution and review records.
	ID string
	// Side is the rule family.
	Side Side
	// Kind is the comparison type.
	Kind string
	// Raw is the verbatim declaration, retained for attribution. For a rule
	// loaded from a file it is the canonical "kind:value" rendering.
	Raw string
	// Host optionally scopes the rule to one host (per-host rule set). An empty
	// host means the rule is global. Per-host sets are built as complete copies,
	// so evaluation never merges maps on the hot path.
	Host string
	// Priority lets the user reorder rules explicitly; lower numbers run first.
	// Rules with equal priority keep their declaration order.
	Priority int

	// Compiled comparison state, populated by Validate at startup.
	ranges   []ffuf.ValueRange // status/size/word/line
	regex    *regexp.Regexp    // regexp
	timeMS   int64             // time
	timeGT   bool              // time: >ms
	timeLT   bool              // time: <ms
	rawValue string            // the value part of the declaration
}

// Validate compiles the rule's value and returns every problem found. It is the
// startup-time gate: a bad rule is reported here, never as a per-request panic.
func (r *Rule) Validate() []error {
	var errs []error
	if r.Side != SideMatcher && r.Side != SideFilter {
		errs = append(errs, fmt.Errorf("rule %q: side must be %q or %q, got %q", r.ID, SideMatcher, SideFilter, r.Side))
	}
	if !validKinds[r.Kind] {
		errs = append(errs, fmt.Errorf("rule %q: unknown kind %q (valid: %s)", r.ID, r.Kind,
			strings.Join([]string{KindStatus, KindSize, KindWord, KindLine, KindRegexp, KindTime}, ", ")))
		return errs // the kind-specific compile below would be meaningless
	}
	if strings.TrimSpace(r.rawValue) == "" {
		errs = append(errs, fmt.Errorf("rule %q (%s): empty comparison value", r.ID, r.Kind))
		return errs
	}

	switch r.Kind {
	case KindStatus, KindSize, KindWord, KindLine:
		for _, sv := range strings.Split(r.rawValue, ",") {
			sv = strings.TrimSpace(sv)
			if r.Kind == KindStatus && sv == "all" {
				r.ranges = append(r.ranges, ffuf.ValueRange{Min: 0, Max: 0})
				continue
			}
			vr, err := ffuf.ValueRangeFromString(sv)
			if err != nil {
				errs = append(errs, fmt.Errorf("rule %q (%s): invalid value %q: %s", r.ID, r.Kind, sv, err))
				continue
			}
			if vr.Min < 0 || vr.Max < 0 {
				errs = append(errs, fmt.Errorf("rule %q (%s): value %q is out of range (negative)", r.ID, r.Kind, sv))
				continue
			}
			r.ranges = append(r.ranges, vr)
		}
	case KindRegexp:
		re, err := regexp.Compile(r.rawValue)
		if err != nil {
			errs = append(errs, fmt.Errorf("rule %q (regexp): invalid expression %q: %s", r.ID, r.rawValue, err))
		} else {
			r.regex = re
		}
	case KindTime:
		gt := strings.HasPrefix(r.rawValue, ">")
		lt := strings.HasPrefix(r.rawValue, "<")
		if gt == lt { // both true or both false
			errs = append(errs, fmt.Errorf("rule %q (time): value must start with > or <, got %q", r.ID, r.rawValue))
			break
		}
		ms, err := strconv.ParseInt(r.rawValue[1:], 10, 64)
		if err != nil {
			errs = append(errs, fmt.Errorf("rule %q (time): invalid duration %q: %s", r.ID, r.rawValue, err))
			break
		}
		if ms < 0 {
			errs = append(errs, fmt.Errorf("rule %q (time): duration %q is out of range (negative)", r.ID, r.rawValue))
			break
		}
		r.timeMS, r.timeGT, r.timeLT = ms, gt, lt
	}
	return errs
}

// valueMissingError marks the "cannot get a comparable value" case required by
// the spec: a declared length that is absent, a negative metric, or a body that
// was truncated mid-stream. These are undecidable, never a silent false.
type valueMissingError struct{ msg string }

func (e *valueMissingError) Error() string { return e.msg }

// extractValue returns the response-derived value(s) a rule kind compares
// against, plus their display forms for attribution. It returns a
// *valueMissingError when the value cannot be obtained.
func extractValue(kind string, resp *ffuf.Response) (int64, map[string]string, error) {
	values := map[string]string{}
	switch kind {
	case KindStatus:
		if resp.StatusCode < 0 {
			return 0, nil, &valueMissingError{fmt.Sprintf("status code is negative (%d), cannot compare", resp.StatusCode)}
		}
		values["status_code"] = strconv.FormatInt(resp.StatusCode, 10)
		return resp.StatusCode, values, nil
	case KindSize:
		// A truncated/cancelled body means the observed length is not the real
		// length; comparing against it would silently mis-decide.
		if resp.Cancelled {
			return 0, nil, &valueMissingError{"response body was truncated or not fetched (cancelled), content length is not comparable"}
		}
		if resp.ContentLength < 0 {
			return 0, nil, &valueMissingError{fmt.Sprintf("content length is negative (%d), cannot compare", resp.ContentLength)}
		}
		values["content_length"] = strconv.FormatInt(resp.ContentLength, 10)
		return resp.ContentLength, values, nil
	case KindWord:
		if resp.Cancelled {
			return 0, nil, &valueMissingError{"response body was truncated or not fetched (cancelled), word count is not comparable"}
		}
		if resp.ContentWords < 0 {
			return 0, nil, &valueMissingError{fmt.Sprintf("word count is negative (%d), cannot compare", resp.ContentWords)}
		}
		values["content_words"] = strconv.FormatInt(resp.ContentWords, 10)
		return resp.ContentWords, values, nil
	case KindLine:
		if resp.Cancelled {
			return 0, nil, &valueMissingError{"response body was truncated or not fetched (cancelled), line count is not comparable"}
		}
		if resp.ContentLines < 0 {
			return 0, nil, &valueMissingError{fmt.Sprintf("line count is negative (%d), cannot compare", resp.ContentLines)}
		}
		values["content_lines"] = strconv.FormatInt(resp.ContentLines, 10)
		return resp.ContentLines, values, nil
	case KindTime:
		// Check the raw duration before truncating to milliseconds: a small
		// negative Duration (e.g. -5ns) would otherwise round to 0 and hide the
		// "negative value" condition.
		if resp.Duration < 0 {
			return 0, nil, &valueMissingError{fmt.Sprintf("response duration is negative (%s), cannot compare", resp.Duration)}
		}
		ms := resp.Duration.Milliseconds()
		values["duration_ms"] = strconv.FormatInt(ms, 10)
		return ms, values, nil
	default:
		return 0, nil, &valueMissingError{fmt.Sprintf("no scalar value for kind %q", kind)}
	}
}

// evaluate runs the rule against one response and returns its three-valued
// result. Panics are turned into an error by the evaluator's guard; this method
// itself only returns ordinary comparison errors.
func (r *Rule) evaluate(resp *ffuf.Response) (bool, map[string]string, error) {
	switch r.Kind {
	case KindRegexp:
		// Reuse the legacy matcher's search space: headers then body, with the
		// request's fuzzing inputs quoted into the pattern.
		var headerBuf bytes.Buffer
		for k, v := range resp.Headers {
			for _, iv := range v {
				headerBuf.WriteString(k)
				headerBuf.WriteString(": ")
				headerBuf.WriteString(iv)
				headerBuf.WriteString("\r\n")
			}
		}
		matchData := append(headerBuf.Bytes(), resp.Data...)
		pattern := r.rawValue
		if resp.Request != nil {
			for keyword, inputItem := range resp.Request.Input {
				pattern = strings.ReplaceAll(pattern, keyword, regexp.QuoteMeta(string(inputItem)))
			}
		}
		re, err := regexp.Compile(pattern)
		if err != nil {
			// The legacy code swallowed this; the spec requires it to enter
			// attribution as an evaluation error rather than count as "no match".
			return false, map[string]string{"regexp": r.rawValue}, fmt.Errorf("regexp could not be compiled after input substitution: %s", err)
		}
		matched := re.Match(matchData)
		return matched, map[string]string{"regexp": r.rawValue, "matched": strconv.FormatBool(matched)}, nil
	case KindTime:
		ms, values, err := extractValue(r.Kind, resp)
		if err != nil {
			return false, values, err
		}
		if r.timeGT {
			return ms > r.timeMS, values, nil
		}
		return ms < r.timeMS, values, nil
	default:
		n, values, err := extractValue(r.Kind, resp)
		if err != nil {
			return false, values, err
		}
		for _, iv := range r.ranges {
			if r.Kind == KindStatus && iv.Min == 0 && iv.Max == 0 {
				return true, values, nil // status "all"
			}
			if iv.Min <= n && n <= iv.Max {
				return true, values, nil
			}
		}
		return false, values, nil
	}
}

// canonicalRaw renders the rule's "kind:value" declaration.
func (r *Rule) canonicalRaw() string {
	return r.Kind + ":" + r.rawValue
}

// trace builds the RuleTrace shell for this rule at the given ordered position.
func (r *Rule) trace(order int) RuleTrace {
	return RuleTrace{
		RuleID: r.ID,
		Side:   r.Side,
		Kind:   r.Kind,
		Raw:    r.Raw,
		Order:  order,
	}
}
