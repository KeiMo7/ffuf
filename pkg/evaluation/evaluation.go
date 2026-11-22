// Package evaluation compares hit-determination strategies against a
// human-labeled ground-truth set and reports recall / false-positive rates for
// each, with every miss attributed to the dimension that failed to cover it.
//
// The three strategies the acceptance work requires are:
//
//	Legacy     - status-code-only matching (the pre-existing MatcherManager
//	             behavior, evaluated exactly as the scan recorded it)
//	Heuristics - the multi-dimensional verdict
//	GroundTruth- the human labels; by definition recall/FPR are 1.0/0.0 here,
//	             and the row exists so the three-way table is self-checking
//
// Inputs are plain records (the same shape the evidence log writes), so an
// evaluation can be run live in tests or offline against a JSONL file produced
// by a real scan.
package evaluation

import (
	"sort"

	"github.com/ffuf/ffuf/v2/pkg/heuristics"
)

// Label is the human truth for one dictionary entry.
type Label struct {
	// Input identifies the entry (the FUZZ value, or any stable key).
	Input string `json:"input"`
	// Exists is the ground-truth "resource really exists" decision.
	Exists bool `json:"exists"`
	// Note is optional reviewer context carried into the miss report.
	Note string `json:"note,omitempty"`
}

// Observation is one evaluated response. It is intentionally decoupled from
// ffuf's types so offline tooling can build it from JSON without the engine.
type Observation struct {
	Input       string
	LegacyMatch bool
	Verdict     *heuristics.Verdict
}

// Metrics are the confusion-matrix derived numbers for one strategy.
type Metrics struct {
	TruePositives  int     `json:"true_positives"`
	FalsePositives int     `json:"false_positives"`
	TrueNegatives  int     `json:"true_negatives"`
	FalseNegatives int     `json:"false_negatives"`
	Recall         float64 `json:"recall"`
	Precision      float64 `json:"precision"`
	// FalsePositiveRate is FP/(FP+TN): the fraction of nonexistent entries the
	// strategy incorrectly reported.
	FalsePositiveRate float64 `json:"false_positive_rate"`
}

// Miss explains one false negative: an existing entry a strategy did not hit.
type Miss struct {
	Input   string   `json:"input"`
	Mode    string   `json:"mode"`
	Note    string   `json:"note,omitempty"`
	Reasons []string `json:"reasons"`
	// CoverageGap names the dimension that failed, derived from the verdict
	// evidence: e.g. "status" (302 not in matcher), "similarity", "length",
	// "soft404", "suppressed", "degraded".
	CoverageGap string                `json:"coverage_gap"`
	Evidence    []heuristics.Evidence `json:"evidence,omitempty"`
}

// FalseAlarm explains one false positive for reviewer triage.
type FalseAlarm struct {
	Input    string                `json:"input"`
	Mode     string                `json:"mode"`
	Reasons  []string              `json:"reasons"`
	BodyHash string                `json:"body_hash,omitempty"`
	Evidence []heuristics.Evidence `json:"evidence,omitempty"`
}

// Report is the full three-way comparison.
type Report struct {
	Total       int     `json:"total"`
	Existing    int     `json:"existing"`
	Nonexistent int     `json:"nonexistent"`
	Legacy      Metrics `json:"legacy_status_code"`
	Heuristics  Metrics `json:"heuristics"`
	// HeuristicsRaw scores the engine on its OWN verdict alone, ignoring hits it
	// only reports to honor the monotonicity guarantee (legacy-matched soft-404s
	// "retained for review"). It answers "how good is the new logic itself",
	// while Heuristics answers "what does the operator actually receive".
	HeuristicsRaw        Metrics      `json:"heuristics_raw"`
	GroundTruth          Metrics      `json:"ground_truth"`
	LegacyMisses         []Miss       `json:"legacy_misses"`
	HeuristicMisses      []Miss       `json:"heuristic_misses"`
	LegacyFalseAlarms    []FalseAlarm `json:"legacy_false_alarms"`
	HeuristicFalseAlarms []FalseAlarm `json:"heuristic_false_alarms"`
	// MonotonicityRetained counts nonexistent entries kept only because legacy
	// matched them; they are flagged soft-404 rather than silently dropped.
	MonotonicityRetained int `json:"monotonicity_retained"`
	Soft404Count         int `json:"soft404_count"`
	SuppressedCount      int `json:"suppressed_count"`
	DegradedCount        int `json:"degraded_count"`
}

// Mode names.
const (
	ModeLegacy      = "legacy-status"
	ModeHeuristics  = "heuristics"
	ModeGroundTruth = "ground-truth"
)

// Evaluate builds the three-way report. Labels and observations are joined on
// Input; an observation without a label is ignored (and vice versa) so scans
// with extra probe traffic do not distort the numbers.
func Evaluate(labels []Label, obs []Observation) Report {
	truth := make(map[string]Label, len(labels))
	for _, l := range labels {
		truth[l.Input] = l
	}
	rep := Report{
		LegacyMisses:         []Miss{},
		HeuristicMisses:      []Miss{},
		LegacyFalseAlarms:    []FalseAlarm{},
		HeuristicFalseAlarms: []FalseAlarm{},
	}

	// Stable ordering makes reports deterministic.
	sort.Slice(obs, func(i, j int) bool { return obs[i].Input < obs[j].Input })

	var legacyTP, legacyFP, legacyTN, legacyFN int
	var heurTP, heurFP, heurTN, heurFN int
	// Raw = engine verdict with monotonicity-retention removed.
	var rawTP, rawFP, rawTN, rawFN int
	var truthTP, truthTN int

	for _, o := range obs {
		l, ok := truth[o.Input]
		if !ok {
			continue
		}
		rep.Total++
		heurHit := o.LegacyMatch
		// engineOwnHit is the decision the engine would make on its own, without
		// the monotonicity safety net: a soft-404 the legacy matcher happened to
		// accept would be rejected by the engine.
		engineOwnHit := heurHit
		if o.Verdict != nil {
			heurHit = o.Verdict.Hit
			engineOwnHit = heurHit
			if o.Verdict.Soft404 {
				rep.Soft404Count++
				engineOwnHit = false
			}
			if o.Verdict.Suppressed {
				rep.SuppressedCount++
			}
			if o.Verdict.Degraded {
				rep.DegradedCount++
			}
		}
		retained := heurHit && !engineOwnHit

		if l.Exists {
			rep.Existing++
			truthTP++
			// legacy
			if o.LegacyMatch {
				legacyTP++
			} else {
				legacyFN++
				rep.LegacyMisses = append(rep.LegacyMisses, Miss{
					Input: o.Input, Mode: ModeLegacy, Note: l.Note,
					Reasons:     []string{"status-code matcher did not accept the response"},
					CoverageGap: legacyGap(o),
				})
			}
			// heuristics (operator-visible)
			if heurHit {
				heurTP++
			} else {
				heurFN++
				rep.HeuristicMisses = append(rep.HeuristicMisses, heuristicMiss(o, l))
			}
			// heuristics (raw engine logic)
			if engineOwnHit {
				rawTP++
			} else {
				rawFN++
			}
		} else {
			rep.Nonexistent++
			truthTN++
			if o.LegacyMatch {
				legacyFP++
				rep.LegacyFalseAlarms = append(rep.LegacyFalseAlarms, FalseAlarm{
					Input: o.Input, Mode: ModeLegacy,
					Reasons: []string{"status code within the matcher's accepted set despite nonexistent resource"},
				})
			} else {
				legacyTN++
			}
			if heurHit {
				heurFP++
				fa := heuristicFalseAlarm(o)
				rep.HeuristicFalseAlarms = append(rep.HeuristicFalseAlarms, fa)
			} else {
				heurTN++
			}
			if retained {
				rep.MonotonicityRetained++
			}
			// Raw: a retained soft-404 is correctly a true negative for the
			// engine's own logic.
			if engineOwnHit {
				rawFP++
			} else {
				rawTN++
			}
		}
	}

	rep.Legacy = metrics(legacyTP, legacyFP, legacyTN, legacyFN)
	rep.Heuristics = metrics(heurTP, heurFP, heurTN, heurFN)
	rep.HeuristicsRaw = metrics(rawTP, rawFP, rawTN, rawFN)
	rep.GroundTruth = metrics(truthTP, 0, truthTN, 0)
	return rep
}

func metrics(tp, fp, tn, fn int) Metrics {
	m := Metrics{TruePositives: tp, FalsePositives: fp, TrueNegatives: tn, FalseNegatives: fn}
	if tp+fn > 0 {
		m.Recall = float64(tp) / float64(tp+fn)
	}
	if tp+fp > 0 {
		m.Precision = float64(tp) / float64(tp+fp)
	}
	if fp+tn > 0 {
		m.FalsePositiveRate = float64(fp) / float64(fp+tn)
	}
	return m
}

// legacyGap names why a status-only matcher missed an existing resource,
// using the recorded status code when a verdict is available.
func legacyGap(o Observation) string {
	if o.Verdict == nil {
		return "status"
	}
	for _, ev := range o.Verdict.Evidence {
		if ev.Dimension == heuristics.DimStatus {
			return heuristics.DimStatus + ": " + ev.Reason
		}
	}
	return "status"
}

func heuristicMiss(o Observation, l Label) Miss {
	m := Miss{Input: o.Input, Mode: ModeHeuristics, Note: l.Note, CoverageGap: "unknown"}
	if o.Verdict == nil {
		m.Reasons = []string{"no heuristic verdict recorded"}
		m.CoverageGap = "degraded"
		return m
	}
	m.Reasons = o.Verdict.Reasons
	m.Evidence = o.Verdict.Evidence
	switch {
	case o.Verdict.Suppressed:
		m.CoverageGap = "suppressed"
	case o.Verdict.Soft404:
		m.CoverageGap = "soft404"
	case o.Verdict.Degraded:
		m.CoverageGap = "degraded"
	default:
		m.CoverageGap = uncoveredDimension(o.Verdict)
	}
	return m
}

// uncoveredDimension identifies which signal could have caught the miss but
// did not: it scans evidence for a dimension that was skipped (rather than
// merely not firing), since a skip is the actionable coverage gap.
func uncoveredDimension(v *heuristics.Verdict) string {
	for _, ev := range v.Evidence {
		if ev.Skipped {
			return ev.Dimension + " skipped: " + ev.Reason
		}
	}
	// Nothing was skipped; all active dimensions measured within baseline
	// ranges. Report the strongest near-miss dimension.
	best := ""
	bestScore := 0.0
	for _, ev := range v.Evidence {
		if ev.Score > bestScore {
			bestScore, best = ev.Score, ev.Dimension
		}
	}
	if best == "" {
		return "no dimension deviated from baseline"
	}
	return best + " deviated but stayed below its threshold"
}

func heuristicFalseAlarm(o Observation) FalseAlarm {
	fa := FalseAlarm{Input: o.Input, Mode: ModeHeuristics}
	if o.Verdict != nil {
		fa.Reasons = o.Verdict.Reasons
		fa.Evidence = o.Verdict.Evidence
		fa.BodyHash = o.Verdict.BodyHash
	}
	return fa
}
