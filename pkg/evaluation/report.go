package evaluation

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/ffuf/ffuf/v2/pkg/evidence"
	"github.com/ffuf/ffuf/v2/pkg/heuristics"
)

// LoadEvidence reads an evidence JSONL file (as written by pkg/evidence) and
// converts each line to an Observation. Legacy-mode lines carry no verdict and
// are evaluated on their legacy_match flag alone.
func LoadEvidence(path string) ([]Observation, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	reader := bufio.NewReader(f)
	out := make([]Observation, 0)
	lineNo := 0
	for {
		line, rerr := reader.ReadBytes('\n')
		if len(line) > 0 {
			lineNo++
			line = trimSpace(line)
			if len(line) > 0 {
				var rec evidence.Record
				if err := json.Unmarshal(line, &rec); err != nil {
					return nil, fmt.Errorf("evidence line %d: %w", lineNo, err)
				}
				out = append(out, Observation{
					Input:       primaryInput(rec.Inputs),
					LegacyMatch: rec.Legacy,
					Verdict:     rec.Verdict,
				})
			}
		}
		if rerr == io.EOF {
			break
		}
		if rerr != nil {
			return nil, rerr
		}
	}
	return out, nil
}

// LoadLabels reads a JSON array of human labels.
func LoadLabels(path string) ([]Label, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var labels []Label
	if err := json.Unmarshal(data, &labels); err != nil {
		return nil, fmt.Errorf("parsing labels file %s: %w", path, err)
	}
	return labels, nil
}

// primaryInput picks the FUZZ value when present, otherwise the first key in
// sorted order, so observation/label joining has one stable key.
func primaryInput(inputs map[string]string) string {
	if v, ok := inputs["FUZZ"]; ok {
		return v
	}
	keys := make([]string, 0, len(inputs))
	for k := range inputs {
		keys = append(keys, k)
	}
	sortStrings(keys)
	if len(keys) == 0 {
		return ""
	}
	return inputs[keys[0]]
}

func trimSpace(b []byte) []byte {
	return []byte(strings.TrimSpace(string(b)))
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j-1] > s[j]; j-- {
			s[j-1], s[j] = s[j], s[j-1]
		}
	}
}

// WriteReportJSON serializes a report.
func WriteReportJSON(path string, rep Report) error {
	data, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// RenderText returns the human-readable three-way comparison.
func RenderText(rep Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Evaluation over %d entries (%d existing, %d nonexistent)\n\n", rep.Total, rep.Existing, rep.Nonexistent)
	fmt.Fprintln(&b, "strategy                 recall    precision FPR")
	row := func(name string, m Metrics) {
		fmt.Fprintf(&b, "%-24s %8.2f%% %9.2f%% %7.2f%%\n", name, m.Recall*100, m.Precision*100, m.FalsePositiveRate*100)
	}
	row("legacy status-code", rep.Legacy)
	row("multi-dim heuristics", rep.Heuristics)
	row("  heuristics (raw logic)", rep.HeuristicsRaw)
	row("human ground truth", rep.GroundTruth)
	fmt.Fprintf(&b, "\nsoft-404 detections: %d   suppressed: %d   degraded groups: %d\n", rep.Soft404Count, rep.SuppressedCount, rep.DegradedCount)
	if rep.MonotonicityRetained > 0 {
		fmt.Fprintf(&b, "monotonicity-retained (legacy-matched soft-404s kept and flagged, not silently dropped): %d\n", rep.MonotonicityRetained)
	}

	if len(rep.LegacyMisses) > 0 {
		fmt.Fprintf(&b, "\nLegacy false negatives (%d) — entries that exist but status-only matching missed:\n", len(rep.LegacyMisses))
		for _, m := range rep.LegacyMisses {
			fmt.Fprintf(&b, "  - %-20s gap: %s\n", m.Input, m.CoverageGap)
		}
	}
	if len(rep.HeuristicMisses) > 0 {
		fmt.Fprintf(&b, "\nHeuristic false negatives (%d):\n", len(rep.HeuristicMisses))
		for _, m := range rep.HeuristicMisses {
			fmt.Fprintf(&b, "  - %-20s gap: %s\n", m.Input, m.CoverageGap)
		}
	}
	if len(rep.LegacyFalseAlarms) > 0 {
		fmt.Fprintf(&b, "\nLegacy false positives (%d):\n", len(rep.LegacyFalseAlarms))
		for _, fa := range rep.LegacyFalseAlarms {
			fmt.Fprintf(&b, "  - %s\n", fa.Input)
		}
	}
	if len(rep.HeuristicFalseAlarms) > 0 {
		fmt.Fprintf(&b, "\nHeuristic false positives (%d):\n", len(rep.HeuristicFalseAlarms))
		for _, fa := range rep.HeuristicFalseAlarms {
			fmt.Fprintf(&b, "  - %-20s %s\n", fa.Input, strings.Join(fa.Reasons, "; "))
		}
	}
	return b.String()
}

// DimensionSummary explains which dimensions fired across a verdict set;
// handy for the report's appendix.
func DimensionSummary(obs []Observation) map[string]int {
	counts := map[string]int{}
	for _, o := range obs {
		if o.Verdict == nil {
			continue
		}
		for _, ev := range o.Verdict.Evidence {
			if ev.Fired {
				counts[ev.Dimension]++
			}
			if ev.Skipped {
				counts[ev.Dimension+":skipped"]++
			}
		}
	}
	_ = heuristics.DimStatus // keep import meaningful for callers using constants
	return counts
}
