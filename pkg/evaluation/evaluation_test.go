package evaluation

import (
	"strings"
	"testing"

	"github.com/ffuf/ffuf/v2/pkg/heuristics"
)

// verdict builds a verdict with explicit per-dimension evidence.
func verdict(hit bool, dims ...heuristics.Evidence) *heuristics.Verdict {
	return &heuristics.Verdict{Hit: hit, Group: heuristics.GroupDefault, Evidence: dims, Reasons: []string{"test"}}
}

func fired(dim string) heuristics.Evidence {
	return heuristics.Evidence{Dimension: dim, Fired: true, Score: 1, Reason: dim + " fired"}
}

func skipped(dim string) heuristics.Evidence {
	return heuristics.Evidence{Dimension: dim, Skipped: true, Reason: dim + " skipped"}
}

func TestEvaluate_ThreeWayTableAndMissAttribution(t *testing.T) {
	// Ground truth: three existing, two nonexistent.
	labels := []Label{
		{Input: "login-redirect", Exists: true, Note: "302 to login"},
		{Input: "forbidden-but-real", Exists: true},
		{Input: "soft404-real", Exists: true},
		{Input: "junk-1", Exists: false},
		{Input: "junk-2", Exists: false},
	}
	obs := []Observation{
		// 302 case: legacy status matcher misses, heuristics catches via status diff.
		{Input: "login-redirect", LegacyMatch: false, Verdict: verdict(true, fired(heuristics.DimStatus))},
		// 403 case: legacy happens to accept 403, both match.
		{Input: "forbidden-but-real", LegacyMatch: true, Verdict: verdict(true, fired(heuristics.DimLength))},
		// A genuine resource that BOTH miss: similarity dimension was skipped.
		{Input: "soft404-real", LegacyMatch: false, Verdict: verdict(false, skipped(heuristics.DimSimilarity))},
		// Soft-404 junk that legacy wrongly matches (200), heuristics correctly rejects.
		{Input: "junk-1", LegacyMatch: true, Verdict: verdict(false)},
		// Correctly rejected by both.
		{Input: "junk-2", LegacyMatch: false, Verdict: verdict(false)},
	}

	rep := Evaluate(labels, obs)

	if rep.Total != 5 || rep.Existing != 3 || rep.Nonexistent != 2 {
		t.Fatalf("counts wrong: %+v", rep)
	}

	// Legacy: TP=1 (forbidden), FN=2, FP=1 (junk-1), TN=1.
	if rep.Legacy.TruePositives != 1 || rep.Legacy.FalseNegatives != 2 ||
		rep.Legacy.FalsePositives != 1 || rep.Legacy.TrueNegatives != 1 {
		t.Errorf("legacy confusion matrix wrong: %+v", rep.Legacy)
	}
	// Recall legacy = 1/3, FPR = 1/2.
	if !near(rep.Legacy.Recall, 1.0/3.0) || !near(rep.Legacy.FalsePositiveRate, 0.5) {
		t.Errorf("legacy rates wrong: recall=%f fpr=%f", rep.Legacy.Recall, rep.Legacy.FalsePositiveRate)
	}

	// Heuristics: TP=2, FN=1, FP=0, TN=2.
	if rep.Heuristics.TruePositives != 2 || rep.Heuristics.FalseNegatives != 1 ||
		rep.Heuristics.FalsePositives != 0 || rep.Heuristics.TrueNegatives != 2 {
		t.Errorf("heuristics confusion matrix wrong: %+v", rep.Heuristics)
	}
	if !near(rep.Heuristics.Recall, 2.0/3.0) || rep.Heuristics.FalsePositiveRate != 0 {
		t.Errorf("heuristics rates wrong: recall=%f fpr=%f", rep.Heuristics.Recall, rep.Heuristics.FalsePositiveRate)
	}

	// Ground truth row is perfect by construction.
	if rep.GroundTruth.Recall != 1.0 || rep.GroundTruth.FalsePositiveRate != 0 {
		t.Errorf("ground truth row wrong: %+v", rep.GroundTruth)
	}

	// Misses are enumerated individually with a coverage gap.
	if len(rep.LegacyMisses) != 2 {
		t.Errorf("want 2 legacy misses, got %d", len(rep.LegacyMisses))
	}
	var foundGap bool
	for _, m := range rep.HeuristicMisses {
		if m.Input == "soft404-real" && strings.Contains(m.CoverageGap, heuristics.DimSimilarity) {
			foundGap = true
		}
	}
	if !foundGap {
		t.Errorf("heuristic miss not attributed to skipped similarity: %+v", rep.HeuristicMisses)
	}

	// The render must contain all three strategy rows.
	text := RenderText(rep)
	for _, want := range []string{"legacy status-code", "multi-dim heuristics", "human ground truth"} {
		if !strings.Contains(text, want) {
			t.Errorf("report text missing %q", want)
		}
	}
}

func TestEvaluate_Soft404AndSuppressedCounters(t *testing.T) {
	labels := []Label{{Input: "a", Exists: false}}
	obs := []Observation{{
		Input: "a", LegacyMatch: true,
		Verdict: &heuristics.Verdict{Hit: false, Soft404: true, Suppressed: false, Degraded: false},
	}}
	rep := Evaluate(labels, obs)
	if rep.Soft404Count != 1 {
		t.Errorf("soft404 count = %d, want 1", rep.Soft404Count)
	}
	if rep.Heuristics.FalsePositives != 0 {
		t.Errorf("a correctly rejected soft-404 must not be a false positive")
	}
}

func TestEvaluate_DegradedGroupCounts(t *testing.T) {
	labels := []Label{{Input: "a", Exists: true}}
	obs := []Observation{{
		Input: "a", LegacyMatch: true,
		Verdict: &heuristics.Verdict{Hit: true, Degraded: true},
	}}
	rep := Evaluate(labels, obs)
	if rep.DegradedCount != 1 {
		t.Errorf("degraded count = %d, want 1", rep.DegradedCount)
	}
}

func TestEvaluate_UnlabeledObservationsIgnored(t *testing.T) {
	labels := []Label{{Input: "a", Exists: true}}
	obs := []Observation{
		{Input: "a", LegacyMatch: true, Verdict: verdict(true)},
		{Input: "baseline-probe-xyz", LegacyMatch: false, Verdict: verdict(false)},
	}
	rep := Evaluate(labels, obs)
	if rep.Total != 1 {
		t.Errorf("unlabeled probe traffic distorted total: %d", rep.Total)
	}
}

func near(a, b float64) bool {
	d := a - b
	if d < 0 {
		d = -d
	}
	return d < 1e-9
}
