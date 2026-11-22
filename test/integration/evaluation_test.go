package integration

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ffuf/ffuf/v2/pkg/assembly"
	"github.com/ffuf/ffuf/v2/pkg/decision"
	"github.com/ffuf/ffuf/v2/pkg/engine"
	"github.com/ffuf/ffuf/v2/pkg/evaluation"
	"github.com/ffuf/ffuf/v2/pkg/evidence"
	"github.com/ffuf/ffuf/v2/pkg/ffuf"
	"github.com/ffuf/ffuf/v2/pkg/filter"
)

// TestEvaluation_ThreeWayAcceptance is the acceptance comparison. One
// dictionary is scanned once against the mock target with both the legacy
// status matcher and the heuristic engine active; every request is written to
// an evidence log. The log is then joined with a human-labeled ground-truth
// set and the three strategies (legacy / heuristics / ground truth) are scored
// for recall and false-positive rate, with every miss attributed.
func TestEvaluation_ThreeWayAcceptance(t *testing.T) {
	target := startTarget(t)
	// Dictionary mixing every false-negative class plus junk.
	words := []string{
		"login-redirect", // exists, 302
		"forbidden-real", // exists, 403
		"waf-block",      // exists, 200 custom WAF body
		"soft-real",      // exists, 200 near-junk body
		"junk-a",         // does not exist: soft-404 200
		"junk-b",         // does not exist: soft-404 200
		"junk-c",         // does not exist: soft-404 200
	}
	labels := []evaluation.Label{
		{Input: "login-redirect", Exists: true, Note: "302 to login"},
		{Input: "forbidden-real", Exists: true, Note: "403 but real"},
		{Input: "waf-block", Exists: true, Note: "WAF custom page"},
		{Input: "soft-real", Exists: true, Note: "near-junk real page"},
		{Input: "junk-a", Exists: false},
		{Input: "junk-b", Exists: false},
		{Input: "junk-c", Exists: false},
	}

	logPath := filepath.Join(t.TempDir(), "evidence.jsonl")
	_, job := buildHeuristicJob(t, target.URL, words, "", "200-299")
	rec, err := evidence.OpenRecorder(logPath)
	if err != nil {
		t.Fatal(err)
	}
	job.Evidence = &decision.EvidenceAdapter{Recorder: rec}
	job.Decider.(*decision.Decider).PrewarmBaselines()
	job.Start()
	if err := rec.Close(); err != nil {
		t.Fatal(err)
	}

	obs, err := evaluation.LoadEvidence(logPath)
	if err != nil {
		t.Fatalf("load evidence: %v", err)
	}
	rep := evaluation.Evaluate(labels, obs)

	// Ground-truth row is the self-check.
	if rep.GroundTruth.Recall != 1.0 || rep.GroundTruth.FalsePositiveRate != 0 {
		t.Fatalf("ground-truth row not perfect: %+v", rep.GroundTruth)
	}

	// Legacy status-only (200-299): the 302 and 403 resources are missed, while
	// the three soft-404 junk pages are false positives.
	if rep.Legacy.Recall >= rep.Heuristics.Recall {
		t.Errorf("heuristics must improve recall over legacy: legacy=%f heur=%f",
			rep.Legacy.Recall, rep.Heuristics.Recall)
	}
	// The engine's OWN logic must drive the false-positive rate down: every
	// soft-404 it recognizes is a raw true negative. The operator-visible
	// Heuristics row can retain some legacy-matched soft-404s, but only as
	// explicitly flagged monotonicity entries.
	if rep.HeuristicsRaw.FalsePositiveRate >= rep.Legacy.FalsePositiveRate {
		t.Errorf("raw heuristic logic must cut the false-positive rate: legacy FPR=%f raw FPR=%f",
			rep.Legacy.FalsePositiveRate, rep.HeuristicsRaw.FalsePositiveRate)
	}
	if rep.MonotonicityRetained == 0 {
		t.Error("expected monotonicity-retained legacy soft-404 matches to be counted")
	}

	// Every legacy false negative must be listed individually with a reason.
	if len(rep.LegacyMisses) == 0 {
		t.Error("expected enumerated legacy misses, got none")
	}
	for _, m := range rep.LegacyMisses {
		if m.CoverageGap == "" {
			t.Errorf("legacy miss %q has no coverage-gap attribution", m.Input)
		}
	}

	// The rendered report must contain all three strategy rows for reviewers.
	text := evaluation.RenderText(rep)
	for _, row := range []string{"legacy status-code", "multi-dim heuristics", "human ground truth"} {
		if !strings.Contains(text, row) {
			t.Errorf("report missing row %q", row)
		}
	}
	t.Logf("\n%s", text)
}

// TestEvaluation_LegacyOnlyModeUnchanged pins the default behavior: with the
// decision layer disabled, evidence records carry legacy verdicts only and the
// evaluation reduces to the legacy confusion matrix.
func TestEvaluation_LegacyOnlyModeUnchanged(t *testing.T) {
	target := startTarget(t)
	words := []string{"login-redirect", "junk-a"}
	opts := ffuf.NewConfigOptions()
	opts.HTTP.URL = target.URL + "/md/FUZZ"
	opts.Input.Wordlists = []string{writeWordlist(t, words)}
	opts.General.Quiet = true
	opts.General.Noninteractive = true

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	conf, err := ffuf.ConfigFromOptions(opts, ctx, cancel)
	if err != nil {
		t.Fatal(err)
	}
	conf.MatcherManager = filter.NewMatcherManager()
	_ = conf.MatcherManager.AddMatcher("status", "200-299")

	job, err := buildPlainJob(conf)
	if err != nil {
		t.Fatal(err)
	}
	out := &capture{}
	job.Output = out
	job.Start()

	// No Decider installed: default path. The 302 must be absent from hits.
	if contains(out.inputs(), "login-redirect") {
		t.Error("legacy-only mode unexpectedly matched the 302 resource")
	}
	// The junk soft-404 (200) is matched by the legacy rule, as before the change.
	if !contains(out.inputs(), "junk-a") {
		t.Error("legacy 200 match behavior changed; default mode must be unchanged")
	}
}

func buildPlainJob(conf *ffuf.Config) (*engine.Job, error) {
	return assembly.BuildJob(conf)
}
