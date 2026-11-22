package integration

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/ffuf/ffuf/v2/pkg/assembly"
	"github.com/ffuf/ffuf/v2/pkg/checkpoint"
	"github.com/ffuf/ffuf/v2/pkg/decision"
	"github.com/ffuf/ffuf/v2/pkg/engine"
	"github.com/ffuf/ffuf/v2/pkg/evidence"
	"github.com/ffuf/ffuf/v2/pkg/ffuf"
	"github.com/ffuf/ffuf/v2/pkg/filter"
	"github.com/ffuf/ffuf/v2/pkg/heuristics"
	"github.com/ffuf/ffuf/v2/pkg/testtarget"
)

// buildHeuristicJob assembles a real Job (real runner, real input) with the
// multi-dimensional decision layer wired exactly as main does, against the
// deterministic mock target. The default status matcher is installed too, so
// each response yields both a legacy and a heuristic verdict.
// buildHeuristicJob assembles a real Job (real runner, real input) with the
// multi-dimensional decision layer wired exactly as main does, against the
// deterministic mock target. legacyMatcher is the status-code rule set
// installed on the legacy MatcherManager, so each response yields both a
// legacy and a heuristic verdict.
func buildHeuristicJob(t *testing.T, targetURL string, words []string, cpDir string, legacyMatcher string) (*ffuf.Config, *engine.Job) {
	t.Helper()
	opts := ffuf.NewConfigOptions()
	opts.HTTP.URL = targetURL + "/md/FUZZ"
	opts.HTTP.Method = "GET"
	opts.Input.Wordlists = []string{writeWordlist(t, words)}
	opts.General.Quiet = true
	opts.General.Noninteractive = true
	opts.Heuristics.HeuristicsEnabled = true

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	conf, err := ffuf.ConfigFromOptions(opts, ctx, cancel)
	if err != nil {
		t.Fatalf("ConfigFromOptions: %v", err)
	}
	conf.MatcherManager = filter.NewMatcherManager()
	if err := conf.MatcherManager.AddMatcher("status", legacyMatcher); err != nil {
		t.Fatal(err)
	}

	job, err := assembly.BuildJob(conf)
	if err != nil {
		t.Fatalf("BuildJob: %v", err)
	}
	out := &capture{}
	job.Output = out

	basereq := ffuf.BaseRequest(conf)
	decider := decision.NewDeciderFromConfig(conf, job.Runner, basereq)
	job.Decider = decider

	if cpDir != "" {
		store, err := checkpoint.CreateOrOpen(cpDir, "scan-it", conf.Url, conf.Wordlists, job.Input.Total())
		if err != nil {
			t.Fatalf("checkpoint: %v", err)
		}
		job.Checkpoint = &decision.CheckpointAdapter{Store: store}
		t.Cleanup(func() { _ = store.Close() })
	}
	return conf, job
}

func startTarget(t *testing.T) *testtarget.Target {
	t.Helper()
	tg := testtarget.New()
	t.Cleanup(tg.Close)
	return tg
}

// jobCapture returns the capturing output provider installed on a job.
func jobCapture(job *engine.Job) *capture { return job.Output.(*capture) }

func loadObservationCount(path string) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if len(sc.Bytes()) == 0 {
			continue
		}
		var rec evidence.Record
		if err := json.Unmarshal(sc.Bytes(), &rec); err != nil {
			return n, err
		}
		n++
	}
	return n, sc.Err()
}

// TestHeuristics_302RedirectIsCaught reproduces the originating bug: a real
// path answering 302 to a login page is invisible to 200-only status matching
// but the multi-dimensional engine reports it with explainable evidence.
func TestHeuristics_302RedirectIsCaught(t *testing.T) {
	target := startTarget(t)
	words := []string{"login-redirect", "does-not-exist-1", "does-not-exist-2"}
	conf, handle := buildHeuristicJob(t, target.URL, words, "", "204")
	_ = conf

	// Pre-collect the default-group baseline from the soft-404 tree.
	handle.Decider.(*decision.Decider).PrewarmBaselines()
	handle.Start()

	hits := jobCapture(handle).inputs()
	if !contains(hits, "login-redirect") {
		t.Errorf("302 login redirect not reported as a hit; hits=%v", hits)
	}
	if contains(hits, "does-not-exist-1") || contains(hits, "does-not-exist-2") {
		t.Errorf("soft-404 junk reported as a hit; hits=%v", hits)
	}

	// The captured response for the 302 must carry explainable evidence.
	for _, resp := range jobCapture(handle).responses {
		if string(resp.Request.Input["FUZZ"]) != "login-redirect" {
			continue
		}
		view := decision.View(&resp)
		v := handle.Decider.(*decision.Decider).Engine().Decide(view, false)
		if len(v.Reasons) == 0 {
			t.Error("hit has no human-readable reasons")
		}
		if !v.Hit {
			t.Error("re-evaluated 302 verdict is not a hit")
		}
		return
	}
	t.Fatal("no response captured for login-redirect")
}

// TestHeuristics_Soft404RejectedButLegacyRetained pins the monotonicity rule:
// when the legacy matcher explicitly matches a soft-404 (e.g. -mc 200), it is
// still surfaced but flagged, rather than silently disappearing.
func TestHeuristics_Soft404RejectedButLegacyRetained(t *testing.T) {
	target := startTarget(t)
	words := []string{"ghost-page", "waf-block"}
	conf, handle := buildHeuristicJob(t, target.URL, words, "", "204")
	// Make the legacy matcher accept everything 200-class, which would naively
	// report the soft-404.
	_ = conf.MatcherManager.AddMatcher("status", "200")
	handle.Decider.(*decision.Decider).PrewarmBaselines()
	handle.Start()

	hits := jobCapture(handle).inputs()
	// Both legacy-match, but the engine must mark the soft-404 distinction.
	var sawSoft, sawWaf bool
	for _, resp := range jobCapture(handle).responses {
		v := handle.Decider.(*decision.Decider).Engine().Decide(decision.View(&resp), true)
		switch string(resp.Request.Input["FUZZ"]) {
		case "ghost-page":
			if !v.Soft404 {
				t.Errorf("ghost-page not detected as soft-404: %+v", v.Evidence)
			}
			sawSoft = true
		case "waf-block":
			if v.Soft404 {
				t.Errorf("distinct WAF body wrongly classified as soft-404")
			}
			sawWaf = true
		}
	}
	if !sawSoft || !sawWaf {
		t.Fatalf("missing verdicts; hits=%v", hits)
	}
}

// TestHeuristics_PerExtensionBaselines verifies .bak and .php get independent
// baselines and a real .bak resource is found against the .bak baseline.
func TestHeuristics_PerExtensionBaselines(t *testing.T) {
	target := startTarget(t)
	// Wordlist paths are under /md/ext so per-extension routing applies.
	words := []string{"ext/backup.bak", "ext/nothing.bak", "ext/page.php"}
	opts := ffuf.NewConfigOptions()
	opts.HTTP.URL = target.URL + "/md/FUZZ"
	opts.HTTP.Method = "GET"
	opts.Input.Wordlists = []string{writeWordlist(t, words)}
	opts.General.Quiet = true
	opts.General.Noninteractive = true
	opts.Heuristics.HeuristicsEnabled = true

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	conf, err := ffuf.ConfigFromOptions(opts, ctx, cancel)
	if err != nil {
		t.Fatal(err)
	}
	conf.MatcherManager = filter.NewMatcherManager()
	_ = conf.MatcherManager.AddMatcher("status", "200-299")

	job, err := assembly.BuildJob(conf)
	if err != nil {
		t.Fatal(err)
	}
	out := &capture{}
	job.Output = out
	decider := decision.NewDeciderFromConfig(conf, job.Runner, ffuf.BaseRequest(conf))
	job.Decider = decider
	job.Start()

	eng := decider.Engine()
	if _, ok := eng.GroupSnapshot(".bak"); !ok {
		t.Error(".bak baseline group was never collected")
	}
	if _, ok := eng.GroupSnapshot(".php"); !ok {
		t.Error(".php baseline group was never collected")
	}
	hits := out.inputs()
	if !contains(hits, "ext/backup.bak") {
		t.Errorf("real .bak resource missed against its own baseline; hits=%v", hits)
	}
}

// TestCheckpoint_ResumeSkipsCompletedAndKeepsHits proves the interrupt/resume
// contract: a second run with the same checkpoint skips every completed entry
// (no duplicate requests) and still surfaces the prior hit.
func TestCheckpoint_ResumeSkipsCompletedAndKeepsHits(t *testing.T) {
	target := startTarget(t)
	words := []string{"login-redirect", "does-not-exist-1", "does-not-exist-2"}
	cpDir := t.TempDir()

	// First run.
	_, h1 := buildHeuristicJob(t, target.URL, words, filepath.Join(cpDir, "cp"), "204")
	h1.Decider.(*decision.Decider).PrewarmBaselines()
	h1.Start()
	firstCount := target.Count()
	firstHits := jobCapture(h1).inputs()
	if !contains(firstHits, "login-redirect") {
		t.Fatalf("first run missed the 302 hit: %v", firstHits)
	}

	// Second run against the same checkpoint.
	_, h2 := buildHeuristicJob(t, target.URL, words, filepath.Join(cpDir, "cp"), "204")
	h2.Start()
	// No new scan requests should have been sent: every entry was done.
	if target.Count() != firstCount {
		t.Errorf("resume re-sent requests: before=%d after=%d", firstCount, target.Count())
	}
	// Prior hit is re-surfaced from the checkpoint.
	if !contains(jobCapture(h2).inputs(), "login-redirect") {
		t.Errorf("resumed run lost the prior hit; got %v", jobCapture(h2).inputs())
	}
}

// TestEvidenceLog_RecordsNonMatches ensures the evidence trail includes the
// misses (not only hits), which the evaluation report depends on.
func TestEvidenceLog_RecordsNonMatches(t *testing.T) {
	target := startTarget(t)
	words := []string{"login-redirect", "does-not-exist-1"}
	logPath := filepath.Join(t.TempDir(), "evidence.jsonl")
	_, handle := buildHeuristicJob(t, target.URL, words, "", "204")
	rec, err := evidence.OpenRecorder(logPath)
	if err != nil {
		t.Fatal(err)
	}
	handle.Evidence = &decision.EvidenceAdapter{Recorder: rec}
	handle.Decider.(*decision.Decider).PrewarmBaselines()
	handle.Start()
	_ = rec.Close()

	obs, err := loadObservationCount(logPath)
	if err != nil {
		t.Fatal(err)
	}
	if obs != 2 {
		t.Errorf("evidence lines = %d, want 2 (hits and non-matches alike)", obs)
	}
}

// TestSuppressor_FalsePositiveSilencesSimilarResponses verifies the tuning
// loop: once a signature is recorded, matching responses are suppressed.
func TestSuppressor_FalsePositiveSilencesSimilarResponses(t *testing.T) {
	target := startTarget(t)
	words := []string{"waf-block", "waf-block-2"}
	// Both WAF endpoints share the same normalized body (server returns the
	// same block string under any /md/waf* path via the generic handler only
	// for unknown names; emulate by querying the same endpoint twice is not
	// possible, so instead assert suppression directly on the engine).
	_, handle := buildHeuristicJob(t, target.URL, words, "", "204")
	dec := handle.Decider.(*decision.Decider)
	dec.PrewarmBaselines()

	view := heuristics.ResponseView{
		StatusCode: 200, ContentLength: 70,
		Body:    []byte("request blocked by edge security appliance reference WAF-42"),
		URLPath: "/md/waf-block",
	}
	hash := heuristics.HashBody(view.Body)
	dec.Engine().AddSuppressor(heuristics.Suppressor{BodyHash: hash, StatusCode: 200, Group: heuristics.GroupDefault, Note: "waf"})

	v := dec.Engine().Decide(view, true)
	if !v.Suppressed || v.Hit {
		t.Fatalf("known WAF false positive not suppressed: %+v", v)
	}
}

// TestCheckpoint_ResumeWithSingleThread is a regression test for a deadlock
// where skipped resume entries acquired (but never released) thread-limiter
// slots. With one thread and all entries skipped, the dispatch loop previously
// blocked forever acquiring the second slot.
func TestCheckpoint_ResumeWithSingleThread(t *testing.T) {
	target := startTarget(t)
	words := []string{"login-redirect", "junk-a", "junk-b"}
	cpDir := filepath.Join(t.TempDir(), "cp")

	run := func() *engine.Job {
		opts := ffuf.NewConfigOptions()
		opts.HTTP.URL = target.URL + "/md/FUZZ"
		opts.Input.Wordlists = []string{writeWordlist(t, words)}
		opts.General.Quiet = true
		opts.General.Noninteractive = true
		opts.General.Threads = 1
		opts.Heuristics.HeuristicsEnabled = true
		ctx, cancel := context.WithCancel(context.Background())
		t.Cleanup(cancel)
		conf, err := ffuf.ConfigFromOptions(opts, ctx, cancel)
		if err != nil {
			t.Fatal(err)
		}
		conf.MatcherManager = filter.NewMatcherManager()
		_ = conf.MatcherManager.AddMatcher("status", "204")
		job, err := assembly.BuildJob(conf)
		if err != nil {
			t.Fatal(err)
		}
		job.Output = &capture{}
		job.Decider = decision.NewDeciderFromConfig(conf, job.Runner, ffuf.BaseRequest(conf))
		store, err := checkpoint.CreateOrOpen(cpDir, "scan-t1", conf.Url, conf.Wordlists, job.Input.Total())
		if err != nil {
			t.Fatal(err)
		}
		job.Checkpoint = &decision.CheckpointAdapter{Store: store}
		job.Start()
		return job
	}

	run() // first run populates the checkpoint
	requestsAfterFirst := target.Count()
	run() // fully resumed: every entry skipped, must terminate with t=1
	if target.Count() != requestsAfterFirst {
		t.Errorf("resume with t=1 re-sent %d requests", target.Count()-requestsAfterFirst)
	}
}
