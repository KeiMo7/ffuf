package heuristics

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestNormalizeBody_StripsMarkupAndNormalizes(t *testing.T) {
	body := []byte(`<html><script>var x=1;</script><body><P>Hello   WORLD</p><style>.a{}</style></body></html>`)
	got := NormalizeBody(body)
	want := []string{"hello", "world"}
	if strings.Join(got, " ") != strings.Join(want, " ") {
		t.Fatalf("normalized = %v, want %v", got, want)
	}
}

func TestHashBody_StableAcrossMarkupWhitespace(t *testing.T) {
	a := []byte("<div>Page not found</div>")
	b := []byte("<div class='x'>Page   not\nfound</div>")
	if HashBody(a) != HashBody(b) {
		t.Fatalf("equivalent visible text produced different hashes")
	}
}

func TestSimilarity_IdenticalAndDifferent(t *testing.T) {
	base := []byte("<p>the quick brown fox jumps over the lazy dog today</p>")
	sim, err := Similarity(context.Background(), base, base, 3)
	if err != nil || sim != 1.0 {
		t.Fatalf("identical bodies: sim=%f err=%v, want 1.0 nil", sim, err)
	}
	other := []byte("<p>completely unrelated content about marine biology research vessels</p>")
	sim, err = Similarity(context.Background(), base, other, 3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if sim > 0.1 {
		t.Fatalf("different bodies too similar: %f", sim)
	}
}

func TestSimilarity_TimeoutSkipsDimension(t *testing.T) {
	// A pre-cancelled context must surface ErrSimilarityTimeout so the caller
	// degrades to "skip dimension", not "drop response".
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := Similarity(ctx, []byte("a b c d e f"), []byte("x y z w q r"), 2)
	if err != ErrSimilarityTimeout {
		t.Fatalf("err = %v, want ErrSimilarityTimeout", err)
	}
}

func TestSimilarity_EmptyBodiesAreIdentical(t *testing.T) {
	sim, err := Similarity(context.Background(), nil, []byte("  "), 3)
	if err != nil || sim != 1.0 {
		t.Fatalf("empty bodies: sim=%f err=%v, want 1.0 nil", sim, err)
	}
}

func TestGroupFor_ExtensionCasedAndDefault(t *testing.T) {
	cases := map[string]string{
		"/admin":      GroupDefault,
		"/admin/":     GroupDefault,
		"/backup.bak": ".bak",
		"/INDEX.PHP":  ".php",
		"/a.b/c":      GroupDefault,
		"/x.php.old":  ".old",
	}
	for path, want := range cases {
		if got := GroupFor(path); got != want {
			t.Errorf("GroupFor(%q) = %q, want %q", path, got, want)
		}
	}
}

func TestBaselineGroup_MedianAndDominantHash(t *testing.T) {
	g := BaselineGroup{Points: []BaselinePoint{
		{ContentLength: 100, Duration: Duration{10 * time.Millisecond}, BodyHash: "aaa"},
		{ContentLength: 120, Duration: Duration{20 * time.Millisecond}, BodyHash: "aaa"},
		{ContentLength: 300, Duration: Duration{30 * time.Millisecond}, BodyHash: "bbb"},
	}}
	if g.MedianLength() != 120 {
		t.Errorf("median length = %d, want 120", g.MedianLength())
	}
	if g.MedianDuration() != 20*time.Millisecond {
		t.Errorf("median duration = %v, want 20ms", g.MedianDuration())
	}
	h, n := g.DominantHash()
	if h != "aaa" || n != 2 {
		t.Errorf("dominant = %s/%d, want aaa/2", h, n)
	}
}

// newTestEngine builds an engine with deterministic fast config.
func newTestEngine() *Engine {
	cfg := DefaultConfig()
	cfg.BaselineSamples = 3
	cfg.SimilarityTimeout = 100 * time.Millisecond
	return NewEngine(cfg)
}

// probe returns a synthetic response for baseline collection.
func makeProbe(status int64, length int64, body string, d time.Duration) ResponseView {
	return ResponseView{
		StatusCode: status, ContentLength: length, Duration: d,
		Body: []byte(body), URLPath: "/x",
	}
}

func TestEnsureBaseline_CollectsOnceAndShares(t *testing.T) {
	e := newTestEngine()
	calls := 0
	probe := func(p string) (ResponseView, error) {
		calls++
		return makeProbe(404, 50, "not found page", 5*time.Millisecond), nil
	}
	// Two concurrent Ensure calls must collapse onto one collection.
	done := make(chan struct{})
	go func() { e.EnsureBaseline(GroupDefault, probe); close(done) }()
	e.EnsureBaseline(GroupDefault, probe)
	<-done
	if calls != 3 {
		t.Fatalf("probe calls = %d, want exactly 3 (one collection)", calls)
	}
	g, ok := e.GroupSnapshot(GroupDefault)
	if !ok || !g.Ready || g.Degraded {
		t.Fatalf("group not ready: %+v ok=%v", g, ok)
	}
}

func TestEnsureBaseline_FailureDegradesGroup(t *testing.T) {
	e := newTestEngine()
	e.EnsureBaseline(GroupDefault, func(p string) (ResponseView, error) {
		return ResponseView{}, context.DeadlineExceeded
	})
	g, _ := e.GroupSnapshot(GroupDefault)
	if !g.Degraded || g.Failure == "" {
		t.Fatalf("expected degraded group with failure, got %+v", g)
	}
}

func TestDecide_StatusDifferenceFires(t *testing.T) {
	e := newTestEngine()
	e.EnsureBaseline(GroupDefault, func(p string) (ResponseView, error) {
		return makeProbe(404, 50, "not found page", 5*time.Millisecond), nil
	})
	// 302 to login: the exact false-negative scenario from the bug report.
	v := e.Decide(makeProbe(302, 0, "<a href=/login>login</a>", 6*time.Millisecond).withPath("/admin"), false)
	if !v.Hit {
		t.Fatalf("302 with different status/body was not a hit; reasons=%v", v.Reasons)
	}
	if !evidenceFired(v, DimStatus) {
		t.Errorf("status dimension did not fire: %+v", v.Evidence)
	}
}

func TestDecide_Soft404_NotAHit(t *testing.T) {
	e := newTestEngine()
	// Every nonexistent probe returns 200 with the same "page not found" body.
	e.EnsureBaseline(GroupDefault, func(p string) (ResponseView, error) {
		return makeProbe(200, 80, "sorry this page does not exist", 5*time.Millisecond), nil
	})
	v := e.Decide(makeProbe(200, 80, "sorry this page does not exist", 5*time.Millisecond).withPath("/ghost"), false)
	if v.Hit {
		t.Fatalf("soft-404 reported as hit: %+v", v.Reasons)
	}
	if !v.Soft404 {
		t.Fatalf("soft-404 not detected")
	}
}

func TestDecide_Soft404_LegacyMatchRetainedMonotonically(t *testing.T) {
	e := newTestEngine()
	e.EnsureBaseline(GroupDefault, func(p string) (ResponseView, error) {
		return makeProbe(200, 80, "sorry this page does not exist", 5*time.Millisecond), nil
	})
	// Legacy says match (e.g. -mc 200): monotonicity keeps it, flagged for review.
	v := e.Decide(makeProbe(200, 80, "sorry this page does not exist", 5*time.Millisecond).withPath("/ghost"), true)
	if !v.Hit {
		t.Fatalf("legacy-matched soft-404 must be retained by monotonicity")
	}
}

func TestDecide_LengthAndSimilarityCatchStatusEqualMiss(t *testing.T) {
	e := newTestEngine()
	e.EnsureBaseline(GroupDefault, func(p string) (ResponseView, error) {
		return makeProbe(200, 100, "the standard error page body for missing things", 5*time.Millisecond), nil
	})
	// Same 200 status, but a genuinely different, much larger body.
	view := ResponseView{
		StatusCode: 200, ContentLength: 5000, Duration: 6 * time.Millisecond,
		Body: []byte("secret admin dashboard with completely different content " + strings.Repeat("data ", 200)),
	}.withPath("/admin")
	v := e.Decide(view, false)
	if !v.Hit {
		t.Fatalf("different-body 200 response missed; reasons=%v", v.Reasons)
	}
	if !evidenceFired(v, DimLength) {
		t.Errorf("length dimension did not fire")
	}
	if !evidenceFired(v, DimSimilarity) {
		t.Errorf("similarity dimension did not fire")
	}
}

func TestDecide_TimingAloneNeverHits(t *testing.T) {
	e := newTestEngine()
	// Two distinct probe bodies stop a unanimous soft-404 template from forming.
	// The observed body is byte-identical to the first probe with a different
	// latency, so ONLY the timing dimension can deviate.
	bodies := []string{
		"the baseline page body content used for timing dimension tests",
		"a second different probe body so the group has no single template hash",
	}
	n := 0
	e.EnsureBaseline(GroupDefault, func(p string) (ResponseView, error) {
		body := bodies[n%len(bodies)]
		n++
		return makeProbe(200, int64(len(body)), body, 5*time.Millisecond), nil
	})
	view := ResponseView{
		StatusCode: 200, ContentLength: int64(len(bodies[0])), Duration: 200 * time.Millisecond,
		Body: []byte(bodies[0]),
	}.withPath("/slow")
	v := e.Decide(view, false)
	if v.Hit {
		t.Fatalf("timing-only deviation produced a hit; score=%v reasons=%v", v.Score, v.Reasons)
	}
	if !evidenceFired(v, DimTime) {
		t.Errorf("timing dimension should still fire (as an auxiliary signal): %+v", v.Evidence)
	}
	if evidenceFired(v, DimSimilarity) || evidenceFired(v, DimLength) || evidenceFired(v, DimStatus) {
		t.Errorf("a hard dimension fired in a timing-only scenario: %+v", v.Evidence)
	}
	if v.Score >= e.cfg.ScoreThreshold {
		t.Errorf("timing-only score %v reached hit threshold %v", v.Score, e.cfg.ScoreThreshold)
	}
}

func TestDecide_DegradedFallsBackToLegacy(t *testing.T) {
	e := newTestEngine()
	e.MarkBaselineFailed(GroupDefault, context.DeadlineExceeded)
	v := e.Decide(makeProbe(302, 0, "x", 5*time.Millisecond).withPath("/admin"), true)
	if !v.Hit || !v.Degraded {
		t.Fatalf("degraded group did not honor legacy match: %+v", v)
	}
}

func TestDecide_NoBaselineUsesLegacyAndMarksDegraded(t *testing.T) {
	e := newTestEngine()
	v := e.Decide(makeProbe(200, 10, "x", 5*time.Millisecond).withPath("/anything"), true)
	if !v.Hit || !v.Degraded {
		t.Fatalf("missing baseline should degrade to legacy: %+v", v)
	}
}

func TestSuppressor_MarksAndSuppresses(t *testing.T) {
	e := newTestEngine()
	e.EnsureBaseline(GroupDefault, func(p string) (ResponseView, error) {
		return makeProbe(404, 50, "not found page", 5*time.Millisecond), nil
	})
	body := []byte("WAF block page custom")
	hash := HashBody(body)
	e.AddSuppressor(Suppressor{BodyHash: hash, StatusCode: 403, Group: GroupDefault, Note: "waf"})
	v := e.Decide(ResponseView{StatusCode: 403, ContentLength: 99, Body: body, Duration: 5 * time.Millisecond}.withPath("/x"), false)
	if !v.Suppressed || v.Hit {
		t.Fatalf("suppressed response reported as hit: %+v", v)
	}
	if v.SuppressorID == "" {
		t.Errorf("suppressor id missing")
	}
	if !e.RemoveSuppressor(v.SuppressorID) {
		t.Errorf("remove suppressor failed")
	}
}

func TestPerExtensionGroups_IndependentBaselines(t *testing.T) {
	e := newTestEngine()
	// .php probes 404 with one body; .bak probes 403 (different extension routing).
	e.EnsureBaseline(".php", func(p string) (ResponseView, error) {
		return makeProbe(404, 50, "php not found", 5*time.Millisecond), nil
	})
	e.EnsureBaseline(".bak", func(p string) (ResponseView, error) {
		return makeProbe(403, 50, "forbidden extension", 5*time.Millisecond), nil
	})
	php, _ := e.GroupSnapshot(".php")
	bak, _ := e.GroupSnapshot(".bak")
	if php.StatusSet()[403] || bak.StatusSet()[404] {
		t.Fatalf("per-extension baselines leaked across groups: php=%v bak=%v", php.StatusSet(), bak.StatusSet())
	}
	// A .bak response with 200 must fire against the .bak 403 baseline.
	v := e.Decide(makeProbe(200, 500, "real backup contents here", 5*time.Millisecond).withPath("/db.bak"), false)
	if !v.Hit {
		t.Fatalf(".bak outlier missed against its own baseline: %v", v.Reasons)
	}
}

func evidenceFired(v Verdict, dim string) bool {
	for _, ev := range v.Evidence {
		if ev.Dimension == dim && ev.Fired {
			return true
		}
	}
	return false
}

// withPath returns the view with URLPath set (test helper).
func (rv ResponseView) withPath(p string) ResponseView {
	rv.URLPath = p
	return rv
}
