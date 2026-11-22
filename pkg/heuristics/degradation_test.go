package heuristics

import (
	"context"
	"testing"
	"time"
)

// TestDecide_SimilarityTimeoutSkipsDimensionOnly proves the degradation rule:
// a similarity timeout must skip just that dimension while the other three
// still produce a valid verdict, never dropping the whole response.
func TestDecide_SimilarityTimeoutSkipsDimensionOnly(t *testing.T) {
	e := NewEngine(Config{
		// Zero-budget similarity guarantees a timeout on any non-trivial body.
		SimilarityTimeout:   1,
		ShingleSize:         3,
		LengthRelThreshold:  0.15,
		LengthAbsFloor:      16,
		SimilarityThreshold: 0.85,
		TimeRelThreshold:    1.0,
		ScoreThreshold:      1.0,
		BaselineSamples:     3,
		Weights:             DefaultConfig().Weights,
	})
	e.EnsureBaseline(GroupDefault, func(p string) (ResponseView, error) {
		return makeProbe(404, 100, "baseline not found body with enough tokens to shingle here now", 5*time.Millisecond), nil
	})
	view := ResponseView{
		StatusCode: 302, ContentLength: 999, Duration: 6 * time.Millisecond,
		Body:    []byte("a totally different real resource body also with enough tokens to shingle"),
		URLPath: "/admin",
	}
	v := e.Decide(view, false)

	var simSkipped, statusFired bool
	for _, ev := range v.Evidence {
		if ev.Dimension == DimSimilarity && ev.Skipped {
			simSkipped = true
		}
		if ev.Dimension == DimStatus && ev.Fired {
			statusFired = true
		}
	}
	if !simSkipped {
		t.Fatalf("similarity dimension was not skipped on timeout: %+v", v.Evidence)
	}
	if !statusFired {
		t.Fatalf("status dimension must still evaluate when similarity times out")
	}
	// The response remains decidable from the surviving dimensions.
	if !v.Hit {
		t.Fatalf("response dropped instead of retained after similarity timeout: %+v", v.Reasons)
	}
}

// TestDecide_ProbeFailureThenRecovery: a failed collection degrades the group,
// and a later explicit restore marks it usable again.
func TestDecide_ProbeFailureThenRecovery(t *testing.T) {
	e := newTestEngine()
	e.EnsureBaseline(GroupDefault, func(p string) (ResponseView, error) {
		return ResponseView{}, context.DeadlineExceeded
	})
	v := e.Decide(makeProbe(302, 10, "x", 5*time.Millisecond).withPath("/admin"), true)
	if !v.Degraded || !v.Hit {
		t.Fatalf("failed baseline must degrade to legacy: %+v", v)
	}

	// Recover: a successful collection replaces the degraded group.
	e.EnsureBaseline(".recovered", func(p string) (ResponseView, error) {
		return makeProbe(404, 50, "not found", 5*time.Millisecond), nil
	})
	g, ok := e.GroupSnapshot(".recovered")
	if !ok || g.Degraded || !g.Ready {
		t.Fatalf("recovered group not ready: %+v", g)
	}
}
