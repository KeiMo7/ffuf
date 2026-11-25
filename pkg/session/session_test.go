package session

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"
)

func mustNew(t *testing.T, opts Options) *Session {
	t.Helper()
	s, err := New(opts)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return s
}

// fixedClock returns a deterministic clock advanced by step on each call.
func fixedClock(start time.Time, step time.Duration) func() time.Time {
	cur := start
	var mu sync.Mutex
	return func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		now := cur
		cur = cur.Add(step)
		return now
	}
}

func TestNew_FieldValidation(t *testing.T) {
	cases := []struct {
		name    string
		fields  []string
		wantErr bool
	}{
		{"empty uses defaults", nil, false},
		{"all empty entries uses defaults", []string{"", "  "}, false},
		{"case and spaces normalized", []string{" URL ", "Status", " LENGTH "}, false},
		{"missing url", []string{"status", "length"}, true},
		{"unknown field", []string{"url", "body"}, true},
		{"valid all", []string{"url", "status", "length", "words", "lines", "redirect", "content-type"}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := New(Options{Fields: c.fields})
			if c.wantErr {
				if !errors.Is(err, ErrInvalidOptions) {
					t.Fatalf("want ErrInvalidOptions, got %v", err)
				}
			} else if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
		})
	}
}

func TestNew_FieldNormalizationOrder(t *testing.T) {
	s := mustNew(t, Options{Fields: []string{"lines", "URL", "status"}})
	want := []string{"url", "status", "lines"}
	if len(s.fields) != len(want) {
		t.Fatalf("fields = %v, want %v", s.fields, want)
	}
	for i := range want {
		if s.fields[i] != want[i] {
			t.Fatalf("fields = %v, want %v", s.fields, want)
		}
	}
}

func TestNew_NegativeCapacity(t *testing.T) {
	_, err := New(Options{Capacity: -1})
	if !errors.Is(err, ErrInvalidOptions) {
		t.Fatalf("want ErrInvalidOptions, got %v", err)
	}
}

func TestNormalizeURL(t *testing.T) {
	cases := []struct{ in, want string }{
		{" HTTP://Example.COM/Path?b=2&a=1 ", "http://example.com/Path?b=2&a=1"},
		{"https://host:443/x", "https://host/x"},
		{"http://host:80/x", "http://host/x"},
		{"http://host:8080/x", "http://host:8080/x"},
		{"http://host/x#frag", "http://host/x"},
		{"https://Host/Path/", "https://host/Path/"},
		// Query order preserved, not sorted.
		{"https://h/?z=1&a=2", "https://h/?z=1&a=2"},
		// Unparseable input falls back to the trimmed original.
		{"http://[::1", "http://[::1"},
		{"::not a url", "::not a url"},
	}
	for _, c := range cases {
		if got := normalizeURL(c.in); got != c.want {
			t.Errorf("normalizeURL(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestFingerprintStability(t *testing.T) {
	s := mustNew(t, Options{})
	obs := Observation{URL: "http://example.com/a", Status: 200, Length: 10, Words: 2, Lines: 1}
	v1, err := s.Observe(obs)
	if err != nil {
		t.Fatal(err)
	}
	// Case-only URL differences normalize to the same fingerprint.
	obs2 := obs
	obs2.URL = "HTTP://EXAMPLE.COM/a"
	v2, err := s.Observe(obs2)
	if err != nil {
		t.Fatal(err)
	}
	if !v2.Duplicate {
		t.Fatal("normalized URL should be a duplicate")
	}
	if v1.EntryID != v2.EntryID {
		t.Fatalf("entry IDs differ: %d vs %d", v1.EntryID, v2.EntryID)
	}
}

func TestObserve_FirstIsUnique(t *testing.T) {
	s := mustNew(t, Options{})
	v, err := s.Observe(Observation{URL: "http://x/y", Status: 200, Position: 7})
	if err != nil {
		t.Fatal(err)
	}
	if v.Duplicate {
		t.Fatal("first observation was a duplicate")
	}
	if v.EntryID != 1 {
		t.Fatalf("EntryID = %d, want 1", v.EntryID)
	}
	if v.FirstPosition != 7 {
		t.Fatalf("FirstPosition = %d, want 7", v.FirstPosition)
	}
	if _, err := s.Observe(Observation{}); !errors.Is(err, ErrInvalidObservation) {
		t.Fatalf("empty URL: want ErrInvalidObservation, got %v", err)
	}
}

func TestStateTransitions(t *testing.T) {
	s := mustNew(t, Options{})
	if err := s.Request(ReasonInterrupt, ScopeSession); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("Request on idle: want ErrInvalidTransition, got %v", err)
	}
	if _, err := s.Drain(context.Background()); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("Drain on idle: want ErrInvalidTransition, got %v", err)
	}
	if err := s.BeginJob(); err != nil {
		t.Fatalf("BeginJob: %v", err)
	}
	if !s.GateOpen() {
		t.Fatal("gate not open after BeginJob")
	}
	// A second BeginJob just reopens the gate.
	if err := s.BeginJob(); err != nil {
		t.Fatalf("second BeginJob: %v", err)
	}
	if _, err := s.Drain(context.Background()); err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if s.Report().State != StateStopped {
		t.Fatalf("state = %s, want stopped", s.Report().State)
	}
	if err := s.BeginJob(); !errors.Is(err, ErrInvalidTransition) {
		t.Fatalf("BeginJob after stop: want ErrInvalidTransition, got %v", err)
	}
}

func TestRequest_FirstReasonAndScope(t *testing.T) {
	s := mustNew(t, Options{})
	if err := s.BeginJob(); err != nil {
		t.Fatal(err)
	}
	if err := s.Request(ReasonMaxTimeJob, ScopeJob); err != nil {
		t.Fatal(err)
	}
	if err := s.Request(ReasonInterrupt, ScopeSession); err != nil {
		t.Fatal(err)
	}
	rep := s.Report()
	if rep.Reason != ReasonMaxTimeJob {
		t.Errorf("Reason = %s, want the first accepted reason %s", rep.Reason, ReasonMaxTimeJob)
	}
	if rep.Scope != ScopeSession {
		t.Errorf("Scope = %s, want widest %s", rep.Scope, ScopeSession)
	}
	if !rep.Canceled {
		t.Error("Canceled should be true after a session-scope stop")
	}
	if len(rep.Requests) != 2 {
		t.Fatalf("Requests = %d, want 2", len(rep.Requests))
	}
	if rep.Requests[0].Seq != 1 || rep.Requests[1].Seq != 2 {
		t.Errorf("request seqs = %d,%d", rep.Requests[0].Seq, rep.Requests[1].Seq)
	}
	if rep.JobStops != 1 {
		t.Errorf("JobStops = %d, want 1", rep.JobStops)
	}
}

func TestRequest_StoppedIsNoop(t *testing.T) {
	s := mustNew(t, Options{})
	if err := s.BeginJob(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	before := len(s.Report().Requests)
	if err := s.Request(ReasonInterrupt, ScopeSession); err != nil {
		t.Fatalf("Request after stop: want nil, got %v", err)
	}
	if got := len(s.Report().Requests); got != before {
		t.Errorf("Requests grew after stop: %d -> %d", before, got)
	}
}

func TestTrackRelease(t *testing.T) {
	s := mustNew(t, Options{})
	// Gate closed before BeginJob: Track must refuse.
	if s.Track() {
		t.Fatal("Track succeeded while idle")
	}
	if err := s.BeginJob(); err != nil {
		t.Fatal(err)
	}
	if !s.Track() {
		t.Fatal("Track failed while running")
	}
	if rep := s.Report(); rep.Outstanding != 1 {
		t.Fatalf("Outstanding = %d, want 1", rep.Outstanding)
	}
	s.Release()
	if rep := s.Report(); rep.Outstanding != 0 {
		t.Fatalf("Outstanding = %d, want 0", rep.Outstanding)
	}
	// Extra Release is a no-op.
	s.Release()
	if rep := s.Report(); rep.Outstanding != 0 {
		t.Fatalf("Outstanding = %d, want 0 after extra Release", rep.Outstanding)
	}
	// A job stop closes the gate; Track then fails.
	if err := s.Request(ReasonMaxTimeJob, ScopeJob); err != nil {
		t.Fatal(err)
	}
	if s.Track() {
		t.Fatal("Track succeeded after job stop")
	}
}

func TestDrain_Success(t *testing.T) {
	s := mustNew(t, Options{Now: fixedClock(time.Unix(1000, 0), time.Second)})
	if err := s.BeginJob(); err != nil {
		t.Fatal(err)
	}
	if !s.Track() {
		t.Fatal("Track failed")
	}
	if err := s.Request(ReasonInterrupt, ScopeSession); err != nil {
		t.Fatal(err)
	}

	done := make(chan Report, 1)
	go func() {
		rep, err := s.Drain(context.Background())
		if err != nil {
			t.Errorf("Drain: %v", err)
		}
		done <- rep
	}()
	time.Sleep(20 * time.Millisecond)
	s.Release()
	rep := <-done
	if rep.State != StateStopped {
		t.Fatalf("State = %s, want stopped", rep.State)
	}
	if rep.Forced {
		t.Fatal("Forced should be false on a clean drain")
	}
	if rep.Outstanding != 0 {
		t.Fatalf("Outstanding = %d, want 0", rep.Outstanding)
	}
	if rep.StoppedAt.IsZero() {
		t.Fatal("StoppedAt not recorded")
	}
}

func TestDrain_Timeout(t *testing.T) {
	s := mustNew(t, Options{})
	if err := s.BeginJob(); err != nil {
		t.Fatal(err)
	}
	if !s.Track() {
		t.Fatal("Track failed")
	}
	if err := s.Request(ReasonInterrupt, ScopeSession); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	rep, err := s.Drain(ctx)
	if !errors.Is(err, ErrDrainTimeout) {
		t.Fatalf("want ErrDrainTimeout, got %v", err)
	}
	if !rep.Forced {
		t.Fatal("Forced should be true on timeout")
	}
	if rep.Outstanding != 1 {
		t.Fatalf("Outstanding = %d, want 1", rep.Outstanding)
	}
	// The late Release must not push the count negative.
	s.Release()
	if n := s.Report().Outstanding; n != 0 {
		t.Fatalf("Outstanding after late Release = %d, want 0", n)
	}
}

func TestDrain_RepeatedReturnsFirst(t *testing.T) {
	s := mustNew(t, Options{})
	if err := s.BeginJob(); err != nil {
		t.Fatal(err)
	}
	if !s.Track() {
		t.Fatal("Track failed")
	}
	if err := s.Request(ReasonInterrupt, ScopeSession); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	first, firstErr := s.Drain(ctx)
	if !errors.Is(firstErr, ErrDrainTimeout) {
		t.Fatalf("first Drain: %v", firstErr)
	}
	// A second Drain, even with work now released, returns the same snapshot.
	s.Release()
	second, secondErr := s.Drain(context.Background())
	if !errors.Is(secondErr, ErrDrainTimeout) {
		t.Fatalf("second Drain err = %v, want the first ErrDrainTimeout", secondErr)
	}
	if !second.Forced {
		t.Fatal("second Drain should still report Forced")
	}
	if second.StoppedAt != first.StoppedAt {
		t.Fatal("second Drain re-timed the stop")
	}
}

func TestObserve_AfterClose(t *testing.T) {
	s := mustNew(t, Options{})
	if err := s.BeginJob(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Drain(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, err := s.Observe(Observation{URL: "http://x/y"})
	if !errors.Is(err, ErrSessionClosed) {
		t.Fatalf("want ErrSessionClosed, got %v", err)
	}
}

func TestCapacityEviction(t *testing.T) {
	s := mustNew(t, Options{Capacity: 2})
	if err := s.BeginJob(); err != nil {
		t.Fatal(err)
	}
	obs := func(u string) Observation { return Observation{URL: u, Status: 200} }
	if _, err := s.Observe(obs("http://x/1")); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Observe(obs("http://x/2")); err != nil {
		t.Fatal(err)
	}
	// Third distinct entry evicts the oldest.
	if _, err := s.Observe(obs("http://x/3")); err != nil {
		t.Fatal(err)
	}
	rep := s.Report()
	if rep.Evicted != 1 {
		t.Errorf("Evicted = %d, want 1", rep.Evicted)
	}
	if len(rep.Entries) != 2 {
		t.Fatalf("Entries = %d, want 2", len(rep.Entries))
	}
	// The evicted fingerprint becomes new again.
	v, err := s.Observe(obs("http://x/1"))
	if err != nil {
		t.Fatal(err)
	}
	if v.Duplicate {
		t.Fatal("evicted fingerprint should be treated as a new entry")
	}
	if s.Report().Evicted != 2 {
		t.Errorf("Evicted = %d, want 2", s.Report().Evicted)
	}
}

func TestResetResults(t *testing.T) {
	s := mustNew(t, Options{})
	if err := s.BeginJob(); err != nil {
		t.Fatal(err)
	}
	if !s.Track() {
		t.Fatal("Track failed")
	}
	if _, err := s.Observe(Observation{URL: "http://x/1", Status: 200}); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Observe(Observation{URL: "http://x/1", Status: 200}); err != nil {
		t.Fatal(err)
	}
	if err := s.Request(ReasonMaxTimeJob, ScopeJob); err != nil {
		t.Fatal(err)
	}
	s.ResetResults()
	rep := s.Report()
	if len(rep.Entries) != 0 || rep.Observed != 0 || rep.Suppressed != 0 || rep.Evicted != 0 {
		t.Fatalf("ledger not cleared: %+v", rep)
	}
	if rep.State != StateRunning {
		t.Errorf("state changed by ResetResults: %s", rep.State)
	}
	if rep.Outstanding != 1 {
		t.Errorf("Outstanding changed by ResetResults: %d", rep.Outstanding)
	}
	if len(rep.Requests) != 1 {
		t.Errorf("stop requests changed by ResetResults: %d", len(rep.Requests))
	}
	v, err := s.Observe(Observation{URL: "http://x/1", Status: 200})
	if err != nil {
		t.Fatal(err)
	}
	if v.Duplicate || v.EntryID != 1 {
		t.Fatalf("after reset want new entry ID 1, got %+v", v)
	}
}

func TestReportCopiesDoNotAlias(t *testing.T) {
	s := mustNew(t, Options{})
	if err := s.BeginJob(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Observe(Observation{URL: "http://x/1", Status: 200}); err != nil {
		t.Fatal(err)
	}
	if err := s.Request(ReasonMaxTimeJob, ScopeJob); err != nil {
		t.Fatal(err)
	}
	rep := s.Report()
	rep.Entries[0].Count = 999
	rep.Requests[0].Reason = "corrupted"
	again := s.Report()
	if again.Entries[0].Count != 1 {
		t.Errorf("entry mutated through report copy: count = %d", again.Entries[0].Count)
	}
	if again.Requests[0].Reason != ReasonMaxTimeJob {
		t.Errorf("request mutated through report copy: %s", again.Requests[0].Reason)
	}
}

func TestDurationUsesInjectedClock(t *testing.T) {
	start := time.Unix(1000, 0)
	// First call (BeginJob) returns start; the drain-time call returns start+5s.
	calls := 0
	now := func() time.Time {
		calls++
		if calls == 1 {
			return start
		}
		return start.Add(5 * time.Second)
	}
	s := mustNew(t, Options{Now: now})
	if err := s.BeginJob(); err != nil {
		t.Fatal(err)
	}
	rep, err := s.Drain(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if rep.Duration != 5*time.Second {
		t.Fatalf("Duration = %v, want 5s", rep.Duration)
	}
	if !rep.StartedAt.Equal(start) {
		t.Errorf("StartedAt = %v, want %v", rep.StartedAt, start)
	}
}

// TestObserve_ConcurrentSameObservation drives 64 goroutines at the same
// observation: exactly one is unique, the rest are duplicates, and the ledger
// holds a single entry counting all 64.
func TestObserve_ConcurrentSameObservation(t *testing.T) {
	s := mustNew(t, Options{})
	if err := s.BeginJob(); err != nil {
		t.Fatal(err)
	}
	obs := Observation{URL: "http://example.com/same", Status: 200, Length: 3, Words: 1, Lines: 1}
	const n = 64
	var wg sync.WaitGroup
	var mu sync.Mutex
	unique, dup := 0, 0
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			v, err := s.Observe(obs)
			if err != nil {
				t.Errorf("Observe: %v", err)
				return
			}
			mu.Lock()
			if v.Duplicate {
				dup++
			} else {
				unique++
			}
			mu.Unlock()
		}()
	}
	close(start)
	wg.Wait()
	if unique != 1 {
		t.Errorf("unique = %d, want 1", unique)
	}
	if dup != n-1 {
		t.Errorf("duplicates = %d, want %d", dup, n-1)
	}
	rep := s.Report()
	if len(rep.Entries) != 1 {
		t.Fatalf("Entries = %d, want 1", len(rep.Entries))
	}
	if rep.Entries[0].Count != n {
		t.Fatalf("Count = %d, want %d", rep.Entries[0].Count, n)
	}
}

// TestTrackRelease_Concurrent interleaves Track and Release on 32 goroutines and
// asserts the drain sees a zero count.
func TestTrackRelease_Concurrent(t *testing.T) {
	s := mustNew(t, Options{})
	if err := s.BeginJob(); err != nil {
		t.Fatal(err)
	}
	const n = 32
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				if s.Track() {
					s.Release()
				}
			}
		}()
	}
	wg.Wait()
	rep, err := s.Drain(context.Background())
	if err != nil {
		t.Fatalf("Drain: %v", err)
	}
	if rep.Outstanding != 0 {
		t.Fatalf("Outstanding = %d, want 0", rep.Outstanding)
	}
}

func TestReasonValues(t *testing.T) {
	want := map[Reason]string{
		ReasonInterrupt:      "interrupt",
		ReasonMaxTime:        "max-time",
		ReasonMaxTimeJob:     "max-time-job",
		ReasonStopOn403:      "stop-on-403",
		ReasonStopOn429:      "stop-on-429",
		ReasonSpuriousErrors: "spurious-errors",
	}
	for r, s := range want {
		if string(r) != s {
			t.Errorf("Reason %v = %q, want %q", r, string(r), s)
		}
	}
	for _, s := range []State{StateIdle, StateRunning, StateDraining, StateStopped} {
		if strings.TrimSpace(string(s)) == "" {
			t.Errorf("empty state constant")
		}
	}
}

// TestDrain_ConcurrentCallersShareFirstReport drives several Drain calls at once:
// the session stops exactly once and every caller sees the same stop timestamp.
func TestDrain_ConcurrentCallersShareFirstReport(t *testing.T) {
	s := mustNew(t, Options{})
	if err := s.BeginJob(); err != nil {
		t.Fatal(err)
	}
	if !s.Track() {
		t.Fatal("Track failed")
	}
	if err := s.Request(ReasonInterrupt, ScopeSession); err != nil {
		t.Fatal(err)
	}
	const n = 8
	var wg sync.WaitGroup
	reports := make([]Report, n)
	errs := make([]error, n)
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			reports[i], errs[i] = s.Drain(context.Background())
		}(i)
	}
	close(start)
	time.Sleep(10 * time.Millisecond)
	s.Release()
	wg.Wait()

	for i := 0; i < n; i++ {
		if errs[i] != nil {
			t.Fatalf("caller %d Drain error: %v", i, errs[i])
		}
		if reports[i].State != StateStopped {
			t.Errorf("caller %d state = %s, want stopped", i, reports[i].State)
		}
		if i > 0 && reports[i].StoppedAt != reports[0].StoppedAt {
			t.Errorf("caller %d StoppedAt = %v differs from caller 0 %v", i, reports[i].StoppedAt, reports[0].StoppedAt)
		}
	}
	if got := s.Report().Outstanding; got != 0 {
		t.Errorf("Outstanding = %d, want 0", got)
	}
}
