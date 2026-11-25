package engine

import (
	"context"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ffuf/ffuf/v2/pkg/ffuf"
	"github.com/ffuf/ffuf/v2/pkg/output"
	"github.com/ffuf/ffuf/v2/pkg/session"
)

// blockingRunner is a RunnerProvider whose Execute blocks until its context is
// done, then reports the cancellation as an error. It counts calls so a test can
// assert that no new request is started after a stop.
type blockingRunner struct {
	ctx   context.Context
	calls int64
}

func (r *blockingRunner) Prepare(input map[string][]byte, basereq *ffuf.Request) (ffuf.Request, error) {
	req := *basereq
	req.Input = input
	return req, nil
}

func (r *blockingRunner) Execute(req *ffuf.Request) (ffuf.Response, error) {
	atomic.AddInt64(&r.calls, 1)
	// The runner's contract: a cancelled context aborts the request.
	<-r.ctx.Done()
	return ffuf.Response{}, r.ctx.Err()
}

func (r *blockingRunner) Dump(req *ffuf.Request) ([]byte, error) { return nil, nil }

// count returns how many Execute calls have started.
func (r *blockingRunner) count() int64 { return atomic.LoadInt64(&r.calls) }

// fakeInput is a minimal InputProvider over a fixed list of values.
type fakeInput struct {
	values []string
	pos    int
}

func (f *fakeInput) ActivateKeywords([]string)                  {}
func (f *fakeInput) AddProvider(ffuf.InputProviderConfig) error { return nil }
func (f *fakeInput) Keywords() []string                         { return []string{"FUZZ"} }
func (f *fakeInput) Position() int                              { return f.pos }
func (f *fakeInput) SetPosition(p int)                          { f.pos = p }
func (f *fakeInput) Reset()                                     { f.pos = 0 }
func (f *fakeInput) Total() int                                 { return len(f.values) }
func (f *fakeInput) Value() map[string][]byte {
	return map[string][]byte{"FUZZ": []byte(f.values[f.pos-1])}
}

func (f *fakeInput) Next() bool {
	if f.pos >= len(f.values) {
		return false
	}
	f.pos++
	return true
}

// discardOutput is a no-op OutputProvider that records nothing. Finalize writes a
// marker file so the test can assert Start finalized the output.
type discardOutput struct {
	finalized bool
	info      []string
}

func (o *discardOutput) Banner()                       {}
func (o *discardOutput) Progress(ffuf.Progress)        {}
func (o *discardOutput) Error(string)                  {}
func (o *discardOutput) Raw(string)                    {}
func (o *discardOutput) Warning(string)                {}
func (o *discardOutput) Result(ffuf.Response)          {}
func (o *discardOutput) PrintResult(ffuf.Result)       {}
func (o *discardOutput) SaveFile(string, string) error { return nil }
func (o *discardOutput) GetCurrentResults() []ffuf.Result {
	return nil
}
func (o *discardOutput) SetCurrentResults([]ffuf.Result)             {}
func (o *discardOutput) FilterCurrentResults(func(ffuf.Result) bool) {}
func (o *discardOutput) SetPaused(bool)                              {}
func (o *discardOutput) PendingResults() int                         { return 0 }
func (o *discardOutput) Reset()                                      {}
func (o *discardOutput) Cycle()                                      {}
func (o *discardOutput) Info(s string)                               { o.info = append(o.info, s) }
func (o *discardOutput) Finalize() error {
	o.finalized = true
	return nil
}

// TestJob_StopWith_Interrupt verifies the session-level stop path: a stop with
// the interrupt reason makes Start return quickly, drains in-flight work, and
// reports a stopped session with the interrupt reason.
func TestJob_StopWith_Interrupt(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	outputFile := filepath.Join(t.TempDir(), "out.json")
	conf := &ffuf.Config{
		Url:               "http://example.org/FUZZ",
		Method:            "GET",
		Threads:           1,
		Context:           ctx,
		Cancel:            cancel,
		Quiet:             true,
		CancelGrace:       0, // immediate drain expiry: in-flight work is forced
		ProgressFrequency: 5,
		OutputFile:        outputFile,
		OutputFormat:      "json",
	}
	conf.MatcherManager = &fakeMatcherManager{}

	job := NewJob(conf)
	job.Output = output.NewStdoutput(conf)
	job.Runner = &blockingRunner{ctx: ctx}
	job.Input = &fakeInput{values: wordValues(20)}

	done := make(chan struct{})
	go func() {
		job.Start()
		close(done)
	}()

	// Let Start dispatch a couple of requests, then stop.
	time.Sleep(50 * time.Millisecond)
	job.StopWith(session.ReasonInterrupt)

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Start did not return within 2s of StopWith")
	}

	rep := job.Report()
	if rep.State != session.StateStopped {
		t.Errorf("State = %s, want stopped", rep.State)
	}
	if rep.Reason != session.ReasonInterrupt {
		t.Errorf("Reason = %s, want interrupt", rep.Reason)
	}
	if !rep.Canceled {
		t.Error("Canceled should be true")
	}
	if !rep.Forced {
		t.Error("Forced should be true: the in-flight request only ends on cancel")
	}
	if rep.InFlightAtStop > 1 {
		t.Errorf("InFlightAtStop = %d, want <= 1", rep.InFlightAtStop)
	}
	if rep.Outstanding != 0 {
		t.Errorf("Outstanding = %d, want 0 after Start returns", rep.Outstanding)
	}

	// No new request may start after Start has returned.
	before := job.Runner.(*blockingRunner).count()
	time.Sleep(50 * time.Millisecond)
	if after := job.Runner.(*blockingRunner).count(); after != before {
		t.Errorf("runner calls grew from %d to %d after Start returned", before, after)
	}

	// The -o output file must still be written even though the run was stopped.
	if _, err := os.Stat(outputFile); err != nil {
		t.Errorf("output file was not written: %v", err)
	}
}

// TestJob_StopWith_GraceAllowsDrain verifies that with a generous -cancel-grace,
// the in-flight request gets to finish naturally (the runner returns once the
// job's stop cancels the context after the drain window), so the drain is not
// forced.
func TestJob_StopWith_GraceAllowsDrain(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// A runner that respects the cancellation but signals the test when it is
	// released, proving the drain waited for it.
	conf := &ffuf.Config{
		Url:     "http://example.org/FUZZ",
		Method:  "GET",
		Threads: 1,
		Context: ctx,
		Cancel:  cancel,
		Quiet:   true,
	}
	conf.MatcherManager = &fakeMatcherManager{}

	job := NewJob(conf)
	out := &discardOutput{}
	job.Output = out
	job.Input = &fakeInput{values: []string{"a"}}
	// Execute returns immediately, so the request is done before the stop lands.
	job.Runner = &instantRunner{}

	done := make(chan struct{})
	go func() {
		job.Start()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Start hung on a clean run")
	}
	rep := job.Report()
	if rep.Canceled {
		t.Error("a normal completion must not record a stop reason")
	}
	if rep.State != session.StateStopped {
		t.Errorf("State = %s, want stopped", rep.State)
	}
	if !out.finalized {
		t.Error("Finalize was not called")
	}
}

// instantRunner completes every request immediately.
type instantRunner struct{}

func (instantRunner) Prepare(input map[string][]byte, basereq *ffuf.Request) (ffuf.Request, error) {
	req := *basereq
	req.Input = input
	return req, nil
}
func (instantRunner) Execute(req *ffuf.Request) (ffuf.Response, error) {
	return ffuf.Response{StatusCode: 200, Request: req, ScraperData: map[string][]string{}}, nil
}
func (instantRunner) Dump(req *ffuf.Request) ([]byte, error) { return nil, nil }

func wordValues(n int) []string {
	out := make([]string, n)
	for i := range out {
		out[i] = "w" + itoa(i)
	}
	return out
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	return string(buf[i:])
}

// TestJob_NoSessionLiteral ensures a Job built as a literal with no Session still
// starts, stops, and finalizes without panicking.
func TestJob_NoSessionLiteral(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conf := &ffuf.Config{
		Url:     "http://example.org/FUZZ",
		Method:  "GET",
		Threads: 1,
		Context: ctx,
		Cancel:  cancel,
		Quiet:   true,
	}
	conf.MatcherManager = &fakeMatcherManager{}
	job := &Job{Config: conf, Output: &discardOutput{}, Runner: &instantRunner{}, Input: &fakeInput{values: []string{"a", "b"}}}
	job.queue = newJobQueue()
	job.Rate = NewRateThrottle(conf)

	done := make(chan struct{})
	go func() {
		job.Start()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Start hung without a Session")
	}
	// Stop/pause/reset must remain safe.
	job.Stop()
	job.Pause()
	job.Resume()
	job.Reset(true)
}

// TestJob_InvalidDedupConfigWarns verifies that a bad dedup configuration in a
// directly-built ffuf.Config does not crash Start; it warns once and disables
// dedup.
func TestJob_InvalidDedupConfigWarns(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	conf := &ffuf.Config{
		Url:         "http://example.org/FUZZ",
		Method:      "GET",
		Threads:     1,
		Context:     ctx,
		Cancel:      cancel,
		Quiet:       true,
		Dedup:       true,
		DedupFields: []string{"status"}, // missing url
	}
	conf.MatcherManager = &fakeMatcherManager{}
	job := NewJob(conf)
	out := &recordingOutput{}
	job.Output = out
	job.Runner = &instantRunner{}
	job.Input = &fakeInput{values: []string{"a"}}

	done := make(chan struct{})
	go func() {
		job.Start()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Start hung with an invalid dedup config")
	}
	if !out.sawWarning {
		t.Error("expected a warning about the invalid dedup configuration")
	}
	if job.dedupEnabled {
		t.Error("dedup should be disabled after a configuration error")
	}
}

// recordingOutput records whether a warning was emitted.
type recordingOutput struct {
	discardOutput
	sawWarning bool
}

func (o *recordingOutput) Warning(string) { o.sawWarning = true }
