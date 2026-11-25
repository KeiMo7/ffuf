package integration

import (
	"context"
	"testing"

	"github.com/ffuf/ffuf/v2/pkg/assembly"
	"github.com/ffuf/ffuf/v2/pkg/ffuf"
	"github.com/ffuf/ffuf/v2/pkg/filter"
	"github.com/ffuf/ffuf/v2/pkg/testtarget"
)

// runScanCapture is runScan's sibling that returns the capturing OutputProvider
// instead of the matched set, so a test can assert how many times Result fired.
func runScanCapture(t *testing.T, url string, wordlist []string, configure func(*ffuf.ConfigOptions)) *capture {
	t.Helper()

	opts := ffuf.NewConfigOptions()
	opts.HTTP.URL = url
	opts.HTTP.Method = "GET"
	opts.Input.Wordlists = []string{writeWordlist(t, wordlist)}
	opts.General.Quiet = true
	if configure != nil {
		configure(opts)
	}

	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)

	conf, err := ffuf.ConfigFromOptions(opts, ctx, cancel)
	if err != nil {
		t.Fatalf("ConfigFromOptions: %v", err)
	}
	conf.MatcherManager = filter.NewMatcherManager()
	if err := conf.MatcherManager.AddMatcher("status", "all"); err != nil {
		t.Fatalf("AddMatcher: %v", err)
	}

	job, err := assembly.BuildJob(conf)
	if err != nil {
		t.Fatalf("BuildJob: %v", err)
	}
	out := &capture{}
	job.Output = out
	job.Start()
	return out
}

// TestDedupSuppressesDuplicateResults: a wordlist with two identical entries hits
// the same URL twice with the same response; with -dedup only the first result is
// emitted, without it both are. The two responses are otherwise identical, so the
// fingerprint truly matches.
func TestDedupSuppressesDuplicateResults(t *testing.T) {
	target := testtarget.New()
	defer target.Close()

	url := target.URL + "/reflect/FUZZ"
	words := []string{"same", "same"}

	off := runScanCapture(t, url, words, func(o *ffuf.ConfigOptions) {
		o.Output.Dedup = false
		o.General.Threads = 1
	})
	if got := len(off.responses); got != 2 {
		t.Fatalf("dedup off: Result calls = %d, want 2", got)
	}

	on := runScanCapture(t, url, words, func(o *ffuf.ConfigOptions) {
		o.Output.Dedup = true
		o.General.Threads = 1
	})
	if got := len(on.responses); got != 1 {
		t.Fatalf("dedup on: Result calls = %d, want 1", got)
	}

	// The two-and-one results all describe the same response shape.
	all := append(append([]ffuf.Response{}, off.responses...), on.responses...)
	first := all[0]
	for _, r := range all {
		if r.Request.Url != first.Request.Url ||
			r.StatusCode != first.StatusCode ||
			r.ContentLength != first.ContentLength ||
			r.ContentWords != first.ContentWords ||
			r.ContentLines != first.ContentLines {
			t.Fatalf("responses differ: %+v vs %+v", r, first)
		}
	}
}
