package verdict

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ffuf/ffuf/v2/pkg/ffuf"
)

func reviewResp(position int) *ffuf.Response {
	return &ffuf.Response{
		StatusCode:    200,
		ContentLength: 10,
		ContentWords:  3,
		ContentLines:  1,
		Headers:       map[string][]string{},
		Request: &ffuf.Request{
			Url:      "http://x/FUZZ",
			Host:     "x",
			Position: position,
			Input:    map[string][]byte{"FUZZ": []byte("payload")},
		},
		Duration: 5 * time.Millisecond,
	}
}

func dropDecision(id string) *Decision {
	b := true
	return &Decision{
		Outcome:     OutcomeDrop,
		BlockedSide: SideFilter,
		DecisiveRule: &RuleTrace{
			RuleID: id, Side: SideFilter, Kind: "size", Raw: "size:10",
			Result: &b, ActualValues: map[string]string{"content_length": "10"},
		},
		Traces:      []RuleTrace{{RuleID: id, Side: SideFilter, Kind: "size", Raw: "size:10", Result: &b}},
		EvaluatedAt: time.Now(),
	}
}

// 形态9/硬约束3: bounded FIFO eviction with a readable eviction count.
func TestReviewStore_FIFOEvictionAndStats(t *testing.T) {
	store := NewReviewStore(3, "")
	for i := 1; i <= 10; i++ {
		store.Record(reviewResp(i), dropDecision("f1"))
	}
	st := store.Stats()
	if st.Capacity != 3 || st.Stored != 3 || st.TotalRecorded != 10 || st.Evicted != 7 {
		t.Fatalf("stats = %+v, want cap3 stored3 total10 evicted7", st)
	}
	entries := store.Entries()
	got := []int{entries[0].Position, entries[1].Position, entries[2].Position}
	want := []int{8, 9, 10}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("retained positions = %v, want %v (FIFO)", got, want)
		}
	}
	// Every retained entry is self-contained: request id, decisive rule, values.
	e := entries[0]
	if e.RequestID == "" || e.Decision.DecisiveRule.RuleID != "f1" {
		t.Fatalf("entry missing request id / decisive rule: %+v", e)
	}
	if e.Decision.DecisiveRule.ActualValues["content_length"] != "10" {
		t.Fatalf("entry missing actual values: %+v", e.Decision.DecisiveRule)
	}
	if e.Input["FUZZ"] != "payload" {
		t.Fatalf("entry missing fuzzing input: %+v", e.Input)
	}
}

// 验收4: review file sink receives one JSON line per record and converges to
// the same eviction boundary in memory.
func TestReviewStore_FileSink(t *testing.T) {
	path := filepath.Join(t.TempDir(), "review.jsonl")
	store := NewReviewStore(2, path)
	t.Cleanup(func() { _ = store.Close() })
	for i := 1; i <= 5; i++ {
		store.Record(reviewResp(i), dropDecision("f1"))
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	f, err := os.Open(path)
	if err != nil {
		t.Fatalf("open sink: %v", err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	lines := 0
	sawSummary := false
	for scanner.Scan() {
		// The final line is a review_summary record, not a ReviewEntry.
		var probe struct {
			Type string `json:"type"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &probe); err == nil && probe.Type == "review_summary" {
			sawSummary = true
			continue
		}
		var entry ReviewEntry
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			t.Fatalf("line %d not valid JSON: %v", lines+1, err)
		}
		if entry.Decision == nil || entry.Decision.Outcome != OutcomeDrop {
			t.Fatalf("line %d missing decision: %+v", lines+1, entry)
		}
		lines++
	}
	if lines != 5 {
		t.Fatalf("sink entry lines = %d, want 5 (disk keeps all; memory ring evicted)", lines)
	}
	if !sawSummary {
		t.Fatal("sink missing the final review_summary record")
	}
	st := store.Stats()
	if st.Evicted != 3 || st.Stored != 2 || st.SinkFailures != 0 || st.SinkDisabled {
		t.Fatalf("unexpected stats: %+v", st)
	}
}

// 降级1: an unwritable sink disables only the disk path; in-memory review and
// verdict production continue, and the failure is readable.
func TestReviewStore_SinkFailureDegrades(t *testing.T) {
	// A directory path cannot be opened as a regular file.
	path := filepath.Join(t.TempDir(), "is-a-dir")
	if err := os.Mkdir(path, 0750); err != nil {
		t.Fatal(err)
	}
	store := NewReviewStore(4, path)
	entry := store.Record(reviewResp(1), dropDecision("f1"))
	if entry == nil || entry.Decision.Outcome != OutcomeDrop {
		t.Fatal("verdict/record must still be produced when the sink is unavailable")
	}
	st := store.Stats()
	if !st.SinkDisabled || st.SinkError == "" {
		t.Fatalf("sink failure not marked: %+v", st)
	}
	if st.Stored != 1 || st.TotalRecorded != 1 {
		t.Fatalf("in-memory review should continue: %+v", st)
	}
	if err := store.Close(); err == nil || !strings.Contains(err.Error(), "unavailable") {
		t.Fatalf("close should report sink unavailable, got %v", err)
	}
}

// Kept policy helper: undecidable responses are kept only when the policy says
// so; keeps/drops are unaffected.
func TestDecision_KeptPolicy(t *testing.T) {
	keep := &Decision{Outcome: OutcomeKeep}
	drop := &Decision{Outcome: OutcomeDrop}
	und := &Decision{Outcome: OutcomeUndecidable}
	if !keep.Kept(false) || drop.Kept(true) {
		t.Fatal("keep/drop policy wrong")
	}
	if und.Kept(false) {
		t.Fatal("undecidable must not be kept when policy is drop")
	}
	if !und.Kept(true) {
		t.Fatal("undecidable must be kept when policy is keep")
	}
}
