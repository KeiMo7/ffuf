package checkpoint

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ffuf/ffuf/v2/pkg/heuristics"
)

func TestRecordAndResume(t *testing.T) {
	dir := t.TempDir()
	store, err := CreateOrOpen(dir, "scan-abc", "http://t/FUZZ", []string{"wl.txt"}, 100)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	inputs := map[string]string{"FUZZ": "admin"}
	if store.IsDone(1, inputs) {
		t.Fatal("fresh store should have no done entries")
	}
	store.Record(Entry{
		Position: 1, Inputs: inputs, Done: true, Matched: true,
		ResponseSignature: Signature{StatusCode: 302, BodyHash: "h1", URL: "http://t/admin"},
	})
	store.Record(Entry{
		Position: 2, Inputs: map[string]string{"FUZZ": "ghost"}, Done: true, Matched: false,
		ResponseSignature: Signature{StatusCode: 404, BodyHash: "h2", URL: "http://t/ghost"},
	})
	if err := store.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	if !store.IsDone(1, inputs) {
		t.Error("entry not reported done after record")
	}
	if got := store.State().Completed; got != 2 {
		t.Errorf("completed = %d, want 2", got)
	}
	if got := store.State().MatchedCount; got != 1 {
		t.Errorf("matched = %d, want 1", got)
	}

	// Reopen: progress survives the process boundary.
	reopened, err := CreateOrOpen(dir, "scan-abc", "http://t/FUZZ", []string{"wl.txt"}, 100)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if !reopened.IsDone(1, inputs) {
		t.Error("done state lost across reopen")
	}
	hits := reopened.MatchedEntries()
	if len(hits) != 1 || hits[0].Position != 1 {
		t.Fatalf("resumed hits = %+v, want position 1 only", hits)
	}
}

func TestScanIdentityMismatchRejected(t *testing.T) {
	dir := t.TempDir()
	s1, err := CreateOrOpen(dir, "scan-1", "http://a/FUZZ", nil, 10)
	if err != nil {
		t.Fatal(err)
	}
	s1.Record(Entry{Position: 1, Inputs: map[string]string{"FUZZ": "x"}, Done: true})
	if err := s1.Flush(); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateOrOpen(dir, "scan-2", "http://b/FUZZ", nil, 10); !errors.Is(err, ErrStaleCheckpoint) {
		t.Fatalf("err = %v, want ErrStaleCheckpoint", err)
	}
}

func TestCorruptFileRejectedClearly(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, StateFileName)
	if err := writeTestFile(path, "{not json"); err != nil {
		t.Fatal(err)
	}
	if _, err := CreateOrOpen(dir, "x", "u", nil, 1); err == nil {
		t.Fatal("corrupt checkpoint should fail with a clear error")
	}
}

func TestBaselineAndSuppressorPersistence(t *testing.T) {
	dir := t.TempDir()
	store, _ := CreateOrOpen(dir, "scan-x", "u", nil, 5)
	store.SaveBaselines(map[string]heuristics.BaselineGroup{
		".php": {Key: ".php", Ready: true, Points: []heuristics.BaselinePoint{{StatusCode: 404, BodyHash: "z"}}},
	})
	store.SaveSuppressors([]heuristics.Suppressor{{ID: "fp-1", BodyHash: "waf", StatusCode: 403}})
	if err := store.Flush(); err != nil {
		t.Fatal(err)
	}
	reopened, err := CreateOrOpen(dir, "scan-x", "u", nil, 5)
	if err != nil {
		t.Fatal(err)
	}
	st := reopened.State()
	g := st.Baselines[".php"]
	if !g.Ready || len(g.Points) != 1 || g.Points[0].StatusCode != 404 {
		t.Errorf("baseline not restored: %+v", g)
	}
	if len(st.Suppressors) != 1 || st.Suppressors[0].BodyHash != "waf" {
		t.Errorf("suppressors not restored: %+v", st.Suppressors)
	}
}

func TestCloseMakesRecordANoOp(t *testing.T) {
	dir := t.TempDir()
	store, _ := CreateOrOpen(dir, "s", "u", nil, 1)
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	before := store.State().Completed
	store.Record(Entry{Position: 9, Inputs: map[string]string{"FUZZ": "x"}, Done: true})
	if store.State().Completed != before {
		t.Error("Record after Close must be a no-op")
	}
}

func writeTestFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o640)
}
