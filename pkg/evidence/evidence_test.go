package evidence

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ffuf/ffuf/v2/pkg/heuristics"
)

func TestRecorder_AppendsValidJSONL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "evidence.jsonl")
	r, err := OpenRecorder(path)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := r.Write(Record{
			Position: i, Inputs: map[string]string{"FUZZ": "x"}, URL: "http://t/x",
			Legacy: i == 0,
			Verdict: &heuristics.Verdict{Hit: i == 1, Group: heuristics.GroupDefault,
				Evidence: []heuristics.Evidence{{Dimension: heuristics.DimStatus, Fired: true, Reason: "r"}}},
		}); err != nil {
			t.Fatal(err)
		}
	}
	if err := r.Close(); err != nil {
		t.Fatal(err)
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	lines := 0
	for scanner.Scan() {
		var rec Record
		if err := json.Unmarshal(scanner.Bytes(), &rec); err != nil {
			t.Fatalf("line %d not valid JSON: %v", lines, err)
		}
		lines++
	}
	if lines != 3 {
		t.Fatalf("got %d JSONL lines, want 3", lines)
	}
}

func TestDiff_DeltasEnumerateDimensions(t *testing.T) {
	d := Diff{
		Path: "/admin",
		A:    DiffEndpoint{Label: "get", Status: 302, Length: 100, MS: 5, BodyHash: "a", Redirect: "/login"},
		B:    DiffEndpoint{Label: "post", Status: 200, Length: 500, MS: 7, BodyHash: "b"},
	}
	deltas := d.Deltas()
	byDim := map[string]DimensionDelta{}
	for _, dl := range deltas {
		byDim[dl.Dimension] = dl
	}
	for _, dim := range []string{heuristics.DimStatus, "length", "words", "lines", "time_ms", "redirect", "body_hash"} {
		if _, ok := byDim[dim]; !ok {
			t.Errorf("diff missing dimension %q", dim)
		}
	}
	if !byDim[heuristics.DimStatus].Different || !byDim["length"].Different || !byDim["body_hash"].Different {
		t.Errorf("expected status/length/body to differ: %+v", byDim)
	}
	if !strings.Contains(byDim["time_ms"].Note, "auxiliary") {
		t.Errorf("timing delta should carry a jitter warning, got %q", byDim["time_ms"].Note)
	}
}
