package integration

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/ffuf/ffuf/v2/pkg/ffuf"
)

type dedupJSONResult struct {
	URL    string          `json:"url"`
	Status int64           `json:"status"`
	Length int64           `json:"length"`
	Dedup  *ffuf.DedupInfo `json:"dedup"`
}

func newDedupTarget(t *testing.T) *httptest.Server {
	t.Helper()
	var n atomic.Int64
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/dedup/")
		switch path {
		case "same/a", "same/b":
			fmt.Fprint(w, "identical shared page")
		case "meta/a":
			w.Header().Set("Location", "/landed")
			w.WriteHeader(http.StatusFound)
			fmt.Fprint(w, "alpha")
		case "meta/b":
			w.Header().Set("Location", "/landed")
			w.WriteHeader(http.StatusFound)
			fmt.Fprint(w, "bravo")
		case "volatile/a", "volatile/b":
			id := n.Add(1)
			fmt.Fprintf(w, `{"timestamp":"2026-11-18T00:00:%02dZ","request_id":"%06x","token":"tok-%04x","value":"same"}`, id, id, id)
		case "empty/a", "empty/b":
			w.WriteHeader(http.StatusOK)
		case "hist":
			w.Header().Set("ETag", `"stable-v1"`)
			fmt.Fprint(w, "history stable page")
		case "broken/a", "broken/b":
			hijacker, ok := w.(http.Hijacker)
			if !ok {
				t.Errorf("test server does not support hijacking")
				return
			}
			conn, buf, err := hijacker.Hijack()
			if err != nil {
				t.Errorf("Hijack: %v", err)
				return
			}
			fmt.Fprint(buf, "HTTP/1.1 200 OK\r\nContent-Length: 100\r\nConnection: close\r\n\r\nshort")
			_ = buf.Flush()
			_ = conn.Close()
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
}

func writeDedupRules(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "dedup-rules.txt")
	rules := `# one Go regexp per line
"timestamp":"[^"]+"
"request_id":"[^"]+"
"token":"[^"]+"
`
	if err := os.WriteFile(path, []byte(rules), 0644); err != nil {
		t.Fatal(err)
	}
	return path
}

func runDedupJSON(t *testing.T, targetURL string, words []string, history, round string) []dedupJSONResult {
	t.Helper()
	outputPath := filepath.Join(t.TempDir(), "dedup-results.json")
	out := runScanStdout(t, targetURL+"/dedup/FUZZ", words,
		func(opts *ffuf.ConfigOptions) {
			opts.General.Threads = 1
			opts.Output.Dedup = true
			opts.Output.DedupRules = writeDedupRules(t)
			opts.Output.DedupHistory = history
			opts.Output.DedupRound = round
			opts.Output.DedupThreshold = 1024
			opts.Output.OutputFile = outputPath
			opts.Output.OutputFormat = "json"
		},
		func(mm ffuf.MatcherManager) { mustMatch(t, mm, "status", "all") },
	)
	if err := out.SaveFile(outputPath, "json"); err != nil {
		t.Fatalf("SaveFile: %v", err)
	}
	data, err := os.ReadFile(outputPath)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Results []dedupJSONResult `json:"results"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal JSON results: %v\n%s", err, data)
	}
	return doc.Results
}

func resultsByURL(results []dedupJSONResult) map[string]dedupJSONResult {
	out := make(map[string]dedupJSONResult, len(results))
	for _, result := range results {
		out[result.URL] = result
	}
	return out
}

func TestDedupAgainstLocalHTTPForms(t *testing.T) {
	target := newDedupTarget(t)
	defer target.Close()
	history := filepath.Join(t.TempDir(), "history.json")

	results := runDedupJSON(t, target.URL, []string{
		"same/a", "same/b",
		"meta/a", "meta/b",
		"volatile/a", "volatile/b",
		"empty/a", "empty/b",
		"broken/a", "broken/b",
	}, history, "1")

	if len(results) != 7 {
		t.Fatalf("retained %d results, want 7: %+v", len(results), results)
	}
	byURL := resultsByURL(results)

	same := byURL[target.URL+"/dedup/same/a"]
	if same.Dedup == nil || same.Dedup.FoldedCount != 1 || len(same.Dedup.OriginalPaths) != 2 {
		t.Fatalf("same-body group = %+v, want one folded path", same.Dedup)
	}
	if _, exists := byURL[target.URL+"/dedup/same/b"]; exists {
		t.Fatal("duplicate same-body path was retained")
	}

	for _, path := range []string{"meta/a", "meta/b"} {
		result := byURL[target.URL+"/dedup/"+path]
		if result.Status != http.StatusFound || result.Length != 5 {
			t.Errorf("%s metadata = status %d length %d, want 302/5", path, result.Status, result.Length)
		}
		if result.Dedup == nil || result.Dedup.FoldedCount != 0 {
			t.Errorf("%s was folded despite a different body: %+v", path, result.Dedup)
		}
	}

	volatile := byURL[target.URL+"/dedup/volatile/a"]
	if volatile.Dedup == nil || volatile.Dedup.FoldedCount != 1 {
		t.Fatalf("volatile-field group = %+v, want two paths folded after normalization", volatile.Dedup)
	}
	empty := byURL[target.URL+"/dedup/empty/a"]
	if empty.Dedup == nil || empty.Dedup.FoldedCount != 1 || !empty.Dedup.FingerprintValid || !empty.Dedup.FingerprintEmpty {
		t.Fatalf("empty-body group = %+v, want one fold", empty.Dedup)
	}
	for _, path := range []string{"broken/a", "broken/b"} {
		result := byURL[target.URL+"/dedup/"+path]
		if result.Dedup == nil || result.Dedup.FoldedCount != 0 || result.Dedup.UnavailableReason == "" || result.Dedup.FingerprintValid {
			t.Errorf("broken response %s = %+v, want independent and unavailable", path, result.Dedup)
		}
	}
}

func TestDedupHistoryReusesFingerprintAndMarksEquivalence(t *testing.T) {
	target := newDedupTarget(t)
	defer target.Close()
	history := filepath.Join(t.TempDir(), "history.json")

	round1 := runDedupJSON(t, target.URL, []string{"hist"}, history, "")
	if len(round1) != 1 || round1[0].Dedup == nil {
		t.Fatalf("round 1 results = %+v", round1)
	}
	if round1[0].Dedup.Round != "1" || round1[0].Dedup.Equivalent {
		t.Fatalf("round 1 dedup = %+v, want new result in round 1", round1[0].Dedup)
	}
	if round1[0].Dedup.FingerprintSource != "computed" {
		t.Fatalf("round 1 fingerprint source = %q, want computed", round1[0].Dedup.FingerprintSource)
	}

	round2 := runDedupJSON(t, target.URL, []string{"hist"}, history, "")
	if len(round2) != 1 || round2[0].Dedup == nil {
		t.Fatalf("round 2 results = %+v", round2)
	}
	info := round2[0].Dedup
	if info.Round != "2" {
		t.Errorf("round 2 label = %q, want 2", info.Round)
	}
	if !info.Equivalent || len(info.EquivalentRounds) != 1 || info.EquivalentRounds[0] != "1" {
		t.Errorf("round 2 equivalence = %+v, want equivalent to round 1", info)
	}
	if info.FingerprintSource != "reused" {
		t.Errorf("round 2 fingerprint source = %q, want reused from history cache", info.FingerprintSource)
	}
}
