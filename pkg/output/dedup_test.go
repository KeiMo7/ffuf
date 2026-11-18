package output

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/ffuf/ffuf/v2/pkg/ffuf"
	"github.com/ffuf/ffuf/v2/pkg/fingerprint"
)

func testDedupConfig(t *testing.T, history string) *ffuf.Config {
	t.Helper()
	rules, err := fingerprint.ParseRules("test-rules", []byte(`request_id=[a-f0-9]+`))
	if err != nil {
		t.Fatalf("ParseRules: %v", err)
	}
	return &ffuf.Config{
		Dedup:            true,
		DedupHistoryFile: history,
		DedupRules:       rules,
		DedupThreshold:   1024,
		Url:              "http://example.test/FUZZ",
		Quiet:            true,
	}
}

func responseWithBody(t *testing.T, rules *fingerprint.Rules, url string, body string) ffuf.Response {
	t.Helper()
	stream := fingerprint.NewStream(rules, 1024)
	if _, err := stream.Write([]byte(body)); err != nil {
		t.Fatalf("fingerprint Write: %v", err)
	}
	return ffuf.Response{
		StatusCode:    200,
		ContentLength: int64(len(body)),
		Data:          []byte(body),
		Fingerprint:   stream.Finish(),
		Headers:       map[string][]string{},
		Request: &ffuf.Request{
			Method: "GET",
			Url:    url,
			Input:  map[string][]byte{"FUZZ": []byte(url)},
		},
	}
}

func TestDedupEmptyBodyFoldsButUnavailableFingerprintDoesNot(t *testing.T) {
	conf := testDedupConfig(t, filepath.Join(t.TempDir(), "history.json"))
	out := NewStdoutput(conf)
	out.SetPaused(true)

	emptyA := responseWithBody(t, conf.DedupRules, "http://example.test/empty-a", "")
	emptyB := responseWithBody(t, conf.DedupRules, "http://example.test/empty-b", "")
	out.Result(emptyA)
	out.Result(emptyB)

	brokenA := responseWithBody(t, conf.DedupRules, "http://example.test/broken-a", "")
	brokenA.Fingerprint = fingerprint.Result{Valid: false, Source: fingerprint.SourceUnavailable, Error: "read failed"}
	brokenB := brokenA
	brokenB.Request = &ffuf.Request{Method: "GET", Url: "http://example.test/broken-b", Input: map[string][]byte{"FUZZ": []byte("broken-b")}}
	out.Result(brokenA)
	out.Result(brokenB)

	path := filepath.Join(t.TempDir(), "out.json")
	if err := out.SaveFile(path, "json"); err != nil {
		t.Fatalf("SaveFile: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Results []struct {
			URL   string          `json:"url"`
			Dedup *ffuf.DedupInfo `json:"dedup"`
		} `json:"results"`
	}
	if err := json.Unmarshal(data, &doc); err != nil {
		t.Fatalf("unmarshal output: %v", err)
	}
	if len(doc.Results) != 3 {
		t.Fatalf("got %d results, want 3 (one empty representative and two read failures)", len(doc.Results))
	}
	byURL := make(map[string]*ffuf.DedupInfo)
	for _, result := range doc.Results {
		byURL[result.URL] = result.Dedup
	}
	empty := byURL["http://example.test/empty-a"]
	if empty == nil || empty.FoldedCount != 1 || len(empty.OriginalPaths) != 2 {
		t.Fatalf("empty-body group = %+v, want folded with two paths", empty)
	}
	for _, url := range []string{"http://example.test/broken-a", "http://example.test/broken-b"} {
		info := byURL[url]
		if info == nil || info.FoldedCount != 0 || info.UnavailableReason == "" {
			t.Errorf("unavailable result %s = %+v, want independent with a reason", url, info)
		}
	}
}

func TestDedupCorruptHistoryDegradesToSingleRound(t *testing.T) {
	history := filepath.Join(t.TempDir(), "history.json")
	if err := os.WriteFile(history, []byte("{not-json"), 0644); err != nil {
		t.Fatal(err)
	}
	out := NewStdoutput(testDedupConfig(t, history))
	warnings := out.dedup.Warnings()
	if len(warnings) == 0 || !strings.Contains(strings.Join(warnings, "\n"), "single-round mode") {
		t.Fatalf("corrupt-history warnings = %v, want a single-round degradation warning", warnings)
	}
	if out.dedup.historyWritable {
		t.Fatal("corrupt history should not be overwritten silently")
	}
}

func TestDedupDisabledLeavesExistingFormatsUnchanged(t *testing.T) {
	conf := &ffuf.Config{InputProviders: []ffuf.InputProviderConfig{{Keyword: "FUZZ"}}}
	res := []ffuf.Result{{
		Input:         map[string][]byte{"FUZZ": []byte("value")},
		StatusCode:    200,
		ContentLength: 3,
		Url:           "http://example.test/value",
	}}
	dir := t.TempDir()

	csvPath := filepath.Join(dir, "out.csv")
	if err := writeCSV(csvPath, conf, res, false); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(csvPath)
	rows, err := csv.NewReader(strings.NewReader(string(data))).ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	wantHeader := append(append([]string{}, conf.InputProviders[0].Keyword), staticheaders...)
	if strings.Join(rows[0], ",") != strings.Join(wantHeader, ",") {
		t.Fatalf("CSV header changed while dedup was disabled: %v", rows[0])
	}

	jsonPath := filepath.Join(dir, "out.json")
	if err := writeJSON(jsonPath, conf, res); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(jsonPath)
	if strings.Contains(string(data), `"dedup"`) {
		t.Fatalf("JSON gained a dedup field while disabled: %s", data)
	}

	mdPath := filepath.Join(dir, "out.md")
	if err := writeMarkdown(mdPath, conf, res); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(mdPath)
	if strings.Contains(string(data), "Dedup Round") {
		t.Fatalf("Markdown gained dedup columns while disabled: %s", data)
	}

	htmlPath := filepath.Join(dir, "out.html")
	if err := writeHTML(htmlPath, conf, res); err != nil {
		t.Fatal(err)
	}
	data, _ = os.ReadFile(htmlPath)
	if strings.Contains(string(data), "Dedup round") {
		t.Fatalf("HTML gained dedup columns while disabled")
	}
}

func TestDedupLargeDictionaryDoesNotRetainResponseBodies(t *testing.T) {
	conf := testDedupConfig(t, filepath.Join(t.TempDir(), "history.json"))
	conf.DedupThreshold = 1024
	out := NewStdoutput(conf)
	out.SetPaused(true)

	body := bytes.Repeat([]byte("0123456789abcdef"), 16384) // 256 KiB
	stream := fingerprint.NewStream(conf.DedupRules, conf.DedupThreshold)
	_, _ = stream.Write(body)
	fp := stream.Finish()

	runtime.GC()
	var before runtime.MemStats
	runtime.ReadMemStats(&before)

	const results = 512
	for i := 0; i < results; i++ {
		bodyCopy := append([]byte(nil), body...)
		url := fmt.Sprintf("http://example.test/path-%04d", i)
		out.Result(ffuf.Response{
			StatusCode:    200,
			ContentLength: int64(len(bodyCopy)),
			Data:          bodyCopy,
			Fingerprint:   fp,
			Headers:       map[string][]string{},
			Request: &ffuf.Request{
				Method: "GET",
				Url:    url,
				Input:  map[string][]byte{"FUZZ": []byte(url)},
			},
		})
	}
	runtime.GC()
	var after runtime.MemStats
	runtime.ReadMemStats(&after)

	if got := len(out.GetCurrentResults()); got != 1 {
		t.Fatalf("retained %d results, want one representative", got)
	}
	group := out.dedup.groups[fp.Digest]
	if group == nil || len(group.paths) != results {
		t.Fatalf("dedup group paths = %v, want %d", group, results)
	}
	const maxMetadataHeap = 32 << 20
	delta := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	t.Logf("folded %d responses of %d bytes each; retained heap delta=%d bytes", results, len(body), delta)
	if delta > maxMetadataHeap {
		t.Fatalf("heap grew by %d bytes for %d folded 256 KiB bodies; response bodies were retained", delta, results)
	}
}

func TestDedupFormatsContainRoundAndEquivalenceMetadata(t *testing.T) {
	conf := &ffuf.Config{
		Dedup:          true,
		InputProviders: []ffuf.InputProviderConfig{{Keyword: "FUZZ"}},
	}
	res := []ffuf.Result{{
		Input:         map[string][]byte{"FUZZ": []byte("value")},
		StatusCode:    200,
		ContentLength: 3,
		Url:           "http://example.test/value",
		Dedup: &ffuf.DedupInfo{
			Round:             "2",
			Equivalent:        true,
			EquivalentRounds:  []string{"1"},
			FoldedCount:       1,
			OriginalPaths:     []string{"http://example.test/value", "http://example.test/other"},
			Fingerprint:       "abc123",
			FingerprintSource: "reused",
			FingerprintValid:  true,
		},
	}}
	dir := t.TempDir()

	csvPath := filepath.Join(dir, "out.csv")
	if err := writeCSV(csvPath, conf, res, false); err != nil {
		t.Fatal(err)
	}
	data, _ := os.ReadFile(csvPath)
	for _, want := range []string{"dedup_round", "dedup_equivalent_rounds", "dedup_original_paths"} {
		if !strings.Contains(string(data), want) {
			t.Errorf("CSV missing %q: %s", want, data)
		}
	}

	for _, tc := range []struct {
		name   string
		format string
		write  func(string, *ffuf.Config, []ffuf.Result) error
		want   string
	}{
		{"json", "json", func(p string, c *ffuf.Config, r []ffuf.Result) error { return writeJSON(p, c, r) }, `"fingerprint_source":"reused"`},
		{"ejson", "ejson", func(p string, c *ffuf.Config, r []ffuf.Result) error { return writeEJSON(p, c, r) }, `"fingerprint_source":"reused"`},
		{"md", "md", func(p string, c *ffuf.Config, r []ffuf.Result) error { return writeMarkdown(p, c, r) }, "Dedup Equivalent"},
		{"html", "html", func(p string, c *ffuf.Config, r []ffuf.Result) error { return writeHTML(p, c, r) }, "Dedup equivalent"},
	} {
		path := filepath.Join(dir, "out."+tc.name)
		if err := tc.write(path, conf, res); err != nil {
			t.Fatalf("%s: %v", tc.format, err)
		}
		data, _ := os.ReadFile(path)
		if !strings.Contains(string(data), tc.want) {
			t.Errorf("%s missing %q", tc.format, tc.want)
		}
	}
}
