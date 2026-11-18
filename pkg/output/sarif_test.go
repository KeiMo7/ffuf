package output

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ffuf/ffuf/v2/pkg/ffuf"
	"github.com/santhosh-tekuri/jsonschema/v6"
)

type sarifTestDocument struct {
	Version string `json:"version"`
	Runs    []struct {
		Tool struct {
			Driver struct {
				Rules []struct {
					ID                   string `json:"id"`
					DefaultConfiguration struct {
						Level string `json:"level"`
					} `json:"defaultConfiguration"`
				} `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Invocations []struct {
			ExecutionSuccessful bool `json:"executionSuccessful"`
		} `json:"invocations"`
		Results []struct {
			RuleID    string       `json:"ruleId"`
			RuleIndex int          `json:"ruleIndex"`
			Level     string       `json:"level"`
			Message   sarifMessage `json:"message"`
			Locations []struct {
				PhysicalLocation struct {
					ArtifactLocation struct {
						URI string `json:"uri"`
					} `json:"artifactLocation"`
					Region sarifRegion `json:"region"`
				} `json:"physicalLocation"`
			} `json:"locations"`
			Properties struct {
				URL     string              `json:"url"`
				Status  int64               `json:"status"`
				Inputs  map[string][]string `json:"inputs"`
				Sources []sarifSource       `json:"sources"`
			} `json:"properties"`
		} `json:"results"`
	} `json:"runs"`
}

func writeTestSARIF(t *testing.T, root string, config *ffuf.Config, results []ffuf.Result, successful bool) (string, []byte) {
	t.Helper()
	filename := filepath.Join(t.TempDir(), "ffuf.sarif")
	if err := writeSARIFWithOptions(filename, config, results, sarifWriteOptions{
		Repository:          root,
		ExecutionSuccessful: successful,
	}); err != nil {
		t.Fatalf("writeSARIFWithOptions: %v", err)
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("read SARIF: %v", err)
	}
	validateSARIFAgainstOfficialSchema(t, data)
	return filename, data
}

func decodeSARIF(t *testing.T, data []byte) sarifTestDocument {
	t.Helper()
	var document sarifTestDocument
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("decode SARIF: %v", err)
	}
	return document
}

func validateSARIFAgainstOfficialSchema(t *testing.T, data []byte) {
	t.Helper()
	schemaBytes, err := os.ReadFile(filepath.Join("testdata", "sarif-2.1.0.json"))
	if err != nil {
		t.Fatalf("read official SARIF schema: %v", err)
	}
	schemaDocument, err := jsonschema.UnmarshalJSON(bytes.NewReader(schemaBytes))
	if err != nil {
		t.Fatalf("parse official SARIF schema: %v", err)
	}
	compiler := jsonschema.NewCompiler()
	const schemaResource = "https://json.schemastore.org/sarif-2.1.0.json"
	if err := compiler.AddResource(schemaResource, schemaDocument); err != nil {
		t.Fatalf("add official SARIF schema: %v", err)
	}
	schema, err := compiler.Compile(schemaResource)
	if err != nil {
		t.Fatalf("compile official SARIF schema: %v", err)
	}
	instance, err := jsonschema.UnmarshalJSON(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("parse SARIF instance: %v", err)
	}
	if err := schema.Validate(instance); err != nil {
		t.Fatalf("SARIF does not validate against the official 2.1.0 schema: %v", err)
	}
}

func TestSARIFMultipleRulesAndMergeSources(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, ".git"), 0755); err != nil {
		t.Fatal(err)
	}
	wordlists := filepath.Join(root, "wordlists")
	if err := os.MkdirAll(wordlists, 0755); err != nil {
		t.Fatal(err)
	}
	first := filepath.Join(wordlists, "first.txt")
	second := filepath.Join(wordlists, "second.txt")
	if err := os.WriteFile(first, []byte("admin\nlogin\napi\n"), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(second, []byte("admin\n"), 0644); err != nil {
		t.Fatal(err)
	}
	config := &ffuf.Config{InputProviders: []ffuf.InputProviderConfig{
		{Name: "wordlist", Keyword: "FUZZ", Value: first},
		{Name: "wordlist", Keyword: "FUZZ", Value: second},
	}}
	results := []ffuf.Result{
		{StatusCode: 200, Url: "http://example.test/admin", Position: 1, Input: map[string][]byte{"FUZZ": []byte("admin")}},
		{StatusCode: 200, Url: "http://example.test/login", Position: 2, Input: map[string][]byte{"FUZZ": []byte("login")}},
		{StatusCode: 403, Url: "http://example.test/admin", Position: 1, Input: map[string][]byte{"FUZZ": []byte("admin")}},
		{StatusCode: 500, Url: "http://example.test/api", Position: 3, Input: map[string][]byte{"FUZZ": []byte("api")}},
		// A duplicate path/rule from another dictionary must merge into the first
		// finding and retain both dictionary sources.
		{StatusCode: 200, Url: "http://example.test/admin", Position: 1, Input: map[string][]byte{"FUZZ": []byte("admin")}},
	}

	_, data := writeTestSARIF(t, root, config, results, true)
	document := decodeSARIF(t, data)
	if len(document.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(document.Runs))
	}
	run := document.Runs[0]
	if len(run.Results) != 4 {
		t.Fatalf("results = %d, want 4 after duplicate merge", len(run.Results))
	}

	ruleIDs := make(map[string]bool)
	levels := make(map[string]string)
	var successAdmin *struct {
		RuleID    string       `json:"ruleId"`
		RuleIndex int          `json:"ruleIndex"`
		Level     string       `json:"level"`
		Message   sarifMessage `json:"message"`
		Locations []struct {
			PhysicalLocation struct {
				ArtifactLocation struct {
					URI string `json:"uri"`
				} `json:"artifactLocation"`
				Region sarifRegion `json:"region"`
			} `json:"physicalLocation"`
		} `json:"locations"`
		Properties struct {
			URL     string              `json:"url"`
			Status  int64               `json:"status"`
			Inputs  map[string][]string `json:"inputs"`
			Sources []sarifSource       `json:"sources"`
		} `json:"properties"`
	}
	for i := range run.Results {
		result := &run.Results[i]
		ruleIDs[result.RuleID] = true
		levels[result.RuleID] = result.Level
		if strings.Contains(result.RuleID, "/") || strings.Contains(result.RuleID, root) {
			t.Errorf("rule ID is not stable/readable: %q", result.RuleID)
		}
		if result.Properties.URL == "http://example.test/admin" && result.RuleID == "ffuf.http.success" {
			successAdmin = result
		}
	}
	if len(ruleIDs) != 3 {
		t.Errorf("rule IDs = %v, want success/access-controlled/server-error", ruleIDs)
	}
	if levels["ffuf.http.success"] != sarifLevelWarning ||
		levels["ffuf.http.access-controlled"] != sarifLevelNote ||
		levels["ffuf.http.server-error"] != sarifLevelError {
		t.Errorf("severity levels = %v, want warning/note/error mapping", levels)
	}
	if successAdmin == nil {
		t.Fatal("merged success finding for /admin not found")
	}
	if successAdmin.RuleIndex != sarifRuleIndex("ffuf.http.success") {
		t.Errorf("ruleIndex = %d, want %d", successAdmin.RuleIndex, sarifRuleIndex("ffuf.http.success"))
	}
	if got := successAdmin.Locations[0].PhysicalLocation.ArtifactLocation.URI; got != "wordlists/first.txt" {
		t.Errorf("primary artifact = %q, want wordlists/first.txt", got)
	}
	if got := successAdmin.Locations[0].PhysicalLocation.Region.StartLine; got != 1 {
		t.Errorf("start line = %d, want 1", got)
	}
	if got := len(successAdmin.Properties.Sources); got != 2 {
		t.Errorf("merged dictionary sources = %d, want 2: %+v", got, successAdmin.Properties.Sources)
	}

	successLines := make(map[int]bool)
	for _, result := range run.Results {
		if result.RuleID == "ffuf.http.success" {
			successLines[result.Locations[0].PhysicalLocation.Region.StartLine] = true
			if result.Properties.URL == "http://example.test/login" && len(result.Properties.Sources) != 1 {
				t.Errorf("login finding sources = %+v, want only the dictionary containing login", result.Properties.Sources)
			}
		}
	}
	if !successLines[1] || !successLines[2] {
		t.Errorf("successful findings lines = %v, want separate lines 1 and 2", successLines)
	}
}

// TestSARIFOfficialSchema is the independent schema gate. The helper above is
// used by the behavioral tests too, but this named test makes schema validation
// an explicit acceptance criterion.
func TestSARIFOfficialSchema(t *testing.T) {
	root := t.TempDir()
	wordlist := filepath.Join(root, "words.txt")
	if err := os.WriteFile(wordlist, []byte("found\n"), 0644); err != nil {
		t.Fatal(err)
	}
	config := &ffuf.Config{InputProviders: []ffuf.InputProviderConfig{{
		Name: "wordlist", Keyword: "FUZZ", Value: wordlist,
	}}}
	results := []ffuf.Result{{
		StatusCode: 500, Url: "http://example.test/found", Position: 1,
		Input: map[string][]byte{"FUZZ": []byte("found")},
	}}
	_, data := writeTestSARIF(t, root, config, results, true)
	validateSARIFAgainstOfficialSchema(t, data)
}

func TestSARIFZeroResults(t *testing.T) {
	_, data := writeTestSARIF(t, t.TempDir(), &ffuf.Config{}, nil, true)
	if !bytes.Contains(data, []byte(`"results":[]`)) {
		t.Errorf("zero-result SARIF must contain an empty results array: %s", data)
	}
	document := decodeSARIF(t, data)
	if len(document.Runs) != 1 || len(document.Runs[0].Results) != 0 {
		t.Errorf("zero-result SARIF has results: %+v", document.Runs)
	}
	if !document.Runs[0].Invocations[0].ExecutionSuccessful {
		t.Error("successful zero-result scan was marked executionSuccessful=false")
	}
}

func TestSARIFScanFailureInvocation(t *testing.T) {
	_, data := writeTestSARIF(t, t.TempDir(), &ffuf.Config{}, nil, false)
	document := decodeSARIF(t, data)
	if document.Runs[0].Invocations[0].ExecutionSuccessful {
		t.Error("failed scan was marked executionSuccessful=true")
	}
}

func TestSARIFOutputErrorMarksInvocationFailed(t *testing.T) {
	root := t.TempDir()
	wordlist := filepath.Join(root, "words.txt")
	if err := os.WriteFile(wordlist, []byte("found\n"), 0644); err != nil {
		t.Fatal(err)
	}
	filename := filepath.Join(t.TempDir(), "ffuf.sarif")
	config := &ffuf.Config{
		OutputFile: filename,
		InputProviders: []ffuf.InputProviderConfig{{
			Name: "wordlist", Keyword: "FUZZ", Value: wordlist,
		}},
	}
	output := NewStdoutput(config)
	output.SetCurrentResults([]ffuf.Result{{
		StatusCode: 200, Url: "http://example.test/found", Position: 1,
		Input: map[string][]byte{"FUZZ": []byte("found")},
	}})
	_ = captureStderr(t, func() {
		output.Error("simulated scan failure")
	})
	if err := output.SaveFile(filename, "sarif"); err != nil {
		t.Fatalf("SaveFile(sarif): %v", err)
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	document := decodeSARIF(t, data)
	if document.Runs[0].Invocations[0].ExecutionSuccessful {
		t.Error("SARIF output after Output.Error was marked executionSuccessful=true")
	}
}

func TestSARIFAtomicWriteLeavesNoPartialFile(t *testing.T) {
	directory := t.TempDir()
	filename := filepath.Join(directory, "ffuf.sarif")
	err := writeAtomic(filename, 0644, func(w io.Writer) error {
		if _, err := io.WriteString(w, `{"version":"2.1.0","runs":[`); err != nil {
			return err
		}
		return errors.New("simulated scan failure")
	})
	if err == nil {
		t.Fatal("writeAtomic returned nil for a failed write")
	}
	if _, err := os.Stat(filename); !os.IsNotExist(err) {
		t.Fatalf("partial output file exists after failure: %v", err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.Contains(entry.Name(), ".tmp-") {
			t.Errorf("temporary file left behind: %s", entry.Name())
		}
	}
}

func TestSARIFSelfCheckReportsFieldPath(t *testing.T) {
	result := sarifResult{
		RuleID:    "ffuf.http.success",
		RuleIndex: sarifRuleIndex("ffuf.http.success"),
		Level:     sarifLevelWarning,
		Message:   sarifMessage{Text: "message"},
		Locations: []sarifLocation{{
			PhysicalLocation: sarifPhysicalLocation{
				ArtifactLocation: sarifArtifactLocation{URI: "wordlists/input.txt"},
				Region:           sarifRegion{StartLine: 0, StartColumn: 1, EndLine: 0, EndColumn: 1},
			},
		}},
	}
	err := validateSARIFResult(result, 7)
	if err == nil {
		t.Fatal("self-check accepted an invalid startLine")
	}
	want := "runs[0].results[7].locations[0].physicalLocation.region.startLine"
	if !strings.Contains(err.Error(), want) {
		t.Errorf("self-check error %q does not identify %s", err, want)
	}
}

func TestSARIFPathEscapingAndSymlinks(t *testing.T) {
	root := t.TempDir()
	wordlists := filepath.Join(root, "wordlists")
	if err := os.MkdirAll(wordlists, 0755); err != nil {
		t.Fatal(err)
	}
	invalidName := string([]byte{'d', 'i', 'c', 't', '-', 0xff, '.', 't', 'x', 't'})
	invalidPath := filepath.Join(wordlists, invalidName)
	if err := os.WriteFile(invalidPath, []byte("needle\n"), 0644); err != nil {
		t.Fatal(err)
	}

	config := &ffuf.Config{InputProviders: []ffuf.InputProviderConfig{{
		Name:    "wordlist",
		Keyword: "FUZZ",
		Value:   invalidPath,
	}}}
	results := []ffuf.Result{{
		StatusCode: 200, Url: "http://example.test/needle", Position: 1,
		Input: map[string][]byte{"FUZZ": []byte("needle")},
	}}
	_, data := writeTestSARIF(t, root, config, results, true)
	if !bytes.Contains(data, []byte("wordlists/dict-%FF.txt")) {
		t.Errorf("non-UTF-8 path was not percent-encoded: %s", data)
	}
	if bytes.Contains(data, []byte(root)) {
		t.Errorf("absolute repository path leaked into SARIF: %s", data)
	}

	outside := t.TempDir()
	outsideFile := filepath.Join(outside, "outside.txt")
	if err := os.WriteFile(outsideFile, []byte("needle\n"), 0644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(wordlists, "linked.txt")
	if err := os.Symlink(outsideFile, link); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	config.InputProviders[0].Value = link
	_, data = writeTestSARIF(t, root, config, results, true)
	if bytes.Contains(data, []byte(outside)) {
		t.Errorf("symlink target path leaked into SARIF: %s", data)
	}
	if !bytes.Contains(data, []byte("wordlists/input-1-FUZZ.txt")) {
		t.Errorf("outside symlink was not mapped to a stable relative artifact: %s", data)
	}

	long := strings.Repeat("a", 12000)
	encoded := sarifEncodeURI(long)
	payload, err := json.Marshal(map[string]string{"uri": encoded})
	if err != nil {
		t.Fatalf("long path JSON marshal: %v", err)
	}
	if !json.Valid(payload) {
		t.Errorf("long path produced invalid JSON: %s", payload)
	}
}

func TestStdoutputSaveFileSARIF(t *testing.T) {
	root := t.TempDir()
	wordlist := filepath.Join(root, "words.txt")
	if err := os.WriteFile(wordlist, []byte("admin\n"), 0644); err != nil {
		t.Fatal(err)
	}
	config := &ffuf.Config{
		OutputFile: filepath.Join(t.TempDir(), "out.sarif"),
		InputProviders: []ffuf.InputProviderConfig{{
			Name: "wordlist", Keyword: "FUZZ", Value: wordlist,
		}},
	}
	output := NewStdoutput(config)
	output.SetCurrentResults([]ffuf.Result{{
		StatusCode: 200, Url: "http://example.test/admin", Position: 1,
		Input: map[string][]byte{"FUZZ": []byte("admin")},
	}})
	if err := output.SaveFile(config.OutputFile, "sarif"); err != nil {
		t.Fatalf("SaveFile(sarif): %v", err)
	}
	data, err := os.ReadFile(config.OutputFile)
	if err != nil {
		t.Fatal(err)
	}
	validateSARIFAgainstOfficialSchema(t, data)
}

func TestSARIFIsNotImplicitlyAddedToAllFormats(t *testing.T) {
	config := &ffuf.Config{OutputFile: filepath.Join(t.TempDir(), "out")}
	output := NewStdoutput(config)
	output.SetCurrentResults([]ffuf.Result{{
		StatusCode: 200, Url: "http://example.test/", Input: map[string][]byte{"FUZZ": []byte("x")},
	}})
	base := config.OutputFile
	if err := output.SaveFile(base, "all"); err != nil {
		t.Fatalf("SaveFile(all): %v", err)
	}
	if _, err := os.Stat(base + ".sarif"); !os.IsNotExist(err) {
		t.Errorf("-of all unexpectedly created a SARIF file")
	}
	for _, extension := range []string{"json", "ejson", "html", "md", "csv", "ecsv"} {
		if _, err := os.Stat(base + "." + extension); err != nil {
			t.Errorf("-of all no longer created %s output: %v", extension, err)
		}
	}
}

func TestSARIFLargeResultSet(t *testing.T) {
	const count = 10000
	results := make([]ffuf.Result, 0, count)
	for i := 0; i < count; i++ {
		results = append(results, ffuf.Result{
			StatusCode: 200,
			Url:        fmt.Sprintf("http://example.test/resource/%d", i),
			Position:   i + 1,
			Input:      map[string][]byte{"FUZZ": []byte(fmt.Sprintf("resource-%d", i))},
		})
	}
	filename := filepath.Join(t.TempDir(), "large.sarif")
	if err := writeSARIFWithOptions(filename, &ffuf.Config{}, results, sarifWriteOptions{
		Repository:          t.TempDir(),
		ExecutionSuccessful: true,
	}); err != nil {
		t.Fatalf("write large SARIF: %v", err)
	}
	info, err := os.Stat(filename)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() == 0 {
		t.Fatal("large SARIF output is empty")
	}
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatal(err)
	}
	document := decodeSARIF(t, data)
	if got := len(document.Runs[0].Results); got != count {
		t.Fatalf("large SARIF results = %d, want %d", got, count)
	}
}
