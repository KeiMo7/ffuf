package e2e

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ffuf/ffuf/v2/pkg/testtarget"
)

type sarifE2EDocument struct {
	Version string `json:"version"`
	Runs    []struct {
		Invocations []struct {
			ExecutionSuccessful bool `json:"executionSuccessful"`
		} `json:"invocations"`
		Results []struct {
			RuleID    string `json:"ruleId"`
			Level     string `json:"level"`
			Locations []struct {
				PhysicalLocation struct {
					ArtifactLocation struct {
						URI string `json:"uri"`
					} `json:"artifactLocation"`
					Region struct {
						StartLine int `json:"startLine"`
					} `json:"region"`
				} `json:"physicalLocation"`
			} `json:"locations"`
		} `json:"results"`
	} `json:"runs"`
}

func readE2ESARIF(t *testing.T, filename string) sarifE2EDocument {
	t.Helper()
	data, err := os.ReadFile(filename)
	if err != nil {
		t.Fatalf("read SARIF output: %v", err)
	}
	var document sarifE2EDocument
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatalf("decode SARIF output: %v", err)
	}
	return document
}

func TestE2E_SARIFOutput(t *testing.T) {
	target := testtarget.New()
	defer target.Close()

	wordlist := writeWordlist(t, []string{"ok", "bad", "missing"})
	filename := filepath.Join(t.TempDir(), "ffuf.sarif")
	_ = runFfuf(t, nil,
		"-u", target.URL+"/map/FUZZ", "-w", wordlist,
		"-mc", "all", "-t", "1", "-noninteractive", "-s",
		"-o", filename, "-of", "sarif",
	)

	document := readE2ESARIF(t, filename)
	if document.Version != "2.1.0" {
		t.Errorf("version = %q, want 2.1.0", document.Version)
	}
	if len(document.Runs) != 1 {
		t.Fatalf("runs = %d, want 1", len(document.Runs))
	}
	run := document.Runs[0]
	if !run.Invocations[0].ExecutionSuccessful {
		t.Error("successful CLI scan marked executionSuccessful=false")
	}
	if len(run.Results) != 3 {
		t.Fatalf("results = %d, want 3", len(run.Results))
	}
	rules := make(map[string]string)
	lines := make(map[int]bool)
	for _, result := range run.Results {
		rules[result.RuleID] = result.Level
		location := result.Locations[0].PhysicalLocation
		if filepath.IsAbs(location.ArtifactLocation.URI) || strings.Contains(location.ArtifactLocation.URI, ":\\") {
			t.Errorf("artifact URI is absolute: %q", location.ArtifactLocation.URI)
		}
		lines[location.Region.StartLine] = true
	}
	if len(rules) != 3 ||
		rules["ffuf.http.success"] != "warning" ||
		rules["ffuf.http.client-error"] != "note" ||
		rules["ffuf.http.server-error"] != "error" {
		t.Errorf("rules/levels = %v, want success=warning, client-error=note, server-error=error", rules)
	}
	for _, line := range []int{1, 2, 3} {
		if !lines[line] {
			t.Errorf("missing finding at dictionary line %d: %v", line, lines)
		}
	}
}

func TestE2E_SARIFZeroResults(t *testing.T) {
	target := testtarget.New()
	defer target.Close()

	wordlist := writeWordlist(t, []string{"404"})
	filename := filepath.Join(t.TempDir(), "ffuf.sarif")
	_ = runFfuf(t, nil,
		"-u", target.URL+"/status/FUZZ", "-w", wordlist,
		"-mc", "200", "-t", "1", "-noninteractive", "-s",
		"-o", filename, "-of", "sarif",
	)

	document := readE2ESARIF(t, filename)
	if len(document.Runs) != 1 || len(document.Runs[0].Results) != 0 {
		t.Fatalf("zero-match scan results = %+v, want empty", document.Runs)
	}
	if !document.Runs[0].Invocations[0].ExecutionSuccessful {
		t.Error("successful zero-match scan marked executionSuccessful=false")
	}
}
