package e2e

import (
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/ffuf/ffuf/v2/pkg/testtarget"
)

// writeTempFile writes content to a fresh temp file and returns its path.
func writeTempFile(t *testing.T, name, content string) string {
	t.Helper()
	dir := t.TempDir()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0640); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return p
}

// 验收4 / 硬约束4: enabling review does not change a byte of the stdout result
// stream. The same scan is run with and without -review and the JSON result
// lines must be identical; only the separate review file gains content.
func TestE2E_ReviewLeavesStdoutUnchanged(t *testing.T) {
	target := testtarget.New()
	defer target.Close()

	wl := writeWordlist(t, []string{"200", "301", "404", "500"})
	rules := writeTempFile(t, "rules.toml", `
combine_matchers = "or"
combine_filters = "or"

[[rules]]
id = "m"
side = "matcher"
kind = "status"
value = "all"

[[rules]]
id = "drop-404"
side = "filter"
kind = "status"
value = "404"
`)
	reviewFile := filepath.Join(t.TempDir(), "review.jsonl")

	common := []string{
		"-u", target.URL + "/status/FUZZ", "-w", wl,
		"-rules", rules, "-json", "-t", "1", "-noninteractive",
	}
	withoutReview := runFfuf(t, nil, common...)
	withReviewArgs := append(append([]string{}, common...),
		"-review", "-review-cap", "10", "-review-file", reviewFile)
	withReview := runFfuf(t, nil, withReviewArgs...)

	// Cross-process fields are inherently nondeterministic (the FFUFHASH history
	// hash derives from the options+time, and duration is a measured latency).
	// The byte-identical guarantee that matters is the result stream's shape and
	// decision: same records, same fields, same kept/dropped set. Compare those.
	stable := func(raw []byte) []map[string]any {
		var out []map[string]any
		for _, line := range strings.Split(string(raw), "\n") {
			line = strings.TrimSpace(line)
			if !strings.HasPrefix(line, "{") {
				continue
			}
			var rec map[string]any
			if json.Unmarshal([]byte(line), &rec) != nil {
				continue
			}
			delete(rec, "duration")
			if in, ok := rec["input"].(map[string]any); ok {
				delete(in, "FFUFHASH")
			}
			out = append(out, rec)
		}
		return out
	}
	a, b := stable(withoutReview), stable(withReview)
	if !reflect.DeepEqual(a, b) {
		t.Fatalf("stdout result stream changed when review enabled\n--- without ---\n%v\n--- with ---\n%v", a, b)
	}
	// The 404 must be absent from stdout (filtered), but present in review.
	assertSet(t, matchedPayloads(withReview), []string{"200", "301", "500"})

	data, err := os.ReadFile(reviewFile)
	if err != nil {
		t.Fatalf("read review file: %v", err)
	}
	text := string(data)
	if !strings.Contains(text, "drop-404") {
		t.Errorf("review file missing decisive rule id drop-404:\n%s", text)
	}
	if !strings.Contains(text, "status_code") {
		t.Errorf("review file missing actual values:\n%s", text)
	}
	if !strings.Contains(text, "review_summary") {
		t.Errorf("review file missing summary record:\n%s", text)
	}
	// Exactly one dropped response (the 404) before the summary.
	entryCount := strings.Count(text, `"request_id"`)
	if entryCount != 1 {
		t.Errorf("review entry count = %d, want 1", entryCount)
	}
}

// 形态8 (CLI): a bad rule set fails at startup with a non-zero exit and the
// errors printed, rather than starting the scan.
func TestE2E_BadRuleSetFailsStartup(t *testing.T) {
	target := testtarget.New()
	defer target.Close()

	wl := writeWordlist(t, []string{"200"})
	rules := writeTempFile(t, "bad.toml", `
[[rules]]
id = "x"
side = "matcher"
kind = "status"
value = "not-a-code"
[[rules]]
id = "y"
side = "filter"
kind = "regexp"
value = "[unterminated"
`)

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, ffufBin,
		"-u", target.URL+"/status/FUZZ", "-w", wl,
		"-rules", rules, "-noninteractive",
	)
	out, _ := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatal("ffuf hung instead of rejecting the bad rule set")
	}
	if cmd.ProcessState.ExitCode() == 0 {
		t.Fatalf("expected non-zero exit for bad rule set, output:\n%s", out)
	}
	text := string(out)
	for _, want := range []string{"x", "y"} {
		if !strings.Contains(text, want) {
			t.Errorf("startup report missing rule %q:\n%s", want, text)
		}
	}
}

// 降级1: an unwritable review file does not abort the scan; the verdict still
// runs and results are produced, with the sink failure confined to review.
func TestE2E_UnwritableReviewSinkDegrades(t *testing.T) {
	target := testtarget.New()
	defer target.Close()

	wl := writeWordlist(t, []string{"200", "404"})
	rules := writeTempFile(t, "rules.toml", `
[[rules]]
id = "m"
side = "matcher"
kind = "status"
value = "all"
[[rules]]
id = "f"
side = "filter"
kind = "status"
value = "404"
`)
	// A directory cannot be opened as a regular file.
	badSink := filepath.Join(t.TempDir(), "a-directory")
	if err := os.Mkdir(badSink, 0750); err != nil {
		t.Fatal(err)
	}

	out := runFfuf(t, nil,
		"-u", target.URL+"/status/FUZZ", "-w", wl,
		"-rules", rules, "-review", "-review-file", badSink,
		"-json", "-t", "1", "-noninteractive",
	)
	// The scan still completed and the kept result is on stdout.
	assertSet(t, matchedPayloads(out), []string{"200"})
}
