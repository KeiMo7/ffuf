package ffuf

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestConfigFromOptions_DedupRuleErrorHasLocation(t *testing.T) {
	rules := filepath.Join(t.TempDir(), "rules.txt")
	if err := os.WriteFile(rules, []byte("# comment\n  ([unclosed\n"), 0644); err != nil {
		t.Fatal(err)
	}
	opts := NewConfigOptions()
	opts.HTTP.URL = "https://example.org/FUZZ"
	opts.Input.Wordlists = []string{"/tmp/wordlist.txt"}
	opts.Output.Dedup = true
	opts.Output.DedupRules = rules

	_, err := ConfigFromOptions(opts, context.Background(), func() {})
	if err == nil {
		t.Fatal("expected invalid dedup rules to be a configuration error")
	}
	if got := err.Error(); !strings.Contains(got, rules+":2:3") {
		t.Fatalf("error %q does not identify the rule file, line and column", got)
	}
}
