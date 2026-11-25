package e2e

import (
	"context"
	"os/exec"
	"strings"
	"testing"
	"time"

	"github.com/ffuf/ffuf/v2/pkg/testtarget"
)

// runFfufResult runs the built binary and returns its combined stdout, stderr and
// exit code. Unlike runFfuf it does not fail on a nonzero exit, so tests can
// assert on configuration errors.
func runFfufResult(t *testing.T, env []string, args ...string) (stdout, stderr []byte, code int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, ffufBin, args...)
	if env != nil {
		cmd.Env = env
	}
	var out, errb strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errb
	err := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		t.Fatalf("ffuf timed out; args: %v", args)
	}
	if err == nil {
		return []byte(out.String()), []byte(errb.String()), 0
	}
	if ee, ok := err.(*exec.ExitError); ok {
		return []byte(out.String()), []byte(errb.String()), ee.ExitCode()
	}
	t.Fatalf("ffuf failed to run: %v; args: %v", err, args)
	return nil, nil, -1
}

// TestE2E_DedupJSON: with -dedup, a duplicate payload produces a single -json
// line.
func TestE2E_DedupJSON(t *testing.T) {
	target := testtarget.New()
	defer target.Close()

	wl := writeWordlist(t, []string{"dup", "dup"})
	out := runFfuf(t, nil,
		"-u", target.URL+"/reflect/FUZZ", "-w", wl,
		"-mc", "all", "-dedup", "-json", "-t", "1", "-noninteractive",
	)
	results := parseResults(out)
	if len(results) != 1 {
		t.Fatalf("-dedup produced %d JSON result lines, want 1:\n%s", len(results), out)
	}
}

// TestE2E_DedupFieldsValidation: a -dedup-fields value without url exits nonzero
// before scanning.
func TestE2E_DedupFieldsValidation(t *testing.T) {
	target := testtarget.New()
	defer target.Close()

	wl := writeWordlist(t, []string{"a"})
	stdout, stderr, code := runFfufResult(t, nil,
		"-u", target.URL+"/reflect/FUZZ", "-w", wl,
		"-dedup", "-dedup-fields", "status", "-noninteractive",
	)
	if code == 0 {
		t.Fatalf("expected nonzero exit for -dedup-fields status; stdout=%s stderr=%s", stdout, stderr)
	}
	if !strings.Contains(string(stdout)+string(stderr), "url") {
		t.Errorf("field error did not mention url:\nstdout=%s\nstderr=%s", stdout, stderr)
	}
}

// TestE2E_CancelGraceNegative: a negative -cancel-grace exits nonzero.
func TestE2E_CancelGraceNegative(t *testing.T) {
	target := testtarget.New()
	defer target.Close()

	wl := writeWordlist(t, []string{"a"})
	stdout, stderr, code := runFfufResult(t, nil,
		"-u", target.URL+"/reflect/FUZZ", "-w", wl,
		"-cancel-grace", "-1", "-noninteractive",
	)
	if code == 0 {
		t.Fatalf("expected nonzero exit for -cancel-grace -1; stdout=%s stderr=%s", stdout, stderr)
	}
	if !strings.Contains(string(stdout)+string(stderr), "cancel-grace") {
		t.Errorf("error did not mention cancel-grace:\nstdout=%s\nstderr=%s", stdout, stderr)
	}
}
