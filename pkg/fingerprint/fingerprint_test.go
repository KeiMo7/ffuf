package fingerprint

import (
	"strings"
	"testing"
)

func TestParseRulesReportsLineAndColumn(t *testing.T) {
	_, err := ParseRules("rules.txt", []byte("# timestamps\n  (unclosed\n"))
	if err == nil {
		t.Fatal("expected invalid regex error")
	}
	got := err.Error()
	for _, want := range []string{"rules.txt:2:3", "invalid ignore regex", "(unclosed"} {
		if !strings.Contains(got, want) {
			t.Errorf("error %q does not contain %q", got, want)
		}
	}
}

func TestRulesNormalizeVolatileFields(t *testing.T) {
	rules, err := ParseRules("rules.txt", []byte(`
"ts":"[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z"
"request_id":"[a-f0-9]+"
"token":"[A-Za-z0-9]+"
`))
	if err != nil {
		t.Fatalf("ParseRules: %v", err)
	}
	a := []byte(`{"ts":"2026-11-18T01:02:03Z","request_id":"abcdef","token":"AAA","value":"same"}`)
	b := []byte(`{"ts":"2026-11-18T09:08:07Z","request_id":"123456","token":"BBB","value":"same"}`)
	if got, want := string(rules.Normalize(a)), string(rules.Normalize(b)); got != want {
		t.Fatalf("volatile fields were not normalized equally:\n%s\n%s", got, want)
	}
}

func TestStreamDistinguishesEmptyFromFailure(t *testing.T) {
	empty := NewStream(EmptyRules(), 1024).Finish()
	if !empty.Valid || !empty.Empty || empty.Digest == "" {
		t.Fatalf("empty body fingerprint = %+v, want valid, empty and hashed", empty)
	}
	failed := Result{Valid: false, Source: SourceUnavailable, Error: "read failed"}
	if failed.Valid || failed.Empty {
		t.Fatalf("failure state = %+v, want invalid and not an empty-body fingerprint", failed)
	}
}

func TestStreamLargeBodyIsBoundedAndChunkStable(t *testing.T) {
	const threshold = 4096
	body := []byte(strings.Repeat("0123456789abcdef", 1<<18)) // 4 MiB
	feed := func(chunk int) Result {
		stream := NewStream(EmptyRules(), threshold)
		for start := 0; start < len(body); start += chunk {
			end := start + chunk
			if end > len(body) {
				end = len(body)
			}
			if _, err := stream.Write(body[start:end]); err != nil {
				t.Fatalf("Write: %v", err)
			}
			if got := stream.RetainedBytes(); got > threshold+chunk {
				t.Fatalf("retained %d bytes, want <= threshold+chunk (%d)", got, threshold+chunk)
			}
		}
		return stream.Finish()
	}
	a := feed(7)
	b := feed(65536)
	if !a.Valid || !a.Sampled || a.Digest != b.Digest {
		t.Fatalf("chunking changed fingerprint: a=%+v b=%+v", a, b)
	}

	changed := append([]byte(nil), body...)
	copy(changed[len(changed)-32:], strings.Repeat("Z", 32))
	stream := NewStream(EmptyRules(), threshold)
	_, _ = stream.Write(changed)
	if got := stream.Finish(); got.Digest == a.Digest {
		t.Fatal("a change in the retained tail sample did not change the fingerprint")
	}
}

func TestStreamSmallBodyIsExact(t *testing.T) {
	a := NewStream(EmptyRules(), 1024)
	_, _ = a.Write([]byte("alpha"))
	first := a.Finish()
	b := NewStream(EmptyRules(), 1024)
	_, _ = b.Write([]byte("bravo"))
	second := b.Finish()
	if first.Digest == second.Digest {
		t.Fatal("different small bodies produced the same fingerprint")
	}
}
