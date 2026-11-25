package ffuf

import (
	"reflect"
	"testing"
	"time"
)

// TestResultFromResponse checks every field of the mapping and that the Input map
// is copied, not aliased.
func TestResultFromResponse(t *testing.T) {
	req := &Request{
		Method:   "GET",
		Host:     "example.org",
		Url:      "https://example.org/path",
		Input:    map[string][]byte{"FUZZ": []byte("value")},
		Position: 42,
	}
	resp := Response{
		StatusCode:    302,
		ContentLength: 1234,
		ContentWords:  56,
		ContentLines:  7,
		ContentType:   "text/html",
		Headers:       map[string][]string{"Location": {"/elsewhere"}},
		Request:       req,
		ResultFile:    "abc123",
		ScraperData:   map[string][]string{"title": {"hi"}},
		Duration:      1500 * time.Millisecond,
	}

	got := ResultFromResponse(resp)

	want := Result{
		Input:            map[string][]byte{"FUZZ": []byte("value")},
		Position:         42,
		StatusCode:       302,
		ContentLength:    1234,
		ContentWords:     56,
		ContentLines:     7,
		ContentType:      "text/html",
		RedirectLocation: "/elsewhere",
		ScraperData:      map[string][]string{"title": {"hi"}},
		Url:              "https://example.org/path",
		Duration:         1500 * time.Millisecond,
		ResultFile:       "abc123",
		Host:             "example.org",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ResultFromResponse mismatch:\n got %+v\nwant %+v", got, want)
	}

	// The Input map is a copy: mutating the result must not touch the request.
	got.Input["FUZZ"] = []byte("changed")
	if string(req.Input["FUZZ"]) != "value" {
		t.Errorf("Result.Input aliases Response.Request.Input: %q", req.Input["FUZZ"])
	}
	got.Input["NEW"] = []byte("x")
	if _, ok := req.Input["NEW"]; ok {
		t.Error("adding a key to Result.Input mutated the request input map")
	}
}
