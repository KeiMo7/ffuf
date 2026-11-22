package decision

import (
	"net/url"
	"testing"
	"time"

	"github.com/ffuf/ffuf/v2/pkg/ffuf"
	"github.com/ffuf/ffuf/v2/pkg/heuristics"
)

// fakeRunner is a deterministic RunnerProvider that records the URLs it was
// asked to send, proving the decider reuses the runner abstraction rather than
// opening a separate HTTP path.
type fakeRunner struct {
	prepared []string
	executed []string
	views    map[string]heuristics.ResponseView
}

func (f *fakeRunner) Prepare(input map[string][]byte, basereq *ffuf.Request) (ffuf.Request, error) {
	req := *basereq
	for k, v := range input {
		req.Url = stringReplace(req.Url, k, string(v))
	}
	req.Input = input
	f.prepared = append(f.prepared, req.Url)
	return req, nil
}

func (f *fakeRunner) Execute(req *ffuf.Request) (ffuf.Response, error) {
	f.executed = append(f.executed, req.Url)
	u, _ := url.Parse(req.Url)
	view := f.views[u.Path]
	return ffuf.Response{
		StatusCode:    view.StatusCode,
		ContentLength: view.ContentLength,
		ContentWords:  10,
		ContentLines:  2,
		Duration:      view.Duration,
		Data:          view.Body,
		Request:       req,
	}, nil
}

func (f *fakeRunner) Dump(req *ffuf.Request) ([]byte, error) { return []byte(req.Url), nil }

func stringReplace(s, old, new string) string {
	out := make([]byte, 0, len(s))
	for i := 0; i < len(s); {
		if i+len(old) <= len(s) && s[i:i+len(old)] == old {
			out = append(out, new...)
			i += len(old)
			continue
		}
		out = append(out, s[i])
		i++
	}
	return string(out)
}

func TestSendProbe_ReusesRunnerAndKeepsExtension(t *testing.T) {
	runner := &fakeRunner{views: map[string]heuristics.ResponseView{
		"/md/probe-1.bak": {StatusCode: 403, ContentLength: 30, Body: []byte("forbidden extension"), Duration: 5 * time.Millisecond},
	}}
	conf := &ffuf.Config{}
	base := ffuf.Request{Method: "GET", Url: "http://t/md/FUZZ", Headers: map[string]string{}}
	d := NewDecider(conf, runner, base, heuristics.DefaultConfig())

	view, err := d.sendProbe("/probe-1.bak")
	if err != nil {
		t.Fatal(err)
	}
	if view.StatusCode != 403 {
		t.Fatalf("status = %d, want 403", view.StatusCode)
	}
	// The probe must have traveled through Prepare/Execute with the extension.
	if len(runner.prepared) != 1 || runner.prepared[0] != "http://t/md/probe-1.bak" {
		t.Fatalf("probe did not reuse runner correctly: %v", runner.prepared)
	}
}

func TestSendProbe_NoKeywordPointsAtOrigin(t *testing.T) {
	runner := &fakeRunner{views: map[string]heuristics.ResponseView{
		"/probe-x": {StatusCode: 404, ContentLength: 10, Body: []byte("nf"), Duration: time.Millisecond},
	}}
	// A URL with no FUZZ keyword: Prepare leaves it unchanged, so sendProbe
	// must rewrite the URL to the probe path on the same origin.
	base := ffuf.Request{Method: "GET", Url: "http://t/fixed/path", Headers: map[string]string{}}
	d := NewDecider(&ffuf.Config{}, runner, base, heuristics.DefaultConfig())
	view, err := d.sendProbe("/probe-x")
	if err != nil {
		t.Fatal(err)
	}
	if view.StatusCode != 404 {
		t.Fatalf("status = %d, want 404", view.StatusCode)
	}
	// Execute saw the rewritten URL even though Prepare could not substitute.
	last := runner.executed[len(runner.executed)-1]
	if last != "http://t/probe-x" {
		t.Fatalf("keyword-less probe not pointed at origin: %s", last)
	}
}

func TestView_AdaptsAllDimensions(t *testing.T) {
	req := &ffuf.Request{Url: "http://t/admin.bak"}
	resp := &ffuf.Response{
		StatusCode: 200, ContentLength: 123, ContentWords: 9, ContentLines: 3,
		Duration: 7 * time.Millisecond, Data: []byte("<b>hi</b>"), Request: req,
	}
	v := View(resp)
	if v.URLPath != "/admin.bak" || heuristics.GroupFor(v.URLPath) != ".bak" {
		t.Errorf("path/group wrong: %q", v.URLPath)
	}
	if v.StatusCode != 200 || v.ContentLength != 123 || v.Duration != 7*time.Millisecond {
		t.Errorf("dimension adaptation wrong: %+v", v)
	}
}

func TestPrewarm_CoversConfiguredExtensions(t *testing.T) {
	conf := &ffuf.Config{Extensions: []string{".php", ".bak"}}
	base := ffuf.Request{Method: "GET", Url: "http://t/FUZZ", Headers: map[string]string{}}
	d := NewDecider(conf, &fakeRunner{views: map[string]heuristics.ResponseView{}}, base, heuristics.DefaultConfig())

	// Collect every group the scan could encounter via injected probes.
	collect := func(probePath string) (heuristics.ResponseView, error) {
		return heuristics.ResponseView{
			StatusCode: 404, ContentLength: 20, Body: []byte("not found body"),
			Duration: time.Millisecond, URLPath: probePath,
		}, nil
	}
	for _, group := range []string{heuristics.GroupDefault, ".php", ".bak"} {
		d.Engine().EnsureBaseline(group, collect)
	}
	for _, group := range []string{heuristics.GroupDefault, ".php", ".bak"} {
		g, ok := d.Engine().GroupSnapshot(group)
		if !ok || g.Degraded || len(g.Points) == 0 {
			t.Errorf("baseline for %q not collected: %+v", group, g)
		}
	}
}
