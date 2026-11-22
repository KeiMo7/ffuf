// Package decision integrates the multi-dimensional heuristics engine with
// ffuf's concrete request runner and response types.
//
// It contains no HTTP logic of its own: baseline probes and scan requests alike
// go through the same ffuf.RunnerProvider (Prepare + Execute), so request
// construction, headers, encoding, proxy and TLS behavior stay identical to
// the rest of the scan. The package only adapts ffuf's types to the
// heuristics.ResponseView shape and orchestrates baseline collection.
package decision

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/ffuf/ffuf/v2/pkg/checkpoint"
	"github.com/ffuf/ffuf/v2/pkg/ffuf"
	"github.com/ffuf/ffuf/v2/pkg/heuristics"
)

// Decider owns one heuristics.Engine and the plumbing to feed it real ffuf
// requests. A Job creates exactly one and consults it per response.
type Decider struct {
	engine  *heuristics.Engine
	runner  ffuf.RunnerProvider
	baseReq ffuf.Request
	conf    *ffuf.Config
}

// NewDecider builds a Decider. runner is the production SimpleRunner (or any
// RunnerProvider), basereq the request template the scan itself uses.
func NewDecider(conf *ffuf.Config, runner ffuf.RunnerProvider, basereq ffuf.Request, cfg heuristics.Config) *Decider {
	return &Decider{
		engine:  heuristics.NewEngine(cfg),
		runner:  runner,
		baseReq: basereq,
		conf:    conf,
	}
}

// Engine exposes the underlying engine for baseline inspection, suppressor
// management and checkpoint persistence.
func (d *Decider) Engine() *heuristics.Engine { return d.engine }

// View adapts an ffuf response to the engine's neutral response shape.
func View(resp *ffuf.Response) heuristics.ResponseView {
	p := ""
	if resp.Request != nil {
		if u, err := url.Parse(resp.Request.Url); err == nil {
			p = u.Path
		}
	}
	return heuristics.ResponseView{
		StatusCode:    resp.StatusCode,
		ContentLength: resp.ContentLength,
		ContentWords:  resp.ContentWords,
		ContentLines:  resp.ContentLines,
		Duration:      resp.Duration,
		Body:          resp.Data,
		URLPath:       p,
	}
}

// EnsureBaseline collects the baseline for the group that urlPath belongs to,
// using the production runner. On failure the engine marks the group degraded
// and decisions for it fall back to status codes — the error is returned only
// for logging, the scan must not abort.
func (d *Decider) EnsureBaseline(urlPath string) error {
	group := heuristics.GroupFor(urlPath)
	var probeErr error
	d.engine.EnsureBaseline(group, func(probePath string) (heuristics.ResponseView, error) {
		view, err := d.sendProbe(probePath)
		if err != nil && probeErr == nil {
			probeErr = err
		}
		return view, err
	})
	return probeErr
}

// PrewarmBaselines collects baselines up front for every extension group the
// scan can encounter. It is best-effort: a failed group is simply degraded.
// Extensions come from conf.Extensions (the -e list); the no-extension default
// group is always included.
func (d *Decider) PrewarmBaselines() []error {
	groups := map[string]bool{heuristics.GroupDefault: true}
	for _, ext := range d.conf.Extensions {
		groups[heuristics.GroupFor("/x"+ext)] = true
	}
	errs := make([]error, 0)
	for group := range groups {
		var lastErr error
		d.engine.EnsureBaseline(group, func(probePath string) (heuristics.ResponseView, error) {
			view, err := d.sendProbe(probePath)
			if err != nil {
				lastErr = err
			}
			return view, err
		})
		if g, ok := d.engine.GroupSnapshot(group); ok && g.Degraded && lastErr != nil {
			errs = append(errs, fmt.Errorf("baseline for group %q degraded: %w", group, lastErr))
		}
	}
	return errs
}

// sendProbe issues one baseline request through the SAME runner the scan uses.
// The probe URL is derived from the base request's scheme/host, with the FUZZ
// keyword (if present in the URL) replaced by the probe path; without a
// keyword the probe path is appended to the URL's directory.
func (d *Decider) sendProbe(probePath string) (heuristics.ResponseView, error) {
	// When FUZZ sits inside the URL (the normal -u .../FUZZ case), the probe
	// value must be relative: a leading slash would produce a double slash and
	// could hit different routing than a real wordlist entry.
	probeValue := strings.TrimPrefix(probePath, "/")
	req, err := d.runner.Prepare(map[string][]byte{"FUZZ": []byte(probeValue)}, &d.baseReq)
	if err != nil {
		return heuristics.ResponseView{}, err
	}
	// When the URL contains no FUZZ keyword, Prepare leaves it unchanged; point
	// the probe at the target host explicitly in that case.
	if req.Url == d.baseReq.Url {
		req.Url = probeURL(d.baseReq.Url, probePath)
	}
	resp, err := d.runner.Execute(&req)
	if err != nil {
		return heuristics.ResponseView{}, err
	}
	return View(&resp), nil
}

// probeURL joins a probe path onto the base URL's origin.
func probeURL(baseURL, probePath string) string {
	u, err := url.Parse(baseURL)
	if err != nil {
		return probePath
	}
	u.Path = probePath
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

// Evaluate runs the full multi-dimensional decision for one scan response.
// legacyMatch is the existing MatcherManager verdict, passed in so the engine
// can guarantee monotonicity (rule tuning never removes a legacy hit).
func (d *Decider) Evaluate(resp *ffuf.Response, legacyMatch bool) heuristics.Verdict {
	return d.engine.Decide(View(resp), legacyMatch)
}

// RestoreFromCheckpoint rebuilds heuristic context persisted by a previous run:
// baseline statistics (status/length/time/soft-404 template) and false-positive
// signatures. Similarity needs actual baseline bytes, which are not persisted,
// so for each restored group one representative probe is re-fetched through the
// production runner; if that re-fetch fails the group stays restored for the
// other three dimensions and similarity simply reports skipped per response.
func (d *Decider) RestoreFromCheckpoint(st checkpoint.State) {
	for key, g := range st.Baselines {
		d.engine.RestoreGroup(g)
		if d.engine.HasBodies(key) {
			continue
		}
		view, err := d.sendProbe(d.engine.NewProbePath(key))
		if err != nil {
			continue
		}
		d.engine.SetBodies(key, [][]byte{view.Body})
	}
	d.engine.LoadSuppressors(st.Suppressors)
}

// NewDeciderFromConfig builds a Decider from a resolved ffuf Config, applying
// the built-in defaults wherever the config left a threshold at zero.
func NewDeciderFromConfig(conf *ffuf.Config, runner ffuf.RunnerProvider, basereq ffuf.Request) *Decider {
	def := heuristics.DefaultConfig()
	hc := conf.Heuristics
	cfg := def
	if hc.LengthThreshold > 0 {
		cfg.LengthRelThreshold = hc.LengthThreshold
	}
	if hc.LengthFloor > 0 {
		cfg.LengthAbsFloor = hc.LengthFloor
	}
	if hc.SimilarityCutoff > 0 {
		cfg.SimilarityThreshold = hc.SimilarityCutoff
	}
	if hc.SimilarityTimeoutMS > 0 {
		cfg.SimilarityTimeout = time.Duration(hc.SimilarityTimeoutMS) * time.Millisecond
	}
	if hc.TimeThreshold > 0 {
		cfg.TimeRelThreshold = hc.TimeThreshold
	}
	if hc.ScoreThreshold > 0 {
		cfg.ScoreThreshold = hc.ScoreThreshold
	}
	if hc.BaselineSamples > 0 {
		cfg.BaselineSamples = hc.BaselineSamples
	}
	return NewDecider(conf, runner, basereq, cfg)
}

// LoadSuppressorsFile reads a JSON array of false-positive signatures. A
// missing file is not an error: an empty slice is returned so a first run
// simply has nothing to suppress.
func LoadSuppressorsFile(path string) ([]heuristics.Suppressor, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []heuristics.Suppressor{}, nil
		}
		return nil, err
	}
	var sup []heuristics.Suppressor
	if err := json.Unmarshal(data, &sup); err != nil {
		return nil, fmt.Errorf("parsing suppressors file %s: %w", path, err)
	}
	return sup, nil
}

// SaveSuppressorsFile writes signatures back after the user marks false
// positives, so tuning accumulates across runs.
func SaveSuppressorsFile(path string, sup []heuristics.Suppressor) error {
	data, err := json.MarshalIndent(sup, "", "  ")
	if err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
