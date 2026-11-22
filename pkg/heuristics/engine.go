package heuristics

import (
	"context"
	"fmt"
	"path"
	"sort"
	"strings"
	"sync"
	"time"
)

// ResponseView is the minimal response shape the engine needs. ffuf.Response
// satisfies it structurally; the indirection keeps this package free of an
// import of pkg/ffuf (which itself must stay unaware of heuristics).
type ResponseView struct {
	StatusCode    int64
	ContentLength int64
	ContentWords  int64
	ContentLines  int64
	Duration      time.Duration
	Body          []byte
	URLPath       string
}

// ProbeFunc executes one baseline request for the given probe path and
// returns the observed response. It is supplied by the engine layer and wraps
// the existing Runner.Prepare/Execute path, so baseline collection reuses the
// production request implementation rather than opening a parallel HTTP stack.
type ProbeFunc func(probePath string) (ResponseView, error)

// Suppressor is a recorded false-positive signature. A response whose body
// hash matches a suppressor is never reported as a hit, but the suppressed
// verdict is still recorded so the tuning history remains auditable.
type Suppressor struct {
	ID         string    `json:"id"`
	BodyHash   string    `json:"body_hash"`
	StatusCode int64     `json:"status_code"`
	Group      string    `json:"group"`
	SampleURL  string    `json:"sample_url"`
	Note       string    `json:"note,omitempty"`
	CreatedAt  time.Time `json:"created_at"`
	HitCount   int       `json:"hit_count"`
}

// Engine evaluates responses against per-path-pattern baselines. It is safe
// for concurrent use: baseline collection for a group happens once and workers
// block on the group's ready channel rather than double-collecting.
type Engine struct {
	cfg Config

	mu     sync.RWMutex
	groups map[string]*BaselineGroup
	ready  map[string]chan struct{}
	bodies map[string][][]byte // group key -> retained baseline bodies for similarity
	suppr  map[string]*Suppressor

	// probes records which probe paths are in flight/used, keyed by group, so
	// the collector never issues the same probe twice.
	usedMu sync.Mutex
	used   map[string]map[string]bool
}

// NewEngine builds an engine with cfg. Nil/zero fields are replaced by
// DefaultConfig values.
func NewEngine(cfg Config) *Engine {
	def := DefaultConfig()
	if cfg.LengthRelThreshold <= 0 {
		cfg.LengthRelThreshold = def.LengthRelThreshold
	}
	if cfg.LengthAbsFloor <= 0 {
		cfg.LengthAbsFloor = def.LengthAbsFloor
	}
	if cfg.SimilarityThreshold <= 0 {
		cfg.SimilarityThreshold = def.SimilarityThreshold
	}
	if cfg.SimilarityTimeout <= 0 {
		cfg.SimilarityTimeout = def.SimilarityTimeout
	}
	if cfg.ShingleSize <= 0 {
		cfg.ShingleSize = def.ShingleSize
	}
	if cfg.TimeRelThreshold <= 0 {
		cfg.TimeRelThreshold = def.TimeRelThreshold
	}
	if cfg.ScoreThreshold <= 0 {
		cfg.ScoreThreshold = def.ScoreThreshold
	}
	if cfg.BaselineSamples <= 0 {
		cfg.BaselineSamples = def.BaselineSamples
	}
	if cfg.BaselineProbePrefix == "" {
		cfg.BaselineProbePrefix = def.BaselineProbePrefix
	}
	if cfg.Weights == nil {
		cfg.Weights = def.Weights
	}
	return &Engine{
		cfg:    cfg,
		groups: make(map[string]*BaselineGroup),
		ready:  make(map[string]chan struct{}),
		bodies: make(map[string][][]byte),
		suppr:  make(map[string]*Suppressor),
		used:   make(map[string]map[string]bool),
	}
}

// Config returns the active engine configuration.
func (e *Engine) Config() Config { return e.cfg }

// GroupFor maps a request path to its baseline group key. The extension is
// lowercased so ".PHP" and ".php" share a baseline; paths with no extension
// (or a trailing slash) go to GroupDefault.
func GroupFor(urlPath string) string {
	ext := strings.ToLower(path.Ext(urlPath))
	if ext == "" {
		return GroupDefault
	}
	return ext
}

// PatternFor returns the glob-style human label for a group, used in evidence
// records and reports.
func PatternFor(key string) string {
	if key == GroupDefault {
		return "* (no extension)"
	}
	return "*" + key
}

// EnsureBaseline makes sure a baseline exists for group, collecting it via
// probe on first use. Concurrent first calls for the same group collapse onto
// one collection; others wait for completion. A failed collection marks the
// group degraded and decision-making for it falls back to status codes.
func (e *Engine) EnsureBaseline(group string, probe ProbeFunc) {
	e.mu.RLock()
	ch, ok := e.ready[group]
	e.mu.RUnlock()
	if ok {
		<-ch
		return
	}

	e.mu.Lock()
	if ch, ok = e.ready[group]; ok {
		// Another goroutine won the race and is collecting; wait for it.
		e.mu.Unlock()
		<-ch
		return
	}
	ch = make(chan struct{})
	e.ready[group] = ch
	e.groups[group] = &BaselineGroup{Key: group, Pattern: PatternFor(group)}
	e.mu.Unlock()

	defer close(ch)
	e.collect(group, probe)
}

// MarkBaselineFailed lets an outer layer record a collection failure it
// detected itself (e.g. the runner was unavailable before the scan started).
func (e *Engine) MarkBaselineFailed(group string, err error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	g, ok := e.groups[group]
	if !ok {
		g = &BaselineGroup{Key: group, Pattern: PatternFor(group)}
		e.groups[group] = g
	}
	g.Degraded = true
	g.Failure = err.Error()
	g.Ready = true
}

func (e *Engine) collect(group string, probe ProbeFunc) {
	points := make([]BaselinePoint, 0, e.cfg.BaselineSamples)
	bodies := make([][]byte, 0, e.cfg.BaselineSamples)
	var firstErr error
	for i := 0; i < e.cfg.BaselineSamples; i++ {
		probePath := e.nextProbePath(group, i)
		view, err := probe(probePath)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		points = append(points, BaselinePoint{
			StatusCode:    view.StatusCode,
			ContentLength: view.ContentLength,
			ContentWords:  view.ContentWords,
			ContentLines:  view.ContentLines,
			Duration:      Duration{view.Duration},
			BodyHash:      HashBody(view.Body),
			CollectedAt:   time.Now(),
		})
		bodies = append(bodies, view.Body)
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	g := e.groups[group]
	g.Points = points
	g.Ready = true
	if len(points) == 0 {
		g.Degraded = true
		if firstErr != nil {
			g.Failure = firstErr.Error()
		} else {
			g.Failure = "no usable baseline responses"
		}
	}
	e.bodies[group] = bodies
}

// nextProbePath produces a unique nonexistent path for a group. Probes keep
// the group's extension so the target applies the same per-extension behavior
// (routing, error pages) it would for a real wordlist entry of that type.
func (e *Engine) nextProbePath(group string, i int) string {
	e.usedMu.Lock()
	defer e.usedMu.Unlock()
	if e.used[group] == nil {
		e.used[group] = make(map[string]bool)
	}
	var p string
	for n := i; ; n++ {
		base := fmt.Sprintf("%s%d-%d", e.cfg.BaselineProbePrefix, time.Now().UnixNano(), n)
		if group == GroupDefault {
			p = "/" + base
		} else {
			p = "/" + base + group
		}
		if !e.used[group][p] {
			e.used[group][p] = true
			return p
		}
	}
}

// GroupSnapshot returns a copy of a baseline group for inspection/reporting.
func (e *Engine) GroupSnapshot(group string) (BaselineGroup, bool) {
	e.mu.RLock()
	defer e.mu.RUnlock()
	g, ok := e.groups[group]
	if !ok {
		return BaselineGroup{}, false
	}
	cp := *g
	cp.Points = append([]BaselinePoint(nil), g.Points...)
	return cp, true
}

// Groups returns the sorted keys of all groups the engine knows about.
func (e *Engine) Groups() []string {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]string, 0, len(e.groups))
	for k := range e.groups {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// IsSoft404 reports whether view matches the group's soft-404 template: a
// response whose status may be 200 but whose normalized body is the same body
// every nonexistent-path probe returns. When baseline probes disagree with
// each other there is no reliable template and the answer is false.
func (e *Engine) IsSoft404(view ResponseView, group string) bool {
	e.mu.RLock()
	g := e.groups[group]
	e.mu.RUnlock()
	if g == nil || len(g.Points) < 2 {
		return false
	}
	dominant, n := g.DominantHash()
	// Require unanimity (or near-unanimity) of the probes before treating the
	// body as a soft-404 template; one flaky probe must not define the template.
	if n < len(g.Points) || dominant == "" {
		return false
	}
	return HashBody(view.Body) == dominant
}

// Decide runs the full multi-dimensional evaluation. legacyMatch is the
// legacy MatcherManager verdict for the same response, supplied so rule
// changes can never erase an already-confirmable hit: when the engine is
// degraded or the response is a soft-404, the legacy verdict is still honored
// as documented per dimension.
func (e *Engine) Decide(view ResponseView, legacyMatch bool) Verdict {
	group := GroupFor(view.URLPath)
	v := Verdict{Group: group, LegacyMatch: legacyMatch, BodyHash: HashBody(view.Body), thresholds: e.cfg}

	e.mu.RLock()
	g := e.groups[group]
	bodies := e.bodies[group]
	suppressor := e.findSuppressorLocked(v.BodyHash, view.StatusCode)
	e.mu.RUnlock()

	if suppressor != nil {
		suppressor.HitCount++
		v.Suppressed = true
		v.SuppressorID = suppressor.ID
		v.Reasons = append(v.Reasons, fmt.Sprintf(
			"suppressed as known false positive (signature %s, %s)", suppressor.ID, suppressor.Note))
		return v
	}

	if g == nil || !g.Ready {
		// No baseline yet (collector disabled): pure legacy behavior, marked.
		v.Degraded = true
		v.Hit = legacyMatch
		v.Evidence = append(v.Evidence, Evidence{
			Dimension: DimStatus, Fired: legacyMatch, Weight: e.cfg.Weights[DimStatus],
			Observed: fmt.Sprintf("%d", view.StatusCode),
			Reason:   "baseline unavailable; status-code-only fallback",
			Skipped:  false,
		})
		if legacyMatch {
			v.Reasons = append(v.Reasons, "matched legacy status-code rules (baseline unavailable)")
		}
		return v
	}

	v.Soft404 = e.IsSoft404(view, group)
	if g.Degraded {
		v.Degraded = true
	}

	// Dimension 1: status code relative to the baseline status set.
	v.evaluateStatus(view, g)
	// Dimension 2: response length relative to baseline median.
	v.evaluateLength(view, g)
	// Dimension 3: response time (weak, auxiliary only).
	v.evaluateTime(view, g)
	// Dimension 4: content similarity (timeout => skip dimension only).
	v.evaluateSimilarity(view, g, bodies)

	v.computeScore()
	v.finalize(legacyMatch)
	return v
}

func (v *Verdict) evaluateStatus(view ResponseView, g *BaselineGroup) {
	ev := Evidence{
		Dimension: DimStatus,
		Weight:    v.thresholds.Weights[DimStatus],
		Observed:  fmt.Sprintf("%d", view.StatusCode),
		Baseline:  joinStatuses(g.StatusSet()),
	}
	switch {
	case v.Soft404:
		ev.Reason = "status looks matchable but body is the soft-404 template; dimension does not fire"
	case g.Degraded:
		ev.Fired = v.LegacyMatch
		ev.Reason = "baseline degraded; using legacy status-code matcher result"
	default:
		known := g.StatusSet()
		if !known[view.StatusCode] {
			ev.Fired = true
			ev.Score = 1.0
			ev.Reason = fmt.Sprintf("status code %d differs from baseline %s", view.StatusCode, ev.Baseline)
		} else {
			ev.Reason = fmt.Sprintf("status code %d is within the baseline set; no signal", view.StatusCode)
		}
	}
	v.Evidence = append(v.Evidence, ev)
}

func (v *Verdict) evaluateLength(view ResponseView, g *BaselineGroup) {
	ev := Evidence{
		Dimension: DimLength,
		Weight:    v.thresholds.Weights[DimLength],
		Observed:  fmt.Sprintf("%d bytes", view.ContentLength),
	}
	if g.Degraded || len(g.Points) == 0 {
		ev.Skipped = true
		ev.Reason = "skipped: baseline degraded"
		v.Evidence = append(v.Evidence, ev)
		return
	}
	median := g.MedianLength()
	diff := view.ContentLength - median
	if diff < 0 {
		diff = -diff
	}
	rel := 0.0
	if median > 0 {
		rel = float64(diff) / float64(median)
	} else {
		// Baseline is empty/near-empty: any non-trivial body is a strong
		// absolute signal.
		rel = 1.0
	}
	ev.Baseline = fmt.Sprintf("median %d bytes", median)
	if v.Soft404 {
		ev.Reason = "body is the soft-404 template; length dimension does not fire"
	} else if diff < e_lenFloor(v) {
		ev.Reason = fmt.Sprintf("length delta %d bytes below absolute floor; no signal", diff)
	} else if rel >= e_relThreshold(v) {
		ev.Fired = true
		ev.Score = clampRel(rel)
		ev.Reason = fmt.Sprintf("length differs from baseline by %d bytes (%.0f%%)", diff, rel*100)
	} else {
		ev.Reason = fmt.Sprintf("length delta %d bytes (%.0f%%) below threshold", diff, rel*100)
	}
	v.Evidence = append(v.Evidence, ev)
}

func (v *Verdict) evaluateTime(view ResponseView, g *BaselineGroup) {
	ev := Evidence{
		Dimension: DimTime,
		Weight:    v.thresholds.Weights[DimTime],
		Observed:  fmt.Sprintf("%d ms", view.Duration.Milliseconds()),
	}
	if g.Degraded || len(g.Points) == 0 {
		ev.Skipped = true
		ev.Reason = "skipped: baseline degraded"
		v.Evidence = append(v.Evidence, ev)
		return
	}
	median := g.MedianDuration()
	ev.Baseline = fmt.Sprintf("median %d ms", median.Milliseconds())
	if median <= 0 {
		ev.Skipped = true
		ev.Reason = "skipped: baseline latency not measurable"
		v.Evidence = append(v.Evidence, ev)
		return
	}
	rel := float64(view.Duration-median) / float64(median)
	if rel >= e_timeThreshold(v) && !v.Soft404 {
		// Timing only contributes a fractional score; it can never on its own
		// reach the hit threshold (weight 0.3, threshold 1.0).
		ev.Fired = true
		ev.Score = clampRel(rel)
		ev.Reason = fmt.Sprintf("latency %.0f%% above baseline median (auxiliary only)", rel*100)
	} else {
		ev.Reason = "latency within normal jitter band; no signal"
	}
	v.Evidence = append(v.Evidence, ev)
}

func (v *Verdict) evaluateSimilarity(view ResponseView, g *BaselineGroup, bodies [][]byte) {
	ev := Evidence{
		Dimension: DimSimilarity,
		Weight:    v.thresholds.Weights[DimSimilarity],
	}
	if g.Degraded || len(bodies) == 0 {
		ev.Skipped = true
		ev.Reason = "skipped: baseline degraded"
		v.Evidence = append(v.Evidence, ev)
		return
	}
	if v.Soft404 {
		ev.Observed = "hash=" + v.BodyHash
		ev.Reason = "body hash equals the soft-404 template; dimension does not fire"
		v.Evidence = append(v.Evidence, ev)
		return
	}

	// Compare against the most representative baseline body (the first probe;
	// probes are unanimous on soft-404 templates by construction).
	ctx, cancel := context.WithTimeout(context.Background(), e_simTimeout(v))
	defer cancel()
	sim, err := Similarity(ctx, bodies[0], view.Body, e_shingle(v))
	if err != nil {
		// Degradation rule: skip this dimension, keep the rest of the verdict.
		ev.Skipped = true
		ev.Reason = "similarity computation timed out; dimension skipped (response retained)"
		v.Evidence = append(v.Evidence, ev)
		return
	}
	ev.Observed = fmt.Sprintf("similarity %.2f", sim)
	ev.Baseline = fmt.Sprintf("threshold <= %.2f means different content", e_simThreshold(v))
	if sim < e_simThreshold(v) {
		ev.Fired = true
		ev.Score = 1.0 - sim
		ev.Reason = fmt.Sprintf("content differs from baseline (similarity %.2f below %.2f)", sim, e_simThreshold(v))
	} else {
		ev.Reason = fmt.Sprintf("content is near-identical to baseline (similarity %.2f)", sim)
	}
	v.Evidence = append(v.Evidence, ev)
}

// computeScore aggregates the weighted dimension scores. Fired hard
// dimensions (status/length/similarity, score>=1 each) carry their full
// weight; the timing dimension contributes at most 0.3.
func (v *Verdict) computeScore() {
	total := 0.0
	for i := range v.Evidence {
		ev := &v.Evidence[i]
		if ev.Skipped {
			continue
		}
		s := ev.Score
		if ev.Fired && s == 0 {
			s = 1.0
		}
		total += s * ev.Weight
	}
	v.Score = total
}

// finalize turns the dimension evidence into the boolean hit and builds the
// human-readable reason list.
func (v *Verdict) finalize(legacyMatch bool) {
	cfg := e_config(v)
	hardFired := false
	for _, ev := range v.Evidence {
		if ev.Skipped || !ev.Fired {
			continue
		}
		if ev.Dimension != DimTime {
			hardFired = true
		}
		v.Reasons = append(v.Reasons, ev.Reason)
	}

	switch {
	case v.Soft404:
		// A soft-404 (HTTP 200 page that is actually the not-found template)
		// is never a heuristic hit. Keep it only if the legacy rules explicitly
		// matched it, and say so.
		v.Hit = legacyMatch
		if legacyMatch {
			v.Reasons = append(v.Reasons, "soft-404 body but legacy matcher explicitly matched; retained for review")
		} else {
			v.Reasons = append(v.Reasons, "soft-404 detected: 200-class response body is identical to nonexistent-path baseline")
		}
	case hardFired || v.Score >= cfg.ScoreThreshold:
		v.Hit = true
	case legacyMatch:
		// Monotonicity guarantee: rule tuning never removes a hit the legacy
		// status-code rules would have reported. It is reported with the reason
		// that only the legacy path fired.
		v.Hit = true
		v.Reasons = append(v.Reasons, "retained by legacy status-code matcher even though no heuristic dimension fired")
	default:
		v.Hit = false
		if len(v.Reasons) == 0 {
			v.Reasons = append(v.Reasons, "all dimensions consistent with baseline; not a hit")
		}
	}
}

// --- false-positive suppression (continuous tuning) ----------------------

// AddSuppressor records a false-positive signature. Future responses with the
// same normalized body hash (and status, when non-zero) are suppressed.
func (e *Engine) AddSuppressor(s Suppressor) Suppressor {
	e.mu.Lock()
	defer e.mu.Unlock()
	if s.ID == "" {
		s.ID = fmt.Sprintf("fp-%d", time.Now().UnixNano())
	}
	if s.CreatedAt.IsZero() {
		s.CreatedAt = time.Now()
	}
	e.suppr[s.ID] = &s
	return s
}

// RemoveSuppressor deletes a signature by ID.
func (e *Engine) RemoveSuppressor(id string) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	if _, ok := e.suppr[id]; !ok {
		return false
	}
	delete(e.suppr, id)
	return true
}

// Suppressors returns copies of all signatures for persistence.
func (e *Engine) Suppressors() []Suppressor {
	e.mu.RLock()
	defer e.mu.RUnlock()
	out := make([]Suppressor, 0, len(e.suppr))
	for _, s := range e.suppr {
		out = append(out, *s)
	}
	return out
}

func (e *Engine) findSuppressorLocked(hash string, status int64) *Suppressor {
	for _, s := range e.suppr {
		if s.BodyHash != hash {
			continue
		}
		if s.StatusCode != 0 && s.StatusCode != status {
			continue
		}
		return s
	}
	return nil
}

// --- small config accessors that keep method signatures short -------------

func e_lenFloor(v *Verdict) int64           { return v.thresholds.LengthAbsFloor }
func e_relThreshold(v *Verdict) float64     { return v.thresholds.LengthRelThreshold }
func e_timeThreshold(v *Verdict) float64    { return v.thresholds.TimeRelThreshold }
func e_simThreshold(v *Verdict) float64     { return v.thresholds.SimilarityThreshold }
func e_simTimeout(v *Verdict) time.Duration { return v.thresholds.SimilarityTimeout }
func e_shingle(v *Verdict) int              { return v.thresholds.ShingleSize }
func e_config(v *Verdict) Config            { return v.thresholds }

func joinStatuses(set map[int64]bool) string {
	parts := make([]string, 0, len(set))
	for code := range set {
		parts = append(parts, fmt.Sprintf("%d", code))
	}
	sort.Strings(parts)
	return "{" + strings.Join(parts, ",") + "}"
}

func clampRel(x float64) float64 {
	if x < 0 {
		return 0
	}
	if x > 1 {
		return 1
	}
	return x
}

// RestoreGroup installs a baseline group loaded from a checkpoint. Points and
// readiness are restored verbatim so status/length/time/soft-404 decisions are
// identical across the resume boundary. Baseline bodies are not persisted
// (they can be large), so HasBodies reports false and the integration layer
// re-fetches one representative probe for the similarity dimension.
func (e *Engine) RestoreGroup(g BaselineGroup) {
	e.mu.Lock()
	defer e.mu.Unlock()
	cp := g
	cp.Points = append([]BaselinePoint(nil), g.Points...)
	e.groups[g.Key] = &cp
	ch := make(chan struct{})
	close(ch)
	e.ready[g.Key] = ch
}

// HasBodies reports whether a restored group has representative bodies for
// similarity comparisons.
func (e *Engine) HasBodies(group string) bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return len(e.bodies[group]) > 0
}

// SetBodies stores representative baseline bodies (typically one re-fetched
// probe after a resume) for a restored group.
func (e *Engine) SetBodies(group string, bodies [][]byte) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.bodies[group] = bodies
}

// LoadSuppressors restores false-positive signatures from a checkpoint or a
// suppressors file.
func (e *Engine) LoadSuppressors(ss []Suppressor) {
	for _, s := range ss {
		cp := s
		e.AddSuppressor(cp)
	}
}

// NewProbePath returns an unused nonexistent path for group, used by the
// integration layer to re-fetch a representative baseline body after a resume
// (bodies themselves are not persisted).
func (e *Engine) NewProbePath(group string) string {
	n := 0
	if g := e.groups[group]; g != nil {
		n = len(g.Points)
	}
	return e.nextProbePath(group, n)
}
