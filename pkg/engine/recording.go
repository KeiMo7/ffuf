package engine

import (
	"net/url"
	"time"

	"github.com/ffuf/ffuf/v2/pkg/ffuf"
	"github.com/ffuf/ffuf/v2/pkg/heuristics"
)

// stringInputs converts the runner's []byte input map to the string-keyed
// form used by checkpoint/evidence records. FFUFHASH is excluded: it is a
// per-run derived value, not part of the entry's identity.
func stringInputs(in map[string][]byte) map[string]string {
	out := make(map[string]string, len(in))
	for k, v := range in {
		if k == "FFUFHASH" {
			continue
		}
		out[k] = string(v)
	}
	return out
}

// urlPathOf extracts the path component of a request URL, tolerating parse
// failures by returning "" (which maps to the default baseline group).
func urlPathOf(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return u.Path
}

func (j *Job) buildSignature(req ffuf.Request, resp ffuf.Response) CheckpointSignature {
	redirect := ""
	if resp.Request != nil {
		redirect = resp.GetRedirectLocation(false)
	}
	return CheckpointSignature{
		StatusCode:    resp.StatusCode,
		ContentLength: resp.ContentLength,
		ContentWords:  resp.ContentWords,
		ContentLines:  resp.ContentLines,
		ContentType:   resp.ContentType,
		DurationMS:    resp.Duration.Milliseconds(),
		BodyHash:      heuristics.HashBody(resp.Data),
		Redirect:      redirect,
		URL:           req.Url,
	}
}

// recordEvidence appends one JSONL line when the evidence recorder is active.
// A write error is reported but never aborts the scan: evidence is observability.
func (j *Job) recordEvidence(req ffuf.Request, resp ffuf.Response, legacyMatch bool, verdict *heuristics.Verdict) {
	if j.Evidence == nil {
		return
	}
	rec := EvidenceRecord{
		Position:    req.Position,
		Inputs:      stringInputs(req.Input),
		URL:         req.Url,
		LegacyMatch: legacyMatch,
		Verdict:     verdict,
		Signature:   j.buildSignature(req, resp),
	}
	if err := j.Evidence.Write(rec); err != nil {
		j.Output.Warning("evidence log write failed: " + err.Error())
	}
}

// recordCheckpoint persists one completed entry when checkpointing is active.
func (j *Job) recordCheckpoint(req ffuf.Request, resp ffuf.Response, legacyMatch bool, verdict *heuristics.Verdict, reqErr string) {
	if j.Checkpoint == nil {
		return
	}
	matched := legacyMatch
	if verdict != nil {
		matched = verdict.Hit
	}
	entry := CheckpointEntry{
		Position:  req.Position,
		Inputs:    stringInputs(req.Input),
		Done:      true,
		Matched:   matched,
		Verdict:   verdict,
		Signature: j.buildSignature(req, resp),
		Error:     reqErr,
	}
	j.Checkpoint.Record(entry)
	// Persist heuristic context alongside progress whenever it changed, so a
	// resumed run evaluates against identical baselines and suppressors.
	if j.Decider != nil {
		eng := j.Decider.Engine()
		groups := make(map[string]heuristics.BaselineGroup)
		for _, key := range eng.Groups() {
			if g, ok := eng.GroupSnapshot(key); ok {
				groups[key] = g
			}
		}
		j.Checkpoint.SaveBaselines(groups)
		j.Checkpoint.SaveSuppressors(eng.Suppressors())
	}
}

// startFlushLoop periodically persists checkpoint state and evidence buffers.
// It returns a stop function that performs a final flush, so a clean exit and a
// SIGTERM-driven Stop both leave a complete state file.
func (j *Job) startFlushLoop() func() {
	interval := time.Duration(j.Config.EvalFlushSecs) * time.Second
	if interval <= 0 {
		interval = 5 * time.Second
	}
	if j.Checkpoint == nil && j.Evidence == nil {
		return func() {}
	}
	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(interval)
		defer ticker.Stop()
		for {
			select {
			case <-done:
				return
			case <-ticker.C:
				j.flushState()
			}
		}
	}()
	return func() {
		close(done)
		j.flushState()
	}
}

func (j *Job) flushState() {
	if j.Checkpoint != nil {
		if err := j.Checkpoint.Flush(); err != nil {
			j.Output.Warning("checkpoint flush failed: " + err.Error())
		}
	}
	if j.Evidence != nil {
		if err := j.Evidence.Flush(); err != nil {
			j.Output.Warning("evidence flush failed: " + err.Error())
		}
	}
}

// resurfacePriorMatches re-emits hits loaded from a checkpoint through the
// output provider, so a resumed run's result set contains everything the
// original run had found without re-requesting those entries. The rebuilt
// responses carry every dimension the output formats render.
func (j *Job) resurfacePriorMatches() {
	if j.Checkpoint == nil {
		return
	}
	prior := j.Checkpoint.MatchedEntries()
	if len(prior) == 0 {
		return
	}
	j.Output.Info(pluralize(len(prior), "resumed match from checkpoint", "resumed matches from checkpoint"))
	for _, e := range prior {
		inputs := make(map[string][]byte, len(e.Inputs)+1)
		for k, v := range e.Inputs {
			inputs[k] = []byte(v)
		}
		req := ffuf.Request{
			Url:      e.Signature.URL,
			Input:    inputs,
			Position: e.Position,
		}
		resp := ffuf.Response{
			StatusCode:    e.Signature.StatusCode,
			ContentLength: e.Signature.ContentLength,
			ContentWords:  e.Signature.ContentWords,
			ContentLines:  e.Signature.ContentLines,
			ContentType:   e.Signature.ContentType,
			Duration:      time.Duration(e.Signature.DurationMS) * time.Millisecond,
			Request:       &req,
			ScraperData:   make(map[string][]string),
		}
		j.Output.Result(resp)
	}
}

func pluralize(n int, singular, plural string) string {
	if n == 1 {
		return "1 " + singular
	}
	// local small integer formatter to avoid importing strconv just for this
	digits := ""
	for n > 0 {
		digits = string(rune('0'+n%10)) + digits
		n /= 10
	}
	return digits + " " + plural
}
