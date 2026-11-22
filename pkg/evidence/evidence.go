// Package evidence records the full per-request decision trail (including
// non-matches) and provides per-payload diffs.
//
// The normal scan output only contains hits; evaluation and reviewer
// triage need the misses too — each with the dimension evidence that explains
// why it was or was not reported. The Recorder writes one JSON object per line
// (JSONL, append-only) so a long scan can be inspected while still running and
// so a crash never loses more than the OS page cache.
package evidence

import (
	"bufio"
	"encoding/json"
	"os"
	"sync"
	"time"

	"github.com/ffuf/ffuf/v2/pkg/heuristics"
)

// Record is one line in the evidence log.
type Record struct {
	TS       time.Time           `json:"ts"`
	Position int                 `json:"position"`
	Inputs   map[string]string   `json:"inputs"`
	URL      string              `json:"url"`
	Legacy   bool                `json:"legacy_match"`
	Verdict  *heuristics.Verdict `json:"verdict,omitempty"`
	Signature
}

// Signature is the compact response fingerprint, duplicated here (rather than
// imported from checkpoint) so the evidence log has no coupling to resume
// state and can be consumed standalone.
type Signature struct {
	StatusCode    int64  `json:"status"`
	ContentLength int64  `json:"length"`
	ContentWords  int64  `json:"words"`
	ContentLines  int64  `json:"lines"`
	ContentType   string `json:"content_type,omitempty"`
	DurationMS    int64  `json:"duration_ms"`
	BodyHash      string `json:"body_hash"`
	Redirect      string `json:"redirect,omitempty"`
}

// Recorder appends JSONL evidence. It is safe for concurrent use.
type Recorder struct {
	mu sync.Mutex
	f  *os.File
	w  *bufio.Writer
}

// OpenRecorder creates (or appends to) an evidence log at path.
func OpenRecorder(path string) (*Recorder, error) {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o640)
	if err != nil {
		return nil, err
	}
	return &Recorder{f: f, w: bufio.NewWriterSize(f, 64*1024)}, nil
}

// Write appends one record.
func (r *Recorder) Write(rec Record) error {
	if rec.TS.IsZero() {
		rec.TS = time.Now()
	}
	line, err := json.Marshal(rec)
	if err != nil {
		return err
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, err := r.w.Write(append(line, '\n')); err != nil {
		return err
	}
	return nil
}

// Flush pushes buffered lines to disk; called periodically and on shutdown.
func (r *Recorder) Flush() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.w.Flush()
}

// Close flushes and closes the file.
func (r *Recorder) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if err := r.w.Flush(); err != nil {
		_ = r.f.Close()
		return err
	}
	return r.f.Close()
}

// Diff captures how two responses for the SAME path (different payloads or
// requests) differ across every measured dimension. It is what answers
// "where exactly do these two differ" instead of only saying "a finding
// exists". Equal dimensions are still enumerated so the reviewer sees the
// whole picture.
type Diff struct {
	Path string       `json:"path"`
	A    DiffEndpoint `json:"a"`
	B    DiffEndpoint `json:"b"`
}

// DiffEndpoint is one side of a comparison.
type DiffEndpoint struct {
	Label      string  `json:"label"`
	Status     int64   `json:"status"`
	Length     int64   `json:"length"`
	Words      int64   `json:"words"`
	Lines      int64   `json:"lines"`
	MS         int64   `json:"duration_ms"`
	BodyHash   string  `json:"body_hash"`
	Redirect   string  `json:"redirect,omitempty"`
	Similarity float64 `json:"similarity,omitempty"`
}

// DimensionDelta describes one compared dimension.
type DimensionDelta struct {
	Dimension string `json:"dimension"`
	A         string `json:"a"`
	B         string `json:"b"`
	Different bool   `json:"different"`
	Note      string `json:"note,omitempty"`
}

// Deltas returns the per-dimension comparison. Bodies are compared by hash
// (exact) and, when available, the caller-supplied similarity score is
// attached; body bytes are never copied into the diff.
func (d Diff) Deltas() []DimensionDelta {
	out := []DimensionDelta{
		{Dimension: heuristics.DimStatus, A: itoa(d.A.Status), B: itoa(d.B.Status), Different: d.A.Status != d.B.Status},
		{Dimension: "length", A: itoa(d.A.Length), B: itoa(d.B.Length), Different: d.A.Length != d.B.Length},
		{Dimension: "words", A: itoa(d.A.Words), B: itoa(d.B.Words), Different: d.A.Words != d.B.Words},
		{Dimension: "lines", A: itoa(d.A.Lines), B: itoa(d.B.Lines), Different: d.A.Lines != d.B.Lines},
		{Dimension: "time_ms", A: itoa(d.A.MS), B: itoa(d.B.MS), Different: d.A.MS != d.B.MS, Note: "timing is jitter-sensitive; treat as auxiliary"},
		{Dimension: "redirect", A: d.A.Redirect, B: d.B.Redirect, Different: d.A.Redirect != d.B.Redirect},
		{Dimension: "body_hash", A: d.A.BodyHash, B: d.B.BodyHash, Different: d.A.BodyHash != d.B.BodyHash},
	}
	if d.A.Similarity > 0 || d.B.Similarity > 0 {
		sim := d.A.Similarity
		if sim == 0 {
			sim = d.B.Similarity
		}
		out = append(out, DimensionDelta{
			Dimension: heuristics.DimSimilarity,
			A:         ftoa(sim), B: ftoa(sim),
			Different: sim < 0.85,
			Note:      "Jaccard similarity of normalized body shingles",
		})
	}
	return out
}

func itoa(n int64) string {
	if n == 0 {
		return "0"
	}
	var buf [20]byte
	i := len(buf)
	neg := n < 0
	if neg {
		n = -n
	}
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func ftoa(f float64) string {
	// One decimal place is enough for a similarity figure in a diff report.
	return string(appendFtoa(nil, f))
}

func appendFtoa(b []byte, f float64) []byte {
	if f < 0 {
		b = append(b, '-')
		f = -f
	}
	whole := int64(f)
	frac := int64((f-float64(whole))*10 + 0.5)
	if frac >= 10 {
		whole++
		frac -= 10
	}
	b = append(b, itoa(whole)...)
	b = append(b, '.')
	b = append(b, byte('0'+frac))
	return b
}
