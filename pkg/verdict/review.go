package verdict

import (
	"encoding/json"
	"errors"
	"os"
	"sync"

	"github.com/ffuf/ffuf/v2/pkg/ffuf"
)

// ReviewEntry is the reviewable record left for a response that was not
// emitted as a normal result (dropped, or kept under the undecidable policy
// while still carrying an undecidable verdict).
type ReviewEntry struct {
	// RequestID identifies the request (engine position + URL).
	RequestID string `json:"request_id"`
	// Position is the engine's per-request position when known (0 otherwise).
	Position int `json:"position"`
	// URL is the fully prepared request URL.
	URL string `json:"url"`
	// Host is the request host, useful with per-host rule sets.
	Host string `json:"host"`
	// Input is the fuzzing input that produced the response.
	Input map[string]string `json:"input"`
	// StatusCode / Length / Words / Lines are the response's comparable
	// metrics, duplicated here so a review record is self-contained.
	StatusCode int64 `json:"status_code"`
	Length     int64 `json:"content_length"`
	Words      int64 `json:"content_words"`
	Lines      int64 `json:"content_lines"`
	Cancelled  bool  `json:"cancelled"`
	// Decision is the full conclusion + attribution.
	Decision *Decision `json:"decision"`
	// Sequence is the global, monotonic insertion number.
	Sequence uint64 `json:"sequence"`
}

// ReviewStats is the bounded-store accounting, readable at any time.
type ReviewStats struct {
	// Capacity is the maximum number of entries retained in memory.
	Capacity int `json:"capacity"`
	// Stored is the number currently held.
	Stored int `json:"stored"`
	// TotalRecorded is how many entries have ever been accepted.
	TotalRecorded uint64 `json:"total_recorded"`
	// Evicted is how many entries were removed by FIFO overflow.
	Evicted uint64 `json:"evicted"`
	// SinkFailures is how many file-sink writes failed (the in-memory record
	// is still kept; only the on-disk copy is missing).
	SinkFailures uint64 `json:"sink_failures"`
	// SinkDisabled is set when the file sink could not be opened/used; when
	// true, review continues in memory but is marked unavailable on disk.
	SinkDisabled bool `json:"sink_disabled"`
	// SinkError is the first sink error that caused SinkDisabled / failures.
	SinkError string `json:"sink_error,omitempty"`
}

// ReviewStore is the bounded, concurrency-safe review buffer with an optional
// JSONL file sink. The zero value is not usable; construct with NewReviewStore.
type ReviewStore struct {
	mu       sync.Mutex
	capacity int
	ring     []*ReviewEntry
	head     int // index of the oldest entry
	count    int
	sequence uint64
	evicted  uint64

	sink        *os.File
	sinkEncoder *json.Encoder
	sinkBroken  bool
	sinkErr     error
	failures    uint64
}

// NewReviewStore creates a store holding at most capacity entries in memory.
// When sinkPath is non-empty, every accepted entry is additionally appended as
// one JSON line to that file. A failure to open the sink does not fail
// construction: per the degradation contract, review stays available in memory
// and the sink is marked unavailable.
func NewReviewStore(capacity int, sinkPath string) *ReviewStore {
	if capacity < 1 {
		capacity = 1
	}
	s := &ReviewStore{capacity: capacity}
	if sinkPath != "" {
		f, err := os.OpenFile(sinkPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0640)
		if err != nil {
			s.sinkBroken = true
			s.sinkErr = err
		} else {
			s.sink = f
			s.sinkEncoder = json.NewEncoder(f)
		}
	}
	return s
}

// ErrSinkUnavailable is returned (wrapped) by Sink when the file sink was never
// opened successfully.
var ErrSinkUnavailable = errors.New("review file sink unavailable")

// Record stores the attributed decision for resp. It never returns an error:
// sink write failures are accounted for in stats rather than disrupting the
// scan, and the verdict itself is produced independently of this call.
func (s *ReviewStore) Record(resp *ffuf.Response, dec *Decision) *ReviewEntry {
	entry := buildEntry(resp, dec)
	s.mu.Lock()
	s.sequence++
	entry.Sequence = s.sequence

	if s.count == s.capacity {
		// FIFO eviction: overwrite the oldest slot.
		s.ring[s.head] = entry
		s.head = (s.head + 1) % s.capacity
		s.evicted++
	} else {
		if s.ring == nil {
			s.ring = make([]*ReviewEntry, s.capacity)
		}
		idx := (s.head + s.count) % s.capacity
		s.ring[idx] = entry
		s.count++
	}

	s.writeSinkLocked(entry)
	s.mu.Unlock()
	return entry
}

// writeSinkLocked appends one JSON line. Any write error (disk full, permission
// lost) disables further sink attempts and is counted; the in-memory record is
// untouched.
func (s *ReviewStore) writeSinkLocked(entry *ReviewEntry) {
	if s.sink == nil {
		return
	}
	if s.sinkBroken {
		s.failures++
		return
	}
	if err := s.sinkEncoder.Encode(entry); err != nil {
		s.sinkBroken = true
		s.sinkErr = err
		s.failures++
	}
}

// Entries returns a copy of the retained entries in FIFO (oldest-first) order.
func (s *ReviewStore) Entries() []*ReviewEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]*ReviewEntry, 0, s.count)
	for i := 0; i < s.count; i++ {
		out = append(out, s.ring[(s.head+i)%s.capacity])
	}
	return out
}

// Stats returns a point-in-time copy of the store accounting.
func (s *ReviewStore) Stats() ReviewStats {
	s.mu.Lock()
	defer s.mu.Unlock()
	st := ReviewStats{
		Capacity:      s.capacity,
		Stored:        s.count,
		TotalRecorded: s.sequence,
		Evicted:       s.evicted,
		SinkFailures:  s.failures,
		SinkDisabled:  s.sinkBroken,
	}
	if s.sinkErr != nil {
		st.SinkError = s.sinkErr.Error()
	}
	return st
}

// Close flushes and closes the file sink, first writing one final stats record
// so the on-disk log is self-describing (including the FIFO eviction count).
// Closing an already-broken or nil sink is a no-op error.
func (s *ReviewStore) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.sink == nil {
		if s.sinkErr != nil {
			return ErrSinkUnavailable
		}
		return nil
	}
	summary := struct {
		Type  string      `json:"type"`
		Stats ReviewStats `json:"stats"`
	}{Type: "review_summary", Stats: s.statsLocked()}
	_ = s.sinkEncoder.Encode(summary) // best effort; Close still flushes
	err := s.sink.Close()
	s.sink = nil
	return err
}

// statsLocked returns the current accounting; caller must hold s.mu.
func (s *ReviewStore) statsLocked() ReviewStats {
	st := ReviewStats{
		Capacity:      s.capacity,
		Stored:        s.count,
		TotalRecorded: s.sequence,
		Evicted:       s.evicted,
		SinkFailures:  s.failures,
		SinkDisabled:  s.sinkBroken,
	}
	if s.sinkErr != nil {
		st.SinkError = s.sinkErr.Error()
	}
	return st
}

func buildEntry(resp *ffuf.Response, dec *Decision) *ReviewEntry {
	entry := &ReviewEntry{
		RequestID:  RequestID(resp),
		Decision:   dec,
		StatusCode: resp.StatusCode,
		Length:     resp.ContentLength,
		Words:      resp.ContentWords,
		Lines:      resp.ContentLines,
		Cancelled:  resp.Cancelled,
		Input:      map[string]string{},
	}
	if resp.Request != nil {
		entry.Position = resp.Request.Position
		entry.URL = resp.Request.Url
		entry.Host = resp.Request.Host
		for k, v := range resp.Request.Input {
			entry.Input[k] = string(v)
		}
	}
	return entry
}
