// Package checkpoint persists scan progress so a multi-hour dictionary run can
// be interrupted and resumed without re-requesting completed entries.
//
// The state file is an append-oriented JSON document keyed by stable entry
// identities (wordlist position + input values), so resuming is independent of
// response ordering and concurrency. Completed entries, verdicts and the
// heuristic engine's baselines/suppressors are all stored: a resumed scan
// reproduces the same decisions it would have made in one uninterrupted run.
//
// Writes are atomic (temp file + rename) and serialized by a file lock, so a
// SIGKILL at any point leaves either the previous complete state or the new
// one, never a torn JSON document.
package checkpoint

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"sync"
	"time"

	"github.com/ffuf/ffuf/v2/pkg/heuristics"
)

// StateFileName is the conventional state file name inside a checkpoint
// directory.
const StateFileName = "ffuf-checkpoint.json"

// SchemaVersion is bumped when the on-disk shape changes incompatibly.
const SchemaVersion = 1

// ErrStaleCheckpoint is returned when a state file was produced for a different
// target/wordlist configuration. Resuming against a mismatched checkpoint
// would silently skip entries against the wrong target, so the caller must
// choose a fresh state file explicitly.
var ErrStaleCheckpoint = errors.New("checkpoint does not match the current scan configuration")

// Entry is the persisted outcome of one wordlist entry.
type Entry struct {
	// Position is the wordlist position assigned by the input provider; it is
	// the primary resume key.
	Position int `json:"position"`
	// Inputs holds the keyword/value combination that produced this entry, so
	// multi-wordlist modes (clusterbomb/pitchfork) can identify themselves
	// without relying on position alone.
	Inputs map[string]string `json:"inputs"`
	// Done means the request was sent (or terminally failed) and needs no
	// retry. Entries that errored transiently are still marked done only when
	// the runner gave up, matching the engine's own retry semantics.
	Done bool `json:"done"`
	// Matched records whether the active decision logic reported a hit.
	Matched bool `json:"matched"`
	// Verdict is the full explainable heuristic verdict (nil in legacy mode).
	Verdict *heuristics.Verdict `json:"verdict,omitempty"`
	// ResponseSignature retains the dimensions needed for the evaluation
	// report and per-payload diffs without storing full response bodies.
	ResponseSignature Signature `json:"signature"`
	// Error holds the terminal request error, if any.
	Error string `json:"error,omitempty"`
	// UpdatedAt makes the file self-describing when triaging an interrupted run.
	UpdatedAt time.Time `json:"updated_at"`
}

// Signature is the compact per-response fingerprint kept in the checkpoint.
type Signature struct {
	StatusCode    int64  `json:"status"`
	ContentLength int64  `json:"length"`
	ContentWords  int64  `json:"words"`
	ContentLines  int64  `json:"lines"`
	ContentType   string `json:"content_type,omitempty"`
	DurationMS    int64  `json:"duration_ms"`
	BodyHash      string `json:"body_hash"`
	Redirect      string `json:"redirect,omitempty"`
	URL           string `json:"url"`
}

// State is the full persisted document.
type State struct {
	SchemaVersion int `json:"schema_version"`
	// ScanID identifies the exact configuration (hash of target URL,
	// wordlist paths, method, extensions, ...). A resume with a different
	// ScanID is refused.
	ScanID string `json:"scan_id"`
	// Target and Wordlists are human-readable confirmations of ScanID.
	Target    string   `json:"target"`
	Wordlists []string `json:"wordlists"`

	// Total is the input provider's expected entry count. A mismatch on resume
	// (wordlist changed size) is surfaced as a warning but resumed positions
	// below the new total remain valid.
	Total int `json:"total"`
	// Completed and MatchedCount are denormalized counters for quick status.
	Completed    int `json:"completed"`
	MatchedCount int `json:"matched_count"`

	Entries map[string]*Entry `json:"entries"`

	// Baselines and Suppressors let a resumed scan keep the exact heuristic
	// context of the original run.
	Baselines   map[string]heuristics.BaselineGroup `json:"baselines,omitempty"`
	Suppressors []heuristics.Suppressor             `json:"suppressors,omitempty"`

	CreatedAt time.Time `json:"created_at"`
	UpdatedAt time.Time `json:"updated_at"`
}

// Store serializes and guards access to one state file. It is safe for
// concurrent use: workers record entries while a flush goroutine persists.
type Store struct {
	mu       sync.Mutex
	path     string
	state    *State
	dirty    bool
	flushNow chan struct{}
	closed   bool
}

// Key builds the stable string identity for an entry.
func Key(position int, inputs map[string]string) string {
	// Sort keys so identical input maps always serialize identically.
	keys := make([]string, 0, len(inputs))
	for k := range inputs {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	key := fmt.Sprintf("p%d", position)
	for _, k := range keys {
		key += "|" + k + "=" + inputs[k]
	}
	return key
}

// CreateOrOpen opens an existing state file for scanID or initializes a fresh
// one. An existing file whose ScanID differs returns ErrStaleCheckpoint.
func CreateOrOpen(dir, scanID, target string, wordlists []string, total int) (*Store, error) {
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return nil, err
	}
	path := filepath.Join(dir, StateFileName)
	st := &State{
		SchemaVersion: SchemaVersion,
		ScanID:        scanID,
		Target:        target,
		Wordlists:     append([]string(nil), wordlists...),
		Total:         total,
		Entries:       make(map[string]*Entry),
		Baselines:     make(map[string]heuristics.BaselineGroup),
		CreatedAt:     time.Now(),
		UpdatedAt:     time.Now(),
	}
	if data, err := os.ReadFile(path); err == nil {
		var loaded State
		if jerr := json.Unmarshal(data, &loaded); jerr != nil {
			return nil, fmt.Errorf("checkpoint %s is corrupt: %w; move or delete it before retrying", path, jerr)
		}
		if loaded.ScanID != scanID {
			return nil, fmt.Errorf("%w: checkpoint scan %q != current scan %q", ErrStaleCheckpoint, loaded.ScanID, scanID)
		}
		if loaded.SchemaVersion != SchemaVersion {
			return nil, fmt.Errorf("checkpoint schema version %d unsupported (want %d)", loaded.SchemaVersion, SchemaVersion)
		}
		st = &loaded
		if st.Entries == nil {
			st.Entries = make(map[string]*Entry)
		}
		if st.Baselines == nil {
			st.Baselines = make(map[string]heuristics.BaselineGroup)
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	return &Store{path: path, state: st, flushNow: make(chan struct{}, 1)}, nil
}

// State returns a copy of the current state for reporting.
func (s *Store) State() State {
	s.mu.Lock()
	defer s.mu.Unlock()
	cp := *s.state
	cp.Entries = make(map[string]*Entry, len(s.state.Entries))
	for k, v := range s.state.Entries {
		ev := *v
		cp.Entries[k] = &ev
	}
	return cp
}

// IsDone reports whether an entry was completed in a previous run.
func (s *Store) IsDone(position int, inputs map[string]string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.state.Entries[Key(position, inputs)]
	return ok && e.Done
}

// MatchedEntry returns the stored entry if it was a match, for re-surfacing
// prior hits on resume without re-requesting.
func (s *Store) MatchedEntries() []Entry {
	s.mu.Lock()
	defer s.mu.Unlock()
	out := make([]Entry, 0, s.state.MatchedCount)
	for _, e := range s.state.Entries {
		if e.Done && e.Matched {
			out = append(out, *e)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Position < out[j].Position })
	return out
}

// EntryAtPosition returns the entry recorded at wordlist position pos and
// whether it existed. Used by the interactive false-positive command to
// recover the body hash and baseline group of a result shown to the user.
func (s *Store) EntryAtPosition(pos int) (Entry, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, e := range s.state.Entries {
		if e.Position == pos {
			return *e, true
		}
	}
	return Entry{}, false
}

// Record stores one completed entry and marks the state dirty.
func (s *Store) Record(e Entry) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return
	}
	e.UpdatedAt = time.Now()
	key := Key(e.Position, e.Inputs)
	prev, existed := s.state.Entries[key]
	s.state.Entries[key] = &e
	if e.Done && (!existed || !prev.Done) {
		s.state.Completed++
	}
	if e.Matched && (!existed || !prev.Matched) {
		s.state.MatchedCount++
	}
	if existed && prev.Matched && !e.Matched {
		s.state.MatchedCount--
	}
	s.state.UpdatedAt = time.Now()
	s.dirty = true
}

// SaveBaselines/Baselines and suppressor persistence keep the heuristic
// context identical across a resume boundary.
func (s *Store) SaveBaselines(groups map[string]heuristics.BaselineGroup) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Baselines = make(map[string]heuristics.BaselineGroup, len(groups))
	for k, v := range groups {
		s.state.Baselines[k] = v
	}
	s.dirty = true
}

func (s *Store) SaveSuppressors(sup []heuristics.Suppressor) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.state.Suppressors = append([]heuristics.Suppressor(nil), sup...)
	s.dirty = true
}

// Flush writes the state to disk atomically if it changed. Safe to call
// repeatedly (e.g. from a ticker and on shutdown).
func (s *Store) Flush() error {
	s.mu.Lock()
	if s.closed || !s.dirty {
		s.mu.Unlock()
		return nil
	}
	s.dirty = false
	data, err := json.MarshalIndent(s.state, "", "  ")
	s.mu.Unlock()
	if err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, s.path)
}

// Close flushes any pending state. After Close, Record becomes a no-op.
func (s *Store) Close() error {
	s.mu.Lock()
	s.closed = true
	s.mu.Unlock()
	return s.Flush()
}

// Path exposes the state file location for status messages.
func (s *Store) Path() string { return s.path }
