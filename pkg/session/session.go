// Package session tracks the stop and result-deduplication state of one ffuf
// session. It is deliberately self-contained: it imports only the standard
// library so the engine can depend on it without pulling in any provider, and so
// it can be unit-tested in isolation.
//
// A Session records the reason the scan was asked to stop, waits for in-flight
// requests to drain (or gives up after a caller-supplied context), and keeps a
// first-seen ledger of responses so duplicate results can be suppressed.
package session

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Sentinel errors. They are wrapped with context by the methods that return
// them, so callers should match them with errors.Is.
var (
	// ErrInvalidOptions is returned by New when the session options are invalid.
	ErrInvalidOptions = errors.New("invalid session options")
	// ErrInvalidTransition is returned when an operation is not valid in the
	// session's current state.
	ErrInvalidTransition = errors.New("invalid session state transition")
	// ErrInvalidObservation is returned by Observe for an observation that
	// cannot be fingerprinted, such as one with an empty URL.
	ErrInvalidObservation = errors.New("invalid observation")
	// ErrSessionClosed is returned by Observe after the session has stopped.
	ErrSessionClosed = errors.New("session closed")
	// ErrDrainTimeout is returned by Drain when in-flight requests did not
	// finish before the drain context expired.
	ErrDrainTimeout = errors.New("session drain timeout")
)

// Reason identifies why a stop was requested.
type Reason string

// The set of stop reasons a session can record.
const (
	// ReasonInterrupt is a keyboard interrupt or SIGTERM.
	ReasonInterrupt Reason = "interrupt"
	// ReasonMaxTime is the whole-process -maxtime limit.
	ReasonMaxTime Reason = "max-time"
	// ReasonMaxTimeJob is the per-job -maxtime-job limit.
	ReasonMaxTimeJob Reason = "max-time-job"
	// ReasonStopOn403 is the -sf "too many 403 responses" stop.
	ReasonStopOn403 Reason = "stop-on-403"
	// ReasonStopOn429 is the -sa "too many 429 responses" stop.
	ReasonStopOn429 Reason = "stop-on-429"
	// ReasonSpuriousErrors is the -se "too many errors" stop.
	ReasonSpuriousErrors Reason = "spurious-errors"
)

// Scope says how wide a stop request reaches.
type Scope string

// The two stop scopes.
const (
	// ScopeJob stops the current queue job only.
	ScopeJob Scope = "job"
	// ScopeSession stops the whole session.
	ScopeSession Scope = "session"
)

// State is the lifecycle state of a session.
type State string

// The session lifecycle states.
const (
	// StateIdle is the state of a freshly created session.
	StateIdle State = "idle"
	// StateRunning is the state after the first BeginJob.
	StateRunning State = "running"
	// StateDraining means a session stop was requested and in-flight work is
	// being awaited.
	StateDraining State = "draining"
	// StateStopped is the terminal state, entered by Drain.
	StateStopped State = "stopped"
)

// defaultFields is the dedup fingerprint dimension set used when Options.Fields
// is empty.
var defaultFields = []string{"url", "status", "length", "words", "lines"}

// allFields is the canonical dimension order. A fingerprint always walks the
// enabled dimensions in this order, regardless of the order they were supplied.
var allFields = []string{"url", "status", "length", "words", "lines", "redirect", "content-type"}

// knownFields reports whether name is a valid fingerprint dimension.
func knownFields(name string) bool {
	for _, f := range allFields {
		if f == name {
			return true
		}
	}
	return false
}

// Options configures a Session.
type Options struct {
	// Capacity bounds the number of remembered entries; 0 means unlimited.
	// A positive capacity evicts the oldest entry when full.
	Capacity int
	// Fields selects the response dimensions folded into the fingerprint.
	// Empty means the default url,status,length,words,lines set. Entries are
	// trimmed, lower-cased, and must include "url".
	Fields []string
	// Now is the clock used for timestamps. Nil means time.Now.
	Now func() time.Time
}

// normalizeFields trims and lower-cases the configured dimensions, drops empty
// entries, rejects unknown names, requires url, and returns them in canonical
// order. An empty input means the default set.
func normalizeFields(in []string) ([]string, error) {
	if len(in) == 0 {
		return append([]string(nil), defaultFields...), nil
	}
	seen := make(map[string]bool, len(in))
	for _, raw := range in {
		name := strings.ToLower(strings.TrimSpace(raw))
		if name == "" {
			continue
		}
		if !knownFields(name) {
			return nil, fmt.Errorf("%w: unknown field %q", ErrInvalidOptions, name)
		}
		seen[name] = true
	}
	if len(seen) == 0 {
		return append([]string(nil), defaultFields...), nil
	}
	if !seen["url"] {
		return nil, fmt.Errorf("%w: fields must include \"url\"", ErrInvalidOptions)
	}
	out := make([]string, 0, len(seen))
	for _, name := range allFields {
		if seen[name] {
			out = append(out, name)
		}
	}
	return out, nil
}

// Observation is the slice of a response the session fingerprints and records.
type Observation struct {
	// URL is the fuzzed request URL. It is required.
	URL string
	// Status is the HTTP status code.
	Status int64
	// Length is the response body length.
	Length int64
	// Words is the response word count.
	Words int64
	// Lines is the response line count.
	Lines int64
	// Redirect is the response's redirect target, if any.
	Redirect string
	// ContentType is the response Content-Type header value.
	ContentType string
	// Position is the fuzzing input position, recorded as the first position of
	// a new entry.
	Position int
}

// Verdict is Observe's answer for a single observation.
type Verdict struct {
	// Duplicate reports whether the fingerprint had already been seen.
	Duplicate bool
	// EntryID is the ledger entry this observation belongs to.
	EntryID int
	// FirstPosition is the input position of the entry's first observation.
	FirstPosition int
}

// Entry is one first-seen result in the dedup ledger.
type Entry struct {
	// EntryID is the 1-based first-seen sequence number.
	EntryID int
	// FirstPosition is the input position of the first observation.
	FirstPosition int
	// Count is how many times the fingerprint has been observed.
	Count int
}

// StopRequest is one accepted stop request.
type StopRequest struct {
	// Seq is the 1-based request sequence number.
	Seq int
	// Reason is why the stop was requested.
	Reason Reason
	// Scope is how wide the stop reaches.
	Scope Scope
	// At is when the request was recorded.
	At time.Time
}

// Report is a snapshot of the session state, safe to retain and modify.
type Report struct {
	// State is the current lifecycle state.
	State State
	// Reason is the reason of the first accepted stop request, if any.
	Reason Reason
	// Scope is the widest scope of the accepted stop requests.
	Scope Scope
	// Canceled reports whether any session-scope stop was requested.
	Canceled bool
	// Forced reports whether a drain timed out with work still in flight.
	Forced bool
	// Outstanding is the current number of tracked in-flight requests.
	Outstanding int
	// InFlightAtStop is the in-flight count when the first stop was accepted.
	InFlightAtStop int
	// JobStops is the number of job-scope stop requests.
	JobStops int
	// Requests is a copy of the accepted stop requests, in order.
	Requests []StopRequest
	// Entries is a copy of the dedup ledger, ordered by EntryID.
	Entries []Entry
	// Observed is the number of observations accepted.
	Observed int
	// Suppressed is the number of duplicate observations.
	Suppressed int
	// Evicted is the number of entries dropped by the capacity bound.
	Evicted int
	// StartedAt is when the first job began.
	StartedAt time.Time
	// StoppedAt is when the first Drain completed.
	StoppedAt time.Time
	// Duration is the time between StartedAt and StoppedAt (or now, while the
	// session has not stopped).
	Duration time.Duration
}

// entry is the internal ledger record.
type entry struct {
	id            int
	firstPosition int
	count         int
}

// Session is the stop and dedup state of one ffuf session. All methods are safe
// for concurrent use.
type Session struct {
	mu       sync.Mutex
	now      func() time.Time
	fields   []string
	capacity int

	state      State
	startedAt  time.Time
	stoppedAt  time.Time
	jobGate    bool
	canceled   bool
	forced     bool
	scope      Scope
	firstSet   bool
	firstCause Reason
	firstIn    int
	requests   []StopRequest
	jobStops   int

	outstanding int
	zeroCh      chan struct{}

	entries    map[string]*entry
	order      []string
	nextID     int
	observed   int
	suppressed int
	evicted    int

	drained     bool
	drainErr    error
	firstReport Report
}

// New creates a Session from opts. It returns an error wrapping
// ErrInvalidOptions when the field selection is invalid or the capacity is
// negative.
func New(opts Options) (*Session, error) {
	fields, err := normalizeFields(opts.Fields)
	if err != nil {
		return nil, err
	}
	if opts.Capacity < 0 {
		return nil, fmt.Errorf("%w: capacity must not be negative", ErrInvalidOptions)
	}
	now := opts.Now
	if now == nil {
		now = time.Now
	}
	zero := make(chan struct{})
	close(zero)
	return &Session{
		now:      now,
		fields:   fields,
		capacity: opts.Capacity,
		state:    StateIdle,
		zeroCh:   zero,
		entries:  make(map[string]*entry),
		nextID:   1,
	}, nil
}

// gateOpenLocked reports whether new work may start. The caller holds s.mu.
func (s *Session) gateOpenLocked() bool {
	return s.state == StateRunning && s.jobGate
}

// GateOpen reports whether new work may start: the session is running and no
// job-scope stop is in effect.
func (s *Session) GateOpen() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.gateOpenLocked()
}

// Canceled reports whether any session-scope stop has been requested.
func (s *Session) Canceled() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.canceled
}

// BeginJob starts the session on the first call (idle -> running) and reopens
// the job gate on later calls. It returns an error wrapping ErrInvalidTransition
// once the session is draining or stopped.
func (s *Session) BeginJob() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch s.state {
	case StateIdle:
		s.state = StateRunning
		s.startedAt = s.now()
		s.jobGate = true
		return nil
	case StateRunning:
		s.jobGate = true
		return nil
	default:
		return fmt.Errorf("%w: cannot begin a job in state %s", ErrInvalidTransition, s.state)
	}
}

// Request records a stop request with the given reason and scope. It returns an
// error wrapping ErrInvalidTransition when the session is idle, and nil without
// recording anything once the session is stopped.
func (s *Session) Request(reason Reason, scope Scope) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	switch s.state {
	case StateIdle:
		return fmt.Errorf("%w: cannot request a stop in state %s", ErrInvalidTransition, s.state)
	case StateStopped:
		return nil
	}

	s.requests = append(s.requests, StopRequest{
		Seq:    len(s.requests) + 1,
		Reason: reason,
		Scope:  scope,
		At:     s.now(),
	})
	if !s.firstSet {
		s.firstSet = true
		s.firstCause = reason
		s.firstIn = s.outstanding
	}
	if scope == ScopeSession {
		s.canceled = true
		s.scope = ScopeSession
		// A session stop closes the dispatch gate and winds the session down. The
		// state stays running so Drain (below or at the end of the run) is the only
		// transition into stopped.
		s.jobGate = false
	} else {
		s.jobStops++
		s.jobGate = false
		if s.scope == "" {
			s.scope = ScopeJob
		}
	}
	return nil
}

// Track registers one in-flight request, if the gate is open. It returns false
// and does not change the count when new work may not start.
func (s *Session) Track() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.gateOpenLocked() {
		return false
	}
	if s.outstanding == 0 {
		s.zeroCh = make(chan struct{})
	}
	s.outstanding++
	return true
}

// Release unregisters one in-flight request. It is a no-op when the count is
// already zero.
func (s *Session) Release() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.outstanding == 0 {
		return
	}
	s.outstanding--
	if s.outstanding == 0 {
		close(s.zeroCh)
	}
}

// Drain waits for every tracked request to finish or for ctx to expire, then
// moves the session to stopped. An idle session returns an error wrapping
// ErrInvalidTransition. Once the in-flight count reaches zero it returns a nil
// error; if ctx expires first it sets Forced and returns an error wrapping
// ErrDrainTimeout. Repeated calls return the first report and error.
func (s *Session) Drain(ctx context.Context) (Report, error) {
	var done <-chan struct{}
	if ctx != nil {
		done = ctx.Done()
	}

	s.mu.Lock()
	switch s.state {
	case StateIdle:
		s.mu.Unlock()
		return Report{}, fmt.Errorf("%w: cannot drain an idle session", ErrInvalidTransition)
	case StateStopped:
		defer s.mu.Unlock()
		return cloneReport(s.firstReport), s.drainErr
	}
	s.state = StateDraining
	for {
		if s.state == StateStopped {
			defer s.mu.Unlock()
			return cloneReport(s.firstReport), s.drainErr
		}
		if s.outstanding == 0 {
			rep := s.finishDrainLocked(false)
			s.mu.Unlock()
			return rep, nil
		}
		ch := s.zeroCh
		s.mu.Unlock()
		select {
		case <-ch:
			s.mu.Lock()
		case <-done:
			s.mu.Lock()
			// Another caller may have completed the drain between our re-check and
			// the timeout firing; the first report wins.
			if s.state == StateStopped {
				defer s.mu.Unlock()
				return cloneReport(s.firstReport), s.drainErr
			}
			if s.outstanding == 0 {
				rep := s.finishDrainLocked(false)
				s.mu.Unlock()
				return rep, nil
			}
			rep := s.finishDrainLocked(true)
			s.mu.Unlock()
			return rep, ErrDrainTimeout
		}
	}
}

// finishDrainLocked transitions to stopped, records the timestamps, and stores
// the first report. The caller holds s.mu and must unlock it.
func (s *Session) finishDrainLocked(forced bool) Report {
	s.state = StateStopped
	s.stoppedAt = s.now()
	if forced {
		s.forced = true
		s.drainErr = ErrDrainTimeout
	} else {
		s.drainErr = nil
	}
	rep := s.snapshotLocked()
	s.firstReport = cloneReport(rep)
	s.drained = true
	return rep
}

// Observe fingerprints an observation and records it in the ledger. The first
// observation of a fingerprint is unique; later ones increment its count and
// are reported as duplicates. It returns an error wrapping
// ErrInvalidObservation for an empty URL and ErrSessionClosed after the session
// has stopped.
func (s *Session) Observe(o Observation) (Verdict, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.state == StateStopped {
		return Verdict{}, ErrSessionClosed
	}
	if strings.TrimSpace(o.URL) == "" {
		return Verdict{}, fmt.Errorf("%w: empty URL", ErrInvalidObservation)
	}

	fp := s.fingerprintLocked(o)
	s.observed++
	if e, ok := s.entries[fp]; ok {
		e.count++
		s.suppressed++
		return Verdict{Duplicate: true, EntryID: e.id, FirstPosition: e.firstPosition}, nil
	}

	if s.capacity > 0 && len(s.order) >= s.capacity {
		victim := s.order[0]
		s.order = s.order[1:]
		delete(s.entries, victim)
		s.evicted++
	}

	e := &entry{id: s.nextID, firstPosition: o.Position, count: 1}
	s.nextID++
	s.entries[fp] = e
	s.order = append(s.order, fp)
	return Verdict{Duplicate: false, EntryID: e.id, FirstPosition: o.Position}, nil
}

// ResetResults clears the dedup ledger and its counters so an interactive
// restart can print results again. It leaves the lifecycle state, stop requests
// and in-flight count untouched.
func (s *Session) ResetResults() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.entries = make(map[string]*entry)
	s.order = nil
	s.nextID = 1
	s.observed = 0
	s.suppressed = 0
	s.evicted = 0
}

// Report returns a snapshot of the current session state.
func (s *Session) Report() Report {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.snapshotLocked()
}

// snapshotLocked builds a Report copy. The caller holds s.mu.
func (s *Session) snapshotLocked() Report {
	rep := Report{
		State:          s.state,
		Scope:          s.scope,
		Canceled:       s.canceled,
		Forced:         s.forced,
		Outstanding:    s.outstanding,
		InFlightAtStop: s.firstIn,
		JobStops:       s.jobStops,
		Observed:       s.observed,
		Suppressed:     s.suppressed,
		Evicted:        s.evicted,
		StartedAt:      s.startedAt,
		StoppedAt:      s.stoppedAt,
	}
	if s.firstSet {
		rep.Reason = s.firstCause
	}
	rep.Requests = append([]StopRequest(nil), s.requests...)
	rep.Entries = s.entriesLocked()

	if !s.startedAt.IsZero() {
		end := s.stoppedAt
		if s.state != StateStopped || end.IsZero() {
			end = s.now()
		}
		if !end.Before(s.startedAt) {
			rep.Duration = end.Sub(s.startedAt)
		}
	}
	return rep
}

// entriesLocked returns the ledger ordered by EntryID. The caller holds s.mu.
func (s *Session) entriesLocked() []Entry {
	out := make([]Entry, 0, len(s.entries))
	for _, fp := range s.order {
		if e, ok := s.entries[fp]; ok {
			out = append(out, Entry{EntryID: e.id, FirstPosition: e.firstPosition, Count: e.count})
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i].EntryID < out[j].EntryID })
	return out
}

// fingerprintLocked hashes the enabled dimensions in canonical order. The caller
// holds s.mu (not strictly required, but keeps the snapshot consistent).
func (s *Session) fingerprintLocked(o Observation) string {
	normalized := normalizeURL(o.URL)
	h := sha256.New()
	for i, name := range s.fields {
		if i > 0 {
			h.Write([]byte{0x1f})
		}
		h.Write([]byte(name))
		h.Write([]byte{'='})
		h.Write([]byte(fieldValue(name, o, normalized)))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// fieldValue renders one fingerprint dimension.
func fieldValue(name string, o Observation, normalizedURL string) string {
	switch name {
	case "url":
		return normalizedURL
	case "status":
		return strconv.FormatInt(o.Status, 10)
	case "length":
		return strconv.FormatInt(o.Length, 10)
	case "words":
		return strconv.FormatInt(o.Words, 10)
	case "lines":
		return strconv.FormatInt(o.Lines, 10)
	case "redirect":
		return o.Redirect
	case "content-type":
		return o.ContentType
	}
	return ""
}

// normalizeURL trims the URL, lower-cases the scheme and host, drops the
// fragment and removes the default port for the scheme. The path and query are
// left exactly as given (the query is not sorted). A URL that fails to parse is
// used as the trimmed original string.
func normalizeURL(raw string) string {
	trimmed := strings.TrimSpace(raw)
	u, err := url.Parse(trimmed)
	if err != nil {
		return trimmed
	}
	u.Scheme = strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	port := u.Port()
	if (u.Scheme == "http" && port == "80") || (u.Scheme == "https" && port == "443") {
		port = ""
		u.Host = host
		if strings.Contains(host, ":") {
			u.Host = "[" + host + "]"
		}
	} else if port != "" {
		u.Host = net.JoinHostPort(host, port)
	} else {
		u.Host = host
		if strings.Contains(host, ":") {
			u.Host = "[" + host + "]"
		}
	}
	u.Fragment = ""
	u.RawFragment = ""
	return u.String()
}

// cloneReport returns a Report whose slice fields share no backing array with
// the original.
func cloneReport(r Report) Report {
	out := r
	out.Requests = append([]StopRequest(nil), r.Requests...)
	out.Entries = append([]Entry(nil), r.Entries...)
	return out
}
