package engine

import (
	"github.com/ffuf/ffuf/v2/pkg/ffuf"
	"github.com/ffuf/ffuf/v2/pkg/heuristics"
)

// DecisionProvider is the engine's view of the multi-dimensional decision
// layer. The concrete implementation lives in pkg/decision; keeping it behind
// an interface here means pkg/engine does not gain a dependency on the
// heuristics plumbing and a nil Decider is the entire "feature disabled"
// switch.
type DecisionProvider interface {
	// EnsureBaseline makes sure a baseline exists for the group urlPath
	// belongs to. Errors are non-fatal: the engine logs them and continues.
	EnsureBaseline(urlPath string) error
	// Evaluate returns the explainable verdict for resp. legacyMatch is the
	// MatcherManager verdict, supplied for the monotonicity guarantee.
	Evaluate(resp *ffuf.Response, legacyMatch bool) heuristics.Verdict
	// Engine exposes the underlying engine for baseline/suppressor
	// persistence into the checkpoint.
	Engine() *heuristics.Engine
}

// CheckpointStore is the engine's view of durable progress.
type CheckpointStore interface {
	IsDone(position int, inputs map[string]string) bool
	Record(e CheckpointEntry)
	Flush() error
	Close() error
	Path() string
	// MatchedEntries returns prior hits so a resumed run can re-surface them
	// without re-requesting.
	MatchedEntries() []CheckpointEntry
	// EntryAtPosition recovers a recorded entry (and its verdict/signature) by
	// wordlist position, for interactive false-positive marking.
	EntryAtPosition(pos int) (CheckpointEntry, bool)
	SaveBaselines(groups map[string]heuristics.BaselineGroup)
	SaveSuppressors(sup []heuristics.Suppressor)
}

// CheckpointEntry mirrors checkpoint.Entry without importing the package.
type CheckpointEntry struct {
	Position  int
	Inputs    map[string]string
	Done      bool
	Matched   bool
	Verdict   *heuristics.Verdict
	Signature CheckpointSignature
	Error     string
}

// CheckpointSignature mirrors checkpoint.Signature.
type CheckpointSignature struct {
	StatusCode    int64
	ContentLength int64
	ContentWords  int64
	ContentLines  int64
	ContentType   string
	DurationMS    int64
	BodyHash      string
	Redirect      string
	URL           string
}

// EvidenceRecorder is the engine's view of the JSONL evidence log.
type EvidenceRecorder interface {
	Write(rec EvidenceRecord) error
	Flush() error
	Close() error
}

// EvidenceRecord mirrors evidence.Record.
type EvidenceRecord struct {
	Position    int
	Inputs      map[string]string
	URL         string
	LegacyMatch bool
	Verdict     *heuristics.Verdict
	Signature   CheckpointSignature
}

// SuppressFalsePositive records a false-positive signature derived from a
// previously reported result. Future responses with the same normalized body
// hash (and status) are suppressed and logged rather than reported. It is a
// no-op when the decision layer is disabled.
func (j *Job) SuppressFalsePositive(bodyHash string, statusCode int64, group, sampleURL, note string) (string, bool) {
	if j.Decider == nil {
		return "", false
	}
	s := j.Decider.Engine().AddSuppressor(heuristics.Suppressor{
		BodyHash:   bodyHash,
		StatusCode: statusCode,
		Group:      group,
		SampleURL:  sampleURL,
		Note:       note,
	})
	if j.Checkpoint != nil {
		j.Checkpoint.SaveSuppressors(j.Decider.Engine().Suppressors())
		_ = j.Checkpoint.Flush()
	}
	return s.ID, true
}
