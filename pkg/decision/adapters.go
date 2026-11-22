package decision

import (
	"github.com/ffuf/ffuf/v2/pkg/checkpoint"
	"github.com/ffuf/ffuf/v2/pkg/engine"
	"github.com/ffuf/ffuf/v2/pkg/evidence"
	"github.com/ffuf/ffuf/v2/pkg/heuristics"
)

// CheckpointAdapter bridges checkpoint.Store to engine.CheckpointStore.
type CheckpointAdapter struct {
	Store *checkpoint.Store
}

var _ engine.CheckpointStore = (*CheckpointAdapter)(nil)

func (a *CheckpointAdapter) IsDone(position int, inputs map[string]string) bool {
	return a.Store.IsDone(position, inputs)
}

func (a *CheckpointAdapter) Record(e engine.CheckpointEntry) {
	a.Store.Record(checkpoint.Entry{
		Position:          e.Position,
		Inputs:            e.Inputs,
		Done:              e.Done,
		Matched:           e.Matched,
		Verdict:           e.Verdict,
		ResponseSignature: sigToCheckpoint(e.Signature),
		Error:             e.Error,
	})
}

func (a *CheckpointAdapter) Flush() error { return a.Store.Flush() }
func (a *CheckpointAdapter) Close() error { return a.Store.Close() }
func (a *CheckpointAdapter) Path() string { return a.Store.Path() }

func (a *CheckpointAdapter) MatchedEntries() []engine.CheckpointEntry {
	stored := a.Store.MatchedEntries()
	out := make([]engine.CheckpointEntry, 0, len(stored))
	for _, e := range stored {
		out = append(out, engine.CheckpointEntry{
			Position:  e.Position,
			Inputs:    e.Inputs,
			Done:      e.Done,
			Matched:   e.Matched,
			Verdict:   e.Verdict,
			Signature: sigFromCheckpoint(e.ResponseSignature),
			Error:     e.Error,
		})
	}
	return out
}

func (a *CheckpointAdapter) SaveBaselines(groups map[string]heuristics.BaselineGroup) {
	a.Store.SaveBaselines(groups)
}

func (a *CheckpointAdapter) SaveSuppressors(sup []heuristics.Suppressor) {
	a.Store.SaveSuppressors(sup)
}

func (a *CheckpointAdapter) EntryAtPosition(pos int) (engine.CheckpointEntry, bool) {
	e, ok := a.Store.EntryAtPosition(pos)
	if !ok {
		return engine.CheckpointEntry{}, false
	}
	return engine.CheckpointEntry{
		Position:  e.Position,
		Inputs:    e.Inputs,
		Done:      e.Done,
		Matched:   e.Matched,
		Verdict:   e.Verdict,
		Signature: sigFromCheckpoint(e.ResponseSignature),
		Error:     e.Error,
	}, true
}

// EvidenceAdapter bridges evidence.Recorder to engine.EvidenceRecorder.
type EvidenceAdapter struct {
	Recorder *evidence.Recorder
}

var _ engine.EvidenceRecorder = (*EvidenceAdapter)(nil)

func (a *EvidenceAdapter) Write(rec engine.EvidenceRecord) error {
	return a.Recorder.Write(evidence.Record{
		Position:  rec.Position,
		Inputs:    rec.Inputs,
		URL:       rec.URL,
		Legacy:    rec.LegacyMatch,
		Verdict:   rec.Verdict,
		Signature: sigToEvidence(rec.Signature),
	})
}

func (a *EvidenceAdapter) Flush() error { return a.Recorder.Flush() }
func (a *EvidenceAdapter) Close() error { return a.Recorder.Close() }

// --- signature converters (the three packages intentionally keep their own
// signature types so none imports the others at the data level) -------------

func sigToCheckpoint(s engine.CheckpointSignature) checkpoint.Signature {
	return checkpoint.Signature{
		StatusCode:    s.StatusCode,
		ContentLength: s.ContentLength,
		ContentWords:  s.ContentWords,
		ContentLines:  s.ContentLines,
		ContentType:   s.ContentType,
		DurationMS:    s.DurationMS,
		BodyHash:      s.BodyHash,
		Redirect:      s.Redirect,
		URL:           s.URL,
	}
}

func sigFromCheckpoint(s checkpoint.Signature) engine.CheckpointSignature {
	return engine.CheckpointSignature{
		StatusCode:    s.StatusCode,
		ContentLength: s.ContentLength,
		ContentWords:  s.ContentWords,
		ContentLines:  s.ContentLines,
		ContentType:   s.ContentType,
		DurationMS:    s.DurationMS,
		BodyHash:      s.BodyHash,
		Redirect:      s.Redirect,
		URL:           s.URL,
	}
}

func sigToEvidence(s engine.CheckpointSignature) evidence.Signature {
	return evidence.Signature{
		StatusCode:    s.StatusCode,
		ContentLength: s.ContentLength,
		ContentWords:  s.ContentWords,
		ContentLines:  s.ContentLines,
		ContentType:   s.ContentType,
		DurationMS:    s.DurationMS,
		BodyHash:      s.BodyHash,
		Redirect:      s.Redirect,
	}
}
