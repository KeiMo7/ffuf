package engine

import (
	"time"

	"github.com/ffuf/ffuf/v2/pkg/ffuf"
	"github.com/ffuf/ffuf/v2/pkg/verdict"
)

// verdictHarness bundles the attributed-decision components a Job needs when an
// ordered rule set is active. It is nil entirely when the user did not supply
// one, which keeps the legacy path allocation-free.
type verdictHarness struct {
	book      *verdict.RuleBook
	evaluator *verdict.Evaluator
	review    *verdict.ReviewStore
}

// ruleBook returns the configured RuleBook, or nil when verdict mode is off.
// The value is stored on Config as an interface to avoid an import cycle from
// pkg/ffuf down to pkg/verdict.
func ruleBook(conf *ffuf.Config) *verdict.RuleBook {
	if conf == nil || conf.RuleBook == nil {
		return nil
	}
	book, _ := conf.RuleBook.(*verdict.RuleBook)
	return book
}

// reviewStore returns the configured ReviewStore, or nil when review is off.
func reviewStore(conf *ffuf.Config) *verdict.ReviewStore {
	if conf == nil || conf.ReviewStore == nil {
		return nil
	}
	store, _ := conf.ReviewStore.(*verdict.ReviewStore)
	return store
}

// newVerdictHarness wires the harness from Config. It returns nil when no rule
// set was loaded, so callers can branch once and keep the hot path flat.
func newVerdictHarness(conf *ffuf.Config) *verdictHarness {
	book := ruleBook(conf)
	if book == nil {
		return nil
	}
	ev := verdict.NewEvaluator()
	if conf.RuleEvalTimeoutMS > 0 {
		ev.Timeout = time.Duration(conf.RuleEvalTimeoutMS) * time.Millisecond
	}
	return &verdictHarness{
		book:      book,
		evaluator: ev,
		review:    reviewStore(conf),
	}
}

// ReviewStore exposes the configured store (nil when review is off) so the
// engine can read its stats and close its sink at finalize time.
func (h *verdictHarness) ReviewStore() *verdict.ReviewStore {
	if h == nil {
		return nil
	}
	return h.review
}

// RuleBook exposes the configured book (nil when verdict mode is off).
func (h *verdictHarness) RuleBook() *verdict.RuleBook {
	if h == nil {
		return nil
	}
	return h.book
}
