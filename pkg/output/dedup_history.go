package output

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/ffuf/ffuf/v2/pkg/fingerprint"
)

const dedupHistoryVersion = 1

type dedupHistory struct {
	Version          int                        `json:"version"`
	Algorithm        string                     `json:"algorithm"`
	Target           string                     `json:"target"`
	UpdatedAt        time.Time                  `json:"updated_at"`
	Rounds           []dedupRound               `json:"rounds"`
	FingerprintCache map[string]dedupCacheEntry `json:"fingerprint_cache,omitempty"`
}

type dedupRound struct {
	Round       string                       `json:"round"`
	RulesSHA256 string                       `json:"rules_sha256"`
	Threshold   int                          `json:"threshold"`
	StartedAt   time.Time                    `json:"started_at"`
	Entries     map[string]dedupHistoryEntry `json:"entries"`
}

type dedupHistoryEntry struct {
	URL      string   `json:"url"`
	Status   int64    `json:"status"`
	Length   int64    `json:"length"`
	Redirect string   `json:"redirect,omitempty"`
	Paths    []string `json:"paths,omitempty"`
}

type dedupCacheEntry struct {
	Digest      string `json:"digest"`
	RulesSHA256 string `json:"rules_sha256"`
	Threshold   int    `json:"threshold"`
	Empty       bool   `json:"empty,omitempty"`
	Sampled     bool   `json:"sampled,omitempty"`
}

type historyState int

const (
	historyNew historyState = iota
	historyLoaded
	historyCorrupt
	historyTargetMismatch
)

func loadDedupHistory(path, target string) (*dedupHistory, historyState, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, historyNew, nil
	}
	if err != nil {
		return nil, historyCorrupt, err
	}
	var history dedupHistory
	if err := json.Unmarshal(data, &history); err != nil {
		return nil, historyCorrupt, err
	}
	if history.Version != dedupHistoryVersion {
		return nil, historyCorrupt, fmt.Errorf("unsupported version %d", history.Version)
	}
	if history.Algorithm != fingerprint.Algorithm {
		return nil, historyCorrupt, fmt.Errorf("fingerprint algorithm is %q, want %q", history.Algorithm, fingerprint.Algorithm)
	}
	if history.Target != target {
		return nil, historyTargetMismatch, fmt.Errorf("target is %q, want %q", history.Target, target)
	}
	if err := validateDedupHistory(&history); err != nil {
		return nil, historyCorrupt, err
	}
	return &history, historyLoaded, nil
}

func validateDedupHistory(history *dedupHistory) error {
	for i, round := range history.Rounds {
		if round.Round == "" {
			return fmt.Errorf("round #%d has an empty label", i+1)
		}
		for digest, entry := range round.Entries {
			if digest == "" {
				return fmt.Errorf("round %q has an empty fingerprint key", round.Round)
			}
			if entry.URL == "" {
				return fmt.Errorf("round %q fingerprint %q has an empty URL", round.Round, digest)
			}
		}
	}
	for key, entry := range history.FingerprintCache {
		if entry.Digest == "" {
			return fmt.Errorf("fingerprint cache key %q has an empty digest", key)
		}
	}
	return nil
}

func saveDedupHistory(path string, history *dedupHistory) error {
	history.UpdatedAt = time.Now().UTC()
	for i := range history.Rounds {
		if history.Rounds[i].StartedAt.IsZero() {
			history.Rounds[i].StartedAt = history.UpdatedAt
		}
	}
	data, err := json.Marshal(history)
	if err != nil {
		return err
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".ffuf-dedup-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0640); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmpName, path)
}
