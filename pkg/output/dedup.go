package output

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/url"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"

	"github.com/ffuf/ffuf/v2/pkg/ffuf"
	"github.com/ffuf/ffuf/v2/pkg/fingerprint"
)

type dedupDecision struct {
	Fold bool
	Info *ffuf.DedupInfo
}

type dedupGroup struct {
	status   int64
	length   int64
	redirect string
	paths    []string
	info     ffuf.DedupInfo
}

func (g *dedupGroup) snapshot() *ffuf.DedupInfo {
	info := g.info
	info.FoldedCount = len(g.paths) - 1
	info.OriginalPaths = append([]string(nil), g.paths...)
	info.EquivalentRounds = append([]string(nil), g.info.EquivalentRounds...)
	return &info
}

type dedupManager struct {
	mu sync.Mutex

	rules      *fingerprint.Rules
	threshold  int
	maxEntries int
	target     string
	round      string

	history         *dedupHistory
	historyPath     string
	historyWritable bool
	warnings        []string
	warningsEmitted bool

	groups map[string]*dedupGroup
	cache  map[string]dedupCacheEntry

	observed    int
	folded      int
	retained    int
	equivalent  int
	cacheHits   int
	unavailable int
	overflow    int
}

func newDedupManager(conf *ffuf.Config) *dedupManager {
	if conf == nil || !conf.Dedup {
		return nil
	}
	rules := conf.DedupRules
	if rules == nil {
		rules = fingerprint.EmptyRules()
	}
	threshold := conf.DedupThreshold
	if threshold <= 0 {
		threshold = fingerprint.DefaultThreshold
	}
	maxEntries := conf.DedupMaxEntries
	if maxEntries <= 0 {
		maxEntries = fingerprint.DefaultMaxEntries
	}
	m := &dedupManager{
		rules:           rules,
		threshold:       threshold,
		maxEntries:      maxEntries,
		target:          dedupTargetKey(conf.Url),
		historyPath:     conf.DedupHistoryFile,
		historyWritable: true,
		groups:          make(map[string]*dedupGroup),
		cache:           make(map[string]dedupCacheEntry),
	}
	if m.historyPath == "" {
		m.historyPath = defaultDedupHistoryPath(m.target)
	}
	history, state, err := loadDedupHistory(m.historyPath, m.target)
	switch state {
	case historyLoaded:
		m.history = history
		if history.FingerprintCache != nil {
			m.cache = history.FingerprintCache
		}
	case historyNew:
	case historyCorrupt:
		m.historyWritable = false
		m.warnings = append(m.warnings, fmt.Sprintf("dedup history %q is unusable (%v); continuing in single-round mode", m.historyPath, err))
	case historyTargetMismatch:
		m.historyWritable = false
		m.warnings = append(m.warnings, fmt.Sprintf("dedup history %q belongs to another target (%v); continuing in single-round mode and leaving the file untouched", m.historyPath, err))
	}
	if conf.DedupRound != "" {
		m.round = conf.DedupRound
	} else {
		m.round = nextDedupRound(m.history)
	}
	return m
}

func dedupTargetKey(raw string) string {
	u, err := url.Parse(raw)
	if err == nil && u.Host != "" {
		return u.Scheme + "://" + u.Host
	}
	return raw
}

func defaultDedupHistoryPath(target string) string {
	sum := sha256.Sum256([]byte(target))
	name := hex.EncodeToString(sum[:])[:16] + ".json"
	return filepath.Join(ffuf.CONFIGDIR, "dedup", name)
}

func nextDedupRound(history *dedupHistory) string {
	if history == nil {
		return "1"
	}
	maxRound := 0
	for _, round := range history.Rounds {
		n, err := strconv.Atoi(round.Round)
		if err == nil && n > maxRound {
			maxRound = n
		}
	}
	if maxRound > 0 {
		return strconv.Itoa(maxRound + 1)
	}
	return strconv.Itoa(len(history.Rounds) + 1)
}

func (m *dedupManager) NewStream() *fingerprint.Stream {
	return fingerprint.NewStream(m.rules, m.threshold)
}

func (m *dedupManager) Lookup(method, requestURL string, status, length int64, redirect string, headers map[string][]string) (fingerprint.Result, bool) {
	key := dedupCacheKey(method, requestURL, status, length, redirect, headers)
	if key == "" {
		return fingerprint.Result{}, false
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	entry, ok := m.cache[key]
	if !ok || entry.RulesSHA256 != m.rules.Hash || entry.Threshold != m.threshold {
		return fingerprint.Result{}, false
	}
	m.cacheHits++
	return fingerprint.Result{
		Valid:   true,
		Empty:   entry.Empty,
		Digest:  entry.Digest,
		Source:  fingerprint.SourceReused,
		Sampled: entry.Sampled,
	}, true
}

func (m *dedupManager) Observe(resp *ffuf.Response, resultURL string) dedupDecision {
	m.mu.Lock()
	defer m.mu.Unlock()

	m.observed++
	info := &ffuf.DedupInfo{
		Round:         m.round,
		OriginalPaths: []string{resultURL},
	}
	fp := resp.Fingerprint
	if resp.BodyReadError != "" {
		fp.Valid = false
		fp.Source = fingerprint.SourceUnavailable
		fp.Error = "response body read failed: " + resp.BodyReadError
	}
	info.Fingerprint = fp.Digest
	info.FingerprintSource = fp.Source
	info.FingerprintValid = fp.Valid
	info.FingerprintEmpty = fp.Empty
	info.Sampled = fp.Sampled
	if !fp.Valid {
		m.unavailable++
		info.UnavailableReason = fp.Error
		if info.UnavailableReason == "" {
			info.UnavailableReason = "fingerprint unavailable"
		}
		return dedupDecision{Info: info}
	}

	if group, ok := m.groups[fp.Digest]; ok {
		group.paths = append(group.paths, resultURL)
		m.folded++
		return dedupDecision{Fold: true}
	}
	if len(m.groups) >= m.maxEntries {
		m.unavailable++
		m.overflow++
		info.UnavailableReason = "fingerprint table capacity reached"
		return dedupDecision{Info: info}
	}

	if rounds := m.equivalentRoundsLocked(fp.Digest); len(rounds) > 0 {
		info.Equivalent = true
		info.EquivalentRounds = rounds
		m.equivalent++
	}

	redirect := resp.GetRedirectLocation(false)
	group := &dedupGroup{
		status:   resp.StatusCode,
		length:   resp.ContentLength,
		redirect: redirect,
		paths:    []string{resultURL},
		info:     *info,
	}
	m.groups[fp.Digest] = group
	m.retained++
	m.storeCacheLocked(resp, fp)
	return dedupDecision{Info: info}
}

func (m *dedupManager) equivalentRoundsLocked(digest string) []string {
	if m.history == nil {
		return nil
	}
	rounds := make([]string, 0)
	for _, round := range m.history.Rounds {
		if round.RulesSHA256 != m.rules.Hash || round.Threshold != m.threshold {
			continue
		}
		if _, ok := round.Entries[digest]; ok {
			rounds = append(rounds, round.Round)
		}
	}
	return rounds
}

func (m *dedupManager) storeCacheLocked(resp *ffuf.Response, fp fingerprint.Result) {
	if resp.Request == nil {
		return
	}
	redirect := resp.GetRedirectLocation(false)
	key := dedupCacheKey(resp.Request.Method, resp.Request.Url, resp.StatusCode, declaredLength(resp.Headers), redirect, resp.Headers)
	if key == "" {
		return
	}
	if _, exists := m.cache[key]; !exists && len(m.cache) >= m.maxEntries {
		return
	}
	m.cache[key] = dedupCacheEntry{
		Digest:      fp.Digest,
		RulesSHA256: m.rules.Hash,
		Threshold:   m.threshold,
		Empty:       fp.Empty,
		Sampled:     fp.Sampled,
	}
}

func declaredLength(headers map[string][]string) int64 {
	if value := headerValue(headers, "Content-Length"); value != "" {
		if n, err := strconv.ParseInt(value, 10, 64); err == nil {
			return n
		}
	}
	return -1
}

func (m *dedupManager) Decorate(results []ffuf.Result) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for i := range results {
		digest := results[i].DedupFingerprint
		if digest == "" {
			continue
		}
		if group, ok := m.groups[digest]; ok {
			results[i].Dedup = group.snapshot()
		}
	}
}

func (m *dedupManager) Warnings() []string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.warningsEmitted {
		return nil
	}
	m.warningsEmitted = true
	return append([]string(nil), m.warnings...)
}

func (m *dedupManager) Finish() string {
	m.mu.Lock()
	defer m.mu.Unlock()

	summary := fmt.Sprintf("De-duplication round %s: %d results, %d retained, %d folded, %d history-equivalent, %d fingerprint reuse hits, %d unavailable (normalized body SHA-256",
		m.round, m.observed, m.retained, m.folded, m.equivalent, m.cacheHits, m.unavailable)
	if m.threshold > 0 {
		summary += fmt.Sprintf(", exact<=%d bytes", m.threshold)
	}
	summary += ")"
	if m.overflow > 0 {
		summary += fmt.Sprintf("; %d results exceeded the fingerprint table limit and were kept independently", m.overflow)
	}

	if !m.historyWritable {
		return summary
	}
	if m.history == nil {
		m.history = &dedupHistory{
			Version:          dedupHistoryVersion,
			Algorithm:        fingerprint.Algorithm,
			Target:           m.target,
			FingerprintCache: make(map[string]dedupCacheEntry),
		}
	}
	round := dedupRound{
		Round:       m.round,
		RulesSHA256: m.rules.Hash,
		Threshold:   m.threshold,
		Entries:     make(map[string]dedupHistoryEntry, len(m.groups)),
	}
	digests := make([]string, 0, len(m.groups))
	for digest := range m.groups {
		digests = append(digests, digest)
	}
	sort.Strings(digests)
	for _, digest := range digests {
		group := m.groups[digest]
		round.Entries[digest] = dedupHistoryEntry{
			URL:      group.paths[0],
			Status:   group.status,
			Length:   group.length,
			Redirect: group.redirect,
			Paths:    append([]string(nil), group.paths...),
		}
	}
	m.history.Rounds = append(m.history.Rounds, round)
	m.history.FingerprintCache = m.cache
	if err := saveDedupHistory(m.historyPath, m.history); err != nil {
		m.warnings = append(m.warnings, fmt.Sprintf("could not write dedup history %q: %v", m.historyPath, err))
	}
	return summary
}

func dedupCacheKey(method, requestURL string, status, length int64, redirect string, headers map[string][]string) string {
	etag := headerValue(headers, "ETag")
	validator := ""
	switch {
	case etag != "" && !strings.HasPrefix(etag, "W/"):
		validator = "etag:" + etag
	case headerValue(headers, "Last-Modified") != "" && length >= 0:
		validator = "last-modified:" + headerValue(headers, "Last-Modified")
	default:
		return ""
	}
	return strings.Join([]string{
		method,
		requestURL,
		strconv.FormatInt(status, 10),
		strconv.FormatInt(length, 10),
		redirect,
		validator,
	}, "\x00")
}

func headerValue(headers map[string][]string, name string) string {
	for key, values := range headers {
		if strings.EqualFold(key, name) && len(values) > 0 {
			return values[0]
		}
	}
	return ""
}
