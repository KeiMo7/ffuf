package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"

	"github.com/ffuf/ffuf/v2/pkg/checkpoint"
	"github.com/ffuf/ffuf/v2/pkg/decision"
	"github.com/ffuf/ffuf/v2/pkg/engine"
	"github.com/ffuf/ffuf/v2/pkg/evaluation"
	"github.com/ffuf/ffuf/v2/pkg/evidence"
	"github.com/ffuf/ffuf/v2/pkg/ffuf"
)

// setupIntegrations wires the three optional layers onto the Job:
// multi-dimensional decision, durable checkpoint and evidence log. Every
// layer is individually optional and nil when its flag is absent, so the
// default run is byte-for-byte the legacy behavior.
//
// It returns a cleanup function (flush/close) and a report writer invoked
// after the job finishes; both are no-ops when the corresponding feature is
// disabled.
func setupIntegrations(conf *ffuf.Config, job *engine.Job) (cleanup func(), writeReport func(), err error) {
	cleanup = func() {}
	writeReport = func() {}

	var cpStore *checkpoint.Store
	if conf.CheckpointDir != "" {
		scanID := scanIdentity(conf)
		if conf.Options != nil && conf.Options.Resume.ResetState {
			_ = os.RemoveAll(conf.CheckpointDir)
		}
		store, cerr := checkpoint.CreateOrOpen(
			conf.CheckpointDir, scanID, conf.Url, conf.Wordlists, job.Input.Total(),
		)
		if cerr != nil {
			return cleanup, writeReport, cerr
		}
		cpStore = store
		job.Checkpoint = &decision.CheckpointAdapter{Store: store}
	}

	// Decision layer (needs the production runner + the job's base request).
	if conf.Heuristics.Enabled {
		basereq := ffuf.BaseRequest(conf)
		decider := decision.NewDeciderFromConfig(conf, job.Runner, basereq)

		// Restore heuristic context from a prior run before any requests go out.
		if cpStore != nil {
			st := cpStore.State()
			decider.RestoreFromCheckpoint(st)
		}
		// Layer in the user-maintained false-positive signature file.
		if conf.Heuristics.SuppressorsFile != "" {
			sup, lerr := decision.LoadSuppressorsFile(conf.Heuristics.SuppressorsFile)
			if lerr != nil {
				return cleanup, writeReport, lerr
			}
			decider.Engine().LoadSuppressors(sup)
		}
		// Eager baseline collection unless disabled; failures degrade per group.
		if conf.Heuristics.Prewarm {
			for _, e := range decider.PrewarmBaselines() {
				job.Output.Warning(e.Error())
			}
		}
		job.Decider = decider
	}

	// Evidence log records every request with its verdict (legacy or heuristic).
	var recorder *evidence.Recorder
	if conf.EvidenceLog != "" {
		if dir := dirOf(conf.EvidenceLog); dir != "" {
			_ = os.MkdirAll(dir, 0o750)
		}
		r, eerr := evidence.OpenRecorder(conf.EvidenceLog)
		if eerr != nil {
			return cleanup, writeReport, eerr
		}
		recorder = r
		job.Evidence = &decision.EvidenceAdapter{Recorder: r}
	}

	cleanup = func() {
		if cpStore != nil {
			_ = cpStore.Close()
		}
		if recorder != nil {
			_ = recorder.Close()
		}
	}

	// Evaluation report is best-effort and only meaningful when a ground-truth
	// label set is supplied alongside the evidence log.
	writeReport = func() {
		if conf.ReportFile == "" || conf.EvidenceLog == "" || conf.Heuristics.LabelsFile == "" {
			return
		}
		obs, oerr := evaluation.LoadEvidence(conf.EvidenceLog)
		if oerr != nil {
			job.Output.Warning("evaluation: cannot read evidence log: " + oerr.Error())
			return
		}
		labels, lerr := evaluation.LoadLabels(conf.Heuristics.LabelsFile)
		if lerr != nil {
			job.Output.Warning("evaluation: cannot read labels: " + lerr.Error())
			return
		}
		rep := evaluation.Evaluate(labels, obs)
		if werr := evaluation.WriteReportJSON(conf.ReportFile, rep); werr != nil {
			job.Output.Warning("evaluation: cannot write report: " + werr.Error())
			return
		}
		job.Output.Info("evaluation report written to " + conf.ReportFile)
		fmt.Fprint(os.Stderr, evaluation.RenderText(rep))
	}

	return cleanup, writeReport, nil
}

// scanIdentity hashes the configuration that must stay constant across a
// resume: target, method, wordlists, extensions and input mode. A changed
// configuration yields a different ID and is refused rather than silently
// skipping entries against the wrong target.
func scanIdentity(conf *ffuf.Config) string {
	parts := []string{
		conf.Url,
		conf.Method,
		conf.InputMode,
		strings.Join(conf.Extensions, ","),
		strings.Join(conf.Wordlists, "|"),
	}
	sum := sha256.Sum256([]byte(strings.Join(parts, "\n")))
	return "scan-" + hex.EncodeToString(sum[:10])
}

func dirOf(p string) string {
	for i := len(p) - 1; i >= 0; i-- {
		if p[i] == '/' || p[i] == os.PathSeparator {
			return p[:i]
		}
	}
	return ""
}
