// Package assembly wires a ffuf.Job together from a Config: the input provider,
// runner(s), output provider, audit logger, and scraper. It exists as its own
// package because it must import the provider packages (input/runner/output/
// scraper), which themselves import pkg/ffuf - so this composition cannot live in
// pkg/ffuf without an import cycle, and it cannot stay unexported in package main
// without being untestable. Both main and the integration tests call BuildJob, so
// the production and test wiring can never drift.
package assembly

import (
	"github.com/ffuf/ffuf/v2/pkg/engine"
	"github.com/ffuf/ffuf/v2/pkg/ffuf"
	"github.com/ffuf/ffuf/v2/pkg/input"
	"github.com/ffuf/ffuf/v2/pkg/output"
	"github.com/ffuf/ffuf/v2/pkg/runner"
	"github.com/ffuf/ffuf/v2/pkg/scraper"
	"github.com/ffuf/ffuf/v2/pkg/verdict"
)

// BuildJob constructs and wires a Job from conf. It is the single source of truth
// for how a Job is assembled. Matchers/filters are NOT installed here (they need
// the CLI flag state); see filter.FromConfig and main.SetupFilters.
func BuildJob(conf *ffuf.Config) (*engine.Job, error) {
	var err error
	job := engine.NewJob(conf)
	var errs ffuf.Multierror

	// Optional attributed rule set. A load failure is a hard startup error; the
	// loader accumulates every rule problem and reports them in one pass. This
	// is fully specified by the Config (unlike the CLI-defaulted matchers), so it
	// can live in the shared assembly path and be exercised by integration tests.
	if conf.Options != nil && conf.Options.Output.RuleSet != "" {
		book, loadErr := verdict.LoadRuleFile(conf.Options.Output.RuleSet)
		if loadErr != nil {
			errs.Add(loadErr)
		} else {
			conf.RuleBook = book
			if conf.ReviewEnabled {
				capacity := conf.ReviewCapacity
				if capacity < 1 {
					capacity = 1000
				}
				conf.ReviewStore = verdict.NewReviewStore(capacity, conf.ReviewFile)
			}
			// NewJob ran before the book/store were assigned, so (re)build the
			// harness once the Config carries them.
			job.RefreshVerdict()
		}
	}

	// Input errors go into their own Multierror. Assigning NewInputProvider's
	// second return straight back into errs would replace the rule-set errors
	// accumulated above and silently swallow them.
	var inputErrs ffuf.Multierror
	job.Input, inputErrs = input.NewInputProvider(conf)
	if inputErrs.ErrorOrNil() != nil {
		errs.Add(inputErrs.ErrorOrNil())
	}

	// Only the http (SimpleRunner) runner exists today.
	job.Runner = runner.NewSimpleRunner(conf, false)
	if len(conf.ReplayProxyURL) > 0 {
		job.ReplayRunner = runner.NewSimpleRunner(conf, true)
	}

	// Only the stdout output provider exists today.
	job.Output = output.NewStdoutput(conf)

	if len(conf.AuditLog) > 0 {
		job.AuditLogger, err = output.NewAuditLogger(conf.AuditLog)
		if err != nil {
			errs.Add(err)
		} else {
			if err = job.AuditLogger.Write(conf); err != nil {
				errs.Add(err)
			}
		}
	}

	newscraper, scraperErr := scraper.FromDir(ffuf.SCRAPERDIR, conf.Scrapers)
	if scraperErr.ErrorOrNil() != nil {
		errs.Add(scraperErr.ErrorOrNil())
	}
	job.Scraper = newscraper
	if conf.ScraperFile != "" {
		if err = job.Scraper.AppendFromFile(conf.ScraperFile); err != nil {
			errs.Add(err)
		}
	}

	return job, errs.ErrorOrNil()
}
