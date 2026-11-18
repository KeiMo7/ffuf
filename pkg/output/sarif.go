package output

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/ffuf/ffuf/v2/pkg/ffuf"
)

const (
	sarifSchemaURI   = "https://json.schemastore.org/sarif-2.1.0.json"
	sarifVersion     = "2.1.0"
	sarifColumnKind  = "unicodeCodePoints"
	sarifWriteBuffer = 64 * 1024
)

const (
	sarifSeverityHigh   = "high"
	sarifSeverityMedium = "medium"
	sarifSeverityHint   = "hint"

	sarifLevelError   = "error"
	sarifLevelWarning = "warning"
	sarifLevelNote    = "note"
)

const (
	sarifRuleSuccess          = "ffuf.http.success"
	sarifRuleRedirect         = "ffuf.http.redirect"
	sarifRuleAccessControlled = "ffuf.http.access-controlled"
	sarifRuleClientError      = "ffuf.http.client-error"
	sarifRuleServerError      = "ffuf.http.server-error"
	sarifRuleResponse         = "ffuf.http.response"
)

// sarifSeverityToLevel is the single severity mapping used for both rule
// metadata and individual results.
var sarifSeverityToLevel = map[string]string{
	sarifSeverityHigh:   sarifLevelError,
	sarifSeverityMedium: sarifLevelWarning,
	sarifSeverityHint:   sarifLevelNote,
}

type sarifRuleDefinition struct {
	ID          string
	Name        string
	Title       string
	Description string
	Severity    string
}

// Rule IDs are deliberately static and independent of scan input. Do not add
// paths, timestamps, hostnames or response data to these identifiers.
var sarifRuleDefinitions = []sarifRuleDefinition{
	{
		ID:          sarifRuleSuccess,
		Name:        "successful-http-response",
		Title:       "Successful HTTP response",
		Description: "The fuzzed request returned a successful 2xx response.",
		Severity:    sarifSeverityMedium,
	},
	{
		ID:          sarifRuleRedirect,
		Name:        "http-redirect",
		Title:       "HTTP redirect",
		Description: "The fuzzed request returned a 3xx redirect response.",
		Severity:    sarifSeverityHint,
	},
	{
		ID:          sarifRuleAccessControlled,
		Name:        "access-controlled-resource",
		Title:       "Access-controlled resource",
		Description: "The fuzzed request returned an authentication or authorization response.",
		Severity:    sarifSeverityHint,
	},
	{
		ID:          sarifRuleClientError,
		Name:        "http-client-error",
		Title:       "HTTP client error",
		Description: "The fuzzed request returned a 4xx client error response.",
		Severity:    sarifSeverityHint,
	},
	{
		ID:          sarifRuleServerError,
		Name:        "http-server-error",
		Title:       "HTTP server error",
		Description: "The fuzzed request returned a 5xx server error response.",
		Severity:    sarifSeverityHigh,
	},
	{
		ID:          sarifRuleResponse,
		Name:        "http-response",
		Title:       "HTTP response",
		Description: "The fuzzed request returned a response outside the standard HTTP status classes.",
		Severity:    sarifSeverityHint,
	},
}

type sarifMessage struct {
	Text string `json:"text"`
}

type sarifConfiguration struct {
	Level string `json:"level"`
}

type sarifReportingDescriptor struct {
	ID                   string              `json:"id"`
	Name                 string              `json:"name,omitempty"`
	ShortDescription     sarifMessage        `json:"shortDescription"`
	FullDescription      sarifMessage        `json:"fullDescription,omitempty"`
	DefaultConfiguration *sarifConfiguration `json:"defaultConfiguration,omitempty"`
	HelpURI              string              `json:"helpUri,omitempty"`
}

type sarifDriver struct {
	Name           string                     `json:"name"`
	InformationURI string                     `json:"informationUri,omitempty"`
	Version        string                     `json:"version,omitempty"`
	Rules          []sarifReportingDescriptor `json:"rules"`
}

type sarifTool struct {
	Driver sarifDriver `json:"driver"`
}

type sarifInvocation struct {
	ExecutionSuccessful bool `json:"executionSuccessful"`
}

type sarifArtifactLocation struct {
	URI string `json:"uri"`
}

type sarifRegion struct {
	StartLine   int `json:"startLine"`
	StartColumn int `json:"startColumn"`
	EndLine     int `json:"endLine"`
	EndColumn   int `json:"endColumn"`
}

type sarifPhysicalLocation struct {
	ArtifactLocation sarifArtifactLocation `json:"artifactLocation"`
	Region           sarifRegion           `json:"region"`
}

type sarifLocation struct {
	PhysicalLocation sarifPhysicalLocation `json:"physicalLocation"`
}

type sarifSource struct {
	Artifact    string `json:"artifact"`
	Keyword     string `json:"keyword"`
	StartLine   int    `json:"startLine"`
	StartColumn int    `json:"startColumn"`
	EndLine     int    `json:"endLine"`
	EndColumn   int    `json:"endColumn"`
	Value       string `json:"value,omitempty"`
}

type sarifResult struct {
	RuleID     string                 `json:"ruleId"`
	RuleIndex  int                    `json:"ruleIndex"`
	Level      string                 `json:"level"`
	Message    sarifMessage           `json:"message"`
	Locations  []sarifLocation        `json:"locations"`
	Properties map[string]interface{} `json:"properties,omitempty"`
}

type sarifFinding struct {
	RuleID  string
	Level   string
	URL     string
	Status  int64
	Inputs  map[string]map[string]struct{}
	Sources map[string]sarifSource
}

type sarifDictionaryLine struct {
	Line      int
	Column    int
	EndColumn int
}

type sarifSourceProvider struct {
	Artifact string
	Keyword  string
	Path     string
	Wordlist bool
	Fallback bool
	Lines    map[string][]sarifDictionaryLine
}

type sarifSourceIndex struct {
	Providers []sarifSourceProvider
	ByKeyword map[string][]int
}

type sarifWriteOptions struct {
	Repository          string
	ExecutionSuccessful bool
}

func sarifRuleIndex(ruleID string) int {
	for i, rule := range sarifRuleDefinitions {
		if rule.ID == ruleID {
			return i
		}
	}
	return -1
}

func sarifRuleIDForStatus(status int64) string {
	switch {
	case status >= 500 && status <= 599:
		return sarifRuleServerError
	case status == 401 || status == 403 || status == 405 || status == 407:
		return sarifRuleAccessControlled
	case status >= 400 && status <= 499:
		return sarifRuleClientError
	case status >= 300 && status <= 399:
		return sarifRuleRedirect
	case status >= 200 && status <= 299:
		return sarifRuleSuccess
	default:
		return sarifRuleResponse
	}
}

func sarifRuleDescriptors() []sarifReportingDescriptor {
	rules := make([]sarifReportingDescriptor, 0, len(sarifRuleDefinitions))
	for _, definition := range sarifRuleDefinitions {
		rules = append(rules, sarifReportingDescriptor{
			ID:               definition.ID,
			Name:             definition.Name,
			ShortDescription: sarifMessage{Text: definition.Title},
			FullDescription:  sarifMessage{Text: definition.Description},
			DefaultConfiguration: &sarifConfiguration{
				Level: sarifSeverityToLevel[definition.Severity],
			},
			HelpURI: "https://github.com/ffuf/ffuf",
		})
	}
	return rules
}

// writeSARIF writes a successful scan. It is separate from the status-aware
// variant so callers that already have a result set keep the same three-argument
// writer shape as the other output formats.
func writeSARIF(filename string, config *ffuf.Config, results []ffuf.Result) error {
	return writeSARIFWithStatus(filename, config, results, true)
}

func writeSARIFWithStatus(filename string, config *ffuf.Config, results []ffuf.Result, executionSuccessful bool) error {
	repository, err := sarifRepositoryRoot()
	if err != nil {
		return err
	}
	return writeSARIFWithOptions(filename, config, results, sarifWriteOptions{
		Repository:          repository,
		ExecutionSuccessful: executionSuccessful,
	})
}

func writeSARIFWithOptions(filename string, config *ffuf.Config, results []ffuf.Result, options sarifWriteOptions) error {
	if options.Repository == "" {
		repository, err := sarifRepositoryRoot()
		if err != nil {
			return err
		}
		options.Repository = repository
	}
	findings, err := buildSARIFResults(config, results, options.Repository)
	if err != nil {
		return err
	}

	return writeAtomic(filename, 0644, func(w io.Writer) error {
		return writeSARIFStream(w, findings, options.ExecutionSuccessful)
	})
}

func writeSARIFStream(w io.Writer, findings []sarifResult, executionSuccessful bool) error {
	write := func(value string) error {
		_, err := io.WriteString(w, value)
		return err
	}
	writeJSON := func(value interface{}) error {
		encoded, err := json.Marshal(value)
		if err != nil {
			return err
		}
		_, err = w.Write(encoded)
		return err
	}

	if err := write(`{"version":`); err != nil {
		return err
	}
	if err := writeJSON(sarifVersion); err != nil {
		return err
	}
	if err := write(`,"$schema":`); err != nil {
		return err
	}
	if err := writeJSON(sarifSchemaURI); err != nil {
		return err
	}
	if err := write(`,"runs":[{"tool":`); err != nil {
		return err
	}
	tool := sarifTool{Driver: sarifDriver{
		Name:           "ffuf",
		InformationURI: "https://github.com/ffuf/ffuf",
		Version:        ffuf.Version(),
		Rules:          sarifRuleDescriptors(),
	}}
	if err := writeJSON(tool); err != nil {
		return err
	}
	if err := write(`,"invocations":[`); err != nil {
		return err
	}
	if err := writeJSON(sarifInvocation{ExecutionSuccessful: executionSuccessful}); err != nil {
		return err
	}
	if err := write(`],"results":[`); err != nil {
		return err
	}

	for i := range findings {
		if err := validateSARIFResult(findings[i], i); err != nil {
			return err
		}
		if i > 0 {
			if err := write(","); err != nil {
				return err
			}
		}
		if err := writeJSON(findings[i]); err != nil {
			return err
		}
	}

	return write(`],"columnKind":` + strconv.Quote(sarifColumnKind) + `}]}`)
}

func buildSARIFResults(config *ffuf.Config, results []ffuf.Result, repository string) ([]sarifResult, error) {
	index := newSARIFSourceIndex(config, results, repository)
	findings := make(map[string]*sarifFinding)

	for _, result := range results {
		ruleID := sarifRuleIDForStatus(result.StatusCode)
		ruleIndex := sarifRuleIndex(ruleID)
		if ruleIndex < 0 {
			return nil, fmt.Errorf("SARIF validation failed at runs[0].results: unknown rule %q", ruleID)
		}
		key := ruleID + "\x00" + result.Url
		finding, exists := findings[key]
		if !exists {
			finding = &sarifFinding{
				RuleID:  ruleID,
				Level:   sarifSeverityToLevel[sarifRuleDefinitions[ruleIndex].Severity],
				URL:     result.Url,
				Status:  result.StatusCode,
				Inputs:  make(map[string]map[string]struct{}),
				Sources: make(map[string]sarifSource),
			}
			findings[key] = finding
		}

		for keyword, value := range result.Input {
			if keyword == "FFUFHASH" {
				continue
			}
			if finding.Inputs[keyword] == nil {
				finding.Inputs[keyword] = make(map[string]struct{})
			}
			finding.Inputs[keyword][string(value)] = struct{}{}
		}
		for _, source := range index.sourcesFor(result) {
			sourceKey := source.Artifact + "\x00" + source.Keyword + "\x00" +
				strconv.Itoa(source.StartLine) + "\x00" + strconv.Itoa(source.StartColumn) + "\x00" + source.Value
			finding.Sources[sourceKey] = source
		}
	}

	keys := make([]string, 0, len(findings))
	for key := range findings {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	out := make([]sarifResult, 0, len(keys))
	for _, key := range keys {
		finding := findings[key]
		sources := make([]sarifSource, 0, len(finding.Sources))
		sourceKeys := make([]string, 0, len(finding.Sources))
		for sourceKey := range finding.Sources {
			sourceKeys = append(sourceKeys, sourceKey)
		}
		sort.Strings(sourceKeys)
		for _, sourceKey := range sourceKeys {
			sources = append(sources, finding.Sources[sourceKey])
		}
		if len(sources) == 0 {
			sources = append(sources, sarifVirtualSource("input", "", maxInt(1, 1), nil))
		}

		inputs := make(map[string][]string, len(finding.Inputs))
		inputKeys := make([]string, 0, len(finding.Inputs))
		for keyword := range finding.Inputs {
			inputKeys = append(inputKeys, keyword)
		}
		sort.Strings(inputKeys)
		for _, keyword := range inputKeys {
			values := make([]string, 0, len(finding.Inputs[keyword]))
			for value := range finding.Inputs[keyword] {
				values = append(values, value)
			}
			sort.Strings(values)
			inputs[keyword] = values
		}

		primary := sources[0]
		out = append(out, sarifResult{
			RuleID:    finding.RuleID,
			RuleIndex: sarifRuleIndex(finding.RuleID),
			Level:     finding.Level,
			Message:   sarifMessage{Text: sarifFindingMessage(finding, inputs)},
			Locations: []sarifLocation{{
				PhysicalLocation: sarifPhysicalLocation{
					ArtifactLocation: sarifArtifactLocation{URI: primary.Artifact},
					Region: sarifRegion{
						StartLine:   primary.StartLine,
						StartColumn: primary.StartColumn,
						EndLine:     primary.EndLine,
						EndColumn:   primary.EndColumn,
					},
				},
			}},
			Properties: map[string]interface{}{
				"url":     finding.URL,
				"status":  finding.Status,
				"inputs":  inputs,
				"sources": sources,
			},
		})
	}
	return out, nil
}

func sarifFindingMessage(finding *sarifFinding, inputs map[string][]string) string {
	message := fmt.Sprintf("ffuf discovered HTTP %d response at %s", finding.Status, finding.URL)
	if len(inputs) == 0 {
		return message
	}
	keywords := make([]string, 0, len(inputs))
	for keyword := range inputs {
		keywords = append(keywords, keyword)
	}
	sort.Strings(keywords)
	parts := make([]string, 0, len(keywords))
	for _, keyword := range keywords {
		parts = append(parts, keyword+"="+strings.Join(inputs[keyword], ","))
	}
	return message + " (input: " + strings.Join(parts, "; ") + ")"
}

func validateSARIFResult(result sarifResult, index int) error {
	resultPath := fmt.Sprintf("runs[0].results[%d]", index)
	if result.RuleID == "" {
		return fmt.Errorf("SARIF validation failed at %s.ruleId: must not be empty", resultPath)
	}
	if result.RuleIndex < 0 || result.RuleIndex >= len(sarifRuleDefinitions) {
		return fmt.Errorf("SARIF validation failed at %s.ruleIndex: %d is outside rules", resultPath, result.RuleIndex)
	}
	if sarifRuleDefinitions[result.RuleIndex].ID != result.RuleID {
		return fmt.Errorf("SARIF validation failed at %s.ruleId: %q does not match ruleIndex %d", resultPath, result.RuleID, result.RuleIndex)
	}
	if result.Level != sarifLevelError && result.Level != sarifLevelWarning && result.Level != sarifLevelNote {
		return fmt.Errorf("SARIF validation failed at %s.level: unsupported level %q", resultPath, result.Level)
	}
	if result.Message.Text == "" {
		return fmt.Errorf("SARIF validation failed at %s.message.text: must not be empty", resultPath)
	}
	if len(result.Locations) == 0 {
		return fmt.Errorf("SARIF validation failed at %s.locations: must contain at least one location", resultPath)
	}
	for locationIndex, location := range result.Locations {
		locationPath := fmt.Sprintf("%s.locations[%d].physicalLocation", resultPath, locationIndex)
		uri := location.PhysicalLocation.ArtifactLocation.URI
		if uri == "" {
			return fmt.Errorf("SARIF validation failed at %s.artifactLocation.uri: must not be empty", locationPath)
		}
		if filepath.IsAbs(uri) || strings.HasPrefix(uri, "/") || strings.HasPrefix(uri, `\`) ||
			filepath.VolumeName(uri) != "" || strings.HasPrefix(strings.ToLower(uri), "file:") {
			return fmt.Errorf("SARIF validation failed at %s.artifactLocation.uri: absolute or file URI %q is not allowed", locationPath, uri)
		}
		if _, err := url.Parse(uri); err != nil {
			return fmt.Errorf("SARIF validation failed at %s.artifactLocation.uri: %s", locationPath, err)
		}
		region := location.PhysicalLocation.Region
		if region.StartLine < 1 {
			return fmt.Errorf("SARIF validation failed at %s.region.startLine: must be >= 1", locationPath)
		}
		if region.StartColumn < 1 {
			return fmt.Errorf("SARIF validation failed at %s.region.startColumn: must be >= 1", locationPath)
		}
		if region.EndLine < region.StartLine {
			return fmt.Errorf("SARIF validation failed at %s.region.endLine: must be >= startLine", locationPath)
		}
		if region.EndColumn < 1 {
			return fmt.Errorf("SARIF validation failed at %s.region.endColumn: must be >= 1", locationPath)
		}
		if region.EndLine == region.StartLine && region.EndColumn < region.StartColumn {
			return fmt.Errorf("SARIF validation failed at %s.region.endColumn: must be >= startColumn", locationPath)
		}
	}
	return nil
}

func newSARIFSourceIndex(config *ffuf.Config, results []ffuf.Result, repository string) *sarifSourceIndex {
	index := &sarifSourceIndex{
		Providers: make([]sarifSourceProvider, 0),
		ByKeyword: make(map[string][]int),
	}
	wanted := make(map[string]map[string]struct{})
	for _, result := range results {
		for keyword, value := range result.Input {
			if keyword == "FFUFHASH" {
				continue
			}
			if wanted[keyword] == nil {
				wanted[keyword] = make(map[string]struct{})
			}
			wanted[keyword][string(value)] = struct{}{}
		}
	}

	if config != nil {
		for i, provider := range config.InputProviders {
			sourceProvider := sarifSourceProvider{
				Artifact: sarifProviderArtifact(provider.Value, repository, i, provider.Keyword),
				Keyword:  provider.Keyword,
				Path:     provider.Value,
				Wordlist: (provider.Name == "" || provider.Name == "wordlist") && provider.Value != "" && provider.Value != "-",
				Lines:    make(map[string][]sarifDictionaryLine),
			}
			sourceProvider.Fallback = provider.Encoders != "" || !sourceProvider.Wordlist
			if sourceProvider.Wordlist {
				if !loadSARIFWordlist(&sourceProvider, wanted[provider.Keyword]) {
					sourceProvider.Fallback = true
				}
			}
			index.Providers = append(index.Providers, sourceProvider)
			index.ByKeyword[provider.Keyword] = append(index.ByKeyword[provider.Keyword], len(index.Providers)-1)
		}
	}
	return index
}

func (index *sarifSourceIndex) sourcesFor(result ffuf.Result) []sarifSource {
	sources := make([]sarifSource, 0)
	keywords := make([]string, 0, len(result.Input))
	for keyword := range result.Input {
		if keyword != "FFUFHASH" {
			keywords = append(keywords, keyword)
		}
	}
	sort.Strings(keywords)

	for _, keyword := range keywords {
		value := string(result.Input[keyword])
		providers := index.ByKeyword[keyword]
		if len(providers) == 0 {
			line := maxInt(1, result.Position)
			sources = append(sources, sarifVirtualSource(keyword, value, line, nil))
			continue
		}
		for _, providerIndex := range providers {
			provider := &index.Providers[providerIndex]
			lines := provider.Lines[value]
			if len(lines) == 0 {
				if !provider.Fallback {
					continue
				}
				line := 1
				if len(providers) == 1 && result.Position > 0 {
					line = result.Position
				}
				sources = append(sources, sarifVirtualSource(keyword, value, line, &provider.Artifact))
				continue
			}
			chosen := lines[0]
			for _, candidate := range lines {
				if candidate.Line == result.Position {
					chosen = candidate
					break
				}
			}
			sources = append(sources, sarifSource{
				Artifact:    provider.Artifact,
				Keyword:     keyword,
				StartLine:   chosen.Line,
				StartColumn: chosen.Column,
				EndLine:     chosen.Line,
				EndColumn:   chosen.EndColumn,
				Value:       value,
			})
		}
	}
	return sources
}

func sarifVirtualSource(keyword, value string, line int, artifact *string) sarifSource {
	uri := sarifEncodeURI("ffuf-input/" + sanitizeSARIFName(keyword) + ".txt")
	if artifact != nil && *artifact != "" {
		uri = *artifact
	}
	column := sarifColumnAfter(value)
	return sarifSource{
		Artifact:    uri,
		Keyword:     keyword,
		StartLine:   maxInt(1, line),
		StartColumn: 1,
		EndLine:     maxInt(1, line),
		EndColumn:   column,
		Value:       value,
	}
}

func loadSARIFWordlist(provider *sarifSourceProvider, wanted map[string]struct{}) bool {
	if len(wanted) == 0 {
		return true
	}
	file, err := os.Open(provider.Path)
	if err != nil {
		return false
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(nil, 512*1024)
	lineNumber := 0
	for scanner.Scan() {
		lineNumber++
		value := scanner.Text()
		if _, ok := wanted[value]; !ok {
			continue
		}
		provider.Lines[value] = append(provider.Lines[value], sarifDictionaryLine{
			Line:      lineNumber,
			Column:    1,
			EndColumn: sarifColumnAfter(value),
		})
	}
	return scanner.Err() == nil
}

func sarifProviderArtifact(path, repository string, providerIndex int, keyword string) string {
	if path != "" && path != "-" {
		absolutePath, err := filepath.Abs(path)
		if err == nil {
			if evaluated, evalErr := filepath.EvalSymlinks(absolutePath); evalErr == nil {
				absolutePath = evaluated
			}
			if repositoryPath, err := filepath.Abs(repository); err == nil {
				if evaluated, evalErr := filepath.EvalSymlinks(repositoryPath); evalErr == nil {
					repositoryPath = evaluated
				}
				if relative, relErr := filepath.Rel(repositoryPath, absolutePath); relErr == nil &&
					relative != "." && !filepath.IsAbs(relative) && relative != ".." &&
					!strings.HasPrefix(relative, ".."+string(filepath.Separator)) {
					return sarifEncodeURI(filepath.ToSlash(relative))
				}
			}
		}
	}
	return sarifEncodeURI(fmt.Sprintf("wordlists/input-%d-%s.txt", providerIndex+1, sanitizeSARIFName(keyword)))
}

func sarifRepositoryRoot() (string, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("could not resolve SARIF repository root: %w", err)
	}
	current := cwd
	for {
		if _, err := os.Stat(filepath.Join(current, ".git")); err == nil {
			return current, nil
		}
		parent := filepath.Dir(current)
		if parent == current {
			return cwd, nil
		}
		current = parent
	}
}

func sarifEncodeURI(path string) string {
	if path == "" {
		return "ffuf-input/input.txt"
	}
	return (&url.URL{Path: path}).EscapedPath()
}

func sanitizeSARIFName(name string) string {
	if name == "" {
		return "input"
	}
	var builder strings.Builder
	for _, char := range name {
		switch {
		case char >= 'a' && char <= 'z', char >= 'A' && char <= 'Z', char >= '0' && char <= '9',
			char == '-', char == '_', char == '.':
			builder.WriteRune(char)
		default:
			builder.WriteByte('_')
		}
		if builder.Len() >= 64 {
			break
		}
	}
	if builder.Len() == 0 {
		return "input"
	}
	return builder.String()
}

func sarifColumnAfter(value string) int {
	if value == "" {
		return 1
	}
	column := 1
	if utf8.ValidString(value) {
		column += len(utf16.Encode([]rune(value)))
	} else {
		column += len(value)
	}
	return column
}

func writeAtomic(filename string, mode os.FileMode, write func(io.Writer) error) (err error) {
	directory := filepath.Dir(filename)
	if directory == "" {
		directory = "."
	}
	temp, err := os.CreateTemp(directory, "."+filepath.Base(filename)+".tmp-*")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	renamed := false
	defer func() {
		_ = temp.Close()
		if !renamed {
			_ = os.Remove(tempName)
		}
	}()

	buffered := bufio.NewWriterSize(temp, sarifWriteBuffer)
	if err := write(buffered); err != nil {
		return err
	}
	if err := buffered.Flush(); err != nil {
		return err
	}
	if err := temp.Chmod(mode); err != nil {
		return err
	}
	if err := temp.Sync(); err != nil {
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tempName, filename); err != nil {
		return err
	}
	renamed = true
	return nil
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
