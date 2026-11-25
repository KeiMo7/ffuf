package ffuf

// ResultFromResponse builds a Result from a matched Response. The field mapping
// is the one the stdout output provider used to inline, lifted here so any
// output path can reuse it. The Input map is copied: the Result owns its own
// map and mutating it cannot affect the response.
func ResultFromResponse(resp Response) Result {
	inputs := make(map[string][]byte, len(resp.Request.Input))
	for k, v := range resp.Request.Input {
		inputs[k] = v
	}
	return Result{
		Input:            inputs,
		Position:         resp.Request.Position,
		StatusCode:       resp.StatusCode,
		ContentLength:    resp.ContentLength,
		ContentWords:     resp.ContentWords,
		ContentLines:     resp.ContentLines,
		ContentType:      resp.ContentType,
		RedirectLocation: resp.GetRedirectLocation(false),
		ScraperData:      resp.ScraperData,
		Url:              resp.Request.Url,
		Duration:         resp.Duration,
		ResultFile:       resp.ResultFile,
		Host:             resp.Request.Host,
	}
}
