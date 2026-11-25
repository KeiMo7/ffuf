package ffuf

import (
	"reflect"
	"testing"
)

func TestParseDedupFields(t *testing.T) {
	cases := []struct {
		name    string
		spec    string
		want    []string
		wantErr bool
	}{
		{"default", "url,status,length,words,lines", []string{"url", "status", "length", "words", "lines"}, false},
		{"case insensitive", "URL,Status,LENGTH", []string{"url", "status", "length"}, false},
		{"spaces trimmed", " url , status ", []string{"url", "status"}, false},
		{"empty items ignored", "url,,status,", []string{"url", "status"}, false},
		{"canonical order", "lines,url,status", []string{"url", "status", "lines"}, false},
		{"all fields", "content-type,redirect,lines,words,length,status,url", []string{"url", "status", "length", "words", "lines", "redirect", "content-type"}, false},
		{"missing url", "status,length", nil, true},
		{"unknown field", "url,body", nil, true},
		{"only unknown", "wat", nil, true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := ParseDedupFields(c.spec)
			if c.wantErr {
				if err == nil {
					t.Fatalf("expected error, got %v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if !reflect.DeepEqual(got, c.want) {
				t.Fatalf("got %v, want %v", got, c.want)
			}
		})
	}
}

func TestDefaultDedupFields(t *testing.T) {
	want := []string{"url", "status", "length", "words", "lines"}
	if !reflect.DeepEqual(DefaultDedupFields, want) {
		t.Fatalf("DefaultDedupFields = %v, want %v", DefaultDedupFields, want)
	}
}
