package cmd

import "testing"

func TestCharsetLabel(t *testing.T) {
	tests := map[string]string{
		"alnum":              "alnum",
		"alnum-symbols":      "alnum-symbols",
		"custom:abc123":      "custom",
		"custom:":            "custom",
		"something-unlisted": "other",
	}
	for in, want := range tests {
		if got := charsetLabel(in); got != want {
			t.Errorf("charsetLabel(%q) = %q, want %q", in, got, want)
		}
	}
}
