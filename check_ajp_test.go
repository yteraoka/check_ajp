package main

import (
	"net"
	"testing"
	"time"
)

func TestSanitizeOutput(t *testing.T) {
	tests := []struct {
		in        string
		multiline bool
		want      string
	}{
		{"plain text", false, "plain text"},
		{"日本語", false, "日本語"},
		{"a|b", false, `a\x7cb`},
		{"\x1b[31mred\x1b[0m", false, `\x1b[31mred\x1b[0m`},
		{"line1\nline2\tx", false, `line1\nline2\tx`},
		{"line1\nline2\tx", true, "line1\nline2\tx"},
		{"cr\r\n", true, "cr\\r\n"},
		{"bad\xff", false, `bad\xff`},
		{"rlo\u202e", false, `rlo\u202e`},
	}
	for _, tt := range tests {
		if got := sanitizeOutput(tt.in, tt.multiline); got != tt.want {
			t.Errorf("sanitizeOutput(%q, %v) = %q, want %q", tt.in, tt.multiline, got, tt.want)
		}
	}
}

func TestSecondsToDuration(t *testing.T) {
	tests := map[float64]time.Duration{
		1.0:   time.Second,
		0.5:   500 * time.Millisecond,
		2.5:   2500 * time.Millisecond,
		0.001: time.Millisecond,
		0:     0,
	}
	for in, want := range tests {
		if got := secondsToDuration(in); got != want {
			t.Errorf("secondsToDuration(%v) = %v, want %v", in, got, want)
		}
	}
}

func TestParseHeaderOption(t *testing.T) {
	tests := map[string]RequestHeader{
		"X-Test: abc":   {Name: "X-Test", Value: "abc"},
		"X-Test:abc":    {Name: "X-Test", Value: "abc"},
		"X-Time: 10:20": {Name: "X-Time", Value: "10:20"},
		"X-Empty:":      {Name: "X-Empty", Value: ""},
	}
	for in, want := range tests {
		got, err := parseHeaderOption(in)
		if err != nil {
			t.Errorf("parseHeaderOption(%q): unexpected error: %v", in, err)
			continue
		}
		if *got != want {
			t.Errorf("parseHeaderOption(%q) = %+v, want %+v", in, *got, want)
		}
	}
	for _, in := range []string{"X-Test", "", ": abc", " :abc"} {
		if _, err := parseHeaderOption(in); err == nil {
			t.Errorf("parseHeaderOption(%q): expected error", in)
		}
	}
}

func TestParseAttributeOption(t *testing.T) {
	got, err := parseAttributeOption("route=node1")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Value != "node1" {
		t.Errorf("value = %q", got.Value)
	}
	for _, in := range []string{"route", "", "unknown=x", "req_attribute=foo"} {
		if _, err := parseAttributeOption(in); err == nil {
			t.Errorf("parseAttributeOption(%q): expected error", in)
		}
	}
}

func TestTrimIPv6Brackets(t *testing.T) {
	tests := map[string]string{
		"127.0.0.1":      "127.0.0.1",
		"example.com":    "example.com",
		"::1":            "::1",
		"[::1]":          "::1",
		"[fe80::1%eth0]": "fe80::1%eth0",
	}
	for in, want := range tests {
		if got := trimIPv6Brackets(in); got != want {
			t.Errorf("trimIPv6Brackets(%q) = %q, want %q", in, got, want)
		}
	}
	for in, want := range map[string]string{"::1": "[::1]:8009", "[::1]": "[::1]:8009", "127.0.0.1": "127.0.0.1:8009"} {
		if got := net.JoinHostPort(trimIPv6Brackets(in), "8009"); got != want {
			t.Errorf("address for %q = %q, want %q", in, got, want)
		}
	}
}

func TestLocalIPAddress(t *testing.T) {
	tests := []struct {
		addr net.Addr
		want string
	}{
		{&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 12345}, "127.0.0.1"},
		{&net.TCPAddr{IP: net.ParseIP("::1"), Port: 12345}, "::1"},
		{&net.TCPAddr{IP: net.ParseIP("fe80::1"), Port: 12345, Zone: "eth0"}, "fe80::1"},
		{&net.UDPAddr{IP: net.ParseIP("::1"), Port: 12345}, "::1"},
	}
	for _, tt := range tests {
		if got := localIPAddress(tt.addr); got != tt.want {
			t.Errorf("localIPAddress(%v) = %q, want %q", tt.addr, got, tt.want)
		}
	}
}
