package main

import (
	"bytes"
	"testing"
)

func packet(payload ...byte) []byte {
	return append([]byte{'A', 'B', byte(len(payload) >> 8), byte(len(payload))}, payload...)
}

func concat(packets ...[]byte) []byte {
	var b []byte
	for _, p := range packets {
		b = append(b, p...)
	}
	return b
}

func TestReadResponse(t *testing.T) {
	data := concat(
		packet(
			4,      // SEND_HEADERS
			0, 200, // status
			0, 2, 'O', 'K', 0, // status message
			0, 2, // num headers
			0xA0, 0x01, 0, 10, 't', 'e', 'x', 't', '/', 'p', 'l', 'a', 'i', 'n', 0,
			0, 3, 'X', '-', 'A', 0, 0xFF, 0xFF, // null string value
		),
		packet(3, 0, 2, 'h', 'i', 0), // SEND_BODY_CHUNK with trailing 0x00
		packet(9),                    // unknown for response, skipped
		packet(3, 0, 1, '!', 0),
		packet(5, 1), // END_RESPONSE
	)
	res, err := readResponse(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if res.StatusCode != 200 || res.StatusMessage != "OK" {
		t.Errorf("status = %d %q", res.StatusCode, res.StatusMessage)
	}
	if got := res.header("Content-Type"); len(got) != 1 || got[0] != "text/plain" {
		t.Errorf("content-type = %v", got)
	}
	if got := res.header("x-a"); len(got) != 1 || got[0] != "" {
		t.Errorf("x-a = %v", got)
	}
	if string(res.Body) != "hi!" {
		t.Errorf("body = %q", res.Body)
	}
}

func TestReadResponseMalformed(t *testing.T) {
	tests := []struct {
		name string
		data []byte
	}{
		{"body chunk longer than packet", []byte{'A', 'B', 0, 3, 3, 0, 2, 'x', 'y'}},
		{"end response without reuse", []byte{'A', 'B', 0, 1, 5, 1, 0, 0, 0}},
		{"get body chunk", []byte{'A', 'B', 0, 3, 6, 0x1f, 0xfa}},
		{"empty packet", []byte{'A', 'B', 0, 0}},
		{"truncated payload", []byte{'A', 'B', 0, 5, 3, 0, 2}},
		{"unknown direction", []byte{'X', 'Y', 0, 2, 5, 1}},
		{"no end response", packet(3, 0, 1, 'x', 0)},
		{"headers longer than packet", packet(4, 0, 200, 0, 2, 'O', 'K', 0, 0, 1)},
		{"unterminated string", packet(4, 0, 200, 0, 2, 'O', 'K', 'X', 0, 0)},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := readResponse(bytes.NewReader(tt.data)); err == nil {
				t.Errorf("expected error")
			}
		})
	}
}

func TestReadResponseKeepsPacketBoundary(t *testing.T) {
	// unknown packet type 7 whose payload starts with "AB" must be skipped as a whole
	data := concat(
		packet(7, 1, 2, 'A', 'B', 0, 2, 5, 1),
		packet(3, 0, 2, 'o', 'k', 0),
		packet(5, 1),
	)
	res, err := readResponse(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(res.Body) != "ok" {
		t.Errorf("body = %q", res.Body)
	}
}

func TestReadResponseDateHeader(t *testing.T) {
	data := concat(
		packet(4, 0, 200, 0, 2, 'O', 'K', 0, 0, 1, 0xA0, 0x04, 0, 1, 'd', 0),
		packet(5, 1),
	)
	res, err := readResponse(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := res.header("Date"); len(got) != 1 || got[0] != "d" {
		t.Errorf("date = %v", got)
	}
}

func TestTitleHeaderName(t *testing.T) {
	tests := map[string]string{
		"content-type":     "Content-Type",
		"www-authenticate": "Www-Authenticate",
		"X-Request-ID":     "X-Request-ID",
		"ETag":             "ETag",
		"":                 "",
	}
	for in, want := range tests {
		if got := titleHeaderName(in); got != want {
			t.Errorf("titleHeaderName(%q) = %q, want %q", in, got, want)
		}
	}
}
