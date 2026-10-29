package main

import (
	"bytes"
	"testing"
)

func TestNewAttribute(t *testing.T) {
	tests := []struct {
		key, value string
		want       Attribute
	}{
		{"route", "node1", Attribute{Code: []byte{0x06}, Value: "node1"}},
		{"REQ_ATTRIBUTE", "name=a=b", Attribute{Code: []byte{0x0A}, Name: "name", Value: "a=b"}},
		{"req_attribute", "name=", Attribute{Code: []byte{0x0A}, Name: "name", Value: ""}},
		{"ssl_key_size", "256", Attribute{Code: []byte{0x0B}, KeySize: 256}},
	}
	for _, tt := range tests {
		got, err := newAttribute(tt.key, tt.value)
		if err != nil {
			t.Errorf("newAttribute(%q, %q): unexpected error: %v", tt.key, tt.value, err)
			continue
		}
		if !bytes.Equal(got.Code, tt.want.Code) || got.Name != tt.want.Name || got.Value != tt.want.Value || got.KeySize != tt.want.KeySize {
			t.Errorf("newAttribute(%q, %q) = %+v, want %+v", tt.key, tt.value, *got, tt.want)
		}
	}
}

func TestNewAttributeInvalid(t *testing.T) {
	tests := []struct{ key, value string }{
		{"unknown", "x"},
		{"req_attribute", "name"},
		{"req_attribute", "=value"},
		{"ssl_key_size", "abc"},
		{"ssl_key_size", "-1"},
		{"ssl_key_size", "65536"},
	}
	for _, tt := range tests {
		if _, err := newAttribute(tt.key, tt.value); err == nil {
			t.Errorf("newAttribute(%q, %q): expected error", tt.key, tt.value)
		}
	}
}

func TestSendRequestAttributes(t *testing.T) {
	var attrs []*Attribute
	for _, kv := range [][2]string{{"req_attribute", "foo=bar"}, {"ssl_key_size", "256"}, {"route", "n1"}} {
		attr, err := newAttribute(kv[0], kv[1])
		if err != nil {
			t.Fatal(err)
		}
		attrs = append(attrs, attr)
	}
	req := AJP13ForwardRequest{PrefixCode: JK_AJP13_FORWARD_REQUEST, Method: "GET", Attributes: attrs}
	var buf bytes.Buffer
	if err := req.sendRequest(&buf); err != nil {
		t.Fatal(err)
	}
	want := []byte{
		0x0A, 0, 3, 'f', 'o', 'o', 0, 0, 3, 'b', 'a', 'r', 0, // req_attribute: name and value
		0x0B, 0x01, 0x00, // ssl_key_size: uint16
		0x06, 0, 2, 'n', '1', 0, // route: string
		0xFF, // request terminator
	}
	if !bytes.HasSuffix(buf.Bytes(), want) {
		t.Errorf("encoded request = % x\nwant suffix      % x", buf.Bytes(), want)
	}
}
