package main

import (
	"bytes"
	"strings"
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

func TestEncodeAttributes(t *testing.T) {
	var attrs []*Attribute
	for _, kv := range [][2]string{{"req_attribute", "foo=bar"}, {"ssl_key_size", "256"}, {"route", "n1"}} {
		attr, err := newAttribute(kv[0], kv[1])
		if err != nil {
			t.Fatal(err)
		}
		attrs = append(attrs, attr)
	}
	req := AJP13ForwardRequest{PrefixCode: JK_AJP13_FORWARD_REQUEST, Method: "GET", Attributes: attrs}
	packet, err := req.encode()
	if err != nil {
		t.Fatal(err)
	}
	want := []byte{
		0x0A, 0, 3, 'f', 'o', 'o', 0, 0, 3, 'b', 'a', 'r', 0, // req_attribute: name and value
		0x0B, 0x01, 0x00, // ssl_key_size: uint16
		0x06, 0, 2, 'n', '1', 0, // route: string
		0xFF, // request terminator
	}
	if !bytes.HasSuffix(packet, want) {
		t.Errorf("encoded request = % x\nwant suffix      % x", packet, want)
	}
}

func TestEncodePacketSize(t *testing.T) {
	base := AJP13ForwardRequest{PrefixCode: JK_AJP13_FORWARD_REQUEST, Method: "GET", ServerPort: 8009}
	packet, err := base.encode()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.HasPrefix(packet, []byte{0x12, 0x34}) {
		t.Errorf("packet does not start with 0x12 0x34: % x", packet[:4])
	}
	if got := int(packet[2])<<8 | int(packet[3]); got != len(packet)-4 {
		t.Errorf("data length = %d, want %d", got, len(packet)-4)
	}

	// grow the URI so that the packet is exactly the default packet size
	req := base
	req.Uri = strings.Repeat("a", AJP13_DEFAULT_PACKET_SIZE-len(packet))
	if packet, err := req.encode(); err != nil || len(packet) != AJP13_DEFAULT_PACKET_SIZE {
		t.Errorf("packet of %d bytes: err = %v", len(packet), err)
	}
	req.Uri += "a"
	if _, err := req.encode(); err == nil {
		t.Errorf("expected error for a packet larger than %d bytes", AJP13_DEFAULT_PACKET_SIZE)
	}
	req.PacketSize = AJP13_MAX_PACKET_SIZE
	if _, err := req.encode(); err != nil {
		t.Errorf("unexpected error with PacketSize %d: %v", req.PacketSize, err)
	}

	// 40,000 bytes URI used to overflow the int16 length field
	req.Uri = strings.Repeat("a", 40000)
	packet, err = req.encode()
	if err != nil {
		t.Fatal(err)
	}
	if got := int(packet[2])<<8 | int(packet[3]); got != len(packet)-4 {
		t.Errorf("data length = %d, want %d", got, len(packet)-4)
	}

	req.Uri = strings.Repeat("a", 0xFFFF)
	if _, err := req.encode(); err == nil {
		t.Errorf("expected error for a string of 0xFFFF bytes")
	}
}

func TestEncodeInvalidValue(t *testing.T) {
	req := AJP13ForwardRequest{PrefixCode: JK_AJP13_FORWARD_REQUEST, Method: "GET", ServerPort: 70000}
	if _, err := req.encode(); err == nil {
		t.Errorf("expected error for port 70000")
	}
}

func TestEncodeLengthFieldOverflow(t *testing.T) {
	// PacketSize is checked by main, but encode must not wrap the length
	// field even if a larger PacketSize is given
	req := AJP13ForwardRequest{PrefixCode: JK_AJP13_FORWARD_REQUEST, Method: "GET", PacketSize: 1 << 20}
	for i := 0; i < 2; i++ {
		req.Headers = append(req.Headers, &RequestHeader{Name: "x-long", Value: strings.Repeat("a", 40000)})
	}
	if _, err := req.encode(); err == nil {
		t.Errorf("expected error for data longer than 0xFFFF bytes")
	}
}
