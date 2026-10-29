package main

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

var SC_REQ_HEADER = map[string][]byte{
	"accept":          {0xA0, 0x01},
	"accept-charset":  {0xA0, 0x02},
	"accept-encoding": {0xA0, 0x03},
	"accept-language": {0xA0, 0x04},
	"authorization":   {0xA0, 0x05},
	"connection":      {0xA0, 0x06},
	"content-type":    {0xA0, 0x07},
	"content-length":  {0xA0, 0x08},
	"cookie":          {0xA0, 0x09},
	"cookie2":         {0xA0, 0x0A},
	"host":            {0xA0, 0x0B},
	"pragma":          {0xA0, 0x0C},
	"referer":         {0xA0, 0x0D},
	"user-agent":      {0xA0, 0x0E},
}

const (
	SC_A_REQ_ATTRIBUTE byte = 0x0A
	SC_A_SSL_KEY_SIZE  byte = 0x0B
)

var SC_REQ_ATTR = map[string][]byte{
	"context":       {0x01}, // Not currently implemented
	"servlet_path":  {0x02}, // Not currently implemented
	"remote_user":   {0x03},
	"auth_type":     {0x04}, // Basic, Digest
	"query_string":  {0x05},
	"route":         {0x06},
	"ssl_cert":      {0x07},
	"ssl_cipher":    {0x08},
	"ssl_session":   {0x09},
	"req_attribute": {SC_A_REQ_ATTRIBUTE}, // Name and Value
	"ssl_key_size":  {SC_A_SSL_KEY_SIZE},  // Integer
	"secret":        {0x0C},
	"stored_method": {0x0D},
}

var METHOD = map[string]int{
	"GET":  2,
	"HEAD": 3,
	/*
	   Other methods are not supported yet.

	   "OPTIONS":          1,
	   "POST":             4,
	   "PUT":              5,
	   "DELETE":           6,
	   "TRACE":            7,
	   "PROPFIND":         8,
	   "PROPPATCH":        9,
	   "MKCOL":            10,
	   "COPY":             11,
	   "MOVE":             12,
	   "LOCK":             13,
	   "UNLOCK":           14,
	   "ACL":              15,
	   "REPORT":           16,
	   "VERSION-CONTROL":  17,
	   "CHECKIN":          18,
	   "CHECKOUT":         19,
	   "UNCHECKOUT":       20,
	   "SEARCH":           21,
	   "MKWORKSPACE":      22,
	   "UPDATE":           23,
	   "LABEL":            24,
	   "MERGE":            25,
	   "BASELINE_CONTROL": 26,
	   "MKACTIVITY":       27,
	*/
}

const JK_AJP13_FORWARD_REQUEST = 0x02

// Packet size limits, same as packetSize of the Tomcat AJP connector.
// The packet size includes the 4 bytes header (0x12 0x34 and the length).
const (
	AJP13_DEFAULT_PACKET_SIZE = 8192
	AJP13_MAX_PACKET_SIZE     = 65536
)

type RequestHeader struct {
	Name  string
	Value string
}

type Attribute struct {
	Code    []byte
	Name    string // req_attribute only
	Value   string
	KeySize int // ssl_key_size only
}

// newAttribute parses the value of an attribute given as key=value.
// req_attribute takes name=value, and ssl_key_size takes an integer.
func newAttribute(key, value string) (*Attribute, error) {
	code := SC_REQ_ATTR[strings.ToLower(key)]
	if code == nil {
		return nil, fmt.Errorf("unknown attribute: %s", key)
	}
	attr := &Attribute{Code: code}
	switch code[0] {
	case SC_A_REQ_ATTRIBUTE:
		parts := strings.SplitN(value, "=", 2)
		if len(parts) != 2 || parts[0] == "" {
			return nil, fmt.Errorf("req_attribute must be given as req_attribute=name=value: %s", value)
		}
		attr.Name = parts[0]
		attr.Value = parts[1]
	case SC_A_SSL_KEY_SIZE:
		n, err := strconv.Atoi(value)
		if err != nil || n < 0 || n > 0xFFFF {
			return nil, fmt.Errorf("ssl_key_size must be an integer between 0 and 65535: %s", value)
		}
		attr.KeySize = n
	default:
		attr.Value = value
	}
	return attr, nil
}

type AJP13ForwardRequest struct {
	PrefixCode int
	Method     string
	Uri        string
	Protocol   string
	RemoteAddr string
	RemoteHost string
	ServerName string
	ServerPort int
	IsSsl      bool
	Headers    []*RequestHeader
	Attributes []*Attribute
	PacketSize int // AJP13_DEFAULT_PACKET_SIZE if 0
}

func newAJP13ForwardRequest(o Options) AJP13ForwardRequest {
	r := AJP13ForwardRequest{}
	r.PrefixCode = JK_AJP13_FORWARD_REQUEST
	r.Method = strings.ToUpper(o.Method)
	r.Protocol = o.Protocol
	r.IsSsl = o.Ssl
	r.Uri = o.Uri
	r.ServerName = o.Ipaddr
	r.ServerPort = o.Port
	r.PacketSize = o.PacketSize
	if o.RemoteAddr != "" {
		r.RemoteAddr = o.RemoteAddr
	}
	if o.RemoteHost != "" {
		r.RemoteHost = o.RemoteHost
	}
	return r
}

// requestEncoder keeps the first error so that the caller only has to check
// it once after encoding the whole packet.
type requestEncoder struct {
	buf []byte
	err error
}

func (e *requestEncoder) setError(err error) {
	if e.err == nil {
		e.err = err
	}
}

func (e *requestEncoder) appendBytes(b []byte) {
	e.buf = append(e.buf, b...)
}

func (e *requestEncoder) appendUint16(i int) {
	if i < 0 || i > 0xFFFF {
		e.setError(fmt.Errorf("value %d does not fit in uint16", i))
		return
	}
	e.buf = binary.BigEndian.AppendUint16(e.buf, uint16(i))
}

func (e *requestEncoder) appendByte(i int) {
	if i < 0 || i > 0xFF {
		e.setError(fmt.Errorf("value %d does not fit in a byte", i))
		return
	}
	e.buf = append(e.buf, byte(i))
}

// appendString appends the length, the string and the 0x00 terminator.
// The length 0xFFFF is reserved for a null string.
func (e *requestEncoder) appendString(s string) {
	if len(s) >= 0xFFFF {
		e.setError(fmt.Errorf("string is too long (%d bytes)", len(s)))
		return
	}
	e.appendUint16(len(s))
	e.buf = append(e.buf, s...)
	e.buf = append(e.buf, 0x00)
}

func (e *requestEncoder) appendBool(b bool) {
	if b {
		e.buf = append(e.buf, 0x01)
	} else {
		e.buf = append(e.buf, 0x00)
	}
}

func (r *AJP13ForwardRequest) validate() error {
	var err error

	if METHOD[r.Method] == 0 {
		err = errors.New(fmt.Sprintf("%s method is not yet supported.", r.Method))
	}

	return err
}

// encode returns the whole forward request packet. It fails if the packet
// exceeds PacketSize.
func (r *AJP13ForwardRequest) encode() ([]byte, error) {
	packetSize := r.PacketSize
	if packetSize == 0 {
		packetSize = AJP13_DEFAULT_PACKET_SIZE
	}

	// Packet Format (Server->Container)
	// Byte       0       1       2       3       4...(n+3)
	// Contents   0x12    0x34    Data Length (n) Data
	// The length is filled in after encoding the data.
	var data requestEncoder
	data.appendBytes([]byte{0x12, 0x34, 0x00, 0x00})
	data.appendByte(r.PrefixCode)
	data.appendByte(METHOD[r.Method])
	data.appendString(r.Protocol)
	data.appendString(r.Uri)
	data.appendString(r.RemoteAddr)
	data.appendString(r.RemoteHost)
	data.appendString(r.ServerName)
	data.appendUint16(r.ServerPort)
	data.appendBool(r.IsSsl)

	// Headers
	data.appendUint16(len(r.Headers))

	for _, hdr := range r.Headers {
		if SC_REQ_HEADER[strings.ToLower(hdr.Name)] != nil {
			data.appendBytes(SC_REQ_HEADER[strings.ToLower(hdr.Name)])
		} else {
			data.appendString(strings.ToLower(hdr.Name))
		}
		data.appendString(hdr.Value)
	}

	// Attributes
	for _, attr := range r.Attributes {
		data.appendBytes(attr.Code)
		switch attr.Code[0] {
		case SC_A_REQ_ATTRIBUTE:
			data.appendString(attr.Name)
			data.appendString(attr.Value)
		case SC_A_SSL_KEY_SIZE:
			data.appendUint16(attr.KeySize)
		default:
			data.appendString(attr.Value)
		}
	}

	data.appendBytes([]byte{0xff})
	if data.err != nil {
		return nil, data.err
	}

	if len(data.buf) > packetSize {
		return nil, fmt.Errorf("request packet is %d bytes, which exceeds the AJP packet size %d bytes (--packet-size)", len(data.buf), packetSize)
	}
	// the data length always fits in uint16 since packetSize is at most 65536
	binary.BigEndian.PutUint16(data.buf[2:4], uint16(len(data.buf)-4))
	return data.buf, nil
}
