package main

import (
	"bytes"
	"errors"
	"fmt"
	"github.com/lunixbochs/struc"
	"io"
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
	"req_attribute": {0x0A}, // Name (the name of the attribut follows)
	"ssl_key_size":  {0x0B},
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

type RequestHeader struct {
	Name  string
	Value string
}

type Attribute struct {
	Code  []byte
	Value string
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
}

type encodeBool struct {
	Value bool `struc:"bool"`
}

type encodeInt8 struct {
	Value int `struc:"uint8"`
}

type encodeInt16 struct {
	Value int `struc:"int16"`
}

type encodeString struct {
	Size      int    `struc:"uint16,sizeof=Value"`
	Value     string `struc:[]byte`
	Terminate []byte `struc:"[1]pad"`
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
	if o.RemoteAddr != "" {
		r.RemoteAddr = o.RemoteAddr
	}
	if o.RemoteHost != "" {
		r.RemoteHost = o.RemoteHost
	}
	return r
}

func (r *AJP13ForwardRequest) appendHeader(header string) {
	hdr := strings.SplitN(header, ": ", 2)
	r.Headers = append(r.Headers, &RequestHeader{Name: strings.ToLower(hdr[0]), Value: hdr[1]})
}

// requestEncoder keeps the first error returned by struc.Pack so that the
// caller only has to check it once after encoding the whole packet.
type requestEncoder struct {
	buf bytes.Buffer
	err error
}

func (e *requestEncoder) pack(data interface{}) {
	if e.err == nil {
		e.err = struc.Pack(&e.buf, data)
	}
}

func (e *requestEncoder) appendUint16(i int) {
	e.pack(&encodeInt16{Value: i})
}

func (e *requestEncoder) appendByte(i int) {
	e.pack(&encodeInt8{Value: i})
}

func (e *requestEncoder) appendString(s string) {
	e.pack(&encodeString{Value: s})
}

func (e *requestEncoder) appendBool(b bool) {
	e.pack(&encodeBool{Value: b})
}

func (r *AJP13ForwardRequest) validate() error {
	var err error

	if METHOD[r.Method] == 0 {
		err = errors.New(fmt.Sprintf("%s method is not yet supported.", r.Method))
	}

	return err
}

func (r *AJP13ForwardRequest) sendRequest(w io.Writer) error {
	var data requestEncoder
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
			data.buf.Write(SC_REQ_HEADER[strings.ToLower(hdr.Name)])
		} else {
			data.appendString(strings.ToLower(hdr.Name))
		}
		data.appendString(hdr.Value)
	}

	// Attributes
	for _, attr := range r.Attributes {
		data.buf.Write(attr.Code)
		data.appendString(attr.Value)
	}

	data.buf.Write([]byte{0xff})
	if data.err != nil {
		return data.err
	}

	// Packet Format (Server->Container)
	// Byte       0       1       2       3       4...(n+3)
	// Contents   0x12    0x34    Data Length (n) Data
	var packet requestEncoder
	packet.buf.Write([]byte{0x12, 0x34})
	packet.appendUint16(data.buf.Len())
	packet.buf.Write(data.buf.Bytes())
	if packet.err != nil {
		return packet.err
	}

	_, err := w.Write(packet.buf.Bytes())
	return err
}
