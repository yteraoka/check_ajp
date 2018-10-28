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
	"GET":              2,
	"HEAD":             3,
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

func appendUint16(buf *bytes.Buffer, i int) {
	struc.Pack(buf, &encodeInt16{Value: i})
}

func appendByte(buf *bytes.Buffer, i int) {
	struc.Pack(buf, &encodeInt8{Value: i})
}

func appendString(buf *bytes.Buffer, s string) {
	struc.Pack(buf, &encodeString{Value: s})
}

func appendBool(buf *bytes.Buffer, b bool) {
	struc.Pack(buf, &encodeBool{Value: b})
}

func (r *AJP13ForwardRequest) validate() error {
	var err error

	if METHOD[r.Method] == 0 {
		err = errors.New(fmt.Sprintf("%s method is not yet supported.", r.Method))
	}

	return err
}

func (r *AJP13ForwardRequest) sendRequest(w io.Writer) error {
	var err error

	var buf bytes.Buffer
	appendByte(&buf, r.PrefixCode)
	appendByte(&buf, METHOD[r.Method])
	appendString(&buf, r.Protocol)
	appendString(&buf, r.Uri)
	appendString(&buf, r.RemoteAddr)
	appendString(&buf, r.RemoteHost)
	appendString(&buf, r.ServerName)
	appendUint16(&buf, r.ServerPort)
	appendBool(&buf, r.IsSsl)

	// Headers
	appendUint16(&buf, len(r.Headers))

	for _, hdr := range r.Headers {
		if SC_REQ_HEADER[strings.ToLower(hdr.Name)] != nil {
			buf.Write(SC_REQ_HEADER[strings.ToLower(hdr.Name)])
		} else {
			appendString(&buf, strings.ToLower(hdr.Name))
		}
		appendString(&buf, hdr.Value)
	}

	// Attributes
	for _, attr := range r.Attributes {
		buf.Write(attr.Code)
		appendString(&buf, attr.Value)
	}

	buf.Write([]byte{0xff})

	// Packet Format (Server->Container)
	// Byte       0       1       2       3       4...(n+3)
	// Contents   0x12    0x34    Data Length (n) Data
	_, err = w.Write([]byte{0x12, 0x34})
	if err = struc.Pack(w, &encodeInt16{Value: buf.Len()}); err != nil {
		return err
	}
	_, err = w.Write(buf.Bytes())

	return err
}
