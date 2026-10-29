package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"github.com/icza/dyno"
	flags "github.com/jessevdk/go-flags"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

const (
	NagiosOk       int = 0
	NagiosWarning  int = 1
	NagiosCritical int = 2
	NagiosUnknown  int = 3
)

var NagiosStatus = map[int]string{
	NagiosOk:       "OK",
	NagiosWarning:  "WARNING",
	NagiosCritical: "CRITICAL",
	NagiosUnknown:  "UNKNOWN",
}

type Options struct {
	UserAgent  string   `short:"A" long:"useragent"  description:"User-Agent header (default: check_ajp (x.y.z))"`
	Attributes []string `short:"a" long:"attr"       description:"Attributes (auth, jvmRoute,...)"`
	Crit       float64  `short:"c" long:"crit"       description:"Critical time in second" default:"10.0"`
	Expect     string   `short:"e" long:"expect"     description:"Expected status codes (csv)" default:""`
	Vhost      string   `short:"H" long:"vhost"      description:"Host header value"`
	Ipaddr     string   `short:"I" long:"ipaddr"     description:"IP address or Server hostname" default:"127.0.0.1"`
	Headers    []string `short:"k" long:"header"     description:"Additional headers"`
	Method     string   `short:"m" long:"method"     description:"HTTP method" default:"GET"`
	Protocol   string   `short:"P" long:"protocol"   description:"HTTP protocol" default:"HTTP/1.0"`
	Port       int      `short:"p" long:"port"       description:"TCP Port" default:"8009"`
	Ssl        bool     `short:"s" long:"ssl"        description:"isSSL flag"`
	Timeout    float64  `short:"t" long:"timeout"    description:"Connect timeout in second" default:"1.0"`
	Uri        string   `short:"u" long:"uri"        description:"URI" default:"/"`
	Verbose    []bool   `short:"v" long:"verbose"    description:"verbose output"`
	Warn       float64  `short:"w" long:"warn"       description:"Warning time in second" default:"5.0"`
	Version    bool     `short:"V" long:"version"    description:"Show version"`
	JsonKey    string   `long:"json-key"             description:"JSON key "`
	JsonValue  string   `long:"json-value"           description:"Expected json value"`
	RemoteAddr string   `long:"remote-addr"          description:"RemoteAddr header value"`
	RemoteHost string   `long:"remote-host"          description:"RemoteHost header value"`
	MaxBody    int      `long:"max-body-size"        description:"Maximum response body size in bytes to keep (the rest is discarded)" default:"1048576"`
	PacketSize int      `long:"packet-size"          description:"AJP packet size in bytes (packetSize of the Tomcat AJP connector)" default:"8192"`
}

func parseHeaderOption(s string) (*RequestHeader, error) {
	parts := strings.SplitN(s, ":", 2)
	if len(parts) != 2 || strings.Trim(parts[0], " ") == "" {
		return nil, fmt.Errorf("header must be given as name:value: %s", s)
	}
	return &RequestHeader{Name: strings.Trim(parts[0], " "), Value: strings.Trim(parts[1], " ")}, nil
}

func parseAttributeOption(s string) (*Attribute, error) {
	parts := strings.SplitN(s, "=", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("attribute must be given as name=value: %s", s)
	}
	return newAttribute(parts[0], parts[1])
}

// sanitizeOutput makes text received from the server safe to print as plugin
// output. Control characters (which could inject terminal escape sequences),
// invalid UTF-8 bytes and '|' (the Nagios performance data separator) are
// escaped. Newlines and tabs are kept when multiline is true.
func sanitizeOutput(s string, multiline bool) string {
	var b strings.Builder
	for i := 0; i < len(s); {
		r, size := utf8.DecodeRuneInString(s[i:])
		switch {
		case r == utf8.RuneError && size == 1:
			fmt.Fprintf(&b, "\\x%02x", s[i])
		case multiline && (r == '\n' || r == '\t'):
			b.WriteRune(r)
		case r == '|':
			b.WriteString(`\x7c`)
		case unicode.IsPrint(r):
			b.WriteRune(r)
		default:
			q := strconv.QuoteRune(r)
			b.WriteString(q[1 : len(q)-1])
		}
		i += size
	}
	return b.String()
}

// trimIPv6Brackets removes the brackets of an IPv6 address given as [::1]
// since net.JoinHostPort adds them. server_name is sent as given.
func trimIPv6Brackets(host string) string {
	if strings.HasPrefix(host, "[") && strings.HasSuffix(host, "]") {
		return host[1 : len(host)-1]
	}
	return host
}

// localIPAddress returns the IP address of the local side of the connection
// without the port (and without the zone of an IPv6 link-local address).
func localIPAddress(addr net.Addr) string {
	if tcpAddr, ok := addr.(*net.TCPAddr); ok {
		return tcpAddr.IP.String()
	}
	if host, _, err := net.SplitHostPort(addr.String()); err == nil {
		return host
	}
	return addr.String()
}

// secondsToDuration converts seconds given as a float into a time.Duration
// without dropping the fractional part (time.Duration(0.5)*time.Second is 0).
func secondsToDuration(sec float64) time.Duration {
	return time.Duration(sec * float64(time.Second))
}

func prettyPrintJSON(b []byte) ([]byte, error) {
	var out bytes.Buffer
	err := json.Indent(&out, b, "", "    ")
	return out.Bytes(), err
}

func main() {
	const Version = "0.1.0"

	var opts Options
	var resultMessage string
	var additionalOut []byte
	nagiosStatusCode := NagiosOk
	_, err := flags.Parse(&opts)
	if err != nil {
		os.Exit(NagiosUnknown)
	}

	if opts.Version {
		fmt.Printf("check_ajp: %s\n", Version)
		os.Exit(NagiosUnknown)
	}
	if opts.MaxBody < 0 {
		nagiosStatusCode = NagiosUnknown
		fmt.Printf("AJP %s - --max-body-size must be 0 or greater\n", NagiosStatus[nagiosStatusCode])
		os.Exit(nagiosStatusCode)
	}
	if opts.PacketSize < AJP13_DEFAULT_PACKET_SIZE || opts.PacketSize > AJP13_MAX_PACKET_SIZE {
		nagiosStatusCode = NagiosUnknown
		fmt.Printf("AJP %s - --packet-size must be between %d and %d\n", NagiosStatus[nagiosStatusCode], AJP13_DEFAULT_PACKET_SIZE, AJP13_MAX_PACKET_SIZE)
		os.Exit(nagiosStatusCode)
	}
	if opts.Vhost != "" {
		opts.Headers = append(opts.Headers, "Host: "+opts.Vhost)
	}
	if opts.UserAgent == "" {
		opts.UserAgent = fmt.Sprintf("check_ajp (%s)", Version)
	}
	opts.Headers = append(opts.Headers, "User-Agent: "+opts.UserAgent)

	if strings.Contains(opts.Uri, "?") {
		splited := strings.SplitN(opts.Uri, "?", 2)
		opts.Uri = splited[0]
		opts.Attributes = append(opts.Attributes, "query_string="+splited[1])
	}

	req := newAJP13ForwardRequest(opts)

	for _, header_string := range opts.Headers {
		hdr, err := parseHeaderOption(header_string)
		if err != nil {
			nagiosStatusCode = NagiosUnknown
			fmt.Printf("AJP %s - %s\n", NagiosStatus[nagiosStatusCode], err)
			os.Exit(nagiosStatusCode)
		}
		req.Headers = append(req.Headers, hdr)
	}

	for _, attribute_string := range opts.Attributes {
		attr, err := parseAttributeOption(attribute_string)
		if err != nil {
			nagiosStatusCode = NagiosUnknown
			fmt.Printf("AJP %s - %s\n", NagiosStatus[nagiosStatusCode], err)
			os.Exit(nagiosStatusCode)
		}
		req.Attributes = append(req.Attributes, attr)
	}

	if err = req.validate(); err != nil {
		nagiosStatusCode = NagiosUnknown
		fmt.Printf("AJP %s - %s\n", NagiosStatus[nagiosStatusCode], err)
		os.Exit(nagiosStatusCode)
	}

	ctx, cancel := context.WithTimeout(context.Background(), secondsToDuration(opts.Timeout))
	defer cancel()

	var dial net.Dialer
	dial.Timeout = secondsToDuration(opts.Timeout)

	remote := net.JoinHostPort(trimIPv6Brackets(opts.Ipaddr), strconv.Itoa(opts.Port))

	t1 := time.Now()

	conn, err := dial.DialContext(ctx, "tcp", remote)
	if err != nil {
		nagiosStatusCode = NagiosCritical
		fmt.Printf("AJP %s - %s\n", NagiosStatus[nagiosStatusCode], err)
		os.Exit(nagiosStatusCode)
	}
	defer conn.Close()

	// set read/write timeout
	deadline := time.Now().Add(secondsToDuration(opts.Crit))
	if err = conn.SetDeadline(deadline); err != nil {
		nagiosStatusCode = NagiosUnknown
		fmt.Printf("AJP %s - %s\n", NagiosStatus[nagiosStatusCode], err)
		os.Exit(nagiosStatusCode)
	}

	localaddr := localIPAddress(conn.LocalAddr())

	if opts.RemoteAddr == "" {
		req.RemoteAddr = localaddr
	}
	if opts.RemoteHost == "" {
		req.RemoteHost = localaddr
	}

	packet, err := req.encode()
	if err != nil {
		nagiosStatusCode = NagiosUnknown
		fmt.Printf("AJP %s - %s\n", NagiosStatus[nagiosStatusCode], err)
		os.Exit(nagiosStatusCode)
	}

	if _, err = conn.Write(packet); err != nil {
		nagiosStatusCode = NagiosCritical
		fmt.Printf("AJP %s - %s\n", NagiosStatus[nagiosStatusCode], err)
		os.Exit(nagiosStatusCode)
	}

	res, err := readResponse(conn, opts.MaxBody)
	if err != nil {
		nagiosStatusCode = NagiosCritical
		if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
			resultMessage = fmt.Sprintf("read timeout exceeded critical threshold %.3fs (%s)", opts.Crit, err.Error())
		} else {
			resultMessage = err.Error()
		}
		fmt.Printf("AJP %s - %s\n", NagiosStatus[nagiosStatusCode], resultMessage)
		os.Exit(nagiosStatusCode)
	}

	t2 := time.Now()
	diff := t2.Sub(t1)

	if len(opts.Verbose) > 0 {
		fmt.Println("[RESPONSE HEADER]")
		res.dumpHeader()
		fmt.Println("")
	}

	if len(opts.Verbose) > 1 {
		fmt.Println("[RESPONSE BODY]")
		fmt.Println(sanitizeOutput(string(res.Body), true))
		if res.bodyTruncated() {
			fmt.Printf("(truncated: showing %d of %d bytes)\n", len(res.Body), res.BodySize)
		}
		fmt.Println("")
	}

	statusTxt := strconv.Itoa(int(res.StatusCode))

	if opts.Expect == "" {
		if res.StatusCode >= 500 {
			nagiosStatusCode = NagiosCritical
			resultMessage = fmt.Sprintf("Unexpected status code: %d", res.StatusCode)
		} else if res.StatusCode >= 400 {
			nagiosStatusCode = NagiosWarning
			resultMessage = fmt.Sprintf("Unexpected status code: %d", res.StatusCode)
		}
	} else {
		nagiosStatusCode = NagiosWarning
		for _, expect := range strings.Split(opts.Expect, ",") {
			if statusTxt == expect {
				nagiosStatusCode = NagiosOk
			}
		}
		if nagiosStatusCode == NagiosWarning {
			resultMessage = fmt.Sprintf("Unexpected status code: %d", res.StatusCode)
		}
	}

	if opts.JsonKey != "" && opts.JsonValue != "" {
		// https://stackoverflow.com/questions/27689058/convert-string-to-interface
		t := strings.Split(opts.JsonKey, ".")
		s := make([]interface{}, len(t))
		for i, v := range t {
			s[i] = v
		}
		// https://reformatcode.com/code/json/taking-a-json-string-unmarshaling-it-into-a-mapstringinterface-editing-and-marshaling-it-into-a-byte-seems-more-complicated-then-it-should-be
		var d map[string]interface{}
		if res.bodyTruncated() {
			nagiosStatusCode = NagiosCritical
			resultMessage = fmt.Sprintf("response body (%d bytes) exceeds --max-body-size (%d bytes), cannot check JSON", res.BodySize, opts.MaxBody)
		} else if err = json.Unmarshal(res.Body, &d); err != nil {
			nagiosStatusCode = NagiosCritical
			resultMessage = fmt.Sprintf("response body is not valid JSON: %s", err)
		} else {
			// https://qiita.com/hnakamur/items/c3560a4b780487ef6065
			v, _ := dyno.Get(d, s...)
			if v != opts.JsonValue {
				nagiosStatusCode = NagiosCritical
				resultMessage = fmt.Sprintf("`%s` is not `%s`", opts.JsonKey, opts.JsonValue)
			}
		}
		if !res.bodyTruncated() {
			additionalOut, err = prettyPrintJSON(res.Body)
		}
	}

	if nagiosStatusCode == NagiosOk && diff.Seconds() > opts.Warn {
		nagiosStatusCode = NagiosWarning
		resultMessage = fmt.Sprintf("response time %.3fs exceeded warning threshold %.3fs", diff.Seconds(), opts.Warn)
	}

	fmt.Printf("AJP %s: %d - %d bytes in %.3f second response time |time=%.6fs;;;%.6f size=%dB;;;0\n", NagiosStatus[nagiosStatusCode], res.StatusCode, res.BodySize, diff.Seconds(), diff.Seconds(), 0.0, res.BodySize)
	if resultMessage != "" {
		fmt.Println(resultMessage)
	}
	if len(additionalOut) > 0 {
		fmt.Printf("\n%s\n", sanitizeOutput(string(additionalOut), true))
	}
	os.Exit(nagiosStatusCode)
}
