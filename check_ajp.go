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
}

func parseHeaderOption(s string) *RequestHeader {
	parts := strings.SplitN(s, ":", 2)
	return &RequestHeader{Name: strings.Trim(parts[0], " "), Value: strings.Trim(parts[1], " ")}
}

func parseAttributeOption(s string) *Attribute {
	parts := strings.SplitN(s, "=", 2)
	if SC_REQ_ATTR[strings.ToLower(parts[0])] == nil {
		fmt.Printf("unknown attribute: %s\n", s)
		os.Exit(NagiosUnknown)
	}
	return &Attribute{Code: SC_REQ_ATTR[strings.ToLower(parts[0])], Value: parts[1]}
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
	if opts.Vhost != "" {
		opts.Headers = append(opts.Headers, "Host: "+opts.Vhost)
	}
	if opts.UserAgent != "" {
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
		req.Headers = append(req.Headers, parseHeaderOption(header_string))
	}

	for _, attribute_string := range opts.Attributes {
		req.Attributes = append(req.Attributes, parseAttributeOption(attribute_string))
	}

	if err = req.validate(); err != nil {
		nagiosStatusCode = NagiosUnknown
		fmt.Printf("AJP %s - %s\n", NagiosStatus[nagiosStatusCode], err)
		os.Exit(nagiosStatusCode)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(opts.Timeout)*time.Second)
	defer cancel()

	var dial net.Dialer
	dial.Timeout = time.Duration(opts.Timeout) * time.Second

	remote := opts.Ipaddr + ":" + strconv.Itoa(opts.Port)

	t1 := time.Now()

	conn, err := dial.DialContext(ctx, "tcp", remote)
	if err != nil {
		nagiosStatusCode = NagiosCritical
		fmt.Printf("AJP %s - %s\n", NagiosStatus[nagiosStatusCode], err)
		os.Exit(nagiosStatusCode)
	}
	defer conn.Close()

	// set read/write timeout
	deadline := time.Now().Add(time.Duration(opts.Crit) * time.Second)
	conn.SetReadDeadline(deadline)
	conn.SetWriteDeadline(deadline)

	localaddr := conn.LocalAddr().String()
	localaddr = localaddr[0:strings.Index(localaddr, ":")]

	if opts.RemoteAddr == "" {
		req.RemoteAddr = localaddr
	}
	if opts.RemoteHost == "" {
		req.RemoteHost = localaddr
	}

	err = req.sendRequest(conn)
	if err != nil {
		nagiosStatusCode = NagiosCritical
		fmt.Printf("AJP %s - %s\n", NagiosStatus[nagiosStatusCode], err)
		os.Exit(nagiosStatusCode)
	}

	res, err := readResponse(conn)
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
		fmt.Println(string(res.Body))
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
		json.Unmarshal(res.Body, &d)
		// https://qiita.com/hnakamur/items/c3560a4b780487ef6065
		v, _ := dyno.Get(d, s...)
		if v != opts.JsonValue {
			nagiosStatusCode = NagiosCritical
			resultMessage = fmt.Sprintf("`%s` is not `%s`", opts.JsonKey, opts.JsonValue)
		}
		additionalOut, err = prettyPrintJSON(res.Body)
	}

	if nagiosStatusCode == NagiosOk && diff.Seconds() > opts.Warn {
		nagiosStatusCode = NagiosWarning
		resultMessage = fmt.Sprintf("response time %.3fs exceeded warning threshold %.3fs", diff.Seconds(), opts.Warn)
	}

	fmt.Printf("AJP %s: %d - %d bytes in %.3f second response time |time=%.6fs;;;%.6f size=%dB;;;0\n", NagiosStatus[nagiosStatusCode], res.StatusCode, len(res.Body), diff.Seconds(), diff.Seconds(), 0.0, len(res.Body))
	if resultMessage != "" {
		fmt.Println(resultMessage)
	}
	if len(additionalOut) > 0 {
		fmt.Printf("\n%s\n", additionalOut)
	}
	os.Exit(nagiosStatusCode)
}
