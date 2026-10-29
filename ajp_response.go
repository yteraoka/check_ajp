package main

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const (
	AJP13_SEND_BODY_CHUNK int = 3
	AJP13_SEND_HEADERS    int = 4
	AJP13_END_RESPONSE    int = 5
	AJP13_GET_BODY_CHUNK  int = 6
	AJP13_CPONG_REPLY     int = 9
)

const (
	SC_RES_CONTENT_TYPE     string = "\xA0\x01"
	SC_RES_CONTENT_LANGUAGE string = "\xA0\x02"
	SC_RES_CONTENT_LENGTH   string = "\xA0\x03"
	SC_RES_DATE             string = "\xA0\x04"
	SC_RES_LAST_MODIFIED    string = "\xA0\x05"
	SC_RES_LOCATION         string = "\xA0\x06"
	SC_RES_SET_COOKIE       string = "\xA0\x07"
	SC_RES_SET_COOKIE2      string = "\xA0\x08"
	SC_RES_SERVLET_ENGINE   string = "\xA0\x09"
	SC_RES_STATUS           string = "\xA0\x0A"
	SC_RES_WWW_AUTHENTICATE string = "\xA0\x0B"
)

var SC_RES_HEADER = map[string]string{
	SC_RES_CONTENT_TYPE:     "content-type",
	SC_RES_CONTENT_LANGUAGE: "content-language",
	SC_RES_CONTENT_LENGTH:   "content-length",
	SC_RES_DATE:             "data",
	SC_RES_LAST_MODIFIED:    "last-modified",
	SC_RES_LOCATION:         "location",
	SC_RES_SET_COOKIE:       "set-cookie",
	SC_RES_SET_COOKIE2:      "set-cookie2",
	SC_RES_SERVLET_ENGINE:   "servlet-engine",
	SC_RES_STATUS:           "status",
	SC_RES_WWW_AUTHENTICATE: "www-authenticate",
}

type ResponseHeader struct {
	Name  string
	Value string
}

type AJP13Response struct {
	StatusCode    int
	StatusMessage string
	Headers       []*ResponseHeader
	Body          []byte
}

func (r *AJP13Response) header(name string) []string {
	var result []string
	for _, hdr := range r.Headers {
		if strings.ToLower(hdr.Name) == strings.ToLower(name) {
			result = append(result, hdr.Value)
		}
	}
	return result
}

var errShortPacket = errors.New("malformed AJP packet: payload is shorter than expected")

// The read* helpers parse fields from a single packet payload that has already
// been read entirely into memory, so they never read beyond the packet boundary.

func readByte(r *bytes.Reader, n int) ([]byte, error) {
	if n < 0 || n > r.Len() {
		return nil, errShortPacket
	}
	data := make([]byte, n)
	r.Read(data)
	return data, nil
}

func readBool(r *bytes.Reader) (bool, error) {
	b, err := r.ReadByte()
	if err != nil {
		return false, errShortPacket
	}
	return b != 0x00, nil
}

func readString(r *bytes.Reader) (string, error) {
	len, err := readUint16(r)
	if err != nil {
		return "", err
	}
	// 0xFFFF means a null string, which has no terminator
	if len == 0xFFFF {
		return "", nil
	}
	return readStringN(r, len)
}

func readStringN(r *bytes.Reader, len int) (string, error) {
	data, err := readByte(r, len+1)
	if err != nil {
		return "", err
	}
	if data[len] != 0x00 {
		return "", errors.New("malformed AJP packet: string is not terminated by 0x00")
	}
	return string(data[0:len]), nil
}

func readUint16(r *bytes.Reader) (int, error) {
	if r.Len() < 2 {
		return 0, errShortPacket
	}
	hi, _ := r.ReadByte()
	lo, _ := r.ReadByte()
	return int(hi)<<8 | int(lo), nil
}

func readUint8(r *bytes.Reader) (int, error) {
	b, err := r.ReadByte()
	if err != nil {
		return 0, errShortPacket
	}
	return int(b), nil
}

// readPacket reads one AJP packet from the container and returns its payload
func readPacket(r io.Reader) ([]byte, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, err
	}
	if header[0] != 'A' || header[1] != 'B' {
		return nil, fmt.Errorf("unknown direction: %v", header[0:2])
	}
	segmentSize := int(header[2])<<8 | int(header[3])
	payload := make([]byte, segmentSize)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, err
	}
	return payload, nil
}

func readResponse(conn io.Reader) (AJP13Response, error) {
	var res AJP13Response
	br := bufio.NewReader(conn)
	for {
		payload, err := readPacket(br)
		if err != nil {
			return res, err
		}
		r := bytes.NewReader(payload)

		prefix, err := readUint8(r)
		if err != nil {
			return res, err
		}

		switch prefix {
		case AJP13_SEND_BODY_CHUNK:
			chunkLength, err := readUint16(r)
			if err != nil {
				return res, err
			}
			chunk, err := readByte(r, chunkLength)
			if err != nil {
				return res, err
			}
			// remaining bytes (e.g. the trailing 0x00) are ignored
			res.Body = append(res.Body, chunk...)
		case AJP13_SEND_HEADERS:
			err = readResponseHeaders(r, &res)
			if err != nil {
				return res, err
			}
		case AJP13_END_RESPONSE:
			_, err = readBool(r) // reuse
			if err != nil {
				return res, err
			}
			if r.Len() != 0 {
				fmt.Fprintf(os.Stderr, "[WARNING] read remain unknown package\n")
			}
			return res, nil
		case AJP13_GET_BODY_CHUNK:
			return res, errors.New("GET_BODY_CHUNK response is not yet supported")
		default:
			// unknown packet: the whole payload has been consumed, so just skip it
			fmt.Fprintf(os.Stderr, "[WARNING] skip unknown packet type: %d\n", prefix)
		}
	}
}

func (r *AJP13Response) dumpHeader() {
	fmt.Printf("StatusCode: %d\n", r.StatusCode)
	fmt.Printf("StatusMessage: %s\n", r.StatusMessage)
	for _, hdr := range r.Headers {
		fmt.Printf("%s: %s\n", strings.Title(hdr.Name), hdr.Value)
	}
}

func readResponseHeaders(r *bytes.Reader, res *AJP13Response) error {
	var err error
	// [1, 2] status
	res.StatusCode, err = readUint16(r)
	if err != nil {
		return err
	}

	// [3,4] length
	// [5...] string
	// [3 + 2 + length] 0x00
	res.StatusMessage, err = readString(r)
	if err != nil {
		return err
	}

	num_headers, err := readUint16(r)
	if err != nil {
		return err
	}

	var header_name, header_value string
	for i := 0; i < num_headers; i++ {
		header_code, err := readByte(r, 2)
		if err != nil {
			return err
		}
		if header_code[0] == byte(0xa0) {
			header_name = SC_RES_HEADER[string(header_code)]
		} else {
			len := int(header_code[0])<<8 | int(header_code[1])
			header_name, err = readStringN(r, len)
			if err != nil {
				return err
			}
		}
		header_value, err = readString(r)
		if err != nil {
			return err
		}
		res.Headers = append(res.Headers, &ResponseHeader{Name: header_name, Value: header_value})
	}
	return nil
}
