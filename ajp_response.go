package main

import (
	"bytes"
	"encoding/binary"
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

func readByte(r io.Reader, n int) ([]byte, error) {
	data := make([]byte, n)
	_, err := io.ReadFull(r, data)
	if err != nil {
		return data, err
	}
	return data, err
}

func readBool(r io.Reader) (bool, error) {
	var b bool
	data, err := readByte(r, 1)
	if err != nil {
		return b, err
	}
	if data[0] == byte(0x00) {
		b = false
	} else {
		b = true
	}
	return b, err
}

func readString(r io.Reader) (string, error) {
	var len uint16
	err := binary.Read(r, binary.BigEndian, &len)
	if err != nil {
		return "", err
	}
	return readStringN(r, int(len))
}

func readStringN(r io.Reader, len int) (string, error) {
	data := make([]byte, len+1)
	_, err := io.ReadFull(r, data)
	if err != nil {
		return string(data), err
	}
	return string(data[0:len]), err
}

func readUint16(r io.Reader) (int, error) {
	var len uint16
	err := binary.Read(r, binary.BigEndian, &len)
	if err != nil {
		return int(len), err
	}
	return int(len), err
}

func readUint8(r io.Reader) (int, error) {
	var b uint8
	err := binary.Read(r, binary.BigEndian, &b)
	if err != nil {
		return int(b), err
	}
	return int(b), err
}

func readResponse(conn io.Reader) (AJP13Response, error) {
	var res AJP13Response
	var err error
READ_RESPONSE:
	for {
		direction, err := readByte(conn, 2)
		if err != nil {
			return res, err
		}
		if bytes.Compare(direction, []byte("AB")) != 0 {
			return res, errors.New(fmt.Sprintf("unknown direction: %v", direction))
		}
		segmentSize, err := readUint16(conn)
		if err != nil {
			return res, err
		}

		prefix, err := readUint8(conn)
		if err != nil {
			return res, err
		}
		segmentSize -= 1

		switch prefix {
		case AJP13_SEND_BODY_CHUNK:
			// fmt.Println("AJP13_SEND_BODY_CHUNK")
			chunkLength, err := readUint16(conn)
			if err != nil {
				return res, err
			}
			segmentSize -= 2
			chunk, err := readByte(conn, chunkLength)
			if err != nil {
				return res, err
			}
			res.Body = append(res.Body, chunk...)
			if segmentSize != chunkLength {
				_, err = readByte(conn, segmentSize-chunkLength)
				if err != nil {
					return res, err
				}
			}
		case AJP13_SEND_HEADERS:
			// fmt.Println("AJP13_SEND_HEADERS")
			err = readResponseHeaders(conn, &res)
			if err != nil {
				return res, err
			}
		case AJP13_END_RESPONSE:
			// fmt.Println("AJP13_END_RESPONSE")
			_, err = readBool(conn)
			if err != nil {
				return res, err
			}
			// reuse := readBool(conn)
			// fmt.Printf("reuse = %v\n", reuse)
			segmentSize -= 1
			if segmentSize != 0 {
				fmt.Fprintf(os.Stderr, "[WARNING] read remain unknown package\n")
				_, err = readByte(conn, segmentSize-1)
				if err != nil {
					return res, err
				}
			}
			break READ_RESPONSE
		case AJP13_GET_BODY_CHUNK:
			panic("GET_BODY_CHUNK response is not yet supported")
		}
	}
	return res, err
}

func (r *AJP13Response) dumpHeader() {
	fmt.Printf("StatusCode: %d\n", r.StatusCode)
	fmt.Printf("StatusMessage: %s\n", r.StatusMessage)
	for _, hdr := range r.Headers {
		fmt.Printf("%s: %s\n", strings.Title(hdr.Name), hdr.Value)
	}
}

func readResponseHeaders(r io.Reader, res *AJP13Response) error {
	var err error
	// [1, 2] status
	res.StatusCode, err = readUint16(r)
	if err != nil {
		return err
	}

	// pos := 3 // skip prefix and status

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
			len, err := readUint16(bytes.NewBuffer(header_code))
			if err != nil {
				return err
			}
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
	return err
}
