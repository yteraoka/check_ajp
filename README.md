# check_ajp

Nagios plugin for checking AJP13 Server

## Usage

```
Usage:
  check_ajp [OPTIONS]

Application Options:
  -A, --useragent=   User-Agent header (default: check_http_go)
  -a, --attr=        Attributes (auth, jvmRoute,...)
  -c, --crit=        Critical time in second (default: 10.0)
  -e, --expect=      Expected status codes (csv)
  -H, --vhost=       Host header value
  -I, --ipaddr=      IP address or Server hostname (default: 127.0.0.1)
  -k, --header=      Additional headers
  -m, --method=      HTTP method (default: GET)
  -P, --protocol=    HTTP protocol (default: HTTP/1.0)
  -p, --port=        TCP Port (default: 8009)
  -s, --ssl          isSSL flag
  -t, --timeout=     Connect timeout in second (default: 1.0)
  -u, --uri=         URI (default: /)
  -v, --verbose      verbose output
  -w, --warn=        Warning time in second (default: 5.0)
  -V, --version      Show version
      --json-key=    JSON key
      --json-value=  Expected json value
      --remote-addr= RemoteAddr header value
      --remote-host= RemoteHost header value

Help Options:
  -h, --help         Show this help message
```

### example

```
./check_ajp -I server -u /checkHealth
AJP OK: 200 - 3 bytes in 0.013 second response time |time=0.012675s;;;0.000000 size=3B;;;0
```

```
$ ./check_ajp -I server -u /healthcheck --json-key status --json-value "ok"
AJP OK: 200 - 137 bytes in 0.012 second response time |time=0.012235s;;;0.000000 size=137B;;;0

{
    "status": "ok"
}
```

## Limitations

Current version supported `GET` and `HEAD` method only.

## How to build

```
go build -o check_ajp
```
