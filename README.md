# check_ajp

Nagios plugin for checking AJP13 Server

## Usage

```
Usage:
  check_ajp [OPTIONS]

Application Options:
  -A, --useragent=     User-Agent header (default: check_ajp (x.y.z))
  -a, --attr=          Attributes (auth, jvmRoute,...)
  -c, --crit=          Critical time in second (default: 10.0)
  -e, --expect=        Expected status codes (csv)
  -H, --vhost=         Host header value
  -I, --ipaddr=        IP address or Server hostname (default: 127.0.0.1)
  -k, --header=        Additional headers
  -m, --method=        HTTP method (default: GET)
  -P, --protocol=      HTTP protocol (default: HTTP/1.0)
  -p, --port=          TCP Port (default: 8009)
  -s, --ssl            isSSL flag
  -t, --timeout=       Connect timeout in second (default: 1.0)
  -u, --uri=           URI (default: /)
  -v, --verbose        verbose output
  -w, --warn=          Warning time in second (default: 5.0)
  -V, --version        Show version
      --json-key=      JSON key
      --json-value=    Expected json value
      --remote-addr=   RemoteAddr header value
      --remote-host=   RemoteHost header value
      --max-body-size= Maximum response body size in bytes to keep (the rest is
                       discarded) (default: 1048576)
      --packet-size=   AJP packet size in bytes (packetSize of the Tomcat AJP
                       connector) (default: 8192)
      --secret-file=   File to read the AJP secret from (default: AJP_SECRET
                       environment variable)

Help Options:
  -h, --help           Show this help message
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

### attributes

Request attributes are given as `-a name=value` and can be repeated.
`req_attribute` takes both a name and a value (`-a req_attribute=name=value`), and `ssl_key_size` takes an integer.

```
./check_ajp -I server -a route=node1 -a req_attribute=foo=bar -a ssl_key_size=256
```

Tomcat rejects a `req_attribute` with 403 unless its name matches `allowedRequestAttributesPattern` of the AJP connector.

### secret

Tomcat requires the `secret` of the AJP connector by default since the fix for CVE-2020-1938 (Ghostcat).
Instead of `-a secret=...`, which other local users can see with `ps`, the secret can be given in one of the following ways.

- `--secret-file=PATH`: read the secret from the file (trailing newlines are removed)
- `AJP_SECRET` environment variable

```
install -m 600 /dev/null /etc/nagios/ajp_secret
vi /etc/nagios/ajp_secret
./check_ajp -I server --secret-file /etc/nagios/ajp_secret
```

`-a secret=...` takes precedence over `AJP_SECRET`, and `--secret-file` also takes precedence over `AJP_SECRET`.
`-a secret=...` and `--secret-file` cannot be used together.

## Limitations

Current version supported `GET` and `HEAD` method only.

## How to build

```
go build -o check_ajp
```
