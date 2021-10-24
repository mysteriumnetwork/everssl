# everssl

Periodic job for SSL cert monitoring.

## Workflow

1. Collects all domains (`enumerator` component)
2. Validates TLS handshake (`validator` component)
3. Reports errors (`reporter` component)
4. Sends heartbeat upon successful completion of work cycle (`heartbeat` component)

## Installation

#### Binaries

Pre-built binaries are available [here](https://github.com/mysteriumnetwork/everssl/releases/latest).

#### Build from source

Alternatively, you may install application from source. Run the following within the source directory:

```
make install
```

## Usage

Intended to be used as a cron job or a systemd timer.

## Recognized environment variables

CLI arguments take precedence over environment variables.

* `CF_API_TOKEN` - same as `-cf-api-token` command line argument
* `PAGERDUTY_KEY` - same as `-pagerduty-key` command line argument
* `HEARTBEAT_URL` - same as `-heartbeat-url` command line argument

## Synopsis

```
$ ./bin/everssl -h
Usage of ./bin/everssl:
  -6	scan IPv6 origins (default true)
  -cf-api-token string
    	Cloudflare API token
  -expire-treshold duration
    	expiration alarm treshold (default 336h0m0s)
  -heartbeat-url string
    	heartbeat URL, URL to GET after successful finish
  -ignore-connection-errors
    	ignore connection errors (default true)
  -ignore-expiration-errors
    	ignore expiration errors
  -ignore-handshake-errors
    	ignore handshake errors (default true)
  -ignore-verification-errors
    	ignore certificate verification errors (default true)
  -pagerduty-key string
    	PagerDuty Events V2 integration key
  -rate-every duration
    	ratelimit period (inverse of frequency) (default 100ms)
  -timeout duration
    	overall scan timeout (default 5m0s)
  -verify
    	verify certificates (default true)
  -version
    	show program version and exit
  -zone string
    	requested zone (domain) name
```
