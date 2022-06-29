package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"regexp"
	"time"

	"github.com/mysteriumnetwork/everssl/enumerator"
	"github.com/mysteriumnetwork/everssl/heartbeat"
	"github.com/mysteriumnetwork/everssl/reporter"
	"github.com/mysteriumnetwork/everssl/validator"
	"github.com/mysteriumnetwork/everssl/workflow"
)

var version = "undefined"

var (
	// global options
	showVersion = flag.Bool("version", false, "show program version and exit")
	timeout     = flag.Duration("timeout", 5*time.Minute, "overall scan timeout")
	oneTimeout  = flag.Duration("1-timeout", 15*time.Second, "timeout for one connection")
	retries     = flag.Int("retries", 3, "validation retries")

	// enumerator options
	CFAPIToken = flag.String("cf-api-token", "", "Cloudflare API token")
	scanIPv6   = flag.Bool("6", true, "scan IPv6 origins")
	ignoreRE   = flag.String("ignore", `\b\B`, "regular expressions which matching domains to ignore")

	// validator options
	expireTreshold = flag.Duration("expire-treshold", 14*24*time.Hour, "expiration alarm treshold")
	rateLimitEvery = flag.Duration("rate-every", 100*time.Millisecond, "ratelimit period (inverse of frequency)")
	verify         = flag.Bool("verify", true, "verify certificates")

	// error filter options
	ignoreConnectionErrors   = flag.Bool("ignore-connection-errors", true, "ignore connection errors")
	ignoreHandshakeErrors    = flag.Bool("ignore-handshake-errors", true, "ignore handshake errors")
	ignoreVerificationErrors = flag.Bool("ignore-verification-errors", true, "ignore certificate verification errors")
	ignoreExpirationErrors   = flag.Bool("ignore-expiration-errors", false, "ignore expiration errors")

	pagerDutyKey = flag.String("pagerduty-key", "", "PagerDuty Events V2 integration key")

	heartbeatURL = flag.String("heartbeat-url", "", "heartbeat URL, URL to GET after successful finish")
)

func run() int {
	flag.Parse()
	if *showVersion {
		fmt.Println(version)
		return 0
	}

	if *CFAPIToken == "" {
		envToken := os.Getenv("CF_API_TOKEN")
		if envToken != "" {
			*CFAPIToken = envToken
		}
	}

	if *CFAPIToken == "" {
		log.Fatal("Cloudflare API token is not specified. Either set CF_API_TOKEN " +
			"environment variable or specify -cf-api-token command line argument")
	}

	if *pagerDutyKey == "" {
		envToken := os.Getenv("PAGERDUTY_KEY")
		if envToken != "" {
			*pagerDutyKey = envToken
		}
	}

	if *heartbeatURL == "" {
		envToken := os.Getenv("HEARTBEAT_URL")
		if envToken != "" {
			*heartbeatURL = envToken
		}
	}

	zones := flag.Args()
	if len(zones) == 0 {
		log.Fatal("please pass zone names as a positional arguments or specify \"__all__\"")
	}

	domainFilter, err := regexp.Compile(*ignoreRE)
	if err != nil {
		log.Fatalf("domain ignore regexp compilation error: %v", err)
	}

	targetEnum, err := enumerator.NewCFEnumerator(*CFAPIToken)
	if err != nil {
		log.Fatalf("unable to construct CFEnumerator: %v", err)
	}

	ctx, cl := context.WithTimeout(context.Background(), *timeout)
	defer cl()

	targetValidator := validator.NewConcurrentValidator(
		*expireTreshold,
		*rateLimitEvery,
		*oneTimeout,
		*retries,
		*verify,
	)

	var drain reporter.Reporter
	if *pagerDutyKey == "" {
		drain = reporter.NewMultiReporter(
			reporter.NewLogReporter(),
		)
	} else {
		drain = reporter.NewMultiReporter(
			reporter.NewLogReporter(),
			reporter.NewPagerDutyReporter(*pagerDutyKey),
		)
	}

	var beat heartbeat.Heartbeat = heartbeat.NewLogHeartbeat()
	if *heartbeatURL != "" {
		beat = heartbeat.NewURLHeartbeat(*heartbeatURL)
	}

	runner := workflow.NewRunner(targetEnum, domainFilter, targetValidator, drain, beat)
	err = runner.Run(ctx,
		zones,
		*scanIPv6,
		*ignoreConnectionErrors,
		*ignoreHandshakeErrors,
		*ignoreVerificationErrors,
		*ignoreExpirationErrors,
	)
	if err != nil {
		log.Fatalf("workflow error: %v", err)
	}

	return 0
}

func main() {
	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: %s [OPTIONS...] ZONE...\n", os.Args[0])
		flag.PrintDefaults()
	}
	log.Default().SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)
	os.Exit(run())
}
