package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/mysteriumnetwork/everssl/enumerator"
	"github.com/mysteriumnetwork/everssl/validator"
	"github.com/mysteriumnetwork/everssl/validator/result"
	"github.com/mysteriumnetwork/everssl/reporter"
)

var version = "undefined"

var (
	// global options
	showVersion = flag.Bool("version", false, "show program version and exit")
	timeout     = flag.Duration("timeout", 5*time.Minute, "overall scan timeout")

	// enumerator options
	CFAPIToken = flag.String("cf-api-token", "", "Cloudflare API token")
	zoneName   = flag.String("zone", "", "requested zone (domain) name")
	scanIPv6   = flag.Bool("6", true, "scan IPv6 origins")

	// validator options
	expireTreshold = flag.Duration("expire-treshold", 14*24*time.Hour, "expiration alarm treshold")
	rateLimitEvery = flag.Duration("rate-every", 100*time.Millisecond, "ratelimit period (inverse of frequency)")
	verify         = flag.Bool("verify", true, "verify certificates")

	// error filter options
	ignoreConnectionErrors   = flag.Bool("ignore-connection-errors", true, "ignore connection errors")
	ignoreHandshakeErrors    = flag.Bool("ignore-handshake-errors", true, "ignore handshake errors")
	ignoreVerificationErrors = flag.Bool("ignore-verification-errors", true, "ignore certificate verification errors")
	ignoreExpirationErrors   = flag.Bool("ignore-expiration-errors", false, "ignore expiration errors")
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

	if *zoneName == "" {
		log.Fatal("zone is not specified")
	}

	var (
		targetEnum enumerator.Enumerator
		err        error
	)
	targetEnum, err = enumerator.NewCFEnumerator(*CFAPIToken)
	if err != nil {
		log.Fatalf("unable to construct CFEnumerator: %v", err)
	}

	ctx, cl := context.WithTimeout(context.Background(), *timeout)
	defer cl()

	targets, err := targetEnum.Enumerate(ctx, *zoneName, *scanIPv6)
	if err != nil {
		log.Fatalf("unable to enumerate targets: %v", err)
	}

	var targetValidator validator.Validator = validator.NewConcurrentValidator(
		*expireTreshold,
		*rateLimitEvery,
		*verify,
	)

	results, err := targetValidator.Validate(ctx, targets)
	if err != nil {
		log.Fatal(err)
	}

	var filteredResults []result.ValidationResult
	for _, res := range results {
		if res.Error == nil {
			filteredResults = append(filteredResults, res)
		} else {
			switch res.Error.Kind() {
			case result.ConnectionError:
				if !*ignoreConnectionErrors {
					filteredResults = append(filteredResults, res)
				}
			case result.HandshakeError:
				if !*ignoreHandshakeErrors {
					filteredResults = append(filteredResults, res)
				}
			case result.VerificationError:
				if !*ignoreVerificationErrors {
					filteredResults = append(filteredResults, res)
				}
			case result.ExpirationError:
				if !*ignoreExpirationErrors {
					filteredResults = append(filteredResults, res)
				}
			default:
				filteredResults = append(filteredResults, res)
			}
		}
	}
	results = nil

	var drain reporter.Reporter = reporter.NewLogReporter()
	drain.Report(ctx, filteredResults)

	return 0
}

func main() {
	log.Default().SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)
	os.Exit(run())
}
