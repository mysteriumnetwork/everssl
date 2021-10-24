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
)

var version = "undefined"

var (
	showVersion = flag.Bool("version", false, "show program version and exit")

	timeout = flag.Duration("timeout", 1*time.Minute, "overall scan timeout")

	CFAPIToken = flag.String("cf-api-token", "", "Cloudflare API token")
	zoneName   = flag.String("zone", "", "requested zone (domain) name")
	scanIPv6   = flag.Bool("6", false, "scan IPv6 origins")

	expireTreshold = flag.Duration("expire-treshold", 7*24*time.Hour, "expiration alarm treshold")
	rateLimitEvery = flag.Duration("rate-every", 100*time.Millisecond, "ratelimit period (inverse of frequency)")
	verify         = flag.Bool("verify", true, "verify certificates")
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

	for _, result := range results {
		if result.Error != nil {
			fmt.Printf("%+v\n", result)
		}
	}

	return 0
}

func main() {
	log.Default().SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)
	os.Exit(run())
}
