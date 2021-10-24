package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"os"
	"time"

	"github.com/cloudflare/cloudflare-go"

	"github.com/mysteriumnetwork/everssl/cfhelper"
)

var version = "undefined"

var (
	showVersion = flag.Bool("version", false, "show program version and exit")

	CFAPIToken = flag.String("cf-api-token", "", "Cloudflare API token")
	zoneName   = flag.String("zone", "", "requested zone (domain) name")
	timeout    = flag.Duration("timeout", 1*time.Minute, "overall scan timeout")
	scanIPv6   = flag.Bool("6", false, "scan IPv6 origins")
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

	api, err := cloudflare.NewWithAPIToken(*CFAPIToken, cloudflare.UsingRetryPolicy(3, 1, 10))
	if err != nil {
		log.Fatal(err)
	}

	ctx, cl := context.WithTimeout(context.Background(), *timeout)
	defer cl()

	zoneID, err := cfhelper.ZoneIDByName(ctx, api, *zoneName)
	if err != nil {
		log.Fatal(err)
	}

	recs, err := api.DNSRecords(ctx, zoneID, cloudflare.DNSRecord{Type: "A"})
	if err != nil {
		log.Fatal(err)
	}

	if *scanIPv6 {
		ipv6recs, err := api.DNSRecords(ctx, zoneID, cloudflare.DNSRecord{Type: "AAAA"})
		if err != nil {
			log.Fatal(err)
		}
		recs = append(recs, ipv6recs...)
	}

	for _, r := range recs {
		fmt.Printf("%s: %s\n", r.Name, r.Content)
	}

	return 0
}

func main() {
	log.Default().SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)
	os.Exit(run())
}
