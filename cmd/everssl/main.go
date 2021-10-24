package main

import (
	"context"
	"fmt"
	"log"
	"os"

	"github.com/cloudflare/cloudflare-go"

	"github.com/mysteriumnetwork/everssl/cfhelper"
)

func run() int {
	// Construct a new API object
	api, err := cloudflare.NewWithAPIToken(os.Getenv("CLOUDFLARE_API_KEY"), cloudflare.UsingRetryPolicy(3, 1, 10))
	if err != nil {
		log.Fatal(err)
	}

	// Most API calls require a Context
	ctx := context.Background()

	// Fetch the zone ID
	zoneID, err := cfhelper.ZoneIDByName(ctx, api, "mysterium.network")
	if err != nil {
		log.Fatal(err)
	}

	// Fetch only A type records
	aTypeRecord := cloudflare.DNSRecord{Type: "A"}
	aRecs, err := api.DNSRecords(ctx, zoneID, aTypeRecord)
	if err != nil {
		log.Fatal(err)
	}

	for _, r := range aRecs {
		fmt.Printf("%s: %s\n", r.Name, r.Content)
	}

	return 0
}

func main() {
	log.Default().SetFlags(log.Ldate | log.Ltime | log.Lmicroseconds | log.Lshortfile)
	os.Exit(run())
}
