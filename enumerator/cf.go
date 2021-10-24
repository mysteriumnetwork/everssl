package enumerator

import (
	"context"
	"log"
	"net"

	"github.com/cloudflare/cloudflare-go"

	"github.com/mysteriumnetwork/everssl/enumerator/cfhelper"
)

const (
	MaxRetries = 3
	MinRetryDelaySecs = 1
	MaxRetryDelaySecs = 10
)

var CFWorkersBackendAddress = net.ParseIP("100::")

type CFEnumerator struct {
	api *cloudflare.API
}

func NewCFEnumerator(apiToken string) (*CFEnumerator, error) {
	api, err := cloudflare.NewWithAPIToken(apiToken,
		cloudflare.UsingRetryPolicy(MaxRetries, MinRetryDelaySecs, MaxRetryDelaySecs))
	if err != nil {
		return nil, err
	}

	return &CFEnumerator{
		api: api,
	}, nil
}

func (e *CFEnumerator) Enumerate(ctx context.Context, zone string, ipv6 bool) ([]Target, error) {
	zoneID, err := cfhelper.ZoneIDByName(ctx, e.api, zone)
	if err != nil {
		return nil, err
	}

	recs, err := e.api.DNSRecords(ctx, zoneID, cloudflare.DNSRecord{Type: "A"})
	if err != nil {
		return nil, err
	}

	if ipv6 {
		ipv6recs, err := e.api.DNSRecords(ctx, zoneID, cloudflare.DNSRecord{Type: "AAAA"})
		if err != nil {
			return nil, err
		}
		recs = append(recs, ipv6recs...)
	}

	var res []Target

	for _, record := range recs {
		ip := net.ParseIP(record.Content)
		if ip == nil {
			log.Printf("WARNING! IP %q parse failed for record %s (ID=%q). Skipping it...",
				record.Content, record.Name, record.ID)
			continue
		}

		// Skip fake address records created for originless domains
		if ip.Equal(CFWorkersBackendAddress) {
			continue
		}

		// Add target for the domain name directly to origin server
		res = append(res, Target{
			Domain: record.Name,
			IPOverride: ip.String(),
		})

		if record.Proxied != nil && *record.Proxied {
			// Add target for the domain name via CF
			res = append(res, Target{
				Domain: record.Name,
				IPOverride: "",
			})
		}
	}

	return res, nil
}
