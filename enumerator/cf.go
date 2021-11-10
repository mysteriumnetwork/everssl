package enumerator

import (
	"context"
	"net"

	"github.com/cloudflare/cloudflare-go"

	"github.com/mysteriumnetwork/everssl/enumerator/cfhelper"
	"github.com/mysteriumnetwork/everssl/target"
)

const (
	MaxRetries        = 3
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

func (e *CFEnumerator) Enumerate(ctx context.Context, zone string, ipv6 bool) ([]target.Target, error) {
	if zone == "__all__" {
		return e.enumerateAllDomains(ctx, ipv6)
	}

	zoneID, err := cfhelper.ZoneIDByName(ctx, e.api, zone)
	if err != nil {
		return nil, err
	}

	return e.enumerateDomain(ctx, zoneID, ipv6)
}

func (e *CFEnumerator) enumerateAllDomains(ctx context.Context, ipv6 bool) ([]target.Target, error) {
	zones, err := e.api.ListZones(ctx)
	if err != nil {
		return nil, err
	}

	var result []target.Target
	for _, zone := range zones {
		zoneTargets, err := e.enumerateDomain(ctx, zone.ID, ipv6)
		if err != nil {
			return nil, err
		}

		result = append(result, zoneTargets...)
	}

	return result, nil
}

func (e *CFEnumerator) enumerateDomain(ctx context.Context, zoneID string, ipv6 bool) ([]target.Target, error) {
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

	var res []target.Target

	for _, record := range recs {
		ip := net.ParseIP(record.Content)

		var fakeOrigin bool
		if ip != nil && ip.Equal(CFWorkersBackendAddress) {
			fakeOrigin = false
		} else {
			fakeOrigin = true
		}

		hasFront := record.Proxied != nil && *record.Proxied
		checkOrigin := !(hasFront && fakeOrigin)

		// Add target for the domain name directly to origin server
		if checkOrigin {
			res = append(res, target.Target{
				Domain:  record.Name,
				Address: record.Content,
			})
		}

		// Add target for the domain name via CF
		if hasFront {
			res = append(res, target.Target{
				Domain:  record.Name,
				Address: "",
			})
		}
	}

	return res, nil
}
