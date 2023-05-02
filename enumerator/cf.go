package enumerator

import (
	"context"
	"fmt"
	"log"
	"net"
	"sync"

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
	api           *cloudflare.API
	poolAddresses map[string][]string
	paMux         sync.RWMutex
}

func NewCFEnumerator(apiToken string) (*CFEnumerator, error) {
	api, err := cloudflare.NewWithAPIToken(apiToken,
		cloudflare.UsingRetryPolicy(MaxRetries, MinRetryDelaySecs, MaxRetryDelaySecs))
	if err != nil {
		return nil, fmt.Errorf("can't instantiate Cloudflare API client: %w", err)
	}

	return &CFEnumerator{
		api:           api,
		poolAddresses: make(map[string][]string),
	}, nil
}

func (e *CFEnumerator) Enumerate(ctx context.Context, zone string, ipv6 bool) ([]target.Target, error) {
	if zone == "__all__" {
		return e.enumerateAllDomains(ctx, ipv6)
	}

	zoneID, accountID, err := cfhelper.ZoneIDByName(ctx, e.api, zone)
	if err != nil {
		return nil, fmt.Errorf("ZoneIDByName failed: %w", err)
	}

	return e.enumerateDomain(ctx, accountID, zoneID, ipv6)
}

func (e *CFEnumerator) resolveLBPool(ctx context.Context, accountID, poolID string) ([]string, error) {
	e.paMux.RLock()
	addresses, ok := e.poolAddresses[poolID]
	e.paMux.RUnlock()
	if ok {
		return addresses, nil
	}

	pool, err := e.api.GetLoadBalancerPool(ctx, cloudflare.AccountIdentifier(accountID), poolID)
	if err != nil {
		return nil, fmt.Errorf("GetLoadBalancerPool failed: %w", err)
	}
	for _, origin := range pool.Origins {
		addresses = append(addresses, origin.Address)
	}

	e.paMux.Lock()
	defer e.paMux.Unlock()
	e.poolAddresses[poolID] = addresses

	return addresses, nil
}

func (e *CFEnumerator) enumerateAllDomains(ctx context.Context, ipv6 bool) ([]target.Target, error) {
	lzr, err := e.api.ListZonesContext(ctx)
	if err != nil {
		return nil, fmt.Errorf("ListZones failed: %w", err)
	}

	var result []target.Target
	for _, zone := range lzr.Result {
		zoneTargets, err := e.enumerateDomain(ctx, zone.Account.ID, zone.ID, ipv6)
		if err != nil {
			return nil, fmt.Errorf("enumerateDomain %q (zoneID=%q accountID=%q) failed: %w", zone.Name, zone.Account.ID, zone.ID, err)
		}

		result = append(result, zoneTargets...)
	}

	return result, nil
}

func (e *CFEnumerator) enumerateDomain(ctx context.Context, accountID, zoneID string, ipv6 bool) ([]target.Target, error) {
	targets := make(map[target.Target]struct{})

	unfilteredRecs, _, err := e.api.ListDNSRecords(ctx, cloudflare.ZoneIdentifier(zoneID), cloudflare.ListDNSRecordsParams{})
	if err != nil {
		return nil, fmt.Errorf("ListDNSRecords failed: %w", err)
	}

	var recs []cloudflare.DNSRecord
	for _, rec := range unfilteredRecs {
		switch rec.Type {
		case "A", "CNAME":
			recs = append(recs, rec)
		case "AAAA":
			if ipv6 {
				recs = append(recs, rec)
			}
		}
	}

	for _, record := range recs {
		checkOrigin := true
		checkProxy := true
		switch record.Type {
		case "A", "AAAA":
			ip := net.ParseIP(record.Content)

			var fakeOrigin bool
			if ip != nil && ip.Equal(CFWorkersBackendAddress) {
				fakeOrigin = false
			} else {
				fakeOrigin = true
			}

			checkOrigin = !(record.Proxied != nil && *record.Proxied && fakeOrigin)
			checkProxy = record.Proxied != nil && *record.Proxied
		case "CNAME":
			checkProxy = record.Proxied != nil && *record.Proxied
			checkOrigin = true
		}

		// Add target for the domain name directly to origin server
		if checkOrigin {
			targets[target.Target{
				Domain:  record.Name,
				Address: record.Content,
			}] = struct{}{}
			log.Printf("new target (origin, %s record): %q -> %q", record.Type, record.Name, record.Content)
		}

		// Add target for the domain name via CF
		if checkProxy {
			targets[target.Target{
				Domain:  record.Name,
				Address: "",
			}] = struct{}{}
			log.Printf("new target (proxied, %s record): %q -> %q", record.Type, record.Name, record.Name)
		}
	}

	lbs, err := e.api.ListLoadBalancers(ctx,
		cloudflare.ZoneIdentifier(zoneID),
		cloudflare.ListLoadBalancerParams{},
	)
	if err != nil {
		return nil, fmt.Errorf("ListLoadBalancers failed: %w", err)
	}

	for _, lb := range lbs {
		if lb.Proxied {
			targets[target.Target{
				Domain:  lb.Name,
				Address: "",
			}] = struct{}{}
			log.Printf("new target (proxied, LB): %q -> %q", lb.Name, "")
		}
		pools := lb.DefaultPools
		pools = append(pools, lb.FallbackPool)
		for _, pool := range lb.RegionPools {
			pools = append(pools, pool...)
		}
		for _, pool := range lb.PopPools {
			pools = append(pools, pool...)
		}
		for _, pool := range lb.CountryPools {
			pools = append(pools, pool...)
		}

		for _, pool := range pools {
			addresses, err := e.resolveLBPool(ctx, accountID, pool)
			if err != nil {
				return nil, fmt.Errorf("resolveLBPool failed: %w", err)
			}

			for _, addr := range addresses {
				targets[target.Target{
					Domain:  lb.Name,
					Address: addr,
				}] = struct{}{}
				log.Printf("new target (origin, LB): %q -> %q", lb.Name, addr)
			}
		}

	}

	res := make([]target.Target, 0, len(targets))

	for k, _ := range targets {
		res = append(res, k)
	}

	return res, nil
}
