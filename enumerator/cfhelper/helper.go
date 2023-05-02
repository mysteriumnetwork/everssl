package cfhelper

import (
	"context"
	"errors"
	"fmt"

	"github.com/cloudflare/cloudflare-go"
	"golang.org/x/net/idna"
)

// normalizeZoneName tries to convert IDNs (international domain names)
// from Punycode to Unicode form. If the given zone name is not represented
// as Punycode, or converting fails (for invalid representations), it
// is returned unchanged.
//
// Because all the zone name comparison is currently done using the API service
// (except for comparison with the empty string), theoretically, we could
// remove this function from the Go library. However, there should be no harm
// calling this function other than gelable performance penalty.
//
// Note: conversion errors are silently discarded.
func normalizeZoneName(name string) string {
	if n, err := idna.ToUnicode(name); err == nil {
		return n
	}
	return name
}

// ZoneIDByName retrieves a zone's ID from the name.
func ZoneIDByName(ctx context.Context, api *cloudflare.API, zoneName string) (string, string, error) {
	zoneName = normalizeZoneName(zoneName)
	res, err := api.ListZonesContext(ctx, cloudflare.WithZoneFilters(zoneName, "", ""))
	if err != nil {
		return "", "", fmt.Errorf("ListZonesContext command failed: %w", err)
	}

	switch len(res.Result) {
	case 0:
		return "", "", errors.New("zone could not be found")
	case 1:
		return res.Result[0].ID, res.Result[0].Account.ID, nil
	default:
		return "", "", errors.New("ambiguous zone name; an account ID might help")
	}
}
