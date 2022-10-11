package asn

import (
	"fmt"
	"net"
	"strconv"
	"strings"

	asnmap "github.com/projectdiscovery/asnmap/libs"
	"github.com/projectdiscovery/mapcidr"
)

type ASNClient struct {
	client *asnmap.Client
}

func New() ASNClient {
	return ASNClient{
		client: asnmap.NewClient(),
	}
}

// GetCIDRsForASNNum returns the slice of cidrs for given ASN number
// accept the ASN number like 'AS15133' and returns the CIDRs for that ASN
func (c *ASNClient) GetCIDRsForASNNum(value string) ([]*net.IPNet, error) {
	var cidrs []*net.IPNet
	if len(value) < 3 {
		return nil, fmt.Errorf("invalid asn number %s", value)
	}
	// drop the AS suffix
	asn := asnmap.ASN(value[2:])
	for _, cidr := range asnmap.GetCIDR(c.client.GetData(asn)) {
		// filter IPv6 CIDR
		if mapcidr.IsIPv4(cidr.IP) {
			cidrs = append(cidrs, cidr)
		}
	}
	return cidrs, nil
}

// GetIPAddressesAsStream returns the chan of IP address for given ASN number
func (c *ASNClient) GetIPAddressesAsStream(value string) (chan string, error) {
	cidrs, err := c.GetCIDRsForASNNum(value)
	if err != nil {
		return nil, err
	}
	ret := make(chan string)
	go func() {
		defer close(ret)
		for _, cidr := range cidrs {
			ips, _ := mapcidr.IPAddressesAsStream(cidr.String())
			for ip := range ips {
				ret <- ip
			}
		}
	}()
	return ret, nil
}

// IsASN checks if the given input is ASN or not,
// its possible to have an domain name starting with AS/as prefix.
func IsASN(value string) bool {
	if len(value) > 2 && strings.HasPrefix(strings.ToUpper(value), "AS") {
		_, err := strconv.Atoi(value[2:])
		return err == nil
	}
	return false
}
