package mapcidr

import (
	"net"

	"github.com/projectdiscovery/blackrock"
)

func ShuffleCidrsWithSeed(cidrs []*net.IPNet, seed int64) chan Item {
	// Shrink and compact
	cidrs, _ = CoalesceCIDRs(cidrs)
	out := make(chan Item)
	go func(out chan Item, cidrs []*net.IPNet) {
		defer close(out)
		targetsCount := int64(TotalIPSInCidrs(cidrs))
		Range := targetsCount
		br := blackrock.New(Range, seed)
		for index := int64(0); index < Range; index++ {
			ipIndex := br.Shuffle(index)
			ip := PickIP(cidrs, ipIndex)
			if ip == "" {
				continue
			}
			out <- Item{IP: ip}
		}
	}(out, cidrs)
	return out
}

func ShuffleCidrsWithPortsAndSeed(cidrs []*net.IPNet, ports []int, seed int64) chan Item {
	// Shrink and compact
	cidrs, _ = CoalesceCIDRs(cidrs)
	out := make(chan Item)
	go func(out chan Item, cidrs []*net.IPNet) {
		defer close(out)
		targetsCount := int64(TotalIPSInCidrs(cidrs))
		portsCount := int64(len(ports))
		Range := targetsCount * portsCount
		br := blackrock.New(Range, seed)
		for index := int64(0); index < Range; index++ {
			xxx := br.Shuffle(index)
			ipIndex := xxx / portsCount
			portIndex := int(xxx % portsCount)
			ip := PickIP(cidrs, ipIndex)
			port := PickPort(ports, portIndex)

			if ip == "" || port <= 0 {
				continue
			}
			out <- Item{IP: ip, Port: port}
		}
	}(out, cidrs)
	return out
}

func PickIP(cidrs []*net.IPNet, index int64) string {
	for _, target := range cidrs {
		subnetIpsCount := int64(AddressCountIpnet(target))
		if index < subnetIpsCount {
			return PickSubnetIP(target, index)
		}
		index -= subnetIpsCount
	}

	return ""
}

func PickSubnetIP(network *net.IPNet, index int64) string {
	return Inet_ntoa(Inet_aton(network.IP) + index).String()
}

func PickPort(ports []int, index int) int {
	return ports[index]
}

func CIDRsAsIPNET(cidrs []string) (ipnets []*net.IPNet) {
	for _, cidr := range cidrs {
		ipnets = append(ipnets, AsIPV4CIDR(cidr))
	}
	return
}
