package mapcidr

import "net"

// inc increments an IP address to the next IP in the subnet
func inc(ip net.IP) net.IP {
	incIP := make([]byte, len(ip))
	copy(incIP, ip)
	for j := len(incIP) - 1; j >= 0; j-- {
		incIP[j]++
		if incIP[j] > 0 {
			break
		}
	}
	return incIP
}

// TotalIPSInCidrs calculates the number of ips in the diven cidrs
func TotalIPSInCidrs(cidrs []*net.IPNet) (totalIPs uint64) {
	for _, cidr := range cidrs {
		totalIPs += AddressCountIpnet(cidr)
	}

	return
}

// AsIPV4CIDR converts ipv4 address to cidr representation
func AsIPV4CIDR(ipv4 string) *net.IPNet {
	if IsIPv4(net.ParseIP(ipv4)) {
		ipv4 += "/32"
	}
	_, network, err := net.ParseCIDR(ipv4)
	if err != nil {
		return nil
	}
	return network
}
