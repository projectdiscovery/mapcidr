package mapcidr

import "net"

// inc increments an IP address to the next IP in the subnet
func inc(IP net.IP) net.IP {
	incIP := make([]byte, len(IP))
	copy(incIP, IP)
	for j := len(incIP) - 1; j >= 0; j-- {
		incIP[j]++
		if incIP[j] > 0 {
			break
		}
	}
	return incIP
}

// dec decrements an IP address to the previous IP in the subnet
func dec(IP net.IP) net.IP {
	decIP := make([]byte, len(IP))
	copy(decIP, IP)
	for j := len(decIP) - 1; j >= 0; j-- {
		decIP[j]--
		if decIP[j] < 255 {
			break
		}
	}
	return decIP
}

func TotalIPSInCidrs(cidrs []*net.IPNet) (totalIPs uint64) {
	for _, cidr := range cidrs {
		totalIPs += AddressCountIpnet(cidr)
	}

	return
}

func AsIPV4CIDR(IPV4 string) *net.IPNet {
	if IsIPv4(net.ParseIP(IPV4)) {
		IPV4 += "/32"
	}
	_, network, err := net.ParseCIDR(IPV4)
	if err != nil {
		return nil
	}
	return network
}
