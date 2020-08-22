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
