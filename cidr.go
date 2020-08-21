package mapcidr

import (
	"encoding/binary"
	"fmt"
	"math"
	"math/big"
	"net"
	"reflect"
)

// Note: parts of the code comes from various sources including github, stackoverflow

// AddressRange returns the first and last addresses in the given CIDR range.
func AddressRange(network *net.IPNet) (net.IP, net.IP) {
	firstIP := network.IP

	prefixLen, bits := network.Mask.Size()
	if prefixLen == bits {
		lastIP := make([]byte, len(firstIP))
		copy(lastIP, firstIP)
		return firstIP, lastIP
	}

	firstIPInt, bits, _ := ipToInt(firstIP)
	hostLen := uint(bits) - uint(prefixLen)
	lastIPInt := big.NewInt(1)
	lastIPInt.Lsh(lastIPInt, hostLen)
	lastIPInt.Sub(lastIPInt, big.NewInt(1))
	lastIPInt.Or(lastIPInt, firstIPInt)

	return firstIP, intToIP(lastIPInt, bits)
}

// AddressCount ips in a CIDR range
func AddressCount(cidr string) uint64 {
	_, ipnet, _ := net.ParseCIDR(cidr)
	return AddressCountIpnet(ipnet)
}

// AddressCountIpnet ips in a ipnet
func AddressCountIpnet(network *net.IPNet) uint64 {
	prefixLen, bits := network.Mask.Size()
	return 1 << (uint64(bits) - uint64(prefixLen))
}

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

// SplitByNumber splits the given cidr into subnets with the closest number of hosts per subnet
func SplitByNumber(iprange string, number int) []*net.IPNet {
	_, ipnet, _ := net.ParseCIDR(iprange)
	return SplitByNumberIpnet(ipnet, number)
}

// SplitByNumberIpnet splits ipnet into subnets with the closest number of hosts per subnet
func SplitByNumberIpnet(ipnet *net.IPNet, number int) []*net.IPNet {
	ipsNumber := AddressCountIpnet(ipnet)
	// truncate result to nearest uint64
	optimalSplit := int(ipsNumber / uint64(number))
	return SplitNIpnet(ipnet, optimalSplit)
}

// SplitN attempts to split a cidr in the exact number of subnets
func SplitN(iprange string, n int) (subnets []*net.IPNet) {
	_, ipnet, _ := net.ParseCIDR(iprange)
	return SplitNIpnet(ipnet, n)
}

// SplitNIpnet attempts to split a ipnet in the exact number of subnets
func SplitNIpnet(iprange *net.IPNet, n int) (subnets []*net.IPNet) {
	// Note: the code and logic aren't really optimized, it just works - any improvement is welcome

	// invalid value
	if n <= 1 || AddressCountIpnet(iprange) < uint64(n) {
		subnets = append(subnets, iprange)
		return
	}
	// power of two
	if isPowerOfTwo(n) || isPowerOfTwoPlusOne(n) {
		return splitIpnet(iprange, n)
	}

	var closestMinorPowerOfTwo int
	// find the closest power of two in a stupid way
	for i := n; i > 0; i-- {
		if isPowerOfTwo(i) {
			closestMinorPowerOfTwo = i
			break
		}
	}

	subnets = splitIpnet(iprange, closestMinorPowerOfTwo)
	for len(subnets) < n {
		var newSubnets []*net.IPNet
		level := 1
		for i := len(subnets) - 1; i >= 0; i-- {
			newSubnets = append(newSubnets, divideIpNet(subnets[i])...)
			if len(subnets)-level+len(newSubnets) == n {
				reverseAny(newSubnets)
				subnets = subnets[:len(subnets)-level]
				subnets = append(subnets, newSubnets...)
				return
			}
			level++
		}
		reverseAny(newSubnets)
		subnets = newSubnets
	}
	return
}

func divide(iprange string) (subnets []*net.IPNet) {
	_, ipnet, _ := net.ParseCIDR(iprange)
	return divideIpNet(ipnet)
}

func divideIpNet(ipnet *net.IPNet) (subnets []*net.IPNet) {
	maskBits, _ := ipnet.Mask.Size()
	wantedMaskBits := maskBits + 1

	currentSubnet := currentSubnet(ipnet, wantedMaskBits)
	subnets = append(subnets, currentSubnet)
	nextSubnet, _ := nextSubnet(currentSubnet, wantedMaskBits)
	subnets = append(subnets, nextSubnet)

	return subnets
}

func splitIpnet(ipnet *net.IPNet, n int) (subnets []*net.IPNet) {
	maskBits, _ := ipnet.Mask.Size()

	closestPow2 := int(closestPowerOfTwo(uint32(n)))

	pow2 := int(math.Log2(float64(closestPow2)))

	wantedMaskBits := maskBits + pow2

	currentSubnet := currentSubnet(ipnet, wantedMaskBits)
	subnets = append(subnets, currentSubnet)
	nxtSubnet := currentSubnet
	for i := 0; i < closestPow2-1; i++ {
		nxtSubnet, _ = nextSubnet(nxtSubnet, wantedMaskBits)
		subnets = append(subnets, nxtSubnet)
	}

	if len(subnets) < n {
		lastSubnet := subnets[len(subnets)-1]
		subnets = subnets[:len(subnets)-1]
		subnets = append(subnets, divideIpNet(lastSubnet)...)
	}

	return subnets
}

func split(iprange string, n int) (subnets []*net.IPNet) {
	_, ipnet, _ := net.ParseCIDR(iprange)
	return splitIpnet(ipnet, n)
}

func ipToInt(ip net.IP) (*big.Int, int, error) {
	val := &big.Int{}
	val.SetBytes([]byte(ip))
	if len(ip) == net.IPv4len {
		return val, 32, nil
	} else if len(ip) == net.IPv6len {
		return val, 128, nil
	} else {
		return nil, 0, fmt.Errorf("Unsupported address length %d", len(ip))
	}
}

func intToIP(ipInt *big.Int, bits int) net.IP {
	ipBytes := ipInt.Bytes()
	ret := make([]byte, bits/8)
	for i := 1; i <= len(ipBytes); i++ {
		ret[len(ret)-i] = ipBytes[len(ipBytes)-i]
	}
	return net.IP(ret)
}

func nextPowerOfTwo(v uint32) uint32 {
	v--
	v |= v >> 1
	v |= v >> 2
	v |= v >> 4
	v |= v >> 8
	v |= v >> 16
	v++
	return v
}

func closestPowerOfTwo(v uint32) uint32 {
	next := nextPowerOfTwo(v)
	if prev := next / 2; (v - prev) < (next - v) {
		next = prev
	}
	return next
}

func currentSubnet(network *net.IPNet, prefixLen int) *net.IPNet {
	currentFirst, _ := AddressRange(network)
	mask := net.CIDRMask(prefixLen, 8*len(currentFirst))
	return &net.IPNet{IP: currentFirst.Mask(mask), Mask: mask}
}

func previousSubnet(network *net.IPNet, prefixLen int) (*net.IPNet, bool) {
	startIP := network.IP
	previousIP := make(net.IP, len(startIP))
	copy(previousIP, startIP)
	cMask := net.CIDRMask(prefixLen, 8*len(previousIP))
	previousIP = dec(previousIP)
	previous := &net.IPNet{IP: previousIP.Mask(cMask), Mask: cMask}
	if startIP.Equal(net.IPv4zero) || startIP.Equal(net.IPv6zero) {
		return previous, true
	}
	return previous, false
}

func nextSubnet(network *net.IPNet, prefixLen int) (*net.IPNet, bool) {
	_, currentLast := AddressRange(network)
	mask := net.CIDRMask(prefixLen, 8*len(currentLast))
	currentSubnet := &net.IPNet{IP: currentLast.Mask(mask), Mask: mask}
	_, last := AddressRange(currentSubnet)
	last = inc(last)
	next := &net.IPNet{IP: last.Mask(mask), Mask: mask}
	if last.Equal(net.IPv4zero) || last.Equal(net.IPv6zero) {
		return next, true
	}
	return next, false
}

func isPowerOfTwoPlusOne(x int) bool {
	return isPowerOfTwo(x - 1)
}

func isPowerOfTwo(x int) bool {
	return x != 0 && (x&(x-1)) == 0
}

func reverseAny(s interface{}) {
	n := reflect.ValueOf(s).Len()
	swap := reflect.Swapper(s)
	for i, j := 0, n-1; i < j; i, j = i+1, j-1 {
		swap(i, j)
	}
}

// Ips of a cidr
func Ips(cidr string) ([]string, error) {
	_, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return []string{}, err
	}
	return ipsIpnet(ipnet), nil
}

func ipsIpnet(ipv4Net *net.IPNet) (ips []string) {
	// convert IPNet struct mask and address to uint32
	mask := binary.BigEndian.Uint32(ipv4Net.Mask)
	start := binary.BigEndian.Uint32(ipv4Net.IP)

	// find the final address
	finish := (start & mask) | (mask ^ 0xffffffff)

	// loop through addresses as uint32
	for i := start; i <= finish; i++ {
		// convert back to net.IP
		ip := make(net.IP, 4)
		binary.BigEndian.PutUint32(ip, i)
		ips = append(ips, ip.String())
	}

	return ips
}
