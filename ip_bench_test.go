package mapcidr

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"math/rand"
	"net"
	"sort"
	"testing"
)

// benchmarkNetworks models host inventories and overlapping route lists. A fixed
// seed keeps the inputs identical across toolchains and implementations.
func benchmarkNetworks(n int, family string, hosts bool) []*net.IPNet {
	rng := rand.New(rand.NewSource(1))
	networks := make([]*net.IPNet, n)
	for i := range networks {
		ip := make(net.IP, net.IPv4len)
		binary.BigEndian.PutUint32(ip, 0x0a000000|rng.Uint32()&0x00ffffff)
		prefix := 24
		if hosts {
			prefix = 32
		}
		if family == "IPv6" {
			ip = make(net.IP, net.IPv6len)
			copy(ip, []byte{0x20, 0x01, 0x0d, 0xb8})
			binary.BigEndian.PutUint64(ip[8:], rng.Uint64())
			prefix = 120
			if hosts {
				prefix = 128
			}
		}
		mask := net.CIDRMask(prefix, len(ip)*8)
		networks[i] = &net.IPNet{IP: ip.Mask(mask), Mask: mask}
	}
	return networks
}

func BenchmarkFindMinCIDR(b *testing.B) {
	for _, family := range []string{"IPv4", "IPv6"} {
		for _, n := range []int{1, 2, 8, 256, 4096, 65536} {
			b.Run(fmt.Sprintf("%s/%d", family, n), func(b *testing.B) {
				networks := benchmarkNetworks(n, family, true)
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					result, err := FindMinCIDR(networks)
					if err != nil || result == nil {
						b.Fatalf("FindMinCIDR: %v", err)
					}
				}
			})
		}
	}
}

func BenchmarkFindMinCIDRInputOrder(b *testing.B) {
	for _, n := range []int{64, 65, 4096} {
		for _, order := range []string{"random", "ascending", "descending", "duplicate", "mapped", "mixed"} {
			b.Run(fmt.Sprintf("%s/%d", order, n), func(b *testing.B) {
				networks := benchmarkNetworks(n, "IPv4", true)
				switch order {
				case "ascending":
					sort.Slice(networks, func(i, j int) bool { return bytes.Compare(networks[i].IP, networks[j].IP) < 0 })
				case "descending":
					sort.Slice(networks, func(i, j int) bool { return bytes.Compare(networks[i].IP, networks[j].IP) > 0 })
				case "duplicate":
					for _, network := range networks {
						copy(network.IP, networks[0].IP)
					}
				case "mapped":
					for _, network := range networks {
						network.IP = network.IP.To16()
					}
				case "mixed":
					networks[len(networks)-1].IP = net.ParseIP("a80::1")
				}
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					result, err := FindMinCIDR(networks)
					if err != nil || result == nil {
						b.Fatalf("FindMinCIDR: %v", err)
					}
				}
			})
		}
	}
}

func BenchmarkCoalesceCIDRs(b *testing.B) {
	for _, family := range []string{"IPv4", "IPv6"} {
		for _, n := range []int{32, 1024, 16384} {
			b.Run(fmt.Sprintf("%s/%d", family, n), func(b *testing.B) {
				networks := benchmarkNetworks(n, family, false)
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					v4, v6 := CoalesceCIDRs(networks)
					if len(v4)+len(v6) == 0 {
						b.Fatal("empty coalesced result")
					}
				}
			})
		}
	}
}

func BenchmarkIPAddresses(b *testing.B) {
	for _, cidr := range []string{"192.0.2.0/24", "10.0.0.0/20", "2001:db8::/120"} {
		b.Run(cidr, func(b *testing.B) {
			_, network, err := net.ParseCIDR(cidr)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if ips := IPAddressesIPnet(network); uint64(len(ips)) != AddressCountIpnet(network) {
					b.Fatal("incorrect address count")
				}
			}
		})
	}
}

func BenchmarkIsExcluded(b *testing.B) {
	for _, family := range []string{"IPv4", "IPv6"} {
		for _, n := range []int{32, 1024} {
			b.Run(fmt.Sprintf("%s/%d", family, n), func(b *testing.B) {
				networks := benchmarkNetworks(n, family, true)
				ips := make([]net.IP, n)
				for i := range networks {
					ips[i] = networks[i].IP
				}
				queries := []net.IP{ips[0], ips[n/2], ips[n-1], net.ParseIP("203.0.113.1")}
				b.ReportAllocs()
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					if got := IsExcluded(ips, queries[i%len(queries)]); got != (i%len(queries) != 3) {
						b.Fatal("incorrect exclusion result")
					}
				}
			})
		}
	}
}
