package mapcidr

import (
	"bytes"
	"math/big"
	"net"
	"reflect"
	"sort"
	"testing"
)

// IntegerToIP round-trips IPToInteger and, for ipInt >= 2^bits, wraps (mod 2^bits)
// instead of panicking with a negative index.
func TestIntegerToIPOverflow(t *testing.T) {
	for _, s := range []string{"0.0.0.0", "10.0.0.1", "255.255.255.255", "192.168.1.1"} {
		i, bits, err := IPToInteger(net.ParseIP(s))
		if err != nil {
			t.Fatalf("IPToInteger(%s): %v", s, err)
		}
		if got := IntegerToIP(i, bits).String(); got != s {
			t.Errorf("round-trip %s => %s", s, got)
		}
	}
	// 2^32 wraps to 0.0.0.0; 2^32 + 0x0a000001 wraps to 10.0.0.1.
	over := new(big.Int).Lsh(big.NewInt(1), 32)
	if got := IntegerToIP(over, 32).String(); got != "0.0.0.0" {
		t.Errorf("overflow 2^32 => %s, want 0.0.0.0", got)
	}
	over.Add(over, big.NewInt(0x0a000001))
	if got := IntegerToIP(over, 32).String(); got != "10.0.0.1" {
		t.Errorf("overflow 2^32+10.0.0.1 => %s, want 10.0.0.1", got)
	}
	// 1<<40 previously panicked: index out of range [-1]
	shift40 := new(big.Int).Lsh(big.NewInt(1), 40)
	if got := IntegerToIP(shift40, 32).String(); got != "0.0.0.0" {
		t.Errorf("overflow 2^40 => %s, want 0.0.0.0", got)
	}
}

func TestSplitIPNetIntoN(t *testing.T) {
	tests := []struct {
		name    string
		iprange string
		n       int
		want    []string
		wantErr bool
	}{
		{
			name:    "IPv4 split into 2",
			iprange: "192.168.1.0/24",
			n:       2,
			want:    []string{"192.168.1.0/25", "192.168.1.128/25"},
			wantErr: false,
		},
		{
			name:    "IPv6 split into 2",
			iprange: "fd80::/9",
			n:       2,
			want:    []string{"fd80::/10", "fdc0::/10"},
			wantErr: false,
		},
		{
			name:    "IPv4 split into 4",
			iprange: "10.0.0.0/8",
			n:       4,
			want:    []string{"10.0.0.0/10", "10.64.0.0/10", "10.128.0.0/10", "10.192.0.0/10"},
			wantErr: false,
		},
		{
			name:    "IPv6 split into 3 (non-power of 2)",
			iprange: "2001:db8::/48",
			n:       3,
			// Expecting it to split into closest power of 2 (2) then subdivide the last one
			want:    []string{"2001:db8::/49", "2001:db8:0:8000::/50", "2001:db8:0:c000::/50"},
			wantErr: false,
		},
		{
			name:    "Split into 1",
			iprange: "192.168.1.0/24",
			n:       1,
			want:    []string{"192.168.1.0/24"},
			wantErr: false,
		},
		{
			name:    "Split into 0",
			iprange: "192.168.1.0/24",
			n:       0,
			want:    []string{"192.168.1.0/24"},
			wantErr: false,
		},
		{
			name:    "Impossible split (IPv4)",
			iprange: "192.168.1.1/32",
			n:       2,
			want:    []string{"192.168.1.1/32"}, // Cannot split a /32
			wantErr: false,
		},
		{
			name:    "Impossible split (IPv6)",
			iprange: "::1/128",
			n:       4,
			want:    []string{"::1/128"}, // Cannot split a /128
			wantErr: false,
		},
		{
			name:    "Split large IPv6",
			iprange: "2001:db8::/32",
			n:       16,
			want: []string{
				"2001:db8::/36", "2001:db8:1000::/36", "2001:db8:2000::/36", "2001:db8:3000::/36",
				"2001:db8:4000::/36", "2001:db8:5000::/36", "2001:db8:6000::/36", "2001:db8:7000::/36",
				"2001:db8:8000::/36", "2001:db8:9000::/36", "2001:db8:a000::/36", "2001:db8:b000::/36",
				"2001:db8:c000::/36", "2001:db8:d000::/36", "2001:db8:e000::/36", "2001:db8:f000::/36",
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ipnet, err := net.ParseCIDR(tt.iprange)
			if err != nil {
				t.Fatalf("Failed to parse CIDR %s: %v", tt.iprange, err)
			}

			gotNets, err := SplitIPNetIntoN(ipnet, tt.n)
			if (err != nil) != tt.wantErr {
				t.Errorf("SplitIPNetIntoN() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			var got []string
			for _, n := range gotNets {
				got = append(got, n.String())
			}

			// NOTE(dwisiswant0): just in case we need to compare IPNets in the future
			// var wantNets []*net.IPNet
			// for _, w := range tt.want {
			// 	_, wn, _ := net.ParseCIDR(w)
			// 	wantNets = append(wantNets, wn)
			// }

			// Simple string comparison for now
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("SplitIPNetIntoN() got = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestSplitIPNetByNumberInvalidCount(t *testing.T) {
	tests := []struct {
		name    string
		iprange string
		number  int
	}{
		{name: "zero hosts per subnet", iprange: "192.168.0.0/16", number: 0},
		{name: "negative hosts per subnet", iprange: "192.168.0.0/16", number: -1},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotNets, err := SplitByNumber(tt.iprange, tt.number)
			if err == nil {
				t.Errorf("SplitByNumber() error = nil, want an error; got %v", gotNets)
			}
			if gotNets != nil {
				t.Errorf("SplitByNumber() = %v, want nil", gotNets)
			}
		})
	}
}

// assertPartitionsInput verifies that got is a disjoint partition of want with
// exactly n subnets and no unset entries.
func assertPartitionsInput(t *testing.T, got []*net.IPNet, want *net.IPNet, n int) {
	t.Helper()

	if len(got) != n {
		t.Fatalf("got %d subnets, want %d", len(got), n)
	}

	var total uint64
	wantOnes, _ := want.Mask.Size()
	sorted := make([]*net.IPNet, 0, len(got))
	for _, subnet := range got {
		if subnet == nil || subnet.Mask == nil || subnet.IP == nil {
			t.Fatalf("got an unset subnet: %v", subnet)
		}
		if ones, _ := subnet.Mask.Size(); ones < wantOnes || !want.Contains(subnet.IP) {
			t.Fatalf("subnet %s is not contained in %s", subnet, want)
		}
		total += AddressCountIpnet(subnet)
		sorted = append(sorted, subnet)
	}

	if wantTotal := AddressCountIpnet(want); total != wantTotal {
		t.Fatalf("subnets cover %d addresses, want %d", total, wantTotal)
	}

	// aligned CIDR blocks either nest or are disjoint, so after sorting by
	// address any overlap shows up between neighbours
	sort.Slice(sorted, func(i, j int) bool {
		return bytes.Compare(sorted[i].IP.To16(), sorted[j].IP.To16()) < 0
	})
	for i := 1; i < len(sorted); i++ {
		if sorted[i-1].Contains(sorted[i].IP) || sorted[i].Contains(sorted[i-1].IP) {
			t.Fatalf("subnets %s and %s overlap", sorted[i-1], sorted[i])
		}
	}
}

func TestSplitIPNetIntoNPartitionsTheInput(t *testing.T) {
	tests := []struct {
		name    string
		iprange string
		n       int
	}{
		{name: "host count reaches the end of the range", iprange: "10.3.0.0/24", n: 85},
		{name: "more subnets than a power of two", iprange: "10.4.0.0/24", n: 200},
		{name: "every address split apart", iprange: "10.5.0.0/24", n: 256},
		{name: "small range", iprange: "10.6.0.0/29", n: 5},
		{name: "IPv6 range", iprange: "2001:db8::/120", n: 200},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ipnet, err := net.ParseCIDR(tt.iprange)
			if err != nil {
				t.Fatalf("Failed to parse CIDR %s: %v", tt.iprange, err)
			}

			got, err := SplitIPNetIntoN(ipnet, tt.n)
			if err != nil {
				t.Fatalf("SplitIPNetIntoN() unexpected error: %v", err)
			}

			assertPartitionsInput(t, got, ipnet, tt.n)
		})
	}
}

func TestSplitIPNetIntoNNeverReturnsUnsetSubnets(t *testing.T) {
	for _, iprange := range []string{"10.7.0.0/25", "10.7.0.0/28", "10.7.0.0/31"} {
		_, ipnet, err := net.ParseCIDR(iprange)
		if err != nil {
			t.Fatalf("Failed to parse CIDR %s: %v", iprange, err)
		}

		for n := 2; n <= 32; n++ {
			got, err := SplitIPNetIntoN(ipnet, n)
			if err != nil {
				continue
			}
			for _, subnet := range got {
				if subnet == nil || subnet.Mask == nil || subnet.IP == nil {
					t.Fatalf("SplitIPNetIntoN(%s, %d) returned an unset subnet", iprange, n)
				}
			}
		}
	}
}

func TestSplitByNumberPartitionsTheInput(t *testing.T) {
	tests := []struct {
		name    string
		iprange string
		number  int
		want    int
	}{
		{name: "host count is not a power of two", iprange: "10.3.0.0/24", number: 3, want: 85},
		{name: "host count above the range size", iprange: "10.3.0.0/24", number: 1000, want: 1},
		{name: "power of two host count", iprange: "10.3.0.0/24", number: 16, want: 16},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, ipnet, err := net.ParseCIDR(tt.iprange)
			if err != nil {
				t.Fatalf("Failed to parse CIDR %s: %v", tt.iprange, err)
			}

			got, err := SplitByNumber(tt.iprange, tt.number)
			if err != nil {
				t.Fatalf("SplitByNumber() unexpected error: %v", err)
			}

			assertPartitionsInput(t, got, ipnet, tt.want)
		})
	}
}

func TestDivideIPNetRejectsSingleAddress(t *testing.T) {
	_, ipnet, err := net.ParseCIDR("10.8.0.1/32")
	if err != nil {
		t.Fatalf("Failed to parse CIDR: %v", err)
	}

	got, err := divideIPNet(ipnet)
	if err == nil {
		t.Fatalf("divideIPNet() error = nil, want an error; got %v", got)
	}
	if got != nil {
		t.Fatalf("divideIPNet() = %v, want nil", got)
	}
}

// a large non power of two count must stay linear: shifting the slice for every
// extra subnet made this quadratic.
func TestSplitIPNetIntoNLargeCount(t *testing.T) {
	_, ipnet, err := net.ParseCIDR("2001:db8::/32")
	if err != nil {
		t.Fatal(err)
	}
	const n = 200_000
	got, err := SplitIPNetIntoN(ipnet, n)
	if err != nil {
		t.Fatal(err)
	}
	assertPartitionsInput(t, got, ipnet, n)
}
