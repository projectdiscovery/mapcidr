package mapcidr

import (
	"math/big"
	"net"
	"testing"

	sliceutil "github.com/projectdiscovery/utils/slice"
	"github.com/stretchr/testify/require"
)

func TestCountIPsInCIDRs(t *testing.T) {
	errorMsg := "unexpected result"
	_, net1, _ := net.ParseCIDR("15.181.232.0/21")
	_, net2, _ := net.ParseCIDR("15.181.232.0/21")
	require.Equal(t, CountIPsInCIDRs(true, true, net1, net2), big.NewInt(4096), errorMsg)
	require.Equal(t, CountIPsInCIDRs(false, false, net1, net2), big.NewInt(4092), errorMsg)
	require.Equal(t, CountIPsInCIDRs(true, false, net1, net2), big.NewInt(4094), errorMsg)
	require.Equal(t, CountIPsInCIDRs(false, true, net1, net2), big.NewInt(4094), errorMsg)
}

func TestIpEncodings(t *testing.T) {
	ip := "127.0.0.1"
	res := AlterIP(ip, []string{"1"}, 0, false)
	require.Equal(t, []string{"127.0.0.1"}, res)
	res = AlterIP(ip, []string{"2"}, 0, false)
	require.Equal(t, []string{"127.1"}, res)
	res = AlterIP(ip, []string{"3"}, 0, false)
	require.Equal(t, []string{"0177.0.0.01"}, res)
	res = AlterIP(ip, []string{"4"}, 0, false)
	require.True(t, sliceutil.ContainsItems(res, []string{"0x7f.0x0.0x0.0x1", "0x7f000001"}))
	res = AlterIP(ip, []string{"5"}, 0, false)
	require.Equal(t, []string{"2130706433"}, res)
	res = AlterIP(ip, []string{"6"}, 0, false)
	require.Equal(t, []string{"1111111000000000000000000000001"}, res)
	res = AlterIP(ip, []string{"7"}, 0, false)
	require.Equal(t, []string{"0x7f.0.0.0x1"}, res)
	res = AlterIP("2001:0db8:85a3:0000:0000:8a2e:0370:7334", []string{"8"}, 0, false)
	require.Equal(t, []string{"2001:db8:85a3::8a2e:370:7334"}, res)
	res = AlterIP(ip, []string{"9"}, 0, false)
	require.Equal(t, []string{"%31%32%37%2E%30%2E%30%2E%31"}, res)
	res = AlterIP(ip, []string{"10"}, 5, true)
	require.Equal(t, []string{"127.0.0.1", "127.0.0.01", "127.0.0.001", "127.0.0.0001", "127.0.0.00001", "127.0.00.1", "127.0.00.01", "127.0.00.001", "127.0.00.0001", "127.0.00.00001", "127.0.000.1", "127.0.000.01", "127.0.000.001", "127.0.000.0001", "127.0.000.00001", "127.0.0000.1", "127.0.0000.01", "127.0.0000.001", "127.0.0000.0001", "127.0.0000.00001", "127.0.00000.1", "127.0.00000.01", "127.0.00000.001", "127.0.00000.0001", "127.0.00000.00001", "127.00.0.1", "127.00.0.01", "127.00.0.001", "127.00.0.0001", "127.00.0.00001", "127.00.00.1", "127.00.00.01", "127.00.00.001", "127.00.00.0001", "127.00.00.00001", "127.00.000.1", "127.00.000.01", "127.00.000.001", "127.00.000.0001", "127.00.000.00001", "127.00.0000.1", "127.00.0000.01", "127.00.0000.001", "127.00.0000.0001", "127.00.0000.00001", "127.00.00000.1", "127.00.00000.01", "127.00.00000.001", "127.00.00000.0001", "127.00.00000.00001", "127.000.0.1", "127.000.0.01", "127.000.0.001", "127.000.0.0001", "127.000.0.00001", "127.000.00.1", "127.000.00.01", "127.000.00.001", "127.000.00.0001", "127.000.00.00001", "127.000.000.1", "127.000.000.01", "127.000.000.001", "127.000.000.0001", "127.000.000.00001", "127.000.0000.1", "127.000.0000.01", "127.000.0000.001", "127.000.0000.0001", "127.000.0000.00001", "127.000.00000.1", "127.000.00000.01", "127.000.00000.001", "127.000.00000.0001", "127.000.00000.00001", "127.0000.0.1", "127.0000.0.01", "127.0000.0.001", "127.0000.0.0001", "127.0000.0.00001", "127.0000.00.1", "127.0000.00.01", "127.0000.00.001", "127.0000.00.0001", "127.0000.00.00001", "127.0000.000.1", "127.0000.000.01", "127.0000.000.001", "127.0000.000.0001", "127.0000.000.00001", "127.0000.0000.1", "127.0000.0000.01", "127.0000.0000.001", "127.0000.0000.0001", "127.0000.0000.00001", "127.0000.00000.1", "127.0000.00000.01", "127.0000.00000.001", "127.0000.00000.0001", "127.0000.00000.00001", "127.00000.0.1", "127.00000.0.01", "127.00000.0.001", "127.00000.0.0001", "127.00000.0.00001", "127.00000.00.1", "127.00000.00.01", "127.00000.00.001", "127.00000.00.0001", "127.00000.00.00001", "127.00000.000.1", "127.00000.000.01", "127.00000.000.001", "127.00000.000.0001", "127.00000.000.00001", "127.00000.0000.1", "127.00000.0000.01", "127.00000.0000.001", "127.00000.0000.0001", "127.00000.0000.00001", "127.00000.00000.1", "127.00000.00000.01", "127.00000.00000.001", "127.00000.00000.0001", "127.00000.00000.00001", "0127.0.0.1", "0127.0.0.01", "0127.0.0.001", "0127.0.0.0001", "0127.0.0.00001", "0127.0.00.1", "0127.0.00.01", "0127.0.00.001", "0127.0.00.0001", "0127.0.00.00001", "0127.0.000.1", "0127.0.000.01", "0127.0.000.001", "0127.0.000.0001", "0127.0.000.00001", "0127.0.0000.1", "0127.0.0000.01", "0127.0.0000.001", "0127.0.0000.0001", "0127.0.0000.00001", "0127.0.00000.1", "0127.0.00000.01", "0127.0.00000.001", "0127.0.00000.0001", "0127.0.00000.00001", "0127.00.0.1", "0127.00.0.01", "0127.00.0.001", "0127.00.0.0001", "0127.00.0.00001", "0127.00.00.1", "0127.00.00.01", "0127.00.00.001", "0127.00.00.0001", "0127.00.00.00001", "0127.00.000.1", "0127.00.000.01", "0127.00.000.001", "0127.00.000.0001", "0127.00.000.00001", "0127.00.0000.1", "0127.00.0000.01", "0127.00.0000.001", "0127.00.0000.0001", "0127.00.0000.00001", "0127.00.00000.1", "0127.00.00000.01", "0127.00.00000.001", "0127.00.00000.0001", "0127.00.00000.00001", "0127.000.0.1", "0127.000.0.01", "0127.000.0.001", "0127.000.0.0001", "0127.000.0.00001", "0127.000.00.1", "0127.000.00.01", "0127.000.00.001", "0127.000.00.0001", "0127.000.00.00001", "0127.000.000.1", "0127.000.000.01", "0127.000.000.001", "0127.000.000.0001", "0127.000.000.00001", "0127.000.0000.1", "0127.000.0000.01", "0127.000.0000.001", "0127.000.0000.0001", "0127.000.0000.00001", "0127.000.00000.1", "0127.000.00000.01", "0127.000.00000.001", "0127.000.00000.0001", "0127.000.00000.00001", "0127.0000.0.1", "0127.0000.0.01", "0127.0000.0.001", "0127.0000.0.0001", "0127.0000.0.00001", "0127.0000.00.1", "0127.0000.00.01", "0127.0000.00.001", "0127.0000.00.0001", "0127.0000.00.00001", "0127.0000.000.1", "0127.0000.000.01", "0127.0000.000.001", "0127.0000.000.0001", "0127.0000.000.00001", "0127.0000.0000.1", "0127.0000.0000.01", "0127.0000.0000.001", "0127.0000.0000.0001", "0127.0000.0000.00001", "0127.0000.00000.1", "0127.0000.00000.01", "0127.0000.00000.001", "0127.0000.00000.0001", "0127.0000.00000.00001", "0127.00000.0.1", "0127.00000.0.01", "0127.00000.0.001", "0127.00000.0.0001", "0127.00000.0.00001", "0127.00000.00.1", "0127.00000.00.01", "0127.00000.00.001", "0127.00000.00.0001", "0127.00000.00.00001", "0127.00000.000.1", "0127.00000.000.01", "0127.00000.000.001", "0127.00000.000.0001", "0127.00000.000.00001", "0127.00000.0000.1", "0127.00000.0000.01", "0127.00000.0000.001", "0127.00000.0000.0001", "0127.00000.0000.00001", "0127.00000.00000.1", "0127.00000.00000.01", "0127.00000.00000.001", "0127.00000.00000.0001", "0127.00000.00000.00001", "00127.0.0.1", "00127.0.0.01", "00127.0.0.001", "00127.0.0.0001", "00127.0.0.00001", "00127.0.00.1", "00127.0.00.01", "00127.0.00.001", "00127.0.00.0001", "00127.0.00.00001", "00127.0.000.1", "00127.0.000.01", "00127.0.000.001", "00127.0.000.0001", "00127.0.000.00001", "00127.0.0000.1", "00127.0.0000.01", "00127.0.0000.001", "00127.0.0000.0001", "00127.0.0000.00001", "00127.0.00000.1", "00127.0.00000.01", "00127.0.00000.001", "00127.0.00000.0001", "00127.0.00000.00001", "00127.00.0.1", "00127.00.0.01", "00127.00.0.001", "00127.00.0.0001", "00127.00.0.00001", "00127.00.00.1", "00127.00.00.01", "00127.00.00.001", "00127.00.00.0001", "00127.00.00.00001", "00127.00.000.1", "00127.00.000.01", "00127.00.000.001", "00127.00.000.0001", "00127.00.000.00001", "00127.00.0000.1", "00127.00.0000.01", "00127.00.0000.001", "00127.00.0000.0001", "00127.00.0000.00001", "00127.00.00000.1", "00127.00.00000.01", "00127.00.00000.001", "00127.00.00000.0001", "00127.00.00000.00001", "00127.000.0.1", "00127.000.0.01", "00127.000.0.001", "00127.000.0.0001", "00127.000.0.00001", "00127.000.00.1", "00127.000.00.01", "00127.000.00.001", "00127.000.00.0001", "00127.000.00.00001", "00127.000.000.1", "00127.000.000.01", "00127.000.000.001", "00127.000.000.0001", "00127.000.000.00001", "00127.000.0000.1", "00127.000.0000.01", "00127.000.0000.001", "00127.000.0000.0001", "00127.000.0000.00001", "00127.000.00000.1", "00127.000.00000.01", "00127.000.00000.001", "00127.000.00000.0001", "00127.000.00000.00001", "00127.0000.0.1", "00127.0000.0.01", "00127.0000.0.001", "00127.0000.0.0001", "00127.0000.0.00001", "00127.0000.00.1", "00127.0000.00.01", "00127.0000.00.001", "00127.0000.00.0001", "00127.0000.00.00001", "00127.0000.000.1", "00127.0000.000.01", "00127.0000.000.001", "00127.0000.000.0001", "00127.0000.000.00001", "00127.0000.0000.1", "00127.0000.0000.01", "00127.0000.0000.001", "00127.0000.0000.0001", "00127.0000.0000.00001", "00127.0000.00000.1", "00127.0000.00000.01", "00127.0000.00000.001", "00127.0000.00000.0001", "00127.0000.00000.00001", "00127.00000.0.1", "00127.00000.0.01", "00127.00000.0.001", "00127.00000.0.0001", "00127.00000.0.00001", "00127.00000.00.1", "00127.00000.00.01", "00127.00000.00.001", "00127.00000.00.0001", "00127.00000.00.00001", "00127.00000.000.1", "00127.00000.000.01", "00127.00000.000.001", "00127.00000.000.0001", "00127.00000.000.00001", "00127.00000.0000.1", "00127.00000.0000.01", "00127.00000.0000.001", "00127.00000.0000.0001", "00127.00000.0000.00001", "00127.00000.00000.1", "00127.00000.00000.01", "00127.00000.00000.001", "00127.00000.00000.0001", "00127.00000.00000.00001"}, res)
	res = AlterIP("127.0.1.0", []string{"11"}, 0, false)
	require.Equal(t, []string{"127.0.256"}, res)
}

func TestRangeToCIDRs(t *testing.T) {
	tests := []struct {
		name          string
		firstIP       net.IP
		lastIP        net.IP
		want          []string
		expectedError string
	}{
		{
			name:          "IP4SingleCIDR",
			firstIP:       net.ParseIP("192.168.0.0"),
			lastIP:        net.ParseIP("192.168.0.255"),
			want:          []string{"192.168.0.0/24"},
			expectedError: "",
		},
		{
			name:    "IP4MultipleCIDR",
			firstIP: net.ParseIP("192.168.0.1"),
			lastIP:  net.ParseIP("192.168.0.255"),
			want: []string{"192.168.0.1/32", "192.168.0.2/31",
				"192.168.0.4/30", "192.168.0.8/29",
				"192.168.0.16/28", "192.168.0.32/27",
				"192.168.0.64/26", "192.168.0.128/25"},
			expectedError: "",
		},
		{
			name:          "IP6RangeCIDR",
			firstIP:       net.ParseIP("2c0f:fec9::"),
			lastIP:        net.ParseIP("2c0f:fed7:ffff:ffff:ffff:ffff:ffff:ffff"),
			want:          []string{"2c0f:fec9::/32", "2c0f:feca::/31", "2c0f:fecc::/30", "2c0f:fed0::/29"},
			expectedError: "",
		},
		{
			name:          "wrongIPRange",
			firstIP:       net.ParseIP("192.168.0.255"),
			lastIP:        net.ParseIP("192.168.0.0"),
			want:          []string{},
			expectedError: "start IP:192.168.0.255 must be less than End IP:192.168.0.0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cidrStringList []string
			got, err := GetCIDRFromIPRange(tt.firstIP, tt.lastIP)
			if err != nil {
				require.Equal(t, tt.expectedError, err.Error())
			} else {
				for _, item := range got {
					cidrStringList = append(cidrStringList, item.String())
				}
				require.Equal(t, tt.want, cidrStringList)
			}
		})
	}
}

// cidrStrings runs GetCIDRFromIPRange and returns the CIDR list as strings.
func cidrStrings(t *testing.T, first, last net.IP) []string {
	t.Helper()
	got, err := GetCIDRFromIPRange(first, last)
	require.NoError(t, err)
	var out []string
	for _, n := range got {
		out = append(out, n.String())
	}
	return out
}

// GetCIDRFromIPRange must accept any legitimate net.IP byte-length. Previously a
// 4-byte (To4) or mixed-length pair panicked, and a mixed-length valid range was
// wrongly rejected by the initial start>end check.
func TestGetCIDRFromIPRangeByteLength(t *testing.T) {
	first16 := net.ParseIP("10.0.0.1")
	last16 := net.ParseIP("10.0.0.9")
	want := cidrStrings(t, first16, last16)
	require.Equal(t, []string{"10.0.0.1/32", "10.0.0.2/31", "10.0.0.4/30", "10.0.0.8/31"}, want)

	cases := []struct {
		name        string
		first, last net.IP
	}{
		{"both4byte", first16.To4(), last16.To4()},
		{"first16last4", first16, last16.To4()},
		{"first4last16", first16.To4(), last16},
		{"integerToIPOutput", intToIPHelper(t, "10.0.0.1"), intToIPHelper(t, "10.0.0.9")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			require.Equal(t, want, cidrStrings(t, tc.first, tc.last))
		})
	}
}

func intToIPHelper(t *testing.T, s string) net.IP {
	t.Helper()
	i, bits, err := IPToInteger(net.ParseIP(s))
	require.NoError(t, err)
	return IntegerToIP(i, bits) // 4-byte form
}

// tiling parity: 4-byte, 16-byte and mixed inputs must yield identical, correct
// CIDR sets (aligned, contiguous, non-overlapping, exact cover of [start,end]).
func TestGetCIDRFromIPRangeTilingParity(t *testing.T) {
	base := new(big.Int).SetBytes(net.ParseIP("172.16.0.0").To4())
	for k := 0; k < 4000; k++ {
		a := int64((k * 2654435761) % (1 << 20))
		b := a + int64((k*40503)%(1<<12))
		s4 := IntegerToIP(new(big.Int).Add(base, big.NewInt(a)), 32)
		e4 := IntegerToIP(new(big.Int).Add(base, big.NewInt(b)), 32)
		got16 := cidrStrings(t, s4.To16(), e4.To16())
		require.Equal(t, got16, cidrStrings(t, s4, e4), "4-byte parity")
		require.Equal(t, got16, cidrStrings(t, s4.To16(), e4), "mixed parity")
		assertTiling(t, s4, e4, got16)
	}
}

func assertTiling(t *testing.T, start, end net.IP, cidrs []string) {
	t.Helper()
	lo := new(big.Int).SetBytes(start.To4())
	end4 := new(big.Int).SetBytes(end.To4())
	for _, c := range cidrs {
		_, n, err := net.ParseCIDR(c)
		require.NoError(t, err)
		ones, size := n.Mask.Size()
		netLo := new(big.Int).SetBytes(n.IP.To4())
		require.Equal(t, 0, lo.Cmp(netLo), "gap/overlap or misalignment at %s", c)
		blk := new(big.Int).Lsh(big.NewInt(1), uint(size-ones))
		lo = new(big.Int).Add(netLo, blk)
	}
	require.Equal(t, 0, lo.Cmp(new(big.Int).Add(end4, big.NewInt(1))), "range not covered exactly")
}

func TestFindSmallestIPRange(t *testing.T) {
	// Input IP addresses
	ips := []string{
		"192.168.1.1",
		"192.168.1.111",
		"192.168.2.2",
	}

	// Expected smallest range
	expectedRange := "192.168.0.0/22"

	var ipNets []*net.IPNet
	for _, ip := range ips {
		_, ipNet, _ := net.ParseCIDR(ip + "/32")
		ipNets = append(ipNets, ipNet)
	}

	// Find the smallest IP range
	smallestRange, err := FindMinCIDR(ipNets)
	if err != nil {
		t.Fatalf("Error finding smallest IP range: %v", err)
	}

	// Convert the result to CIDR notation
	cidr := smallestRange.String()

	// Check if the result matches the expected range
	if cidr != expectedRange {
		t.Errorf("Expected smallest range %s, but got %s", expectedRange, cidr)
	}
}

func TestRemoveCIDRsReservedIPv4(t *testing.T) {
	_, allowCIDR, err := net.ParseCIDR("0.0.0.0/0")
	require.NoError(t, err)

	removeCIDRs := []string{
		"0.0.0.0/8",
		"10.0.0.0/8",
		"100.64.0.0/10",
		"127.0.0.0/8",
		"169.254.0.0/16",
		"172.16.0.0/12",
		"192.0.0.0/24",
		"192.0.2.0/24",
		"192.88.99.0/24",
		"192.168.0.0/16",
		"198.18.0.0/15",
		"198.51.100.0/24",
		"203.0.113.0/24",
		"224.0.0.0/4",
		"240.0.0.0/4",
	}

	var removeNetworks []*net.IPNet
	for _, cidr := range removeCIDRs {
		_, network, parseErr := net.ParseCIDR(cidr)
		require.NoError(t, parseErr)
		removeNetworks = append(removeNetworks, network)
	}

	newAllows, removeErr := RemoveCIDRs([]*net.IPNet{allowCIDR}, removeNetworks)
	require.NoError(t, removeErr)
	require.NotEmpty(t, newAllows)
}
