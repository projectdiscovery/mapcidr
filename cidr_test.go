package mapcidr

import (
	"net"
	"reflect"
	"testing"
)

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
