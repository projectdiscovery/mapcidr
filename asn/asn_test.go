package asn

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func Test_asnClient_GetCIDRsForASNNum(t *testing.T) {
	tests := []struct {
		name      string
		asnNumber string
		expected  []string
	}{
		{
			name:      "ASN Number CIDR 1",
			asnNumber: "AS14421",
			expected:  []string{"216.101.17.0/24"},
		},
		{
			name:      "ASN Number I",
			asnNumber: "AS7712",
			expected:  []string{"118.67.200.0/23", "118.67.202.0/24", "118.67.203.0/24", "118.67.204.0/22"},
		},
	}
	asnClient := New()
	for _, tt := range tests {
		var result []string
		got := asnClient.GetCIDRsForASNNum(tt.asnNumber)
		for _, cidr := range got {
			result = append(result, cidr.String())
		}
		require.ElementsMatch(t, tt.expected, result, "could not get correct cidrs")
	}
}
