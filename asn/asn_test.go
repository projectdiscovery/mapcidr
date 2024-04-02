package asn

import (
	"os"
	"testing"

	sliceutil "github.com/projectdiscovery/utils/slice"
	stringsutil "github.com/projectdiscovery/utils/strings"
	"github.com/stretchr/testify/require"
)

func Test_asnClient_GetCIDRsForASNNum(t *testing.T) {
	tests := []struct {
		name                string
		asnNumber           string
		potentiallyExpected [][]string
	}{
		{
			name:                "ASN Number 1",
			asnNumber:           "AS14421",
			potentiallyExpected: [][]string{{"216.101.17.0/24"}},
		},
		{
			name:                "ASN Number 2",
			asnNumber:           "AS7712",
			potentiallyExpected: [][]string{{"118.67.200.0/21"}},
		},
		{
			name:                "Wrong ASN number",
			asnNumber:           "AS",
			potentiallyExpected: [][]string{{}},
		},
	}

	for _, tt := range tests {
		var result []string
		got, err := GetCIDRsForASNNum(tt.asnNumber)
		if err != nil {
			require.ErrorContains(t, err, "invalid asn number")
		}
		for _, cidr := range got {
			result = append(result, cidr.String())
		}
		var found bool
		for _, expected := range tt.potentiallyExpected {
			found = found || sliceutil.ElementsMatch(expected, result)
		}
		if !found {
			t.Errorf("could not get correct cidrs: %v %v", tt.potentiallyExpected, result)
		}
	}
}

func TestASNClient_GetIPAddressesAsStream(t *testing.T) {
	tests := []struct {
		name               string
		asnNumber          string
		expectedOutputFile string
	}{
		{
			name:               "ASN Number 1",
			asnNumber:          "AS14421",
			expectedOutputFile: "tests/AS14421.txt",
		},
		{
			name:               "ASN Number 2",
			asnNumber:          "AS134029",
			expectedOutputFile: "tests/AS134029.txt",
		},
	}
	for _, tt := range tests {
		var result []string
		got, err := GetIPAddressesAsStream(tt.asnNumber)
		if err != nil {
			require.ErrorContains(t, err, "invalid asn number")
		}
		for ip := range got {
			result = append(result, ip)
		}
		// read the expectedOutputFile
		fileContent, err := os.ReadFile(tt.expectedOutputFile)
		require.Nil(t, err, "could not read the expectedOutputFile file")
		items := stringsutil.SplitAny(string(fileContent), "\n", "\r")

		require.ElementsMatch(t, items, result, "could not get correct cidrs")
	}
}
