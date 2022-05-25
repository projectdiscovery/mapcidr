package mapcidr

import (
	"math/big"
	"net"
	"testing"

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
