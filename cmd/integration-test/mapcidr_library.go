package main

import (
	"net"
	"strings"

	"github.com/projectdiscovery/mapcidr"
)

type ipIntegrationTest struct {
	Input    string
	Expected []string
}
type cidrAsIPNETIntegrationTest struct {
	Input    string
	Expected []string
}
type getCIDRFromIPRANGEIntegrationTest struct {
	Input    string
	Expected []string
}

func (h *ipIntegrationTest) Execute() error {
	ips, _ := mapcidr.IPAddresses(h.Input)
	var ipList []string
	ipList = append(ipList, ips...)
	return compareResult(h.Expected, ipList)
}

func (h *cidrAsIPNETIntegrationTest) Execute() error {
	cidr := strings.Split(h.Input, ",")
	ips := mapcidr.CIDRsAsIPNET(cidr)
	var ipList []string
	for _, v := range ips {
		ipList = append(ipList, v.String())
	}
	return compareResult(h.Expected, ipList)
}

func (h *getCIDRFromIPRANGEIntegrationTest) Execute() error {
	ips := strings.Split(h.Input, ",")
	firstIP := net.ParseIP(ips[0])
	lastIP := net.ParseIP(ips[1])
	cidrs, _ := mapcidr.GetCIDRFromIPRange(firstIP, lastIP)
	var ipList []string
	for _, v := range cidrs {
		ipList = append(ipList, v.String())
	}
	return compareResult(h.Expected, ipList)
}
